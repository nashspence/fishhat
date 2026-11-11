"""Pure Slurm batch projections; no submission, grant, or release evidence.

Provider semantics: https://slurm.schedmd.com/sbatch.html and
https://slurm.schedmd.com/job_state_codes.html. The configured worker script is
owner-installed. Its request reference is correlation data, never authorization.
Slurm cgroup configuration and a fenced worker remain separate prerequisites.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from re import fullmatch
from typing import Any, Literal

from fishhat_adapters import check_configuration
from fishhat_contracts.validation import ContractError, digest, strict_json, validate

_MIB = 1024 * 1024
_EXACT_INTEGER = 9_007_199_254_740_991


@dataclass(frozen=True)
class BatchProjection:
    """A reviewable partial translation, never an admissible native launch."""

    request_digest: str
    submission_key: str
    argv: tuple[str, ...] | None
    charged_cpu_millis: int
    charged_memory_bytes: int
    unsupported: tuple[str, ...]
    requires: tuple[str, ...]
    admissible: Literal[False] = False
    native_qualified: Literal[False] = False


@dataclass(frozen=True)
class JobState:
    """Provider state only; even terminal state cannot release a Fishhat grant."""

    phase: Literal["queued", "allocated", "running", "stopping", "terminal", "unknown"]
    outcome: str | None = None
    may_repeat: bool = False


@dataclass(frozen=True)
class SubmissionReceipt:
    """Parsed acceptance correlation, without a step, execution, or incarnation."""

    job_id: str
    cluster: str


def _configuration(configuration: dict[str, Any]) -> None:
    descriptor = strict_json(Path(__file__).with_name("descriptor.json").read_bytes())
    schema = descriptor["configuration_schema"]
    check_configuration(schema, configuration, digest(schema))


def project_submission(request: dict[str, Any], configuration: dict[str, Any]) -> BatchProjection:
    """Translate only representable quantities; expose every unfulfilled limit.

    Only the shape and provider relationship are checked here. The host owner must
    independently admit policy, scope, runtime generation, and immutable work custody.
    No caller-provided shell, script, environment, or native options are accepted.
    """
    validate("resource-admission.schema.json", request, "ResourceRequest")
    _configuration(configuration)
    host = configuration["target_host"]
    if request["context"]["target_host"] != host or request["domain"]["host"] != host:
        raise ContractError("SCHEDULER_HOST_BINDING_MISMATCH")
    demand, limits = request["demand"], request["limits"]
    cpus = (int(demand["cpu_millis"]) + 999) // 1000
    memory = (int(demand["memory_bytes"]) + _MIB - 1) // _MIB
    unsupported = {"tasks-max", "supervision"}
    if request["lifetime"] != "transient":
        unsupported.add("resident-lifetime")
    if demand["devices"]:
        unsupported.add("device-isolation")
    if cpus == 0 or memory == 0 or cpus * 1000 > _EXACT_INTEGER or memory * _MIB > _EXACT_INTEGER:
        # Slurm --mem=0 means all memory; it cannot express a zero-byte claim.
        unsupported.add("quantities")
    if cpus * 1000 != limits["cpu_max_millis"]:
        unsupported.add("cpu-max")
    if memory * _MIB != limits["memory_max_bytes"]:
        unsupported.add("memory-max")
    seconds = None if limits["walltime_seconds"] is None else int(limits["walltime_seconds"])
    if seconds is None or seconds % 60:
        # Slurm rounds seconds upward to minutes, weakening an exact hard cap.
        unsupported.add("walltime")
    key = request["id"]
    commitment = digest(request)
    argv: tuple[str, ...] | None = None
    if seconds is not None and unsupported == {"tasks-max", "supervision"}:
        argv = (
            "sbatch",
            "--parsable",
            "--clusters=" + configuration["cluster"],
            "--partition=" + configuration["partition"],
            "--account=" + configuration["account"],
            "--nodes=1",
            "--ntasks=1",
            "--nodelist=" + configuration["node"],
            "--cpus-per-task=" + str(cpus),
            "--mem=" + str(memory) + "M",
            "--time=" + str(seconds // 60),
            "--no-requeue",
            "--export=NIL",
            "--job-name=fishhat-" + key,
            "--comment=fishhat:" + key + ":" + commitment,
            "--",
            configuration["worker_script"],
            "--resource-request",
            key,
            "--resource-request-digest",
            commitment,
        )
    return BatchProjection(
        commitment,
        key,
        argv,
        cpus * 1000,
        memory * _MIB,
        tuple(sorted(unsupported)),
        (
            "cpu-reservation",
            "memory-reservation",
            "cpu-max",
            "memory-max",
            "walltime",
            "host-affinity",
        ),
    )


def parse_submission(stdout: str, *, cluster: str) -> SubmissionReceipt:
    """Require the projected cluster in parsable output; never infer running work.

    An absent or ambiguous response must be reconciled by the host owner. The
    comment is a correlation marker, not a native idempotency key or permission
    to resubmit. A returned job number is not a stable execution incarnation.
    """
    value = stdout.removesuffix("\n")
    matched = fullmatch(r"([1-9][0-9]*);([a-z][a-z0-9._-]*)", value)
    if matched is None or matched[2] != cluster:
        raise ContractError("SCHEDULER_SUBMISSION_UNCERTAIN")
    return SubmissionReceipt(matched[1], matched[2])


def normalize_state(state: str, flags: tuple[str, ...] = ()) -> JobState:
    """Keep preemption/requeue and cleanup visible instead of inventing success."""
    if any(flag in {"REQUEUED", "REQUEUE_HOLD", "REQUEUE_FED"} for flag in flags):
        return JobState("unknown", may_repeat=True)
    if "COMPLETING" in flags:
        return JobState("stopping")
    if "CONFIGURING" in flags:
        return JobState("allocated")
    if flags:
        return JobState("unknown")
    if state == "PENDING":
        return JobState("queued")
    if state == "RUNNING":
        return JobState("running")
    if state == "COMPLETING":
        return JobState("stopping")
    if state in {"PREEMPTED", "REQUEUED", "REQUEUE_HOLD", "REQUEUE_FED"}:
        return JobState("unknown", may_repeat=True)
    outcomes = {
        "COMPLETED": "backend-exit-zero",
        "CANCELLED": "cancelled",
        "TIMEOUT": "timed-out",
        "OUT_OF_MEMORY": "out-of-memory",
        "FAILED": "failed",
        "NODE_FAIL": "node-failed",
        "BOOT_FAIL": "boot-failed",
        "DEADLINE": "deadline",
    }
    if state in outcomes:
        return JobState("terminal", outcomes[state])
    # Suspended and stopped work still owns resources. Unknown flags/states
    # cannot establish cessation or the absence of another execution.
    return JobState("unknown")
