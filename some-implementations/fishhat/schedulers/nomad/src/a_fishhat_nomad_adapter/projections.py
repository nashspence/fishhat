"""Pure Nomad batch HTTP projections; no requests are sent to a native service.

Semantics: https://developer.hashicorp.com/nomad/api-docs/jobs,
https://developer.hashicorp.com/nomad/docs/job-specification/resources, and
https://developer.hashicorp.com/nomad/docs/job-specification/group.
Jobs are desired intent; evaluations and allocations are separate identities.
The exec driver reserves cores but does not supply a portable CPU bandwidth cap.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from fishhat_adapters import check_configuration
from fishhat_contracts.validation import (
    ContractError,
    canonical,
    digest,
    strict_json,
    validate,
)

_MIB = 1024 * 1024
_SECOND_NS = 1_000_000_000
_EXACT_INTEGER = 9_007_199_254_740_991


@dataclass(frozen=True)
class JobProjection:
    """A declarative create-only proposal, not permission to run a worker."""

    request_digest: str
    job_id: str
    endpoint_handle: str
    method: Literal["PUT"]
    path: str
    query: tuple[tuple[str, str], ...]
    body: bytes | None
    charged_cpu_millis: int
    charged_memory_bytes: int
    unsupported: tuple[str, ...]
    requires: tuple[str, ...]
    admissible: Literal[False] = False
    native_qualified: Literal[False] = False


@dataclass(frozen=True)
class AllocationState:
    """Partial provider evidence, never a resource release or owner outcome."""

    phase: Literal["queued", "running", "stopping", "terminal", "unknown"]
    outcome: str | None = None
    may_repeat: bool = False


@dataclass(frozen=True)
class RegistrationReceipt:
    """Job registration and evaluation identity; no allocation has been observed."""

    job_id: str
    job_modify_index: int
    evaluation_id: str
    evaluation_create_index: int


def _configuration(configuration: dict[str, Any]) -> None:
    descriptor = strict_json(Path(__file__).with_name("descriptor.json").read_bytes())
    schema = descriptor["configuration_schema"]
    check_configuration(schema, configuration, digest(schema))


def project_submission(request: dict[str, Any], configuration: dict[str, Any]) -> JobProjection:
    """Use a deterministic job ID and create-only CAS; never submit arbitrary HCL.

    The fixed worker receives an immutable request reference and must independently
    obtain host dispatch authority. Native qualification must cover its isolation,
    fencing, and the exact API profile, including MaxRunDuration semantics.
    """
    validate("resource-admission.schema.json", request, "ResourceRequest")
    _configuration(configuration)
    host = configuration["target_host"]
    if request["context"]["target_host"] != host or request["domain"]["host"] != host:
        raise ContractError("SCHEDULER_HOST_BINDING_MISMATCH")
    demand, limits = request["demand"], request["limits"]
    cores = (int(demand["cpu_millis"]) + 999) // 1000
    memory = (int(demand["memory_bytes"]) + _MIB - 1) // _MIB
    unsupported = {"cpu-max", "tasks-max", "supervision"}
    if request["lifetime"] != "transient":
        unsupported.add("resident-lifetime")
    if demand["devices"]:
        unsupported.add("device-isolation")
    if cores == 0 or memory == 0 or cores * 1000 > _EXACT_INTEGER or memory * _MIB > _EXACT_INTEGER:
        unsupported.add("quantities")
    if memory * _MIB != limits["memory_max_bytes"]:
        unsupported.add("memory-max")
    seconds = None if limits["walltime_seconds"] is None else int(limits["walltime_seconds"])
    if seconds is None or seconds > _EXACT_INTEGER // _SECOND_NS:
        unsupported.add("walltime")
    key = "fishhat-" + request["id"]
    commitment = digest(request)
    body = None
    if seconds is not None and unsupported == {"cpu-max", "tasks-max", "supervision"}:
        body = canonical(
            {
                "EnforceIndex": True,
                "JobModifyIndex": 0,
                "Job": {
                    "ID": key,
                    "Name": key,
                    "Type": "batch",
                    "Region": configuration["region"],
                    "Namespace": configuration["namespace"],
                    "Datacenters": [configuration["datacenter"]],
                    "Constraints": [
                        {
                            "LTarget": "${node.unique.id}",
                            "Operand": "=",
                            "RTarget": configuration["node_id"],
                        }
                    ],
                    "Meta": {"fishhat_request_digest": commitment},
                    "TaskGroups": [
                        {
                            "Name": "work",
                            "Count": 1,
                            "RestartPolicy": {"Attempts": 0, "Mode": "fail"},
                            "ReschedulePolicy": {"Attempts": 0, "Unlimited": False},
                            "Disconnect": {
                                "LostAfter": seconds * _SECOND_NS,
                                "Replace": False,
                                "Reconcile": "keep_original",
                            },
                            "MaxRunDuration": seconds * _SECOND_NS,
                            "Tasks": [
                                {
                                    "Name": "worker",
                                    "Driver": "exec",
                                    "Config": {
                                        "command": configuration["worker_executable"],
                                        "args": [
                                            "--resource-request",
                                            request["id"],
                                            "--resource-request-digest",
                                            commitment,
                                        ],
                                    },
                                    "Resources": {"Cores": cores, "MemoryMB": memory},
                                }
                            ],
                        }
                    ],
                },
            }
        )
    return JobProjection(
        commitment,
        key,
        configuration["endpoint_handle"],
        "PUT",
        "/v1/jobs",
        (("region", configuration["region"]), ("namespace", configuration["namespace"])),
        body,
        cores * 1000,
        memory * _MIB,
        tuple(sorted(unsupported)),
        ("cpu-reservation", "memory-reservation", "memory-max", "walltime", "host-affinity"),
    )


def reconcile_job_identity(projection: JobProjection, observed_job: dict[str, Any]) -> str:
    """Check a supplied snapshot after uncertain create; do not update/replay it.

    The caller must authenticate the observer, compare effective specification,
    and retain incarnation/index evidence. This compares correlation only;
    matching untrusted JSON never establishes acceptance or native execution.
    """
    if projection.body is None:
        raise ContractError("SCHEDULER_PROJECTION_UNREPRESENTABLE")
    wanted = strict_json(projection.body)["Job"]
    metadata = observed_job.get("Meta")
    if (
        observed_job.get("ID") != projection.job_id
        or observed_job.get("Region") != wanted["Region"]
        or observed_job.get("Namespace") != wanted["Namespace"]
        or not isinstance(metadata, dict)
        or metadata.get("fishhat_request_digest") != projection.request_digest
    ):
        raise ContractError("SCHEDULER_SUBMISSION_IDENTITY_CONFLICT")
    return "matching-correlation-requires-observation"


def parse_registration(projection: JobProjection, response: dict[str, Any]) -> RegistrationReceipt:
    """Separate registration/evaluation from placement, task start, and outcome.

    Native response authentication remains the caller's responsibility. An
    uncertain create is observed using its stable job ID; it is never replayed.
    """
    evaluation = response.get("EvalID")
    index = response.get("JobModifyIndex")
    evaluation_index = response.get("EvalCreateIndex")
    try:
        valid_evaluation = isinstance(evaluation, str) and str(UUID(evaluation)) == evaluation
    except ValueError:
        valid_evaluation = False
    if (
        projection.body is None
        or not valid_evaluation
        or type(index) is not int
        or not 1 <= index <= _EXACT_INTEGER
        or type(evaluation_index) is not int
        or not 1 <= evaluation_index <= _EXACT_INTEGER
    ):
        raise ContractError("SCHEDULER_SUBMISSION_UNCERTAIN")
    return RegistrationReceipt(projection.job_id, index, str(evaluation), evaluation_index)


def cancellation_request(projection: JobProjection) -> tuple[str, str, tuple[tuple[str, str], ...]]:
    """Stop the desired job; stopping one allocation would request replacement."""
    return "DELETE", "/v1/job/" + projection.job_id, (*projection.query, ("purge", "false"))


def normalize_allocation(
    client_status: str,
    *,
    desired_status: str = "run",
    description: str = "",
    replacement_observed: bool = False,
) -> AllocationState:
    """Treat timeout-complete and replacement as distinct from successful work.

    An evaluation's 'complete' belongs to another API object and must never be passed
    as an allocation status. Terminal results still require task/output verification.
    """
    if replacement_observed:
        return AllocationState("unknown", may_repeat=True)
    if client_status in {"unknown", "lost"}:
        return AllocationState("unknown", may_repeat=True)
    if client_status == "complete":
        outcome = (
            "timed-out"
            if description == "allocation exceeded max_run_duration"
            else "backend-complete"
        )
        return AllocationState("terminal", outcome)
    if client_status == "failed":
        return AllocationState("terminal", "failed")
    if desired_status == "stop" and client_status in {"pending", "running"}:
        return AllocationState("stopping")
    if desired_status != "run":
        return AllocationState("unknown")
    if client_status == "pending":
        return AllocationState("queued")
    if client_status == "running":
        return AllocationState("running")
    return AllocationState("unknown")
