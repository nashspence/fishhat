"""Select and independently account for interruption after admitted XFS setup."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from scripts import native_smoke_interruption as channel
from scripts import native_smoke_storage as storage
from scripts.native_smoke_loop import live, require, same_claim, token
from scripts.native_smoke_mount import directory_record, namespace_record
from scripts.validation_timeouts import Deadline, current, execution_conditions, watchdog

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "owned-smoke-storage-interruption-only"


def checkpoint(enrollment: str, descriptor: int, claim: Any, end: float) -> None:
    token(enrollment)
    live(end)
    require(descriptor > 2 and os.geteuid() != 0, "storage-checkpoint-unavailable")
    require(
        type(claim) is dict and claim.get("enrollment") == enrollment,
        "storage-checkpoint-claim-unavailable",
    )
    with socket.socket(fileno=descriptor) as peer:
        require(
            peer.family == socket.AF_UNIX and peer.type == socket.SOCK_STREAM,
            "storage-checkpoint-channel-unavailable",
        )
        channel.send(
            peer,
            {"enrollment": enrollment, "shell_pid": os.getppid(), "claim": claim, "end": end},
            end,
        )
        require(
            same_claim(
                channel.receive(peer, end),
                {
                    "enrollment": enrollment,
                    "claim_sha256": channel.digest(claim),
                    "permit": "interrupt-after-storage",
                },
            ),
            "storage-checkpoint-permission-unavailable",
        )


def validate(
    report: Any, enrollment: str, claim: dict[str, Any], status: int, *, interrupted: bool = True
) -> dict[str, Any]:
    from scripts.run_stats import valid_stats

    token(enrollment)
    if type(report) is not dict:
        raise ValueError("storage-root-outcome-unavailable")
    require(
        report.get("scope") == storage.SCOPE
        and type(report.get("evidence_validation_exit")) is int
        and report["evidence_validation_exit"] == 0
        and report.get("enrollment") == enrollment
        and report.get("native_product_qualified") is False
        and type(status) is int
        and status == (storage.FAULT_STATUS if interrupted else 0)
        and type(report.get("original_primary_exit")) is int
        and report["original_primary_exit"] == status
        and type(report.get("cleanup_exit")) is int
        and report["cleanup_exit"] == 0
        and report.get("completed_stages")
        == (["setup"] if interrupted else ["setup", "bytes", "inodes"])
        and report.get("claim_sha256") == channel.digest(claim)
        and same_claim(report.get("retained_identity"), claim)
        and valid_stats(report.get("statistics")),
        "storage-original-outcome-mismatch",
    )
    namespace_record(claim["namespace"])
    directory_record(claim["mount"]["directory"])
    owner_pid = None
    for phase in ("before", "after", "retired"):
        observed = report[phase]
        require(type(observed) is dict, "storage-root-observation-unavailable")
        expected_present = phase == "before"
        require(
            observed.get("phase") == phase
            and observed.get("enrollment") == enrollment
            and same_claim(observed.get("namespace"), claim["namespace"])
            and observed.get("observation_complete") is True
            and observed.get("identity_sha256") == channel.digest(claim)
            and observed.get("association_observation")
            == ("bound" if phase == "before" else "ENXIO")
            and all(
                observed.get(role + "_present") is expected_present
                for role in ("association", "mount", "image")
            )
            and re.fullmatch("[0-9a-f]{64}", observed.get("inventory_sha256", "")) is not None,
            "storage-root-absence-unobserved",
        )
        if phase == "retired":
            require(observed.get("arena_absent") is True, "storage-arena-absence-unobserved")
        else:
            require(
                observed.get("unrelated_image_preserved") is True,
                "storage-image-preservation-unobserved",
            )
        actor = root_actor(observed["observer"])
        if owner_pid is None:
            owner_pid = actor["parent_pid"]
        require(actor["parent_pid"] == owner_pid, "storage-root-owner-changed")
    before, after = report["parent_before"], report["parent_after"]
    for value in (before, after):
        namespace_record(value["parent_namespace"])
        require(
            root_actor(value["observer"])["parent_pid"] == owner_pid,
            "storage-parent-observer-changed",
        )
    require(
        before["baseline_mounts_preserved"] is after["baseline_mounts_preserved"] is True
        and before["owned_mount_absent"] is after["owned_mount_absent"] is True
        and same_claim(before["parent_namespace"], after["parent_namespace"])
        and not same_claim(before["parent_namespace"], claim["namespace"])
        and before["baseline_sha256"] == after["baseline_sha256"]
        and re.fullmatch("[0-9a-f]{64}", before["baseline_sha256"]) is not None,
        "storage-parent-mount-preservation-unobserved",
    )
    source = report["source_before"]
    require(
        type(source) is dict
        and set(source) == {"commit", "clean", "fingerprint"}
        and source["clean"] is True
        and same_claim(source, report["source_after"])
        and re.fullmatch("[0-9a-f]{40}", source["commit"]) is not None
        and re.fullmatch("[0-9a-f]{64}", source["fingerprint"]) is not None,
        "storage-source-binding-unavailable",
    )
    origin = report["execution_origin"]
    require(
        type(origin) is dict
        and set(origin) == {"kind", "run_id", "attempt", "job"}
        and origin["kind"] == "github-actions"
        and origin["job"] == "native-prerequisites"
        and all(
            type(origin[key]) is str
            and origin[key].isascii()
            and origin[key].isdecimal()
            and int(origin[key]) > 0
            for key in ("run_id", "attempt")
        ),
        "storage-origin-binding-unavailable",
    )
    if not interrupted:
        require(
            report["bytes"]["quota_enforced"] is True
            and type(report["bytes"]["admitted_bytes"]) is int
            and 0 < report["bytes"]["admitted_bytes"] <= 8 * 1048576
            and type(report["bytes"]["control_bytes"]) is int
            and report["bytes"]["control_bytes"] == 16 * 1048576,
            "storage-byte-workload-unavailable",
        )
        require(
            report["inodes"]["quota_enforced"] is True
            and type(report["inodes"]["admitted_files"]) is int
            and 0 < report["inodes"]["admitted_files"] < 64
            and type(report["inodes"]["control_files"]) is int
            and report["inodes"]["control_files"] == 256,
            "storage-inode-workload-unavailable",
        )
    return report


def root_actor(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError("storage-root-observer-unavailable")
    require(
        set(value)
        == {"pid", "parent_pid", "process_group", "session", "start_ticks", "uids", "gids"}
        and all(
            type(value.get(key)) is int and value[key] > 0
            for key in ("pid", "parent_pid", "process_group", "session", "start_ticks")
        ),
        "storage-root-observer-unavailable",
    )
    for role in ("uids", "gids"):
        require(
            type(value[role]) is list
            and len(value[role]) == 4
            and all(type(item) is int and item == 0 for item in value[role]),
            "storage-root-observer-credentials-unavailable",
        )
    return value


def transcript(raw: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    stages = []
    outcomes = []
    for line in raw.decode("utf-8").splitlines():
        match = re.fullmatch(
            r"native-prerequisite stage=([a-z-]+) status=(passed|failed) exit=([0-9]+) elapsed_seconds=([0-9]+)",
            line,
        )
        if match:
            stages.append(
                {
                    "stage": match[1],
                    "status": match[2],
                    "exit": int(match[3]),
                    "elapsed_seconds": int(match[4]),
                }
            )
        prefix = "native-prerequisite storage-observation="
        if line.startswith(prefix):
            outcomes.append(
                json.loads(line[len(prefix) :], object_pairs_hook=channel.unique_object)
            )
    expected = [
        "package-update",
        "package-install",
        "account",
        "rootless-runtime",
        "cgroup-controls",
        "quadlet",
        "xfs-setup",
        "cleanup",
    ]
    require([entry["stage"] for entry in stages] == expected, "storage-selected-stages-unavailable")
    for entry in stages:
        failed = entry["stage"] == "xfs-setup"
        require(
            entry["status"] == ("failed" if failed else "passed")
            and entry["exit"] == (storage.FAULT_STATUS if failed else 0),
            "storage-selected-stage-outcome-mismatch",
        )
    require(
        len(outcomes) == 1 and type(outcomes[0]) is dict,
        "storage-original-root-receipt-unavailable",
    )
    return stages, outcomes[0]


def run(directory: Path, end: float) -> dict[str, Any]:
    from scripts.run_stats import RunStats, valid_stats

    measurement = RunStats()
    enrollment = str(uuid.uuid4())
    report: dict[str, Any] = {
        "scope": SCOPE,
        "selection_enrollment": enrollment,
        "status": "failed",
        "native_product_qualified": False,
    }
    canary = directory / "unrelated"
    canary.write_bytes(os.urandom(32))
    canary.chmod(0o600)
    before = channel.canary(canary)
    report["canary_before"] = before
    parent, child = socket.socketpair()
    process = None
    with tempfile.TemporaryFile(dir=directory) as output:
        try:
            process = subprocess.Popen(
                [
                    "bash",
                    str(ROOT / "scripts/ci/native_smoke.sh"),
                    "--github-hosted-only",
                    "--interrupt-after-storage",
                    enrollment,
                    str(child.fileno()),
                ],
                cwd=ROOT,
                stdout=output,
                stderr=subprocess.STDOUT,
                pass_fds=(child.fileno(),),
            )
            child.close()
            request = channel.receive(parent, end)
            require(
                type(request) is dict
                and set(request) == {"enrollment", "shell_pid", "claim", "end"},
                "storage-selection-request-unavailable",
            )
            require(
                request["enrollment"] == enrollment
                and type(request["shell_pid"]) is int
                and request["shell_pid"] == process.pid,
                "storage-selection-actor-unavailable",
            )
            observed_end = request["end"]
            live(observed_end)
            require(
                observed_end <= end and type(request["claim"]) is dict,
                "storage-selection-deadline-unavailable",
            )
            claim = request["claim"]
            require(claim.get("enrollment") == enrollment, "storage-selected-claim-unavailable")
            channel.send(
                parent,
                {
                    "enrollment": enrollment,
                    "claim_sha256": channel.digest(claim),
                    "permit": "interrupt-after-storage",
                },
                observed_end,
            )
            observation_deadline = Deadline(end)
            status = process.wait(timeout=observation_deadline.remaining())
            report["original_exit_status"] = status
            output.seek(0)
            original = output.read()
            report["original_transcript_sha256"] = hashlib.sha256(original).hexdigest()
            stages, root = transcript(original)
            report["original_stages"] = stages
            report["original_root_outcome"] = validate(root, enrollment, claim, status)
            report["original_cleanup_passed"] = True
            report["canary_after"] = channel.canary(canary)
            require(report["canary_after"] == before, "storage-outer-canary-changed")
            report["status"] = "passed"
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            report["problem"] = "storage-interruption-evidence-unavailable"
        finally:
            parent.close()
            child.close()
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=watchdog(5))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=watchdog(5))
                report["status"] = "failed"
            try:
                require(channel.canary(canary) == before, "storage-canary-changed")
                canary.unlink()
                report["owned_canary_removed"] = storage.path_absent(canary)
                require(report["owned_canary_removed"], "storage-canary-remains")
            except (OSError, ValueError):
                report.update(status="failed", problem="storage-outer-cleanup-unverified")
            report["statistics"] = measurement.finish()
            if not valid_stats(report["statistics"]):
                report.update(status="failed", problem="storage-statistics-unavailable")
    return report


def main(arguments: list[str] | None = None) -> int:
    args = sys.argv[1:] if arguments is None else arguments
    try:
        if args[:1] == ["checkpoint"]:
            require(len(args) == 5, "storage-checkpoint-selection-unavailable")
            checkpoint(
                args[1],
                int(args[2]),
                json.loads(args[3], object_pairs_hook=channel.unique_object),
                float(args[4]),
            )
            return 0
        require(
            sys.platform == "linux"
            and args[:2] == ["--github-hosted-only", "--output"]
            and len(args) == 3
            and os.geteuid() != 0,
            "storage-hosted-enrollment-required",
        )
        require(
            all(
                os.environ.get(key) == value
                for key, value in (
                    ("GITHUB_ACTIONS", "true"),
                    ("RUNNER_ENVIRONMENT", "github-hosted"),
                    ("ImageOS", "ubuntu24"),
                    ("GITHUB_REF", "refs/heads/main"),
                )
            ),
            "storage-hosted-enrollment-required",
        )
        require(
            os.environ.get("GITHUB_EVENT_NAME") in {"push", "workflow_dispatch"},
            "storage-main-enrollment-required",
        )
        from scripts.check_evidence import execution_origin
        from scripts.validation import source_identity

        origin = execution_origin()
        require(
            origin.get("kind") == "github-actions" and origin.get("job") == "native-prerequisites",
            "storage-origin-unavailable",
        )
        conditions = execution_conditions()
        outer = conditions["job_watchdog"]
        require(
            outer is not None
            and outer["nominal_minutes"] == 25
            and outer["effective_minutes"] == math.ceil(25 * current().scale),
            "storage-outer-watchdog-required",
        )
        source = source_identity(ROOT)
        require(source["clean"], "storage-clean-source-required")
        with tempfile.TemporaryDirectory(
            prefix="fishhat-storage-interruption-", dir=os.environ["RUNNER_TEMP"]
        ) as temporary:
            report = run(Path(temporary), time.monotonic() + outer["effective_minutes"] * 60)
        report.update(
            source_before=source,
            source_after=source_identity(ROOT),
            execution_origin=origin,
            conditions=conditions,
            outer_directory_absent=storage.path_absent(Path(temporary)),
        )
        root = report.get("original_root_outcome", {})
        if (
            report["source_after"] != source
            or report["outer_directory_absent"] is not True
            or root.get("source_before") != source
            or root.get("source_after") != source
            or root.get("execution_origin") != origin
        ):
            report.update(status="failed", problem="storage-source-or-origin-unavailable")
        output = Path(args[2])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(
            json.dumps(
                {"scope": SCOPE, "status": report["status"], "native_product_qualified": False}
            )
        )
        return 0 if report["status"] == "passed" else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(
            "Refusing: independently witnessed hosted storage interruption unavailable.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
