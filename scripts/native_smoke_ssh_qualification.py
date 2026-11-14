"""Qualify one explicitly selected, independently witnessed SSH setup interruption."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from scripts import native_smoke_ssh as ssh
from scripts.native_smoke_interruption import canary, unique_object
from scripts.validation_timeouts import VARIABLE, Deadline, current, execution_conditions, watchdog

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "owned-smoke-ssh-interruption-only"


def canonical_uuid(value: Any) -> bool:
    return type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).version == 4


def sha(value: Any) -> bool:
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def validate(value: Any, token: str, status: int) -> dict[str, Any]:
    ssh.require(canonical_uuid(token), "ssh-selection-enrollment-unavailable")
    expected = {
        "scope",
        "enrollment",
        "interruption_selected",
        "original_primary_exit",
        "cleanup_exit",
        "injection_observed",
        "native_product_qualified",
        "protected_accounts_before",
        "protected_accounts_after",
        "canary_before",
        "canary_after",
        "refusals_verified",
        "unrelated_canary_preserved",
        "protected_accounts_preserved",
        "before",
        "after",
        "termination",
        "inventory_sha256",
        "status",
    }
    ssh.require(type(value) is dict and set(value) == expected, "ssh-original-outcome-unavailable")
    ssh.require(
        value["scope"] == ssh.SCOPE
        and value["status"] == "failed"
        and value["enrollment"] == token
        and value["native_product_qualified"] is False,
        "ssh-original-outcome-unavailable",
    )
    ssh.require(
        value["interruption_selected"] is value["injection_observed"] is True,
        "ssh-injection-unobserved",
    )
    ssh.require(
        type(status) is int
        and status == ssh.FAULT_STATUS
        and type(value["original_primary_exit"]) is int
        and value["original_primary_exit"] == status
        and type(value["cleanup_exit"]) is int
        and value["cleanup_exit"] == 0,
        "ssh-original-outcome-mismatch",
    )
    ssh.require(
        value["unrelated_canary_preserved"] is value["protected_accounts_preserved"] is True,
        "ssh-preservation-unobserved",
    )
    protected = value["protected_accounts_before"]
    ssh.require(
        type(protected) is dict
        and set(protected) == {"root", "runner"}
        and all(sha(v) for v in protected.values())
        and value["protected_accounts_after"] == protected,
        "ssh-protected-account-changed",
    )
    before = value["canary_before"]
    ssh.require(
        type(before) is dict
        and set(before) == {"device", "inode", "uid", "gid", "mode", "sha256"}
        and all(type(before[k]) is int for k in ("device", "inode", "uid", "gid", "mode"))
        and before["device"] >= 0
        and before["inode"] > 0
        and before["uid"] == before["gid"] == 0
        and before["mode"] == 0o600
        and sha(before["sha256"])
        and value["canary_after"] == before,
        "ssh-canary-changed",
    )
    after = value["canary_after"]
    ssh.require(
        type(after) is dict
        and set(after) == set(before)
        and all(type(after[k]) is int for k in ("device", "inode", "uid", "gid", "mode")),
        "ssh-canary-observation-unavailable",
    )
    ssh.require(
        value["refusals_verified"]
        == [
            "foreign-pid",
            "stale-start-ticks",
            "foreign-actor",
            "foreign-executable",
            "foreign-enrollment",
        ],
        "ssh-refusals-unproved",
    )
    challenges = {token}
    for phase, observations in (
        ("before", {"owned_process", "owned_listener", "owned_arena"}),
        (
            "after",
            {
                "original_process_absent",
                "process_group_absent",
                "session_absent",
                "listener_absent",
                "arena_absent",
            },
        ),
    ):
        item = value[phase]
        ssh.require(
            type(item) is dict
            and set(item)
            == {
                "scope",
                "observer_uid",
                "phase",
                "status",
                "challenge",
                "enrollment",
                "identity",
                "listener",
                "observer_pid",
                "observer_parent_pid",
                "inventory_sha256",
                "observations",
                "native_product_qualified",
            },
            "ssh-independent-witness-unavailable",
        )
        ssh.require(
            item["scope"] == ssh.SCOPE
            and type(item["observer_uid"]) is int
            and item["observer_uid"] == 0
            and item["phase"] == phase
            and item["status"] == "observed"
            and item["enrollment"] == token
            and item["native_product_qualified"] is False
            and sha(item["inventory_sha256"])
            and item["inventory_sha256"] == value["inventory_sha256"]
            and canonical_uuid(item["challenge"])
            and item["challenge"] not in challenges,
            "ssh-independent-witness-mismatch",
        )
        identity = ssh.identity_record(item["identity"])
        listener = ssh.listener_record(item["listener"])
        ssh.require(
            identity["enrollment"] == token
            and type(item["observer_pid"]) is int
            and item["observer_pid"] > 0
            and item["observer_pid"] not in {identity["pid"], identity["parent_pid"]}
            and type(item["observer_parent_pid"]) is int
            and item["observer_parent_pid"] == identity["parent_pid"],
            "ssh-observer-custody-mismatch",
        )
        if phase == "after":
            ssh.require(
                identity == value["before"]["identity"] and listener == value["before"]["listener"],
                "ssh-observed-custody-changed",
            )
        challenges.add(item["challenge"])
        ssh.require(
            type(item["observations"]) is dict
            and set(item["observations"]) == observations
            and all(v is True for v in item["observations"].values()),
            "ssh-independent-absence-unproved",
        )
    termination = value["termination"]
    ssh.require(
        type(termination) is dict
        and set(termination)
        == {"pid", "parent_pid", "returncode", "exit_observed", "reaped", "stale_handle_refused"}
        and type(termination["pid"]) is int
        and termination["pid"] == value["before"]["identity"]["pid"]
        and type(termination["parent_pid"]) is int
        and termination["parent_pid"] == value["before"]["identity"]["parent_pid"]
        and type(termination["returncode"]) is int
        and termination["returncode"] in {0, -15}
        and all(
            termination[k] is True for k in ("exit_observed", "reaped", "stale_handle_refused")
        ),
        "ssh-owned-child-reaping-unobserved",
    )
    result: dict[str, Any] = value
    return result


def run(directory: Path, end: float) -> dict[str, Any]:
    from scripts.run_stats import RunStats, valid_stats

    measurement = RunStats()
    cleanup_grace = Deadline(end + watchdog(5))
    ssh.remaining(end)
    token = str(uuid.uuid4())
    report: dict[str, Any] = {
        "scope": SCOPE,
        "status": "failed",
        "selection_enrollment": token,
        "native_product_qualified": False,
    }
    path = directory / "unrelated"
    path.write_bytes(os.urandom(32))
    path.chmod(0o600)
    original = canary(path)
    report["canary_before"] = original
    try:
        contact = current().units(30, unit_seconds=1, maximum=2147483647)
        root_remaining = ssh.remaining(end)
        result = subprocess.run(
            [
                "sudo",
                "-n",
                "timeout",
                "-k",
                str(watchdog(5)),
                str(root_remaining),
                "/usr/bin/env",
                "GITHUB_ACTIONS=true",
                "RUNNER_ENVIRONMENT=github-hosted",
                "ImageOS=ubuntu24",
                VARIABLE + "=" + str(current().scale),
                "/usr/bin/python3",
                "-m",
                "scripts.native_smoke_ssh",
                "--github-hosted-only",
                "interrupt-after-listener",
                str(end),
                str(contact),
                token,
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=cleanup_grace.remaining(),
        )
        report.update(
            original_root_exit_status=result.returncode,
            original_root_stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
        )
        outcome = validate(
            json.loads(result.stdout, object_pairs_hook=unique_object), token, result.returncode
        )
        report.update(
            original_root_exit_status=result.returncode,
            original_root_outcome=outcome,
            original_root_stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
        )
        report["canary_after"] = canary(path)
        ssh.require(report["canary_after"] == original, "ssh-outer-canary-changed")
        report["status"] = "passed"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        report["reason"] = "ssh-interruption-evidence-unavailable"
    finally:
        try:
            report["canary_before_removal"] = canary(path)
            ssh.require(report["canary_before_removal"] == original, "ssh-outer-canary-changed")
            path.unlink()
            report["owned_canary_removed"] = not path.exists() and not path.is_symlink()
            ssh.require(report["owned_canary_removed"], "ssh-outer-canary-removal-unobserved")
        except (OSError, ValueError):
            report.update(status="failed", reason="ssh-outer-canary-unobserved")
        report["statistics"] = measurement.finish()
        if not valid_stats(report["statistics"]):
            report.update(status="failed", reason="ssh-parent-statistics-unavailable")
    return report


def main(arguments: list[str] | None = None) -> int:
    args = sys.argv[1:] if arguments is None else arguments
    try:
        ssh.require(sys.platform == "linux", "explicit-hosted-enrollment-required")
        ssh.require(
            args[:1] == ["--github-hosted-only"]
            and len(args) == 3
            and args[1] == "--output"
            and os.geteuid() != 0,
            "explicit-hosted-enrollment-required",
        )
        ssh.require(
            all(
                os.environ.get(k) == v
                for k, v in (
                    ("GITHUB_ACTIONS", "true"),
                    ("RUNNER_ENVIRONMENT", "github-hosted"),
                    ("ImageOS", "ubuntu24"),
                )
            ),
            "explicit-hosted-enrollment-required",
        )
        ssh.require(
            os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") in {"push", "workflow_dispatch"},
            "main-only-hosted-enrollment-required",
        )
        from scripts.check_evidence import execution_origin
        from scripts.validation import source_identity

        origin = execution_origin()
        ssh.require(
            origin.get("kind") == "github-actions" and origin.get("job") == "native-prerequisites",
            "explicit-hosted-enrollment-required",
        )
        conditions = execution_conditions()
        outer = conditions["job_watchdog"]
        ssh.require(
            outer is not None
            and outer["nominal_minutes"] == 25
            and outer["effective_minutes"] == math.ceil(25 * current().scale),
            "outer-watchdog-required",
        )
        source = source_identity(ROOT)
        ssh.require(source["clean"], "clean-source-required")
        with tempfile.TemporaryDirectory(
            prefix="fishhat-ssh-interruption-", dir=os.environ["RUNNER_TEMP"]
        ) as temporary:
            report = run(Path(temporary), Deadline.after(120).end)
        report.update(
            source_before=source,
            source_after=source_identity(ROOT),
            execution_origin=origin,
            conditions=conditions,
            outer_directory_absent=not Path(temporary).exists()
            and not Path(temporary).is_symlink(),
        )
        if (
            report["source_after"] != source
            or not report["outer_directory_absent"]
            or report.get("owned_canary_removed") is not True
        ):
            report.update(status="failed", reason="ssh-source-or-outer-cleanup-unverified")
        output = Path(args[2])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(
            json.dumps(
                {"scope": SCOPE, "status": report["status"], "native_product_qualified": False}
            )
        )
        return 0 if report["status"] == "passed" else 1
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print(
            "Refusing: independent hosted SSH interruption evidence unavailable.", file=sys.stderr
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
