"""Independently witness one explicitly enrolled pre-manager smoke interruption."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from scripts import native_smoke_cleanup as cleanup
from scripts.validation_timeouts import Deadline, execution_conditions, watchdog

SCOPE = "owned-smoke-pre-manager-interruption-only"
FAULT_STATUS = 73
ROOT = Path(__file__).resolve().parents[1]


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def identity_record(identity: cleanup.Identity) -> dict[str, Any]:
    return {
        "account": identity.account,
        "uid": identity.uid,
        "gid": identity.gid,
        "work": str(identity.work),
    }


def identity_from(value: Any) -> cleanup.Identity:
    if type(value) is not dict or set(value) != {"account", "uid", "gid", "work"}:
        raise ValueError("interruption-identity-unavailable")
    if type(value["account"]) is not str or type(value["work"]) is not str:
        raise ValueError("interruption-identity-unavailable")
    identity = cleanup.Identity(value["account"], value["uid"], value["gid"], Path(value["work"]))
    if not identity.valid() or str(identity.work) != value["work"]:
        raise ValueError("interruption-identity-unavailable")
    return identity


def enrollment(value: str) -> str:
    if str(uuid.UUID(value)) != value:
        raise ValueError("interruption-enrollment-unavailable")
    return value


def deadline(end: float) -> Deadline:
    if not math.isfinite(end) or not 0 < end - time.monotonic() <= threading.TIMEOUT_MAX:
        raise ValueError("interruption-deadline-unavailable")
    return Deadline(end)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("ambiguous-interruption-record")
        value[key] = item
    return value


def receive(channel: socket.socket, end: float) -> Any:
    deadline(end)
    timer = Deadline(end)
    parts = []
    while True:
        remaining = timer.remaining()
        if remaining <= 0:
            raise TimeoutError("interruption-deadline-expired")
        channel.settimeout(remaining)
        part = channel.recv(4096)
        if not part:
            raise ValueError("interruption-channel-unavailable")
        parts.append(part)
        if b"\n" in part:
            if not part.endswith(b"\n") or part.count(b"\n") != 1:
                raise ValueError("interruption-channel-unavailable")
            return json.loads(b"".join(parts), object_pairs_hook=unique_object)


def send(channel: socket.socket, value: Any, end: float) -> None:
    deadline(end)
    timer = Deadline(end)
    channel.settimeout(timer.remaining())
    channel.sendall(json.dumps(value, sort_keys=True).encode() + b"\n")


def checkpoint(token: str, descriptor: int, identity: cleanup.Identity, end: float) -> None:
    enrollment(token)
    if descriptor <= 2 or os.geteuid() == 0 or identity.account != f"dtci{os.geteuid()}":
        raise ValueError("interruption-channel-unavailable")
    identity = identity_from(identity_record(identity))
    with socket.socket(fileno=descriptor) as channel:
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_STREAM:
            raise ValueError("interruption-channel-unavailable")
        send(
            channel,
            {
                "enrollment": token,
                "shell_pid": os.getppid(),
                "identity": identity_record(identity),
                "end": end,
            },
            end,
        )
        reply = receive(channel, end)
        if reply != {
            "enrollment": token,
            "identity_sha256": digest(identity_record(identity)),
            "permit": "inject-before-manager",
        }:
            raise ValueError("interruption-permission-unavailable")


def protected_accounts(identity: cleanup.Identity, end: float) -> dict[str, str]:
    result = {}
    for role, uid in (("root", 0), ("runner", int(identity.account[4:]))):
        account = cleanup.lookup("passwd", str(uid), end)
        if (
            account is None
            or int(account[2]) != uid
            or uid == identity.uid
            or int(account[3]) == identity.gid
        ):
            raise ValueError("protected-account-unavailable")
        group = cleanup.lookup("group", account[3], end)
        if group is None or group[2] != account[3]:
            raise ValueError("protected-group-unavailable")
        result[role] = digest([account, group])
    return result


def before(identity: cleanup.Identity, end: float, paths: cleanup.Paths) -> dict[str, Any]:
    state = cleanup.teardown_state(identity, end, False, paths)
    if (
        not state.get("state_verified")
        or state.get("account") != "owned"
        or any(state["states"].values())
    ):
        raise ValueError("pre-manager-state-unavailable")
    owned = cleanup.owned_paths(identity, paths)
    generator = owned["generator"].lstat()
    home = owned["home"].lstat()
    temporary = (owned["home"] / "tmp").lstat()
    work = owned["work"].lstat()
    if not (
        stat.S_ISREG(generator.st_mode)
        and generator.st_uid == generator.st_gid == 0
        and stat.S_IMODE(generator.st_mode) == 0o755
        and all(
            stat.S_ISDIR(v.st_mode) and v.st_uid == identity.uid and v.st_gid == identity.gid
            for v in (home, temporary)
        )
        and stat.S_ISDIR(work.st_mode)
        and work.st_uid == int(identity.account[4:])
        and stat.S_IMODE(work.st_mode) == 0o700
    ):
        raise ValueError("pre-manager-custody-unavailable")
    return {
        "state": state,
        "generator_owned": True,
        "home_owned": True,
        "work_owned": True,
        "protected_accounts": protected_accounts(identity, end),
    }


def absence(value: Any, identity: cleanup.Identity) -> bool:
    roles = [
        "account-name",
        "account-uid",
        "group-name",
        "group-gid",
        "login-user",
        "user-manager",
        "runtime-manager",
        "process-credentials",
        *cleanup.owned_paths(identity, cleanup.Paths()),
        "subuid",
        "subgid",
    ]
    return bool(
        type(value) is dict
        and set(value)
        == {
            "scope",
            "observer_uid",
            "status",
            "measurement_scope",
            "observations",
            "complete_absence_verified",
            "native_qualified",
        }
        and value.get("scope") == "owned-smoke-cleanup-observation-only"
        and type(value.get("observer_uid")) is int
        and value["observer_uid"] == 0
        and value.get("complete_absence_verified") is True
        and value.get("status") == "absent"
        and value.get("native_qualified") is False
        and value.get("measurement_scope")
        == "exact owned identity and read-only system/process/filesystem observations"
        and value.get("observations") == [{"role": r, "status": "absent"} for r in roles]
    )


def observe(
    mode: str, identity: cleanup.Identity, end: float, paths: cleanup.Paths | None = None
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "scope": SCOPE,
        "observer_uid": os.geteuid(),
        "identity_sha256": digest(identity_record(identity)),
        "status": "unavailable",
        "native_qualified": False,
    }
    try:
        identity_from(identity_record(identity))
        deadline(end)
        if os.geteuid() != 0 or mode not in {"before", "after"}:
            raise ValueError("root-observer-required")
        paths = cleanup.Paths() if paths is None else paths
        if mode == "before":
            result.update(before(identity, end, paths))
        else:
            value = cleanup.observe_once(identity, end, paths)
            if not absence(value, identity):
                raise ValueError("independent-absence-unavailable")
            result.update(cleanup=value, protected_accounts=protected_accounts(identity, end))
        result["status"] = "observed"
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        pass
    return result


def root_observation(mode: str, identity: cleanup.Identity, end: float) -> dict[str, Any]:
    deadline(end)
    timer = Deadline(end)
    result = subprocess.run(
        [
            "sudo",
            "-n",
            "/usr/bin/python3",
            "-m",
            "scripts.native_smoke_interruption",
            "observe-" + mode,
            identity.account,
            str(identity.uid),
            str(identity.gid),
            str(identity.work),
            str(end),
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=timer.remaining(),
    )
    if result.returncode != 0:
        raise ValueError("independent-observation-unavailable")
    value = json.loads(result.stdout, object_pairs_hook=unique_object)
    expected = {
        "scope",
        "observer_uid",
        "identity_sha256",
        "status",
        "native_qualified",
        "protected_accounts",
    }
    expected.update(
        {"state", "generator_owned", "home_owned", "work_owned"}
        if mode == "before"
        else {"cleanup"}
    )
    if not (
        type(value) is dict
        and set(value) == expected
        and value.get("scope") == SCOPE
        and value.get("status") == "observed"
        and type(value.get("observer_uid")) is int
        and value["observer_uid"] == 0
        and value.get("identity_sha256") == digest(identity_record(identity))
        and value.get("native_qualified") is False
    ):
        raise ValueError("independent-observation-unavailable")
    return value


def transcript_events(raw: bytes) -> list[str]:
    pattern = re.compile(
        r"native-prerequisite (?:stage|control)=[a-z0-9-]+ status=(?:started|passed|failed)(?: budget_nominal_seconds=[0-9]+| exit=[0-9]+(?: elapsed_seconds=[0-9]+)?)?"
    )
    return [line for line in raw.decode(errors="replace").splitlines() if pattern.fullmatch(line)]


def validate_events(events: list[str], status: int) -> None:
    if status != FAULT_STATUS:
        raise ValueError("original-interruption-status-unavailable")
    controls = [
        "account-create",
        "generator-directory-check",
        "generator-write",
        "generator-mode",
        "generator-metadata",
        "pre-manager-custody",
        "pre-manager-injection",
        "cleanup-state-initial",
        "cleanup-state-before-stop",
        "cleanup-state-settlement",
        "cleanup-account-remove",
        "cleanup-generator-remove",
        "cleanup-work-remove",
        "cleanup-observation",
    ]
    actual_controls = [line for line in events if line.startswith("native-prerequisite control=")]
    expected = []
    for name in controls:
        expected.append(f"native-prerequisite control={name} status=started")
        outcome = "failed exit=73" if name == "pre-manager-injection" else "passed exit=0"
        expected.append(f"native-prerequisite control={name} status={outcome}")
    if actual_controls != expected:
        raise ValueError("original-interruption-controls-unavailable")
    actual_stages = [line for line in events if line.startswith("native-prerequisite stage=")]
    expected_stages = []
    for name, budget in (
        ("package-update", 300),
        ("package-install", 600),
        ("account", 120),
        ("cleanup", 120),
    ):
        expected_stages.append(
            f"native-prerequisite stage={name} status=started budget_nominal_seconds={budget}"
        )
        outcome = "failed exit=73" if name == "account" else "passed exit=0"
        expected_stages.append(
            f"native-prerequisite stage={name} status={outcome} elapsed_seconds="
        )
    if len(actual_stages) != len(expected_stages) or any(
        (not actual.startswith(wanted) or not actual[len(wanted) :].isdigit())
        if "elapsed_seconds=" in wanted
        else actual != wanted
        for actual, wanted in zip(actual_stages, expected_stages, strict=True)
    ):
        raise ValueError("original-interruption-stages-unavailable")
    positions = {line: index for index, line in enumerate(events)}
    account_start, account_end = (positions[actual_stages[i]] for i in (4, 5))
    cleanup_start, cleanup_end = (positions[actual_stages[i]] for i in (6, 7))
    if not account_end < cleanup_start:
        raise ValueError("original-interruption-order-unavailable")
    for line in actual_controls:
        start, end = (
            (cleanup_start, cleanup_end)
            if " control=cleanup-" in line
            else (account_start, account_end)
        )
        if not start < positions[line] < end:
            raise ValueError("original-interruption-order-unavailable")


def canary(path: Path) -> dict[str, Any]:
    value = path.lstat()
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.geteuid()
        or stat.S_IMODE(value.st_mode) != 0o600
    ):
        raise ValueError("unrelated-canary-unavailable")
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": stat.S_IMODE(value.st_mode),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def run(end: float, directory: Path) -> dict[str, Any]:
    from scripts.run_stats import RunStats

    deadline(end)
    timer = Deadline(end)
    measurement = RunStats()
    token = str(uuid.uuid4())
    result: dict[str, Any] = {
        "scope": SCOPE,
        "enrollment": token,
        "status": "failed",
        "native_product_qualified": False,
    }
    canary_path = directory / "unrelated"
    canary_path.write_bytes(os.urandom(32))
    canary_path.chmod(0o600)
    original_canary = canary(canary_path)
    result["canary_before"] = original_canary
    parent, child_channel = socket.socketpair()
    process = None
    transcript = tempfile.TemporaryFile(dir=directory)
    try:
        process = subprocess.Popen(
            [
                "bash",
                str(ROOT / "scripts/ci/native_smoke.sh"),
                "--github-hosted-only",
                "--interrupt-before-manager",
                token,
                str(child_channel.fileno()),
            ],
            cwd=ROOT,
            stdout=transcript,
            stderr=subprocess.STDOUT,
            pass_fds=(child_channel.fileno(),),
        )
        child_channel.close()
        request = receive(parent, timer.end)
        if type(request) is not dict or set(request) != {
            "enrollment",
            "shell_pid",
            "identity",
            "end",
        }:
            raise ValueError("interruption-request-unavailable")
        identity = identity_from(request["identity"])
        if (
            request["enrollment"] != token
            or type(request["shell_pid"]) is not int
            or request["shell_pid"] != process.pid
            or identity.account != f"dtci{os.geteuid()}"
        ):
            raise ValueError("interruption-request-unavailable")
        if (
            type(request["end"]) not in {int, float}
            or not math.isfinite(request["end"])
            or not time.monotonic() < request["end"] <= timer.end
        ):
            raise ValueError("interruption-deadline-unavailable")
        observed_end = float(request["end"])
        before_value = root_observation("before", identity, observed_end)
        state = before_value.get("state", {})
        expected_state = {
            "scope": "owned-smoke-teardown-state-only",
            "observer_uid": 0,
            "status": "observed",
            "state_verified": True,
            "native_qualified": False,
            "account": "owned",
            "states": {
                role: False
                for role in (
                    "manager",
                    "runtime",
                    "login",
                    "linger",
                    "service_stop_required",
                    "processes",
                )
            },
        }
        if not (
            state == expected_state
            and state.get("state_verified") is True
            and state.get("native_qualified") is False
            and type(state.get("observer_uid")) is int
            and all(type(v) is bool for v in state.get("states", {}).values())
            and all(
                before_value.get(key) is True
                for key in ("generator_owned", "home_owned", "work_owned")
            )
        ):
            raise ValueError("independent-before-state-unavailable")
        accounts = before_value.get("protected_accounts")
        if (
            type(accounts) is not dict
            or set(accounts) != {"root", "runner"}
            or any(
                type(v) is not str or re.fullmatch("[0-9a-f]{64}", v) is None
                for v in accounts.values()
            )
        ):
            raise ValueError("protected-account-evidence-unavailable")
        send(
            parent,
            {
                "enrollment": token,
                "identity_sha256": digest(identity_record(identity)),
                "permit": "inject-before-manager",
            },
            observed_end,
        )
        observation_deadline = Deadline(observed_end)
        status = process.wait(timeout=observation_deadline.remaining())
        transcript.seek(0)
        raw = transcript.read()
        events = transcript_events(raw)
        validate_events(events, status)
        after_value = root_observation("after", identity, observed_end)
        if not absence(after_value.get("cleanup"), identity) or before_value[
            "protected_accounts"
        ] != after_value.get("protected_accounts"):
            raise ValueError("independent-after-state-unavailable")
        result["canary_after"] = canary(canary_path)
        if result["canary_after"] != original_canary:
            raise ValueError("unrelated-canary-changed")
        result.update(
            status="passed",
            identity_sha256=digest(identity_record(identity)),
            original_exit_status=status,
            original_events=events,
            original_events_sha256=digest(events),
            original_transcript_sha256=hashlib.sha256(raw).hexdigest(),
            before=before_value,
            after=after_value,
            unrelated_canary_preserved=True,
            protected_accounts_preserved=True,
            original_primary_failure_preserved=True,
            original_cleanup_passed=True,
        )
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        result["reason"] = "independent-interruption-evidence-unavailable"
    finally:
        parent.close()
        child_channel.close()
        if process is not None and process.poll() is None:
            try:
                process.wait(timeout=timer.remaining())
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=watchdog(5))
        if process is not None:
            transcript.seek(0)
            raw = transcript.read()
            result.update(
                original_exit_status=process.returncode,
                original_events=transcript_events(raw),
                original_transcript_sha256=hashlib.sha256(raw).hexdigest(),
            )
            result["original_events_sha256"] = digest(result["original_events"])
        transcript.close()
        try:
            result["canary_before_removal"] = canary(canary_path)
            if result["canary_before_removal"] != original_canary:
                raise ValueError("unrelated-canary-changed")
            canary_path.unlink()
            result["owned_canary_removed"] = (
                not canary_path.exists() and not canary_path.is_symlink()
            )
            if not result["owned_canary_removed"]:
                raise ValueError("canary-removal-unavailable")
        except (OSError, ValueError):
            result.update(
                status="failed", reason="unrelated-canary-changed", owned_canary_removed=False
            )
        result["statistics"] = measurement.finish()
    return result


def main(arguments: list[str] | None = None) -> int:
    args = sys.argv[1:] if arguments is None else arguments
    try:
        if args[:1] == ["checkpoint"] and len(args) == 8:
            identity = cleanup.Identity(args[3], int(args[4]), int(args[5]), Path(args[6]))
            checkpoint(args[1], int(args[2]), identity, float(args[7]))
            return 0
        if args[:1] in (["observe-before"], ["observe-after"]) and len(args) == 6:
            identity = cleanup.Identity(args[1], int(args[2]), int(args[3]), Path(args[4]))
            value = observe(args[0].removeprefix("observe-"), identity, float(args[5]))
            print(json.dumps(value, sort_keys=True))
            return 0 if value["status"] == "observed" else 1
        if (
            args[:1] != ["--github-hosted-only"]
            or len(args) != 3
            or args[1] != "--output"
            or os.geteuid() == 0
        ):
            raise ValueError("explicit-hosted-enrollment-required")
        if any(
            os.environ.get(key) != value
            for key, value in (
                ("GITHUB_ACTIONS", "true"),
                ("RUNNER_ENVIRONMENT", "github-hosted"),
                ("ImageOS", "ubuntu24"),
            )
        ):
            raise ValueError("explicit-hosted-enrollment-required")
        if os.environ.get("GITHUB_REF") != "refs/heads/main" or os.environ.get(
            "GITHUB_EVENT_NAME"
        ) not in {"push", "workflow_dispatch"}:
            raise ValueError("main-only-hosted-enrollment-required")
        from scripts.check_evidence import execution_origin
        from scripts.validation import source_identity

        origin = execution_origin()
        if origin.get("kind") != "github-actions" or origin.get("job") != "native-prerequisites":
            raise ValueError("explicit-hosted-enrollment-required")
        conditions = execution_conditions()
        outer = conditions["job_watchdog"]
        if outer is None:
            raise ValueError("outer-watchdog-required")
        end = time.monotonic() + outer["effective_minutes"] * 60
        source = source_identity(ROOT)
        if not source["clean"]:
            raise ValueError("clean-source-required")
        with tempfile.TemporaryDirectory(
            prefix="fishhat-interruption-", dir=os.environ["RUNNER_TEMP"]
        ) as temporary:
            report = run(end, Path(temporary))
        report["outer_directory_absent"] = (
            not Path(temporary).exists() and not Path(temporary).is_symlink()
        )
        if not report["outer_directory_absent"] or report.get("owned_canary_removed") is not True:
            report.update(status="failed", reason="outer-cleanup-unverified")
        report.update(
            source_before=source,
            source_after=source_identity(ROOT),
            execution_origin=origin,
            conditions=conditions,
        )
        if report["source_after"] != source:
            report.update(status="failed", reason="source-changed")
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
        print("Refusing: independent hosted interruption evidence unavailable.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
