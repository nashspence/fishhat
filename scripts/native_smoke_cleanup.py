"""Observe exact disposable-account cleanup without printing outside state."""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

from scripts.validation_timeouts import Deadline


@dataclass(frozen=True)
class Identity:
    account: str
    uid: int
    gid: int
    work: Path

    def valid(self) -> bool:
        return bool(
            re.fullmatch(r"dtci[1-9][0-9]*", self.account)
            and type(self.uid) is int
            and type(self.gid) is int
            and 0 < self.uid < 2**32 - 1
            and 0 < self.gid < 2**32 - 1
            and self.uid != int(self.account[4:])
            and self.work.parent == Path("/tmp")
            and re.fullmatch(r"fishhat-native\.[A-Za-z0-9]{8}", self.work.name)
        )


@dataclass(frozen=True)
class Paths:
    proc: Path = Path("/proc")
    etc: Path = Path("/etc")
    run: Path = Path("/run")
    home: Path = Path("/home")
    var: Path = Path("/var")
    usr: Path = Path("/usr")
    sys: Path = Path("/sys")
    tmp: Path = Path("/tmp")


def query(command: list[str], end: float) -> tuple[int, str]:
    deadline = Deadline(end)
    if not 0 < deadline.remaining() <= threading.TIMEOUT_MAX:
        raise ValueError("observation-deadline-expired")
    result = subprocess.run(command, capture_output=True, text=True, timeout=deadline.remaining())
    return result.returncode, result.stdout


def lookup(database: str, key: str, end: float) -> list[str] | None:
    status, text = query(["/usr/bin/getent", database, key], end)
    if status == 2 and not text:
        return None
    if status != 0 or len(text.splitlines()) != 1:
        raise ValueError("name-service-unavailable")
    fields = text.strip().split(":")
    if len(fields) != (7 if database == "passwd" else 4) or not fields[2].isdecimal():
        raise ValueError("name-service-unavailable")
    if database == "passwd" and not fields[3].isdecimal():
        raise ValueError("name-service-unavailable")
    return fields


def name_service(identity: Identity, end: float) -> dict[str, bool]:
    for database in ("passwd", "group"):
        root = lookup(database, "0", end)
        if root is None or root[0] != "root" or root[2] != "0":
            raise ValueError("name-service-unavailable")
    return {
        "account-name": lookup("passwd", identity.account, end) is not None,
        "account-uid": lookup("passwd", str(identity.uid), end) is not None,
        "group-name": lookup("group", identity.account, end) is not None,
        "group-gid": lookup("group", str(identity.gid), end) is not None,
    }


def login_user_present(identity: Identity, end: float) -> bool:
    status, text = query(
        [
            "/usr/bin/busctl",
            "--system",
            "--json=short",
            "--auto-start=no",
            "--allow-interactive-authorization=no",
            "call",
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "ListUsers",
        ],
        end,
    )
    if status != 0:
        raise ValueError("login-manager-unavailable")
    value = json.loads(text)
    if (
        type(value) is not dict
        or set(value) != {"type", "data"}
        or value["type"] != "a(uso)"
        or type(value["data"]) is not list
        or len(value["data"]) != 1
        or type(value["data"][0]) is not list
    ):
        raise ValueError("login-manager-unavailable")
    seen: set[int] = set()
    present = False
    for row in value["data"][0]:
        if (
            type(row) is not list
            or len(row) != 3
            or type(row[0]) is not int
            or not 0 <= row[0] < 2**32 - 1
            or row[0] in seen
            or type(row[1]) is not str
            or not row[1]
            or type(row[2]) is not str
            or re.fullmatch(r"/(?:[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*)?", row[2]) is None
        ):
            raise ValueError("login-manager-unavailable")
        seen.add(row[0])
        present = present or row[0] == identity.uid or row[1] == identity.account
    return present


def unit_present(unit: str, end: float) -> bool:
    status, text = query(
        [
            "/usr/bin/systemctl",
            "--no-pager",
            "--no-ask-password",
            "show",
            unit,
            "--property=LoadState",
            "--property=ActiveState",
        ],
        end,
    )
    rows = text.splitlines()
    if status != 0 or len(rows) != 2 or any("=" not in row for row in rows):
        raise ValueError("system-manager-unavailable")
    fields = dict(row.split("=", 1) for row in rows)
    if (
        set(fields) != {"LoadState", "ActiveState"}
        or fields["LoadState"] != "loaded"
        or fields["ActiveState"]
        not in {
            "active",
            "reloading",
            "inactive",
            "failed",
            "activating",
            "deactivating",
            "maintenance",
            "refreshing",
        }
    ):
        raise ValueError("system-manager-unavailable")
    return fields["ActiveState"] != "inactive"


def credentials(path: Path) -> tuple[list[int], list[int]]:
    rows: dict[str, list[int]] = {}
    for line in path.read_text().splitlines():
        if line.startswith(("Uid:", "Gid:")):
            key, text = line.split(":", 1)
            parts = text.split()
            if key in rows or len(parts) != 4 or any(not v.isdecimal() for v in parts):
                raise ValueError("process-observation-unavailable")
            rows[key] = [int(v) for v in parts]
    if set(rows) != {"Uid", "Gid"}:
        raise ValueError("process-observation-unavailable")
    return rows["Uid"], rows["Gid"]


def owned_processes(identity: Identity, paths: Paths) -> int:
    if credentials(paths.proc / "self/status")[0] != [0, 0, 0, 0]:
        raise ValueError("process-observation-unavailable")
    count = 0
    for directory in paths.proc.iterdir():
        if not directory.name.isascii() or not directory.name.isdecimal():
            continue
        try:
            uids, gids = credentials(directory / "status")
        except FileNotFoundError:
            if directory.exists():
                raise
            continue
        count += identity.uid in uids or identity.gid in gids
    return count


def owned_paths(identity: Identity, paths: Paths) -> dict[str, Path]:
    unit = f"user-{identity.uid}.slice"
    return {
        "home": paths.home / identity.account,
        "runtime-directory": paths.run / "user" / str(identity.uid),
        "linger": paths.var / "lib/systemd/linger" / identity.account,
        "generator": paths.usr
        / "lib/systemd/user-environment-generators"
        / f"99-fishhat-probe-{identity.uid}",
        "work": paths.tmp / identity.work.name,
        "user-cgroup": paths.sys / "fs/cgroup/user.slice" / unit,
        "runtime-properties": paths.run / "systemd/system.control" / (unit + ".d"),
        "transient-slice": paths.run / "systemd/transient" / unit,
        "transient-slice-properties": paths.run / "systemd/transient" / (unit + ".d"),
    }


def path_present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def subordinate_present(identity: Identity, path: Path) -> bool:
    present = False
    for line in path.read_text().splitlines():
        if not line:
            continue
        fields = line.split(":")
        if len(fields) != 3 or any(not v.isdecimal() for v in fields[1:]):
            raise ValueError("subordinate-mapping-unavailable")
        present = present or fields[0] == identity.account
    return present


def observe_once(identity: Identity, end: float, paths: Paths | None = None) -> dict[str, Any]:
    paths = Paths() if paths is None else paths
    observations: list[dict[str, Any]] = []

    def record(role: str, function: Callable[[], bool | int]) -> None:
        try:
            present = function()
        except (OSError, ValueError, subprocess.SubprocessError):
            observations.append({"role": role, "status": "unavailable"})
        else:
            observations.append({"role": role, "status": "present" if present else "absent"})

    try:
        names = name_service(identity, end)
    except (OSError, ValueError, subprocess.SubprocessError):
        for role in ("account-name", "account-uid", "group-name", "group-gid"):
            observations.append({"role": role, "status": "unavailable"})
    else:
        for role, present in names.items():
            observations.append({"role": role, "status": "present" if present else "absent"})
    record("login-user", lambda: login_user_present(identity, end))
    record("user-manager", lambda: unit_present(f"user@{identity.uid}.service", end))
    record("runtime-manager", lambda: unit_present(f"user-runtime-dir@{identity.uid}.service", end))
    record("process-credentials", lambda: owned_processes(identity, paths))
    required = (
        paths.home,
        paths.run,
        paths.tmp,
        paths.var / "lib/systemd",
        paths.usr / "lib/systemd/user-environment-generators",
        paths.sys / "fs/cgroup",
    )
    try:
        if not all(path.is_dir() for path in required):
            raise ValueError("path-observation-unavailable")
        if not {"cpu", "memory", "pids"} <= set(
            (paths.sys / "fs/cgroup/cgroup.controllers").read_text().split()
        ):
            raise ValueError("cgroup-observation-unavailable")
    except (OSError, ValueError):
        for role in owned_paths(identity, paths):
            observations.append({"role": role, "status": "unavailable"})
    else:
        for role, path in owned_paths(identity, paths).items():
            record(role, partial(path_present, path))
    for name in ("subuid", "subgid"):
        record(name, partial(subordinate_present, identity, paths.etc / name))
    status = (
        "unavailable"
        if any(r["status"] == "unavailable" for r in observations)
        else ("present" if any(r["status"] == "present" for r in observations) else "absent")
    )
    return {
        "scope": "owned-smoke-cleanup-observation-only",
        "observer_uid": os.geteuid(),
        "status": status,
        "measurement_scope": "exact owned identity and read-only system/process/filesystem observations",
        "observations": observations,
        "complete_absence_verified": status == "absent",
        "native_qualified": False,
    }


def configuration_paths(identity: Identity, paths: Paths) -> dict[str, Path]:
    unit = f"user-{identity.uid}.slice"
    roots = {
        "persistent": paths.etc / "systemd/system",
        "persistent-control": paths.etc / "systemd/system.control",
        "runtime": paths.run / "systemd/system",
        "runtime-control": paths.run / "systemd/system.control",
    }
    return {
        role + kind: root / (unit + suffix)
        for role, root in roots.items()
        for kind, suffix in (("-unit", ""), ("-dropins", ".d"))
    }


def configuration_clear(
    identity: Identity, end: float, paths: Paths | None = None
) -> dict[str, Any]:
    paths = Paths() if paths is None else paths
    observations = []
    canonical = False
    try:
        unit = f"user-{identity.uid}.slice"
        status, output = query(
            [
                "/usr/bin/systemctl",
                "--no-pager",
                "--no-ask-password",
                "show",
                unit,
                "--property=Id",
            ],
            end,
        )
        canonical = status == 0 and output == f"Id={unit}\n"
        if (
            not canonical
            or not (paths.etc / "systemd").is_dir()
            or not (paths.run / "systemd").is_dir()
        ):
            raise ValueError("slice-configuration-unavailable")
        for role, path in configuration_paths(identity, paths).items():
            observations.append(
                {"role": role, "status": "present" if path_present(path) else "absent"}
            )
        state = "present" if any(row["status"] == "present" for row in observations) else "absent"
    except (OSError, ValueError, subprocess.SubprocessError):
        state = "unavailable"
    return {
        "scope": "owned-smoke-slice-configuration-observation-only",
        "observer_uid": os.geteuid(),
        "status": state,
        "canonical_unit_verified": canonical,
        "observations": observations,
        "complete_absence_verified": state == "absent",
        "native_qualified": False,
    }


def observe(identity: Identity, end: float) -> dict[str, Any]:
    result = observe_once(identity, end)
    while result["status"] == "present" and Deadline(end).remaining() > 0:
        time.sleep(min(0.25, Deadline(end).remaining()))
        result = observe_once(identity, end)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    value: dict[str, Any] = {
        "scope": "owned-smoke-cleanup-observation-only",
        "status": "unavailable",
        "reason": "owned-identity-and-deadline-required",
        "complete_absence_verified": False,
        "native_qualified": False,
    }
    try:
        if (
            len(arguments) != 6
            or arguments[0] not in {"observe", "configuration-clear"}
            or os.geteuid() != 0
        ):
            raise ValueError("owned-identity-and-deadline-required")
        identity = Identity(arguments[1], int(arguments[2]), int(arguments[3]), Path(arguments[4]))
        end = float(arguments[5])
        if (
            not identity.valid()
            or not math.isfinite(end)
            or not 0 < end - time.monotonic() <= threading.TIMEOUT_MAX
        ):
            raise ValueError("owned-identity-and-deadline-required")
        value = (
            configuration_clear(identity, end)
            if arguments[0] == "configuration-clear"
            else observe(identity, end)
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    label = (
        "slice-configuration-observation"
        if arguments[:1] == ["configuration-clear"]
        else "cleanup-observation"
    )
    print("native-prerequisite " + label + "=" + json.dumps(value, sort_keys=True))
    return 0 if value["complete_absence_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
