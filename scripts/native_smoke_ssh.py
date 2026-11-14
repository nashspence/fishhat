"""Own and independently observe one disposable root SSH server lifetime."""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import pwd

from scripts.native_smoke_cleanup import Paths
from scripts.native_smoke_interruption import digest, unique_object
from scripts.validation_timeouts import Deadline

SCOPE = "owned-smoke-ssh-lifetime-only"
FAULT_STATUS = 74
PORT = 22229
ROOT = Path(__file__).resolve().parents[1]


def require(condition: Any, category: str) -> None:
    if not condition:
        raise ValueError(category)


def remaining(end: float) -> float:
    require(type(end) in {int, float} and math.isfinite(end), "ssh-deadline-unavailable")
    value = Deadline(end).remaining()
    require(value > 0, "ssh-deadline-expired")
    return value


def fields(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text().splitlines():
        key, value = line.split(":", 1)
        require(key not in result, "ssh-observation-unavailable")
        result[key] = value.strip()
    return result


def stable(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def file_bytes(path: Path, end: float, *, uid: int, mode: int | None = None) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == uid,
            "ssh-file-custody-unavailable",
        )
        require(not before.st_mode & 0o022, "ssh-file-custody-unavailable")
        if mode is not None:
            require(stat.S_IMODE(before.st_mode) == mode, "ssh-file-custody-unavailable")
        chunks = []
        while block := stream.read(65536):
            remaining(end)
            chunks.append(block)
        require(stable(os.fstat(stream.fileno())) == stable(before), "ssh-file-changed")
        return b"".join(chunks)


def executable(path: Path, end: float, uid: int = 0) -> dict[str, Any]:
    # /proc/<pid>/exe is a kernel-owned link. Bind bytes and metadata to the
    # same open file, rather than reopening its pathname after hashing.
    value = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == uid
            and not before.st_mode & 0o022
            and before.st_mode & 0o111,
            "ssh-executable-unavailable",
        )
        while block := stream.read(65536):
            remaining(end)
            value.update(block)
        require(stable(os.fstat(stream.fileno())) == stable(before), "ssh-executable-changed")
    return {
        "device": before.st_dev,
        "inode": before.st_ino,
        "uid": uid,
        "sha256": value.hexdigest(),
    }


def process_state(pid: int, proc: Path = Path("/proc")) -> dict[str, Any]:
    require(type(pid) is int and pid > 0, "ssh-process-identity-unavailable")
    base = proc / str(pid)
    raw = (base / "stat").read_text()
    head, separator, rest = raw.rpartition(")")
    require(separator and head.startswith(str(pid) + " ("), "ssh-process-identity-unavailable")
    values = rest.split()
    require(len(values) >= 20, "ssh-process-identity-unavailable")
    credentials = fields(base / "status")
    uids = [int(v) for v in credentials["Uid"].split()]
    gids = [int(v) for v in credentials["Gid"].split()]
    require(len(uids) == len(gids) == 4, "ssh-process-identity-unavailable")
    return {
        "pid": pid,
        "parent_pid": int(values[1]),
        "process_group": int(values[2]),
        "session": int(values[3]),
        "start_ticks": int(values[19]),
        "uids": uids,
        "gids": gids,
    }


def listeners(proc: Path = Path("/proc")) -> Iterator[dict[str, Any]]:
    for family, width in (("tcp", 8), ("tcp6", 32)):
        with (proc / "net" / family).open() as stream:
            require("local_address" in stream.readline(), "ssh-listener-observation-unavailable")
            for line in stream:
                parts = line.split()
                require(len(parts) >= 10, "ssh-listener-observation-unavailable")
                address, separator, port = parts[1].partition(":")
                require(
                    separator
                    and re.fullmatch("[0-9A-Fa-f]{" + str(width) + "}", address)
                    and re.fullmatch("[0-9A-Fa-f]{4}", port),
                    "ssh-listener-observation-unavailable",
                )
                require(
                    re.fullmatch("[0-9A-Fa-f]{2}", parts[3]), "ssh-listener-observation-unavailable"
                )
                if parts[3] != "0A":
                    continue
                inode = int(parts[9])
                require(inode > 0, "ssh-listener-observation-unavailable")
                yield (
                    {
                        "family": family,
                        "address": address.upper(),
                        "port": int(port, 16),
                        "inode": inode,
                    }
                )


def socket_inodes(pid: int, proc: Path = Path("/proc")) -> set[int]:
    base = proc / str(pid) / "fd"
    result = set()
    for path in base.iterdir():
        try:
            target = os.readlink(path)
        except FileNotFoundError:
            # A descriptor can close between directory enumeration and readlink.
            require(base.is_dir(), "ssh-process-observation-unavailable")
            continue
        match = re.fullmatch(r"socket:\[([0-9]+)\]", target)
        if match:
            result.add(int(match[1]))
    return result


def owned_listener(pid: int, proc: Path = Path("/proc")) -> dict[str, Any]:
    rows = [v for v in listeners(proc) if v["port"] == PORT]
    require(len(rows) == 1, "ssh-listener-custody-unavailable")
    item = rows[0]
    require(
        item["family"] == "tcp" and item["address"] == "0100007F",
        "ssh-listener-custody-unavailable",
    )
    require(item["inode"] in socket_inodes(pid, proc), "ssh-listener-custody-unavailable")
    return {"port": PORT, "inode": item["inode"], "loopback_only": True}


@dataclass
class OwnedChild:
    process: subprocess.Popen[bytes]
    handle: int
    image: dict[str, Any]
    image_path: Path
    enrollment: str
    arguments_sha256: str
    uid: int
    gid: int
    admitted: dict[str, Any] | None = None
    termination_requested: bool = False

    @classmethod
    def open(
        cls,
        process: subprocess.Popen[bytes],
        image: dict[str, Any],
        image_path: Path,
        enrollment: str,
        arguments: list[str],
        uid: int = 0,
        gid: int = 0,
    ) -> OwnedChild:
        require(str(uuid.UUID(enrollment)) == enrollment, "ssh-enrollment-unavailable")
        handle = os.pidfd_open(process.pid, 0)
        return cls(
            process,
            handle,
            image,
            image_path,
            enrollment,
            hashlib.sha256(b"\0".join(v.encode() for v in arguments) + b"\0").hexdigest(),
            uid,
            gid,
        )

    def exited(self) -> Any:
        return os.waitid(os.P_PIDFD, self.handle, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def identity(self, end: float) -> dict[str, Any]:
        remaining(end)
        require(self.exited() is None, "ssh-owned-child-not-active")
        info = fields(Path("/proc/self/fdinfo") / str(self.handle))
        require(int(info["Pid"]) == self.process.pid, "ssh-kernel-handle-mismatch")
        value = process_state(self.process.pid)
        require(value["parent_pid"] == os.getpid(), "ssh-owned-parent-mismatch")
        require(
            value["process_group"] == value["session"] == self.process.pid,
            "ssh-owned-session-mismatch",
        )
        require(
            value["uids"] == [self.uid] * 4 and value["gids"] == [self.gid] * 4,
            "ssh-owned-actor-mismatch",
        )
        image = Path("/proc") / str(self.process.pid) / "exe"
        require(Path(os.readlink(image)) == self.image_path, "ssh-owned-executable-mismatch")
        require(
            executable(image, end, self.image["uid"]) == self.image, "ssh-owned-executable-mismatch"
        )
        return {
            **value,
            "executable": self.image,
            "enrollment": self.enrollment,
            "requested_arguments_sha256": self.arguments_sha256,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        }

    def admit(self, end: float) -> dict[str, Any]:
        require(self.admitted is None, "ssh-child-already-admitted")
        self.admitted = self.identity(end)
        return self.admitted

    def terminate(self, claim: Any, end: float) -> None:
        require(self.admitted is not None and claim == self.admitted, "ssh-process-claim-refused")
        require(self.identity(end) == self.admitted, "ssh-process-claim-refused")
        remaining(end)
        signal.pidfd_send_signal(self.handle, signal.SIGTERM)
        self.termination_requested = True

    def finish(self, end: float) -> dict[str, Any]:
        timer = Deadline(end)
        # The unreaped direct child and kernel handle retain custody even when
        # an external claimed identity or a later observation is refused.
        if self.exited() is None and not self.termination_requested:
            signal.pidfd_send_signal(self.handle, signal.SIGTERM)
            self.termination_requested = True
        try:
            require(
                select.select([self.handle], [], [], remaining(end))[0], "ssh-child-exit-unobserved"
            )
        except (OSError, ValueError):
            # Reuse the maintained backend kill grace after a failed deadline;
            # a forced reap cannot turn that original failure into a pass.
            if self.exited() is None:
                signal.pidfd_send_signal(self.handle, signal.SIGKILL)
            grace = Deadline.after(5)
            require(
                select.select([self.handle], [], [], remaining(grace.end))[0],
                "ssh-child-forced-exit-unobserved",
            )
            self.process.wait(timeout=grace.remaining())
            raise
        observed = self.exited()
        require(
            observed is not None and observed.si_pid == self.process.pid,
            "ssh-child-exit-unobserved",
        )
        result = self.process.wait(timeout=timer.remaining())
        require(
            (observed.si_code == os.CLD_EXITED and observed.si_status == result == 0)
            or (
                observed.si_code == os.CLD_KILLED
                and observed.si_status == signal.SIGTERM
                and result == -signal.SIGTERM
            ),
            "ssh-child-original-exit-failed",
        )
        try:
            signal.pidfd_send_signal(self.handle, 0)
        except ProcessLookupError as error:
            require(error.errno == errno.ESRCH, "ssh-stale-handle-unavailable")
        else:
            raise ValueError("ssh-stale-handle-accepted")
        return {
            "pid": self.process.pid,
            "parent_pid": os.getpid(),
            "returncode": result,
            "exit_observed": True,
            "reaped": True,
            "stale_handle_refused": True,
        }

    def close(self) -> None:
        os.close(self.handle)


def childless(child: OwnedChild, end: float) -> None:
    path = Path("/proc") / str(child.process.pid) / "task" / str(child.process.pid) / "children"
    while True:
        child.identity(end)
        values = path.read_text().split()
        require(
            all(v.isdecimal() and int(v) > 0 for v in values),
            "ssh-children-observation-unavailable",
        )
        if not values:
            return
        time.sleep(min(0.05, remaining(end)))


def identity_record(identity: Any) -> dict[str, Any]:
    if type(identity) is not dict:
        raise ValueError("ssh-observer-inventory-unavailable")
    require(
        set(identity)
        == {
            "pid",
            "parent_pid",
            "process_group",
            "session",
            "start_ticks",
            "uids",
            "gids",
            "executable",
            "enrollment",
            "requested_arguments_sha256",
            "boot_id",
        },
        "ssh-observer-inventory-unavailable",
    )
    require(
        all(
            type(identity[k]) is int and identity[k] > 0
            for k in ("pid", "parent_pid", "process_group", "session", "start_ticks")
        ),
        "ssh-observer-inventory-unavailable",
    )
    require(
        identity["process_group"] == identity["session"] == identity["pid"],
        "ssh-observer-inventory-unavailable",
    )
    for name in ("uids", "gids"):
        require(
            type(identity[name]) is list
            and len(identity[name]) == 4
            and all(type(v) is int and v == 0 for v in identity[name]),
            "ssh-observer-inventory-unavailable",
        )
    image = identity["executable"]
    require(
        type(image) is dict and set(image) == {"device", "inode", "uid", "sha256"},
        "ssh-observer-inventory-unavailable",
    )
    require(
        all(type(image[k]) is int for k in ("device", "inode", "uid"))
        and image["device"] >= 0
        and image["inode"] > 0
        and image["uid"] == 0,
        "ssh-observer-inventory-unavailable",
    )
    for item in (image["sha256"], identity["requested_arguments_sha256"]):
        require(
            type(item) is str and re.fullmatch("[0-9a-f]{64}", item),
            "ssh-observer-inventory-unavailable",
        )
    for key in ("enrollment", "boot_id"):
        require(
            type(identity[key]) is str and str(uuid.UUID(identity[key])) == identity[key],
            "ssh-observer-inventory-unavailable",
        )
    return identity


def listener_record(listener: Any) -> dict[str, Any]:
    if type(listener) is not dict:
        raise ValueError("ssh-observer-inventory-unavailable")
    require(
        set(listener) == {"port", "inode", "loopback_only"},
        "ssh-observer-inventory-unavailable",
    )
    require(
        type(listener["port"]) is int
        and listener["port"] == PORT
        and type(listener["inode"]) is int
        and listener["inode"] > 0
        and listener["loopback_only"] is True,
        "ssh-observer-inventory-unavailable",
    )
    return listener


def inventory_record(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError("ssh-observer-inventory-unavailable")
    require(
        set(value) == {"identity", "listener", "arena"},
        "ssh-observer-inventory-unavailable",
    )
    identity_record(value["identity"])
    listener_record(value["listener"])
    require(type(value["arena"]) is str, "ssh-observer-inventory-unavailable")
    arena = Path(value["arena"])
    require(
        str(arena) == value["arena"]
        and arena.parent == Path("/tmp")
        and re.fullmatch("fishhat-smoke-ssh-[a-z0-9_]+", arena.name),
        "ssh-observer-inventory-unavailable",
    )
    return value


def arena_custody(path: Path) -> bool:
    value = path.lstat()
    return (
        stat.S_ISDIR(value.st_mode)
        and value.st_uid == value.st_gid == 0
        and stat.S_IMODE(value.st_mode) == 0o711
    )


def observe(request: Any, paths: Paths | None = None) -> dict[str, Any]:
    paths = Paths() if paths is None else paths
    require(sys.platform == "linux" and os.geteuid() == 0, "ssh-observer-requires-root")
    require(
        type(request) is dict and set(request) == {"phase", "challenge", "inventory", "end"},
        "ssh-observer-request-unavailable",
    )
    require(request["phase"] in {"before", "after"}, "ssh-observer-request-unavailable")
    require(
        str(uuid.UUID(request["challenge"])) == request["challenge"],
        "ssh-observer-request-unavailable",
    )
    end = request["end"]
    remaining(end)
    inventory = inventory_record(request["inventory"])
    identity = inventory["identity"]
    require(
        type(identity) is dict and type(identity.get("pid")) is int and identity["pid"] > 0,
        "ssh-observer-inventory-unavailable",
    )
    arena = paths.tmp / Path(inventory["arena"]).name
    require(
        (paths.proc / "sys/kernel/random/boot_id").read_text().strip() == identity["boot_id"],
        "ssh-observer-boot-mismatch",
    )
    if request["phase"] == "before":
        actual = process_state(identity["pid"], paths.proc)
        require(all(actual[k] == identity[k] for k in actual), "ssh-observer-identity-mismatch")
        require(actual["uids"] == actual["gids"] == [0] * 4, "ssh-observer-identity-mismatch")
        require(
            executable(paths.proc / str(identity["pid"]) / "exe", end) == identity["executable"],
            "ssh-observer-executable-mismatch",
        )
        require(
            owned_listener(identity["pid"], paths.proc) == inventory["listener"],
            "ssh-observer-listener-mismatch",
        )
        require(arena_custody(arena), "ssh-observer-arena-mismatch")
        observations = {"owned_process": True, "owned_listener": True, "owned_arena": True}
    else:
        try:
            actual = process_state(identity["pid"], paths.proc)
        except FileNotFoundError:
            require(
                not (paths.proc / str(identity["pid"])).exists(), "ssh-process-absence-unavailable"
            )
        else:
            require(actual["start_ticks"] != identity["start_ticks"], "ssh-owned-process-remains")
        for base in paths.proc.iterdir():
            if not base.name.isdecimal():
                continue
            remaining(end)
            try:
                value = process_state(int(base.name), paths.proc)
            except FileNotFoundError:
                require(not base.exists(), "ssh-process-absence-unavailable")
                continue
            require(
                value["session"] != identity["session"]
                and value["process_group"] != identity["process_group"],
                "ssh-owned-session-remains",
            )
        all_listeners = listeners(paths.proc)
        require(
            not any(
                v["port"] == PORT or v["inode"] == inventory["listener"]["inode"]
                for v in all_listeners
            ),
            "ssh-owned-listener-remains",
        )
        try:
            arena.lstat()
        except FileNotFoundError:
            pass
        else:
            raise ValueError("ssh-owned-arena-remains")
        observations = {
            "original_process_absent": True,
            "process_group_absent": True,
            "session_absent": True,
            "listener_absent": True,
            "arena_absent": True,
        }
    return {
        "scope": SCOPE,
        "observer_uid": 0,
        "phase": request["phase"],
        "status": "observed",
        "challenge": request["challenge"],
        "enrollment": identity["enrollment"],
        "identity": identity,
        "listener": inventory["listener"],
        "observer_pid": os.getpid(),
        "observer_parent_pid": os.getppid(),
        "inventory_sha256": digest(inventory),
        "observations": observations,
        "native_product_qualified": False,
    }


def independent_observation(inventory: dict[str, Any], phase: str, end: float) -> dict[str, Any]:
    timer = Deadline(end)
    remaining(end)
    request = {"phase": phase, "challenge": str(uuid.uuid4()), "inventory": inventory, "end": end}
    result = subprocess.run(
        ["/usr/bin/python3", "-m", "scripts.native_smoke_ssh", "observe"],
        input=json.dumps(request).encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=ROOT,
        timeout=timer.remaining(),
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    require(result.returncode == 0, "ssh-independent-observation-unavailable")
    value = json.loads(result.stdout, object_pairs_hook=unique_object)
    if type(value) is not dict:
        raise ValueError("ssh-independent-observation-mismatch")
    require(
        set(value)
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
        }
        and value.get("scope") == SCOPE
        and type(value.get("observer_uid")) is int
        and value.get("observer_uid") == 0
        and value.get("native_product_qualified") is False
        and value.get("phase") == phase
        and value.get("status") == "observed"
        and value.get("challenge") == request["challenge"]
        and value.get("enrollment") == inventory["identity"]["enrollment"]
        and value.get("identity") == inventory["identity"]
        and value.get("listener") == inventory["listener"]
        and type(value.get("observer_pid")) is int
        and value["observer_pid"] > 0
        and value["observer_pid"]
        not in {inventory["identity"]["pid"], inventory["identity"]["parent_pid"]}
        and type(value.get("observer_parent_pid")) is int
        and value["observer_parent_pid"] == inventory["identity"]["parent_pid"]
        and value.get("inventory_sha256") == digest(inventory),
        "ssh-independent-observation-mismatch",
    )
    expected = (
        {"owned_process", "owned_listener", "owned_arena"}
        if phase == "before"
        else {
            "original_process_absent",
            "process_group_absent",
            "session_absent",
            "listener_absent",
            "arena_absent",
        }
    )
    require(
        type(value["observations"]) is dict
        and set(value["observations"]) == expected
        and all(v is True for v in value["observations"].values()),
        "ssh-independent-observation-mismatch",
    )
    return value


def public_key_fields(raw: bytes) -> tuple[bytes, bytes]:
    """Read the key fields while keeping an optional comment opaque."""
    rows = raw.splitlines()
    require(len(rows) == 1 and b"\0" not in raw, "ssh-public-key-unavailable")
    parts = rows[0].split(maxsplit=2)
    require(len(parts) >= 2 and parts[0] == b"ssh-ed25519", "ssh-public-key-unavailable")
    return parts[0], parts[1]


def configuration(actor: str, directory: Path, authorized_keys: Path) -> str:
    require(re.fullmatch("[a-z_][a-z0-9_-]*", actor), "ssh-actor-unavailable")
    require("\n" not in str(directory) + str(authorized_keys), "ssh-input-unavailable")
    return "\n".join(
        [
            f"Port {PORT}",
            "ListenAddress 127.0.0.1",
            f"HostKey {directory}/server",
            f"PidFile {directory}/sshd.pid",
            f"AuthorizedKeysFile {authorized_keys}",
            "StrictModes yes",
            "UsePAM yes",
            "PubkeyAuthentication yes",
            "AuthenticationMethods publickey",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "PermitRootLogin no",
            f"AllowUsers {actor}",
            "DisableForwarding yes",
            "PermitTTY no",
            "PermitUserEnvironment no",
            "PermitUserRC no",
            "ForceCommand /usr/bin/printf ssh-fixture-ok",
            "LogLevel VERBOSE",
            "",
        ]
    )


class CommandFailure(ValueError):
    def __init__(self, status: int) -> None:
        self.status = status if 0 < status <= 255 else 1
        super().__init__("ssh-command-failed")


@contextmanager
def termination_guard() -> Iterator[None]:
    original = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
    received = False

    def interrupted(number: int, _frame: Any) -> None:
        nonlocal received
        if not received:
            received = True
            raise CommandFailure(128 + number)

    for number in original:
        signal.signal(number, interrupted)
    try:
        yield
    finally:
        for number, handler in original.items():
            signal.signal(number, handler)


def command(
    arguments: list[str], end: float, *, uid: int | None = None, gid: int | None = None
) -> subprocess.CompletedProcess[bytes]:
    timer = Deadline(end)
    remaining(end)
    return subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        cwd="/",
        timeout=timer.remaining(),
        user=uid,
        group=gid,
        extra_groups=[] if uid is not None else None,
    )


def checked(arguments: list[str], end: float) -> bytes:
    result = command(arguments, end)
    if result.returncode:
        raise CommandFailure(result.returncode)
    return result.stdout


def write(path: Path, raw: bytes, *, uid: int = 0, gid: int = 0) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), 0o600)
        os.fchown(stream.fileno(), uid, gid)


def account_fingerprints(runner: int) -> dict[str, str]:
    import grp
    import pwd

    result = {}
    for role, uid in (("root", 0), ("runner", runner)):
        item = pwd.getpwuid(uid)
        group = grp.getgrgid(item.pw_gid)
        result[role] = digest([list(item), list(group)])
    return result


def canary_snapshot(path: Path, end: float) -> dict[str, Any]:
    raw = file_bytes(path, end, uid=0, mode=0o600)
    value = path.lstat()
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": stat.S_IMODE(value.st_mode),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def refusal_challenges(child: OwnedChild, end: float) -> list[str]:
    original = child.admitted
    if original is None:
        raise ValueError("ssh-child-not-admitted")
    changes = {
        "foreign-pid": ("pid", os.getpid()),
        "stale-start-ticks": ("start_ticks", original["start_ticks"] + 1),
        "foreign-actor": ("uids", [1] * 4),
        "foreign-executable": ("executable", {}),
        "foreign-enrollment": ("enrollment", str(uuid.uuid4())),
    }
    result = []
    for name, (key, value) in changes.items():
        claim = {**original, key: value}
        try:
            child.terminate(claim, end)
        except ValueError:
            require(child.identity(end) == original, "ssh-refusal-altered-owned-child")
            result.append(name)
        else:
            raise ValueError("ssh-foreign-claim-accepted")
    return result


def _probe(
    actor: pwd.struct_passwd,
    runner: int,
    runner_gid: int,
    end: float,
    *,
    source: Path | None = None,
    interrupted: bool = False,
    contact_timeout: int = 30,
    enrollment: str | None = None,
) -> dict[str, Any]:
    timer = Deadline(end)
    remaining(end)
    require(actor.pw_uid > 0 and runner > 0, "ssh-actor-unavailable")
    require(type(contact_timeout) is int and contact_timeout > 0, "ssh-contact-timeout-unavailable")
    require(
        hasattr(os, "pidfd_open")
        and hasattr(os, "P_PIDFD")
        and hasattr(signal, "pidfd_send_signal"),
        "ssh-kernel-custody-unavailable",
    )
    require(not any(v["port"] == PORT for v in listeners()), "ssh-endpoint-already-owned")
    image_path = Path("/usr/sbin/sshd").resolve(strict=True)
    image = executable(image_path, end)
    protected = account_fingerprints(runner)
    token = str(uuid.uuid4()) if enrollment is None else enrollment
    require(
        str(uuid.UUID(token)) == token and uuid.UUID(token).version == 4,
        "ssh-enrollment-unavailable",
    )
    report: dict[str, Any] = {
        "scope": SCOPE,
        "enrollment": token,
        "interruption_selected": interrupted,
        "original_primary_exit": 0,
        "cleanup_exit": 0,
        "injection_observed": False,
        "native_product_qualified": False,
    }
    report["protected_accounts_before"] = protected
    inventory = None
    before = None
    termination = None
    child = None
    process = None
    with tempfile.TemporaryFile() as server_errors:
        with tempfile.TemporaryDirectory(prefix="fishhat-smoke-ssh-", dir="/tmp") as temporary:
            arena = Path(temporary)
            arena.chmod(0o711)
            canary = uuid.uuid4().bytes
            write(arena / "unrelated-canary", canary)
            report["canary_before"] = canary_snapshot(arena / "unrelated-canary", end)
            try:
                for role in ("server", "client"):
                    if source is None:
                        checked(
                            [
                                "/usr/bin/ssh-keygen",
                                "-q",
                                "-t",
                                "ed25519",
                                "-N",
                                "",
                                "-f",
                                str(arena / role),
                            ],
                            end,
                        )
                    else:
                        write(arena / role, file_bytes(source / role, end, uid=runner, mode=0o600))
                        write(
                            arena / (role + ".pub"),
                            file_bytes(source / (role + ".pub"), end, uid=runner),
                        )
                server_public = public_key_fields(
                    checked(["/usr/bin/ssh-keygen", "-y", "-f", str(arena / "server")], end)
                )
                declared = public_key_fields(file_bytes(arena / "server.pub", end, uid=0))
                require(server_public == declared, "ssh-host-key-mismatch")
                client_public = public_key_fields(file_bytes(arena / "client.pub", end, uid=0))
                client_derived = public_key_fields(
                    checked(["/usr/bin/ssh-keygen", "-y", "-f", str(arena / "client")], end)
                )
                require(client_public == client_derived, "ssh-client-key-mismatch")
                authorized = (
                    (Path(actor.pw_dir) / ".ssh/authorized_keys")
                    if source is not None
                    else arena / "client.pub"
                )
                if source is not None:
                    require(
                        file_bytes(authorized, end, uid=actor.pw_uid, mode=0o600)
                        == file_bytes(arena / "client.pub", end, uid=0),
                        "ssh-authorized-key-mismatch",
                    )
                write(
                    arena / "sshd_config", configuration(actor.pw_name, arena, authorized).encode()
                )
                checked([str(image_path), "-t", "-f", str(arena / "sshd_config")], end)
                arguments = [str(image_path), "-D", "-e", "-f", str(arena / "sshd_config")]
                process = subprocess.Popen(
                    arguments,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=server_errors,
                    start_new_session=True,
                    cwd="/",
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
                )
                child = OwnedChild.open(process, image, image_path, token, arguments)
                child.admit(end)
                while True:
                    child.identity(end)
                    if any(v["port"] == PORT for v in listeners()):
                        break
                    time.sleep(min(0.05, remaining(end)))
                inventory = {
                    "identity": child.admitted,
                    "listener": owned_listener(process.pid),
                    "arena": str(arena),
                }
                childless(child, end)
                before = independent_observation(inventory, "before", end)
                report["refusals_verified"] = refusal_challenges(child, end)
                if interrupted:
                    report["injection_observed"] = True
                    raise CommandFailure(FAULT_STATUS)
                write(
                    arena / "known_hosts",
                    b"[127.0.0.1]:22229 " + b" ".join(server_public) + b"\n",
                    uid=runner,
                    gid=runner_gid,
                )
                os.chown(arena / "client", runner, runner_gid)
                arguments = [
                    "/usr/bin/ssh",
                    "-F",
                    "/dev/null",
                    "-T",
                    "-p",
                    str(PORT),
                    "-i",
                    str(arena / "client"),
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=" + str(contact_timeout),
                    "-o",
                    "StrictHostKeyChecking=yes",
                ]
                result = command(
                    [
                        *arguments,
                        "-o",
                        "UserKnownHostsFile=" + str(arena / "known_hosts"),
                        actor.pw_name + "@127.0.0.1",
                        "arbitrary-input",
                    ],
                    end,
                    uid=runner,
                    gid=runner_gid,
                )
                if result.returncode:
                    raise CommandFailure(result.returncode)
                require(result.stdout == b"ssh-fixture-ok", "ssh-forced-command-mismatch")
                report["pinned_host_and_forced_command_verified"] = True
                denied = command(
                    [
                        *arguments,
                        "-o",
                        "UserKnownHostsFile=/dev/null",
                        actor.pw_name + "@127.0.0.1",
                        "info",
                    ],
                    end,
                    uid=runner,
                    gid=runner_gid,
                )
                require(
                    denied.returncode == 255 and b"Host key verification failed." in denied.stderr,
                    "ssh-unknown-host-rejection-unproved",
                )
                report["unknown_host_key_rejected"] = True
                childless(child, end)
                child.terminate(child.admitted, end)
            except CommandFailure as error:
                report["original_primary_exit"] = error.status
            except (OSError, ValueError, subprocess.SubprocessError):
                report["original_primary_exit"] = 1
                report["problem"] = "ssh-stage-unavailable"
            finally:
                try:
                    if child is not None:
                        termination = child.finish(end)
                    elif process is not None:
                        # This is still our unreaped direct Popen child; never a pidfile claim.
                        process.kill()
                        process.wait(timeout=timer.remaining())
                except (OSError, ValueError, subprocess.SubprocessError):
                    report["cleanup_exit"] = 1
                    report["cleanup_problem"] = "ssh-termination-unobserved"
                finally:
                    if child is not None:
                        child.close()
                try:
                    require(
                        file_bytes(arena / "unrelated-canary", end, uid=0, mode=0o600) == canary,
                        "ssh-canary-changed",
                    )
                    report["canary_after"] = canary_snapshot(arena / "unrelated-canary", end)
                    require(report["canary_before"] == report["canary_after"], "ssh-canary-changed")
                    report["protected_accounts_after"] = account_fingerprints(runner)
                    require(
                        report["protected_accounts_after"] == protected,
                        "ssh-protected-account-changed",
                    )
                    report["unrelated_canary_preserved"] = report[
                        "protected_accounts_preserved"
                    ] = True
                except (OSError, ValueError):
                    report["cleanup_exit"] = 1
                    report["cleanup_problem"] = "ssh-preservation-unobserved"
        try:
            if inventory is None or before is None or termination is None:
                raise ValueError("ssh-custody-unobserved")
            report["before"] = before
            report["after"] = independent_observation(inventory, "after", end)
            report["termination"] = termination
            report["inventory_sha256"] = digest(inventory)
        except (OSError, ValueError, subprocess.SubprocessError):
            report["cleanup_exit"] = 1
            report["cleanup_problem"] = "ssh-final-absence-unobserved"
    report["status"] = (
        "passed" if report["original_primary_exit"] == report["cleanup_exit"] == 0 else "failed"
    )
    return report


def probe(
    actor: pwd.struct_passwd,
    runner: int,
    runner_gid: int,
    end: float,
    *,
    source: Path | None = None,
    interrupted: bool = False,
    contact_timeout: int = 30,
    enrollment: str | None = None,
) -> dict[str, Any]:
    with termination_guard():
        return _probe(
            actor,
            runner,
            runner_gid,
            end,
            source=source,
            interrupted=interrupted,
            contact_timeout=contact_timeout,
            enrollment=enrollment,
        )


def root_enrollment(arguments: list[str]) -> tuple[int, int]:
    require(sys.platform == "linux", "ssh-enrollment-unavailable")
    import pwd

    require(arguments and arguments[0] == "--github-hosted-only", "ssh-enrollment-unavailable")
    require(
        os.geteuid() == 0
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("ImageOS") == "ubuntu24",
        "ssh-enrollment-unavailable",
    )
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    require(uid > 0 and gid >= 0 and pwd.getpwuid(uid).pw_gid == gid, "ssh-enrollment-unavailable")
    return uid, gid


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if arguments == ["observe"]:
            value = observe(json.loads(sys.stdin.buffer.read(), object_pairs_hook=unique_object))
            print(json.dumps(value, sort_keys=True))
            return 0
        runner, gid = root_enrollment(arguments)
        import pwd

        if len(arguments) == 8 and arguments[1] == "probe":
            from scripts.native_smoke_cleanup import Identity

            identity = Identity(
                arguments[2], int(arguments[3]), int(arguments[4]), Path(arguments[5])
            )
            require(
                identity.valid() and identity.account == "dtci" + str(runner),
                "ssh-identity-unavailable",
            )
            actor = pwd.getpwnam(identity.account)
            require(
                actor.pw_uid == identity.uid
                and actor.pw_gid == identity.gid
                and actor.pw_dir == "/home/" + identity.account,
                "ssh-identity-unavailable",
            )
            report = probe(
                actor,
                runner,
                gid,
                float(arguments[6]),
                source=identity.work,
                contact_timeout=int(arguments[7]),
            )
            print("native-prerequisite ssh-observation=" + json.dumps(report, sort_keys=True))
        elif len(arguments) == 5 and arguments[1] == "interrupt-after-listener":
            report = probe(
                pwd.getpwuid(runner),
                runner,
                gid,
                float(arguments[2]),
                interrupted=True,
                contact_timeout=int(arguments[3]),
                enrollment=arguments[4],
            )
            print(json.dumps(report, sort_keys=True))
        else:
            raise ValueError("ssh-selection-unavailable")
        return int(report["original_primary_exit"] or report["cleanup_exit"])
    except CommandFailure as error:
        print(
            json.dumps(
                {
                    "scope": SCOPE,
                    "status": "failed",
                    "problem": "ssh-stage-interrupted",
                    "original_primary_exit": error.status,
                    "native_product_qualified": False,
                }
            )
        )
        return error.status
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "scope": SCOPE,
                    "status": "failed",
                    "problem": "ssh-observation-or-custody-unavailable",
                    "native_product_qualified": False,
                },
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
