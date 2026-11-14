"""Single-caller, deadline-bound command and protocol custody for disposable storage."""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from scripts.native_smoke_interruption import unique_object
from scripts.native_smoke_loop import live, require, same_claim, token
from scripts.native_smoke_ssh import process_state
from scripts.validation_timeouts import Deadline


class CommandFailed(ValueError):
    def __init__(self, status: int):
        self.status = status if 0 < status < 256 else 1
        super().__init__("storage-command-failed")


class ParentLost(ValueError):
    pass


@dataclass
class Parent:
    handle: int
    identity: dict[str, Any]

    @classmethod
    def open(cls, pid: int, uid: int, gid: int, end: float) -> Parent:
        live(end)
        before = process_state(pid)
        handle = os.pidfd_open(pid)
        try:
            require(before == process_state(pid), "storage-parent-changed")
            require(
                before["uids"] == [uid] * 4 and before["gids"] == [gid] * 4,
                "storage-parent-actor-mismatch",
            )
            ancestor, seen = os.getppid(), set()
            while ancestor != pid:
                require(ancestor > 1 and ancestor not in seen, "storage-parent-not-ancestor")
                seen.add(ancestor)
                ancestor = process_state(ancestor)["parent_pid"]
            result = cls(handle, before)
            result.check()
            return result
        except BaseException:
            os.close(handle)
            raise

    def check(self) -> None:
        if select.select([self.handle], [], [], 0)[0]:
            raise ParentLost("storage-parent-exited")

    def close(self) -> None:
        os.close(self.handle)


class Commands:
    def __init__(self, parent: Parent | None):
        self.parent = parent

    def run(
        self,
        arguments: list[str],
        end: float,
        *,
        descriptors: tuple[int, ...] = (),
        payload: bytes = b"",
        uid: int | None = None,
        gid: int | None = None,
        cwd: Path = Path("/"),
        environment: dict[str, str] | None = None,
    ) -> bytes:
        live(end)
        if self.parent is not None:
            self.parent.check()
        with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as output:
            source.write(payload)
            source.seek(0)
            with tempfile.TemporaryFile() as errors:
                process = subprocess.Popen(
                    arguments,
                    stdin=source,
                    stdout=output,
                    stderr=errors,
                    pass_fds=descriptors,
                    env={
                        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                        "LANG": "C",
                        "LC_ALL": "C",
                        **(environment or {}),
                    },
                    cwd=cwd,
                    user=uid,
                    group=gid,
                    extra_groups=[] if uid is not None else None,
                )
                handle = None
                try:
                    handle = os.pidfd_open(process.pid)
                    watched = [handle] + ([] if self.parent is None else [self.parent.handle])
                    timer = Deadline(end)
                    ready = select.select(watched, [], [], timer.remaining())[0]
                    if self.parent is not None and self.parent.handle in ready:
                        raise ParentLost("storage-parent-exited")
                    require(handle in ready, "storage-command-deadline")
                    status = process.wait(timeout=timer.remaining())
                    if status:
                        raise CommandFailed(status)
                    output.seek(0)
                    return output.read()
                finally:
                    if process.poll() is None:
                        # This unreaped direct Popen child is our authority;
                        # no numeric PID or caller-supplied claim selects it.
                        if handle is None:
                            process.kill()
                        else:
                            signal.pidfd_send_signal(handle, signal.SIGKILL)
                        grace = Deadline.after(5)
                        process.wait(timeout=grace.remaining())
                    if handle is not None:
                        os.close(handle)


def receive(descriptor: int, end: float, parent: Parent | None = None) -> Any:
    raw = bytearray()
    while True:
        live(end)
        watched = [descriptor] + ([] if parent is None else [parent.handle])
        ready = select.select(watched, [], [], Deadline(end).remaining())[0]
        if parent is not None and parent.handle in ready:
            raise ParentLost("storage-parent-exited")
        require(descriptor in ready, "storage-protocol-deadline")
        block = os.read(descriptor, 16384)
        if not block:
            raise ParentLost("storage-protocol-eof")
        raw.extend(block)
        if b"\n" in block:
            require(raw.count(b"\n") == 1 and raw.endswith(b"\n"), "storage-protocol-overlap")
            return json.loads(raw, object_pairs_hook=unique_object)


def send(descriptor: int, value: Any, end: float, parent: Parent | None = None) -> None:
    raw = json.dumps(value, sort_keys=True, allow_nan=False).encode() + b"\n"
    offset = 0
    while offset < len(raw):
        live(end)
        watched = [] if parent is None else [parent.handle]
        readable, writable, _ = select.select(watched, [descriptor], [], Deadline(end).remaining())
        if parent is not None and parent.handle in readable:
            raise ParentLost("storage-parent-exited")
        require(writable, "storage-protocol-deadline")
        # PIPE_BUF-sized writes cannot turn a ready bounded pipe observation
        # into an unbounded large blocking write. This chunks a complete frame.
        count = os.write(descriptor, memoryview(raw)[offset : offset + 4096])
        require(count > 0, "storage-protocol-progress-unavailable")
        offset += count


class Backend(Protocol):
    def claim(self) -> dict[str, Any]: ...
    def setup(self, end: float) -> dict[str, Any]: ...
    def quota(self, dimension: str, end: float) -> dict[str, Any]: ...
    def cleanup(self, end: float) -> dict[str, Any]: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class Outcome:
    primary: int
    cleanup: int

    @property
    def status(self) -> int:
        return self.primary or self.cleanup


def serve(
    backend: Backend,
    enrollment: str,
    parent: Parent,
    source: int,
    destination: int,
    end: float,
) -> Outcome:
    """Retain the backend across requests; caller loss always enters owned cleanup."""
    token(enrollment)
    primary = 0
    cleaned = False
    cleanup_exit = 0
    try:
        while True:
            request = receive(source, end, parent)
            action = None
            try:
                require(
                    type(request) is dict
                    and set(request) == {"enrollment", "action", "claim", "end", "primary"},
                    "storage-request-unavailable",
                )
                require(request["enrollment"] == enrollment, "storage-foreign-enrollment-refused")
                action = request["action"]
                require(action in {"setup", "bytes", "inodes", "cleanup"}, "storage-action-refused")
                require(
                    same_claim(request["claim"], backend.claim()), "storage-foreign-claim-refused"
                )
                stage_end = request["end"]
                live(stage_end)
                require(stage_end <= end, "storage-stage-deadline-refused")
                require(
                    type(request["primary"]) is int and 0 <= request["primary"] < 256,
                    "storage-primary-outcome-unavailable",
                )
                if action == "cleanup":
                    primary = primary or request["primary"]
                    cleaned = True
                    proof = backend.cleanup(stage_end)
                elif action == "setup":
                    proof = backend.setup(stage_end)
                else:
                    proof = backend.quota(action, stage_end)
                reply = {"status": 0, "claim": backend.claim(), "proof": proof}
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                status = error.status if isinstance(error, CommandFailed) else 1
                if cleaned:
                    cleanup_exit = status
                else:
                    primary = primary or status
                reply = {
                    "status": status,
                    "claim": backend.claim(),
                    "proof": {"status": "failed", "problem": "storage-request-failed"},
                }
                if isinstance(error, ParentLost):
                    raise
            send(destination, reply, end, parent)
            if cleaned:
                break
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        primary = primary or 1
    finally:
        if not cleaned:
            try:
                # The remaining existing lifecycle ceiling bounds emergency
                # cleanup too. No new retry or independent root budget exists.
                backend.cleanup(min(end, Deadline.after(120).end))
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                cleanup_exit = 1
        try:
            backend.close()
        except (OSError, ValueError, ExceptionGroup):
            cleanup_exit = 1
    return Outcome(primary, cleanup_exit)
