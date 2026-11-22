"""Owned ordinary-file child processes with administrative enrollment replaced."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fishhat_owner import checkpoint_store as store

from scripts.validation_timeouts import watchdog
from tests.support import ROOT


@contextmanager
def ordinary_enrollment(root):
    journal_fds = set()
    real_os = store.os
    controlled_os = SimpleNamespace(**{name: getattr(real_os, name) for name in dir(real_os)})

    @contextmanager
    def directory(path, metrics):
        assert path.parent == root and path.is_dir()
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
        descriptor = real_os.open(path, real_os.O_RDONLY | real_os.O_DIRECTORY | real_os.O_NOFOLLOW)
        if path.name.startswith("journal"):
            journal_fds.add(descriptor)
        try:
            yield descriptor
        finally:
            journal_fds.discard(descriptor)
            real_os.close(descriptor)

    def fstat(descriptor):
        value = real_os.fstat(descriptor)
        return SimpleNamespace(st_dev=value.st_dev + 1) if descriptor in journal_fds else value

    controlled_os.fstat = fstat
    with patch.object(store, "os", controlled_os), patch.object(store, "_directory", directory):
        yield


def send(connection, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    connection.sendall(len(raw).to_bytes(8, "big") + raw)


def receive(connection):
    def exact(extent):
        chunks = []
        while extent:
            part = connection.recv(min(extent, 65536))
            if not part:
                raise EOFError("owned test controller closed")
            chunks.append(part)
            extent -= len(part)
        return b"".join(chunks)

    return json.loads(exact(int.from_bytes(exact(8), "big")))


@contextmanager
def child_process(paths, owner, journal_id, action, *, inherited=None):
    connection, peer = socket.socketpair()
    connection.settimeout(watchdog(15))
    process = None
    try:
        descriptors = (peer.fileno(),) + (() if inherited is None else (inherited,))
        process = subprocess.Popen(
            [sys.executable, "-m", "tests.checkpoint_process_support", str(peer.fileno())],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=descriptors,
            start_new_session=True,
        )
        peer.close()
        send(
            connection,
            {
                "root": str(paths[0].parent),
                "authority": str(paths[0]),
                "journal": str(paths[1]),
                "owner": owner,
                "journal_id": journal_id,
                "action": action,
                "inherited": inherited,
            },
        )
        yield process, connection
    finally:
        connection.close()
        peer.close()
        if process is not None:
            try:
                process.communicate(timeout=watchdog(15))
            except subprocess.TimeoutExpired:
                process.terminate()
                process.communicate(timeout=watchdog(15))
                raise AssertionError("owned checkpoint test child did not settle") from None


def _alias(configuration, connection):
    import fcntl

    descriptor = configuration["inherited"]
    anchor = Path(configuration["authority"]) / store.ANCHOR
    if descriptor is None:
        original = os.open(anchor, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fcntl.flock(original, fcntl.LOCK_EX | fcntl.LOCK_NB)
            descriptor = os.dup(original)
        finally:
            os.close(original)
    try:
        held, linked = os.fstat(descriptor), anchor.stat()
        assert (held.st_dev, held.st_ino) == (linked.st_dev, linked.st_ino)
        send(connection, {"status": "alias-held"})
        assert receive(connection) == {"operation": "release"}
    finally:
        os.close(descriptor)
    send(connection, {"status": "released"})


def _storage(configuration, connection):
    paths = Path(configuration["authority"]), Path(configuration["journal"])
    with store.CheckpointStore.open(
        *paths, owner=configuration["owner"], journal_id=configuration["journal_id"]
    ) as checkpoint:
        if configuration["action"] == "pause-pending":
            write = store._write_pending

            def pause(directory, value, metrics):
                write(directory, value, metrics)
                send(connection, {"status": "pending-synchronized"})
                receive(connection)

            with patch.object(store, "_write_pending", pause), checkpoint.locked():
                checkpoint.compare_and_swap(None, "1" * 64)
            return
        if configuration["action"] == "commit-without-ack":
            with checkpoint.locked():
                checkpoint.compare_and_swap(None, "1" * 64)
            os._exit(0)
        send(connection, {"status": "ready", "current": checkpoint.read()["current"]})
        while True:
            command = receive(connection)
            if command == {"operation": "close"}:
                send(connection, {"status": "closed"})
                return
            assert command["operation"] == "publish"
            try:
                with checkpoint.locked():
                    value = checkpoint.compare_and_swap(command["expected"], command["current"])
            except BlockingIOError:
                send(connection, {"status": "blocked"})
            else:
                send(connection, {"status": "published", "current": value["current"]})


def main():
    with socket.socket(fileno=int(sys.argv[1])) as connection:
        connection.settimeout(watchdog(15))
        try:
            configuration = receive(connection)
            with ordinary_enrollment(Path(configuration["root"])):
                if configuration["action"] == "alias":
                    _alias(configuration, connection)
                else:
                    _storage(configuration, connection)
        except EOFError:
            return 0
        except BaseException as error:
            try:
                send(
                    connection,
                    {"error_type": type(error).__name__, "errno": getattr(error, "errno", None)},
                )
            except OSError:
                pass
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
