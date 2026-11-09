"""Probe real local child/socket plumbing without enrolling QEMU or a guest."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from scripts import native_linux_enrollment as native
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import Deadline, watchdog

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_linux_enrollment.py", "scripts/validation_timeouts.py"],
    "scope": "owned child/Unix peer identity, QMP framing/correlation, shared observation deadline and quiescent controller cleanup",
    "relationship": "no-product-claim",
    "reason": "Real unprivileged Python children and private Unix sockets challenge the tooling. They never launch QEMU, boot a guest or establish native owner behavior; actual disposable main evidence remains separately required.",
    "claims": [],
}

SERVER = r"""
import json, socket, sys

endpoint, identity, mode = sys.argv[1:]
version = {"major": 8, "minor": 2, "micro": 2}
greeting = {"qemu": dict(version), "package": "fixture"}
if mode == "wrong-greeting": greeting["qemu"]["minor"] = 3
if mode == "float-greeting": greeting["qemu"]["major"] = 8.0
if mode == "invalid-version": greeting = []
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
    server.bind(endpoint)
    server.listen(1)
    connection, _ = server.accept()
    with connection, connection.makefile("rb") as reader:
        connection.sendall(json.dumps({"QMP": {"version": greeting, "capabilities": []}}).encode()+b"\r\n")
        for line in reader:
            command = json.loads(line)
            name = command["execute"]
            if name == "qmp_capabilities":
                result = {"unexpected": True} if mode == "capabilities" else {}
            elif name == "query-version":
                result = {"qemu": {**version, "minor": 3 if mode == "wrong-query" else 2}}
                if mode == "float-query": result["qemu"]["major"] = 8.0
            elif name == "query-uuid":
                result = {"UUID": "foreign-fixture" if mode == "wrong-instance" else identity}
            elif name == "query-status":
                result = {"running": mode == "running", "status": "paused" if mode == "wrong-state" else "prelaunch"}
            elif name == "query-kvm":
                result = {"enabled": mode == "kvm", "present": True}
            else:
                raise RuntimeError("unexpected fixture command")
            data = json.dumps({"return": result, "id": command["id"]}).encode()+b"\r\n"
            if mode == "events": data = b'{"event":"FIXTURE","data":{"private":"fixture-only"}}\r\n'+data
            connection.sendall(data[:7])
            connection.sendall(data[7:])
"""


@pytest.fixture
def controller(tmp_path, monkeypatch):
    program = tmp_path / "controller.py"
    program.write_text(SERVER)
    state = {"mode": "normal", "children": [], "endpoints": [], "identities": []}
    real_popen = subprocess.Popen
    monkeypatch.setattr(native, "QEMU", Path(sys.executable))

    def start(endpoint, identity):
        assert endpoint.parent.stat().st_mode & 0o777 == 0o700
        state["endpoints"].append(endpoint)
        state["identities"].append(identity)
        child = real_popen(
            [sys.executable, str(program), str(endpoint), identity, state["mode"]],
            env=native.COMMAND_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            umask=0o077,
        )
        state["children"].append(child)
        return child

    monkeypatch.setattr(native, "start_controller", start)
    digest = hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="fht-", dir="/tmp") as directory:
        yield state, digest, Path(directory)
        for child in state["children"]:
            if child.returncode is None:
                child.kill()
                child.wait(timeout=watchdog(5))


def test_launch_uses_only_paused_diskless_tcg_and_private_control(tmp_path, monkeypatch):
    calls = []

    def popen(command, **kwargs):
        calls.append((command, kwargs))
        return "controlled-launch"

    monkeypatch.setattr(native.subprocess, "Popen", popen)
    endpoint = tmp_path / "qmp"
    assert native.start_controller(endpoint, "fixture-identity") == "controlled-launch"
    command, options = calls[0]
    assert command[0] == str(native.QEMU)
    for flag, value in [
        ("-machine", "none"),
        ("-accel", "tcg"),
        ("-nic", "none"),
        ("-display", "none"),
        ("-monitor", "none"),
        ("-m", "128M"),
        ("-smp", "1"),
    ]:
        assert command[command.index(flag) + 1] == value
    assert {"-S", "-nodefaults", "-no-user-config"} <= set(command)
    assert command[-2:] == ["-qmp", f"unix:{endpoint},server=on,wait=off"]
    assert options["env"] == native.COMMAND_ENV
    assert options["start_new_session"] and options["umask"] == 0o077
    assert options["cwd"] == endpoint.parent
    assert options["stdin"] == options["stdout"] == options["stderr"] == subprocess.DEVNULL


@pytest.mark.parametrize("mode", ["normal", "events"])
def test_real_child_peer_protocol_and_cleanup_leave_unrelated_process(controller, mode):
    state, digest, directory = controller
    state["mode"] = mode
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(60)"], start_new_session=True
    )
    try:
        result = native.probe_controller(digest, directory)
        assert result["instance_uuid"] == state["identities"][0]
        assert result["qmp_version"] == {"major": 8, "minor": 2, "micro": 2}
        assert result["executable_sha256"] == digest
        assert result["accelerator"] == "tcg" and result["machine"] == "none"
        assert result["status"] == "prelaunch" and result["running"] is False
        assert result["unix_peer_verified"] and result["process_reaped"]
        assert result["temporary_resources_removed"] and not list(directory.iterdir())
        assert not state["endpoints"][0].parent.exists()
        assert state["children"][0].returncode is not None
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=watchdog(5))


@pytest.mark.parametrize(
    "mode",
    [
        "wrong-greeting",
        "invalid-version",
        "float-greeting",
        "float-query",
        "wrong-query",
        "wrong-instance",
        "running",
        "wrong-state",
        "kvm",
        "capabilities",
    ],
)
def test_wrong_controller_identity_never_passes_and_owned_child_is_reaped(controller, mode):
    state, digest, directory = controller
    state["mode"] = mode
    with pytest.raises(native.EnrollmentError):
        native.probe_controller(digest, directory)
    assert state["children"][0].returncode is not None
    assert not list(directory.iterdir())


def test_executing_binary_must_match_selected_package_identity(controller):
    state, _, directory = controller
    with pytest.raises(native.EnrollmentError, match="executable-mismatch"):
        native.probe_controller("0" * 64, directory)
    assert state["children"][0].returncode is not None
    assert not list(directory.iterdir())


def test_kernel_unix_peer_must_be_the_owned_child(controller, monkeypatch):
    state, digest, directory = controller
    unpack = native.struct.unpack

    def different_peer(format, data):
        pid, uid, gid = unpack(format, data)
        return pid + 1, uid, gid

    monkeypatch.setattr(native.struct, "unpack", different_peer)
    with pytest.raises(native.EnrollmentError, match="control-peer-mismatch"):
        native.probe_controller(digest, directory)
    assert state["children"][0].returncode is not None
    assert not list(directory.iterdir())


class Connection:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.timeouts = []
        self.sent = []

    def settimeout(self, remaining):
        self.timeouts.append(remaining)

    def recv(self, count):
        assert count == 4096
        return next(self.chunks, b"")

    def sendall(self, data):
        self.sent.append(json.loads(data))


@pytest.mark.parametrize(
    "response",
    [
        {"return": {}, "id": 0},
        {"return": {}, "id": True},
        {"return": {}, "id": 1.0},
        {"error": {"desc": "fixture-private-output"}, "id": 1},
    ],
    ids=["stale-reply", "boolean-reply", "float-reply", "rejected"],
)
def test_commands_require_their_own_success_response(response):
    connection = Connection([json.dumps(response).encode() + b"\n"])
    qmp = native.Qmp(connection, Deadline.after(5))
    with pytest.raises(native.EnrollmentError, match="uncorrelated-or-rejected-command") as caught:
        qmp.command("qmp_capabilities")
    assert "fixture-private-output" not in str(caught.value)


def test_fragmented_reads_and_multiple_commands_consume_one_deadline():
    class Budget:
        def __init__(self):
            self.value = 1.0

        def remaining(self):
            self.value = max(0, self.value - 0.15)
            return self.value

    connection = Connection([b'{"return":', b'{},"id":1}\n', b'{"return":{},"id":2}\n'])
    qmp = native.Qmp(connection, Budget())
    assert qmp.command("qmp_capabilities") == {}
    with pytest.raises(native.EnrollmentError, match="observation-deadline"):
        qmp.command("query-version")
    assert all(
        a > b > 0 for a, b in zip(connection.timeouts, connection.timeouts[1:], strict=False)
    )


def test_probe_failure_is_retained_as_failed_unqualified_enrollment(tmp_path, monkeypatch):
    source = {"commit": "a" * 40, "clean": True, "fingerprint": "b" * 64}
    monkeypatch.setattr(native, "enroll", lambda *args, **kwargs: {})
    monkeypatch.setattr(native, "source_identity", lambda: source)
    monkeypatch.setattr(native, "provision", lambda: {"binary_sha256": "c" * 64})
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))

    def failed(*args):
        raise native.EnrollmentError("controller-identity", "instance-mismatch")

    monkeypatch.setattr(native, "probe_controller", failed)
    output = tmp_path / "report.json"
    assert native.main(["--github-hosted-only", "--output", str(output)]) == 1
    report = json.loads(output.read_text())
    assert report["status"] == "failed"
    assert report["problem"] == {"stage": "controller-identity", "reason": "instance-mismatch"}
    assert (
        not report["guest_booted"]
        and not report["native_tools_qualified"]
        and not report["production_qualified"]
    )
    assert valid_stats(report["statistics"])
