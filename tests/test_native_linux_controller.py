"""Probe real local child/socket plumbing without enrolling QEMU or a guest."""

from __future__ import annotations

import hashlib
import json
import os
import signal
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
import json, socket, sys, time

endpoint, identity, mode = sys.argv[1:]
if mode == "exit-before-socket": sys.exit(23)
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
        if mode == "stall-greeting": time.sleep(60)
        connection.sendall(json.dumps({"QMP": {"version": greeting, "capabilities": []}}).encode()+b"\r\n")
        for line in reader:
            command = json.loads(line)
            name = command["execute"]
            if mode == "stall-reply": time.sleep(60)
            if mode == "partial-reply":
                connection.sendall(b'{"private":"fixture-private-output"')
                break
            if mode == "malformed-reply":
                connection.sendall(b'{"private":"fixture-private-output",}\n')
                break
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


@pytest.mark.parametrize(
    "frame",
    [
        b'{"private":"fixture-private-output",}\n',
        b'{"return":{},"return":{},"id":1}\n',
        b'{"return":{"n":NaN},"id":1}\n',
        b'{"return":{"s":"\xff"},"id":1}\n',
        '{"return":{},"id":1}\n'.encode("utf-16"),
        b"[]\n",
        b'{"return":{"nested":' + b"[" * 2000 + b'"fixture-private-output"}\n',
        b"x" * 65537 + b"\n",
    ],
    ids=[
        "syntax",
        "duplicate-fields",
        "non-finite",
        "invalid-utf8",
        "utf16",
        "array",
        "deep",
        "oversized",
    ],
)
def test_malformed_control_frames_fail_without_exposing_payload(frame):
    connection = Connection([frame])
    with pytest.raises(native.EnrollmentError, match="invalid-control-frame") as caught:
        native.Qmp(connection, Deadline.after(5)).command("query-status")
    assert "fixture-private-output" not in str(caught.value)


def test_event_cannot_masquerade_as_a_correlated_command_result():
    response = b'{"event":"fixture","return":{},"id":1}\n'
    with pytest.raises(native.EnrollmentError, match="uncorrelated-or-rejected-command"):
        native.Qmp(Connection([response]), Deadline.after(5)).command("query-status")


@pytest.mark.parametrize(
    "mode,reason",
    [
        ("exit-before-socket", r"owned-controller-unavailable|controller-unavailable"),
        ("stall-greeting", "observation-deadline"),
        ("stall-reply", "observation-deadline"),
        ("partial-reply", "control-connection-closed"),
        ("malformed-reply", "invalid-control-frame"),
    ],
    ids=["exit", "stalled-greeting", "stalled-command", "closed-partial", "malformed"],
)
def test_live_protocol_failure_reaps_child_and_removes_only_owned_resources(
    controller, monkeypatch, mode, reason
):
    state, digest, directory = controller
    state["mode"] = mode
    marker = directory / "unrelated"
    marker.write_text("keep")
    real_after = Deadline.after
    monkeypatch.setattr(
        native.Deadline, "after", lambda nominal: real_after(2 if nominal == 30 else nominal)
    )
    with pytest.raises(native.EnrollmentError, match=reason) as caught:
        native.probe_controller(digest, directory)
    assert "fixture-private-output" not in str(caught.value)
    assert state["children"][0].returncode is not None
    assert not state["endpoints"][0].parent.exists()
    assert marker.read_text() == "keep"
    assert list(directory.iterdir()) == [marker]


def test_controller_launch_failure_removes_private_directory(controller, monkeypatch):
    _, digest, directory = controller
    owned = []

    def unavailable(endpoint, identity):
        owned.append(endpoint.parent)
        raise OSError("fixture-private-output")

    monkeypatch.setattr(native, "start_controller", unavailable)
    with pytest.raises(native.EnrollmentError, match="controller-unavailable") as caught:
        native.probe_controller(digest, directory)
    assert "fixture-private-output" not in str(caught.value)
    assert owned and not owned[0].exists() and not list(directory.iterdir())


def test_real_fault_matrix_preserves_refusals_statistics_and_unrelated_resources(controller):
    state, digest, directory = controller
    marker = directory / "unrelated"
    marker.write_text("keep")
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(60)"], start_new_session=True
    )
    results = []
    try:
        native.controller_faults(digest, directory, results)
        assert [case["scenario"] for case in results] == [
            "socket-setup",
            "controller-loss",
            "control-stall",
        ]
        assert [case["identity_verified_before_fault"] for case in results] == [False, True, True]
        for case in results:
            assert case["status"] == "failed" and case["expected_failure_verified"] is True
            assert case["scope"] == "disposable-controller-injected-fault-only"
            assert case["process_reaped"] and case["temporary_resources_removed"]
            assert case["fault_injection_verified"] is True
            assert valid_stats(case["statistics"])
            assert case["statistics"]["scope"] == "process-excludes-children"
        assert all(child.returncode is not None for child in state["children"])
        assert all(not endpoint.parent.exists() for endpoint in state["endpoints"])
        assert marker.read_text() == "keep" and list(directory.iterdir()) == [marker]
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=watchdog(5))


def test_cleanup_failure_cannot_be_accepted_as_an_expected_fault(controller, monkeypatch):
    state, digest, directory = controller
    real_stop = native.stop_controller

    def failed_cleanup(process):
        real_stop(process)
        raise native.EnrollmentError("controller-cleanup", "controlled-cleanup-failure")

    monkeypatch.setattr(native, "stop_controller", failed_cleanup)
    results = []
    with pytest.raises(native.EnrollmentError, match="required-failure-proof-missing"):
        native.controller_faults(digest, directory, results)
    assert len(results) == 1 and not results[0]["expected_failure_verified"]
    assert results[0]["status"] == "failed"
    assert results[0]["problem"]["stage"] == "controller-cleanup"
    assert valid_stats(results[0]["statistics"])
    assert state["children"][0].returncode is not None and not list(directory.iterdir())


def test_group_identity_mismatch_never_signals_an_unrelated_group(controller, monkeypatch):
    state, digest, directory = controller
    real_getpgid = native.os.getpgid
    real_stop = native.stop_controller
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(60)"], start_new_session=True
    )
    signalled_groups = []
    real_killpg = native.os.killpg

    def killpg(group, sig):
        signalled_groups.append(group)
        return real_killpg(group, sig)

    def mismatched_stop(process):
        monkeypatch.setattr(native.os, "getpgid", lambda pid: unrelated.pid)
        return real_stop(process)

    monkeypatch.setattr(native.os, "killpg", killpg)
    monkeypatch.setattr(native, "stop_controller", mismatched_stop)
    try:
        with pytest.raises(native.EnrollmentError, match="process-group-mismatch"):
            native.probe_controller(digest, directory)
        assert unrelated.poll() is None
        assert signalled_groups == []
        assert state["children"][0].returncode is not None and not list(directory.iterdir())
    finally:
        monkeypatch.setattr(native.os, "getpgid", real_getpgid)
        unrelated.terminate()
        unrelated.wait(timeout=watchdog(5))


def test_unresponsive_owned_group_is_force_killed_and_reaped(tmp_path):
    ready = tmp_path / "ready"
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal,sys,time;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);Path(sys.argv[1]).touch();time.sleep(60)",
            str(ready),
        ],
        start_new_session=True,
    )
    try:
        deadline = Deadline.after(10)
        while not ready.exists():
            native.controller_remaining(deadline)
            native.time.sleep(min(0.02, native.controller_remaining(deadline)))
        native.stop_controller(process)
        assert process.returncode == -signal.SIGKILL
        with pytest.raises(ProcessLookupError):
            os.kill(process.pid, 0)
        with pytest.raises(ProcessLookupError):
            os.killpg(process.pid, 0)
    finally:
        if process.returncode is None:
            process.kill()
            process.wait(timeout=watchdog(5))


def test_required_fault_failure_returns_failed_enrollment_and_original_statistics(
    controller, monkeypatch, tmp_path
):
    _, digest, directory = controller
    source = {"commit": "a" * 40, "clean": True, "fingerprint": "b" * 64}
    monkeypatch.setattr(native, "enroll", lambda *args, **kwargs: {})
    monkeypatch.setattr(native, "source_identity", lambda: source)
    monkeypatch.setattr(native, "provision", lambda: {"binary_sha256": digest})
    monkeypatch.setenv("RUNNER_TEMP", str(directory))
    real_stop = native.stop_controller
    calls = 0

    def selected_failure(process):
        nonlocal calls
        calls += 1
        real_stop(process)
        if calls == 2:
            raise native.EnrollmentError("controller-cleanup", "controlled-cleanup-failure")

    monkeypatch.setattr(native, "stop_controller", selected_failure)
    output = tmp_path / "report.json"
    assert native.main(["--github-hosted-only", "--output", str(output)]) == 1
    report = json.loads(output.read_text())
    assert report["status"] == "failed"
    assert report["problem"] == {
        "stage": "controller-faults",
        "reason": "required-failure-proof-missing",
    }
    assert report["controller_faults"][0]["problem"]["stage"] == "controller-cleanup"
    assert not report["controller_faults"][0]["expected_failure_verified"]
    assert valid_stats(report["statistics"])
    assert valid_stats(report["controller_faults"][0]["statistics"])
    assert report["source_before"] == report["source_after"] == source
    assert not any(
        report[key] for key in ("guest_booted", "native_tools_qualified", "production_qualified")
    )


def test_an_unexpected_success_in_a_selected_failure_case_blocks_the_matrix(
    controller, monkeypatch
):
    state, digest, directory = controller
    real_command = native.Qmp.command

    def command(self, name):
        if name == "query-status" and native.child_exited(state["children"][-1]):
            return {}
        return real_command(self, name)

    monkeypatch.setattr(native.Qmp, "command", command)
    results = []
    with pytest.raises(native.EnrollmentError, match="required-failure-proof-missing"):
        native.controller_faults(digest, directory, results)
    assert len(results) == 2
    assert results[0]["expected_failure_verified"]
    assert results[1]["status"] == "passed" and not results[1]["expected_failure_verified"]
    assert "problem" not in results[1]
    assert valid_stats(results[1]["statistics"])
    assert all(child.returncode is not None for child in state["children"])
    assert not list(directory.iterdir())


def test_failed_fault_injection_cannot_supply_an_expected_controller_loss(controller, monkeypatch):
    state, digest, directory = controller
    real_kill = native.os.kill

    def kill(pid, sig):
        if sig == signal.SIGKILL and pid == state["children"][-1].pid:
            raise PermissionError("fixture-private-output")
        return real_kill(pid, sig)

    monkeypatch.setattr(native.os, "kill", kill)
    results = []
    with pytest.raises(native.EnrollmentError, match="required-failure-proof-missing"):
        native.controller_faults(digest, directory, results)
    assert len(results) == 2 and results[0]["expected_failure_verified"]
    assert results[1]["problem"] == {
        "stage": "controller-probe",
        "reason": "controller-unavailable",
    }
    assert not results[1]["fault_injection_verified"]
    assert not results[1]["expected_failure_verified"]
    assert valid_stats(results[1]["statistics"])
    assert "fixture-private-output" not in json.dumps(results)
    assert all(child.returncode is not None for child in state["children"])
    assert not list(directory.iterdir())
