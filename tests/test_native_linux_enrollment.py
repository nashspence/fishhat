"""Controller enrollment refuses unsafe hosts and preserves required failures."""

from __future__ import annotations

import hashlib
import json
import os
import sys

import pytest

from scripts import native_linux_enrollment as native
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import Policy, using

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_linux_enrollment.py", "scripts/validation_timeouts.py"],
    "scope": "enrollment refusal, exact controller identities, maintained watchdogs, sanitized provisioning failures and source/statistics receipts",
    "relationship": "no-product-claim",
    "reason": "Controlled package/tool responses never install packages. A real unprivileged child exercises timeout/reaping. Only the separate admitted disposable-runner job can establish actual controller prerequisites; no guest or native owner is qualified here.",
    "claims": [],
}


@pytest.fixture
def enrollment(tmp_path, monkeypatch):
    environment = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "ImageOS": "ubuntu24",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "push",
        "RUNNER_TEMP": str(tmp_path),
    }
    facts = {
        "platform": "linux",
        "machine": "x86_64",
        "uid": 1001,
        "distribution": "ubuntu",
        "distribution_version": "24.04",
        "pid1": "systemd",
        "cgroup_v2": True,
    }
    monkeypatch.setattr(native, "machine_facts", lambda: dict(facts))
    return environment, facts


@pytest.mark.parametrize(
    "field,value",
    [
        ("GITHUB_ACTIONS", "false"),
        ("RUNNER_ENVIRONMENT", "self-hosted"),
        ("ImageOS", "ubuntu22"),
        ("GITHUB_REF", "refs/pull/1/merge"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("RUNNER_TEMP", "relative"),
    ],
    ids=[
        "ordinary",
        "persistent",
        "wrong-image",
        "pull-request-ref",
        "pull-request-event",
        "wrong-temporary-root",
    ],
)
def test_wrong_enrollment_rejects_before_host_inspection(enrollment, monkeypatch, field, value):
    environment, _ = enrollment
    environment[field] = value

    def forbidden():
        pytest.fail("rejected enrollment inspected the host")

    monkeypatch.setattr(native, "machine_facts", forbidden)
    with pytest.raises(native.EnrollmentError, match=r"required|unavailable"):
        native.enroll(environment, confirmed=True)


@pytest.mark.parametrize(
    "field,value",
    [
        ("uid", 0),
        ("platform", "darwin"),
        ("machine", "aarch64"),
        ("distribution", "debian"),
        ("distribution_version", "22.04"),
        ("pid1", "other"),
        ("cgroup_v2", False),
    ],
    ids=[
        "root",
        "wrong-platform",
        "wrong-abi",
        "wrong-distribution",
        "wrong-version",
        "wrong-init",
        "wrong-cgroup",
    ],
)
def test_host_facts_cannot_be_replaced_by_runner_labels(enrollment, field, value):
    environment, facts = enrollment
    facts[field] = value
    with pytest.raises(native.EnrollmentError, match="selected-controller-host-required"):
        native.enroll(environment, confirmed=True)


def test_enrollment_requires_confirmation_and_accepts_selected_host(enrollment):
    environment, facts = enrollment
    with pytest.raises(native.EnrollmentError, match="explicit-disposable"):
        native.enroll(environment, confirmed=False)
    assert native.enroll(environment, confirmed=True) == facts


@pytest.fixture
def tools(tmp_path, monkeypatch):
    binary = tmp_path / "qemu"
    binary.write_bytes(b"controlled-binary-identity")
    monkeypatch.setattr(native, "QEMU", binary)
    output = "".join(f"{name}\t{native.VERSION}\tamd64\n" for name in native.PACKAGES)
    state = {"packages": output, "version": "QEMU emulator version 8.2.2 (fixture)\n"}
    calls = []

    def run(command, name, nominal, *, capture=False):
        calls.append((command, name, nominal, capture))
        if command[0] == "/usr/bin/dpkg-query":
            return state["packages"]
        if command[0] == str(binary):
            return state["version"]
        return ""

    monkeypatch.setattr(native, "run", run)
    return state, calls, binary


@pytest.mark.parametrize("factor", [1, 4])
def test_selected_packages_root_watchdogs_and_binary_identity(tools, factor):
    _, calls, binary = tools
    with using(Policy(factor)):
        result = native.provision()
    assert result == {
        "packages": dict.fromkeys(native.PACKAGES, native.VERSION),
        "qemu_version": "8.2.2",
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    update, install = calls[:2]
    for command, _, nominal, _ in (update, install):
        assert command[:4] == ["/usr/bin/sudo", "-n", "/usr/bin/timeout", "-k"]
        assert command[4] == str(5 * factor)
        assert command[6:8] == ["/usr/bin/env", "-i"]
        assert f"Acquire::http::Timeout={30 * factor}" in command
        assert f"Acquire::https::Timeout={30 * factor}" in command
        assert f"DPkg::Lock::Timeout={30 * factor}" in command
        assert "Acquire::Retries=0" in command
        assert nominal in {310, 610}
    assert update[0][5] == str(300 * factor)
    assert install[0][5] == str(600 * factor)
    assert all(f"{name}={native.VERSION}" in install[0] for name in native.PACKAGES)


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "duplicate",
        "foreign",
        "wrong-version",
        "wrong-abi",
        "malformed",
        "wrong-binary",
        "missing-binary",
    ],
)
def test_unverified_tool_identity_never_passes(tools, case):
    state, _, binary = tools
    if case == "missing":
        state["packages"] = ""
    elif case == "duplicate":
        state["packages"] += state["packages"]
    elif case == "foreign":
        state["packages"] = state["packages"].replace("qemu-utils", "foreign-package")
    elif case == "wrong-version":
        state["packages"] = state["packages"].replace(native.VERSION, "other-version")
    elif case == "wrong-abi":
        state["packages"] = state["packages"].replace("amd64", "arm64")
    elif case == "malformed":
        state["packages"] = "qemu-utils\n"
    elif case == "wrong-binary":
        state["version"] = "QEMU emulator version 8.2.1\n"
    else:
        binary.unlink()
    with pytest.raises(
        native.EnrollmentError, match=r"identity-mismatch|version-mismatch|binary-unavailable"
    ):
        native.provision()


def test_ordinary_invocation_creates_no_artifacts_or_native_commands(tmp_path, monkeypatch):
    output = tmp_path / "absent" / "report.json"

    def forbidden(*args, **kwargs):
        pytest.fail("ordinary invocation reached native setup")

    monkeypatch.setattr(native, "provision", forbidden)
    assert native.main(["--output", str(output)]) == 2
    assert not output.parent.exists()


@pytest.mark.parametrize("failure", ["none", "provisioning", "dirty-source", "changed-source"])
def test_selected_run_records_failure_source_scope_and_required_statistics(
    tmp_path, monkeypatch, tools, failure, capsys
):
    output = tmp_path / "report.json"
    before = {"commit": "a" * 40, "clean": failure != "dirty-source", "fingerprint": "b" * 64}
    after = {**before, "commit": "c" * 40} if failure == "changed-source" else before
    sources = iter([before, after])
    monkeypatch.setattr(native, "source_identity", lambda: next(sources))
    monkeypatch.setattr(native, "enroll", lambda *args, **kwargs: {"machine": "x86_64"})
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr(native, "probe_controller", lambda *args: {"controlled_fixture": True})
    monkeypatch.setattr(native, "controller_faults", lambda *args: None)
    monkeypatch.setenv("NATIVE_TEST_SECRET", "fixture-private-value")
    if failure == "provisioning":

        def failed():
            raise native.EnrollmentError("package-install", "command-exit-19")

        monkeypatch.setattr(native, "provision", failed)
    status = native.main(["--github-hosted-only", "--output", str(output)])
    report = json.loads(output.read_text())
    assert status == (0 if failure == "none" else 1)
    assert report["status"] == ("passed" if failure == "none" else "failed")
    assert report["guest_booted"] is False
    assert report["native_tools_qualified"] is report["production_qualified"] is False
    assert report["source_before"] == before and report["source_after"] == after
    assert valid_stats(report["statistics"])
    assert report["statistics"]["scope"] == "process-excludes-children"
    if failure == "provisioning":
        assert report["problem"] == {"stage": "package-install", "reason": "command-exit-19"}
    if failure == "dirty-source":
        assert not tools[1]
    logs = capsys.readouterr()
    assert "fixture-private-value" not in output.read_text() + logs.out + logs.err


def test_real_command_failure_discards_private_output_and_inherited_environment(monkeypatch):
    monkeypatch.setenv("NATIVE_TEST_SECRET", "fixture-private-value")
    assert (
        native.run(
            [
                sys.executable,
                "-c",
                "import os; print(os.environ.get('NATIVE_TEST_SECRET','absent'))",
            ],
            "identity",
            10,
            capture=True,
        )
        == "absent\n"
    )
    with pytest.raises(native.EnrollmentError, match="command-exit-23") as caught:
        native.run(
            [sys.executable, "-c", "import sys; print('private-fixture-output'); sys.exit(23)"],
            "identity",
            10,
            capture=True,
        )
    assert "private-fixture-output" not in str(caught.value)


def test_real_held_command_expires_and_is_reaped(tmp_path):
    pid_file = tmp_path / "child.pid"
    code = "import os,sys,time; from pathlib import Path; Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)"
    with pytest.raises(native.EnrollmentError, match="observation-deadline"):
        native.run([sys.executable, "-c", code, str(pid_file)], "held-command", 0.5)
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_missing_command_is_a_required_failure(tmp_path):
    with pytest.raises(native.EnrollmentError, match="command-unavailable"):
        native.run([str(tmp_path / "absent-command")], "identity", 10)
