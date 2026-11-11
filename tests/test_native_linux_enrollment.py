"""Controller enrollment refuses unsafe hosts and preserves required failures."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from scripts import native_linux_enrollment as native
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import Policy, using

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_linux_enrollment.py", "scripts/validation_timeouts.py"],
    "scope": "enrollment refusal, exact controller identities, maintained watchdogs, allowlisted secret-safe package/image failure observations, sanitized provisioning failures and source/statistics receipts",
    "relationship": "no-product-claim",
    "reason": "Controlled package/tool responses never install packages. Real unprivileged children exercise timeout/reaping and closed stdout/stderr classification without exposing their output. Only the separate admitted disposable-runner job can establish actual controller prerequisites; no guest or native owner is qualified here.",
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


@pytest.mark.parametrize(
    "failure",
    [
        "none",
        "provisioning",
        "package-classified",
        "image-http-classified",
        "image-malformed",
        "dirty-source",
        "changed-source",
    ],
)
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
    monkeypatch.setattr(native, "guest_storage_faults", lambda *a: None)
    monkeypatch.setattr(native, "guest_reboot_faults", lambda *a: None)
    monkeypatch.setattr(native, "verify_guest_cleanup", lambda *a: None)
    monkeypatch.setattr(native, "provision_tools", lambda *args: {})
    monkeypatch.setattr(native, "boot_guest", lambda *args: None)
    monkeypatch.setattr(
        native,
        "guest_inputs",
        lambda *args: nullcontext(SimpleNamespace(verify=lambda *args: None)),
    )
    monkeypatch.setenv("NATIVE_TEST_SECRET", "fixture-private-value")
    if failure == "provisioning":

        def failed():
            raise native.EnrollmentError("package-install", "command-exit-19")

        monkeypatch.setattr(native, "provision", failed)
    elif failure == "package-classified":

        def package_failed():
            raise native.PackageCommandError(
                "package-install", 100, "Version 'fixture-private-value' was not found"
            )

        monkeypatch.setattr(native, "provision", package_failed)
    elif failure in ("image-http-classified", "image-malformed"):

        def image_failed(*args):
            raise native.ImageDownloadCommandError(
                "guest-image-download",
                40,
                '{"http_status":503}'
                if failure == "image-http-classified"
                else "fixture-private-value",
            )

        monkeypatch.setattr(native, "guest_inputs", image_failed)
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
    if failure == "package-classified":
        assert report["problem"] == {
            "stage": "package-install",
            "reason": "command-exit-100",
            "classifications": ["pinned-package-unavailable"],
        }
    if failure in ("image-http-classified", "image-malformed"):
        expected = {
            "stage": "guest-image-download",
            "reason": "command-exit-40",
            "classifications": ["image-http-response-failure"],
        }
        if failure == "image-http-classified":
            expected["http_status"] = 503
        assert report["problem"] == expected
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


@pytest.mark.parametrize("stage", ["package-update", "package-install"])
@pytest.mark.parametrize(
    "message,classes",
    [
        pytest.param(
            "Version 'fixture-private-value' was not found",
            ("pinned-package-unavailable",),
            id="pin",
        ),
        pytest.param(
            "NO_PUBKEY fixture-private-value",
            ("package-authentication-failure",),
            id="authentication",
        ),
        pytest.param(
            "Temporary failure resolving fixture-private-value",
            ("package-transport-failure",),
            id="transport",
        ),
        pytest.param(
            "Failed to fetch fixture-private-value", ("package-fetch-failure",), id="fetch"
        ),
        pytest.param(
            "Hash Sum mismatch fixture-private-value", ("package-content-mismatch",), id="content"
        ),
        pytest.param(
            "Could not get lock fixture-private-value", ("package-state-conflict",), id="state"
        ),
        pytest.param(
            "unmet dependencies fixture-private-value",
            ("package-dependency-failure",),
            id="dependency",
        ),
        pytest.param(
            "No space left on device fixture-private-value",
            ("package-resource-failure",),
            id="resource",
        ),
        pytest.param("fixture-private-value", ("unclassified-package-failure",), id="unknown"),
        pytest.param(
            "Failed to fetch fixture-private-value: Temporary failure resolving",
            ("package-fetch-failure", "package-transport-failure"),
            id="multiple",
        ),
    ],
)
def test_package_command_failure_keeps_original_exit_and_only_allowlisted_classes(
    stage, message, classes, capsys
):
    code = (
        "import sys; print('fixture-private-value'); sys.stderr.write(sys.argv[1]); sys.exit(100)"
    )
    with pytest.raises(native.EnrollmentError) as caught:
        native.run([sys.executable, "-I", "-S", "-c", code, message], stage, 10, capture=True)
    assert caught.value.stage == stage and caught.value.reason == "command-exit-100"
    assert getattr(caught.value, "classifications", None) == classes
    assert "fixture-private-value" not in str(caught.value) + repr(caught.value.__dict__)
    logs = capsys.readouterr()
    assert logs.out == logs.err == ""


@pytest.mark.parametrize("stage", ["package-update", "package-install"])
def test_successful_package_command_does_not_publish_stderr_diagnostics(stage, capsys):
    code = "import sys; print('fixture-private-value'); sys.stderr.write('Failed to fetch fixture-private-value')"
    assert native.run([sys.executable, "-I", "-S", "-c", code], stage, 10) == ""
    logs = capsys.readouterr()
    assert logs.out == logs.err == ""


def test_unrelated_command_does_not_acquire_package_diagnostics(capsys):
    code = "import sys; sys.stderr.write('NO_PUBKEY fixture-private-value'); sys.exit(23)"
    with pytest.raises(native.EnrollmentError) as caught:
        native.run([sys.executable, "-I", "-S", "-c", code], "identity", 10, capture=True)
    assert type(caught.value) is native.EnrollmentError
    assert caught.value.reason == "command-exit-23"
    assert not hasattr(caught.value, "classifications")
    assert "fixture-private-value" not in str(caught.value) + repr(caught.value.__dict__)
    logs = capsys.readouterr()
    assert logs.out == logs.err == ""


@pytest.mark.parametrize("stage", ["package-update", "package-install"])
def test_malformed_package_stderr_cannot_mask_original_exit(stage, capsys):
    code = "import sys; sys.stderr.buffer.write(b'fixture-private-\\xff'); sys.exit(100)"
    with pytest.raises(native.PackageCommandError) as caught:
        native.run([sys.executable, "-I", "-S", "-c", code], stage, 10)
    assert caught.value.reason == "command-exit-100"
    assert caught.value.classifications == ("unclassified-package-failure",)
    assert "fixture-private" not in str(caught.value) + repr(caught.value.__dict__)
    logs = capsys.readouterr()
    assert logs.out == logs.err == ""


@pytest.mark.parametrize(
    "status,output,expected,http_status",
    [
        (40, b'{"http_status":503}', "image-http-response-failure", 503),
        (41, b"fixture-private-value", "image-transport-failure", None),
        (42, b"fixture-private-value", "image-tls-failure", None),
        (43, b"fixture-private-value", "image-network-timeout", None),
        (44, b"fixture-private-value", "image-incomplete-content", None),
        (45, b"fixture-private-value", "image-excessive-content", None),
        (46, b"fixture-private-value", "image-destination-refused", None),
        (47, b"fixture-private-value", "image-unexpected-worker-failure", None),
        (19, b'{"http_status":503}', "image-unexpected-worker-failure", None),
        (40, b"\xfffixture-private-value", "image-http-response-failure", None),
        (40, b'{"http_status":true}', "image-http-response-failure", None),
        (40, b'{"http_status":503.0}', "image-http-response-failure", None),
        (40, b'{"http_status":99}', "image-http-response-failure", None),
        (40, b'{"http_status":600}', "image-http-response-failure", None),
        (
            40,
            b'{"http_status":503,"url":"fixture-private-value"}',
            "image-http-response-failure",
            None,
        ),
    ],
    ids=[
        "http",
        "transport",
        "tls",
        "timeout",
        "short",
        "excessive",
        "destination",
        "worker",
        "unknown-exit",
        "malformed-encoding",
        "boolean-status",
        "float-status",
        "low-status",
        "high-status",
        "additional-field",
    ],
)
def test_real_download_child_retains_exit_and_only_closed_safe_metadata(
    status, output, expected, http_status, capsys
):
    code = f"import sys; sys.stdout.buffer.write({output!r}); sys.stderr.write('fixture-private-value'); sys.exit({status})"
    with pytest.raises(native.ImageDownloadCommandError) as caught:
        native.run([sys.executable, "-I", "-S", "-c", code], "guest-image-download", 10)
    assert caught.value.stage == "guest-image-download"
    assert caught.value.reason == f"command-exit-{status}"
    assert caught.value.classifications == (expected,) and caught.value.http_status == http_status
    assert "fixture-private-value" not in str(caught.value)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
