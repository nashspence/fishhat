"""Controlled boot/SSH plumbing and real guard code; no native guest is started."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shlex
import stat
import sys
import uuid
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from scripts import native_linux_enrollment as native
from scripts import native_linux_guest as guests
from scripts import native_linux_images as images_module
from scripts.native_linux_images import GuestInputError, GuestInputs, identity
from scripts.run_stats import valid_stats

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_linux_guest.py", "scripts/native_linux_enrollment.py"],
    "scope": "private seed/key custody, exact SSH options, loopback process ownership and guest OS/kernel/boot/enrollment guards with required statistics",
    "relationship": "no-product-claim",
    "reason": "Controlled tool/SSH observations and execution of the production remote guard against fake filesystem reads challenge tooling only. No image is downloaded, QEMU started or native owner qualified; actual guest behavior requires the separate enrolled main run.",
    "claims": [],
}


def observed(guest):
    admin, peer = guest.accounts
    return {
        "distribution": "ubuntu",
        "distribution_version": "24.04",
        "machine": "x86_64",
        "kernel": guests.KERNEL,
        "pid1": "systemd",
        "cgroup_v2": True,
        "boot_id": str(uuid.uuid4()),
        "dmi_uuid": guest.enrollment,
        "enrollment": guest.enrollment,
        "instance_id": guest.enrollment,
        "ssh_principal": admin,
        "packages": dict(guests.GUEST_PACKAGES),
        "cloud_init_complete": True,
        "accounts": {admin: {"uid": 1001, "gid": 1001}, peer: {"uid": 1002, "gid": 1002}},
    }


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    enrolled = str(uuid.uuid4())
    monkeypatch.setattr(images_module, "IMAGE_BYTES", len(b"controlled-image"))
    monkeypatch.setattr(
        images_module, "IMAGE_SHA256", hashlib.sha256(b"controlled-image").hexdigest()
    )
    images = tmp_path / "images"
    images.mkdir(mode=0o700)
    inputs = GuestInputs(enrolled, images, identity(images, directory=True))
    for name in ("base.img", "root.qcow2", "control.qcow2", "data.qcow2"):
        p = images / name
        p.write_bytes(b"controlled-image")
        p.chmod(0o400 if name == "base.img" else 0o600)
        inputs.register(name)
    tool_paths = {}
    for name in guests.TOOL_PATHS:
        p = tmp_path / name
        p.write_bytes(name.encode())
        tool_paths[name] = p
    monkeypatch.setattr(guests, "TOOL_PATHS", tool_paths)
    tools = {
        "sha256": {
            name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in tool_paths.items()
        }
    }
    state = {
        "mode": "normal",
        "calls": [],
        "guest": None,
        "value": None,
        "process": None,
        "actions": [],
        "verifications": 0,
    }

    def launch(arguments, **kwargs):
        assert arguments[0] == "/controlled/qemu"
        assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"] == native.subprocess.DEVNULL
        assert kwargs["start_new_session"] and kwargs["umask"] == 0o077
        assert "SSH_AUTH_SOCK" not in kwargs["env"]
        state["launch"] = (arguments, kwargs)
        state["process"] = SimpleNamespace(pid=12345, returncode=None)
        return state["process"]

    monkeypatch.setattr(guests.subprocess, "Popen", launch)
    monkeypatch.setattr(
        guests,
        "listening_endpoints",
        lambda pid: [
            ("0.0.0.0" if state["mode"] == "foreign-listener" else "127.0.0.1", state["guest"].port)
        ],
    )

    def command(arguments, name, nominal, *, capture=False):
        state["calls"].append((arguments, name, nominal, capture))
        mode = state["mode"]
        if name == "guest-keygen":
            path = Path(arguments[-1])
            if mode == "keygen-failure":
                raise native.EnrollmentError(name, "command-exit-23")
            path.write_text("private-controlled-" + path.name)
            path.chmod(0o600)
            raw = (
                b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
                + hashlib.sha256(("same" if mode == "same-keys" else path.name).encode()).digest()
            )
            text = "ssh-ed25519 " + base64.b64encode(raw).decode()
            pub = path.with_suffix(".pub")
            pub.write_text("fixture-private-output" if mode == "wrong-key" else text + "\n")
            pub.chmod(0o644)
            return ""
        if name == "guest-seed":
            if mode == "iso-failure":
                raise native.EnrollmentError(name, "command-exit-23")
            path = Path(arguments[arguments.index("-output") + 1])
            if mode == "iso-replaced":
                replacement = path.parent / "replacement"
                replacement.write_bytes(b"replacement")
                replacement.chmod(0o600)
                replacement.replace(path)
            else:
                path.write_bytes(b"controlled-iso")
            return ""
        assert name == "guest-ssh"
        guest = state["guest"]
        if state["value"] is None:
            state["value"] = observed(guest)
        value = state["value"]
        if (
            any(
                "UserKnownHostsFile=" + str(guest.directory / "wrong-hosts") == arg
                for arg in arguments
            )
            and mode != "wrong-pin-accepted"
        ):
            raise native.EnrollmentError(name, "command-exit-255")
        parts = shlex.split(arguments[-1])
        script = parts[parts.index("-c") + 1]
        if script == guests.PEER:
            if mode == "invalid-peer":
                return "fixture-private-output"
            return json.dumps(
                {
                    "account": guest.accounts[1],
                    "uid": value["accounts"][guest.accounts[1]]["uid"],
                    "boot_id": value["boot_id"],
                    "enrollment": guest.enrollment,
                }
            )
        assert script == guests.REMOTE
        expected = json.loads(parts[-2])
        action = json.loads(parts[-1])
        if expected is not None and expected != value and mode != "guard-accepted":
            raise native.EnrollmentError(name, "command-exit-73")
        if action is not None:
            state["actions"].append(action)
            return ""
        return json.dumps(value)

    state["command"] = command
    state["inputs"] = inputs
    state["temporary"] = tmp_path
    state["tools"] = tools
    return state


def session(fixture, report):
    return guests.guest_session(
        fixture["inputs"],
        fixture["temporary"],
        fixture["command"],
        fixture["tools"],
        Path("/controlled/qemu"),
        report,
    )


def boot(fixture, guest):
    fixture["guest"] = guest
    guest.launch(guest.directory / "qmp", guest.enrollment)

    def verify(deadline):
        assert deadline.remaining() > 0
        fixture["verifications"] += 1

    guest.ready(verify)


def test_private_seed_authenticated_accounts_guards_and_cleanup(fixture):
    report = {}
    with session(fixture, report) as guest:
        config = yaml.safe_load(guest.path("user-data").read_text())
        assert config["ssh_keys"]["ed25519_private"] == "private-controlled-host"
        assert (
            config["users"][0]["name"] == guest.accounts[0]
            and config["users"][1]["name"] == guest.accounts[1]
        )
        assert (
            config["users"][0]["sudo"] == "ALL=(ALL) NOPASSWD:ALL"
            and config["users"][1]["sudo"] is False
        )
        assert (
            config["ssh_pwauth"] is False
            and config["ssh"]["emit_keys_to_console"] is False
            and not config["ssh_publish_hostkeys"]["enabled"]
        )
        assert all(stat.S_IMODE(guest.path(name).stat().st_mode) == 0o600 for name in guest.files)
        boot(fixture, guest)
        guest.refusals()
        assert len(report["key_fingerprints"]) == len(set(report["key_fingerprints"].values())) == 3
        args, _ = fixture["launch"]
        assert (
            "pc-q35-8.2,dump-guest-core=off" in args and "tcg,thread=multi" in args and "-S" in args
        )
        assert any("restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:" in arg for arg in args)
        assert fixture["verifications"] > 5
        assert not any(action[0] == "/usr/bin/touch" for action in fixture["actions"])
        fixture["process"].returncode = 0
        private = guest.directory
    assert (
        report["status"] == "passed"
        and report["process_reaped"]
        and report["temporary_resources_removed"]
        and not private.exists()
    )
    assert (
        report["denied_mutation_canary_absent"]
        and report["peer_authenticated"]
        and valid_stats(report["statistics"])
    )
    encoded = json.dumps(report)
    assert (
        "private-controlled" not in encoded
        and "ssh-ed25519" not in encoded
        and "#cloud-config" not in encoded
    )


@pytest.mark.parametrize(
    "mode", ["keygen-failure", "wrong-key", "same-keys", "iso-failure", "iso-replaced"]
)
def test_partial_or_substituted_seed_setup_cleans_up_without_secret_diagnostics(fixture, mode):
    fixture["mode"] = mode
    report = {}
    with pytest.raises((guests.GuestBootError, native.EnrollmentError, GuestInputError)) as caught:
        with session(fixture, report):
            pytest.fail("invalid setup yielded")
    assert "fixture-private-output" not in str(caught.value)
    assert (
        report["status"] == "failed"
        and report["temporary_resources_removed"]
        and valid_stats(report["statistics"])
    )
    assert not list(fixture["temporary"].glob("fhg-*")) and fixture["inputs"].directory.exists()
    assert fixture["process"] is None


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("distribution", "foreign"),
        ("distribution_version", "22.04"),
        ("machine", "aarch64"),
        ("kernel", "foreign"),
        ("pid1", "foreign"),
        ("cgroup_v2", False),
        ("cgroup_v2", 1),
        ("dmi_uuid", "foreign"),
        ("enrollment", "foreign"),
        ("instance_id", "foreign"),
        ("ssh_principal", "foreign"),
        ("boot_id", "foreign"),
        ("cloud_init_complete", 1),
        ("packages", {}),
        ("accounts", {}),
    ],
)
def test_exact_guest_profile_rejects_contradictory_or_untyped_identity(fixture, attribute, value):
    report = {}
    with pytest.raises(guests.GuestBootError, match="guest-identity-mismatch"):
        with session(fixture, report) as guest:
            sample = observed(guest)
            sample[attribute] = value
            guest.validate(sample)
    assert report["status"] == "failed" and valid_stats(report["statistics"])


@pytest.mark.parametrize(
    "mode,reason",
    [
        ("wrong-pin-accepted", "wrong-host-key-accepted"),
        ("guard-accepted", "foreign-or-stale-identity-accepted"),
        ("foreign-listener", "owned-loopback-endpoint-mismatch"),
        ("invalid-peer", "invalid-peer-observation"),
    ],
)
def test_invalid_authentication_identity_or_endpoint_cannot_report_success(fixture, mode, reason):
    report = {}
    with pytest.raises(guests.GuestBootError, match=reason):
        with session(fixture, report) as guest:
            try:
                boot(fixture, guest)
                fixture["mode"] = mode
                guest.refusals()
            finally:
                if fixture["process"] is not None:
                    fixture["process"].returncode = 0
    assert (
        report["status"] == "failed"
        and report["temporary_resources_removed"]
        and valid_stats(report["statistics"])
    )


@pytest.mark.parametrize("change", ["contents", "inode", "symlink", "mode"])
def test_private_key_substitution_refuses_before_any_ssh_command(fixture, change):
    report = {}
    with pytest.raises((guests.GuestBootError, GuestInputError)):
        with session(fixture, report) as guest:
            try:
                boot(fixture, guest)
                path = guest.path("admin")
                if change == "contents":
                    path.write_text("changed")
                elif change == "mode":
                    path.chmod(0o644)
                elif change == "inode":
                    replacement = guest.directory / "replacement"
                    replacement.write_text("private-controlled-admin")
                    replacement.chmod(0o600)
                    replacement.replace(path)
                else:
                    path.unlink()
                    path.symlink_to(fixture["temporary"] / "ssh")
                before = len(fixture["calls"])
                try:
                    guest.guarded(["/usr/bin/true"], guest.enrollment, guest.observed["boot_id"])
                finally:
                    assert len(fixture["calls"]) == before
            finally:
                fixture["process"].returncode = 0
    assert (
        report["status"] == "failed"
        and report["temporary_resources_removed"]
        and valid_stats(report["statistics"])
    )


def test_ssh_uses_only_owned_keys_pins_and_loopback_without_ambient_configuration(fixture):
    report = {}
    with pytest.raises(RuntimeError, match="controlled-end"):
        with session(fixture, report) as guest:
            try:
                boot(fixture, guest)
                args = next(call[0] for call in fixture["calls"] if call[1] == "guest-ssh")
                for option in [
                    "IdentityAgent=none",
                    "StrictHostKeyChecking=yes",
                    "GlobalKnownHostsFile=/dev/null",
                    "UpdateHostKeys=no",
                    "ProxyCommand=none",
                    "ProxyJump=none",
                    "ControlMaster=no",
                    "ControlPath=none",
                    "ClearAllForwardings=yes",
                    "PermitLocalCommand=no",
                    "PasswordAuthentication=no",
                    "KbdInteractiveAuthentication=no",
                    "HostKeyAlgorithms=ssh-ed25519",
                ]:
                    assert option in args
                assert args[args.index("-F") + 1] == "/dev/null" and args[-2] == "127.0.0.1"
                assert args[args.index("-i") + 1] == str(guest.path("admin"))
                raise RuntimeError("controlled-end")
            finally:
                fixture["process"].returncode = 0
    assert report["status"] == "failed" and valid_stats(report["statistics"])


@pytest.mark.parametrize(
    "attribute",
    [None, "no-guard", "boot_id", "dmi_uuid", "enrollment", "kernel", "packages", "ssh_principal"],
)
def test_production_remote_guard_checks_identity_before_mutating_execution(
    fixture, monkeypatch, capsys, attribute
):
    report = {}
    with pytest.raises(RuntimeError, match="controlled-end"):
        with session(fixture, report) as guest:
            info = observed(guest)
            admin, peer = guest.accounts
            executed = []
            reads = {
                "/etc/os-release": 'ID=ubuntu\nVERSION_ID="24.04"\n',
                "/proc/1/comm": "systemd\n",
                "/proc/sys/kernel/random/boot_id": info["boot_id"],
                "/sys/class/dmi/id/product_uuid": guest.enrollment,
                guests.MARKER: guest.enrollment,
                "/var/lib/cloud/data/instance-id": guest.enrollment,
                "/run/cloud-init/status.json": json.dumps(
                    {"v1": {"modules-final": {"errors": []}}}
                ),
            }
            original_read = Path.read_text
            original_isfile = Path.is_file
            monkeypatch.setattr(
                Path,
                "read_text",
                lambda path, *a, **k: (
                    reads[str(path)] if str(path) in reads else original_read(path, *a, **k)
                ),
            )
            monkeypatch.setattr(
                Path,
                "is_file",
                lambda path: (
                    True
                    if str(path)
                    in {
                        "/var/lib/cloud/instance/boot-finished",
                        "/sys/fs/cgroup/cgroup.controllers",
                    }
                    else original_isfile(path)
                ),
            )
            monkeypatch.setattr(
                guests.subprocess,
                "check_output",
                lambda *a, **k: "".join(
                    name + "\t" + version + "\n" for name, version in guests.GUEST_PACKAGES.items()
                ).encode(),
            )
            import platform
            import pwd

            monkeypatch.setattr(platform, "release", lambda: guests.KERNEL)
            monkeypatch.setattr(platform, "machine", lambda: "x86_64")
            monkeypatch.setattr(
                pwd,
                "getpwnam",
                lambda name: SimpleNamespace(
                    pw_uid=info["accounts"][name]["uid"], pw_gid=info["accounts"][name]["gid"]
                ),
            )
            monkeypatch.setenv("SUDO_USER", admin)
            expected = copy.deepcopy(info)
            if attribute == "no-guard":
                expected = None
            elif attribute is not None:
                expected[attribute] = "foreign"
            monkeypatch.setattr(
                sys,
                "argv",
                [
                    "guard",
                    admin,
                    peer,
                    json.dumps(expected),
                    json.dumps(["/usr/bin/touch", "/controlled/canary"]),
                ],
            )

            class Executed(Exception):
                pass

            def execute(path, args):
                executed.append((path, args))
                raise Executed()

            monkeypatch.setattr(os, "execv", execute)
            if attribute is None:
                with pytest.raises(Executed):
                    exec(guests.REMOTE, {})
                assert executed == [("/usr/bin/touch", ["/usr/bin/touch", "/controlled/canary"])]
            else:
                with pytest.raises(SystemExit) as denied:
                    exec(guests.REMOTE, {})
                assert denied.value.code == 73 and not executed
            assert not capsys.readouterr().out
            raise RuntimeError("controlled-end")
    assert report["status"] == "failed" and valid_stats(report["statistics"])


def test_mutating_command_without_verified_identity_is_unavailable(fixture):
    report = {}
    with pytest.raises(guests.GuestBootError, match="guest-not-verified"):
        with session(fixture, report) as guest:
            guest.remote(None, ["/usr/bin/touch", "/controlled/canary"])
    assert report["temporary_resources_removed"] and valid_stats(report["statistics"])


def test_owned_controller_rejects_invalid_explicit_enrollment_before_launch(tmp_path):
    calls = []
    with pytest.raises(native.EnrollmentError, match="invalid-fixture-enrollment"):
        with native.owned_controller(tmp_path, lambda *a: calls.append(a), enrollment="foreign"):
            pytest.fail("invalid enrollment yielded")
    assert not calls and not list(tmp_path.iterdir())


@pytest.mark.parametrize("failed", [False, True], ids=["accepted", "refused"])
def test_main_reports_verified_boot_without_promoting_native_qualification(
    fixture, monkeypatch, tmp_path, failed
):
    source = {"commit": "a" * 40, "clean": True, "fingerprint": "b" * 64}
    monkeypatch.setattr(native, "enroll", lambda *a, **k: {})
    monkeypatch.setattr(native, "source_identity", lambda: source)

    def provision():
        guests.watchdog(7)
        return {"binary_sha256": "c" * 64}

    monkeypatch.setattr(native, "provision", provision)
    monkeypatch.setattr(native, "probe_controller", lambda *a: {})
    monkeypatch.setattr(native, "controller_faults", lambda *a: None)
    monkeypatch.setattr(native, "guest_storage_faults", lambda *a: None)
    monkeypatch.setattr(native, "verify_guest_cleanup", lambda *a: None)
    monkeypatch.setattr(native, "provision_tools", lambda *a: {})
    monkeypatch.setattr(native, "guest_inputs", lambda *a: nullcontext(fixture["inputs"]))

    def boot(*args):
        guests.watchdog(11)
        args[-1].update(boot_verified=True, status="failed" if failed else "passed")
        if failed:
            raise guests.GuestBootError("controlled-refusal")

    monkeypatch.setattr(native, "boot_guest", boot)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    output = tmp_path / "report.json"
    assert native.main(["--github-hosted-only", "--output", str(output)]) == int(failed)
    report = json.loads(output.read_text())
    assert report["guest_booted"] and report["source_before"] == report["source_after"] == source
    assert report["status"] == ("failed" if failed else "passed")
    assert report["native_tools_qualified"] is report["production_qualified"] is False
    assert valid_stats(report["statistics"])
    assert report["watchdogs"]["budgets_seconds"]["7"] == 7 * report["watchdogs"]["scale"]
    assert report["watchdogs"]["budgets_seconds"]["11"] == 11 * report["watchdogs"]["scale"]


@pytest.mark.parametrize("mode", ["valid", "version", "architecture", "duplicate"])
def test_guest_helper_package_identity_is_exact_before_boot(fixture, mode):
    calls = []
    rows = [[name, *values] for name, values in guests.TOOLS.items()]
    if mode == "version":
        rows[0][1] = "foreign"
    elif mode == "architecture":
        rows[0][2] = "foreign"
    elif mode == "duplicate":
        rows[-1] = rows[0]

    def command(arguments, name, nominal, *, capture=False):
        assert name == "guest-tools" and capture
        return "\n".join("\t".join(row) for row in rows)

    def root_command(arguments, name, nominal):
        calls.append((arguments, name, nominal))

    if mode == "valid":
        tools = guests.provision_tools(command, root_command, lambda name: nullcontext())
        assert tools["sha256"] == fixture["tools"]["sha256"]
    else:
        with pytest.raises(guests.GuestBootError, match="guest-tool-package-mismatch"):
            guests.provision_tools(command, root_command, lambda name: nullcontext())
    assert len(calls) == 1 and calls[0][0][0] == "/usr/bin/apt-get"
    assert {
        part
        for part in calls[0][0]
        if "=" in part and not part.startswith("Acquire") and not part.startswith("DPkg")
    } == {name + "=" + version for name, (version, _) in guests.TOOLS.items()}


def test_private_cleanup_failure_keeps_failed_status_and_valid_statistics(fixture, monkeypatch):
    report = {}
    original = guests.shutil.rmtree
    removed = []

    def fail(path):
        removed.append(path)
        raise OSError("fixture-private-output")

    monkeypatch.setattr(guests.shutil, "rmtree", fail)
    try:
        with pytest.raises(guests.GuestBootError, match="guest-private-cleanup-failed"):
            with session(fixture, report) as guest:
                boot(fixture, guest)
                guest.refusals()
                fixture["process"].returncode = 0
        assert report["status"] == "failed" and not report["temporary_resources_removed"]
        assert valid_stats(report["statistics"])
    finally:
        for path in removed:
            original(path)


@pytest.mark.parametrize("code", [255, 23], ids=["unavailable", "invalid-result"])
def test_readiness_has_one_deadline_and_does_not_retry_other_failures(fixture, monkeypatch, code):
    report = {}
    tick = [0]
    attempts = []
    bound = SimpleNamespace(remaining=lambda: max(0, 2 - tick[0]))
    monkeypatch.setattr(guests, "Deadline", SimpleNamespace(after=lambda nominal: bound))
    monkeypatch.setattr(guests.time, "sleep", lambda seconds: tick.__setitem__(0, tick[0] + 1))

    def unavailable(guest, deadline=None):
        assert deadline is bound
        attempts.append(deadline)
        raise native.EnrollmentError("guest-ssh", f"command-exit-{code}")

    monkeypatch.setattr(guests.Guest, "observe", unavailable)
    expected = guests.GuestBootError if code == 255 else native.EnrollmentError
    with pytest.raises(expected):
        with session(fixture, report) as guest:
            guest.ready(lambda deadline: attempts.append(deadline))
    assert len(attempts) == (4 if code == 255 else 2)
    assert (
        report["status"] == "failed"
        and report["temporary_resources_removed"]
        and valid_stats(report["statistics"])
    )


def test_base_is_reauthenticated_immediately_before_guest_launch(fixture):
    report = {}
    with pytest.raises(GuestInputError, match="base-image-changed"):
        with session(fixture, report) as guest:
            base = fixture["inputs"].directory / "base.img"
            base.chmod(0o600)
            base.write_bytes(b"x" * len(b"controlled-image"))
            base.chmod(0o400)
            guest.launch(guest.directory / "qmp", guest.enrollment)
    assert fixture["process"] is None and report["status"] == "failed"
    assert report["temporary_resources_removed"] and valid_stats(report["statistics"])


@pytest.mark.parametrize("change", ["missing", "foreign-symlink"])
def test_missing_or_foreign_private_root_preserves_failure_stats_and_foreign_data(fixture, change):
    report = {}
    relocated = fixture["temporary"] / "relocated-private"
    foreign = fixture["temporary"] / "foreign"
    foreign.mkdir(mode=0o700)
    marker = foreign / "keep"
    marker.write_text("unrelated")
    original = None
    try:
        with pytest.raises((guests.GuestBootError, GuestInputError)):
            with session(fixture, report) as guest:
                original = guest.directory
                original.rename(relocated)
                if change == "foreign-symlink":
                    original.symlink_to(foreign, target_is_directory=True)
        assert report["status"] == "failed" and not report["temporary_resources_removed"]
        assert valid_stats(report["statistics"]) and marker.read_text() == "unrelated"
    finally:
        if original is not None and original.is_symlink():
            original.unlink()
        guests.shutil.rmtree(relocated)


@pytest.mark.parametrize(
    ("refused", "storage_error"),
    [(False, False), (True, False), (False, True)],
    ids=["started", "refused", "storage-refused"],
)
def test_boot_coordinator_admits_exact_paused_controller_before_start_and_reaps(
    fixture, monkeypatch, refused, storage_error
):
    events = []
    report = {}
    monkeypatch.setattr(native, "run", fixture["command"])
    monkeypatch.setattr(native, "QEMU", Path("/controlled/qemu"))
    storage_calls = []

    def qualify(guest, progress, result, *, inject_failure):
        assert guest is fixture["guest"] and result is report["storage"]
        assert report["boot_verified"] and report["peer_authenticated"]
        assert report["denied_mutation_canary_absent"]
        assert inject_failure is storage_error
        storage_calls.append("storage")
        if storage_error:
            raise native.GuestStorageError("controlled-storage-refusal")

    monkeypatch.setattr(native, "qualify_storage", qualify)

    def process_kill(guest, progress, temporary, result):
        assert guest is fixture["guest"] and result is report["process_kill"]
        assert storage_calls == ["storage"] and not storage_error
        assert temporary == fixture["temporary"]
        storage_calls.append("process")

    monkeypatch.setattr(native, "qualify_process_kill", process_kill)

    @contextmanager
    def owned(temporary, launch, *, enrollment):
        assert enrollment == fixture["inputs"].enrollment
        fixture["guest"] = launch.__self__
        process = launch(temporary / "qmp", enrollment)
        events.append("launch")
        try:
            yield process, temporary / "qmp", enrollment
        finally:
            process.returncode = 0
            events.append("reaped")

    @contextmanager
    def channel(process, endpoint, enrollment, digest, deadline):
        assert process is fixture["process"] and enrollment == fixture["inputs"].enrollment
        assert digest == "c" * 64 and deadline.remaining() > 0
        events.append("identity-verified")

        def command(name):
            assert name == "cont" and events[-1] == "identity-verified"
            events.append("cont")
            return {"foreign": True} if refused else {}

        yield SimpleNamespace(command=command)

    monkeypatch.setattr(native, "owned_controller", owned)
    monkeypatch.setattr(native, "controller_channel", channel)
    monkeypatch.setattr(
        native,
        "controller_executable",
        lambda process, digest, deadline: events.append("reverified"),
    )

    def invoke():
        native.boot_guest(
            fixture["inputs"],
            fixture["tools"],
            "c" * 64,
            fixture["temporary"],
            report,
            storage_failure=storage_error,
        )

    if refused or storage_error:
        reason = "guest-start-rejected" if refused else "controlled-storage-refusal"
        with pytest.raises(guests.GuestBootError, match=reason):
            invoke()
    else:
        invoke()
    if refused:
        assert not any(call[1] == "guest-ssh" for call in fixture["calls"])
    else:
        assert report["controller_verified"]["instance_uuid"] == fixture["inputs"].enrollment
        assert report["controller_verified"]["unix_peer_verified"]
    assert storage_calls == (
        [] if refused else ["storage"] if storage_error else ["storage", "process"]
    )
    assert events[:3] == ["launch", "identity-verified", "cont"] and events[-1] == "reaped"
    assert report["boot_verified"] is not refused
    assert report["status"] == ("failed" if refused or storage_error else "passed")
    assert (
        report["process_reaped"]
        and report["temporary_resources_removed"]
        and valid_stats(report["statistics"])
    )


@pytest.mark.parametrize(
    ("remaining", "scale", "expected"),
    [(90, 1, 60), (17, 1, 17), (17, 4, 4.25)],
    ids=["operation-budget", "remaining-deadline", "scaled-remaining-deadline"],
)
def test_guarded_storage_command_respects_caller_and_shared_deadline(
    fixture, monkeypatch, remaining, scale, expected
):
    report = {}
    with session(fixture, report) as guest:
        boot(fixture, guest)
        guest.refusals()
        bound = SimpleNamespace(remaining=lambda: remaining)
        monkeypatch.setattr(
            guests,
            "current",
            lambda: SimpleNamespace(scale=scale, units=lambda *args, **kwargs: 5),
        )
        try:
            guest.guarded(
                ["/usr/bin/true"],
                guest.enrollment,
                guest.observed["boot_id"],
                deadline=bound,
                nominal=60,
            )
            assert fixture["calls"][-1][2] == expected
            assert fixture["actions"][-1] == ["/usr/bin/true"]
        finally:
            fixture["process"].returncode = 0
    assert report["status"] == "passed" and valid_stats(report["statistics"])


@pytest.mark.parametrize(
    "nominal",
    [0, -1, float("inf"), float("nan")],
    ids=["zero", "negative", "infinite", "not-a-number"],
)
def test_invalid_guarded_command_budget_refuses_before_dispatch(fixture, nominal):
    report = {}
    with session(fixture, report) as guest:
        boot(fixture, guest)
        guest.refusals()
        before = len(fixture["calls"])
        try:
            with pytest.raises(guests.GuestBootError, match="invalid-guest-command-budget"):
                guest.guarded(
                    ["/usr/bin/true"],
                    guest.enrollment,
                    guest.observed["boot_id"],
                    nominal=nominal,
                )
            assert len(fixture["calls"]) == before
        finally:
            fixture["process"].returncode = 0
    assert report["status"] == "passed" and valid_stats(report["statistics"])


def test_expired_storage_deadline_refuses_before_dispatch(fixture):
    report = {}
    with session(fixture, report) as guest:
        boot(fixture, guest)
        guest.refusals()
        before = len(fixture["calls"])
        try:
            with pytest.raises(guests.GuestBootError, match="guest-readiness-deadline"):
                guest.guarded(
                    ["/usr/bin/true"],
                    guest.enrollment,
                    guest.observed["boot_id"],
                    deadline=SimpleNamespace(remaining=lambda: 0),
                    nominal=60,
                )
            assert len(fixture["calls"]) == before
        finally:
            fixture["process"].returncode = 0
    assert report["status"] == "passed" and valid_stats(report["statistics"])
