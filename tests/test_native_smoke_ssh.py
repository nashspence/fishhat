"""Exercise exact SSH custody using isolated observations and unprivileged children."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_smoke_ssh as ssh
from scripts import native_smoke_ssh_qualification as qualification
from scripts.native_smoke_cleanup import Paths
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import current, observe_child, watchdog
from tests.support import ROOT

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_smoke_ssh.py",
        "scripts/native_smoke_ssh_qualification.py",
        "tests/native_smoke_ssh_worker.py",
        "scripts/ci/native_smoke.sh",
        "scripts/validation_timeouts.py",
    ],
    "scope": "retained direct-child and kernel process-handle ownership, identity/refusal/termination/reaping, exact process/listener before and final absence observations, strict typed fresh independent witness binding, private key/configuration custody and original failure preservation using isolated filesystem observations and real unprivileged controlled children",
    "relationship": "no-product-claim",
    "reason": "Controlled unprivileged workers and simulated read-only root observations do not qualify a native SSH server, deployment, account or checkpoint owner.",
    "claims": [],
}


def end(seconds=10):
    return time.monotonic() + watchdog(seconds)


def process_files(root, pid=123, *, ticks=456, parent=77, group=None, session=None, uid=0, gid=0):
    base = root / str(pid)
    base.mkdir(parents=True, exist_ok=True)
    values = ["0"] * 20
    values[0] = "S"
    values[1] = str(parent)
    values[2] = str(pid if group is None else group)
    values[3] = str(pid if session is None else session)
    values[19] = str(ticks)
    (base / "stat").write_text(str(pid) + " (listener (controlled)) " + " ".join(values) + "\n")
    (base / "status").write_text(
        "Uid:\t" + "\t".join([str(uid)] * 4) + "\nGid:\t" + "\t".join([str(gid)] * 4) + "\n"
    )
    return base


def network_files(root, *, port=ssh.PORT, inode=987, address="0100007F", state="0A"):
    net = root / "net"
    net.mkdir(parents=True, exist_ok=True)
    header = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    row = f"   0: {address}:{port:04X} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 0 0 {inode}\n"
    (net / "tcp").write_text(header + row)
    (net / "tcp6").write_text(header)


@pytest.fixture
def observed_system(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    proc.mkdir()
    base = process_files(proc)
    (base / "fd").mkdir()
    (base / "fd/3").symlink_to("socket:[987]")
    boot = proc / "sys/kernel/random"
    boot.mkdir(parents=True)
    token = str(uuid.uuid4())
    (boot / "boot_id").write_text(token)
    image = {"device": 1, "inode": 2, "uid": 0, "sha256": "1" * 64}
    identity = {
        **ssh.process_state(123, proc),
        "executable": image,
        "enrollment": str(uuid.uuid4()),
        "requested_arguments_sha256": "2" * 64,
        "boot_id": token,
    }
    arena = tmp_path / "fishhat-smoke-ssh-fixture"
    arena.mkdir()
    inventory = {
        "identity": identity,
        "listener": {"port": ssh.PORT, "inode": 987, "loopback_only": True},
        "arena": "/tmp/" + arena.name,
    }
    network_files(proc)
    monkeypatch.setattr(
        ssh,
        "os",
        SimpleNamespace(
            geteuid=lambda: 0, readlink=os.readlink, getpid=lambda: 555, getppid=lambda: 77
        ),
    )
    monkeypatch.setattr(ssh, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(ssh, "executable", lambda *_args: dict(image))
    monkeypatch.setattr(ssh, "arena_custody", lambda p: p == arena)
    request = {
        "phase": "before",
        "challenge": str(uuid.uuid4()),
        "inventory": inventory,
        "end": end(),
    }
    return SimpleNamespace(
        proc=proc,
        base=base,
        arena=arena,
        inventory=inventory,
        request=request,
        paths=Paths(proc=proc, tmp=tmp_path),
    )


def test_independent_before_observes_exact_process_listener_and_arena(observed_system):
    f = observed_system
    value = ssh.observe(f.request, f.paths)
    assert value["observations"] == {
        "owned_process": True,
        "owned_listener": True,
        "owned_arena": True,
    }
    assert value["observer_uid"] == 0 and value["inventory_sha256"] == ssh.digest(f.inventory)
    assert (
        value["challenge"] == f.request["challenge"] and value["native_product_qualified"] is False
    )


@pytest.mark.parametrize(
    "changed",
    [
        "parent",
        "ticks",
        "actor",
        "group",
        "listener-inode",
        "listener-address",
        "missing-listener",
        "unavailable-table",
        "missing-status",
        "arena",
    ],
)
def test_before_refuses_substituted_or_unavailable_observations(
    observed_system, monkeypatch, changed
):
    f = observed_system
    if changed in {"parent", "ticks", "actor", "group"}:
        process_files(
            f.proc,
            parent=88 if changed == "parent" else 77,
            ticks=999 if changed == "ticks" else 456,
            uid=1 if changed == "actor" else 0,
            group=999 if changed == "group" else 123,
        )
    elif changed == "listener-inode":
        network_files(f.proc, inode=999)
    elif changed == "listener-address":
        network_files(f.proc, address="00000000")
    elif changed == "missing-listener":
        network_files(f.proc, state="01")
    elif changed == "unavailable-table":
        (f.proc / "net/tcp6").unlink()
    elif changed == "missing-status":
        (f.base / "status").unlink()
    else:
        monkeypatch.setattr(ssh, "arena_custody", lambda _: False)
    with pytest.raises((OSError, ValueError)):
        ssh.observe(f.request, f.paths)


def absent(f):
    shutil.rmtree(f.base)
    f.arena.rmdir()
    network_files(f.proc, state="01")
    f.request["phase"] = "after"


def test_after_requires_actual_complete_absence_and_preserves_unrelated_state(observed_system):
    f = observed_system
    absent(f)
    process_files(f.proc, pid=888, group=777, session=777)
    unrelated = f.paths.tmp / "unrelated"
    unrelated.write_bytes(b"preserve")
    value = ssh.observe(f.request, f.paths)
    assert value["observations"] == {
        "original_process_absent": True,
        "process_group_absent": True,
        "session_absent": True,
        "listener_absent": True,
        "arena_absent": True,
    }
    assert unrelated.read_bytes() == b"preserve" and (f.proc / "888/stat").is_file()


@pytest.mark.parametrize(
    "leftover",
    [
        "process",
        "group",
        "session",
        "port",
        "inode",
        "arena",
        "unavailable-process",
        "unavailable-network",
    ],
)
def test_after_never_adopts_leftovers_or_unavailable_facilities_as_absence(
    observed_system, leftover
):
    f = observed_system
    absent(f)
    if leftover == "process":
        process_files(f.proc)
    elif leftover == "group":
        process_files(f.proc, pid=999, group=123, session=999)
    elif leftover == "session":
        process_files(f.proc, pid=999, group=999, session=123)
    elif leftover == "port":
        network_files(f.proc, inode=999)
    elif leftover == "inode":
        network_files(f.proc, port=22230)
    elif leftover == "arena":
        f.arena.mkdir()
    elif leftover == "unavailable-process":
        f.base.mkdir()
    else:
        (f.proc / "net/tcp").unlink()
    with pytest.raises((OSError, ValueError)):
        ssh.observe(f.request, f.paths)


@pytest.mark.parametrize(
    "change",
    [
        "pid-bool",
        "start-bool",
        "uid-bool",
        "foreign-uid",
        "foreign-enrollment",
        "extra-field",
        "image-bool",
        "image-hash",
        "port-bool",
        "inode-bool",
        "loopback-int",
        "arena-parent",
        "arena-traversal",
        "boot",
    ],
)
def test_inventory_is_strictly_typed_and_cannot_adopt_foreign_input(observed_system, change):
    value = copy.deepcopy(observed_system.inventory)
    identity = value["identity"]
    if change == "pid-bool":
        identity["pid"] = True
    elif change == "start-bool":
        identity["start_ticks"] = True
    elif change == "uid-bool":
        identity["uids"][0] = False
    elif change == "foreign-uid":
        identity["uids"][0] = 1
    elif change == "foreign-enrollment":
        identity["enrollment"] = "not-a-fresh-enrollment"
    elif change == "extra-field":
        identity["extra"] = "unowned"
    elif change == "image-bool":
        identity["executable"]["uid"] = False
    elif change == "image-hash":
        identity["executable"]["sha256"] = "unavailable"
    elif change == "port-bool":
        value["listener"]["port"] = True
    elif change == "inode-bool":
        value["listener"]["inode"] = True
    elif change == "loopback-int":
        value["listener"]["loopback_only"] = 1
    elif change == "arena-parent":
        value["arena"] = "/var/fishhat-smoke-ssh-fixture"
    elif change == "arena-traversal":
        value["arena"] = "/tmp/x/../fishhat-smoke-ssh-fixture"
    else:
        identity["boot_id"] = "unavailable"
    with pytest.raises((OSError, ValueError, TypeError)):
        ssh.inventory_record(value)


@pytest.mark.parametrize(
    "unavailable",
    [
        "status",
        "observer",
        "phase",
        "challenge",
        "inventory",
        "extra",
        "observation",
        "observation-bool",
    ],
)
def test_separate_observer_response_must_be_fresh_complete_and_exact(
    monkeypatch, observed_system, unavailable
):
    f = observed_system

    def run(args, **kwargs):
        assert args == ["/usr/bin/python3", "-m", "scripts.native_smoke_ssh", "observe"]
        request = json.loads(kwargs["input"])
        value = {
            "scope": ssh.SCOPE,
            "observer_uid": 0,
            "phase": "before",
            "status": "observed",
            "challenge": request["challenge"],
            "enrollment": request["inventory"]["identity"]["enrollment"],
            "identity": request["inventory"]["identity"],
            "listener": request["inventory"]["listener"],
            "observer_pid": 555,
            "observer_parent_pid": 77,
            "inventory_sha256": ssh.digest(request["inventory"]),
            "observations": {"owned_process": True, "owned_listener": True, "owned_arena": True},
            "native_product_qualified": False,
        }
        if unavailable == "status":
            value["status"] = "unavailable"
        elif unavailable == "observer":
            value["observer_uid"] = False
        elif unavailable == "phase":
            value["phase"] = "after"
        elif unavailable == "challenge":
            value["challenge"] = str(uuid.uuid4())
        elif unavailable == "inventory":
            value["inventory_sha256"] = "0" * 64
        elif unavailable == "extra":
            value["raw"] = "must-be-refused"
        elif unavailable == "observation":
            del value["observations"]["owned_listener"]
        else:
            value["observations"]["owned_process"] = 1
        return SimpleNamespace(returncode=0, stdout=json.dumps(value).encode())

    monkeypatch.setattr(ssh.subprocess, "run", run)
    with pytest.raises(ValueError):
        ssh.independent_observation(f.inventory, "before", end())


@pytest.mark.parametrize("changed", ["expired", "nan", "infinite", "boolean"])
def test_no_work_can_start_without_a_finite_live_shared_deadline(changed):
    values = {
        "expired": time.monotonic() - 1,
        "nan": float("nan"),
        "infinite": float("inf"),
        "boolean": True,
    }
    with pytest.raises(ValueError):
        ssh.remaining(values[changed])


def test_generated_configuration_preserves_every_authentication_restriction():
    config = ssh.configuration(
        "dtci123", Path("/tmp/fishhat-smoke-ssh-config"), Path("/home/dtci123/.ssh/authorized_keys")
    )
    assert config.splitlines() == [
        "Port 22229",
        "ListenAddress 127.0.0.1",
        "HostKey /tmp/fishhat-smoke-ssh-config/server",
        "PidFile /tmp/fishhat-smoke-ssh-config/sshd.pid",
        "AuthorizedKeysFile /home/dtci123/.ssh/authorized_keys",
        "StrictModes yes",
        "UsePAM yes",
        "PubkeyAuthentication yes",
        "AuthenticationMethods publickey",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PermitRootLogin no",
        "AllowUsers dtci123",
        "DisableForwarding yes",
        "PermitTTY no",
        "PermitUserEnvironment no",
        "PermitUserRC no",
        "ForceCommand /usr/bin/printf ssh-fixture-ok",
        "LogLevel VERBOSE",
    ]
    assert "raw" not in config


@pytest.mark.parametrize(
    "actor",
    ["root\nPermitRootLogin yes", "actor value", "/root", "actor;echo"],
    ids=["newline", "whitespace", "path", "metacharacter"],
)
def test_configuration_cannot_introduce_an_unowned_principal_or_directive(actor):
    with pytest.raises(ValueError):
        ssh.configuration(actor, Path("/tmp/fixture"), Path("/tmp/authorized"))


def test_private_input_reads_reject_symlinks_hardlinks_and_changed_permissions(tmp_path):
    value = tmp_path / "key"
    value.write_bytes(b"controlled key bytes")
    value.chmod(0o600)
    assert ssh.file_bytes(value, end(), uid=os.geteuid(), mode=0o600) == b"controlled key bytes"
    link = tmp_path / "link"
    link.symlink_to(value)
    with pytest.raises(OSError):
        ssh.file_bytes(link, end(), uid=os.geteuid())
    hard = tmp_path / "hard"
    os.link(value, hard)
    with pytest.raises(ValueError):
        ssh.file_bytes(value, end(), uid=os.geteuid())
    hard.unlink()
    value.chmod(0o666)
    with pytest.raises(ValueError):
        ssh.file_bytes(value, end(), uid=os.geteuid())


@pytest.mark.parametrize("mutation", ["pid", "ticks", "actor", "image", "enrollment"])
def test_real_unprivileged_kernel_handle_refuses_foreign_claim_then_reaps_only_owned_child(
    mutation,
):
    if sys.platform != "linux":
        assert not hasattr(os, "pidfd_open")
        return
    value = controlled_kernel_worker(mutation)
    assert value["foreign_claim_refused"] is value["owned_termination_and_reaping_verified"] is True
    assert value["unrelated_canary_preserved"] is value["stale_handle_refused"] is True


def test_real_controlled_listener_is_bound_to_the_actual_child_socket(monkeypatch):
    if sys.platform != "linux":
        assert not hasattr(os, "pidfd_open")
        return
    with socket.socket() as channel:
        channel.bind(("127.0.0.1", 0))
        channel.listen()
        monkeypatch.setattr(ssh, "PORT", channel.getsockname()[1])
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", "import time; time.sleep(60)"],
            pass_fds=[channel.fileno()],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            value = ssh.owned_listener(process.pid)
            assert value["port"] == channel.getsockname()[1] and value["loopback_only"] is True
            assert value["inode"] in ssh.socket_inodes(process.pid)
        finally:
            process.terminate()
            process.wait(timeout=watchdog(5))


def root_outcome(token):
    image = "a" * 64
    snapshot = {"device": 1, "inode": 2, "uid": 0, "gid": 0, "mode": 0o600, "sha256": "b" * 64}
    value = {
        "scope": ssh.SCOPE,
        "enrollment": token,
        "interruption_selected": True,
        "original_primary_exit": ssh.FAULT_STATUS,
        "cleanup_exit": 0,
        "injection_observed": True,
        "native_product_qualified": False,
        "protected_accounts_before": {"root": "c" * 64, "runner": "d" * 64},
        "protected_accounts_after": {"root": "c" * 64, "runner": "d" * 64},
        "canary_before": dict(snapshot),
        "canary_after": dict(snapshot),
        "refusals_verified": [
            "foreign-pid",
            "stale-start-ticks",
            "foreign-actor",
            "foreign-executable",
            "foreign-enrollment",
        ],
        "unrelated_canary_preserved": True,
        "protected_accounts_preserved": True,
        "termination": {
            "pid": 123,
            "parent_pid": 77,
            "returncode": -15,
            "exit_observed": True,
            "reaped": True,
            "stale_handle_refused": True,
        },
        "inventory_sha256": image,
        "status": "failed",
    }
    for phase, observations in [
        ("before", ["owned_process", "owned_listener", "owned_arena"]),
        (
            "after",
            [
                "original_process_absent",
                "process_group_absent",
                "session_absent",
                "listener_absent",
                "arena_absent",
            ],
        ),
    ]:
        identity = {
            "pid": 123,
            "parent_pid": 77,
            "process_group": 123,
            "session": 123,
            "start_ticks": 456,
            "uids": [0] * 4,
            "gids": [0] * 4,
            "executable": {"device": 1, "inode": 2, "uid": 0, "sha256": "e" * 64},
            "enrollment": token,
            "requested_arguments_sha256": "f" * 64,
            "boot_id": token,
        }
        value[phase] = {
            "scope": ssh.SCOPE,
            "observer_uid": 0,
            "phase": phase,
            "status": "observed",
            "challenge": str(uuid.uuid4()),
            "enrollment": token,
            "identity": identity,
            "listener": {"port": ssh.PORT, "inode": 987, "loopback_only": True},
            "observer_pid": 555 if phase == "before" else 556,
            "observer_parent_pid": 77,
            "inventory_sha256": image,
            "observations": dict.fromkeys(observations, True),
            "native_product_qualified": False,
        }
    return value


def test_selected_original_outcome_requires_real_failure_and_complete_independent_witnesses():
    token = str(uuid.uuid4())
    value = root_outcome(token)
    assert qualification.validate(value, token, ssh.FAULT_STATUS) == value
    assert value["original_primary_exit"] == 74 and value["cleanup_exit"] == 0
    assert value["before"]["challenge"] != value["after"]["challenge"]
    assert all(v is True for v in value["after"]["observations"].values())


@pytest.mark.parametrize(
    "changed",
    [
        "selection",
        "injection",
        "primary",
        "actual-exit",
        "cleanup",
        "enrollment",
        "before-enrollment",
        "after-enrollment",
        "stale-challenge",
        "observer",
        "inventory",
        "missing-absence",
        "unobserved-absence",
        "unreaped",
        "canary",
        "canary-bool",
        "protected",
        "missing-refusals",
        "unsafe-extra",
        "extra-after",
    ],
)
def test_native_receipt_rejects_skipped_masked_stale_leaked_or_unsafe_evidence(changed):
    token = str(uuid.uuid4())
    value = root_outcome(token)
    status = ssh.FAULT_STATUS
    if changed == "selection":
        value["interruption_selected"] = False
    elif changed == "injection":
        value["injection_observed"] = False
    elif changed == "primary":
        value["original_primary_exit"] = 0
    elif changed == "actual-exit":
        status = 0
    elif changed == "cleanup":
        value["cleanup_exit"] = 1
    elif changed == "enrollment":
        value["enrollment"] = str(uuid.uuid4())
    elif changed == "before-enrollment":
        value["before"]["enrollment"] = str(uuid.uuid4())
    elif changed == "after-enrollment":
        value["after"]["enrollment"] = str(uuid.uuid4())
    elif changed == "stale-challenge":
        value["after"]["challenge"] = value["before"]["challenge"]
    elif changed == "observer":
        value["after"]["observer_uid"] = False
    elif changed == "inventory":
        value["after"]["inventory_sha256"] = "e" * 64
    elif changed == "missing-absence":
        del value["after"]["observations"]["listener_absent"]
    elif changed == "unobserved-absence":
        value["after"]["observations"]["listener_absent"] = 1
    elif changed == "unreaped":
        value["termination"]["reaped"] = False
    elif changed == "canary":
        value["canary_after"]["inode"] += 1
    elif changed == "canary-bool":
        value["canary_after"]["uid"] = False
    elif changed == "protected":
        value["protected_accounts_after"]["runner"] = "f" * 64
    elif changed == "missing-refusals":
        value["refusals_verified"] = []
    elif changed == "unsafe-extra":
        value["unsafe"] = "unreviewed-raw-payload"
    else:
        value["after"]["raw"] = "unreviewed-raw-payload"
    with pytest.raises((ValueError, TypeError)):
        qualification.validate(value, token, status)


@pytest.mark.parametrize(
    "mode", ["valid", "missing-injection", "wrong-exit", "unsafe", "leak", "canary-change"]
)
def test_outer_driver_preserves_original_exit_scope_stats_and_unrelated_canary(
    tmp_path, monkeypatch, mode
):
    def root_run(arguments, **kwargs):
        assert arguments[:4] == ["sudo", "-n", "timeout", "-k"]
        assert float(arguments[4]) == watchdog(5) and float(arguments[5]) > 0
        assert arguments[6] == "/usr/bin/env"
        assert "scripts.native_smoke_ssh" in arguments and "interrupt-after-listener" in arguments
        assert kwargs["timeout"] > 0 and kwargs["stderr"] == subprocess.DEVNULL
        token = arguments[-1]
        value = root_outcome(token)
        if mode == "missing-injection":
            value["injection_observed"] = False
        elif mode == "unsafe":
            value["unsafe"] = "unreviewed-raw-payload"
        elif mode == "leak":
            value["after"]["observations"]["listener_absent"] = False
        elif mode == "canary-change":
            (tmp_path / "unrelated").write_bytes(b"changed")
        return SimpleNamespace(
            returncode=0 if mode == "wrong-exit" else 74,
            stdout=(json.dumps(value, sort_keys=True) + "\n").encode(),
        )

    monkeypatch.setattr(qualification.subprocess, "run", root_run)
    value = qualification.run(tmp_path, end())
    assert value["status"] == ("passed" if mode == "valid" else "failed")
    assert value["original_root_exit_status"] == (0 if mode == "wrong-exit" else 74)
    assert (
        valid_stats(value["statistics"])
        and value["statistics"]["scope"] == "process-excludes-children"
    )
    assert "unreviewed-raw-payload" not in json.dumps(value)
    if mode != "canary-change":
        assert value["canary_before"] == value["canary_before_removal"]
        assert value["owned_canary_removed"] is True and not (tmp_path / "unrelated").exists()
    else:
        assert value["canary_before_removal"] != value["canary_before"]


@pytest.mark.parametrize(
    "missing", ["flag", "actions", "runner", "image", "ref", "event", "origin", "job", "source"]
)
def test_native_driver_refuses_missing_enrollment_before_root_effects(
    tmp_path, monkeypatch, capsys, missing
):
    environment = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "ImageOS": "ubuntu24",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "native-prerequisites",
        "RUNNER_TEMP": str(tmp_path),
        "FISHHAT_VALIDATION_NOMINAL_MINUTES": "25",
        "FISHHAT_VALIDATION_JOB_MINUTES": str(math.ceil(25 * current().scale)),
    }
    keys = {
        "actions": "GITHUB_ACTIONS",
        "runner": "RUNNER_ENVIRONMENT",
        "image": "ImageOS",
        "ref": "GITHUB_REF",
        "event": "GITHUB_EVENT_NAME",
        "origin": "GITHUB_RUN_ID",
        "job": "GITHUB_JOB",
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    if missing in keys:
        monkeypatch.setenv(keys[missing], "unavailable")
    import scripts.validation as validation

    monkeypatch.setattr(
        validation,
        "source_identity",
        lambda *_: {"commit": "1" * 40, "clean": missing != "source", "fingerprint": "2" * 64},
    )

    def unexpected(*_args, **_kwargs):
        raise AssertionError("unenrolled native effect")

    monkeypatch.setattr(qualification, "run", unexpected)
    args = ["--github-hosted-only", "--output", str(tmp_path / "result.json")]
    if missing == "flag":
        args[0] = "--implicit"
    assert qualification.main(args) == 2
    assert not (tmp_path / "result.json").exists()
    assert "Refusing" in capsys.readouterr().err


def test_signal_guard_preserves_first_status_and_restores_handlers(monkeypatch):
    handlers = {signal.SIGTERM: signal.SIG_DFL, signal.SIGINT: signal.SIG_DFL}
    original = dict(handlers)
    monkeypatch.setattr(ssh.signal, "getsignal", lambda number: handlers[number])
    monkeypatch.setattr(
        ssh.signal, "signal", lambda number, handler: handlers.__setitem__(number, handler)
    )
    with ssh.termination_guard():
        with pytest.raises(ssh.CommandFailure) as failed:
            handlers[signal.SIGTERM](signal.SIGTERM, None)
        assert failed.value.status == 143
        handlers[signal.SIGTERM](signal.SIGTERM, None)
    assert handlers == original


def test_failed_exit_deadline_forcibly_reaps_own_term_ignoring_child_without_passing():
    if sys.platform != "linux":
        assert not hasattr(os, "pidfd_open")
        return
    value = controlled_kernel_worker("term-ignoring")
    assert value["original_deadline_failure_preserved"] is value["forced_reaping_verified"] is True
    assert value["unrelated_canary_preserved"] is value["stale_handle_refused"] is True


def controlled_kernel_worker(scenario):
    # The native helper uses the receiver's stdlib interpreter. Developer Python
    # distributions can omit the kernel wrappers even on a capable Linux host.
    bootstrap = "import sys; sys.path.insert(0, sys.argv[1]); import json; from tests.native_smoke_ssh_worker import run; print(json.dumps(run(sys.argv[2]), sort_keys=True))"
    result = subprocess.run(
        ["/usr/bin/python3", "-I", "-S", "-c", bootstrap, str(ROOT), scenario],
        capture_output=True,
        timeout=watchdog(20),
        check=True,
    )
    value = json.loads(result.stdout)
    assert value["status"] == "passed" and value["unprivileged"] is True
    assert value["native_product_qualified"] is False
    assert (
        value["source_sha256"]
        == hashlib.sha256((ROOT / "scripts/native_smoke_ssh.py").read_bytes()).hexdigest()
    )
    observe_child(value["watchdogs"])
    return value


@pytest.mark.parametrize(
    "raw",
    [
        b"ssh-ed25519 fixtureblob\n",
        b"ssh-ed25519 fixtureblob comment\n",
        b"ssh-ed25519 fixtureblob comment with words\n",
    ],
    ids=["bare", "comment", "multiword-comment"],
)
def test_public_key_identity_preserves_key_fields_with_optional_opaque_comment(raw):
    assert ssh.public_key_fields(raw) == (b"ssh-ed25519", b"fixtureblob")


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"ssh-ed25519\n",
        b"ssh-rsa fixtureblob\n",
        b"ssh-ed25519 fixtureblob\nssh-ed25519 foreign\n",
        b"ssh-ed25519 fixtureblob\0comment\n",
    ],
    ids=["empty", "missing-key", "foreign-algorithm", "multiple-keys", "control-character"],
)
def test_public_key_identity_refuses_malformed_or_additional_key_records(raw):
    with pytest.raises(ValueError):
        ssh.public_key_fields(raw)
