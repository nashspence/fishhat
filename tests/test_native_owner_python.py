"""Controlled transport and forged replies supply no native runtime qualification."""

import ast
import copy
import hashlib
import json
import os
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_linux_enrollment as enrollment
from scripts import native_linux_owner_python as native
from scripts.native_linux_guest import Guest, GuestBootError
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import Deadline, Policy, using

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_owner_python.py",
        "scripts/native_linux_guest.py",
        "scripts/native_linux_enrollment.py",
    ],
    "scope": "fixture invocation, exact stdin plumbing and rejection of forged runtime/custody/process evidence",
    "relationship": "no-product-claim",
    "reason": "Guest programs are parsed only. Fake transports and invented observations exercise rejection rules, never native permission, engine, installation or reboot claims. The command-input tests execute only ordinary isolated Python children on temporary files, without SSH or privileged operations.",
    "claims": [],
}


def observation(config):
    prefix = "/var/lib/fishhat-python-fixture-" + config["enrollment"] + "/installed/python"
    row = {
        "pid": 102,
        "parent_pid": 100,
        "uids": [0] * 3,
        "gids": [0] * 3,
        "groups": [],
        "executable": prefix + "/bin/python3.12",
        "prefix": prefix,
        "base_prefix": prefix,
        "version": [3, 12, 16],
        "search_paths": [prefix + "/lib/python3.12"],
        "sqlite_version": "3.53.1",
        "sqlite_source_id": native.SQLITE_SOURCE,
        "sqlite_module_origin": "built-in",
        "sqlite_module_file": None,
        "sqlite_builtin": True,
        "flags": dict.fromkeys(
            (
                "isolated",
                "ignore_environment",
                "no_site",
                "no_user_site",
                "safe_path",
                "dont_write_bytecode",
            ),
            1,
        ),
        "mapped_files": {prefix + "/bin/python3.12": "a" * 64},
        "capabilities": "0000000000000000",
        "denied": [],
    }
    peer = copy.deepcopy(row)
    peer.update(pid=103, uids=[config["peer_uid"]] * 3, gids=[config["peer_gid"]] * 3)
    peer["denied"] = [
        {"role": role, "operation": operation, "errno": 13}
        for role in ("executable", "stdlib", "interrupted")
        for operation in ("write", "unlink")
    ]
    metadata = {"device": 1, "inode": 2, "uid": 0, "gid": 0, "mode": 0o555, "kind": "directory"}
    retained = {
        **metadata,
        "inode": 3,
        "mode": 0o400,
        "kind": "regular",
        "bytes": native.OWNER_PYTHON_BYTES,
        "sha256": native.OWNER_PYTHON_SHA256,
    }
    before = {".": metadata, "runtime.tar.gz": retained}
    return {
        "scope": native.SCOPE,
        "status": "passed",
        "native_product_qualified": False,
        **{key: config[key] for key in ("enrollment", "boot_id", "bootstrap_sha256")},
        "observer_pid": 100,
        "observer_uid": 0,
        "primary_error": None,
        "cleanup_errors": [],
        "input": {**retained, "mode": 0o600},
        "input_after_sha256": "b" * 64,
        "before": before,
        "after": copy.deepcopy(before),
        "administrative": row,
        "peer": peer,
        "interruption": {
            "pid": 101,
            "parent_pid": 100,
            "uid": 0,
            "boot_id": config["boot_id"],
            "returncode": -9,
            "joined": True,
            "destination": {**metadata, "mode": 0o700},
            "retained_sha256": native.OWNER_PYTHON_SHA256,
            "runtime_absent": True,
        },
        "cleanup": [
            {
                "path": root + "/fishhat-python-fixture-" + config["enrollment"],
                "device": 1,
                "inode": i,
                "absent": True,
            }
            for i, root in enumerate(("/tmp", "/var/lib"), 4)
        ],
        "rejections": [
            {"case": case, "error": error, "errno": code}
            for case, error, code in (
                ("interrupted-destination", "FileExistsError", 17),
                ("source-symlink", "ValueError", None),
                ("truncated-archive", "ValueError", None),
                ("changed-archive", "ValueError", None),
                ("existing-installation", "FileExistsError", 17),
            )
        ],
    }


@pytest.fixture
def guest():
    fixture = SimpleNamespace(
        enrollment="00000000-0000-4000-8000-000000000001",
        accounts=("admin", "peer"),
        observed={
            "boot_id": "00000000-0000-4000-8000-000000000002",
            "accounts": {"peer": {"uid": 1002, "gid": 1002}},
        },
    )
    config = {
        "enrollment": fixture.enrollment,
        "boot_id": fixture.observed["boot_id"],
        "bootstrap_sha256": "c" * 64,
        "peer_uid": 1002,
        "peer_gid": 1002,
    }
    return fixture, config


@pytest.mark.parametrize("accepted", [True, False], ids=["accepted", "rejected-original-retained"])
@pytest.mark.parametrize("scale", [1, 4])
def test_fixture_programs_parse_and_original_reply_is_retained(tmp_path, guest, accepted, scale):
    fixture, _ = guest
    for program in (native.REMOTE, native.OBSERVE, native.INTERRUPTED):
        ast.parse(program)
    calls = []

    def command(argv, name, nominal):
        assert argv[1:4] == ["-I", "-S", "-B"]
        assert argv[5:9] == [
            str(tmp_path / Path(argv[5]).parent.name / "selected.tar.gz"),
            native.OWNER_PYTHON_URL,
            str(native.OWNER_PYTHON_BYTES),
            native.OWNER_PYTHON_SHA256,
        ]
        assert float(argv[9]) == 30 * scale
        path = Path(argv[5])
        path.write_bytes(b"controlled transfer placeholder")
        path.chmod(0o600)
        calls.append((name, nominal))

    def guarded(argv, token, boot, *, nominal, input_path):
        assert argv[:5] == ["/usr/bin/python3", "-I", "-S", "-B", "-c"]
        assert argv[5] == native.REMOTE
        assert token == fixture.enrollment and boot == fixture.observed["boot_id"]
        assert input_path.is_file() and input_path.stat().st_mode & 0o777 == 0o600
        config = json.loads(argv[6])
        assert config["child_timeout"] == 120 * scale
        assert (
            config["bootstrap_sha256"]
            == hashlib.sha256(__import__("base64").b64decode(config["bootstrap"])).hexdigest()
        )
        calls.append(("guarded", nominal))
        value = observation(config)
        if not accepted:
            value["peer"]["prefix"] = "/caller/python"
        return json.dumps(value)

    fixture.command, fixture.guarded = command, guarded
    report = {}
    with using(Policy(scale)):
        if accepted:
            native.qualify_python(fixture, tmp_path, lambda name: nullcontext(), report)
        else:
            with pytest.raises(GuestBootError, match="runtime-mismatch"):
                native.qualify_python(fixture, tmp_path, lambda name: nullcontext(), report)
    assert calls == [("owner-python-download", 180), ("guarded", 300)]
    assert report["status"] == ("passed" if accepted else "failed")
    assert report["native_product_qualified"] is False
    assert report["original_observation"]["status"] == "passed"
    assert valid_stats(report["qualification_statistics"])
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "path,replacement",
    [
        (("scope",), "other"),
        (("status",), "failed"),
        (("native_product_qualified",), True),
        (("enrollment",), "other"),
        (("boot_id",), "old-boot"),
        (("bootstrap_sha256",), "0" * 64),
        (("observer_uid",), 1002),
        (("observer_pid",), True),
        (("primary_error",), {"stage": "failed"}),
        (("cleanup_errors",), [{"stage": "failed"}]),
        (("input", "sha256"), "0" * 64),
        (("input", "bytes"), 0),
        (("input", "mode"), 0o666),
        (("input_after_sha256",), native.OWNER_PYTHON_SHA256),
        (("after",), {}),
        (("before", ".", "mode"), 0o777),
        (("before", ".", "uid"), 1002),
        (("before", "runtime.tar.gz", "bytes"), 0),
        (("administrative", "version"), [3, 12, 3]),
        (("peer", "prefix"), "/caller/python"),
        (("peer", "executable"), "/caller/python"),
        (("peer", "sqlite_source_id"), "unqualified engine"),
        (("peer", "sqlite_module_origin"), "/caller/_sqlite3.so"),
        (("peer", "sqlite_module_file"), "/caller/_sqlite3.so"),
        (("peer", "sqlite_builtin"), False),
        (("peer", "search_paths"), ["/caller"]),
        (("peer", "flags", "no_site"), 0),
        (("peer", "uids"), [0] * 3),
        (("peer", "groups"), [0]),
        (("peer", "capabilities"), "0000000000000001"),
        (("peer", "parent_pid"), 999),
        (("peer", "pid"), 101),
        (("peer", "denied"), []),
        (("interruption", "returncode"), 0),
        (("interruption", "joined"), False),
        (("interruption", "runtime_absent"), False),
        (("interruption", "destination", "mode"), 0o755),
        (("cleanup",), []),
        (("rejections",), []),
    ],
    ids=[
        "scope",
        "status",
        "qualification",
        "enrollment",
        "boot",
        "bootstrap",
        "observer-uid",
        "observer-pid",
        "primary-error",
        "cleanup-error",
        "input-digest",
        "input-size",
        "input-mode",
        "original-input-not-changed",
        "changed-inventory",
        "writable-inventory",
        "foreign-inventory",
        "retained-size",
        "old-python",
        "caller-prefix",
        "caller-executable",
        "wrong-sqlite-source",
        "nonbuiltin-sqlite-origin",
        "external-sqlite-file",
        "sqlite-not-builtin",
        "caller-search-path",
        "site-enabled",
        "privileged-peer",
        "peer-groups",
        "peer-capabilities",
        "foreign-parent",
        "aliased-pid",
        "missing-denials",
        "interruption-exit",
        "interruption-unjoined",
        "interrupted-runtime-present",
        "interrupted-prefix-exposed",
        "missing-cleanup",
        "missing-refusals",
    ],
)
def test_forged_runtime_observation_is_rejected(guest, path, replacement):
    fixture, config = guest
    value = observation(config)
    parent = value
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = replacement
    with pytest.raises(GuestBootError):
        native.verify_observation(value, fixture, config["bootstrap_sha256"])


def test_unverified_guest_cannot_download_or_install(tmp_path, guest):
    fixture, _ = guest
    fixture.observed = None
    with pytest.raises(GuestBootError, match="guest-not-verified"):
        native.qualify_python(fixture, tmp_path, lambda name: nullcontext(), {})
    assert list(tmp_path.iterdir()) == []


def test_file_input_removes_ssh_devnull_only_for_that_invocation(tmp_path):
    fixture = object.__new__(Guest)
    calls = []
    fixture.ssh_command = lambda *args, **kwargs: (
        ["/usr/bin/ssh", "-n", "-F", "/dev/null", "remote"],
        Deadline.after(15),
    )
    fixture.command = lambda argv, name, nominal, **kwargs: calls.append((argv, kwargs)) or "reply"
    source = tmp_path / "input"
    assert fixture.ssh("guarded request", input_path=source) == "reply"
    assert calls[-1] == (
        ["/usr/bin/ssh", "-F", "/dev/null", "remote"],
        {"capture": True, "input_path": source},
    )
    assert fixture.ssh("ordinary observation") == "reply"
    assert calls[-1] == (["/usr/bin/ssh", "-n", "-F", "/dev/null", "remote"], {"capture": True})


def test_regular_owned_input_streams_to_ordinary_python_child(tmp_path):
    source = tmp_path / "input"
    source.write_bytes(b"public controlled input\x00with bytes")
    source.chmod(0o600)
    result = enrollment.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            "import hashlib,sys;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())",
        ],
        "controlled-input",
        10,
        capture=True,
        input_path=source,
    )
    assert result.strip() == hashlib.sha256(source.read_bytes()).hexdigest()


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "writable", "hardlink"])
def test_unprotected_input_never_starts_a_child(tmp_path, monkeypatch, kind):
    retained = tmp_path / "retained"
    retained.write_bytes(b"retained input")
    retained.chmod(0o600)
    source = tmp_path / "input"
    if kind == "symlink":
        source.symlink_to(retained)
    elif kind == "fifo":
        os.mkfifo(source, mode=0o600)
    elif kind == "directory":
        source.mkdir(mode=0o600)
    elif kind == "hardlink":
        os.link(retained, source)
    else:
        source.write_bytes(b"unprotected")
        source.chmod(0o666)
    monkeypatch.setattr(
        enrollment.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("rejected input started a child"),
    )
    with pytest.raises(
        enrollment.EnrollmentError, match=r"unprotected-command-input|command-unavailable"
    ):
        enrollment.run(["never executed"], "controlled-input", 10, input_path=source)
    assert retained.read_bytes() == b"retained input"
