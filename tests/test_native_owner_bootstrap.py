"""Forged evidence challenges tooling; guest programs never execute locally."""

import ast
import copy
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import zipfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_linux_owner_bootstrap as native
from scripts.native_linux_guest import GuestBootError
from scripts.run_stats import valid_stats

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_linux_owner_bootstrap.py", "scripts/native_linux_enrollment.py"],
    "scope": "exact static input, original observation, process/environment/loader/permission refusal and cleanup predicates",
    "relationship": "no-product-claim",
    "reason": "Invented observations and fake transport challenge the reader and coordinator only. Guest programs are parsed, never executed; no native binary, credential change, SSH, account, package or privileged operation executes locally.",
    "claims": [],
}


CHECK_OVERRIDES = {
    name: {
        "purpose": "validation-tooling",
        "authority": [
            "scripts/native_linux_owner_bootstrap.py#_prepare_inputs",
            "scripts/native_linux_enrollment.py#run",
        ],
        "scope": "complete ordinary-file prepared ZIP custody, private input under caller umasks, real unprivileged byte transport and refusal of existing/dirty-source inputs",
        "relationship": "no-product-claim",
        "reason": "Fake downloaders supply synthetic inert bytes; a real ordinary Python child reads only that ZIP. No downloaded binary, selected runtime, credentials, SSH, package or privileged operation executes.",
        "claims": [],
    }
    for name in (
        "test_prepared_complete_input_crosses_real_unprivileged_transport_guard",
        "test_prepared_input_never_replaces_existing_destination",
        "test_dirty_source_rejects_before_preparing_fixed_inputs",
    )
}


def configuration():
    return {
        "enrollment": "fc72c95b-177a-430a-b5db-f313266b0bbb",
        "boot_id": "443bb91e-ef79-42d6-9a17-134f00165bd0",
        "bootstrap_sha256": "a" * 64,
        "input_sha256": "b" * 64,
        "input_bytes": 100,
        "runtime_executable_sha256": "d" * 64,
        "peer_uid": 1002,
        "peer_gid": 1002,
    }


def observation(c):
    inode = [20]

    def node(mode=0o700, kind="directory", uid=0, gid=0):
        inode[0] += 1
        return {"device": 23, "inode": inode[0], "uid": uid, "gid": gid, "mode": mode, "kind": kind}

    def tree(sealed=False, prepared=False):
        pins = dict(native.PINS)
        if prepared:
            pins["runtime.tar.gz"] = {
                "bytes": native.OWNER_PYTHON_BYTES,
                "sha256": native.OWNER_PYTHON_SHA256,
            }
        return {
            ".": node(mode=0o555 if sealed else 0o700),
            **{
                name: {
                    **node(
                        mode=(0o555 if name == "busybox" else 0o444) if sealed else 0o600,
                        kind="regular",
                    ),
                    **pin,
                }
                for name, pin in pins.items()
            },
        }

    prefix = "/var/lib/fishhat-bootstrap-fixture-" + c["enrollment"]
    poison = "/tmp/fishhat-bootstrap-fixture-" + c["enrollment"]
    complete, partial, prepared = tree(sealed=True), tree(), tree(prepared=True)
    namespaces = [{"path": prefix, **node(mode=0o755)}, {"path": poison, **node()}]
    invocations = {}
    for index, role in enumerate(("administrative", "peer")):
        peer = role == "peer"
        uid = c["peer_uid"] if peer else 0
        denied = (
            [
                {"role": role, "operation": operation, "errno": 13}
                for role, operation in native.DENIALS
            ]
            if peer
            else []
        )
        base = {
            "parent_pid": 120,
            "uids": [uid] * 3,
            "gids": [c["peer_gid"] if peer else 0] * 3,
            "groups": [] if peer else [0],
            "capabilities": "0" * 16 if peer else "000001ffffffffff",
            "boot_id": c["boot_id"],
            "enrollment": c["enrollment"],
            "cwd": poison,
            "executable": prefix + "/runtime/python/bin/python3.12",
            "executable_sha256": c["runtime_executable_sha256"],
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
            "denied": denied,
            "administrative_refusal": peer,
        }
        negative = {
            **base,
            "pid": 122 + 2 * index,
            "probe": f"00000000-0000-4000-8000-{index * 2:012d}",
            "environment": {
                **native.ENVIRONMENT,
                **dict.fromkeys(
                    (
                        "PATH",
                        "HOME",
                        "PYTHONHOME",
                        "PYTHONPATH",
                        "PYTHONUSERBASE",
                        "LD_LIBRARY_PATH",
                    ),
                    poison,
                ),
                "LD_DEBUG": "libs,files",
                "LD_DEBUG_OUTPUT": poison + "/loader-" + role,
                "LD_PRELOAD": poison + "/missing-preload.so",
                "ENV": poison + "/shell-startup",
                "BASH_ENV": poison + "/shell-startup",
                "PYTHONSTARTUP": poison + "/startup.py",
            },
        }
        sanitized = {
            **base,
            "pid": negative["pid"] + 1,
            "probe": f"00000000-0000-4000-8000-{index * 2 + 1:012d}",
            "environment": native.ENVIRONMENT,
        }
        loader = {
            **node(kind="regular", mode=0o600, uid=uid, gid=uid),
            "path": poison + "/loader-" + role + "." + str(negative["pid"]),
            "bytes": 2000,
            "sha256": "e" * 64,
        }
        invocations[role] = {
            "negative": negative,
            "negative_loader": loader,
            "sanitized": sanitized,
            "sanitized_loader_path": poison + "/loader-" + role + "." + str(sanitized["pid"]),
            "sanitized_loader_absent": True,
        }
    return copy.deepcopy(
        {
            "scope": native.SCOPE,
            "status": "passed",
            "native_product_qualified": False,
            **{key: c[key] for key in ("enrollment", "boot_id", "bootstrap_sha256")},
            "observer_pid": 120,
            "observer_uid": 0,
            "primary_error": None,
            "cleanup_errors": [],
            "cleanup": [
                {
                    "path": row["path"],
                    "device": row["device"],
                    "inode": row["inode"],
                    "absent": True,
                }
                for row in reversed(namespaces)
            ],
            "namespaces": namespaces,
            "input": {
                **node(kind="regular", mode=0o600),
                "bytes": c["input_bytes"],
                "sha256": c["input_sha256"],
            },
            "preparation_tool": {
                "path": "/usr/bin/dpkg-deb",
                "sha256": "f" * 64,
                "mode": "read-package-filesystem-only",
                "maintainer_scripts_executed": False,
            },
            "prepared": prepared,
            "prepared_after": copy.deepcopy(prepared),
            "before": complete,
            "after": copy.deepcopy(complete),
            "interruption": {
                "pid": 121,
                "parent_pid": 120,
                "uid": 0,
                "boot_id": c["boot_id"],
                "returncode": -9,
                "joined": True,
                "candidate": partial,
            },
            "interrupted_after": copy.deepcopy(partial),
            "rejections": [
                {
                    "case": name,
                    "type": "FileExistsError"
                    if name in ("interrupted", "existing")
                    else "NotADirectoryError"
                    if name in ("source-alias", "parent-alias")
                    else "ValueError",
                    "errno": 17
                    if name in ("interrupted", "existing")
                    else 20
                    if name in ("source-alias", "parent-alias")
                    else None,
                }
                for name in native.REJECTIONS
            ],
            "invocations": invocations,
        }
    )


def replace(value, path, replacement):
    for name in path[:-1]:
        value = value[name]
    value[path[-1]] = replacement


def test_controlled_complete_observation_is_accepted_without_native_claim():
    c = configuration()
    value = observation(c)
    assert native.verify_observation(value, c) is None
    assert value["native_product_qualified"] is False


FORGED_CASES = [
    (("scope",), "foreign"),
    (("status",), "failed"),
    (("native_product_qualified",), True),
    (("enrollment",), "foreign"),
    (("boot_id",), "foreign"),
    (("bootstrap_sha256",), "f" * 64),
    (("observer_uid",), False),
    (("observer_pid",), 1),
    (("primary_error",), {"stage": "failed"}),
    (("cleanup_errors",), [{"stage": "namespace"}]),
    (("input", "sha256"), "f" * 64),
    (("input", "bytes"), 0),
    (("before", "busybox", "mode"), 0o777),
    (("before", "LICENSE", "sha256"), "f" * 64),
    (("after", "busybox", "inode"), 200),
    (("prepared_after", "runtime.tar.gz", "sha256"), "f" * 64),
    (("interruption", "pid"), 120),
    (("interruption", "parent_pid"), 1),
    (("interruption", "uid"), 1002),
    (("interruption", "boot_id"), "foreign"),
    (("interruption", "returncode"), 0),
    (("interruption", "joined"), False),
    (("interruption", "candidate", ".", "mode"), 0o755),
    (("interrupted_after", "busybox", "inode"), 200),
    (("rejections",), []),
    (("rejections", 0, "errno"), 0),
    (("preparation_tool", "path"), "/untrusted/decoder"),
    (("preparation_tool", "maintainer_scripts_executed"), True),
    (("invocations", "peer", "sanitized", "environment"), {"LD_PRELOAD": "poison"}),
    (("invocations", "peer", "negative", "environment", "LD_DEBUG"), ""),
    (("invocations", "peer", "sanitized", "uids"), [0, 0, 0]),
    (("invocations", "peer", "sanitized", "gids"), [0, 0, 0]),
    (("invocations", "peer", "sanitized", "groups"), [0]),
    (("invocations", "peer", "sanitized", "capabilities"), "0000000000000001"),
    (("invocations", "peer", "sanitized", "executable"), "/untrusted/python"),
    (("invocations", "peer", "sanitized", "executable_sha256"), "f" * 64),
    (("invocations", "peer", "sanitized", "flags", "ignore_environment"), 0),
    (("invocations", "peer", "sanitized", "pid"), 121),
    (("invocations", "peer", "sanitized", "parent_pid"), 1),
    (("invocations", "peer", "sanitized", "boot_id"), "foreign"),
    (("invocations", "peer", "sanitized", "denied", 0, "errno"), 0),
    (("invocations", "peer", "sanitized", "administrative_refusal"), False),
    (("invocations", "peer", "negative_loader", "bytes"), 0),
    (("invocations", "peer", "negative_loader", "path"), "/unrelated/output"),
    (("invocations", "peer", "negative_loader", "uid"), 0),
    (("invocations", "peer", "sanitized_loader_absent"), False),
    (("cleanup",), []),
    (("cleanup", 0, "inode"), 200),
    (("cleanup", 0, "absent"), False),
    (("namespaces", 0, "mode"), 0o777),
]


@pytest.mark.parametrize(
    "path,replacement", FORGED_CASES, ids=["-".join(map(str, path)) for path, _ in FORGED_CASES]
)
def test_forged_or_incomplete_observation_is_rejected(path, replacement):
    c = configuration()
    value = observation(c)
    replace(value, path, replacement)
    with pytest.raises((GuestBootError, KeyError, TypeError, ValueError)):
        native.verify_observation(value, c)


@pytest.mark.parametrize(
    "program",
    [native.OBSERVE, native.INTERRUPTED, native.REMOTE],
    ids=["observer", "interrupted-installer", "coordinator"],
)
def test_guest_programs_parse_without_execution(program):
    assert ast.parse(program)


@pytest.mark.parametrize("reply", ["passed", "invalid-json", "forged", "transport-failure"])
def test_coordinator_retains_original_reply_and_scoped_statistics_without_execution(
    tmp_path, monkeypatch, reply
):
    c = configuration()
    path = tmp_path / "inputs.zip"
    path.write_bytes(b"synthetic inert transport")
    prepared = {key: c[key] for key in ("input_sha256", "input_bytes", "runtime_executable_sha256")}
    calls = []

    def guarded(action, enrollment, boot, *, nominal, input_path):
        assert (
            action[:5] == ["/usr/bin/python3", "-I", "-S", "-B", "-c"]
            and action[5] == native.REMOTE
        )
        assert (
            enrollment == c["enrollment"]
            and boot == c["boot_id"]
            and nominal == 600
            and input_path == path
        )
        config = json.loads(action[-1])
        calls.append(config)
        value = observation(config)
        if reply == "transport-failure":
            raise GuestBootError("controlled-transport-failure")
        if reply == "forged":
            value["invocations"]["peer"]["sanitized"]["environment"] = {"LD_PRELOAD": "poison"}
        return "invalid-json" if reply == "invalid-json" else json.dumps(value)

    guest = SimpleNamespace(
        observed={
            "boot_id": c["boot_id"],
            "accounts": {"peer": {"uid": c["peer_uid"], "gid": c["peer_gid"]}},
        },
        enrollment=c["enrollment"],
        accounts=("root", "peer"),
        guarded=guarded,
    )
    monkeypatch.setattr(native, "_prepare_inputs", lambda *args: (path, prepared))
    report = {}
    if reply == "passed":
        native.qualify_bootstrap(guest, tmp_path, lambda label: nullcontext(), report)
        assert report["status"] == "passed"
    else:
        with pytest.raises(GuestBootError):
            native.qualify_bootstrap(guest, tmp_path, lambda label: nullcontext(), report)
        assert report["status"] == "failed"
    assert report["native_product_qualified"] is False and valid_stats(
        report["qualification_statistics"]
    )
    if reply in ("passed", "forged"):
        original = json.dumps(report["original_observation"])
        assert report["original_reply_sha256"] == hashlib.sha256(original.encode()).hexdigest()
    elif reply == "invalid-json":
        assert report["unparsed_original_reply"] == "invalid-json"
    assert calls


def test_unverified_guest_rejects_before_input_or_transport(tmp_path, monkeypatch):
    monkeypatch.setattr(
        native, "_prepare_inputs", lambda *args: pytest.fail("unverified guest prepared inputs")
    )
    with pytest.raises(GuestBootError, match="guest-not-verified"):
        native.qualify_bootstrap(
            SimpleNamespace(observed=None), tmp_path, lambda label: nullcontext(), {}
        )


@pytest.fixture
def prepared_input_fixture(monkeypatch):
    stream = io.BytesIO()
    executable = b"synthetic non-executed interpreter bytes"
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        member = tarfile.TarInfo("python/bin/python3.12")
        member.size = len(executable)
        archive.addfile(member, io.BytesIO(executable))
    members = {name: ("synthetic data: " + name).encode() for name in native.TRANSFER_NAMES}
    members["runtime.tar.gz"] = stream.getvalue()
    monkeypatch.setattr(
        native,
        "PINS",
        {
            name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for name, raw in members.items()
            if name != "runtime.tar.gz"
        },
    )
    monkeypatch.setattr(native, "OWNER_PYTHON_BYTES", len(members["runtime.tar.gz"]))
    monkeypatch.setattr(
        native, "OWNER_PYTHON_SHA256", hashlib.sha256(members["runtime.tar.gz"]).hexdigest()
    )
    monkeypatch.setattr(native, "source_identity", lambda: {"commit": "a" * 40, "clean": True})
    calls = []

    def download(command, label, nominal):
        path = Path(command[5])
        raw = members[path.name]
        assert (
            command[1:4] == ["-I", "-S", "-B"]
            and label == "owner-bootstrap-fixed-input-download"
            and nominal == 180
        )
        assert command[6] == (
            native.OWNER_PYTHON_URL if path.name == "runtime.tar.gz" else native.ARCHIVE + path.name
        )
        assert command[7:9] == [str(len(raw)), hashlib.sha256(raw).hexdigest()]
        assert command[9] == str(native.watchdog(30))
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
        calls.append(path.name)

    return SimpleNamespace(command=download), members, executable, calls


@pytest.mark.parametrize("mask", [0o000, 0o022, 0o077])
def test_prepared_complete_input_crosses_real_unprivileged_transport_guard(
    tmp_path, prepared_input_fixture, mask
):
    from scripts.native_linux_enrollment import run

    guest, members, executable, calls = prepared_input_fixture
    before = os.umask(mask)
    try:
        path, record = native._prepare_inputs(guest, tmp_path)
    finally:
        os.umask(before)
    assert calls == list(members)
    assert (
        stat.S_IMODE(path.stat().st_mode) == 0o600
        and path.stat().st_uid == os.geteuid()
        and path.stat().st_nlink == 1
    )
    original = path.read_bytes()
    reply = run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-c",
            "import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())",
        ],
        "local-bootstrap-byte-reader",
        10,
        capture=True,
        input_path=path,
    )
    assert reply.strip() == hashlib.sha256(original).hexdigest() == record["input_sha256"]
    assert record["input_bytes"] == len(original)
    assert record["input_members"] == {
        name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()
    }
    assert record["runtime_executable_sha256"] == hashlib.sha256(executable).hexdigest()
    with zipfile.ZipFile(path) as archive:
        assert archive.namelist() == list(members)
        assert {name: archive.read(name) for name in members} == members
        assert all(item.compress_type == zipfile.ZIP_STORED for item in archive.infolist())


@pytest.mark.parametrize("kind", ["regular", "symlink", "hardlink"])
def test_prepared_input_never_replaces_existing_destination(tmp_path, prepared_input_fixture, kind):
    guest, _, _, _ = prepared_input_fixture
    retained = tmp_path / "retained"
    retained.write_bytes(b"unrelated preserved input")
    path = tmp_path / "inputs.zip"
    if kind == "regular":
        path.write_bytes(b"existing input")
    elif kind == "symlink":
        path.symlink_to(retained)
    else:
        os.link(retained, path)
    before = path.lstat()
    with pytest.raises(FileExistsError):
        native._prepare_inputs(guest, tmp_path)
    assert path.lstat() == before and retained.read_bytes() == b"unrelated preserved input"
    if kind == "regular":
        assert path.read_bytes() == b"existing input"


def test_dirty_source_rejects_before_preparing_fixed_inputs(
    tmp_path, prepared_input_fixture, monkeypatch
):
    guest, _, _, calls = prepared_input_fixture
    monkeypatch.setattr(native, "source_identity", lambda: {"commit": "a" * 40, "clean": False})
    with pytest.raises(GuestBootError, match="source-not-clean"):
        native._prepare_inputs(guest, tmp_path)
    assert not calls and not list(tmp_path.iterdir())
