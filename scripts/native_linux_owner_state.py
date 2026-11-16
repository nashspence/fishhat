"""Observe fresh owner storage only in an authenticated disposable Linux guest."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest, GuestBootError
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import watchdog

SCOPE = "disposable-guest-fresh-protected-owner-state-only"
REJECTIONS = (
    "interrupted-destination",
    "existing-directory",
    "existing-file",
    "existing-symlink",
    "foreign-ancestor",
    "writable-ancestor",
    "symlink-ancestor",
)
DENIALS = ("list", "read", "write", "create", "unlink", "rename")
CANARY = b"protected synthetic state canary; no owner initialized"

PEER = r"""
import base64, errno, json, os, pathlib, sys, types
c = json.loads(sys.argv[1])
state = pathlib.Path(c["state"])
operations = {
    "list": lambda: list(state.iterdir()),
    "read": lambda: (state / "canary").read_bytes(),
    "write": lambda: (state / "canary").write_bytes(b"peer mutation"),
    "create": lambda: (state / "new").touch(exist_ok=False),
    "unlink": lambda: (state / "canary").unlink(),
    "rename": lambda: state.rename(state.with_name("peer-renamed")),
}
denied = []
for name, action in operations.items():
    try:
        action()
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EPERM)
        denied.append({"operation": name, "errno": error.errno})
    else:
        raise AssertionError("peer accessed protected state")
module = types.ModuleType("approved_state_installer")
exec(compile(base64.b64decode(c["bootstrap"]), "<approved-bootstrap>", "exec"), module.__dict__)
try:
    module._prepare_owner_state(pathlib.Path(c["peer_root"]) / "unavailable")
except ValueError as error:
    assert "administrative custody" in str(error)
else:
    raise AssertionError("peer provisioned administrative state")
assert not (pathlib.Path(c["peer_root"]) / "unavailable").exists()
print(json.dumps({"pid": os.getpid(), "parent_pid": os.getppid(), "uids": list(os.getresuid()),
                  "gids": list(os.getresgid()), "groups": os.getgroups(),
                  "capabilities": next(line.split(":", 1)[1].strip() for line in pathlib.Path("/proc/self/status").read_text().splitlines() if line.startswith("CapEff:")),
                  "denied": denied, "administrative_refusal": True}, sort_keys=True))
"""

INTERRUPTED = r"""
import base64, json, os, pathlib, sys, types
c = json.loads(sys.argv[1])
module = types.ModuleType("approved_interrupted_state_installer")
exec(compile(base64.b64decode(c["bootstrap"]), "<approved-bootstrap>", "exec"), module.__dict__)
def pause(descriptor):
    ready = pathlib.Path(c["ready"])
    pending = ready.with_suffix(".pending")
    with pending.open("x") as stream:
        os.chmod(pending, 0o600)
        json.dump({"pid": os.getpid(), "parent_pid": os.getppid(), "uid": os.geteuid(), "boot_id": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()}, stream)
        stream.flush()
        original(stream.fileno())
    os.replace(pending, ready)
    assert sys.stdin.buffer.read(1) == b"never release"
    raise AssertionError("interrupted provisioning resumed")
original = module.os.fsync
module.os.fsync = pause
module._prepare_owner_state(pathlib.Path(c["interrupted"]))
"""

REMOTE = r"""
import base64, errno, hashlib, json, os, pathlib, shutil, signal, stat, subprocess, sys, time, types
c = json.loads(sys.argv[1])
result = {"scope": c["scope"], "status": "failed", "native_product_qualified": False,
          "enrollment": c["enrollment"], "boot_id": c["boot_id"], "bootstrap_sha256": c["bootstrap_sha256"],
          "observer_pid": os.getpid(), "observer_uid": os.geteuid(), "primary_error": None,
          "cleanup_errors": [], "cleanup": []}
owned = []
child = None
stage = "admission"
def metadata(path):
    value = path.lstat()
    return {"device": value.st_dev, "inode": value.st_ino, "uid": value.st_uid, "gid": value.st_gid,
            "mode": stat.S_IMODE(value.st_mode), "kind": "link" if stat.S_ISLNK(value.st_mode) else "directory" if stat.S_ISDIR(value.st_mode) else "regular" if stat.S_ISREG(value.st_mode) else "other"}
def content(path):
    raw = path.read_bytes()
    return {**metadata(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
def snapshot(path):
    return {"directory": metadata(path), "entries": {p.name: content(p) for p in path.iterdir()}}
try:
    assert os.geteuid() == os.getegid() == 0
    assert pathlib.Path("/etc/fishhat-fixture-enrollment").read_text().strip() == c["enrollment"]
    assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == c["boot_id"]
    raw = base64.b64decode(c["bootstrap"])
    assert hashlib.sha256(raw).hexdigest() == c["bootstrap_sha256"]
    module = types.ModuleType("approved_state_installer")
    exec(compile(raw, "<approved-bootstrap>", "exec"), module.__dict__)
    prefix = pathlib.Path("/var/lib") / ("fishhat-state-fixture-" + c["enrollment"])
    peer_root = pathlib.Path("/tmp") / ("fishhat-state-fixture-" + c["enrollment"])
    for path, mode in ((prefix, 0o755), (peer_root, 0o700)):
        path.mkdir(mode=mode)
        owned.append((path, metadata(path)))
    os.chown(peer_root, c["peer_uid"], c["peer_gid"])
    clean = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    interrupted = prefix / "interrupted"
    ready = prefix / "ready.json"
    stage = "interruption-before-sync"
    config = {**c, "interrupted": str(interrupted), "ready": str(ready)}
    child = subprocess.Popen(["/usr/bin/python3", "-I", "-S", "-B", "-c", c["interrupt_program"], json.dumps(config)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd="/", env=clean, close_fds=True)
    deadline = time.monotonic() + c["child_timeout"]
    while not ready.exists():
        assert child.poll() is None, "interrupted child exited before gate"
        assert time.monotonic() < deadline, "interrupted child gate timeout"
        time.sleep(0.05)
    original_child = json.loads(ready.read_text())
    assert original_child == {"pid": child.pid, "parent_pid": os.getpid(), "uid": 0, "boot_id": c["boot_id"]}
    child.kill()
    child.communicate(timeout=c["child_timeout"])
    assert child.returncode == -signal.SIGKILL
    result["interruption"] = {**original_child, "returncode": child.returncode, "joined": True,
                              "state": snapshot(interrupted)}
    child = None
    result["rejections"] = []
    def reject(name, path):
        try:
            module._prepare_owner_state(path)
        except (OSError, ValueError) as error:
            result["rejections"].append({"case": name, "error": type(error).__name__, "errno": getattr(error, "errno", None)})
        else:
            raise AssertionError("state refusal missing: " + name)
    reject("interrupted-destination", interrupted)
    assert result["interruption"]["state"] == snapshot(interrupted)
    state = prefix / "state"
    stage = "fresh-state"
    assert module._prepare_owner_state(state) == state
    result["created"] = snapshot(state)
    canary = state / "canary"
    canary.write_bytes(base64.b64decode(c["canary"]))
    os.chmod(canary, 0o600)
    result["before"] = snapshot(state)
    stage = "peer-permissions"
    peer_config = {**c, "state": str(state), "peer_root": str(peer_root)}
    child = subprocess.Popen(["/usr/bin/python3", "-I", "-S", "-B", "-c", c["peer_program"], json.dumps(peer_config)],
                             user=c["peer_uid"], group=c["peer_gid"], extra_groups=[], stdin=subprocess.DEVNULL,
                             cwd=str(peer_root), env=clean, close_fds=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, errors = child.communicate(timeout=c["child_timeout"])
    assert child.returncode == 0, errors.decode(errors="replace")
    result["peer_pid"] = child.pid
    result["peer"] = json.loads(output)
    assert result["peer"]["pid"] == child.pid and result["peer"]["parent_pid"] == os.getpid()
    child = None
    result["after"] = snapshot(state)
    assert result["before"] == result["after"]
    stage = "existing-input-preservation"
    existing_file = prefix / "retained"
    existing_file.write_bytes(b"unrelated existing installation data")
    os.chmod(existing_file, 0o600)
    alias = prefix / "alias"
    alias.symlink_to(state, target_is_directory=True)
    result["existing_before"] = {"file": content(existing_file), "alias": {**metadata(alias), "target": os.readlink(alias)}, "directory": snapshot(state)}
    for name, path in (("existing-directory", state), ("existing-file", existing_file), ("existing-symlink", alias)):
        reject(name, path)
    result["existing_after"] = {"file": content(existing_file), "alias": {**metadata(alias), "target": os.readlink(alias)}, "directory": snapshot(state)}
    assert result["existing_before"] == result["existing_after"]
    stage = "ancestry-refusals"
    result["ancestors"] = []
    for kind in ("foreign", "writable", "symlink"):
        parent = prefix / ("ancestor-" + kind)
        if kind == "symlink":
            target = prefix / "ancestor-target"
            target.mkdir(mode=0o700)
            parent.symlink_to(target, target_is_directory=True)
        else:
            parent.mkdir(mode=0o700)
            if kind == "foreign":
                os.chown(parent, c["peer_uid"], c["peer_gid"])
            else:
                os.chmod(parent, 0o770)
        result["ancestors"].append({"case": kind + "-ancestor", "identity": metadata(parent)})
        reject(kind + "-ancestor", parent / "unavailable")
        assert not (parent / "unavailable").exists()
    result["state_final"] = snapshot(state)
    assert result["state_final"] == result["before"]
    result["interrupted_final"] = snapshot(interrupted)
    assert result["interrupted_final"] == result["interruption"]["state"]
    result["status"] = "passed"
except BaseException as error:
    result["primary_error"] = {"stage": stage, "type": type(error).__name__}
finally:
    if child is not None:
        try:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=c["child_timeout"])
        except BaseException as error:
            result["cleanup_errors"].append({"stage": "child", "type": type(error).__name__})
    for path, enrolled in reversed(owned):
        try:
            observed = metadata(path)
            assert all(observed[key] == enrolled[key] for key in ("device", "inode", "kind"))
            assert observed["uid"] in (0, c["peer_uid"])
            assert shutil.rmtree.avoids_symlink_attacks
            shutil.rmtree(path)
            assert not path.exists() and not path.is_symlink()
            result["cleanup"].append({"path": str(path), "device": enrolled["device"], "inode": enrolled["inode"], "absent": True})
        except BaseException as error:
            result["cleanup_errors"].append({"stage": "namespace", "type": type(error).__name__})
    if result["cleanup_errors"]:
        result["status"] = "failed"
print(json.dumps(result, sort_keys=True))
"""


def _metadata(row: dict[str, Any], uid: int, gid: int, mode: int, kind: str) -> None:
    if (
        set(row) != {"device", "inode", "uid", "gid", "mode", "kind"}
        or any(type(row[k]) is not int or row[k] < 0 for k in ("device", "uid", "gid", "mode"))
        or type(row["inode"]) is not int
        or row["inode"] <= 0
        or (row["uid"], row["gid"], row["mode"], row["kind"]) != (uid, gid, mode, kind)
    ):
        raise GuestBootError("owner-state-metadata-mismatch")


def _file(row: dict[str, Any], raw: bytes) -> None:
    identity = {k: v for k, v in row.items() if k not in ("bytes", "sha256")}
    _metadata(identity, 0, 0, 0o600, "regular")
    if row.get("bytes") != len(raw) or row.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise GuestBootError("owner-state-content-mismatch")


def _state(row: dict[str, Any], *, populated: bool = False) -> None:
    if set(row) != {"directory", "entries"}:
        raise GuestBootError("owner-state-inventory-mismatch")
    _metadata(row["directory"], 0, 0, 0o700, "directory")
    if set(row["entries"]) != ({"canary"} if populated else set()):
        raise GuestBootError("owner-state-unexpected-entry")
    if populated:
        _file(row["entries"]["canary"], CANARY)


def verify_observation(value: dict[str, Any], configuration: dict[str, Any]) -> None:
    if (
        value.get("scope") != SCOPE
        or value.get("status") != "passed"
        or value.get("native_product_qualified") is not False
        or value.get("primary_error") is not None
        or value.get("cleanup_errors") != []
        or type(value.get("observer_uid")) is not int
        or value["observer_uid"] != 0
    ):
        raise GuestBootError("owner-state-observation-failed")
    required = {
        "scope",
        "status",
        "native_product_qualified",
        "enrollment",
        "boot_id",
        "bootstrap_sha256",
        "observer_pid",
        "observer_uid",
        "primary_error",
        "cleanup_errors",
        "cleanup",
        "interruption",
        "rejections",
        "created",
        "before",
        "peer_pid",
        "peer",
        "after",
        "existing_before",
        "existing_after",
        "ancestors",
        "state_final",
        "interrupted_final",
    }
    if set(value) != required:
        raise GuestBootError("owner-state-incomplete-observation")
    for key in ("enrollment", "boot_id", "bootstrap_sha256"):
        if value[key] != configuration[key]:
            raise GuestBootError("owner-state-identity-mismatch")
    _state(value["created"])
    _state(value["before"], populated=True)
    if (
        value["created"]["directory"] != value["before"]["directory"]
        or value["before"] != value["after"]
        or value["after"] != value["state_final"]
        or value["existing_before"] != value["existing_after"]
        or value["existing_before"]["directory"] != value["before"]
    ):
        raise GuestBootError("owner-state-preservation-mismatch")
    _file(value["existing_before"]["file"], b"unrelated existing installation data")
    alias = value["existing_before"]["alias"]
    _metadata({k: v for k, v in alias.items() if k != "target"}, 0, 0, 0o777, "link")
    prefix = "/var/lib/fishhat-state-fixture-" + configuration["enrollment"]
    if alias.get("target") != prefix + "/state":
        raise GuestBootError("owner-state-alias-mismatch")
    interrupted = value["interruption"]
    _state(interrupted["state"])
    if (
        interrupted["returncode"] != -9
        or interrupted["joined"] is not True
        or interrupted["uid"] != 0
        or interrupted["boot_id"] != configuration["boot_id"]
        or interrupted["state"] != value["interrupted_final"]
        or interrupted["state"]["directory"]["inode"] == value["created"]["directory"]["inode"]
    ):
        raise GuestBootError("owner-state-interruption-mismatch")
    peer = value["peer"]
    if (
        peer["uids"] != [configuration["peer_uid"]] * 3
        or peer["gids"] != [configuration["peer_gid"]] * 3
        or peer["groups"] != []
        or int(peer["capabilities"], 16) != 0
        or peer["administrative_refusal"] is not True
        or peer["pid"] != value["peer_pid"]
        or [r["operation"] for r in peer["denied"]] != list(DENIALS)
        or any(type(r["errno"]) is not int or r["errno"] not in (1, 13) for r in peer["denied"])
    ):
        raise GuestBootError("owner-state-peer-mismatch")
    pids = [value["observer_pid"], peer["pid"], interrupted["pid"]]
    if (
        any(type(pid) is not int or pid <= 0 for pid in pids)
        or len(set(pids)) != 3
        or peer["parent_pid"] != value["observer_pid"]
        or interrupted["parent_pid"] != value["observer_pid"]
    ):
        raise GuestBootError("owner-state-process-mismatch")
    if [row["case"] for row in value["rejections"]] != list(REJECTIONS):
        raise GuestBootError("owner-state-refusals-missing")
    for row in value["rejections"]:
        expected = (
            ({"FileExistsError"}, {17})
            if row["case"] in REJECTIONS[:4]
            else ({"NotADirectoryError", "OSError"}, {20, 40})
            if row["case"] == "symlink-ancestor"
            else ({"ValueError"}, {None})
        )
        if row["error"] not in expected[0] or row["errno"] not in expected[1]:
            raise GuestBootError("owner-state-refusal-kind-mismatch")
    ancestors = value["ancestors"]
    if [row["case"] for row in ancestors] != list(REJECTIONS[4:]):
        raise GuestBootError("owner-state-ancestor-witness-missing")
    for row, fields in zip(
        ancestors,
        (
            (configuration["peer_uid"], configuration["peer_gid"], 0o700, "directory"),
            (0, 0, 0o770, "directory"),
            (0, 0, 0o777, "link"),
        ),
        strict=True,
    ):
        _metadata(row["identity"], *fields)
    cleanup = value["cleanup"]
    if (
        [row["path"] for row in cleanup]
        != ["/tmp/fishhat-state-fixture-" + configuration["enrollment"], prefix]
        or any(row["absent"] is not True for row in cleanup)
        or any(
            type(row[k]) is not int or row[k] < 1 for row in cleanup for k in ("device", "inode")
        )
        or len({(row["device"], row["inode"]) for row in cleanup}) != 2
    ):
        raise GuestBootError("owner-state-cleanup-mismatch")


def qualify_state(guest: Guest, report: dict[str, Any]) -> None:
    if guest.observed is None:
        raise GuestBootError("guest-not-verified")
    metrics = RunStats()
    report.update(scope=SCOPE, status="failed", native_product_qualified=False)
    try:
        bootstrap = Path(__file__).with_name("bundle_install.py").read_bytes()
        peer = guest.observed["accounts"][guest.accounts[1]]
        config = {
            "scope": SCOPE,
            "enrollment": guest.enrollment,
            "boot_id": guest.observed["boot_id"],
            "bootstrap": base64.b64encode(bootstrap).decode(),
            "bootstrap_sha256": hashlib.sha256(bootstrap).hexdigest(),
            "peer_uid": peer["uid"],
            "peer_gid": peer["gid"],
            "canary": base64.b64encode(CANARY).decode(),
            "child_timeout": watchdog(30),
            "peer_program": PEER,
            "interrupt_program": INTERRUPTED,
        }
        raw = guest.guarded(
            ["/usr/bin/python3", "-I", "-S", "-B", "-c", REMOTE, json.dumps(config)],
            guest.enrollment,
            guest.observed["boot_id"],
            nominal=120,
        )
        report["original_reply_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
        try:
            value = json.loads(raw)
        except (ValueError, RecursionError):
            report["unparsed_original_reply"] = raw
            raise GuestBootError("owner-state-invalid-original-reply") from None
        report["original_observation"] = value
        try:
            verify_observation(value, config)
        except (KeyError, TypeError, ValueError, AttributeError):
            raise GuestBootError("owner-state-invalid-observation-shape") from None
        report["status"] = "passed"
    finally:
        report["qualification_statistics"] = metrics.finish()
        if not valid_stats(report["qualification_statistics"]):
            raise GuestBootError("owner-state-invalid-statistics")
