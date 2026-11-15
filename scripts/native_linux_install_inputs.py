"""Observe protected input custody only inside an already enrolled disposable guest."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest, GuestBootError
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import Deadline, watchdog

SCOPE = "disposable-guest-protected-bundle-inputs-only"
REJECTIONS = (
    "source-file-symlink",
    "source-directory-symlink",
    "source-root-symlink",
    "source-fifo",
    "existing-directory",
    "existing-file",
    "existing-symlink",
    "foreign-ancestor",
    "writable-ancestor",
    "symlink-ancestor",
    "recursive-destination",
)

PEER = r"""
import base64, errno, json, os, pathlib, types
c = json.loads(__import__("sys").argv[1])
uid, gid = c["peer_uid"], c["peer_gid"]
assert list(os.getresuid()) == [uid] * 3 and list(os.getresgid()) == [gid] * 3
assert os.getgroups() == []
caps = next(line.split(":", 1)[1].strip() for line in pathlib.Path("/proc/self/status").read_text().splitlines() if line.startswith("CapEff:"))
assert int(caps, 16) == 0
denied = []
target = pathlib.Path(c["staged"]) / "wheels/fixture.whl"
for operation in ("write", "unlink"):
    try:
        if operation == "write":
            descriptor = os.open(target, os.O_WRONLY | os.O_NONBLOCK)
            os.close(descriptor)
        else:
            target.unlink()
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EPERM)
        denied.append({"operation": operation, "errno": error.errno})
    else:
        raise AssertionError("unprivileged staged input mutation was allowed")
source = pathlib.Path(c["source"])
for name in ("locks/fixture.txt", "wheels/fixture.whl"):
    (source / name).write_bytes(b"caller replacement")
module = types.ModuleType("isolated_fixture_stager")
exec(compile(base64.b64decode(c["bootstrap"]), "<approved-bootstrap>", "exec"), module.__dict__)
try:
    module._protected_parent(source / "unavailable")
except ValueError as error:
    assert "administrative custody" in str(error)
else:
    raise AssertionError("unprivileged administrative staging was allowed")
assert not (source / "unavailable").exists()
print(json.dumps({"pid": os.getpid(), "parent_pid": os.getppid(), "uids": list(os.getresuid()), "gids": list(os.getresgid()), "groups": os.getgroups(), "effective_capabilities": caps, "denied": denied, "administrative_refusal": True}))
"""

REMOTE = r"""
import base64, errno, hashlib, json, os, pathlib, shutil, stat, subprocess, sys, traceback, types
c = json.loads(sys.argv[1])
scope = "disposable-guest-protected-bundle-inputs-only"
result = {"scope": scope, "status": "failed", "native_product_qualified": False,
          "enrollment": c["enrollment"], "boot_id": c["boot_id"],
          "bootstrap_sha256": c["bootstrap_sha256"], "manifest_sha256": c["manifest_sha256"],
          "observer_uid": os.geteuid(), "observer_pid": os.getpid(),
          "primary_error": None, "cleanup_errors": [], "cleanup": []}
owned = []
stage = "admission"

def snapshot(path):
    value = path.lstat()
    return {"device": value.st_dev, "inode": value.st_ino, "uid": value.st_uid,
            "gid": value.st_gid, "mode": stat.S_IMODE(value.st_mode),
            "kind": "directory" if stat.S_ISDIR(value.st_mode) else "regular" if stat.S_ISREG(value.st_mode) else "other"}

def owned_directory(path, uid=0, gid=0):
    path.mkdir(mode=0o700)
    os.chown(path, uid, gid)
    value = snapshot(path)
    owned.append((path, value))
    return path

def make_bundle(path):
    path.mkdir(mode=0o700)
    for name, encoded in c["files"].items():
        target = path / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(base64.b64decode(encoded))
    return path

def inventory(path):
    files, directories = {}, {".": snapshot(path)}
    for target in path.rglob("*"):
        assert not target.is_symlink()
        name = target.relative_to(path).as_posix()
        if target.is_dir():
            directories[name] = snapshot(target)
        else:
            assert stat.S_ISREG(target.lstat().st_mode)
            raw = target.read_bytes()
            files[name] = {**snapshot(target), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    return {"files": files, "directories": directories}

try:
    assert os.geteuid() == os.getegid() == 0 and c["peer_uid"] > 0
    assert pathlib.Path("/etc/fishhat-fixture-enrollment").read_text().strip() == c["enrollment"]
    assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == c["boot_id"]
    raw = base64.b64decode(c["bootstrap"])
    assert hashlib.sha256(raw).hexdigest() == c["bootstrap_sha256"]
    module = types.ModuleType("approved_fixture_stager")
    exec(compile(raw, "<approved-bootstrap>", "exec"), module.__dict__)
    def forbidden(*args, **kwargs):
        raise AssertionError("installer execution during input staging")
    module.subprocess = types.SimpleNamespace(run=forbidden)
    prefix = owned_directory(pathlib.Path("/var/lib") / ("fishhat-input-fixture-" + c["enrollment"]))
    source_root = owned_directory(pathlib.Path("/tmp") / ("fishhat-input-fixture-" + c["enrollment"]), c["peer_uid"], c["peer_gid"])
    source = make_bundle(source_root / "source")
    for path in [source, *source.rglob("*")]:
        os.chown(path, c["peer_uid"], c["peer_gid"])
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    result["source_before"] = inventory(source)
    canary = prefix / "unrelated-canary"
    canary.write_bytes(b"unrelated retained fixture input")
    os.chmod(canary, 0o600)
    original_canary = {**snapshot(canary), "sha256": hashlib.sha256(canary.read_bytes()).hexdigest()}
    stage = "protected-stage"
    staged = module._stage_verified(source, prefix / "staged", c["manifest_sha256"])
    result["before"] = inventory(staged)
    assert result["before"]["files"].keys() == c["files"].keys()
    for name, row in result["before"]["files"].items():
        expected = base64.b64decode(c["files"][name])
        assert row["bytes"] == len(expected) and row["sha256"] == hashlib.sha256(expected).hexdigest()
        assert row["uid"] == row["gid"] == 0 and row["mode"] == 0o600
    assert all(row["uid"] == row["gid"] == 0 and row["mode"] == 0o700 for row in result["before"]["directories"].values())
    stage = "peer-observation"
    peer_config = {**c, "source": str(source), "staged": str(staged)}
    with subprocess.Popen(["/usr/bin/python3", "-I", "-S", "-B", "-c", c["peer_program"], json.dumps(peer_config)],
                          user=c["peer_uid"], group=c["peer_gid"], extra_groups=[],
                          cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                          stdin=subprocess.DEVNULL, close_fds=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        try:
            output, errors = child.communicate(timeout=c["child_timeout_seconds"])
        except subprocess.TimeoutExpired:
            child.kill()
            output, errors = child.communicate()
            raise AssertionError("peer observation timed out")
        assert child.returncode == 0, errors.decode(errors="replace")
        result["peer_pid"] = child.pid
        result["peer"] = json.loads(output)
        assert result["peer"]["pid"] == child.pid and result["peer"]["parent_pid"] == os.getpid()
    result["after"] = inventory(staged)
    assert result["before"] == result["after"]
    result["source_after"] = inventory(source)
    assert all((source / name).read_bytes() == b"caller replacement" for name in ("locks/fixture.txt", "wheels/fixture.whl"))
    result["rejections"] = []
    def reject(name, action, expected):
        try:
            action()
        except (OSError, ValueError) as error:
            assert expected(error), (name, type(error).__name__, str(error))
            result["rejections"].append({"case": name, "error": type(error).__name__, "errno": getattr(error, "errno", None)})
        else:
            raise AssertionError("rejection was not observed: " + name)
        assert {**snapshot(canary), "sha256": hashlib.sha256(canary.read_bytes()).hexdigest()} == original_canary
    stage = "source-substitutions"
    for kind in ("file", "directory", "root", "fifo"):
        bad = make_bundle(source_root / ("bad-" + kind))
        argument = bad
        if kind == "root":
            argument = source_root / "source-alias"
            argument.symlink_to(bad, target_is_directory=True)
        elif kind == "fifo":
            (bad / "wheels/fixture.whl").unlink()
            os.mkfifo(bad / "wheels/fixture.whl", 0o600)
        else:
            path = bad / ("wheels/fixture.whl" if kind == "file" else "wheels")
            retained = source_root / ("retained-" + kind)
            path.rename(retained)
            path.symlink_to(retained, target_is_directory=kind == "directory")
        name = "source-" + (kind + "-symlink" if kind != "fifo" else "fifo")
        expected = (lambda error: isinstance(error, OSError) and error.errno in (errno.ELOOP, errno.ENOTDIR)) if kind == "root" else (lambda error: isinstance(error, ValueError) and ("symbolic link" in str(error) or "not a regular file" in str(error)))
        reject(name, lambda: module._stage_verified(argument, prefix / ("denied-" + kind), c["manifest_sha256"]), expected)
    clean = make_bundle(source_root / "clean")
    stage = "destination-substitutions"
    result["preserved_existing"] = []
    for kind in ("directory", "file", "symlink"):
        destination = prefix / ("existing-" + kind)
        if kind == "file":
            destination.write_bytes(b"retained existing input")
            os.chmod(destination, 0o600)
            target = destination
        else:
            target = destination if kind == "directory" else prefix / "unrelated-existing-target"
            target.mkdir(mode=0o700)
            (target / "keep").write_bytes(b"retained existing input")
            os.chmod(target / "keep", 0o600)
            if kind == "symlink":
                destination.symlink_to(target, target_is_directory=True)
        def retained():
            if kind == "file":
                data = target.read_bytes()
                content = {"files": {".": {**snapshot(target), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}}, "directories": {}}
            else:
                content = inventory(target)
            return {"node": snapshot(destination), "content": content}
        before = retained()
        reject("existing-" + kind, lambda: module._stage_verified(clean, destination, c["manifest_sha256"]), lambda error: isinstance(error, FileExistsError))
        after = retained()
        assert after == before
        result["preserved_existing"].append({"case": "existing-" + kind, "before": before, "after": after})
    stage = "ancestry-substitutions"
    result["ancestor_observations"] = []
    for kind in ("foreign", "writable", "symlink"):
        parent = prefix / ("ancestor-" + kind)
        if kind == "symlink":
            target = prefix / "ancestor-target"
            target.mkdir(mode=0o700)
            (target / "child").mkdir(mode=0o700)
            parent.symlink_to(target, target_is_directory=True)
        else:
            parent.mkdir(mode=0o700)
            (parent / "child").mkdir(mode=0o700)
            if kind == "foreign":
                os.chown(parent, c["peer_uid"], c["peer_gid"])
            else:
                os.chmod(parent, 0o770)
        result["ancestor_observations"].append({"case": kind + "-ancestor", "ancestor": snapshot(parent), "leaf_parent": snapshot(parent / "child")})
        expected = (lambda error: isinstance(error, OSError) and error.errno in (errno.ELOOP, errno.ENOTDIR)) if kind == "symlink" else (lambda error: isinstance(error, ValueError) and "unprotected staging ancestry" in str(error))
        reject((kind + "-ancestor"), lambda: module._stage_verified(clean, parent / "child/unavailable", c["manifest_sha256"]), expected)
        assert not (parent / "child/unavailable").exists()
    stage = "recursive-destination"
    recursive_source = make_bundle(prefix / "recursive-source")
    reject("recursive-destination", lambda: module._stage_verified(recursive_source, recursive_source / "nested", c["manifest_sha256"]), lambda error: isinstance(error, ValueError) and "source contains destination" in str(error))
    assert not (recursive_source / "nested").exists()
    result["unrelated_canary"] = original_canary
    result["primary_error"] = None
except BaseException as error:
    result["primary_error"] = {"stage": stage, "type": type(error).__name__, "traceback": traceback.format_exc()}
finally:
    for path, expected in reversed(owned):
        try:
            assert snapshot(path) == expected
            assert shutil.rmtree.avoids_symlink_attacks
            shutil.rmtree(path)
            assert not os.path.lexists(path)
            result["cleanup"].append({"identity": expected, "absent": True})
        except BaseException as error:
            result["cleanup_errors"].append({"type": type(error).__name__, "traceback": traceback.format_exc()})
result["status"] = "passed" if result["primary_error"] is None and not result["cleanup_errors"] and len(result["cleanup"]) == 2 else "failed"
print(json.dumps(result, sort_keys=True))
"""


def fixture_files() -> tuple[dict[str, bytes], str]:
    wheel = b"public synthetic offline artifact"
    lock = ("fixture==1.0 --hash=sha256:" + hashlib.sha256(wheel).hexdigest() + "\n").encode()
    files = {"wheels/fixture.whl": wheel, "locks/fixture.txt": lock}
    manifest = {
        "format": "fishhat-scaffold-bundle/v1",
        "production_qualified": False,
        "profile": {"platform": "linux", "machine": "x86_64", "python": "3.12"},
        "components": {
            "fixture": {
                "distribution": "fixture",
                "lock": "locks/fixture.txt",
                "dependencies": ["fixture"],
            }
        },
        "files": {
            name: {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for name, raw in files.items()
        },
    }
    files["manifest.json"] = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    expected = hashlib.sha256(files["manifest.json"]).hexdigest()
    files["SHA256SUMS"] = "".join(
        hashlib.sha256(files[name]).hexdigest() + "  " + name + "\n" for name in sorted(files)
    ).encode()
    return files, expected


def _metadata(row: dict[str, Any], uid: int, gid: int, mode: int, kind: str) -> None:
    for key in ("device", "inode", "uid", "gid", "mode"):
        if type(row[key]) is not int or row[key] < (1 if key == "inode" else 0):
            raise GuestBootError("protected-input-invalid-metadata")
    if (row["uid"], row["gid"], row["mode"], row["kind"]) != (uid, gid, mode, kind):
        raise GuestBootError("protected-input-metadata-mismatch")


def _inventory(
    value: dict[str, Any], files: dict[str, bytes], directories: set[str], uid: int, gid: int
) -> None:
    if (
        set(value) != {"files", "directories"}
        or set(value["files"]) != set(files)
        or set(value["directories"]) != directories
    ):
        raise GuestBootError("protected-input-inventory-mismatch")
    identities = set()
    for name, row in value["files"].items():
        if set(row) != {"device", "inode", "uid", "gid", "mode", "kind", "bytes", "sha256"}:
            raise GuestBootError("protected-input-invalid-file-metadata")
        _metadata(row, uid, gid, 0o600, "regular")
        if (
            type(row["bytes"]) is not int
            or row["bytes"] != len(files[name])
            or row["sha256"] != hashlib.sha256(files[name]).hexdigest()
        ):
            raise GuestBootError("protected-input-byte-mismatch")
        identities.add((row["device"], row["inode"]))
    for row in value["directories"].values():
        if set(row) != {"device", "inode", "uid", "gid", "mode", "kind"}:
            raise GuestBootError("protected-input-invalid-directory-metadata")
        _metadata(row, uid, gid, 0o700, "directory")
        identities.add((row["device"], row["inode"]))
    if len(identities) != len(files) + len(directories):
        raise GuestBootError("protected-input-aliased-inventory")


def _peer_observation(value: dict[str, Any], uid: int, gid: int) -> None:
    peer = value["peer"]
    if set(peer) != {
        "pid",
        "parent_pid",
        "uids",
        "gids",
        "groups",
        "effective_capabilities",
        "denied",
        "administrative_refusal",
    }:
        raise GuestBootError("protected-input-peer-shape-mismatch")
    if (
        peer["uids"] != [uid] * 3
        or peer["gids"] != [gid] * 3
        or peer["groups"] != []
        or int(peer["effective_capabilities"], 16) != 0
    ):
        raise GuestBootError("protected-input-peer-credential-mismatch")
    if any(
        type(v) is not int for v in [*peer["uids"], *peer["gids"], peer["pid"], peer["parent_pid"]]
    ):
        raise GuestBootError("protected-input-invalid-peer-identities")
    if (
        peer["pid"] != value["peer_pid"]
        or peer["parent_pid"] != value["observer_pid"]
        or peer["administrative_refusal"] is not True
    ):
        raise GuestBootError("protected-input-peer-process-mismatch")
    if [row["operation"] for row in peer["denied"]] != ["write", "unlink"] or any(
        type(row["errno"]) is not int or row["errno"] not in (1, 13) for row in peer["denied"]
    ):
        raise GuestBootError("protected-input-peer-mutation-allowed")


def _rejection_observations(value: dict[str, Any], uid: int, gid: int) -> None:
    if tuple(row["case"] for row in value["rejections"]) != REJECTIONS:
        raise GuestBootError("protected-input-rejection-set-mismatch")
    for row in value["rejections"]:
        case = row["case"]
        expected = (
            ({"NotADirectoryError", "OSError"}, {20, 40})
            if case in ("source-root-symlink", "symlink-ancestor")
            else ({"FileExistsError"}, {17})
            if case.startswith("existing-")
            else ({"ValueError"}, {None})
        )
        if (
            set(row) != {"case", "error", "errno"}
            or row["error"] not in expected[0]
            or row["errno"] not in expected[1]
        ):
            raise GuestBootError("protected-input-rejection-kind-mismatch")
    ancestors = value["ancestor_observations"]
    if [row["case"] for row in ancestors] != [
        "foreign-ancestor",
        "writable-ancestor",
        "symlink-ancestor",
    ]:
        raise GuestBootError("protected-input-ancestor-witness-missing")
    for row, ancestor_fields in zip(
        ancestors,
        ((uid, gid, 0o700, "directory"), (0, 0, 0o770, "directory"), (0, 0, 0o777, "other")),
        strict=True,
    ):
        _metadata(row["ancestor"], *ancestor_fields)
        _metadata(row["leaf_parent"], 0, 0, 0o700, "directory")


def _existing_inputs(value: dict[str, Any]) -> None:
    existing = value["preserved_existing"]
    if [row["case"] for row in existing] != [
        "existing-directory",
        "existing-file",
        "existing-symlink",
    ]:
        raise GuestBootError("protected-input-existing-witness-missing")
    for row in existing:
        if row["before"] != row["after"]:
            raise GuestBootError("protected-input-existing-state-changed")
        kind = row["case"].removeprefix("existing-")
        mode, node_kind = {
            "directory": (0o700, "directory"),
            "file": (0o600, "regular"),
            "symlink": (0o777, "other"),
        }[kind]
        _metadata(row["before"]["node"], 0, 0, mode, node_kind)
        _inventory(
            row["before"]["content"],
            {"." if kind == "file" else "keep": b"retained existing input"},
            set() if kind == "file" else {"."},
            0,
            0,
        )


def validate_observation(value: dict[str, Any], configuration: dict[str, Any]) -> None:
    if (
        value.get("scope") != SCOPE
        or value.get("status") != "passed"
        or value.get("native_product_qualified") is not False
    ):
        raise GuestBootError("protected-input-observation-failed")
    required = {
        "scope",
        "status",
        "native_product_qualified",
        "enrollment",
        "boot_id",
        "bootstrap_sha256",
        "manifest_sha256",
        "observer_uid",
        "observer_pid",
        "primary_error",
        "cleanup_errors",
        "cleanup",
        "source_before",
        "source_after",
        "before",
        "after",
        "peer_pid",
        "peer",
        "rejections",
        "unrelated_canary",
        "ancestor_observations",
        "preserved_existing",
    }
    if set(value) != required:
        raise GuestBootError("protected-input-incomplete-observation")
    for name in ("enrollment", "boot_id", "bootstrap_sha256", "manifest_sha256"):
        if value[name] != configuration[name]:
            raise GuestBootError("protected-input-identity-mismatch")
    if (
        type(value["observer_uid"]) is not int
        or value["observer_uid"] != 0
        or value["primary_error"] is not None
        or value["cleanup_errors"] != []
    ):
        raise GuestBootError("protected-input-incomplete-observation")
    for key in ("observer_pid", "peer_pid"):
        if type(value[key]) is not int or value[key] <= 1:
            raise GuestBootError("protected-input-invalid-process")
    if value["observer_pid"] == value["peer_pid"] or value["before"] != value["after"]:
        raise GuestBootError("protected-input-custody-changed")
    files = {name: base64.b64decode(raw) for name, raw in configuration["files"].items()}
    directories = {".", "wheels", "locks"}
    _inventory(value["before"], files, directories, 0, 0)
    uid, gid = configuration["peer_uid"], configuration["peer_gid"]
    _inventory(value["source_before"], files, directories, uid, gid)
    changed = {
        **files,
        "locks/fixture.txt": b"caller replacement",
        "wheels/fixture.whl": b"caller replacement",
    }
    _inventory(value["source_after"], changed, directories, uid, gid)
    for name in files:
        original = value["source_before"]["files"][name]
        after = value["source_after"]["files"][name]
        staged = value["before"]["files"][name]
        if (original["device"], original["inode"]) == (staged["device"], staged["inode"]):
            raise GuestBootError("protected-input-shares-caller-inode")
        if {k: v for k, v in original.items() if k not in ("bytes", "sha256")} != {
            k: v for k, v in after.items() if k not in ("bytes", "sha256")
        }:
            raise GuestBootError("protected-input-caller-object-changed")
    _peer_observation(value, uid, gid)
    _rejection_observations(value, uid, gid)
    _existing_inputs(value)
    canary = value["unrelated_canary"]
    _metadata(canary, 0, 0, 0o600, "regular")
    if canary["sha256"] != hashlib.sha256(b"unrelated retained fixture input").hexdigest():
        raise GuestBootError("protected-input-unrelated-canary-mismatch")
    cleanup = value["cleanup"]
    if len(cleanup) != 2 or any(row["absent"] is not True for row in cleanup):
        raise GuestBootError("protected-input-cleanup-unproved")
    _metadata(cleanup[0]["identity"], uid, gid, 0o700, "directory")
    _metadata(cleanup[1]["identity"], 0, 0, 0o700, "directory")


def qualify_inputs(guest: Guest, report: dict[str, Any]) -> None:
    metrics = RunStats()
    report.update(status="failed", scope=SCOPE, native_product_qualified=False)
    try:
        if guest.observed is None:
            raise GuestBootError("guest-not-verified")
        bootstrap = Path(__file__).with_name("bundle_install.py").read_bytes()
        files, expected = fixture_files()
        principal = guest.observed["accounts"][guest.accounts[1]]
        configuration = {
            "enrollment": guest.enrollment,
            "boot_id": guest.observed["boot_id"],
            "bootstrap": base64.b64encode(bootstrap).decode(),
            "bootstrap_sha256": hashlib.sha256(bootstrap).hexdigest(),
            "manifest_sha256": expected,
            "files": {name: base64.b64encode(raw).decode() for name, raw in files.items()},
            "peer_uid": principal["uid"],
            "peer_gid": principal["gid"],
            "peer_program": PEER,
            "child_timeout_seconds": watchdog(15),
        }
        raw = guest.guarded(
            ["/usr/bin/python3", "-I", "-S", "-B", "-c", REMOTE, json.dumps(configuration)],
            guest.enrollment,
            guest.observed["boot_id"],
            deadline=Deadline.after(60),
            nominal=60,
        )
        report["original_reply"] = raw
        value = json.loads(raw)
        validate_observation(value, configuration)
        report.update(
            status="passed",
            observation=value,
            bootstrap_sha256=configuration["bootstrap_sha256"],
            manifest_sha256=expected,
            actual_peer_credentials_verified=True,
            complete_inputs_preserved=True,
            cleanup_verified=True,
        )
    except (KeyError, TypeError, ValueError):
        raise GuestBootError("invalid-protected-input-observation") from None
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            raise ValueError("invalid required protected input statistics")
