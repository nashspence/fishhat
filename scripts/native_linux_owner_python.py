"""Witness the selected runtime only in an authenticated enrolled Linux guest."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import tempfile
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from scripts.bundle_install import OWNER_PYTHON_BYTES, OWNER_PYTHON_SHA256, OWNER_PYTHON_URL
from scripts.native_linux_guest import Guest, GuestBootError
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import watchdog

SCOPE = "disposable-guest-selected-owner-python-installation-only"
SQLITE_SOURCE = (
    "2026-05-05 10:34:17 c88b22011a54b4f6fbd149e9f8e4de77658ce58143a1af0e3785e4e6475127e9"
)

OBSERVE = r"""
import _sqlite3, errno, hashlib, json, os, pathlib, sqlite3, sys
c = json.loads(sys.argv[1])
root = pathlib.Path(c["runtime"])
def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
libraries = {}
for line in pathlib.Path("/proc/self/maps").read_text().splitlines():
    columns = line.split(None, 5)
    if len(columns) == 6 and columns[5].startswith("/"):
        path = pathlib.Path(columns[5])
        if str(path) not in libraries:
            libraries[str(path)] = digest(path)
with sqlite3.connect(":memory:") as database:
    source_id = database.execute("select sqlite_source_id()").fetchone()[0]
result = {"pid": os.getpid(), "parent_pid": os.getppid(),
          "uids": list(os.getresuid()), "gids": list(os.getresgid()), "groups": os.getgroups(),
          "capabilities": next(line.split(":", 1)[1].strip() for line in pathlib.Path("/proc/self/status").read_text().splitlines() if line.startswith("CapEff:")),
          "executable": sys.executable, "prefix": sys.prefix, "base_prefix": sys.base_prefix,
          "version": list(sys.version_info[:3]), "search_paths": sys.path,
          "sqlite_version": sqlite3.sqlite_version, "sqlite_source_id": source_id,
          "sqlite_extension": _sqlite3.__file__, "mapped_files": libraries,
          "flags": {name: getattr(sys.flags, name) for name in ("isolated", "ignore_environment", "no_site", "no_user_site", "safe_path", "dont_write_bytecode")},
          "denied": []}
if c["peer"]:
    for role, path in [("executable", pathlib.Path(sys.executable)), ("stdlib", root / "lib/python3.12/os.py"), ("interrupted", pathlib.Path(c["interrupted"]) / "runtime.tar.gz")]:
        for operation in ("write", "unlink"):
            try:
                if operation == "write":
                    descriptor = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
                    os.close(descriptor)
                else:
                    path.unlink()
            except OSError as error:
                assert error.errno in (errno.EACCES, errno.EPERM)
                result["denied"].append({"role": role, "operation": operation, "errno": error.errno})
            else:
                raise AssertionError("peer changed protected runtime")
print(json.dumps(result, sort_keys=True))
"""

INTERRUPTED = r"""
import base64, json, os, pathlib, sys, tarfile, types
c = json.loads(sys.argv[1])
module = types.ModuleType("approved_interrupted_runtime_installer")
exec(compile(base64.b64decode(c["bootstrap"]), "<approved-bootstrap>", "exec"), module.__dict__)
def pause_before_extract(*args, **kwargs):
    path = pathlib.Path(c["ready"])
    with path.open("x") as stream:
        os.chmod(path, 0o600)
        json.dump({"pid": os.getpid(), "parent_pid": os.getppid(), "uid": os.geteuid(), "boot_id": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    assert sys.stdin.buffer.read(1) == b"never release"
    raise AssertionError("interrupted candidate resumed")
tarfile.open = pause_before_extract
module._install_owner_python(pathlib.Path(c["archive"]), pathlib.Path(c["interrupted"]))
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
def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
def walk_error(error):
    raise error
def inventory(root):
    rows = {".": metadata(root)}
    for directory, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in directories + files:
            path = pathlib.Path(directory) / name
            row = metadata(path)
            if row["kind"] == "link":
                row["target"] = os.readlink(path)
            elif row["kind"] == "regular":
                row.update(bytes=path.stat().st_size, sha256=digest(path))
            rows[path.relative_to(root).as_posix()] = row
    return rows
def command(argv, **kwargs):
    global child
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             close_fds=True, **kwargs)
    try:
        output, errors = child.communicate(timeout=c["child_timeout"])
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        raise AssertionError("runtime child timeout")
    assert child.returncode == 0, errors.decode(errors="replace")
    pid = child.pid
    child = None
    return pid, output
try:
    assert os.geteuid() == os.getegid() == 0
    assert pathlib.Path("/etc/fishhat-fixture-enrollment").read_text().strip() == c["enrollment"]
    assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == c["boot_id"]
    raw = base64.b64decode(c["bootstrap"])
    assert hashlib.sha256(raw).hexdigest() == c["bootstrap_sha256"]
    module = types.ModuleType("approved_runtime_installer")
    exec(compile(raw, "<approved-bootstrap>", "exec"), module.__dict__)
    prefix = pathlib.Path("/var/lib") / ("fishhat-python-fixture-" + c["enrollment"])
    poison = pathlib.Path("/tmp") / ("fishhat-python-fixture-" + c["enrollment"])
    for path, mode in ((prefix, 0o755), (poison, 0o700)):
        path.mkdir(mode=mode)
        owned.append((path, metadata(path)))
    archive = prefix / "input.tar.gz"
    stage = "archive-transfer"
    count = 0
    checksum = hashlib.sha256()
    with archive.open("xb") as stream:
        os.chmod(archive, 0o600)
        while chunk := sys.stdin.buffer.read(1_048_576):
            count += len(chunk)
            assert count <= c["archive_bytes"]
            checksum.update(chunk)
            stream.write(chunk)
        stream.flush()
        os.fsync(stream.fileno())
    assert count == c["archive_bytes"] and checksum.hexdigest() == c["archive_sha256"]
    result["input"] = {**metadata(archive), "bytes": count, "sha256": checksum.hexdigest()}
    clean = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    interrupted = prefix / "interrupted"
    ready = prefix / "interrupted-ready.json"
    interrupt_config = {**c, "archive": str(archive), "interrupted": str(interrupted), "ready": str(ready)}
    stage = "interrupt-before-extraction"
    child = subprocess.Popen(["/usr/bin/python3", "-I", "-S", "-B", "-c", c["interrupt_program"], json.dumps(interrupt_config)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd="/", env=clean, close_fds=True)
    deadline = time.monotonic() + c["child_timeout"]
    while not ready.exists():
        assert child.poll() is None, "interrupted installer exited before gate"
        assert time.monotonic() < deadline, "interrupted installer gate timeout"
        time.sleep(0.05)
    original_child = json.loads(ready.read_text())
    assert original_child == {"pid": child.pid, "parent_pid": os.getpid(), "uid": 0, "boot_id": c["boot_id"]}
    child.kill()
    child.communicate(timeout=c["child_timeout"])
    assert child.returncode == -signal.SIGKILL
    result["interruption"] = {**original_child, "returncode": child.returncode, "joined": True,
                              "destination": metadata(interrupted), "retained_sha256": digest(interrupted / "runtime.tar.gz"),
                              "runtime_absent": not (interrupted / "python").exists()}
    child = None
    result["rejections"] = []
    def reject(name, source, destination):
        try:
            module._install_owner_python(source, destination)
        except (OSError, ValueError) as error:
            result["rejections"].append({"case": name, "error": type(error).__name__, "errno": getattr(error, "errno", None)})
        else:
            raise AssertionError("runtime refusal missing: " + name)
    reject("interrupted-destination", archive, interrupted)
    alias = prefix / "archive-alias"
    alias.symlink_to(archive)
    reject("source-symlink", alias, prefix / "bad-link")
    short = prefix / "short.tar.gz"
    short.write_bytes(b"truncated archive")
    reject("truncated-archive", short, prefix / "bad-short")
    stage = "fresh-installation"
    installed = prefix / "installed"
    executable = module._install_owner_python(archive, installed)
    result["before"] = inventory(installed)
    result["installed_executable"] = str(executable)
    runtime = installed / "python"
    os.chown(poison, c["peer_uid"], c["peer_gid"])
    for name in ("sitecustomize.py", "usercustomize.py", "sqlite3.py", "hashlib.py", "startup.py"):
        path = poison / name
        path.write_text("raise SystemExit('poisoned runtime startup')\n")
        os.chown(path, c["peer_uid"], c["peer_gid"])
        os.chmod(path, 0o600)
    fake = poison / "python3.12"
    fake.write_text("#!/bin/sh\nexit 91\n")
    os.chown(fake, c["peer_uid"], c["peer_gid"])
    os.chmod(fake, 0o700)
    poison_environment = {**clean, "PATH": str(poison), "HOME": str(poison), "PYTHONHOME": str(poison),
                          "PYTHONPATH": str(poison), "PYTHONUSERBASE": str(poison), "PYTHONSTARTUP": str(poison / "startup.py")}
    stage = "independent-installed-invocations"
    for role, peer in (("administrative", False), ("peer", True)):
        config = {"runtime": str(runtime), "interrupted": str(interrupted), "peer": peer}
        credentials = {"user": c["peer_uid"], "group": c["peer_gid"], "extra_groups": []} if peer else {}
        pid, output = command([str(executable), "-I", "-S", "-B", "-c", c["observe_program"], json.dumps(config)],
                              cwd=str(poison) if peer else "/", env=poison_environment if peer else clean, **credentials)
        result[role] = json.loads(output)
        assert result[role]["pid"] == pid and result[role]["parent_pid"] == os.getpid()
    result["after"] = inventory(installed)
    assert result["before"] == result["after"]
    stage = "changed-input-and-existing-installation"
    with archive.open("r+b") as stream:
        stream.write(b"caller replacement")
    reject("changed-archive", archive, prefix / "bad-digest")
    reject("existing-installation", archive, installed)
    assert result["before"] == inventory(installed)
    result["input_after_sha256"] = digest(archive)
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


def _verify_custody(value: dict[str, Any], enrollment: str) -> None:
    if value["input"]["bytes"] != OWNER_PYTHON_BYTES or (
        value["input"]["sha256"] != OWNER_PYTHON_SHA256
        or value["input_after_sha256"] == OWNER_PYTHON_SHA256
        or value["input"]["mode"] != 0o600
        or value["input"]["uid"] != 0
        or value["input"]["kind"] != "regular"
        or value["before"] != value["after"]
    ):
        raise GuestBootError("owner-python-custody-changed")
    for name, row in value["before"].items():
        path = Path(name)
        if path.is_absolute() or ".." in path.parts:
            raise GuestBootError("owner-python-unsafe-inventory-path")
        if any(
            type(row[key]) is not int or row[key] < 0
            for key in ("device", "inode", "uid", "gid", "mode")
        ):
            raise GuestBootError("owner-python-invalid-inventory-metadata")
        if row["uid"] != 0 or row["gid"] != 0 or row["inode"] == 0:
            raise GuestBootError("owner-python-foreign-inventory")
        kind = row["kind"]
        if kind == "link":
            if row["mode"] != 0o777 or not isinstance(row["target"], str):
                raise GuestBootError("owner-python-invalid-alias")
        elif kind == "directory":
            if row["mode"] != 0o555:
                raise GuestBootError("owner-python-unsealed-directory")
        elif kind == "regular":
            if row["mode"] not in (0o400, 0o444, 0o555) or (
                type(row["bytes"]) is not int
                or row["bytes"] < 0
                or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None
            ):
                raise GuestBootError("owner-python-unsealed-file")
        else:
            raise GuestBootError("owner-python-special-member")
    retained = value["before"]["runtime.tar.gz"]
    if (retained["bytes"], retained["sha256"], retained["mode"]) != (
        OWNER_PYTHON_BYTES,
        OWNER_PYTHON_SHA256,
        0o400,
    ):
        raise GuestBootError("owner-python-retained-archive-mismatch")
    expected_cleanup = [
        "/tmp/fishhat-python-fixture-" + enrollment,
        "/var/lib/fishhat-python-fixture-" + enrollment,
    ]
    if [row["path"] for row in value["cleanup"]] != expected_cleanup or not all(
        row["absent"] is True for row in value["cleanup"]
    ):
        raise GuestBootError("owner-python-cleanup-mismatch")


def _verify_processes(value: dict[str, Any]) -> None:
    observer = value["observer_pid"]
    children = [value[name] for name in ("administrative", "peer", "interruption")]
    if type(observer) is not int or observer <= 1:
        raise GuestBootError("owner-python-invalid-observer-process")
    for row in children:
        if type(row["pid"]) is not int or row["pid"] <= 1 or row["parent_pid"] != observer:
            raise GuestBootError("owner-python-child-process-mismatch")
    if len({observer, *(row["pid"] for row in children)}) != 4:
        raise GuestBootError("owner-python-aliased-processes")
    expected_denials = [
        (role, operation)
        for role in ("executable", "stdlib", "interrupted")
        for operation in ("write", "unlink")
    ]
    denied = value["peer"]["denied"]
    if [(row["role"], row["operation"]) for row in denied] != expected_denials or any(
        type(row["errno"]) is not int or row["errno"] not in (1, 13) for row in denied
    ):
        raise GuestBootError("owner-python-peer-mutation-allowed")
    if value["administrative"]["denied"] != []:
        raise GuestBootError("owner-python-administrative-observation-mismatch")
    expected_rejections = [
        ("interrupted-destination", "FileExistsError", 17),
        ("source-symlink", "ValueError", None),
        ("truncated-archive", "ValueError", None),
        ("changed-archive", "ValueError", None),
        ("existing-installation", "FileExistsError", 17),
    ]
    if [
        (row["case"], row["error"], row["errno"]) for row in value["rejections"]
    ] != expected_rejections:
        raise GuestBootError("owner-python-refusals-missing")


def verify_observation(value: dict[str, Any], guest: Guest, bootstrap: str) -> None:
    identity = guest.observed
    if identity is None or (
        value.get("scope") != SCOPE
        or value.get("status") != "passed"
        or value.get("native_product_qualified") is not False
        or value.get("enrollment") != guest.enrollment
        or value.get("boot_id") != identity["boot_id"]
        or value.get("bootstrap_sha256") != bootstrap
        or value.get("observer_uid") != 0
        or value.get("primary_error") is not None
        or value.get("cleanup_errors") != []
    ):
        raise GuestBootError("owner-python-incomplete-observation")
    expected_prefix = "/var/lib/fishhat-python-fixture-" + guest.enrollment + "/installed/python"
    peer = identity["accounts"][guest.accounts[1]]
    _verify_custody(value, guest.enrollment)
    _verify_processes(value)
    for role, uid, gid in (("administrative", 0, 0), ("peer", peer["uid"], peer["gid"])):
        row = value[role]
        if (
            row["uids"] != [uid] * 3
            or row["gids"] != [gid] * 3
            or row["version"] != [3, 12, 16]
            or row["prefix"] != expected_prefix
            or row["base_prefix"] != expected_prefix
            or row["executable"] != expected_prefix + "/bin/python3.12"
            or row["sqlite_version"] != "3.53.1"
            or row["sqlite_source_id"] != SQLITE_SOURCE
            or not all(row["flags"].values())
            or not all(Path(path).is_relative_to(expected_prefix) for path in row["search_paths"])
            or not Path(row["sqlite_extension"]).is_relative_to(expected_prefix)
        ):
            raise GuestBootError("owner-python-runtime-mismatch")
    if value["peer"]["groups"] != [] or int(value["peer"]["capabilities"], 16) != 0:
        raise GuestBootError("owner-python-peer-privileges")
    interruption = value["interruption"]
    if (
        interruption["returncode"] != -9
        or interruption["joined"] is not True
        or interruption["destination"]["mode"] != 0o700
        or interruption["destination"]["uid"] != 0
        or interruption["uid"] != 0
        or interruption["boot_id"] != identity["boot_id"]
        or interruption["retained_sha256"] != OWNER_PYTHON_SHA256
        or interruption["runtime_absent"] is not True
        or len(value["cleanup"]) != 2
        or not all(row["absent"] for row in value["cleanup"])
    ):
        raise GuestBootError("owner-python-interruption-or-cleanup-mismatch")


def qualify_python(
    guest: Guest,
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    report: dict[str, Any],
) -> None:
    if guest.observed is None:
        raise GuestBootError("guest-not-verified")
    metrics = RunStats()
    report.update(scope=SCOPE, status="failed", native_product_qualified=False)
    try:
        with tempfile.TemporaryDirectory(prefix="fh-python-", dir=temporary) as directory:
            archive = Path(directory) / "selected.tar.gz"
            with progress("guest-owner-python-input"):
                guest.command(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        str(Path(__file__).with_name("native_owner_python_download.py")),
                        str(archive),
                        OWNER_PYTHON_URL,
                        str(OWNER_PYTHON_BYTES),
                        OWNER_PYTHON_SHA256,
                        str(watchdog(30)),
                    ],
                    "owner-python-download",
                    180,
                )
            bootstrap = Path(__file__).with_name("bundle_install.py").read_bytes()
            bootstrap_hash = hashlib.sha256(bootstrap).hexdigest()
            peer = guest.observed["accounts"][guest.accounts[1]]
            config = {
                "scope": SCOPE,
                "enrollment": guest.enrollment,
                "boot_id": guest.observed["boot_id"],
                "bootstrap": base64.b64encode(bootstrap).decode(),
                "bootstrap_sha256": bootstrap_hash,
                "archive_bytes": OWNER_PYTHON_BYTES,
                "archive_sha256": OWNER_PYTHON_SHA256,
                "peer_uid": peer["uid"],
                "peer_gid": peer["gid"],
                "child_timeout": watchdog(120),
                "observe_program": OBSERVE,
                "interrupt_program": INTERRUPTED,
            }
            with progress("guest-owner-python-install"):
                raw = guest.guarded(
                    ["/usr/bin/python3", "-I", "-S", "-B", "-c", REMOTE, json.dumps(config)],
                    guest.enrollment,
                    guest.observed["boot_id"],
                    nominal=300,
                    input_path=archive,
                )
            report["original_reply_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
            try:
                value = json.loads(raw)
            except (ValueError, RecursionError):
                report["unparsed_original_reply"] = raw
                raise GuestBootError("owner-python-invalid-original-reply") from None
            report["original_observation"] = value
            try:
                verify_observation(value, guest, bootstrap_hash)
            except (KeyError, TypeError, ValueError, AttributeError):
                raise GuestBootError("owner-python-invalid-observation-shape") from None
            report["status"] = "passed"
    finally:
        report["qualification_statistics"] = metrics.finish()
        if not valid_stats(report["qualification_statistics"]):
            raise GuestBootError("owner-python-invalid-statistics")
