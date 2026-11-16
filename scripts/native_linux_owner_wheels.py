"""Observe approved wheel payloads only in the enrolled disposable Linux guest."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
import zipfile
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from scripts.bundle_install import OWNER_PYTHON_BYTES, OWNER_PYTHON_SHA256, OWNER_PYTHON_URL
from scripts.native_linux_guest import Guest, GuestBootError
from scripts.run_stats import RunStats, valid_stats
from scripts.validation import source_identity
from scripts.validation_timeouts import watchdog

SCOPE = "disposable-guest-protected-host-wheel-payloads-only"
DENIALS = ("code-write", "wheel-write", "create", "unlink", "rename", "chmod")
MODULES = {
    "alembic": "alembic",
    "attrs": "attrs",
    "cffi": "cffi",
    "cryptography": "cryptography",
    "fishhat-adapter-protocol": "fishhat_adapters",
    "fishhat-cli-support": "fishhat_cli",
    "fishhat-contracts": "fishhat_contracts",
    "fishhat-host": "fishhat_host",
    "fishhat-owner-support": "fishhat_owner",
    "jsonschema": "jsonschema",
    "jsonschema-specifications": "jsonschema_specifications",
    "mako": "mako",
    "markupsafe": "markupsafe",
    "pycparser": "pycparser",
    "pyyaml": "yaml",
    "referencing": "referencing",
    "rfc8785": "rfc8785",
    "rpds-py": "rpds",
    "sqlalchemy": "sqlalchemy",
    "typing-extensions": "typing_extensions",
}

OBSERVE = r"""
import base64, contextlib, hashlib, importlib, io, json, os, pathlib, sys, types
c = json.loads(sys.argv[1])
sys.path.insert(0, c["library"])
modules = {}
for distribution, name in c["modules"].items():
    module = importlib.import_module(name)
    path = pathlib.Path(module.__file__)
    assert path.is_relative_to(c["library"])
    modules[distribution] = {"module": name, "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
binary_names = ["_cffi_backend", "yaml._yaml", "markupsafe._speedups", "cryptography.hazmat.bindings._rust", "rpds.rpds"]
for path in (pathlib.Path(c["library"]) / "sqlalchemy").rglob("*.so"):
    relative = path.relative_to(c["library"])
    binary_names.append(".".join((*relative.parts[:-1], path.name.split(".")[0])))
binaries = {}
for name in binary_names:
    module = importlib.import_module(name)
    path = pathlib.Path(module.__file__)
    assert path.is_relative_to(c["library"]) and path.suffix == ".so"
    binaries[name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
from fishhat_host.cli import main
sys.argv = ["host-ops", "info", "--json"]
output = io.StringIO()
with contextlib.redirect_stdout(output):
    status = main()
info = json.loads(output.getvalue())
assert status == 0 and info["native_mutations"] is info["production_qualified"] is False
assert not pathlib.Path(c["marker"]).exists()
denied = []
administrative_refusal = False
if c["peer"]:
    root = pathlib.Path(c["installed"])
    operations = {
        "code-write": lambda: pathlib.Path(modules["fishhat-host"]["path"]).write_bytes(b"peer mutation"),
        "wheel-write": lambda: next((root / "wheels").iterdir()).write_bytes(b"peer mutation"),
        "create": lambda: (root / "lib/peer-created").touch(exist_ok=False),
        "unlink": lambda: pathlib.Path(modules["fishhat-host"]["path"]).unlink(),
        "rename": lambda: root.rename(root.with_name("peer-renamed")),
        "chmod": lambda: root.chmod(0o777),
    }
    for name, action in operations.items():
        try:
            action()
        except OSError as error:
            assert error.errno in (1, 13)
            denied.append({"operation": name, "errno": error.errno})
        else:
            raise AssertionError("peer changed protected code")
    bootstrap = types.ModuleType("approved_wheel_installer")
    exec(compile(base64.b64decode(c["bootstrap"]), "<approved-bootstrap>", "exec"), bootstrap.__dict__)
    unavailable = pathlib.Path(c["poison"]) / "unavailable"
    try:
        bootstrap._install_owner_wheels(pathlib.Path(c["bundle"]), unavailable, c["manifest_sha256"])
    except ValueError as error:
        assert "administrative custody" in str(error)
        administrative_refusal = True
    else:
        raise AssertionError("peer installed administrative code")
    assert not unavailable.exists()
print(json.dumps({"pid": os.getpid(), "parent_pid": os.getppid(), "uids": list(os.getresuid()),
    "gids": list(os.getresgid()), "groups": os.getgroups(),
    "capabilities": next(line.split(":", 1)[1].strip() for line in pathlib.Path("/proc/self/status").read_text().splitlines() if line.startswith("CapEff:")),
    "executable": sys.executable, "version": list(sys.version_info[:3]), "cwd": os.getcwd(),
    "isolated": sys.flags.isolated, "no_site": sys.flags.no_site, "no_bytecode": sys.flags.dont_write_bytecode,
    "sys_path": sys.path, "modules": modules, "binaries": binaries, "cli_status": status, "cli_info": info,
    "poison_marker_absent": not pathlib.Path(c["marker"]).exists(), "denied": denied,
    "administrative_refusal": administrative_refusal}, sort_keys=True))
"""

INTERRUPTED = r"""
import base64, json, os, pathlib, sys, types
c = json.loads(sys.argv[1])
module = types.ModuleType("approved_interrupted_wheel_installer")
exec(compile(base64.b64decode(c["bootstrap"]), "<approved-bootstrap>", "exec"), module.__dict__)
original = module._unpack_owner_wheel
def pause(*args):
    original(*args)
    ready = pathlib.Path(c["ready"])
    pending = ready.with_suffix(".pending")
    with pending.open("x") as stream:
        os.chmod(pending, 0o600)
        json.dump({"pid": os.getpid(), "parent_pid": os.getppid(), "uid": os.geteuid(),
                   "boot_id": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, ready)
    assert sys.stdin.buffer.read(1) == b"never release"
    raise AssertionError("interrupted installation resumed")
module._unpack_owner_wheel = pause
module._install_owner_wheels(pathlib.Path(c["bundle"]), pathlib.Path(c["interrupted"]), c["manifest_sha256"])
"""

REMOTE = r"""
import base64, hashlib, json, os, pathlib, shutil, signal, stat, subprocess, sys, time, types, zipfile
c = json.loads(sys.argv[1])
result = {"scope": c["scope"], "status": "failed", "native_product_qualified": False,
    "enrollment": c["enrollment"], "boot_id": c["boot_id"], "bootstrap_sha256": c["bootstrap_sha256"],
    "input_sha256": c["input_sha256"], "manifest_sha256": c["manifest_sha256"],
    "observer_pid": os.getpid(), "observer_uid": os.geteuid(), "primary_error": None, "cleanup_errors": [], "cleanup": []}
owned = []
child = None
stage = "admission"
def metadata(path):
    value = path.lstat()
    return {"device": value.st_dev, "inode": value.st_ino, "uid": value.st_uid, "gid": value.st_gid,
            "mode": stat.S_IMODE(value.st_mode), "kind": "link" if stat.S_ISLNK(value.st_mode) else "directory" if stat.S_ISDIR(value.st_mode) else "regular" if stat.S_ISREG(value.st_mode) else "other"}
def inventory(root):
    result = {".": metadata(root)}
    for directory, names, files in os.walk(root):
        for name in names + files:
            path = pathlib.Path(directory) / name
            row = metadata(path)
            assert row["kind"] in ("regular", "directory")
            if row["kind"] == "regular":
                data = path.read_bytes()
                row.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            result[path.relative_to(root).as_posix()] = row
    return result
def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
try:
    assert os.geteuid() == os.getegid() == 0
    assert pathlib.Path("/etc/fishhat-fixture-enrollment").read_text().strip() == c["enrollment"]
    assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == c["boot_id"]
    raw = base64.b64decode(c["bootstrap"])
    assert hashlib.sha256(raw).hexdigest() == c["bootstrap_sha256"]
    module = types.ModuleType("approved_wheel_installer")
    exec(compile(raw, "<approved-bootstrap>", "exec"), module.__dict__)
    prefix = pathlib.Path("/var/lib") / ("fishhat-wheels-fixture-" + c["enrollment"])
    poison = pathlib.Path("/tmp") / ("fishhat-wheels-fixture-" + c["enrollment"])
    for path, mode in ((prefix, 0o755), (poison, 0o700)):
        path.mkdir(mode=mode)
        owned.append((path, metadata(path)))
    os.chown(poison, c["peer_uid"], c["peer_gid"])
    source = prefix / "inputs.zip"
    with source.open("xb") as output:
        while block := sys.stdin.buffer.read(1048576):
            output.write(block)
        output.flush()
        os.fsync(output.fileno())
    assert source.stat().st_size == c["input_bytes"] and digest(source) == c["input_sha256"]
    input_root = prefix / "inputs"
    input_root.mkdir(mode=0o700)
    with zipfile.ZipFile(source) as archive:
        assert {m.filename for m in archive.infolist()} == set(c["input_members"])
        assert len(archive.infolist()) == len(c["input_members"])
        for member in archive.infolist():
            parts = module._member_parts(member.filename)
            assert "/".join(parts) == member.filename and not member.is_dir()
            assert stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG)
            target = input_root / member.filename
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with archive.open(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, 1048576)
            assert digest(target) == c["input_members"][member.filename]
    bundle = input_root / "bundle"
    bundle.mkdir(mode=0o700)
    with zipfile.ZipFile(input_root / "bundle.zip") as archive:
        seen = set()
        for member in archive.infolist():
            parts = module._member_parts(member.filename)
            assert "/".join(parts) == member.filename and not member.is_dir()
            assert member.filename not in seen and stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG)
            seen.add(member.filename)
            target = bundle / member.filename
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with archive.open(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, 1048576)
    source = input_root / "runtime.tar.gz"
    assert source.stat().st_size == c["runtime_bytes"] and digest(source) == c["runtime_sha256"]
    stage = "selected-runtime"
    executable = module._install_owner_python(source, prefix / "runtime")
    result["runtime"] = {"path": str(executable), "sha256": digest(executable), "archive_sha256": digest(prefix / "runtime/runtime.tar.gz")}
    bundle = input_root / "bundle"
    result["manifest"] = json.loads((bundle / "manifest.json").read_bytes())
    stage = "interrupted-payload"
    interrupted = prefix / "interrupted"
    ready = prefix / "ready.json"
    config = {**c, "bundle": str(bundle), "interrupted": str(interrupted), "ready": str(ready)}
    clean = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    child = subprocess.Popen(["/usr/bin/python3", "-I", "-S", "-B", "-c", c["interrupt_program"], json.dumps(config)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/", env=clean, close_fds=True)
    deadline = time.monotonic() + c["child_timeout"]
    while not ready.exists():
        assert child.poll() is None and time.monotonic() < deadline, "interrupted installation gate unavailable"
        time.sleep(0.05)
    witness = json.loads(ready.read_text())
    assert witness == {"pid": child.pid, "parent_pid": os.getpid(), "uid": 0, "boot_id": c["boot_id"]}
    child.kill()
    child.communicate(timeout=c["child_timeout"])
    assert child.returncode == -signal.SIGKILL
    result["interruption"] = {**witness, "returncode": child.returncode, "joined": True, "inventory": inventory(interrupted)}
    assert result["interruption"]["inventory"]["."]["mode"] == 0o700
    child = None
    result["rejections"] = []
    def reject(name, target):
        try:
            module._install_owner_wheels(bundle, target, c["manifest_sha256"])
        except (OSError, ValueError) as error:
            result["rejections"].append({"case": name, "error": type(error).__name__, "errno": getattr(error, "errno", None)})
        else:
            raise AssertionError("existing wheel installation was adopted")
    reject("interrupted-destination", interrupted)
    assert inventory(interrupted) == result["interruption"]["inventory"]
    stage = "fresh-installation"
    installed = prefix / "installed"
    library = module._install_owner_wheels(bundle, installed, c["manifest_sha256"])
    result["before"] = inventory(installed)
    reject("existing-directory", installed)
    existing = prefix / "existing-file"
    existing.write_bytes(b"unrelated existing bytes")
    existing.chmod(0o600)
    alias = prefix / "existing-alias"
    alias.symlink_to(installed, target_is_directory=True)
    result["existing_before"] = {"file": {**metadata(existing), "sha256": digest(existing)}, "alias": {**metadata(alias), "target": str(installed)}}
    reject("existing-file", existing)
    reject("existing-symlink", alias)
    marker = poison / "executed"
    for name in ("sitecustomize.py", "usercustomize.py", "fishhat_host.py"):
        (poison / name).write_text("import pathlib; pathlib.Path(" + repr(str(marker)) + ").touch(); raise RuntimeError('unapproved source')")
    (poison / "python3.12").write_text("#!/bin/sh\nexit 89\n")
    (poison / "python3.12").chmod(0o755)
    environment = {**clean, "PATH": str(poison), "HOME": str(poison), "PYTHONPATH": str(poison),
        "PYTHONHOME": str(poison), "PYTHONSTARTUP": str(poison / "sitecustomize.py"), "PYTHONINSPECT": "1"}
    observe = {"library": str(library), "installed": str(installed), "poison": str(poison), "marker": str(marker),
        "modules": c["modules"], "bootstrap": c["bootstrap"], "bundle": str(bundle), "manifest_sha256": c["manifest_sha256"]}
    for role in ("root", "peer"):
        stage = role + "-isolated-import"
        arguments = [str(executable), "-I", "-S", "-B", "-c", c["observe_program"], json.dumps({**observe, "peer": role == "peer"})]
        credentials = {"user": c["peer_uid"], "group": c["peer_gid"], "extra_groups": []} if role == "peer" else {}
        child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, cwd=poison, close_fds=True, **credentials)
        stdout, stderr = child.communicate(timeout=c["child_timeout"])
        assert child.returncode == 0, "isolated package invocation failed"
        result[role + "_pid"] = child.pid
        result[role] = json.loads(stdout)
        assert result[role]["pid"] == child.pid and result[role]["parent_pid"] == os.getpid()
        child = None
    result["after"] = inventory(installed)
    result["interrupted_final"] = inventory(interrupted)
    result["existing_after"] = {"file": {**metadata(existing), "sha256": digest(existing)}, "alias": {**metadata(alias), "target": str(installed)}}
    assert result["before"] == result["after"] and result["existing_before"] == result["existing_after"]
    assert result["interrupted_final"] == result["interruption"]["inventory"] and not marker.exists()
    result["status"] = "passed"
except BaseException as error:
    result["primary_error"] = {"stage": stage, "type": type(error).__name__}
finally:
    if child is not None:
        try:
            if child.poll() is None: child.kill()
            child.communicate(timeout=c["child_timeout"])
        except BaseException as error:
            result["cleanup_errors"].append({"stage": "child", "type": type(error).__name__})
    for path, enrolled in reversed(owned):
        try:
            current = metadata(path)
            assert all(current[k] == enrolled[k] for k in ("device", "inode", "kind")) and current["uid"] in (0, c["peer_uid"])
            assert shutil.rmtree.avoids_symlink_attacks
            shutil.rmtree(path)
            assert not path.exists() and not path.is_symlink()
            result["cleanup"].append({"path": str(path), "device": enrolled["device"], "inode": enrolled["inode"], "absent": True})
        except BaseException as error:
            result["cleanup_errors"].append({"stage": "namespace", "type": type(error).__name__})
    if result["cleanup_errors"]: result["status"] = "failed"
print(json.dumps(result, sort_keys=True))
"""


def _expected_payloads(candidate: Path, manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Derive every retained input and installed payload from the original ZIP."""
    expected: dict[str, dict[str, Any]] = {}

    def directory(name: str) -> None:
        row = {"kind": "directory"}
        if name in expected and expected[name] != row:
            raise GuestBootError("owner-wheel-conflicting-input-namespace")
        expected[name] = row

    def file(name: str, data: bytes) -> None:
        if name in expected:
            raise GuestBootError("owner-wheel-duplicate-input-payload")
        expected[name] = {
            "kind": "regular",
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        parts = name.split("/")[:-1]
        for end in range(1, len(parts) + 1):
            directory("/".join(parts[:end]))

    directory(".")
    directory("lib")
    directory("wheels")
    selection = manifest["components"]["host"]
    if set(selection["dependencies"]) != set(MODULES):
        raise GuestBootError("owner-wheel-profile-imports-not-enrolled")
    dependencies = set(selection["dependencies"])
    selected = set()
    with zipfile.ZipFile(candidate) as archive:
        file("manifest.json", archive.read("manifest.json"))
        file(selection["lock"], archive.read(selection["lock"]))
        for name in manifest["files"]:
            if not name.startswith("wheels/") or not name.endswith(".whl"):
                continue
            distribution = name.split("/")[-1].split("-")[0].replace("_", "-").lower()
            if distribution not in dependencies:
                continue
            if distribution in selected:
                raise GuestBootError("owner-wheel-duplicate-input-distribution")
            selected.add(distribution)
            raw = archive.read(name)
            file(name, raw)
            import io

            with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
                for member in wheel.infolist():
                    if member.is_dir():
                        directory("lib/" + member.filename.rstrip("/"))
                    else:
                        file("lib/" + member.filename, wheel.read(member))
    if selected != set(selection["dependencies"]):
        raise GuestBootError("owner-wheel-incomplete-input-closure")
    return expected


def _prepare_inputs(guest: Guest, temporary: Path) -> tuple[Path, dict[str, Any]]:
    """Retain the same-run Ubuntu candidate and selected runtime as guest input."""
    candidate = Path("artifacts/native-owner-candidate/scaffold-bundle.zip")
    if candidate.is_symlink() or not candidate.is_file():
        raise GuestBootError("owner-wheel-candidate-unavailable")
    candidate_hash = hashlib.sha256(candidate.read_bytes()).hexdigest()
    with zipfile.ZipFile(candidate) as archive:
        manifest_raw = archive.read("manifest.json")
        if archive.read("install.py") != Path(__file__).with_name("bundle_install.py").read_bytes():
            raise GuestBootError("owner-wheel-candidate-bootstrap-mismatch")
        manifest = json.loads(manifest_raw)
        provenance = json.loads(archive.read("provenance.json"))
        source = source_identity()
        if (
            not source["clean"]
            or provenance["source_commit"] != source["commit"]
            or provenance["working_tree_dirty"] is not False
            or provenance["github_run_id"] != os.environ.get("GITHUB_RUN_ID")
            or provenance["production_qualified"] is not False
            or manifest["profile"] != {"platform": "linux", "machine": "x86_64", "python": "3.12"}
        ):
            raise GuestBootError("owner-wheel-candidate-source-mismatch")
    runtime = temporary / "runtime.tar.gz"
    guest.command(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(__file__).with_name("native_owner_python_download.py")),
            str(runtime),
            OWNER_PYTHON_URL,
            str(OWNER_PYTHON_BYTES),
            OWNER_PYTHON_SHA256,
            str(watchdog(30)),
        ],
        "owner-wheel-runtime-download",
        180,
    )
    import tarfile

    with tarfile.open(runtime, "r:gz") as archive:
        executable = archive.extractfile("python/bin/python3.12")
        if executable is None:
            raise GuestBootError("owner-wheel-runtime-executable-unavailable")
        with executable:
            digest = hashlib.sha256()
            while chunk := executable.read(1_048_576):
                digest.update(chunk)
            executable_hash = digest.hexdigest()
    path = temporary / "inputs.zip"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as output:
            output.write(runtime, "runtime.tar.gz")
            output.write(candidate, "bundle.zip")
        stream.flush()
        os.fsync(stream.fileno())
    if hashlib.sha256(candidate.read_bytes()).hexdigest() != candidate_hash:
        raise GuestBootError("owner-wheel-candidate-changed")
    return path, {
        "manifest": manifest,
        "expected_payloads": _expected_payloads(candidate, manifest),
        "runtime_executable_sha256": executable_hash,
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "input_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "input_bytes": path.stat().st_size,
        "input_members": {"runtime.tar.gz": OWNER_PYTHON_SHA256, "bundle.zip": candidate_hash},
        "candidate_sha256": candidate_hash,
        "candidate_bytes": candidate.stat().st_size,
        "candidate_source": source,
        "candidate_provenance": provenance,
    }


def _tree(value: dict[str, Any], *, sealed: bool) -> None:
    if "." not in value:
        raise GuestBootError("owner-wheel-inventory-incomplete")
    identities = set()
    for path, row in value.items():
        if path != "." and (Path(path).is_absolute() or ".." in Path(path).parts or "\\" in path):
            raise GuestBootError("owner-wheel-unsafe-inventory-path")
        if (
            any(type(row[k]) is not int or row[k] < 0 for k in ("device", "uid", "gid", "mode"))
            or type(row["inode"]) is not int
            or row["inode"] <= 0
            or row["uid"] != 0
            or row["gid"] != 0
            or row["kind"] not in ("regular", "directory")
        ):
            raise GuestBootError("owner-wheel-invalid-inventory-metadata")
        identity = row["device"], row["inode"]
        if identity in identities:
            raise GuestBootError("owner-wheel-aliased-inventory")
        identities.add(identity)
        if sealed and row["mode"] != (0o555 if row["kind"] == "directory" else 0o444):
            raise GuestBootError("owner-wheel-unsealed-inventory")
        if row["kind"] == "regular" and (
            type(row["bytes"]) is not int
            or row["bytes"] < 0
            or not isinstance(row["sha256"], str)
            or len(row["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in row["sha256"])
        ):
            raise GuestBootError("owner-wheel-invalid-file-digest")
    if not sealed and value["."]["mode"] != 0o700:
        raise GuestBootError("owner-wheel-interrupted-prefix-public")


def _verify_imports(
    value: dict[str, Any], configuration: dict[str, Any], library: str, poison: str
) -> None:
    for role in ("root", "peer"):
        observed = value[role]
        uid, gid = (
            (0, 0) if role == "root" else (configuration["peer_uid"], configuration["peer_gid"])
        )
        if (
            observed["pid"] != value[role + "_pid"]
            or observed["parent_pid"] != value["observer_pid"]
            or observed["uids"] != [uid] * 3
            or observed["gids"] != [gid] * 3
            or observed["executable"] != value["runtime"]["path"]
            or observed["version"] != [3, 12, 16]
            or observed["cwd"] != poison
            or observed["isolated"] != 1
            or observed["no_site"] != 1
            or observed["no_bytecode"] != 1
            or observed["poison_marker_absent"] is not True
            or set(observed["modules"]) != set(MODULES)
            or observed["sys_path"][0] != library
            or any(p == poison or p == "" for p in observed["sys_path"])
            or observed["cli_status"] != 0
            or observed["cli_info"]["tool"] != "host-ops"
            or observed["cli_info"]["native_mutations"] is not False
            or observed["cli_info"]["production_qualified"] is not False
        ):
            raise GuestBootError("owner-wheel-isolated-import-mismatch")
        for name, row in observed["modules"].items():
            if row["module"] != MODULES[name] or not row["path"].startswith(library + "/"):
                raise GuestBootError("owner-wheel-import-origin-mismatch")
            local = "lib/" + row["path"].removeprefix(library + "/")
            if value["before"][local]["sha256"] != row["sha256"]:
                raise GuestBootError("owner-wheel-import-digest-mismatch")
        if not {
            "_cffi_backend",
            "yaml._yaml",
            "markupsafe._speedups",
            "cryptography.hazmat.bindings._rust",
            "rpds.rpds",
        } <= set(observed["binaries"]):
            raise GuestBootError("owner-wheel-native-import-missing")
        for row in observed["binaries"].values():
            local = "lib/" + row["path"].removeprefix(library + "/")
            if (
                not row["path"].startswith(library + "/")
                or value["before"][local]["sha256"] != row["sha256"]
            ):
                raise GuestBootError("owner-wheel-binary-origin-mismatch")


def verify_observation(value: dict[str, Any], configuration: dict[str, Any]) -> None:
    required = {
        "scope",
        "status",
        "native_product_qualified",
        "enrollment",
        "boot_id",
        "bootstrap_sha256",
        "input_sha256",
        "manifest_sha256",
        "observer_pid",
        "observer_uid",
        "primary_error",
        "cleanup_errors",
        "cleanup",
        "runtime",
        "manifest",
        "interruption",
        "rejections",
        "before",
        "after",
        "existing_before",
        "existing_after",
        "root_pid",
        "root",
        "peer_pid",
        "peer",
        "interrupted_final",
    }
    if (
        set(value) != required
        or value["scope"] != SCOPE
        or value["status"] != "passed"
        or value["native_product_qualified"] is not False
    ):
        raise GuestBootError("owner-wheel-incomplete-observation")
    if (
        value["observer_uid"] != 0
        or value["primary_error"] is not None
        or value["cleanup_errors"] != []
    ):
        raise GuestBootError("owner-wheel-failed-observation")
    for key in ("enrollment", "boot_id", "bootstrap_sha256", "input_sha256", "manifest_sha256"):
        if value[key] != configuration[key]:
            raise GuestBootError("owner-wheel-identity-mismatch")
    if value["manifest"] != configuration["manifest"]:
        raise GuestBootError("owner-wheel-manifest-mismatch")
    _tree(value["before"], sealed=True)
    expected = configuration["expected_payloads"]
    if set(value["before"]) != set(expected) or any(
        any(value["before"][name].get(key) != field for key, field in row.items())
        for name, row in expected.items()
    ):
        raise GuestBootError("owner-wheel-complete-payload-mismatch")
    _tree(value["interruption"]["inventory"], sealed=False)
    original_ids = {(row["device"], row["inode"]) for row in value["before"].values()}
    partial_ids = {
        (row["device"], row["inode"]) for row in value["interruption"]["inventory"].values()
    }
    if original_ids & partial_ids or not any(
        name.startswith("lib/") and row["kind"] == "regular"
        for name, row in value["interruption"]["inventory"].items()
    ):
        raise GuestBootError("owner-wheel-interruption-inventory-mismatch")
    if (
        value["before"] != value["after"]
        or value["existing_before"] != value["existing_after"]
        or value["interrupted_final"] != value["interruption"]["inventory"]
    ):
        raise GuestBootError("owner-wheel-preservation-mismatch")
    prefix = "/var/lib/fishhat-wheels-fixture-" + configuration["enrollment"]
    poison = "/tmp/fishhat-wheels-fixture-" + configuration["enrollment"]
    library = prefix + "/installed/lib"
    if (
        value["runtime"]["path"] != prefix + "/runtime/python/bin/python3.12"
        or value["runtime"]["archive_sha256"] != OWNER_PYTHON_SHA256
    ):
        raise GuestBootError("owner-wheel-runtime-mismatch")
    if value["runtime"]["sha256"] != configuration["runtime_executable_sha256"]:
        raise GuestBootError("owner-wheel-runtime-executable-mismatch")
    existing = value["existing_before"]
    if existing["file"] != {
        **existing["file"],
        "uid": 0,
        "gid": 0,
        "kind": "regular",
        "mode": 0o600,
        "sha256": hashlib.sha256(b"unrelated existing bytes").hexdigest(),
    } or existing["alias"] != {
        **existing["alias"],
        "uid": 0,
        "gid": 0,
        "kind": "link",
        "mode": 0o777,
        "target": prefix + "/installed",
    }:
        raise GuestBootError("owner-wheel-existing-witness-mismatch")
    interrupted = value["interruption"]
    if (
        interrupted["returncode"] != -9
        or interrupted["joined"] is not True
        or interrupted["uid"] != 0
        or interrupted["boot_id"] != configuration["boot_id"]
    ):
        raise GuestBootError("owner-wheel-interruption-mismatch")
    if value["before"]["."]["inode"] == interrupted["inventory"]["."]["inode"]:
        raise GuestBootError("owner-wheel-retry-reused-candidate")
    pids = [value["observer_pid"], interrupted["pid"], value["root_pid"], value["peer_pid"]]
    if (
        any(type(pid) is not int or pid <= 0 for pid in pids)
        or len(set(pids)) != 4
        or interrupted["parent_pid"] != value["observer_pid"]
    ):
        raise GuestBootError("owner-wheel-process-mismatch")
    _verify_imports(value, configuration, library, poison)
    peer = value["peer"]
    if (
        peer["groups"] != []
        or int(peer["capabilities"], 16) != 0
        or peer["administrative_refusal"] is not True
        or [r["operation"] for r in peer["denied"]] != list(DENIALS)
        or any(type(r["errno"]) is not int or r["errno"] not in (1, 13) for r in peer["denied"])
    ):
        raise GuestBootError("owner-wheel-peer-mismatch")
    if value["root"]["denied"] != [] or value["root"]["administrative_refusal"] is not False:
        raise GuestBootError("owner-wheel-root-observation-mismatch")
    if [r["case"] for r in value["rejections"]] != [
        "interrupted-destination",
        "existing-directory",
        "existing-file",
        "existing-symlink",
    ] or any(r["error"] != "FileExistsError" or r["errno"] != 17 for r in value["rejections"]):
        raise GuestBootError("owner-wheel-existing-refusals-missing")
    if [r["path"] for r in value["cleanup"]] != [poison, prefix] or any(
        r["absent"] is not True or type(r["inode"]) is not int or r["inode"] <= 0
        for r in value["cleanup"]
    ):
        raise GuestBootError("owner-wheel-cleanup-mismatch")


def qualify_wheels(
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
        with tempfile.TemporaryDirectory(prefix="fh-wheels-", dir=temporary) as directory:
            with progress("guest-owner-wheel-inputs"):
                path, inputs = _prepare_inputs(guest, Path(directory))
            report["inputs"] = inputs
            bootstrap = Path(__file__).with_name("bundle_install.py").read_bytes()
            peer = guest.observed["accounts"][guest.accounts[1]]
            configuration = {
                **inputs,
                "scope": SCOPE,
                "enrollment": guest.enrollment,
                "boot_id": guest.observed["boot_id"],
                "bootstrap": base64.b64encode(bootstrap).decode(),
                "bootstrap_sha256": hashlib.sha256(bootstrap).hexdigest(),
                "runtime_bytes": OWNER_PYTHON_BYTES,
                "runtime_sha256": OWNER_PYTHON_SHA256,
                "peer_uid": peer["uid"],
                "peer_gid": peer["gid"],
                "child_timeout": watchdog(180),
                "observe_program": OBSERVE,
                "interrupt_program": INTERRUPTED,
                "modules": MODULES,
            }
            wire_configuration = {
                key: value
                for key, value in configuration.items()
                if key not in ("manifest", "expected_payloads")
            }
            with progress("guest-owner-wheel-payload-custody"):
                raw = guest.guarded(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-S",
                        "-B",
                        "-c",
                        REMOTE,
                        json.dumps(wire_configuration),
                    ],
                    guest.enrollment,
                    guest.observed["boot_id"],
                    nominal=600,
                    input_path=path,
                )
            report["original_reply_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
            try:
                value = json.loads(raw)
            except (ValueError, RecursionError):
                report["unparsed_original_reply"] = raw
                raise GuestBootError("owner-wheel-invalid-original-reply") from None
            report["original_observation"] = value
            try:
                verify_observation(value, configuration)
            except (KeyError, TypeError, ValueError, AttributeError):
                raise GuestBootError("owner-wheel-invalid-observation-shape") from None
            report["status"] = "passed"
    finally:
        report["qualification_statistics"] = metrics.finish()
        if not valid_stats(report["qualification_statistics"]):
            raise GuestBootError("owner-wheel-invalid-statistics")
