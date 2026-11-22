"""Qualify protected checkpoint storage only in the enrolled disposable guest."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
import zipfile
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path, PurePosixPath
from typing import Any

from scripts import native_linux_owner_entrypoint as entrypoint
from scripts import native_linux_owner_wheels as wheels
from scripts.native_checkpoint_fixture import REMOTE
from scripts.native_checkpoint_probe import PROGRAM
from scripts.native_linux_guest import Guest, GuestBootError
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import watchdog

SCOPE = "disposable-guest-protected-checkpoint-storage-only"
CASES = (
    "valid",
    "missing",
    "contested",
    "aliases",
    "replaced",
    "unlinked",
    "initializing",
    "fresh",
    "interrupted",
    "lost",
    "uncertain",
    "malformed",
    "file-mode",
    "directory-mode",
    "file-owner",
    "directory-owner",
    "hardlink",
    "capability",
    "pending",
)
TRACE_FILTER = "trace=%file,%process,%creds,%network,umask,close_range,close,read,write,writev,fsync,fdatasync,flock,fchmod,fcntl,dup,dup2,dup3,getdents64,flistxattr,fgetxattr"
STRING_LIMIT = 65536
CLEANUP = r"""
import json,os,pathlib,sys
c=json.loads(sys.argv[1]);assert os.geteuid()==0
print(json.dumps({'pid':os.getpid(),'uid':os.geteuid(),
 'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
 'enrollment':pathlib.Path('/etc/fishhat-fixture-enrollment').read_text().strip(),
 'paths':[{'path':path,'absent':not pathlib.Path(path).exists() and not pathlib.Path(path).is_symlink()} for path in c['paths']],
 'processes':[{'pid':pid,'absent':not pathlib.Path('/proc',str(pid)).exists()} for pid in c['pids']]},sort_keys=True))
"""


def require(value: bool, reason: str) -> None:
    if not value:
        raise GuestBootError("owner-checkpoint-" + reason)


def fixture_owner(enrollment: str) -> dict[str, str]:
    namespace = uuid.UUID(enrollment)
    return {
        "tool": "host-ops",
        "id": str(uuid.uuid5(namespace, "protected-checkpoint-owner")),
        "epoch": str(uuid.uuid5(namespace, "protected-checkpoint-epoch")),
    }


def fixture_context(guest: Guest) -> dict[str, Any]:
    require(guest.observed is not None, "guest-unverified")
    assert guest.observed is not None
    prefix = PurePosixPath("/var/lib/fishhat-checkpoint-fixture-" + guest.enrollment)
    journal = (
        PurePosixPath("/run/fhs-" + uuid.UUID(guest.enrollment).hex)
        / "control"
        / ("checkpoint-" + uuid.UUID(guest.enrollment).hex)
    )
    return {
        "scope": SCOPE,
        "enrollment": guest.enrollment,
        "boot_id": guest.observed["boot_id"],
        "probe_sha256": hashlib.sha256(PROGRAM.encode()).hexdigest(),
        "library": str(prefix / "packages/lib"),
        "control": str(prefix / "control"),
        "cases": {name: str(prefix / "authority" / name) for name in CASES},
        "journals": [str(journal / name) for name in ("original", "copy")],
        "local_journal": str(prefix / "same-domain-journal"),
        "owner": fixture_owner(guest.enrollment),
        "journal_id": str(uuid.uuid5(uuid.UUID(guest.enrollment), "protected-checkpoint-journal")),
    }


def _prepare_inputs(guest: Guest, temporary: Path) -> tuple[Path, dict[str, Any]]:
    base = temporary / "wheel-inputs"
    base.mkdir(mode=0o700)
    original, prepared = wheels._prepare_inputs(guest, base)
    with zipfile.ZipFile(original) as source:
        require(set(source.namelist()) == {"runtime.tar.gz", "bundle.zip"}, "shared-inputs-changed")
        candidate = source.read("bundle.zip")
    members, observer = entrypoint._observer_payloads(guest, temporary)
    context = fixture_context(guest)
    context_raw = (json.dumps(context, sort_keys=True, separators=(",", ":")) + "\n").encode()
    bootstrap = Path(__file__).with_name("bundle_install.py").read_bytes()
    members.update(
        {
            "bundle.zip": candidate,
            "install.py": bootstrap,
            "probe.py": PROGRAM.encode(),
            "context.json": context_raw,
        }
    )
    runtime = base / "runtime.tar.gz"
    expected_runtime = {
        "." if name == "runtime" else name.removeprefix("runtime/"): row
        for name, row in entrypoint._runtime_payloads(runtime).items()
    }
    expected_wheels = {
        name: row | {"mode": 0o555 if row["kind"] == "directory" else 0o444}
        for name, row in prepared["expected_payloads"].items()
    }
    output = temporary / "inputs.zip"
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.write(runtime, "runtime.tar.gz")
            for name, raw in members.items():
                archive.writestr(name, raw)
        stream.flush()
        os.fsync(stream.fileno())
    with output.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    return output, {
        "source": prepared["candidate_source"],
        "candidate_provenance": prepared["candidate_provenance"],
        "candidate_sha256": prepared["candidate_sha256"],
        "candidate_bytes": prepared["candidate_bytes"],
        "manifest_sha256": prepared["manifest_sha256"],
        "runtime_executable_sha256": prepared["runtime_executable_sha256"],
        "bootstrap_sha256": hashlib.sha256(bootstrap).hexdigest(),
        "input_sha256": checksum,
        "input_bytes": output.stat().st_size,
        "input_members": {"runtime.tar.gz": prepared["input_members"]["runtime.tar.gz"]}
        | {name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()},
        "context": context,
        "programs": {
            name: {
                "kind": "regular",
                "mode": 0o444,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            for name, raw in members.items()
            if name in ("probe.py", "context.json")
        },
        "expected_runtime": expected_runtime,
        "expected_wheels": expected_wheels,
        "expected_observer": observer,
    }


def qualify_checkpoint(
    guest: Guest,
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    report: dict[str, Any],
    storage: dict[str, Any],
) -> None:
    from scripts.native_checkpoint_observation import verify_observation

    require(guest.observed is not None, "guest-unverified")
    assert guest.observed is not None
    require(
        storage.get("status") == "passed" and storage.get("permissions_verified") is True,
        "storage-not-qualified",
    )
    require(
        set(storage["filesystems"]) == {"root", "control", "data"}, "storage-context-incomplete"
    )
    metrics = RunStats()
    report.update(
        scope=SCOPE,
        status="failed",
        native_product_qualified=False,
        writer_authority_qualified=False,
        resources_destroyed_with_guest=False,
    )
    try:
        with tempfile.TemporaryDirectory(prefix="fh-checkpoint-", dir=temporary) as directory:
            with progress("guest-owner-checkpoint-inputs"):
                path, inputs = _prepare_inputs(guest, Path(directory))
            report["inputs"] = inputs
            admin, peer = guest.accounts
            identity = guest.observed["accounts"][peer]
            c = {
                "scope": SCOPE,
                "enrollment": guest.enrollment,
                "boot_id": guest.observed["boot_id"],
                "admin_account": admin,
                "peer_account": peer,
                "peer_uid": identity["uid"],
                "peer_gid": identity["gid"],
                "storage": storage["filesystems"],
                "cases": list(CASES),
                "heads": [
                    hashlib.sha256(("checkpoint-head-" + name).encode()).hexdigest()
                    for name in ("a", "b")
                ],
                "observer_pins": entrypoint.OBSERVER_PINS,
                "trace_filter": TRACE_FILTER,
                "string_limit": STRING_LIMIT,
                "child_timeout": watchdog(180),
                **{
                    key: inputs[key]
                    for key in (
                        "input_sha256",
                        "input_bytes",
                        "input_members",
                        "bootstrap_sha256",
                        "manifest_sha256",
                    )
                },
            }
            report["configuration"] = c
            with progress("guest-protected-owner-checkpoint"):
                raw = guest.guarded(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-S",
                        "-B",
                        "-c",
                        REMOTE,
                        json.dumps(c, sort_keys=True),
                    ],
                    guest.enrollment,
                    c["boot_id"],
                    nominal=1200,
                    input_path=path,
                )
            report["original_reply_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
            try:
                value = json.loads(raw)
            except (ValueError, RecursionError):
                report["unparsed_original_reply"] = raw
                raise GuestBootError("owner-checkpoint-invalid-original-reply") from None
            report["original_observation"] = value
            pids = [row["tracer_pid"] for row in value["owned_children"]]
            pids.extend(pid for row in value["owned_children"] for pid in row["tracee_pids"])
            roots = [
                str(PurePosixPath(inputs["context"]["journals"][0]).parent),
                "/var/lib/fishhat-checkpoint-fixture-" + guest.enrollment,
            ]
            cleanup = guest.guarded(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    CLEANUP,
                    json.dumps({"paths": roots, "pids": sorted(set(pids))}, sort_keys=True),
                ],
                guest.enrollment,
                c["boot_id"],
                nominal=30,
            )
            report["cleanup_observer_original_reply"] = cleanup
            checked = json.loads(cleanup)
            require(
                type(checked["pid"]) is int
                and checked["pid"] > 1
                and checked["pid"] != value["observer_pid"],
                "cleanup-observer-not-distinct",
            )
            require(
                checked["uid"] == 0
                and checked["boot_id"] == c["boot_id"]
                and checked["enrollment"] == guest.enrollment,
                "cleanup-context-changed",
            )
            require(
                checked["paths"] == [{"path": name, "absent": True} for name in roots],
                "namespace-cleanup-unconfirmed",
            )
            require(
                checked["processes"] == [{"pid": pid, "absent": True} for pid in sorted(set(pids))],
                "child-cleanup-unconfirmed",
            )
            try:
                verify_observation(
                    value, c | {"inputs": inputs, "accounts": guest.observed["accounts"]}
                )
            except (KeyError, TypeError, ValueError, AttributeError, IndexError):
                raise GuestBootError("owner-checkpoint-invalid-observation-shape") from None
            report["status"] = "passed"
    finally:
        report["qualification_statistics"] = metrics.finish()
        if not valid_stats(report["qualification_statistics"]):
            raise GuestBootError("owner-checkpoint-invalid-statistics")
