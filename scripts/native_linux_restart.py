"""Borrow exact protected boot inputs for one owned cold controller replacement."""

from __future__ import annotations

import copy
import errno
import socket
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest, GuestBootError
from scripts.native_linux_images import DISK_BYTES, identity
from scripts.native_linux_reboot import (
    host_custody,
    invoke,
    new_boot,
    refuse_stale,
    validate_canary,
)
from scripts.native_linux_reboot import (
    phase as measured_phase,
)
from scripts.native_linux_snapshots import absent_process, stopped_source
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import Deadline, current

PRIVATE_FILES = frozenset(
    (
        "host",
        "host.pub",
        "admin",
        "admin.pub",
        "peer",
        "peer.pub",
        "user-data",
        "meta-data",
        "known-hosts",
        "wrong-hosts",
        "seed.iso",
    )
)


class GuestRestartError(GuestBootError):
    stage = "guest-restart"


def require(value: Any, reason: str) -> None:
    if not value:
        raise GuestRestartError(reason)


def problem(error: BaseException) -> dict[str, str]:
    return {
        "stage": getattr(error, "stage", "unclassified"),
        "reason": getattr(error, "reason", "unclassified"),
        "type": type(error).__name__,
    }


@contextmanager
def phase(report: dict[str, Any], name: str) -> Iterator[dict[str, Any]]:
    with measured_phase(report, name) as item:
        try:
            yield item
        except BaseException as error:
            item["problem"] = problem(error)
            raise


def boot_closure(guest: Guest) -> dict[str, Any]:
    require(set(guest.files) == PRIVATE_FILES, "incomplete-boot-inputs")
    guest.verify_tools()
    guest.inputs.verify(guest.enrollment)
    return {
        "enrollment": guest.enrollment,
        "accounts": guest.accounts,
        "endpoint": {"address": "127.0.0.1", "port": guest.port},
        "private_directory": {"path": str(guest.directory), "identity": guest.directory_identity},
        "private_files": {
            name: {"path": str(guest.path(name)), "identity": value[0], "sha256": value[1]}
            for name, value in guest.files.items()
        },
        "input_directory": {
            "path": str(guest.inputs.directory),
            "identity": guest.inputs.directory_identity,
        },
        "disks": {
            name: {"path": str(guest.inputs.path(name, guest.enrollment)), "identity": value}
            for name, value in guest.inputs.files.items()
        },
        "tools": copy.deepcopy(guest.tools),
        "qemu": str(guest.qemu),
        "controller_profile": copy.deepcopy(guest.report["controller_verified"]),
        "key_fingerprints": copy.deepcopy(guest.report["key_fingerprints"]),
    }


@dataclass
class RetainedBootInputs:
    source: Guest
    custody: dict[str, Any]
    expected: dict[str, Any]
    source_before: dict[str, Any]
    active: bool = False
    borrowed: Guest | None = field(default=None, repr=False)

    def verify(self) -> None:
        require(self.active and self.source.boot_inputs_borrowed, "boot-input-handle-expired")
        require(boot_closure(self.source) == self.expected, "boot-input-closure-changed")

    def guest(self, enrollment: str, report: dict[str, Any]) -> Guest:
        self.verify()
        require(enrollment == self.expected["enrollment"], "foreign-boot-input-enrollment")
        require(self.borrowed is None, "boot-input-handle-already-borrowed")
        require(
            stopped_source(self.source, self.custody) == self.source_before,
            "stopped-source-changed",
        )
        source = self.source
        # The enclosing guest_session remains the sole owner of these files.
        # A fresh Guest receives no old process, callback or boot admission.
        child = Guest(
            source.inputs,
            source.directory,
            source.command,
            copy.deepcopy(source.tools),
            report,
            source.port,
            source.qemu,
            source.directory_identity,
            files=copy.deepcopy(source.files),
        )
        report.update(
            status="failed",
            scope="disposable-retained-input-guest-only",
            enrollment=enrollment,
            boot_verified=False,
            key_fingerprints=copy.deepcopy(self.expected["key_fingerprints"]),
        )
        self.borrowed = child
        return child


@contextmanager
def retained_boot_inputs(
    source: Guest,
    custody: dict[str, Any],
    report: dict[str, Any],
    *,
    expected_source: dict[str, Any],
) -> Iterator[RetainedBootInputs]:
    metrics = RunStats()
    handle: RetainedBootInputs | None = None
    acquired = False
    complete = False
    report.update(status="failed", lifetime_ended=False, shared_private_inputs_preserved=False)
    try:
        require(not source.boot_inputs_borrowed, "boot-inputs-already-borrowed")
        before = stopped_source(source, custody)
        require(before == expected_source, "accepted-source-bytes-changed")
        closure = boot_closure(source)
        handle = RetainedBootInputs(source, copy.deepcopy(custody), closure, before, active=True)
        source.boot_inputs_borrowed = acquired = True
        report.update(closure_before=copy.deepcopy(closure), source_before=before)
        try:
            yield handle
            complete = True
        finally:
            handle.verify()
            report["closure_after"] = boot_closure(source)
            report["shared_private_inputs_preserved"] = True
            child = handle.borrowed
            if child is not None and child.process is not None:
                require(child.process.returncode is not None, "replacement-not-reaped")
                absent_process(child.process.pid)
                absent_process(child.process.pid, group=True)
            source.boot_inputs_borrowed = False
            acquired = False
            report.update(status="passed" if complete else "failed", lifetime_ended=True)
    finally:
        if handle is not None:
            handle.active = False
        # Keep the source unavailable if exact cleanup could not be proved.
        if acquired:
            report["status"] = "failed"
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            report["status"] = "failed"
            raise ValueError("invalid required retained boot-input statistics")


def stopped_replacement(guest: Guest) -> dict[str, Any]:
    process = guest.process
    require(process is not None and process.returncode is not None, "replacement-not-reaped")
    assert process is not None
    absent_process(process.pid)
    absent_process(process.pid, group=True)
    endpoint = Path(guest.report["control_endpoint"])
    require(endpoint.is_absolute() and endpoint.name == "qmp", "replacement-endpoint-mismatch")
    arguments = process.args
    require(
        isinstance(arguments, list) and arguments.count("-qmp") == 1, "replacement-command-mismatch"
    )
    assert isinstance(arguments, list)
    index = arguments.index("-qmp")
    require(
        index + 1 < len(arguments)
        and arguments[index + 1] == f"unix:{endpoint},server=on,wait=off",
        "replacement-endpoint-mismatch",
    )
    for path in (endpoint, endpoint.parent):
        require(not path.exists() and not path.is_symlink(), "replacement-control-endpoint-remains")
    with socket.socket() as probe:
        probe.settimeout(current().seconds(2))
        require(
            probe.connect_ex(("127.0.0.1", guest.port)) == errno.ECONNREFUSED,
            "replacement-ssh-endpoint-remains",
        )
    return {
        "pid": process.pid,
        "pgid": process.pid,
        "process_absent": True,
        "group_absent": True,
        "control_endpoint": str(endpoint),
        "control_endpoint_removed": True,
        "ssh_endpoint": {"address": "127.0.0.1", "port": guest.port},
        "ssh_endpoint_closed": True,
    }


def admitted_capture_source(source: Guest) -> dict[str, Any]:
    captured = source.report.get("snapshot_capture")
    require(isinstance(captured, dict), "accepted-capture-source-missing")
    assert isinstance(captured, dict)
    require(
        captured.get("status") == "passed"
        and captured.get("scope") == "owned-disposable-cold-disk-bytes-only"
        and captured.get("source_preserved") is True
        and captured.get("temporary_resources_removed") is True,
        "accepted-capture-source-missing",
    )
    phases = captured.get("phases")
    require(isinstance(phases, list) and bool(phases), "accepted-capture-source-missing")
    assert isinstance(phases, list)
    require(
        isinstance(phases[-1], dict) and phases[-1].get("phase") == "preservation",
        "accepted-capture-source-missing",
    )
    value = phases[-1].get("source_after")
    require(isinstance(value, dict), "accepted-capture-source-missing")
    assert isinstance(value, dict)
    return copy.deepcopy(value)


def canary_configuration(source: Guest) -> dict[str, Any]:
    prepared = source.report["reboot"]["phases"][0]["observation"]
    content = prepared["identity"]["content"].splitlines()
    require(
        len(content) == 2 and content[0] == "reboot:" + source.enrollment, "missing-source-canary"
    )
    require(str(uuid.UUID(content[1])) == content[1], "missing-source-canary")
    c = {
        "enrollment": source.enrollment,
        "nonce": content[1],
        "sizes": {k.removesuffix(".qcow2"): v for k, v in DISK_BYTES.items()},
        "identity": copy.deepcopy(prepared["identity"]),
        "image": copy.deepcopy(prepared["observer"]["executable"]),
    }
    validate_canary(prepared, c)
    return c


def observe_replacement(
    guest: Guest, source: Guest, endpoint: Path, c: dict[str, Any], report: dict[str, Any]
) -> None:
    require(source.observed is not None, "source-boot-not-admitted")
    assert source.observed is not None
    before = copy.deepcopy(source.observed)
    deadline = Deadline.after(600)
    with phase(report, "independent-boot") as p:
        after = p["identity"] = new_boot(guest, before, p, deadline)
    with phase(report, "independent-canary") as p:
        p["observation"] = value = invoke(guest, after, c, "inspect", deadline, p)
        validate_canary(value, c)
    with phase(report, "refusals") as p:
        p["refused"] = refuse_stale(guest, before, after, deadline)
        p["observation"] = value = invoke(guest, after, c, "inspect", deadline, p)
        validate_canary(value, c)
    with phase(report, "final-observation") as p:
        value = p["identity"] = guest.observe(deadline)
        guest.validate_profile(value)
        require(value == after, "replacement-identity-changed-again")
        p["observation"] = canary = invoke(guest, value, c, "inspect", deadline, p)
        validate_canary(canary, c)
        p["host_custody"] = host_custody(guest, endpoint, deadline)
        report["controller_custody"] = copy.deepcopy(p["host_custody"])
    require(
        guest.observed is None and source.observed == before, "replacement-admission-changed-early"
    )
    guest.observed = copy.deepcopy(after)
    guest.report.update(boot_verified=True, identity=copy.deepcopy(after), status="passed")
    report["after_identity"] = copy.deepcopy(after)


def qualify_restart(
    source: Guest,
    custody: dict[str, Any],
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    launch: Callable[[Guest], AbstractContextManager[Path]],
    report: dict[str, Any],
) -> None:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="owned-disposable-original-disk-cold-restart-only",
        mechanism="reaped-controller-then-fresh-pinned-boot-original-disks",
        phases=[],
        snapshot_restore_qualified=False,
        product_authority_qualified=False,
        resources_destroyed_with_guest=False,
        boot_inputs={},
        guest={},
    )
    child: Guest | None = None
    try:
        before = copy.deepcopy(source.observed)
        original_report = copy.deepcopy({k: v for k, v in source.report.items() if v is not report})
        with tempfile.TemporaryDirectory(prefix="fhrc-", dir=temporary) as folder:
            canary = Path(folder) / "unrelated"
            content = uuid.uuid4().bytes
            canary.write_bytes(content)
            canary.chmod(0o600)
            original = identity(canary), canary.stat().st_mtime_ns
            try:
                with retained_boot_inputs(
                    source,
                    custody,
                    report["boot_inputs"],
                    expected_source=admitted_capture_source(source),
                ) as retained:
                    with phase(report, "input-admission") as p:
                        c = canary_configuration(source)
                        child = retained.guest(source.enrollment, report["guest"])
                        p["closure_verified"] = True
                        try:
                            retained.guest(str(uuid.uuid4()), {})
                        except GuestRestartError as error:
                            require(
                                error.reason == "foreign-boot-input-enrollment",
                                "wrong-input-refusal",
                            )
                        else:
                            raise GuestRestartError("foreign-boot-input-accepted")
                        p["foreign_enrollment_refused"] = True
                    try:
                        with (
                            progress("guest-cold-controller-replacement"),
                            launch(child) as endpoint,
                        ):
                            with phase(report, "prelaunch") as p:
                                retained.verify()
                                require(
                                    child.report["controller_verified"]
                                    == retained.expected["controller_profile"],
                                    "replacement-controller-profile-changed",
                                )
                                p["controller"] = copy.deepcopy(child.report["controller_verified"])
                            observe_replacement(child, source, endpoint, c, report)
                            retained.verify()
                    finally:
                        if child.process is not None:
                            with phase(report, "stopped-replacement") as p:
                                p["observation"] = stopped_replacement(child)
                    require(child.observed is not None, "replacement-never-admitted")
                try:
                    retained.guest(source.enrollment, {})
                except GuestRestartError as error:
                    require(error.reason == "boot-input-handle-expired", "wrong-input-refusal")
                else:
                    raise GuestRestartError("expired-boot-input-accepted")
                report["expired_handle_refused"] = True
            finally:
                require(
                    canary.read_bytes() == content
                    and (identity(canary), canary.stat().st_mtime_ns) == original,
                    "unrelated-restart-canary-changed",
                )
                report["unrelated_canary_preserved"] = True
        require(source.observed == before, "source-boot-admission-changed")
        require(
            {k: v for k, v in source.report.items() if v is not report} == original_report,
            "original-guest-evidence-changed",
        )
        report.update(status="passed", original_guest_evidence_preserved=True)
    except OSError as error:
        report["resource_failure"] = {"errno": error.errno, "type": type(error).__name__}
        report["problem"] = problem(GuestRestartError("restart-resource-unavailable"))
        raise GuestRestartError("restart-resource-unavailable") from None
    except BaseException as error:
        report["problem"] = problem(error)
        raise
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            report["status"] = "failed"
            raise ValueError("invalid required cold restart statistics")
