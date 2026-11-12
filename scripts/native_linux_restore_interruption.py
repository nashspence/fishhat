"""Observe a typed interruption before complete private restore admission."""

from __future__ import annotations

import copy
import stat
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest
from scripts.native_linux_images import DISK_BYTES, digest, identity
from scripts.native_linux_restart import phase, problem
from scripts.native_linux_restore import (
    RestoredDisks,
    RestoreError,
    RestoreSource,
    capture_projection,
    private_restored_disks,
)
from scripts.native_linux_restored_boot import writable_inputs
from scripts.native_linux_snapshots import DiskSnapshots
from scripts.run_stats import RunStats, valid_stats


class RestoreInterruptionError(RestoreError):
    stage = "guest-restore-interruption"


class PartialRestoreInterrupted(RestoreInterruptionError):
    def __init__(self) -> None:
        super().__init__("controlled-after-first-private-disk-before-admission")


def require(value: Any, reason: str) -> None:
    if not value:
        raise RestoreInterruptionError(reason)


def observe_file(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "identity": identity(path),
        "sha256": digest(path),
        "mode": stat.S_IMODE(path.lstat().st_mode),
        "mtime_ns": path.lstat().st_mtime_ns,
    }


def refuse(action: Callable[[], Any], reason: str) -> dict[str, str]:
    try:
        action()
    except RestoreError as error:
        require(error.reason == reason, "wrong-partial-restore-refusal")
        return problem(error)
    raise RestoreInterruptionError("partial-restore-input-accepted")


def qualify_restore_interruption(
    source: Guest,
    custody: dict[str, Any],
    snapshots: DiskSnapshots,
    capture: dict[str, Any],
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    report: dict[str, Any],
) -> None:
    require(not report, "prepopulated-interruption-report")
    metrics = RunStats()
    report.update(
        status="failed",
        scope="owned-disposable-controlled-partial-restore-only",
        consistency="cold-bytes-after-controller-termination",
        fault_kind="after-first-private-disk-before-complete-admission",
        interruption_verified=False,
        no_writer_admitted=False,
        originals_preserved=False,
        resources_destroyed_with_guest=False,
        snapshot_restore_qualified=False,
        product_authority_qualified=False,
        statistics_scope="partial preparation through private cleanup; shared teardown measured separately and by enclosing timeline",
        phases=[],
        private_inputs={},
        refusals={},
        writer_gate={},
    )
    candidate: RestoredDisks | None = None
    intended = PartialRestoreInterrupted()
    try:
        with tempfile.TemporaryDirectory(prefix="fhri-canary-", dir=temporary) as folder:
            canary = Path(folder) / "unrelated"
            canary.write_bytes(uuid.uuid4().bytes)
            canary.chmod(0o600)
            with phase(report, "input-admission"):
                original = capture_projection(capture)
                guard = RestoreSource(source, copy.deepcopy(custody), snapshots, original)
                guard.verify()
                before = copy.deepcopy(guard.current)
                unrelated = observe_file(canary)
                report.update(original_capture=copy.deepcopy(original), source_before=before)
            private = report["private_inputs"]
            first = next(iter(DISK_BYTES))

            @contextmanager
            def interrupted(name: str) -> Iterator[None]:
                nonlocal candidate
                with progress(name):
                    yield
                if name != "restore-" + first:
                    return
                require(candidate is None, "partial-interruption-repeated")
                phases = private["phases"]
                require(
                    [p["phase"] for p in phases] == ["input-admission", first]
                    and all(
                        p["status"] == "passed" and valid_stats(p["statistics"]) for p in phases
                    )
                    and private["restored_inputs_admitted"] is False,
                    "wrong-partial-interruption-boundary",
                )
                directory = Path(private["directory"]["path"])
                enrolled = identity(directory, directory=True)
                require(
                    enrolled == tuple(private["directory"]["identity"]), "partial-directory-changed"
                )
                require({p.name for p in directory.iterdir()} == {first}, "not-one-private-disk")
                observed = observe_file(directory / first)
                copied = phases[-1]["observation"]
                require(
                    observed["identity"] == copied["identity"]
                    and observed["sha256"] == copied["sha256"]
                    and observed["mode"] == 0o600
                    and copied["synced"]
                    is copied["logical_contents_equal"]
                    is copied["structure_checked"]
                    is True,
                    "partial-disk-proof-incomplete",
                )
                # An unadmitted candidate describes the actual partial disk set;
                # it cannot borrow the complete restore owner's authority.
                partial_owner = RestoredDisks(source.enrollment, directory, enrolled)
                candidate = partial_owner
                partial_owner.files[first] = copied["identity"], copied["sha256"]
                report["partial_candidate"] = {
                    "directory": copy.deepcopy(private["directory"]),
                    "files": {first: observed},
                    "complete_input_count": len(DISK_BYTES),
                }
                calls = (
                    ("partial-admission", partial_owner.admit, "incomplete-restored-inputs"),
                    (
                        "partial-path",
                        lambda: partial_owner.path(first, source.enrollment),
                        "restore-not-admitted",
                    ),
                    (
                        "foreign-enrollment",
                        lambda: partial_owner.path(first, str(uuid.uuid4())),
                        "restore-not-admitted",
                    ),
                )
                for label, action, reason in calls:
                    report["refusals"][label] = refuse(action, reason)
                substituted = copy.copy(partial_owner)
                substituted.directory = Path(folder)
                report["refusals"]["substituted-directory"] = refuse(
                    lambda: substituted.path(first, source.enrollment), "restore-not-admitted"
                )
                try:
                    with writable_inputs(partial_owner, report["writer_gate"]):
                        raise RestoreInterruptionError("partial-writer-admitted")
                except RestoreError as error:
                    require(
                        type(error) is RestoreError and error.reason == "restore-not-admitted",
                        "wrong-partial-writer-refusal",
                    )
                    report["writer_admission_failure"] = problem(error)
                else:
                    raise RestoreInterruptionError("partial-writer-admitted")
                require(
                    not partial_owner.active
                    and partial_owner._admitted is None
                    and partial_owner._writer is None
                    and observe_file(directory / first) == observed
                    and observe_file(canary) == unrelated
                    and {p.name for p in directory.iterdir()} == {first},
                    "partial-refusal-caused-effects",
                )
                guard.verify()
                require(guard.current == before, "partial-refusal-changed-source")
                raise intended

            with phase(report, "controlled-partial-restore") as item:
                try:
                    with private_restored_disks(
                        source, custody, snapshots, capture, temporary, interrupted, private
                    ):
                        raise RestoreInterruptionError("complete-inputs-unexpectedly-admitted")
                except PartialRestoreInterrupted as error:
                    require(
                        error is intended and candidate is not None,
                        "unobserved-partial-interruption",
                    )
                    item["original_failure"] = report["expected_failure"] = problem(error)
                require(
                    private["problem"] == problem(intended)
                    and private["status"] == "failed"
                    and private["restored_inputs_admitted"] is False
                    and private["temporary_resources_removed"] is True
                    and valid_stats(private.get("statistics"))
                    and "cleanup_problem" not in private,
                    "partial-restore-failure-proof-incomplete",
                )
                require(
                    [p["phase"] for p in private["phases"]] == ["input-admission", first, "cleanup"]
                    and all(
                        p["status"] == "passed" and valid_stats(p["statistics"])
                        for p in private["phases"]
                    ),
                    "partial-restore-phase-proof-incomplete",
                )
                report["interruption_verified"] = True
            with phase(report, "preservation"):
                guard.verify()
                require(
                    guard.current == before and capture_projection(capture) == original,
                    "interruption-changed-source",
                )
                require(observe_file(canary) == unrelated, "unrelated-partial-canary-changed")
                report.update(
                    source_after=copy.deepcopy(guard.current),
                    unrelated_canary=unrelated,
                    originals_preserved=True,
                )
            with phase(report, "expired-partial-refusal"):
                assert candidate is not None
                report["refusals"]["expired-partial"] = refuse(
                    lambda: candidate.path(first, source.enrollment), "restore-not-admitted"
                )
                require(
                    not candidate.active and candidate._writer is None, "partial-writer-remains"
                )
                require(
                    all(p["absent"] for p in private["phases"][-1]["paths"]),
                    "partial-resource-remains",
                )
                require(
                    not candidate.directory.exists() and not candidate.directory.is_symlink(),
                    "partial-directory-remains",
                )
                report["no_writer_admitted"] = True
        report["status"] = "observed"
    except BaseException as error:
        report["status"] = "failed"
        report.setdefault("problem", problem(error))
        raise
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            report["status"] = "failed"
            raise ValueError("invalid required partial restore statistics")


def finish_restore_interruption(report: dict[str, Any]) -> None:
    try:
        require(
            report.get("status") == "observed"
            and report.get("interruption_verified") is True
            and report.get("no_writer_admitted") is True
            and report.get("originals_preserved") is True
            and report.get("source_before") == report.get("source_after")
            and valid_stats(report.get("statistics")),
            "required-partial-restore-proof-missing",
        )
        require(
            [p["phase"] for p in report["phases"]]
            == [
                "input-admission",
                "controlled-partial-restore",
                "preservation",
                "expired-partial-refusal",
            ]
            and all(
                p["status"] == "passed" and valid_stats(p["statistics"]) for p in report["phases"]
            ),
            "required-partial-restore-phases-missing",
        )
        private, writer = report["private_inputs"], report["writer_gate"]
        expected = problem(PartialRestoreInterrupted())
        require(
            report["expected_failure"] == private.get("problem") == expected
            and report["phases"][1]["original_failure"] == expected
            and private.get("status") == "failed"
            and private.get("restored_inputs_admitted") is False
            and private.get("temporary_resources_removed") is True
            and "cleanup_problem" not in private
            and valid_stats(private.get("statistics")),
            "required-original-partial-failure-missing",
        )
        first = next(iter(DISK_BYTES))
        require(
            [p["phase"] for p in private["phases"]] == ["input-admission", first, "cleanup"]
            and all(
                p["status"] == "passed" and valid_stats(p["statistics"]) for p in private["phases"]
            )
            and set(report["partial_candidate"]["files"]) == {first}
            and report["partial_candidate"]["complete_input_count"] == len(DISK_BYTES),
            "required-partial-boundary-missing",
        )
        require(
            set(report["refusals"])
            == {
                "partial-admission",
                "partial-path",
                "foreign-enrollment",
                "substituted-directory",
                "expired-partial",
            }
            and report["refusals"]["partial-admission"]
            == problem(RestoreError("incomplete-restored-inputs"))
            and all(
                v == problem(RestoreError("restore-not-admitted"))
                for k, v in report["refusals"].items()
                if k != "partial-admission"
            )
            and writer.get("status") == "failed"
            and report.get("writer_admission_failure")
            == problem(RestoreError("restore-not-admitted"))
            and writer.get("lifetime_ended") is True
            and valid_stats(writer.get("statistics")),
            "required-partial-refusal-missing",
        )
        directory = Path(private["directory"]["path"])
        cleanup = private["phases"][-1]["paths"]
        expected_paths = {str(directory), *(str(directory / name) for name in DISK_BYTES)}
        require(
            len(cleanup) == len(expected_paths)
            and {p["path"] for p in cleanup} == expected_paths
            and all(p["absent"] is True for p in cleanup),
            "required-partial-cleanup-observation-missing",
        )
        with phase(report, "shared-resource-cleanup") as item:
            paths = [Path(p["path"]) for p in report["private_inputs"]["phases"][-1]["paths"]]
            canary = Path(report["unrelated_canary"]["path"])
            paths += [canary, canary.parent]
            item["paths"] = [
                {"path": str(p), "absent": not p.exists() and not p.is_symlink()} for p in paths
            ]
            require(all(p["absent"] for p in item["paths"]), "partial-restore-resource-remains")
        report.update(status="passed", resources_destroyed_with_guest=True)
    except BaseException as error:
        report["status"] = "failed"
        report.setdefault("problem", problem(error))
        raise
