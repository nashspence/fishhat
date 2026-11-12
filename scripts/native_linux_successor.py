"""Bind one witnessed original-disk successor to an exact active cold capture."""

from __future__ import annotations

import copy
import tempfile
import uuid
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest
from scripts.native_linux_images import digest, identity
from scripts.native_linux_reboot import host_custody, qualify_canary_advance
from scripts.native_linux_restart import (
    canary_configuration,
    observe_replacement,
    phase,
    problem,
    retained_boot_inputs,
    stopped_replacement,
)
from scripts.native_linux_snapshots import DiskSnapshots, require, stopped_source
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import Deadline


def source_binding(source: Guest) -> tuple[Any, ...]:
    """Freeze metadata that cannot change when the owned disks acquire new bytes."""
    return (
        id(source.inputs),
        id(source.command),
        id(source.process),
        copy.deepcopy(source.process.args) if source.process is not None else None,
        source.enrollment,
        source.inputs.directory,
        source.inputs.directory_identity,
        copy.deepcopy(source.inputs.files),
        source.directory,
        source.directory_identity,
        copy.deepcopy(source.files),
        copy.deepcopy(source.tools),
        source.qemu,
        source.port,
        copy.deepcopy(source.observed),
    )


class CaptureLifetime:
    def __init__(
        self,
        source: Guest,
        custody: dict[str, Any],
        snapshots: DiskSnapshots,
        before: dict[str, Any],
        temporary: Path,
        capture: dict[str, Any],
        image_tool: Path,
    ) -> None:
        self._source = source
        self._custody = copy.deepcopy(custody)
        self._snapshots = snapshots
        self._sealed = copy.deepcopy(snapshots.closure())
        self._image_tool = image_tool
        self._image_tool_hash = capture["image_tool"]["binary_sha256"]
        self._before = copy.deepcopy(before)
        self._temporary = temporary
        self._capture = capture
        self._capture_keys = tuple(k for k, v in source.report.items() if v is capture)
        self._original_capture = copy.deepcopy(capture)
        # Empty result slots and later reports carry no original accepted evidence.
        self._original_report = copy.deepcopy(
            {k: v for k, v in source.report.items() if v is not capture and v != {}}
        )
        self._binding = source_binding(source)
        self._anchor = (source, copy.deepcopy(custody), copy.deepcopy(before))
        self._active = True
        self._attempted = False
        self._advanced = False

    @property
    def advanced(self) -> bool:
        return self._advanced

    def bound_to(self, snapshots: DiskSnapshots) -> bool:
        return self._snapshots is snapshots

    def expire(self) -> None:
        self._active = False

    def _protected(self, enrollment: str) -> None:
        require(
            self._active and self._snapshots.active and self._snapshots._source_owner is self,
            "capture-source-handle-expired",
        )
        require(enrollment == self._before["enrollment"], "foreign-capture-source-enrollment")
        require(self._snapshots.closure() == self._sealed, "capture-sealed-custody-changed")
        self._snapshots.verify()
        require(
            digest(self._image_tool) == self._image_tool_hash,
            "image-tool-changed",
        )
        require(source_binding(self._source) == self._binding, "capture-source-binding-changed")
        require(
            all(self._source.report.get(k) is self._capture for k in self._capture_keys),
            "original-capture-report-rebound",
        )
        require(
            all(
                k in self._capture and self._capture[k] == v
                for k, v in self._original_capture.items()
            ),
            "original-capture-evidence-changed",
        )
        require(
            all(
                k in self._source.report and self._source.report[k] == v
                for k, v in self._original_report.items()
            ),
            "original-guest-evidence-changed",
        )
        self._source.inputs.verify(enrollment)
        self._source.verify_tools()
        for name in self._source.files:
            self._source.path(name)

    def observation(self, enrollment: str) -> dict[str, Any]:
        self._protected(enrollment)
        guest, custody, accepted = self._anchor
        observed = stopped_source(guest, custody)
        require(observed == accepted, "source-changed")
        return copy.deepcopy(observed)

    def advance(
        self,
        enrollment: str,
        progress: Callable[[str], AbstractContextManager[None]],
        launch: Callable[[Guest], AbstractContextManager[Path]],
        report: dict[str, Any],
    ) -> dict[str, Any]:
        require(not self._attempted, "capture-source-already-attempted")
        self.observation(enrollment)
        require(not report, "successor-report-not-empty")
        canary_configuration(self._source)
        self._attempted = True
        try:
            result = observe_successor(
                self._source,
                self._custody,
                self._before,
                self._temporary,
                progress,
                launch,
                lambda: self._protected(enrollment),
                report,
            )
            self._protected(enrollment)
            guest, custody, after = result
            require(stopped_source(guest, custody) == after, "successor-source-changed")
            self._anchor = (guest, copy.deepcopy(custody), copy.deepcopy(after))
            self._advanced = True
            return copy.deepcopy(after)
        except BaseException as error:
            report["status"] = "failed"
            report.setdefault("problem", problem(error))
            raise


def observe_successor(
    source: Guest,
    custody: dict[str, Any],
    before: dict[str, Any],
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    launch: Callable[[Guest], AbstractContextManager[Path]],
    verify: Callable[[], None],
    report: dict[str, Any],
) -> tuple[Guest, dict[str, Any], dict[str, Any]]:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="owned-disposable-observed-source-successor-only",
        consistency="cold-bytes-after-controller-termination",
        snapshot_restore_qualified=False,
        product_authority_qualified=False,
        phases=[],
        boot_inputs={},
        guest={},
        canary_advance={},
    )
    complete = False
    child: Guest | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="fhsc-", dir=temporary) as folder:
            unrelated = Path(folder) / "unrelated"
            content = uuid.uuid4().bytes
            unrelated.write_bytes(content)
            unrelated.chmod(0o600)
            original = identity(unrelated), unrelated.stat().st_mtime_ns
            try:
                with retained_boot_inputs(
                    source, custody, report["boot_inputs"], expected_source=before
                ) as retained:
                    with phase(report, "input-admission") as item:
                        verify()
                        c = canary_configuration(source)
                        child = retained.guest(source.enrollment, report["guest"])
                        item["source_before"] = copy.deepcopy(before)
                    try:
                        with progress("guest-source-successor"), launch(child) as endpoint:
                            with phase(report, "prelaunch") as item:
                                verify()
                                retained.verify()
                                require(
                                    child.report["controller_verified"]
                                    == retained.expected["controller_profile"],
                                    "successor-controller-profile-changed",
                                )
                                item["controller"] = copy.deepcopy(
                                    child.report["controller_verified"]
                                )
                            observe_replacement(child, source, endpoint, c, report)
                            assert child.observed is not None
                            prior_probes = [
                                p["observation"]["probe"]
                                for p in report["phases"]
                                if "observation" in p
                            ]
                            original_probes = {
                                p["observation"]["probe"]
                                for p in source.report["reboot"]["phases"]
                                if "observation" in p
                            }
                            require(
                                len(prior_probes) == len(set(prior_probes))
                                and not original_probes.intersection(prior_probes),
                                "canary-challenge-reused",
                            )
                            deadline = Deadline.after(600)
                            updated = qualify_canary_advance(
                                child,
                                child.observed,
                                c,
                                deadline,
                                report["canary_advance"],
                                prior_probes=frozenset([*original_probes, *prior_probes]),
                            )
                            with phase(report, "written-source-custody") as item:
                                observed = child.observe(deadline)
                                child.validate_profile(observed)
                                require(observed == child.observed, "successor-boot-changed")
                                current = host_custody(child, endpoint, deadline)
                                require(
                                    current == report["controller_custody"],
                                    "successor-custody-changed",
                                )
                                item["host_custody"] = copy.deepcopy(current)
                                item["identity"] = copy.deepcopy(observed)
                                verify()
                                retained.verify()
                    except BaseException as error:
                        report["problem"] = problem(error)
                        raise
                    finally:
                        if child.process is not None:
                            try:
                                with phase(report, "stopped-successor") as item:
                                    item["observation"] = stopped_replacement(child)
                            except BaseException as error:
                                report["cleanup_problem"] = problem(error)
                                raise
                    with phase(report, "later-stopped-source") as item:
                        after = stopped_source(child, current)
                        require(
                            set(after["disks"]) == set(before["disks"])
                            and all(
                                {k: v for k, v in disk.items() if k not in ("bytes", "sha256")}
                                == {
                                    k: v
                                    for k, v in before["disks"][name].items()
                                    if k not in ("bytes", "sha256")
                                }
                                for name, disk in after["disks"].items()
                            ),
                            "successor-source-disk-custody-changed",
                        )
                        require(
                            after["disks"]["root.qcow2"]["sha256"]
                            != before["disks"]["root.qcow2"]["sha256"],
                            "source-bytes-not-advanced",
                        )
                        require(
                            after["boot_identity"]["boot_id"] != before["boot_identity"]["boot_id"],
                            "successor-boot-not-distinct",
                        )
                        item["observation"] = copy.deepcopy(after)
                        report["later_source"] = copy.deepcopy(after)
                        report["later_canary"] = copy.deepcopy(updated)
                        verify()
            finally:
                require(
                    unrelated.read_bytes() == content
                    and (identity(unrelated), unrelated.stat().st_mtime_ns) == original,
                    "unrelated-successor-canary-changed",
                )
                report["unrelated_canary_preserved"] = True
        verify()
        complete = True
        return child, current, after
    except BaseException as error:
        report.setdefault("problem", problem(error))
        raise
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            report["status"] = "failed"
            raise ValueError("invalid required source successor statistics")
        if complete:
            report["status"] = "passed"
