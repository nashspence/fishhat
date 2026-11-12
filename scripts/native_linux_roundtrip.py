"""Compare an older private restored boot with its witnessed newer stopped source."""

from __future__ import annotations

import copy
import json
import uuid
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest, GuestBootError
from scripts.native_linux_reboot import validate_canary
from scripts.native_linux_restart import canary_configuration, phase, problem
from scripts.native_linux_restore import RestoreSource, capture_projection
from scripts.native_linux_restored_boot import qualify_restored_boot
from scripts.native_linux_snapshots import DiskSnapshots
from scripts.run_stats import RunStats, valid_stats


class RestoredSuccessorError(GuestBootError):
    stage = "guest-restored-successor"


def require(value: Any, reason: str) -> None:
    if not value:
        raise RestoredSuccessorError(reason)


def probes(phases: list[dict[str, Any]]) -> list[str]:
    values = [p["observation"]["probe"] for p in phases if "probe" in p.get("observation", {})]
    for value in values:
        try:
            require(str(uuid.UUID(value)) == value, "invalid-canary-challenge")
        except (ValueError, TypeError, AttributeError):
            raise RestoredSuccessorError("invalid-canary-challenge") from None
    return values


def compare_restored_successor(
    source: Guest,
    custody: dict[str, Any],
    snapshots: DiskSnapshots,
    capture: dict[str, Any],
    transition: dict[str, Any],
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    launch: Callable[[Guest], AbstractContextManager[Path]],
    report: dict[str, Any],
) -> None:
    require(not report, "prepopulated-roundtrip-report")
    metrics = RunStats()
    report.update(
        status="failed",
        scope="owned-disposable-older-restored-newer-source-comparison-only",
        consistency="cold-bytes-after-controller-termination",
        snapshot_restore_qualified=False,
        product_authority_qualified=False,
        comparison_verified=False,
        resources_destroyed_with_guest=False,
        statistics_scope="comparison-through-private-disk-cleanup; shared teardown measured separately and by enclosing timeline",
        phases=[],
        restored_boot={},
    )
    try:
        with phase(report, "input-admission") as item:
            original = capture_projection(capture)
            guard = RestoreSource(source, copy.deepcopy(custody), snapshots, original)
            guard.verify()
            assert guard.current is not None
            later = copy.deepcopy(guard.current)
            unchanged_transition = copy.deepcopy(transition)
            before = canary_configuration(source)
            after = copy.deepcopy(transition["later_canary"])
            advance = transition["canary_advance"]
            require(
                transition.get("status") == advance.get("status") == "passed"
                and transition.get("later_source") == later
                and original["source"]["boot_identity"]["boot_id"]
                != later["boot_identity"]["boot_id"]
                and original["source"]["disks"]["root.qcow2"]["sha256"]
                != later["disks"]["root.qcow2"]["sha256"],
                "independently-witnessed-later-source-required",
            )
            require(
                advance["prior_canary"] == before["identity"]
                and advance["written_canary"] == advance["observed_canary"] == after["identity"]
                and before["identity"]["content"] != after["identity"]["content"]
                and before["identity"]["sha256"] != after["identity"]["sha256"],
                "independently-observed-different-source-canary-required",
            )
            require(
                [p.get("phase") for p in advance["phases"]]
                == [
                    "prior-observation",
                    "persist-different-bytes",
                    "independent-readback",
                ]
                and all(
                    p.get("status") == "passed" and valid_stats(p.get("statistics"))
                    for p in advance["phases"]
                )
                and valid_stats(advance.get("statistics")),
                "source-canary-proof-incomplete",
            )
            validate_canary(advance["phases"][0]["observation"], before)
            written, readback = advance["phases"][1:]
            require(written["observation"]["canary_fsynced"] is True, "source-canary-not-synced")
            for p in advance["phases"]:
                require(
                    json.loads(p["original_reply"]) == p["observation"],
                    "original-source-canary-reply-changed",
                )
                require(
                    p["observation"]["boot_id"] == later["boot_identity"]["boot_id"],
                    "source-canary-boot-changed",
                )
            validate_canary(written["observation"], after)
            validate_canary(readback["observation"], after)
            prior_probes = probes(source.report["reboot"]["phases"])
            prior_probes += probes(transition["phases"]) + probes(advance["phases"])
            require(len(prior_probes) == len(set(prior_probes)), "canary-challenge-reused")
            report.update(
                original_capture=copy.deepcopy(original),
                source_before=copy.deepcopy(later),
                original_canary=copy.deepcopy(before["identity"]),
                later_canary=copy.deepcopy(after["identity"]),
            )
            item["witnessed_later_source"] = copy.deepcopy(later)
        with phase(report, "private-restored-boot"):
            qualify_restored_boot(
                source,
                custody,
                snapshots,
                capture,
                temporary,
                progress,
                launch,
                report["restored_boot"],
            )
        with phase(report, "independent-comparison") as item:
            restored = report["restored_boot"]
            require(
                restored.get("status") == "passed"
                and restored.get("restored_boot_verified") is True
                and valid_stats(restored.get("statistics"))
                and restored.get("original_guest_evidence_preserved") is True
                and restored.get("expired_boot_handle_refused") is True
                and restored.get("expired_writable_handle_refused") is True,
                "restored-boot-proof-incomplete",
            )
            phases = restored["phases"]
            require(
                [p.get("phase") for p in phases]
                == [
                    "input-admission",
                    "prelaunch",
                    "independent-boot",
                    "independent-canary",
                    "refusals",
                    "final-observation",
                ]
                and all(
                    p.get("status") == "passed" and valid_stats(p.get("statistics")) for p in phases
                ),
                "restored-phase-proof-incomplete",
            )
            identity = restored["after_identity"]
            known_boots = {
                source.report["identity"]["boot_id"],
                source.report["reboot"]["phases"][0]["observation"]["boot_id"],
                original["source"]["boot_identity"]["boot_id"],
                later["boot_identity"]["boot_id"],
            }
            require(identity["boot_id"] not in known_boots, "restored-boot-not-distinct")
            observed_probes = probes(phases)
            require(
                len(observed_probes) == len(set(observed_probes)) == 3
                and not set(observed_probes).intersection(prior_probes),
                "canary-challenge-reused",
            )
            for p in phases[3:]:
                observed = p["observation"]
                require(
                    json.loads(p["original_reply"]) == observed, "original-canary-reply-changed"
                )
                require(observed["boot_id"] == identity["boot_id"], "restored-canary-boot-changed")
                validate_canary(observed, before)
            require(
                phases[4]["refused"] == ["stale-boot", "foreign-enrollment"],
                "restored-refusals-missing",
            )
            private = restored["private_inputs"]
            first, preserved = private["phases"][0], private["phases"][-2]
            require(
                private.get("originals_preserved") is True
                and first["observation"] == preserved["observation"] == original
                and first["source_before"] == preserved["source_after"] == later
                and restored["boot_inputs"]["source_before"] == later,
                "original-and-current-source-evidence-changed",
            )
            guard.verify()
            require(
                guard.current == later
                and capture_projection(capture) == original
                and transition == unchanged_transition
                and canary_configuration(source) == before,
                "roundtrip-source-preservation-failed",
            )
            report.update(
                source_after=copy.deepcopy(guard.current),
                restored_canary=copy.deepcopy(before["identity"]),
            )
            item["restored_identity"] = copy.deepcopy(identity)
            item["restored_canary"] = copy.deepcopy(phases[3]["observation"]["identity"])
        report.update(status="observed", comparison_verified=True)
    except BaseException as error:
        report["problem"] = problem(error)
        raise
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            report.update(status="failed", comparison_verified=False)
            raise ValueError("invalid required restored-successor statistics")


def finish_restored_successor(report: dict[str, Any]) -> None:
    try:
        with phase(report, "shared-resource-cleanup") as item:
            restored = report["restored_boot"]
            require(
                report.get("status") == "observed"
                and report.get("comparison_verified") is True
                and restored.get("resources_destroyed_with_guest") is True
                and restored.get("cleanup", {}).get("status") == "passed"
                and restored["cleanup"].get("ssh_endpoint_closed") is True
                and valid_stats(restored["cleanup"].get("statistics"))
                and valid_stats(report.get("statistics")),
                "roundtrip-cleanup-proof-incomplete",
            )
            item["observation"] = copy.deepcopy(restored["cleanup"])
    except BaseException as error:
        report.update(status="failed", problem=problem(error))
        raise
    report.update(status="passed", resources_destroyed_with_guest=True)
