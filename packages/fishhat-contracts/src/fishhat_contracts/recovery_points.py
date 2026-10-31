"""Conservative data-age assessments; callers independently authenticate the inputs."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .bounds import Bounds, bounds
from .validation import ContractError, digest, validate

if TYPE_CHECKING:
    from .checkpoints import CheckpointInputs


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@bounds(
    Bounds(
        id="recovery-points.interval",
        work="O(B) complete fixed-field time interval and evidence identity",
        extent="Both inclusive UTC bounds and the exact supporting evidence digest",
        limits=(),
        capacity=(),
        proofs=("tests/test_recovery_points.py::test_time_interval_requires_ordered_bounds",),
        linear_proofs=(
            "tests/test_recovery_points.py::test_complete_recovery_assessment_linear_work",
        ),
    )
)
def validate_recovery_point(value: dict[str, Any] | None) -> None:
    """Validate ordered bounds; null explicitly means the data time is unknown."""
    if value is None:
        return
    validate("recovery-point.schema.json", value, "TimeInterval")
    _require(_instant(value["earliest"]) <= _instant(value["latest"]), "reversed time bounds")


def _microseconds(later: datetime, earlier: datetime) -> int:
    delta = later - earlier
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


@bounds(
    Bounds(
        id="recovery-points.assess",
        work="O(B + D) complete checkpoint and Snapshot bytes with indexed dataset joins",
        extent="Every selected dataset, its immutable data-time bounds and independent current clock",
        limits=(),
        capacity=("The receiving owner admits complete authenticated metadata before assessment",),
        proofs=(
            "tests/test_recovery_points.py::test_complete_set_uses_oldest_data_not_verification_time",
        ),
        linear_proofs=(
            "tests/test_recovery_points.py::test_complete_recovery_assessment_linear_work",
        ),
    )
)
def assess_recovery_point(
    checkpoint: dict[str, Any],
    inputs: CheckpointInputs,
    *,
    observed_at: dict[str, Any] | None,
    rpo_seconds: int,
) -> dict[str, Any]:
    """Assess complete resolved data, never receipt or verification freshness.

    The owner supplies ``inputs`` from authenticated ``resolve_checkpoint`` for
    this exact checkpoint and independently establishes the current clock bounds.
    Shape validation cannot authenticate either native fact. This observation
    grants no permission and adds no admission block. Independent datasets retain
    their original consistency scope; a minimum time is not an atomic snapshot.
    """
    from .checkpoints import validate_checkpoint

    validate_checkpoint(checkpoint)
    _require(inputs.checkpoint_digest == digest(checkpoint), "resolved recovery checkpoint changed")
    validate_recovery_point(observed_at)
    _require(
        type(rpo_seconds) is int and 1 <= rpo_seconds <= 9007199254740991,
        "invalid recovery-point objective",
    )
    _require(
        set(inputs.snapshots) == set(checkpoint["datasets"]), "incomplete recovery dataset set"
    )
    earliest: list[datetime] = []
    latest: list[datetime] = []
    known = observed_at is not None
    snapshot_digests: dict[str, str] = {}
    closure = set(checkpoint["recovery_closure"])
    for dataset, snapshot in inputs.snapshots.items():
        validate("adapter.schema.json", snapshot, "Snapshot")
        _require(snapshot["dataset"] == dataset, "recovery snapshot dataset changed")
        snapshot_digests[dataset] = digest(snapshot)
        point = snapshot["recovery_point"]
        validate_recovery_point(point)
        if point is None:
            known = False
            continue
        _require(
            point["evidence_digest"] in closure,
            "recovery point evidence is outside checkpoint closure",
        )
        low, high = _instant(point["earliest"]), _instant(point["latest"])
        earliest.append(low)
        latest.append(high)
        if observed_at is not None and high > _instant(observed_at["earliest"]):
            known = False
    result: dict[str, Any] = {
        "format": "deployment-ops/recovery-point-assessment/v1",
        "kind": "RecoveryPointAssessment",
        "checkpoint_digest": digest(checkpoint),
        "snapshot_digests": snapshot_digests,
        "observed_at": deepcopy(observed_at),
        "rpo_seconds": rpo_seconds,
        "state": "unknown",
        "age_lower_seconds": None,
        "age_upper_seconds": None,
    }
    if known:
        assert observed_at is not None
        lower = _microseconds(_instant(observed_at["earliest"]), min(latest)) // 1000000
        upper = (_microseconds(_instant(observed_at["latest"]), min(earliest)) + 999999) // 1000000
        result.update(age_lower_seconds=lower, age_upper_seconds=upper)
        if upper <= rpo_seconds:
            result["state"] = "within-objective"
        elif lower > rpo_seconds:
            result["state"] = "exceeded"
    validate("recovery-point.schema.json", result, "RecoveryPointAssessment")
    return result
