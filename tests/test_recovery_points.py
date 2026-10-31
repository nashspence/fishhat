"""Data age uses complete authenticated captures and conservative clock bounds."""

from copy import deepcopy

import pytest
from fishhat_contracts import recovery_points
from fishhat_contracts.recovery_points import assess_recovery_point, validate_recovery_point
from fishhat_contracts.validation import ContractError, digest

from tests.linear_support import assert_linear, measure
from tests.test_checkpoint_resolution import fixture, resolve_checkpoint, seal

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/recovery-point.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json#/$defs/Snapshot",
    ],
    "scope": "immutable captured-data time, complete multi-dataset aggregation and independent current clock uncertainty",
    "relationship": "candidate",
    "reason": "Authenticated synthetic receipts and adverse temporal substitutions challenge deterministic data-age assessment; clock truth and native capture remain owner obligations.",
    "claims": [],
}
CHECK_OVERRIDES = {
    name: {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/recovery_points.py#" + function
            for function in functions
        ],
        "scope": "ordered time intervals and conservative complete checkpoint data-age assessment",
        "relationship": "scoped-witness",
        "reason": "Executed reference validation covers complete metadata and increasing dataset extent without inferring native clock or capture qualification.",
        "claims": ["engineering:recovery-points." + claim for claim in claims],
    }
    for name, functions, claims in (
        ("test_time_interval_requires_ordered_bounds", ("validate_recovery_point",), ("interval",)),
        (
            "test_complete_set_uses_oldest_data_not_verification_time",
            ("assess_recovery_point",),
            ("assess",),
        ),
        (
            "test_complete_recovery_assessment_linear_work",
            ("validate_recovery_point", "assess_recovery_point"),
            ("interval", "assess"),
        ),
    )
}


def interval(earliest, latest=None):
    return {
        "earliest": earliest,
        "latest": latest or earliest,
        "evidence_digest": digest([earliest, latest]),
    }


NOW = interval("2026-10-25T00:00:00Z")
OLD = interval("2026-10-24T00:00:00Z")
FRESH = interval("2026-10-24T23:59:50Z")


def resolved(points):
    checkpoint, context, _ = fixture(
        len(points),
        recovery_points={f"dataset-{index:04d}": point for index, point in enumerate(points)},
    )
    return checkpoint, resolve_checkpoint(checkpoint, **context), context


def test_time_interval_requires_ordered_bounds():
    validate_recovery_point(OLD)
    validate_recovery_point(None)
    with pytest.raises(ContractError, match="reversed time"):
        validate_recovery_point(interval(NOW["earliest"], OLD["latest"]))


def test_complete_set_uses_oldest_data_not_verification_time():
    checkpoint, inputs, context = resolved([FRESH, OLD])
    result = assess_recovery_point(checkpoint, inputs, observed_at=NOW, rpo_seconds=3600)
    assert result["state"] == "exceeded"
    assert result["age_lower_seconds"] == result["age_upper_seconds"] == 86400
    changed = deepcopy(checkpoint)
    changed["verified_at"] = NOW["earliest"]
    seal(changed)
    context["expected_checkpoint_digest"] = digest(changed)
    refreshed = resolve_checkpoint(changed, **context)
    assert refreshed.snapshots == inputs.snapshots
    after = assess_recovery_point(changed, refreshed, observed_at=NOW, rpo_seconds=3600)
    assert (after["state"], after["age_lower_seconds"], after["age_upper_seconds"]) == (
        "exceeded",
        86400,
        86400,
    )


@pytest.mark.parametrize(
    "points,clock",
    [
        ([FRESH, None], NOW),
        ([FRESH], None),
        ([interval("2026-10-25T00:00:01Z")], NOW),
        ([interval("2026-10-24T23:59:59Z", "2026-10-25T00:00:01Z")], NOW),
    ],
)
def test_unestablished_data_or_clock_order_is_unknown(points, clock):
    checkpoint, inputs, _ = resolved(points)
    result = assess_recovery_point(checkpoint, inputs, observed_at=clock, rpo_seconds=3600)
    assert result["state"] == "unknown"
    assert result["age_lower_seconds"] is None and result["age_upper_seconds"] is None


def test_uncertainty_crossing_objective_cannot_claim_success_or_violation():
    checkpoint, inputs, _ = resolved([interval("2026-10-24T23:59:48Z", "2026-10-24T23:59:52Z")])
    result = assess_recovery_point(checkpoint, inputs, observed_at=NOW, rpo_seconds=10)
    assert (result["state"], result["age_lower_seconds"], result["age_upper_seconds"]) == (
        "unknown",
        8,
        12,
    )


def test_clock_and_fractional_rounding_are_conservative():
    checkpoint, inputs, _ = resolved([interval("2026-10-24T23:59:59Z")])
    clock = interval("2026-10-25T00:00:00Z", "2026-10-25T00:00:00.000001Z")
    result = assess_recovery_point(checkpoint, inputs, observed_at=clock, rpo_seconds=1)
    assert (result["state"], result["age_lower_seconds"], result["age_upper_seconds"]) == (
        "unknown",
        1,
        2,
    )
    assert (
        assess_recovery_point(checkpoint, inputs, observed_at=clock, rpo_seconds=2)["state"]
        == "within-objective"
    )


def test_assessment_cannot_omit_an_old_dataset_or_relabel_checkpoint():
    checkpoint, inputs, _ = resolved([FRESH, OLD])
    del inputs.snapshots["dataset-0001"]
    with pytest.raises(ContractError, match="incomplete recovery"):
        assess_recovery_point(checkpoint, inputs, observed_at=NOW, rpo_seconds=3600)
    other, _, _ = resolved([FRESH])
    with pytest.raises(ContractError, match="checkpoint changed"):
        assess_recovery_point(other, inputs, observed_at=NOW, rpo_seconds=3600)


def test_snapshot_time_evidence_must_remain_in_checkpoint_custody():
    checkpoint, _, context = resolved([OLD])
    checkpoint["recovery_closure"].remove(OLD["evidence_digest"])
    seal(checkpoint)
    context["expected_checkpoint_digest"] = digest(checkpoint)
    with pytest.raises(ContractError, match="recovery-point evidence"):
        resolve_checkpoint(checkpoint, **context)


def test_complete_recovery_assessment_linear_work():
    samples = []
    for count in (4, 16, 64):
        checkpoint, inputs, _ = resolved([OLD] * count)
        _, work = measure(
            lambda checkpoint=checkpoint, inputs=inputs: assess_recovery_point(
                checkpoint, inputs, observed_at=NOW, rpo_seconds=3600
            ),
            modules=(recovery_points,),
        )
        samples.append((count, work))
    assert_linear(samples)
