"""Actual complete-input validation work for independent child and binding growth."""

from __future__ import annotations

import pytest
from fishhat_contracts.handoffs import validate_workflow
from fishhat_contracts.workflow_recovery import validate_recovery_proposal

from tests.linear_support import assert_linear, measure
from tests.test_workflow_recovery import commit, prepare, scenario
from tests.workflow_growth_support import (
    chain,
    count_child_indexes,
    count_recovery_joins,
    unprepared_owners,
)

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_recovery.py#validate_recovery_proposal",
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_bindings.py#validate_workflow_bindings",
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_recovery.py#validate_recovery_custody",
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_unprepared.py#validate_never_prepared",
        "release.toml#/engineering",
    ],
    "scope": "complete recovery validation over child-only, causal binding, never-prepared owner and retained recovery preparation extents",
    "relationship": "scoped-witness",
    "reason": "Fully validated origin capsules and successor proposals exercise sixteenfold growth with executed Python, serialization and container counters plus actual complete child-index, full-proposal hash and ordered owner-closure visits. Nested recovered capsules validate their complete preparation custody. Setup remains outside measurement; no count cap or timing target is introduced. This is reference work evidence, not native recovery qualification.",
    "claims": ["engineering:workflow.recovery-proposal"],
}

CHECK_OVERRIDES = {
    "test_recovery_validation_linear_child_and_binding_work": {
        **CHECK_PURPOSE,
        "scope": "complete retained binding and recovery-proposal validation across child-only and causal-binding extents",
        "reason": "Sixteenfold child and retained-binding growth measures actual complete capsule validation within recovery validation, including the binding validator and child indexes. Setup remains outside measurement. This is reference work evidence, not native recovery qualification or end-to-end orchestration.",
        "claims": ["engineering:workflow.recovery-proposal", "engineering:workflow.bindings"],
    }
}


@pytest.mark.parametrize("bound", [False, True], ids=["child-only", "causal-bindings"])
def test_recovery_validation_linear_child_and_binding_work(monkeypatch, bound):
    samples, indexes = [], []
    for count in (4, 16, 64):
        value = chain(count, bound=bound)
        outcomes = {
            receipt["request"]["predecessors"][0]["request_id"]: receipt["request"]["predecessors"][
                0
            ]
            for receipt in value["bindings"]
        }
        kinds = ["completed"] * count + ["unaccepted"] if bound else ["unaccepted"] * (count + 1)
        proposal, records = scenario(original=value, kinds=kinds, outcomes=outcomes)
        with monkeypatch.context() as patch:
            counts = count_child_indexes(patch)
            _, work = measure(
                lambda proposal=proposal, records=records: validate_recovery_proposal(
                    proposal, verified_origins=records
                )
            )
        assert len(proposal["children"]) == count + 1
        assert len(records[0]["record"]["bindings"]) == (count if bound else 0)
        assert counts["indexed_children"] > 0
        samples.append((count, work))
        indexes.append((count, counts))
    assert_linear(samples)
    assert_linear(indexes)


def test_recovery_validation_linear_unprepared_owner_work(monkeypatch):
    samples, joins = [], []
    for count in (2, 8, 32):
        proposal, records = unprepared_owners(count)
        with monkeypatch.context() as patch:
            counts = count_recovery_joins(patch)
            _, work = measure(
                lambda proposal=proposal, records=records: validate_recovery_proposal(
                    proposal, verified_origins=records
                )
            )
        assert len(records) == count + 1
        assert sum("record" in origin for origin in records) == 1
        assert counts["original_proposal_hashes"] == 1
        assert counts["original_participants_hashed"] == count + 1
        assert counts["unprepared_local_participants"] == count
        samples.append((count, work))
        joins.append((count, counts))
    assert_linear(samples)
    assert_linear(joins)


def test_retained_recovery_preparations_linear_owner_work(monkeypatch):
    samples, joins = [], []
    for count in (2, 8, 32):
        proposal, records = unprepared_owners(count)
        _, value = commit(prepare(proposal, records), proposal)
        with monkeypatch.context() as patch:
            counts = count_recovery_joins(patch)
            _, work = measure(lambda value=value: validate_workflow(value))
        assert len(value["recovery"]["preparations"]) == count + 1
        assert counts["preparation_indexes"] == 1
        assert counts["preparation_owners_indexed"] == count + 1
        assert counts["recovery_proposal_hashes"] > 0
        samples.append((count, work))
        joins.append((count, counts))
    assert_linear(samples)
    assert_linear(joins)
