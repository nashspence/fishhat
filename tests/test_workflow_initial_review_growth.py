"""Complete retained first-child binding work across growing participant extent."""

from __future__ import annotations

from fishhat_contracts.handoffs import validate_workflow
from fishhat_contracts.workflow_bindings import bind_workflow

from tests.linear_support import assert_linear, measure
from tests.test_workflow_initial_review import initial_request, initial_stage

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_bindings.py#validate_workflow_bindings",
        "release.toml#/engineering",
    ],
    "scope": "complete capsule validation including every first-child binding and retained installed phase-entry evidence",
    "relationship": "scoped-witness",
    "reason": "Actual Python, container and serialization counters cover sixteenfold growth in consumer participants and already-retained initial bindings. Setup is outside measurement. This establishes per-validation reference growth, not full repeated orchestration, native persistence or authentication.",
    "claims": ["engineering:workflow.bindings"],
}


def test_initial_binding_validation_linear_complete_history_work():
    samples = []
    for count in (4, 16, 64):
        value = initial_stage(consumers=count)
        for index in range(1, count + 1):
            query, trusted = initial_request(value, index)
            value = bind_workflow(query, value, **trusted)
        _, work = measure(lambda value=value: validate_workflow(value))
        assert len(value["bindings"]) == count
        assert len(value["proposal"]["participants"]) == count + 1
        assert all(not r["request"]["predecessors"] for r in value["bindings"])
        samples.append((count, work))
    assert_linear(samples)
