"""Measured complete selected-transfer work, independent of unrelated history."""

from __future__ import annotations

from fishhat_contracts.workflow_transfer_history import validate_transfer_record

from tests.linear_support import assert_linear, measure
from tests.test_workflow_transfer_history import many_participant_record

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_transfer_history.py#validate_transfer_record",
        "release.toml#/engineering",
    ],
    "scope": "complete selected transfer participant and retained witness closure across sixteenfold extent",
    "relationship": "scoped-witness",
    "reason": "Actual Python, container and serialized-byte counters include schema validation, original phase joins and complete completion evidence. Fixtures are outside measurement. This establishes reference validation work only, not native lookup indexing, persistence, authentication or end-to-end orchestration.",
    "claims": ["engineering:workflow.transfer-record"],
}


def test_transfer_history_validation_linear_complete_witness_work():
    samples = []
    for count in (4, 16, 64):
        record = many_participant_record(count)
        _, work = measure(lambda record=record: validate_transfer_record(record))
        assert len(record["transfer"]["proposal"]["participants"]) == count
        assert len(record["transfer"]["accepted_phases"][1]["witnesses"]) == count
        samples.append((count, work))
    assert_linear(samples)
