"""The introduced append-only format preserves original accepted custody."""

import json
from pathlib import Path

import pytest
from fishhat_contracts.validation import ContractError, strict_json
from fishhat_owner.workflow_journal import WorkflowJournal

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "fishhat/owner-support/src/fishhat_owner/workflow_journal.py",
        "state/inventory.toml",
        "state/fixtures/v1/workflow-journal.json",
    ],
    "scope": "immutable introduced workflow journal format and exact accepted input and outcome bytes",
    "relationship": "candidate",
    "reason": "Cold restoration and replay preserve the original durable bytes and receipt without creating new accepted work. This fixture exercises reference storage, not native filesystem qualification.",
    "claims": [],
}


def test_original_workflow_journal_fixture_preserves_exact_input_and_outcome(tmp_path):
    fixture_path = Path(__file__).resolve().parents[1] / "state/fixtures/v1/workflow-journal.json"
    fixture = json.loads(fixture_path.read_text())
    path = tmp_path / "journal"
    path.write_bytes(bytes.fromhex(fixture["journal_hex"]))
    head = path.with_name("journal.head")
    head.write_bytes(bytes.fromhex(fixture["head_hex"]))
    original_bytes = path.read_bytes(), head.read_bytes()
    journal = WorkflowJournal.open(
        path, expected_owner=fixture["owner"], expected_schema=fixture["schema"]
    )
    try:
        command = journal.command_bytes(fixture["event_id"], read_authorized=True)
        outcome = journal.outcome_bytes(fixture["event_id"], read_authorized=True)
        assert command == bytes.fromhex(fixture["command_hex"])
        assert outcome == bytes.fromhex(fixture["outcome_hex"])
        replay = journal.append(
            fixture["event_id"],
            strict_json(command, max_bytes=len(command)),
            strict_json(outcome, max_bytes=len(outcome)),
            expected_head="stale-replay-predecessor",
        )
        assert replay["receipt"] == fixture["receipt"]
        assert len(list(journal.iter_events(read_authorized=True))) == 1
        with pytest.raises(ContractError):
            journal.command_bytes(fixture["event_id"], read_authorized=False)
    finally:
        journal.close()
    assert original_bytes == (path.read_bytes(), head.read_bytes())
