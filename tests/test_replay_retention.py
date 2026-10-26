"""Terminal history is not the lifetime of an accepted request identity."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.validation import ContractError
from fishhat_owner.journal import Journal

from tests.test_contracts import OWNER, SUBJECT, uid

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/states.json#/rules",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/OperationPage",
    ],
    "scope": "epoch-lifetime accepted request reservations across terminal outcomes and restart",
    "relationship": "candidate",
    "reason": "A minimal SQLite reference journal retains exact terminal outcomes, original attribution and changed-payload rejection beyond admission expiry and later work. These cases do not qualify native history compaction, restoration or storage-capacity policy.",
    "claims": [],
}


def submit(journal, request_id, *, subject=SUBJECT, now=100, expires=200, generation=0):
    return journal.submit(
        request_id,
        subject,
        principal="original-operator",
        authorized=True,
        expected_epoch=OWNER["epoch"],
        expected_generation=generation,
        expires=expires,
        now=now,
    )


@pytest.mark.parametrize(
    "state,effect",
    [
        ("succeeded", "known"),
        ("failed", "none"),
        ("failed", "unknown"),
        ("cancelled", "none"),
        ("cancelled", "known"),
        ("quarantined", "unknown"),
    ],
)
def test_terminal_identity_is_reserved_after_restart_and_admission_expiry(tmp_path, state, effect):
    path = tmp_path / "owner.sqlite"
    identity = uid("retained-terminal-request")
    journal = Journal(path, OWNER["id"], OWNER["epoch"], initialize=True)
    submit(journal, identity)
    journal.transition(identity, "running", "unknown")
    journal.transition(identity, state, effect)
    journal.close()
    journal = Journal(path, OWNER["id"], OWNER["epoch"])
    try:
        statements = []
        journal.db.set_trace_callback(statements.append)
        replay = journal.submit(
            identity,
            SUBJECT,
            principal="replacement-operator",
            authorized=True,
            expected_epoch=OWNER["epoch"],
            expected_generation=0,
            expires=200,
            now=1000000,
        )
        assert replay == {
            "request_id": identity,
            "principal": "original-operator",
            "state": state,
            "effect": effect,
        }
        assert not any(s.startswith(("INSERT", "UPDATE", "DELETE")) for s in statements)
        changed = copy.deepcopy(SUBJECT)
        changed["arguments"]["components"] = ["different-component"]
        with pytest.raises(ContractError, match="same ID changed payload"):
            submit(journal, identity, subject=changed, now=1000000)
        assert journal.db.execute("SELECT count(*) FROM requests").fetchone() == (1,)
    finally:
        journal.close()


def test_later_successful_work_cannot_make_original_identity_new(tmp_path):
    journal = Journal(tmp_path / "owner.sqlite", OWNER["id"], OWNER["epoch"], initialize=True)
    identity = uid("first-retained-request")
    try:
        submit(journal, identity)
        journal.transition(identity, "running", "unknown")
        journal.transition(identity, "succeeded", "known")
        for number in range(1, 9):
            later = uid(f"later-retained-request-{number}")
            submit(journal, later, generation=number, expires=2000, now=1000)
            journal.transition(later, "running", "unknown")
            journal.transition(later, "succeeded", "known")
        assert journal.generation == 9
        assert submit(journal, identity, now=1000000)["state"] == "succeeded"
        with pytest.raises(ContractError, match="same ID changed payload"):
            submit(journal, identity, generation=9, expires=2000000, now=1000000)
        assert journal.db.execute("SELECT count(*) FROM requests").fetchone() == (9,)
    finally:
        journal.close()
