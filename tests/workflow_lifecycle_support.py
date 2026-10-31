"""Synthetic native lifecycle context for decoded contract tests."""

from __future__ import annotations

import copy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_contracts.validation import digest
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_lifecycle import lifecycle_destination, record_native_lifecycle_view

from tests.test_contracts import uid
from tests.test_owner_handoffs import operation


def lifecycle_decision(value, action):
    result = {
        "owner": copy.deepcopy(value["owner"]),
        "workflow_id": value["id"],
        "advance_id": uid(f"lifecycle-{value['id']}-{value['generation']}-{action}"),
        "proposal_digest": value["proposal_digest"],
        "procedure": value["type"],
        "expected_generation": value["generation"],
        "driver_term": value["driver_term"],
        "phase": value["phase"],
        "from_state": value["state"],
        "action": action,
        "request": None,
    }
    return seal_lifecycle(result, value)


def seal_lifecycle(decision, value):
    body = {k: v for k, v in operation()["witness"].items() if k != "signature"}
    body.update(
        id=uid("lifecycle-witness-" + decision["advance_id"]),
        owner=copy.deepcopy(decision["owner"]),
        kind="approval",
        workflow_id=decision["workflow_id"],
        subject_digest=digest({k: v for k, v in decision.items() if k != "witness"}),
        generation=decision["expected_generation"] + 1,
        state=lifecycle_destination(decision, value),
        evidence_digests=[],
    )
    decision["witness"] = sign(body, Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))
    return decision


def lifecycle(value, action, **changes):
    decision = lifecycle_decision(value, action)
    context = {
        "expected_owner": value["owner"],
        "native_authorized": True,
        "verified_decision": copy.deepcopy(decision),
        "verified_driver": {"principal": value["driver_principal"], "term": value["driver_term"]},
        "verified_reconciled": True,
    }
    context.update(changes)
    return record_native_lifecycle_view(decision, value, **context)
