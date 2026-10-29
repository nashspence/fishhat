"""Retirement receipts distinguish absent incarnations from active quota enforcement."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import check_response
from fishhat_contracts.validation import ContractError

from tests.test_adapter_handoffs import installed, invocation_for, response_for

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/storage-adapter.schema.json",
    ],
    "scope": "exact retired allocation incarnation and historical quota preconditions",
    "relationship": "candidate",
    "reason": "Direct and lost-response reconciliation cases distinguish absent storage from live enforcement and reject replacement incarnations. Synthetic results do not prove native deletion or retained-data safety.",
    "claims": [],
}


def retirement(reconcile=False):
    _, executor = installed("storage")
    query = {
        "contract": "fishhat.storage",
        "method": "retire",
        "input": {
            "scope": executor["scope"],
            "allocation": "allocation:demo",
            "native_identity_digest": "sha256:" + "a" * 64,
            "capacity_bytes": 2048,
            "capacity_inodes": 10,
            "purposes": ["state", "logs"],
            "hard_isolation": True,
        },
    }
    invocation = invocation_for(query)
    receipt = {
        "allocation": "allocation:demo",
        "native_identity_digest": "sha256:" + "a" * 64,
        "state": "absent",
        "reviewed": {
            "capacity_bytes": 2048,
            "capacity_inodes": 10,
            "purposes": ["logs", "state"],
            "hard_isolation": True,
        },
        "observed_at": "2026-10-29T12:00:00Z",
    }
    if reconcile:
        query = {
            "contract": query["contract"],
            "method": "reconcile",
            "input": {"scope": executor["scope"], "invocation": invocation},
        }
    reply = response_for(query, invocation["attempt"], {"retirement": receipt})
    return query, invocation, reply


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
def test_retirement_success_records_absence_without_live_enforcement(reconcile):
    query, invocation, reply = retirement(reconcile)
    check_response("storage", query, reply, invocation=invocation)
    receipt = reply["output"]["retirement"]
    assert receipt["state"] == "absent"
    assert "counters" not in receipt and "hard_isolation" not in receipt
    assert receipt["reviewed"]["hard_isolation"] is True


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
@pytest.mark.parametrize(
    "change", ["allocation", "incarnation", "bytes", "inodes", "purposes", "isolation"]
)
def test_retirement_cannot_substitute_incarnation_or_reviewed_preconditions(change, reconcile):
    query, invocation, reply = retirement(reconcile)
    receipt = reply["output"]["retirement"]
    if change == "allocation":
        receipt["allocation"] = "allocation:replacement"
    elif change == "incarnation":
        receipt["native_identity_digest"] = "sha256:" + "b" * 64
    elif change == "bytes":
        receipt["reviewed"]["capacity_bytes"] = 0
    elif change == "inodes":
        receipt["reviewed"]["capacity_inodes"] = 0
    elif change == "purposes":
        receipt["reviewed"]["purposes"] = ["scratch"]
    else:
        receipt["reviewed"]["hard_isolation"] = False
    with pytest.raises(ContractError, match="RETIREMENT_OUTPUT_IDENTITY"):
        check_response("storage", query, reply, invocation=invocation)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
@pytest.mark.parametrize("shape", ["missing", "active-allocation", "live-counters"])
def test_retirement_cannot_claim_success_without_its_absence_receipt(shape, reconcile):
    query, invocation, reply = retirement(reconcile)
    if shape == "missing":
        reply["output"]["retirement"] = None
    elif shape == "active-allocation":
        reply["output"] = {"allocations": []}
    else:
        reply["output"]["retirement"]["counters"] = []
    with pytest.raises(ContractError):
        check_response("storage", query, reply, invocation=invocation)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
def test_unknown_retirement_preserves_uncertainty_without_an_absence_claim(reconcile):
    query, invocation, reply = retirement(reconcile)
    receipt = copy.deepcopy(reply["output"]["retirement"])
    reply["effect"].update(effect_certainty="unknown", postcondition="unknown")
    reply["coverage"] = "unknown"
    reply["output"]["retirement"] = None
    check_response("storage", query, reply, invocation=invocation)
    reply["output"]["retirement"] = receipt
    with pytest.raises(ContractError):
        check_response("storage", query, reply, invocation=invocation)
