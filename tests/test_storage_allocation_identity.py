"""Exact allocation preimages survive native result and reconciliation boundaries."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import check_invocation, check_request, check_response
from fishhat_contracts.validation import ContractError, digest

from tests.test_adapter_handoffs import installed, invocation_for, response_for
from tests.test_adapter_invocations import recovered
from tests.test_adapter_quantities import counter

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/storage-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resources.schema.json",
    ],
    "scope": "explicit allocation creation or exact native incarnation update and retained result identity",
    "relationship": "candidate",
    "reason": "Independent target, domain and recovery substitutions exercise the typed boundary; actual absence, native exclusion and quota enforcement remain unqualified executor duties.",
    "claims": [],
}


def allocation_case(kind="update-exact", *, reconcile=False):
    _, executor = installed("storage")
    precondition = {"kind": kind, "accounting_domain": "domain:approved"}
    if kind == "update-exact":
        precondition["native_identity_digest"] = "sha256:" + "a" * 64
    request = {
        "contract": "fishhat.storage",
        "method": "allocate",
        "input": {
            "scope": executor["scope"],
            "allocation": "allocation:demo",
            "precondition": precondition,
            "capacity_bytes": 2048,
            "capacity_inodes": 10,
            "purposes": ["state"],
            "hard_isolation": True,
        },
    }
    invocation = invocation_for(request)
    allocation = {
        "handle": "allocation:demo",
        "accounting_domain": "domain:approved",
        "purposes": ["state"],
        "native_identity_digest": "sha256:" + "a" * 64,
        "counters": [counter("storage-used", 0)],
        "hard_isolation": True,
        "capacity_bytes": 2048,
        "capacity_inodes": 10,
    }
    query = recovered(invocation) if reconcile else request
    reply = response_for(query, invocation["attempt"], {"allocations": [allocation]})
    return query, invocation, reply


@pytest.mark.parametrize("method", ["plan", "allocate"])
@pytest.mark.parametrize("kind", ["create-if-absent", "update-exact"])
def test_storage_review_distinguishes_absent_creation_from_exact_update(method, kind):
    query, _, _ = allocation_case(kind)
    query["method"] = method
    check_request("storage", query)
    previous = digest(query)
    query["input"]["precondition"]["accounting_domain"] = "domain:other"
    assert digest(query) != previous
    del query["input"]["precondition"]
    with pytest.raises(ContractError):
        check_request("storage", query)


@pytest.mark.parametrize(
    "precondition",
    [
        {"kind": "upsert", "accounting_domain": "domain:approved"},
        {"kind": "update-exact", "accounting_domain": "domain:approved"},
        {"kind": "create-if-absent"},
        {
            "kind": "create-if-absent",
            "accounting_domain": "domain:approved",
            "native_identity_digest": "sha256:" + "a" * 64,
        },
    ],
    ids=["implicit-upsert", "missing-incarnation", "missing-domain", "mixed-preimages"],
)
def test_storage_preimages_have_no_implicit_or_mixed_form(precondition):
    query, _, _ = allocation_case()
    query["input"]["precondition"] = precondition
    with pytest.raises(ContractError):
        check_request("storage", query)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
@pytest.mark.parametrize("change", ["incarnation", "domain", "handle", "absence"])
def test_storage_update_success_cannot_replace_the_reviewed_allocation(change, reconcile):
    query, invocation, reply = allocation_case(reconcile=reconcile)
    check_response("storage", query, reply, invocation=invocation)
    allocation = reply["output"]["allocations"][0]
    if change == "incarnation":
        allocation["native_identity_digest"] = "sha256:" + "b" * 64
    elif change == "domain":
        allocation["accounting_domain"] = "domain:other"
    elif change == "handle":
        allocation["handle"] = "allocation:other"
        allocation["counters"][0]["allocation"] = "allocation:other"
    else:
        reply["output"]["allocations"] = []
    with pytest.raises(ContractError):
        check_response("storage", query, reply, invocation=invocation)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
def test_storage_creation_returns_its_new_identity_in_the_approved_domain(reconcile):
    query, invocation, reply = allocation_case("create-if-absent", reconcile=reconcile)
    check_response("storage", query, reply, invocation=invocation)
    assert reply["output"]["allocations"][0]["native_identity_digest"]
    reply["output"]["allocations"][0]["accounting_domain"] = "domain:other"
    with pytest.raises(ContractError, match="SUCCESS_OUTPUT_IDENTITY"):
        check_response("storage", query, reply, invocation=invocation)


@pytest.mark.parametrize("change", ["mode", "incarnation", "domain"])
def test_storage_recovery_cannot_replace_the_original_allocation_preimage(change):
    query, invocation, reply = allocation_case(reconcile=True)
    original = copy.deepcopy(invocation)
    precondition = invocation["request"]["input"]["precondition"]
    if change == "mode":
        precondition["kind"] = "create-if-absent"
        del precondition["native_identity_digest"]
    elif change == "incarnation":
        precondition["native_identity_digest"] = "sha256:" + "b" * 64
    else:
        precondition["accounting_domain"] = "domain:other"
    with pytest.raises(ContractError, match="INVOCATION_IDENTITY"):
        check_invocation("storage", invocation)
    invocation["attempt"]["input_digest"] = digest(invocation["request"])
    check_invocation("storage", invocation)
    with pytest.raises(ContractError, match="RECONCILIATION_IDENTITY"):
        check_response("storage", query, reply, invocation=invocation)
    assert query["input"]["invocation"] == original
