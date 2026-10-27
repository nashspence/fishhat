"""RRset membership is unordered while each typed member retains its own meaning."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import check_response
from fishhat_contracts.dns import validate_changes, validate_rrsets
from fishhat_contracts.validation import ContractError, canonical

from tests.test_adapter_dns import change, rrset
from tests.test_adapter_handoffs import artifact, installed, invocation_for, response_for
from tests.test_adapter_invocations import recovered

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/dns-intent.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/dns-changes.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/dns-adapter.schema.json",
    ],
    "scope": "unordered RDATA membership, semantic no-op rejection and exact direct/reconciled DNS publication results",
    "relationship": "candidate",
    "reason": "Independent member-order and actual-content substitutions preserve accepted request bytes without claiming native DNS atomicity or live publication.",
    "claims": [],
}


def multi(typ="A"):
    value = rrset()
    if typ == "TXT":
        value.update(type="TXT", rdata=[{"chunks": ["a", "b"]}, {"chunks": ["c", "d"]}])
    else:
        value["rdata"].append({"address": "192.0.2.11"})
    return value


@pytest.mark.parametrize("typ", ["A", "TXT"])
def test_reordering_rdata_alone_is_not_a_dns_change(typ):
    before = multi(typ)
    after = copy.deepcopy(before)
    after["rdata"].reverse()
    validate_rrsets([after])
    with pytest.raises(ContractError, match="INVALID_RRSET_REPLACEMENT"):
        validate_changes(change(before, after))


@pytest.mark.parametrize("difference", ["addition", "removal", "ttl", "txt-chunks"])
def test_real_membership_ttl_or_ordered_member_content_still_changes_the_rrset(difference):
    before = multi("TXT" if difference == "txt-chunks" else "A")
    after = copy.deepcopy(before)
    if difference == "addition":
        after["rdata"].append({"address": "192.0.2.12"})
    elif difference == "removal":
        after["rdata"].pop()
    elif difference == "ttl":
        after["ttl"]["seconds"] = 30
    else:
        after["rdata"][0]["chunks"].reverse()
    validate_changes(change(before, after))


@pytest.mark.parametrize("typ", ["A", "TXT"])
@pytest.mark.parametrize("reconciliation", [False, True], ids=["direct", "lost-reply"])
def test_success_can_observe_identical_rrset_members_in_a_different_order(typ, reconciliation):
    _, executor = installed("dns")
    changes = change(after=multi(typ))
    changes["scope"] = copy.deepcopy(executor["scope"])
    original = {
        "contract": "fishhat.dns",
        "method": "publish",
        "input": {"scope": executor["scope"], "change": changes},
    }
    invocation = invocation_for(original)
    accepted_bytes = canonical(invocation)
    query = recovered(invocation) if reconciliation else original
    observed = copy.deepcopy(changes["changes"][0]["after"])
    observed["rdata"].reverse()
    reply = response_for(
        query,
        invocation["attempt"],
        {"rrsets": [observed], "served_generation": artifact("b")["digest"]},
    )
    check_response("dns", query, reply, invocation=invocation)
    assert canonical(invocation) == accepted_bytes
    observed["ttl"]["seconds"] = 30
    with pytest.raises(ContractError, match="SUCCESS_OUTPUT_IDENTITY"):
        check_response("dns", query, reply, invocation=invocation)
    observed["ttl"]["seconds"] = 0
    if typ == "TXT":
        observed["rdata"][0]["chunks"].reverse()
    else:
        observed["rdata"].pop()
    with pytest.raises(ContractError, match="SUCCESS_OUTPUT_IDENTITY"):
        check_response("dns", query, reply, invocation=invocation)


def test_empty_dns_change_is_still_rejected():
    with pytest.raises(ContractError, match="INVALID_RRSET_REPLACEMENT"):
        validate_changes(change())
