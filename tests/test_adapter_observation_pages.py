"""Shared collection extent and continuation rules across typed adapter roles."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import check_response
from fishhat_contracts.validation import ContractError, digest

from tests.test_adapter_handoffs import artifact, installed
from tests.test_adapter_quantities import counter, limit

ROLES = (
    "backup",
    "build",
    "compute",
    "credential-issuer",
    "dns",
    "ingress",
    "network",
    "report",
    "repository",
    "runtime",
    "secret-source",
    "service",
    "software",
    "storage",
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/"
        + role
        + "-adapter.schema.json"
        for role in ROLES
    ],
    "scope": "per-page collection bounds and complete, resumable incomplete and non-resumable unknown observation responses",
    "relationship": "candidate",
    "reason": "Typed cross-role pages, retry identities, empty scan steps and multi-collection bounds exercise the common data boundary, not native snapshot authentication, total-work growth or provider completeness.",
    "claims": [],
}


def page(role, method="observe"):
    _, executor = installed(role)
    query = {
        "contract": "fishhat." + role,
        "method": method,
        "input": {"scope": executor["scope"], "cursor": "page:one", "limit": 1},
    }
    if role in {
        "repository",
        "service",
        "software",
        "runtime",
        "secret-source",
        "credential-issuer",
    }:
        query["input"]["binding"] = executor
    if role == "runtime":
        query["input"]["barrier"] = None
    outputs = {
        "backup": {"objects": []},
        "build": {"artifacts": []},
        "compute": {"allocation": None, "limits": [], "counters": []},
        "credential-issuer": {"leases": []},
        "dns": {"rrsets": [], "served_generation": None},
        "ingress": {"serving_generation": None},
        "network": {"policy_generation": None},
        "report": {"receipt_handle": None},
        "repository": {"refs": []},
        "runtime": {"deployment": None, "observation": None, "objects": []},
        "secret-source": {"versions": []},
        "service": {"services": [], "transition": None},
        "software": {"packages": []},
        "storage": {"allocations": []},
    }
    reply = {
        "contract": query["contract"],
        "method": method,
        "request_digest": digest(query),
        "scope": query["input"]["scope"],
        "coverage": "complete",
        "continuation": None,
        "proposal": None,
        "problem": None,
        "output": outputs[role],
    }
    return query, reply


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("continuation", [None, "page:one"], ids=["absent", "unchanged"])
def test_every_observation_role_requires_an_advancing_incomplete_cursor(role, continuation):
    query, reply = page(role)
    reply.update(coverage="incomplete", continuation=continuation)
    with pytest.raises(ContractError):
        check_response(role, query, reply)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("coverage", ["complete", "unknown"])
def test_complete_and_unknown_coverage_do_not_offer_a_resumable_cursor(role, coverage):
    query, reply = page(role)
    reply["coverage"] = coverage
    check_response(role, query, reply)
    reply["continuation"] = "page:next"
    with pytest.raises(ContractError):
        check_response(role, query, reply)


@pytest.mark.parametrize("role", ROLES)
def test_empty_bounded_scan_steps_can_advance_without_fabricating_complete_coverage(role):
    query, reply = page(role)
    reply.update(coverage="incomplete", continuation="page:next")
    original = copy.deepcopy(reply)
    check_response(role, query, reply)
    check_response(role, query, copy.deepcopy(reply))
    assert reply == original
    query["input"]["cursor"] = reply["continuation"]
    with pytest.raises(ContractError, match="RESPONSE_IDENTITY"):
        check_response(role, query, reply)
    reply.update(request_digest=digest(query), coverage="complete", continuation=None)
    check_response(role, query, reply)


def test_runtime_inventory_uses_the_same_progress_contract_as_observe():
    query, reply = page("runtime", "inventory")
    reply.update(coverage="incomplete", continuation="page:one")
    with pytest.raises(ContractError, match="OBSERVATION_CURSOR_PROGRESS"):
        check_response("runtime", query, reply)
    reply["continuation"] = "page:next"
    check_response("runtime", query, reply)


def test_backup_limit_bounds_each_page_without_limiting_total_collection_extent():
    query, reply = page("backup")
    objects = [
        {
            "handle": "object:" + str(number),
            "repository": "repository:demo",
            "artifacts": [artifact("a"), artifact("b")],
            "completeness": "sealed",
            "retrieval": "available",
        }
        for number in range(3)
    ]
    reply["output"]["objects"] = objects[:2]
    with pytest.raises(ContractError, match="OBSERVATION_PAGE_CAPACITY"):
        check_response("backup", query, reply)
    seen = []
    for index, record in enumerate(objects):
        last = index == len(objects) - 1
        reply.update(
            request_digest=digest(query),
            coverage="complete" if last else "incomplete",
            continuation=None if last else "page:" + str(index + 2),
            output={"objects": [record]},
        )
        check_response("backup", query, reply)
        seen.extend(reply["output"]["objects"])
        query["input"]["cursor"] = reply["continuation"]
    assert seen == objects


def test_compute_limit_counts_all_top_level_collections_together():
    query, reply = page("compute")
    reply["output"] = {
        "allocation": "allocation:demo",
        "limits": [limit()],
        "counters": [counter()],
    }
    with pytest.raises(ContractError, match="OBSERVATION_PAGE_CAPACITY"):
        check_response("compute", query, reply)
    query["input"]["limit"] = 2
    reply["request_digest"] = digest(query)
    check_response("compute", query, reply)
