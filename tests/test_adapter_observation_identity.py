"""Scoped stable-snapshot records, exact retries and approved historical issuers."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import ObservationSequence, check_request, check_response
from fishhat_contracts.validation import ContractError, digest

from tests.adapter_support import identifier, observation
from tests.linear_support import assert_linear, measure
from tests.test_adapter_observation_pages import page

ROLES = ("runtime", "secret-source", "credential-issuer")
CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/"
        + role
        + "-adapter.schema.json"
        for role in ROLES
    ],
    "scope": "observation record identity, exact page retries and complete incremental snapshot intake",
    "relationship": "candidate",
    "reason": "Independent scope, identity, replay and historical-mapping substitutions exercise data consistency; native snapshot authentication, permission and completeness remain owner duties.",
    "claims": [],
}


def observed(role, binding, index=0):
    if role == "runtime":
        return {
            "handle": f"object:{index}",
            "scope": copy.deepcopy(binding["scope"]),
            "kind": "container",
            "native_selector": f"native:{index}",
            "incarnation": identifier(index + 200),
            "produced_by": identifier(100),
            "references": [],
        }
    if role == "secret-source":
        return {
            "source": binding["instance"],
            "entry": "database",
            "version": f"version:{index}",
            "value_handle": f"protected:{index}",
            "validity": "valid",
            "expires_at": None,
        }
    return {
        "identity": "database:user",
        "consumer": "demo",
        "value_handle": f"protected:{index}",
        "lease": f"lease:{index}",
        "validity": "valid",
        "expires_at": None,
        "renewable": True,
        "issuer": copy.deepcopy(binding),
        "valid_from": None,
    }


def collection(role):
    return {"runtime": "objects", "secret-source": "versions", "credential-issuer": "leases"}[role]


def query_page(role, *, index=0, count=1, cursor=None, continuation=None):
    query, reply = page(role)
    query["input"].update(cursor=cursor, limit=max(1, count))
    reply.update(
        request_digest=digest(query),
        coverage="complete" if continuation is None else "incomplete",
        continuation=continuation,
    )
    reply["output"][collection(role)] = [
        observed(role, query["input"]["binding"], value) for value in range(index, index + count)
    ]
    return query, reply


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("change", ["absent", "role", "scope"])
def test_observation_requires_exact_typed_observer_binding(role, change):
    query, _ = query_page(role)
    if change == "absent":
        del query["input"]["binding"]
    elif change == "role":
        query["input"]["binding"]["role"] = "storage"
    else:
        query["input"]["binding"] = copy.deepcopy(query["input"]["binding"])
        query["input"]["binding"]["scope"]["handle"] = "foreign"
    with pytest.raises(ContractError):
        check_request(role, query)


@pytest.mark.parametrize("field", ["authority", "kind", "handle"])
def test_runtime_objects_cannot_substitute_another_scope(field):
    query, reply = query_page("runtime")
    reply["output"]["objects"][0]["scope"][field] = {
        "authority": identifier(99),
        "kind": "dataset",
        "handle": "other-app",
    }[field]
    with pytest.raises(ContractError, match="OBSERVATION_OBJECT_SCOPE"):
        check_response("runtime", query, reply)


def test_secret_observation_cannot_claim_another_source():
    query, reply = query_page("secret-source")
    reply["output"]["versions"][0]["source"] = "foreign"
    with pytest.raises(ContractError, match="OBSERVATION_SOURCE_IDENTITY"):
        check_response("secret-source", query, reply)


@pytest.mark.parametrize("field", ["instance", "installation_digest"])
def test_runtime_summary_names_the_selected_observer(field):
    query, reply = query_page("runtime")
    binding = query["input"]["binding"]
    summary = observation()
    summary.update(
        scope=copy.deepcopy(query["input"]["scope"]),
        instance=binding["instance"],
        installation_digest=binding["installation_digest"],
    )
    reply["output"]["observation"] = summary
    check_response("runtime", query, reply)
    summary[field] = "foreign" if field == "instance" else digest("foreign")
    with pytest.raises(ContractError, match="OBSERVATION_EXECUTOR_IDENTITY"):
        check_response("runtime", query, reply)


@pytest.mark.parametrize("field", ["role", "instance", "scope"])
def test_lease_observation_cannot_claim_another_issuer(field):
    query, reply = query_page("credential-issuer")
    reply["output"]["leases"][0]["issuer"][field] = {
        "role": "runtime",
        "instance": "foreign",
        "scope": {**query["input"]["scope"], "handle": "foreign"},
    }[field]
    with pytest.raises(ContractError, match="OBSERVATION_ISSUER_IDENTITY"):
        check_response("credential-issuer", query, reply)


@pytest.mark.parametrize("role", ROLES)
def test_conflicting_logical_records_reject_within_one_page(role):
    query, reply = query_page(role, count=2)
    records = reply["output"][collection(role)]
    records[1] = copy.deepcopy(records[0])
    records[1]["incarnation" if role == "runtime" else "validity"] = (
        identifier(999) if role == "runtime" else "revoked"
    )
    with pytest.raises(ContractError, match="OBSERVATION_DUPLICATE_IDENTITY"):
        check_response(role, query, reply)


@pytest.mark.parametrize("role", ROLES)
def test_sequence_rejects_cross_page_duplicates_without_consuming_failed_page(role):
    first, response = query_page(role, continuation="page:two")
    sequence = ObservationSequence(
        role,
        first,
        approved_binding=first["input"]["binding"],
        approved_runtime_binding=first["input"].get("target"),
    )
    assert sequence.accept(first, response)
    second, reply = query_page(role, cursor="page:two")
    records = reply["output"][collection(role)]
    records[0]["incarnation" if role == "runtime" else "validity"] = (
        identifier(999) if role == "runtime" else "revoked"
    )
    with pytest.raises(ContractError, match="OBSERVATION_DUPLICATE_IDENTITY"):
        sequence.accept(second, reply)
    assert not sequence.complete
    records[0] = observed(role, second["input"]["binding"], 1)
    assert sequence.accept(second, reply)
    assert sequence.complete


@pytest.mark.parametrize("role", ROLES)
def test_exact_page_retries_are_idempotent_even_after_completion(role):
    first, response = query_page(role, continuation="page:two")
    sequence = ObservationSequence(
        role,
        first,
        approved_binding=first["input"]["binding"],
        approved_runtime_binding=first["input"].get("target"),
    )
    assert sequence.accept(first, response)
    assert not sequence.accept(copy.deepcopy(first), copy.deepcopy(response))
    second, reply = query_page(role, index=1, cursor="page:two")
    assert sequence.accept(second, reply)
    assert sequence.complete
    assert not sequence.accept(first, response)
    assert not sequence.accept(second, reply)
    changed = copy.deepcopy(response)
    changed["output"][collection(role)][0] = observed(role, first["input"]["binding"], 5)
    with pytest.raises(ContractError, match="OBSERVATION_PAGE_REPLAY_CHANGED"):
        sequence.accept(first, changed)


@pytest.mark.parametrize("change", ["query", "cursor", "cycle"])
def test_traversal_cannot_change_query_skip_pages_or_cycle(change):
    first, response = query_page("runtime", count=0, continuation="page:two")
    sequence = ObservationSequence(
        "runtime",
        first,
        approved_binding=first["input"]["binding"],
        approved_runtime_binding=first["input"].get("target"),
    )
    sequence.accept(first, response)
    second, reply = query_page("runtime", count=0, cursor="page:two", continuation="page:three")
    sequence.accept(second, reply)
    third, reply = query_page("runtime", count=0, cursor="page:three")
    if change == "query":
        third["input"]["limit"] = 2
    elif change == "cursor":
        third["input"]["cursor"] = "page:unissued"
    else:
        reply.update(coverage="incomplete", continuation="page:two")
    reply["request_digest"] = digest(third)
    with pytest.raises(ContractError, match=r"OBSERVATION_(SEQUENCE|CURSOR)"):
        sequence.accept(third, reply)


def test_unknown_coverage_does_not_become_complete_or_resume():
    query, reply = query_page("runtime")
    reply["coverage"] = "unknown"
    sequence = ObservationSequence(
        "runtime",
        query,
        approved_binding=query["input"]["binding"],
        approved_runtime_binding=query["input"].get("target"),
    )
    assert sequence.accept(query, reply)
    assert not sequence.complete
    query["input"]["cursor"] = "page:unissued"
    reply["request_digest"] = digest(query)
    with pytest.raises(ContractError, match="OBSERVATION_SEQUENCE_CURSOR"):
        sequence.accept(query, reply)


def test_historical_issuer_requires_an_independently_approved_exact_mapping():
    query, reply = query_page("credential-issuer", count=2)
    approved = query["input"]["binding"]
    historical = copy.deepcopy(approved)
    historical.update(instance_generation=1, configuration_digest=digest({"old": "configuration"}))
    reply["output"]["leases"][0]["issuer"] = historical
    # Structural intake preserves the original issuer, never rewrites it to the current observer.
    check_response("credential-issuer", query, reply)
    sequence = ObservationSequence("credential-issuer", query, approved_binding=approved)
    with pytest.raises(ContractError, match="OBSERVATION_HISTORICAL_ISSUER_UNAPPROVED"):
        sequence.accept(query, reply)
    approved_sequence = ObservationSequence(
        "credential-issuer", query, approved_binding=approved, approved_issuers=[historical]
    )
    assert approved_sequence.accept(query, reply)
    assert reply["output"]["leases"][0]["issuer"] == historical
    assert reply["output"]["leases"][1]["issuer"] == approved
    assert approved_sequence.complete


@pytest.mark.parametrize("change", ["observer", "historical"])
def test_request_data_cannot_supply_receiver_approval(change):
    query, _ = query_page("credential-issuer")
    approved = copy.deepcopy(query["input"]["binding"])
    if change == "observer":
        approved["configuration_digest"] = digest("other")
        historical = []
    else:
        historical = [{**approved, "instance": "unrelated"}]
    with pytest.raises(ContractError, match="OBSERVATION_APPROVED_"):
        ObservationSequence(
            "credential-issuer", query, approved_binding=approved, approved_issuers=historical
        )


@pytest.mark.parametrize("role", ROLES)
def test_observation_sequence_linear_work(role):
    samples = []
    for count in (16, 64, 256):
        first, _ = query_page(role, count=8)
        approved = first["input"]["binding"]
        issuers = (
            [
                {**copy.deepcopy(approved), "instance_generation": index + 10}
                for index in range(count)
            ]
            if role == "credential-issuer"
            else []
        )
        pages = []
        for index in range(0, count, 8):
            query, reply = query_page(
                role,
                index=index,
                count=8,
                cursor=None if index == 0 else f"page:{index}",
                continuation=None if index + 8 == count else f"page:{index + 8}",
            )
            if issuers:
                for offset, lease in enumerate(reply["output"]["leases"]):
                    lease["issuer"] = issuers[index + offset]
            pages.append((query, reply))

        def traverse(first=first, approved=approved, issuers=issuers, pages=pages):
            sequence = ObservationSequence(
                role,
                first,
                approved_binding=approved,
                approved_runtime_binding=first["input"].get("target"),
                approved_issuers=issuers,
            )
            accepted = 0
            for query, reply in pages:
                accepted += sequence.accept(query, reply)
                assert not sequence.accept(query, reply)
            assert sequence.complete
            return accepted

        accepted, work = measure(traverse)
        assert accepted == count // 8
        samples.append((count, work))
    assert_linear(samples)


CHECK_OVERRIDES = {
    "test_observation_sequence_linear_work": {
        "purpose": "implementation",
        "authority": [
            "release.toml#/engineering",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_observations.py#ObservationSequence.__init__",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_observations.py#ObservationSequence.accept",
        ],
        "scope": "complete observation traversals, exact retries and retained issuer mapping intake",
        "relationship": "scoped-witness",
        "reason": "Measured actual initialization and every page/retry over sixteenfold collection growth; not native query, persistence or authorization qualification.",
        "claims": [
            "engineering:adapters.observation-sequence.start",
            "engineering:adapters.observation-sequence.accept",
        ],
    }
}
