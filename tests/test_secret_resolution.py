"""Exact secret lookup identity and explicit absence, without native retrieval."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import check_request, check_response
from fishhat_contracts.validation import ContractError, digest

from tests.test_adapter_handoffs import installed

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/secret-source-adapter.schema.json#/$defs/resolve",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/secret-source-adapter.schema.json#/$defs/ResolveOutput",
    ],
    "scope": "exact secret-source lookup, approved instance joins and absence coverage",
    "relationship": "candidate",
    "reason": "Substituted source, entry, version and coverage exercise the data boundary; no native secret retrieval or authorization is qualified.",
    "claims": [],
}


def lookup(state="present"):
    registry, binding = installed("secret-source")
    query = {
        "contract": "fishhat.secret-source",
        "method": "resolve",
        "input": {
            "scope": copy.deepcopy(binding["scope"]),
            "binding": binding,
            "entry": "database",
            "version": "version:one",
            "consumer": "demo",
        },
    }
    version = {
        "source": binding["instance"],
        "entry": "database",
        "version": "version:one",
        "value_handle": "protected:one",
        "validity": "valid",
        "expires_at": None,
    }
    response = {
        "contract": query["contract"],
        "method": "resolve",
        "request_digest": digest(query),
        "scope": copy.deepcopy(binding["scope"]),
        "coverage": "unknown" if state == "unknown" else "complete",
        "continuation": None,
        "proposal": None,
        "problem": None,
        "output": {"state": state, "version": version if state == "present" else None},
    }
    return registry, query, response


@pytest.mark.parametrize("state", ["present", "absent", "unknown"])
def test_exact_lookup_has_explicit_presence_and_coverage(state):
    registry, query, response = lookup(state)
    assert (
        registry.authorize_request("selected", "secret-source", query, owner_approved=True)["id"]
        == "selected"
    )
    check_response("secret-source", query, response)


@pytest.mark.parametrize(
    "field,value",
    [("source", "another-source"), ("entry", "another-entry"), ("version", "version:two")],
    ids=["source", "entry", "version"],
)
def test_complete_lookup_cannot_substitute_the_requested_secret_identity(field, value):
    _, query, response = lookup()
    response["output"]["version"][field] = value
    with pytest.raises(ContractError, match="SECRET_RESOLUTION_IDENTITY"):
        check_response("secret-source", query, response)


@pytest.mark.parametrize(
    "field,value",
    [
        ("instance", "another-source"),
        ("configuration_digest", "sha256:" + "b" * 64),
        ("installation_digest", "sha256:" + "b" * 64),
        ("instance_digest", "sha256:" + "b" * 64),
        ("instance_generation", 4),
    ],
    ids=["instance", "configuration", "installation", "instance-digest", "generation"],
)
def test_lookup_must_use_the_complete_independently_enrolled_binding(field, value):
    registry, query, _ = lookup()
    query["input"]["binding"][field] = value
    with pytest.raises(ContractError, match="HANDOFF_INSTANCE_IDENTITY"):
        registry.authorize_request("selected", "secret-source", query, owner_approved=True)


@pytest.mark.parametrize("field", ["role", "scope"])
def test_lookup_binding_cannot_change_its_role_or_scope(field):
    _, query, _ = lookup()
    if field == "role":
        query["input"]["binding"]["role"] = "credential-issuer"
    else:
        query["input"]["binding"]["scope"]["handle"] = "another"
    with pytest.raises(ContractError, match="HANDOFF_BINDING_SCOPE"):
        check_request("secret-source", query)


@pytest.mark.parametrize(
    "state,coverage",
    [
        ("present", "incomplete"),
        ("present", "unknown"),
        ("absent", "incomplete"),
        ("absent", "unknown"),
        ("unknown", "complete"),
        ("unknown", "incomplete"),
    ],
)
def test_lookup_never_confuses_unknown_or_partial_evidence_with_absence(state, coverage):
    _, query, response = lookup(state)
    response["coverage"] = coverage
    with pytest.raises(ContractError, match="SECRET_RESOLUTION_COVERAGE"):
        check_response("secret-source", query, response)


@pytest.mark.parametrize("state", ["present", "absent", "unknown"])
def test_exact_lookup_cannot_hide_another_result_behind_continuation(state):
    _, query, response = lookup(state)
    response["continuation"] = "page:next"
    with pytest.raises(ContractError):
        check_response("secret-source", query, response)


@pytest.mark.parametrize("state", ["absent", "unknown"])
def test_nonpresent_lookup_cannot_expose_a_secret_value(state):
    _, query, response = lookup()
    response["output"]["state"] = state
    response["coverage"] = "unknown" if state == "unknown" else "complete"
    with pytest.raises(ContractError):
        check_response("secret-source", query, response)


def test_present_lookup_requires_one_value_and_old_listing_shape_is_rejected():
    _, query, response = lookup()
    response["output"]["version"] = None
    with pytest.raises(ContractError):
        check_response("secret-source", query, response)
    response["output"] = {"versions": []}
    with pytest.raises(ContractError):
        check_response("secret-source", query, response)
    del query["input"]["binding"]
    with pytest.raises(ContractError):
        check_request("secret-source", query)
