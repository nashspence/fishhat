from __future__ import annotations

import copy
import json

import pytest
from fishhat_adapters import (
    ROLES,
    Registry,
    check_configuration,
    check_descriptor,
    check_request,
    check_schema,
)
from fishhat_contracts.validation import SCHEMAS, ContractError, digest, validate

from tests.adapter_support import SCOPE, D, descriptors, observation, request, runtime_registry

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": ["packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json"],
    "scope": "closed adapter data and reference admission, not native execution",
    "relationship": "candidate",
    "reason": "Negative and cross-field schema checks; no native capability claim.",
    "claims": [],
}


@pytest.mark.parametrize("path", descriptors(), ids=lambda p: p.parts[-4])
def test_supplied_descriptors_are_closed_and_truthful(path):
    value = json.loads(path.read_text())
    check_descriptor(value)
    assert value["native_qualified"] is False
    assert not value["implemented"]


@pytest.mark.parametrize("role", sorted(ROLES))
def test_every_role_has_a_closed_typed_schema(role):
    branches = SCHEMAS[role + "-adapter.schema.json"]["oneOf"]
    assert {b["properties"]["method"]["const"] for b in branches} == set(ROLES[role])
    assert all(b["additionalProperties"] is False for b in branches)
    for semantics in ROLES[role].values():
        assert semantics["effect"] == (semantics["repeat"] == "reconcile-before-repeat")


def test_issuer_get_shaped_issuance_is_an_effect():
    assert ROLES["credential-issuer"]["issue"]["effect"] is True
    assert ROLES["credential-issuer"]["observe"]["effect"] is False


@pytest.mark.parametrize("member", ["argv", "shell", "authenticated_principal", "owner_approved"])
def test_native_requests_cannot_acquire_ambient_authority(member):
    value = request()
    value["input"][member] = "not-authority"
    with pytest.raises(ContractError):
        check_request("runtime", value)


def test_registered_configuration_identity_is_checked():
    _, descriptor, instance = runtime_registry()
    schema = descriptor["configuration_schema"]
    check_configuration(schema, instance["configuration"], digest(schema))
    with pytest.raises(ContractError, match="SCHEMA_IDENTITY"):
        check_configuration(schema, instance["configuration"], D)
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        check_configuration(
            schema, {**instance["configuration"], "privileged": True}, digest(schema)
        )


def test_schema_cannot_fetch_remote_definitions_or_accept_extra_fields():
    with pytest.raises(ContractError, match="NONLOCAL_SCHEMA_REFERENCE"):
        check_schema({"$ref": "https://untrusted.example/schema"})
    with pytest.raises(ContractError, match="OPEN_OBJECT_SCHEMA"):
        check_schema({"type": "object", "properties": {}})


def test_external_identity_does_not_need_a_core_switch():
    registry, descriptor, instance = runtime_registry()
    assert descriptor["id"].startswith("independent-author.")
    selection = {
        "instance": instance["id"],
        "source_schema_digest": digest(descriptor["source_schema"]),
        "source": {"files": ["web.container"]},
    }
    resolved = registry.resolve(selection, {"web": {"native": {"unit": "web.container"}}})
    assert resolved == instance
    with pytest.raises(ContractError):
        registry.resolve(selection, {"web": {"native": {"service": "web"}}})
    selection["source"]["files"] = ["changed.container"]
    assert registry.resolve(selection, {}) == instance
    selection["source"]["account"] = "unapproved-account"
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        registry.resolve(selection, {})


def test_source_does_not_install_or_enroll_an_adapter():
    registry = Registry()
    with pytest.raises(ContractError, match="UNENROLLED_ADAPTER"):
        registry.resolve({"instance": "unknown", "source_schema_digest": D, "source": {}}, {})


def test_installation_approval_and_scope_are_not_descriptor_fields():
    registry, descriptor, instance = runtime_registry()
    descriptor["owner_approved"] = True
    with pytest.raises(ContractError):
        check_descriptor(descriptor)
    with pytest.raises(ContractError, match="OPERATION_NOT_AUTHORIZED"):
        registry.authorize(instance["id"], "runtime", "activate", SCOPE, owner_approved=False)
    with pytest.raises(ContractError, match="SCOPE_NOT_GRANTED"):
        registry.authorize(
            instance["id"], "runtime", "activate", {**SCOPE, "handle": "other"}, owner_approved=True
        )


def test_enrollment_does_not_silently_rebind():
    registry, _, instance = runtime_registry()
    changed = copy.deepcopy(instance)
    changed["generation"] += 1
    with pytest.raises(ContractError, match="EXPLICIT_REBIND_REQUIRED"):
        registry.enroll(changed, owner_approved=True)


def test_change_grants_require_explicit_native_mutation_authority():
    _, _, instance = runtime_registry()
    grant = instance["grants"][0]
    grant["mutation"] = None
    with pytest.raises(ContractError):
        validate("adapter.schema.json", instance, "Instance")
    del grant["mutation"]
    with pytest.raises(ContractError):
        validate("adapter.schema.json", instance, "Instance")


def test_observation_grants_cannot_claim_native_mutation_authority():
    _, _, instance = runtime_registry()
    grant = instance["grants"][0]
    grant["access"] = ["observe"]
    with pytest.raises(ContractError):
        validate("adapter.schema.json", instance, "Instance")
    grant["mutation"] = None
    validate("adapter.schema.json", instance, "Instance")


def test_control_records_keep_their_strict_encoding():
    from fishhat_contracts.validation import canonical

    with pytest.raises(ContractError):
        canonical({"cpu": 0.5})


def test_adapter_health_result_does_not_stand_in_for_check_capability():
    value = observation()
    value["health_check"] = "unsupported"
    validate("adapter.schema.json", value, "Observation")
    value["health"] = "healthy"
    with pytest.raises(ContractError):
        validate("adapter.schema.json", value, "Observation")
    value["health"] = "unsupported"
    with pytest.raises(ContractError):
        validate("adapter.schema.json", value, "Observation")


def test_unknown_runtime_implementation_is_not_a_schema_enum():
    validate("adapter.schema.json", "external-author.future-native-runtime", "ImplementationId")
    with pytest.raises(ContractError):
        validate("adapter.schema.json", "../../untrusted.py", "ImplementationId")


def test_source_selection_cannot_override_host_instance_configuration():
    registry, descriptor, instance = runtime_registry()
    selection = {
        "instance": instance["id"],
        "source_schema_digest": digest(descriptor["source_schema"]),
        "source": {"files": ["web.container"], "account": "wrong-account"},
    }
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        registry.resolve(selection, {})


def test_unimplemented_native_method_cannot_be_authorized_by_manifest_role_alone():
    registry, _, instance = runtime_registry()
    with pytest.raises(ContractError, match="NATIVE_EXECUTOR_UNIMPLEMENTED"):
        registry.authorize(instance["id"], "runtime", "materialize", SCOPE, owner_approved=True)


@pytest.mark.parametrize("role", sorted(ROLES))
def test_role_response_shape_is_closed_and_method_specific(role):
    responses = SCHEMAS[role + "-adapter.schema.json"]["$defs"]["Response"]["oneOf"]
    assert {branch["properties"]["method"]["const"] for branch in responses} == set(ROLES[role])
    assert all(branch["additionalProperties"] is False for branch in responses)
    for branch in responses:
        method = branch["properties"]["method"]["const"]
        assert ("effect" in branch["required"]) is (
            ROLES[role][method]["effect"] or method == "reconcile"
        )


def test_read_response_is_bound_to_request_and_complete_coverage():
    from fishhat_adapters import check_response

    query = {
        "contract": "fishhat.runtime",
        "method": "observe",
        "input": {"scope": SCOPE, "cursor": None, "limit": 10, "barrier": None},
    }
    response = {
        "contract": query["contract"],
        "method": "observe",
        "request_digest": digest(query),
        "scope": SCOPE,
        "coverage": "complete",
        "continuation": None,
        "proposal": None,
        "output": {"deployment": None, "observation": None, "objects": []},
    }
    check_response("runtime", query, response)
    response["continuation"] = "page:next"
    with pytest.raises(ContractError, match="INCOMPLETE_RESPONSE_COVERAGE"):
        check_response("runtime", query, response)
    response["continuation"] = None
    response["request_digest"] = D
    with pytest.raises(ContractError, match="RESPONSE_IDENTITY"):
        check_response("runtime", query, response)


@pytest.mark.parametrize(
    "schema",
    [
        {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
            "allOf": [{"$ref": "#/$defs/Missing"}],
        },
        {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
            "$defs": {"Loop": {"$ref": "#/$defs/Loop"}},
            "allOf": [{"$ref": "#/$defs/Loop"}],
        },
    ],
    ids=["unresolved-local-reference", "recursive-local-reference"],
)
def test_invalid_local_schema_resolution_is_a_redacted_contract_rejection(schema):
    with pytest.raises(ContractError, match=r"^(UNRESOLVED|RECURSIVE)_SCHEMA_REFERENCE$"):
        check_configuration(schema, {}, digest(schema))
