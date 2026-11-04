"""A reviewed plan binds readable consequences to exact affected resources."""

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_contracts.validation import ContractError, digest, validate_cli, validate_plan
from fishhat_contracts.witness import sign

from tests.test_contracts import plan, uid

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Plan"
    ],
    "scope": "offline plan integrity and affected-resource joins",
    "relationship": "candidate",
    "reason": "Exact scope and disclosure checks use synthetic plans; they do not establish that native effects match their descriptions or qualify recovery.",
    "claims": [],
}


def reseal(value):
    value["digest"] = digest({k: v for k, v in value.items() if k not in ("digest", "witness")})
    body = {k: v for k, v in value["witness"].items() if k != "signature"}
    body["subject_digest"] = value["digest"]
    value["witness"] = sign(body, Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))
    return value


def test_consistently_signed_plan_must_belong_to_issuing_tool():
    value = plan()
    owner = {**value["owner"], "tool": "host-ops"}
    value["owner"] = value["witness"]["owner"] = owner
    value["preconditions"][0]["owner"] = value["effects"][0]["executor"] = owner
    with pytest.raises(ContractError, match="owner tool"):
        validate_plan(reseal(value))


@pytest.mark.parametrize("field", ["summary", "data_consequences", "recovery_limits"])
def test_reviewed_consequence_cannot_change_under_the_same_plan(field):
    value = plan()
    value[field] = "A different outcome or consequence."
    with pytest.raises(ContractError, match="plan digest mismatch"):
        validate_plan(value)


def test_effect_target_and_explanation_are_both_bound_to_review():
    for key, replacement in (
        ("resource", {"kind": "app", "id": "unreviewed-app"}),
        ("summary", "Replace stored application data."),
    ):
        value = plan()
        value["effects"][0][key] = replacement
        with pytest.raises(ContractError, match="plan digest mismatch"):
            validate_plan(value)


def test_signed_effect_cannot_expand_scope_without_its_resource_precondition():
    value = plan()
    value["effects"][0]["resource"] = {"kind": "app", "id": "another-app"}
    with pytest.raises(ContractError, match="effect lacks resource precondition"):
        validate_plan(reseal(value))


def test_matching_resource_on_another_owner_does_not_supply_a_precondition():
    value = plan()
    value["effects"][0]["executor"] = {**value["owner"], "id": uid("other-owner")}
    with pytest.raises(ContractError, match="effect lacks resource precondition"):
        validate_plan(reseal(value))


def test_plan_subject_needs_its_own_precondition_even_with_no_direct_effect():
    value = plan()
    value["subject"] = copy.deepcopy(value["subject"])
    value["subject"]["resource"]["id"] = "another-app"
    with pytest.raises(ContractError, match="subject lacks resource precondition"):
        validate_plan(reseal(value))


def test_effect_cannot_use_an_input_outside_the_reviewed_closure():
    value = plan()
    value["effects"][0]["input_digest"] = digest({"different": "input"})
    with pytest.raises(ContractError, match="effect input outside reviewed plan"):
        validate_plan(reseal(value))


def test_conflicting_preconditions_do_not_create_an_ambiguous_review():
    value = plan()
    changed = copy.deepcopy(value["preconditions"][0])
    changed["generation"] += 1
    value["preconditions"].append(changed)
    with pytest.raises(ContractError, match="duplicate resource precondition"):
        validate_plan(reseal(value))


def test_cross_owner_scope_is_valid_when_every_effect_is_explicit():
    value = plan()
    owner = {**value["owner"], "id": uid("second-owner")}
    resource = {"kind": "app", "id": "second-app"}
    precondition = {
        **copy.deepcopy(value["preconditions"][0]),
        "owner": owner,
        "resource": resource,
    }
    effect = {
        **copy.deepcopy(value["effects"][0]),
        "step": "restart-second",
        "executor": owner,
        "resource": resource,
        "summary": "Restart the explicitly reviewed second application.",
    }
    value["preconditions"].append(precondition)
    value["effects"].append(effect)
    validate_plan(reseal(value))


def test_blocked_plan_can_still_be_reviewed_without_becoming_admitted():
    value = plan()
    value["blockers"] = ["The selected resource is currently held by another operation."]
    validate_plan(reseal(value))


def test_recovery_cannot_be_both_unnecessary_and_required():
    value = plan()
    value["recovery"] = ["none-needed", "checkpoint-restore"]
    with pytest.raises(ContractError, match="conflicting recovery procedures"):
        validate_plan(reseal(value))


def test_cli_review_cannot_present_unbound_plan_consequences():
    value = {
        "format": "deployment-ops/cli/v1",
        "ok": True,
        "state": "planned",
        "complete": True,
        "request_id": None,
        "location": "caller-session",
        "result": plan(),
        "problem": None,
    }
    validate_cli(value)
    value["result"]["data_consequences"] = "All persistent data will be removed."
    with pytest.raises(ContractError, match="plan digest mismatch"):
        validate_cli(value)
