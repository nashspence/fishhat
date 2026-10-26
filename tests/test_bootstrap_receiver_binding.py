"""Receiver-owned bootstrap joins, including retained original reconciliation."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import (
    Registry,
    check_invocation,
    check_request,
    check_response,
    instance_reference,
)
from fishhat_client.bootstrap import prepare_request
from fishhat_contracts.validation import ContractError, digest

from tests.adapter_support import D
from tests.test_adapter_handoffs import artifact, attempt_for, response_for
from tests.test_adapter_invocations import recovered
from tests.test_bootstrap import PROVIDERS, fixture, records, reseal

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/bootstrap-recovery.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/bootstrap-source-adapter.schema.json",
    ],
    "scope": "receiver joins of selected bootstrap source, executor and installed pins on dispatch and reconciliation",
    "relationship": "candidate",
    "reason": "Independently approved substituted executors and retained original requests exercise rejection without native source restoration or qualification.",
    "claims": [],
}


def accepted(provider="forgejo-restic", method="recover"):
    value = records(provider)
    value["descriptor"]["implemented"] = [
        "bootstrap-source.recover",
        "bootstrap-source.verify",
        "bootstrap-source.reconcile",
    ]
    reseal(value)
    query = prepare_request(**value)
    query["method"] = method
    if method == "verify":
        query["input"]["output"] = artifact("a")
    return value, query


def receiver(value, *, replacement=None):
    value = copy.deepcopy(value)
    if replacement == "installation":
        value["installation"]["artifact"] = artifact("b")
    elif replacement == "configuration":
        value["configuration"]["repository_handle"] = "different-backup"
    instance = {
        "id": "offline-source",
        "implementation": value["descriptor"]["id"],
        "installation_digest": value["installation"]["artifact"]["digest"],
        "role": "bootstrap-source",
        "schema_digest": digest(value["descriptor"]["configuration_schema"]),
        "configuration": value["configuration"],
        "grants": [
            {
                "scope": value["scope"],
                "access": ["observe", "change"],
                "mutation": {
                    "controller": "offline-source",
                    "namespaces": [
                        {
                            "authority": value["scope"]["authority"],
                            "resource": value["scope"]["handle"],
                            "facet": "recovery-source",
                        }
                    ],
                },
            }
        ],
        "generation": 1,
    }
    registry = Registry()
    registry.install(value["installation"], value["descriptor"], owner_approved=True)
    registry.enroll(instance, owner_approved=True)
    return registry, instance_reference(instance, value["scope"])


def invocation(query, executor):
    attempt = attempt_for(query)
    attempt["executor"] = copy.deepcopy(executor)
    return {"attempt": attempt, "request": copy.deepcopy(query)}


def authorize(registry, original, reconciliation):
    if reconciliation:
        query = recovered(original)
        registry.authorize_request(
            original["attempt"]["executor"]["instance"],
            "bootstrap-source",
            query,
            owner_approved=True,
            invocation=original,
        )
    else:
        query = original["request"]
        registry.authorize_invocation("bootstrap-source", original, owner_approved=True)
    return query


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("method", ["recover", "verify"])
@pytest.mark.parametrize("reconciliation", [False, True], ids=["dispatch", "reconcile"])
def test_exact_bootstrap_selection_survives_initial_dispatch_and_lost_reply(
    provider, method, reconciliation
):
    value, request = accepted(provider, method)
    registry, executor = receiver(value)
    original = invocation(request, executor)
    before = copy.deepcopy(original)
    query = authorize(registry, original, reconciliation)
    receipt = fixture("source-receipt")
    selection = request["input"]["selection"]
    receipt.update(
        selection_digest=digest(selection),
        domain_id=selection["domain_id"],
        source_id=selection["source_id"],
        ref=selection["ref"],
        commit=selection["expected_commit"],
        destination=selection["recovery_root"] + "/source.git",
        output_digest=D,
    )
    reply = response_for(query, original["attempt"], {"receipt": receipt})
    check_response("bootstrap-source", query, reply, invocation=original)
    assert original == before


@pytest.mark.parametrize("replacement", ["installation", "configuration"])
@pytest.mark.parametrize("reconciliation", [False, True], ids=["dispatch", "reconcile"])
def test_another_approved_bootstrap_executor_cannot_satisfy_the_selected_pins(
    replacement, reconciliation
):
    value, request = accepted()
    registry, executor = receiver(value, replacement=replacement)
    original = invocation(request, executor)
    with pytest.raises(ContractError, match="BOOTSTRAP_EXECUTOR_IDENTITY"):
        check_invocation("bootstrap-source", original)
    with pytest.raises(ContractError, match="BOOTSTRAP_EXECUTOR_IDENTITY"):
        authorize(registry, original, reconciliation)


@pytest.mark.parametrize("pin", ["implementation", "descriptor_digest", "source_schema_digest"])
@pytest.mark.parametrize("reconciliation", [False, True], ids=["dispatch", "reconcile"])
def test_receiver_independently_joins_descriptor_pins_not_only_executor_artifacts(
    pin, reconciliation
):
    value, request = accepted()
    registry, executor = receiver(value)
    request["input"]["selection"]["adapter"][pin] = (
        "other.bootstrap" if pin == "implementation" else artifact("b")["digest"]
    )
    original = invocation(request, executor)
    check_invocation("bootstrap-source", original)
    with pytest.raises(ContractError, match="BOOTSTRAP_BINDING_IDENTITY"):
        authorize(registry, original, reconciliation)


@pytest.mark.parametrize("reconciliation", [False, True], ids=["dispatch", "reconcile"])
def test_receiver_rejects_a_source_selection_under_another_approved_repository_scope(
    reconciliation,
):
    value, request = accepted()
    value["scope"]["handle"] = "different-repository"
    request["input"]["scope"] = copy.deepcopy(value["scope"])
    registry, executor = receiver(value)
    original = invocation(request, executor)
    with pytest.raises(ContractError, match="BOOTSTRAP_SCOPE_IDENTITY"):
        check_request("bootstrap-source", request)
    with pytest.raises(ContractError, match="BOOTSTRAP_SCOPE_IDENTITY"):
        authorize(registry, original, reconciliation)


def test_reconciliation_cannot_retarget_a_retained_bootstrap_invocation_after_replacement():
    value, request = accepted()
    registry, executor = receiver(value)
    original = invocation(request, executor)
    authorize(registry, original, False)
    retained = copy.deepcopy(original)
    replacement, _ = receiver(value, replacement="configuration")
    with pytest.raises(ContractError, match="RECONCILIATION_INSTANCE_IDENTITY"):
        authorize(replacement, original, True)
    assert original == retained
