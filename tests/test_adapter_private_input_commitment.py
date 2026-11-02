"""Owner admission retains private operation-value identity before dispatch."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.validation import ContractError, digest
from fishhat_owner.adapter_state import AdapterCoordinator

from tests.adapter_support import OWNER, identifier, request, runtime_sources
from tests.test_adapter_authority import delegated, prepare_service
from tests.test_adapter_effects import coordinator, result

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json#/$defs/EffectAttempt",
        "fishhat/owner-support/src/fishhat_owner/adapter_state.py",
    ],
    "scope": "runtime and delegated-service private operation-value commitment admission, retained replay, dispatch and reconciliation",
    "relationship": "candidate",
    "reason": "The injected owner commit boundary retains the exact approved metadata commitment before releasing an Invocation and rejects substitution or omission on replay. Synthetic retained state does not establish native byte custody, authentication or durable transactions.",
    "claims": [],
}

PRIVATE_INPUTS_DIGEST = digest(
    [
        {
            "handle": "private:application-value",
            "source": {
                "kind": "enrolled",
                "owner": OWNER,
                "enrollment_id": identifier(701),
                "version": identifier(702),
            },
            "size_bytes": 13,
        }
    ]
)


def prepare_private(owner, role, commitment=PRIVATE_INPUTS_DIGEST):
    if role == "service":
        return prepare_service(owner, private_inputs_digest=commitment)
    return owner.prepare(
        "demo",
        request(),
        **runtime_sources(owner.registry),
        operation_id=identifier(8),
        effect_id=identifier(9),
        attempt_id=identifier(10),
        owner_approved=True,
        private_inputs_digest=commitment,
    )


@pytest.fixture(params=["runtime", "service"])
def selected_owner(request):
    owner, commits = coordinator()
    if request.param == "service":
        delegated(owner)
    return owner, commits, request.param


def test_private_operation_values_are_committed_before_executable_invocation(selected_owner):
    owner, commits, role = selected_owner
    prepared = prepare_private(owner, role)
    attempt_id = prepared["attempt_id"]
    assert prepared["private_inputs_digest"] == PRIVATE_INPUTS_DIGEST
    assert commits[-1]["updates"]["attempts"][attempt_id] == prepared

    invocation = owner.dispatch("demo", attempt_id)
    assert invocation["attempt"]["private_inputs_digest"] == PRIVATE_INPUTS_DIGEST
    assert commits[-1]["updates"]["attempts"][attempt_id] == invocation["attempt"]
    assert prepare_private(owner, role) == invocation["attempt"]


@pytest.mark.parametrize("substitution", [None, "sha256:" + "b" * 64], ids=["omit", "replace"])
def test_private_operation_value_commitment_cannot_change_on_replay(selected_owner, substitution):
    owner, commits, role = selected_owner
    prepared = prepare_private(owner, role)
    before = copy.deepcopy(commits)
    with pytest.raises(ContractError, match="ATTEMPT_IDENTITY_CONFLICT"):
        prepare_private(owner, role, substitution)
    assert commits == before
    assert owner.snapshot()["attempts"][prepared["attempt_id"]] == prepared


def test_empty_private_operation_value_closure_cannot_acquire_inputs_on_replay(selected_owner):
    owner, commits, role = selected_owner
    prepared = prepare_private(owner, role, None)
    assert "private_inputs_digest" not in prepared
    before = copy.deepcopy(commits)
    with pytest.raises(ContractError, match="ATTEMPT_IDENTITY_CONFLICT"):
        prepare_private(owner, role)
    assert commits == before


def test_invalid_private_operation_value_commitment_never_commits(selected_owner):
    owner, commits, role = selected_owner
    before = copy.deepcopy(commits)
    with pytest.raises(ContractError):
        prepare_private(owner, role, "invalid")
    assert commits == before
    assert owner.snapshot()["attempts"] == {}


def test_restoration_and_reconciliation_preserve_original_private_values(selected_owner):
    owner, _, role = selected_owner
    prepared = prepare_private(owner, role)
    attempt_id = prepared["attempt_id"]
    invocation = owner.dispatch("demo", attempt_id)
    recovered = AdapterCoordinator(OWNER, owner.registry, lambda value: None)
    recovered.restore(owner.snapshot())
    assert recovered.snapshot()["attempts"][attempt_id] == invocation["attempt"]
    assert prepare_private(recovered, role) == invocation["attempt"]

    query = {
        "contract": invocation["request"]["contract"],
        "method": "reconcile",
        "input": {"scope": invocation["attempt"]["scope"], "invocation": invocation},
    }
    _, response = result(recovered, invocation["attempt"])
    response.update(method="reconcile", request_digest=digest(query))
    substituted = copy.deepcopy(query)
    del substituted["input"]["invocation"]["attempt"]["private_inputs_digest"]
    changed_response = {**response, "request_digest": digest(substituted)}
    with pytest.raises(ContractError, match="RECONCILIATION_IDENTITY"):
        recovered.settle(attempt_id, substituted, changed_response)
    recovered.settle(attempt_id, query, response)
    retained = recovered.snapshot()
    assert retained["attempts"][attempt_id]["private_inputs_digest"] == PRIVATE_INPUTS_DIGEST
    assert retained["attempts"][attempt_id]["state"] == "resolved"
    recovered.restore(retained)
    assert recovered.snapshot()["attempts"][attempt_id] == retained["attempts"][attempt_id]
    assert recovered.snapshot()["results"] == retained["results"]
