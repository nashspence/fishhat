"""Request-driven observation ordering in the owner reference; no native qualification."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import (
    Registry,
    check_request,
    check_response,
    instance_reference,
    runtime_binding_digest,
)
from fishhat_contracts.validation import ContractError, digest, validate
from fishhat_owner.adapter_state import AdapterCoordinator

from tests.adapter_support import (
    OWNER,
    SCOPE,
    D,
    fresh_observation,
    identifier,
    native_exclusion,
    observation,
    observation_target,
    request,
    runtime_registry,
    runtime_sources,
)
from tests.test_adapter_authority import delegated, prepare_service
from tests.test_adapter_effects import coordinator, prepare, result

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json#/$defs/ObservationBarrier",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/runtime-adapter.schema.json",
        "fishhat/owner-support/src/fishhat_owner/adapter_state.py",
        "packages/fishhat-adapter-protocol/src/fishhat_adapters/protocol.py",
    ],
    "scope": "owner-issued post-drain challenges, reference clearance ordering, trusted exclusion and typed request/result joins",
    "relationship": "candidate",
    "reason": "Synthetic native exclusion and observed activity exercise causal rejection and custody preservation, not native supervision or actual cessation.",
    "claims": [],
}


def containment(owner):
    return owner.prepare(
        "demo",
        request("deactivate"),
        **runtime_sources(owner.registry),
        operation_id=identifier(18),
        effect_id=identifier(19),
        attempt_id=identifier(20),
        owner_approved=True,
    )


@pytest.mark.parametrize("method", ["observe", "inventory"])
@pytest.mark.parametrize(
    "change",
    ["request-scope", "request-owner", "result-scope", "result-barrier", "result-generation"],
)
def test_protocol_correlates_observation_challenges_independently_of_coordinator(method, change):
    executor = instance_reference(runtime_registry()[2], SCOPE)
    target = observation_target(executor, admission_generation=1)
    barrier = {
        "id": identifier(80),
        "owner": copy.deepcopy(OWNER),
        "scope": copy.deepcopy(SCOPE),
        "binding_digest": runtime_binding_digest(target),
        "admission_generation": 1,
        "exclusion_id": identifier(90),
    }
    query = {
        "contract": "fishhat.runtime",
        "method": method,
        "input": {
            "scope": copy.deepcopy(SCOPE),
            "cursor": None,
            "limit": 10,
            "barrier": barrier,
            "binding": executor,
            "target": target,
        },
    }
    reply = {
        "contract": query["contract"],
        "method": method,
        "request_digest": digest(query),
        "scope": copy.deepcopy(SCOPE),
        "coverage": "complete",
        "continuation": None,
        "proposal": None,
        "problem": None,
        "output": {
            "deployment": None,
            "observation": observation(1, barrier=barrier),
            "objects": [],
        },
    }
    check_request("runtime", query)
    check_response("runtime", query, reply)
    if change.startswith("request-"):
        if change == "request-scope":
            query["input"]["barrier"]["scope"]["handle"] = "other"
        else:
            query["input"]["barrier"]["owner"]["id"] = identifier(81)
        validate("runtime-adapter.schema.json", query)
        with pytest.raises(ContractError, match="OBSERVATION_BARRIER_SCOPE"):
            check_request("runtime", query)
        return
    observed = reply["output"]["observation"]
    if change == "result-scope":
        observed["scope"]["handle"] = "other"
    elif change == "result-barrier":
        observed["barrier"]["id"] = identifier(82)
    else:
        observed["admission_generation"] += 1
    validate("runtime-adapter.schema.json", reply, "Response")
    code = "GENERATION" if change == "result-generation" else "IDENTITY"
    with pytest.raises(ContractError, match="OBSERVATION_BARRIER_" + code):
        check_response("runtime", query, reply)


def test_pre_settlement_observation_cannot_be_replayed_after_activation_settles():
    owner, _ = coordinator()
    attempt = prepare(owner)
    owner.dispatch("demo", attempt["attempt_id"])
    owner.close_admission("demo")
    premature = observation(1)
    with pytest.raises(ContractError, match="PENDING_NATIVE_WORK"):
        owner.observation_request("demo", owner_approved=True)
    with pytest.raises(ContractError, match="PENDING_NATIVE_WORK"):
        owner.prove_quiescent("demo", premature, owner_approved=True)

    owner.settle(attempt["attempt_id"], *result(owner, attempt))
    current = fresh_observation(owner)
    assert current["observed_at"] == premature["observed_at"]
    assert current["admission_generation"] == premature["admission_generation"]
    with pytest.raises(ContractError, match="STALE_OBSERVATION_BARRIER"):
        owner.prove_quiescent("demo", premature, owner_approved=True)
    assert owner.snapshot()["quiescent"]["demo"] is False
    owner.prove_quiescent("demo", current, owner_approved=True)
    owner.open_admission("demo", owner_approved=True)


@pytest.mark.parametrize("state", ["prepared", "dispatched", "reconciling"])
def test_outstanding_work_cannot_receive_a_post_drain_challenge(state):
    owner, _ = coordinator()
    attempt = prepare(owner)
    if state != "prepared":
        owner.dispatch("demo", attempt["attempt_id"])
    if state == "reconciling":
        owner.settle(
            attempt["attempt_id"],
            *result(
                owner,
                attempt,
                acknowledgment="unknown",
                task_state="unknown",
                effect_certainty="unknown",
                postcondition="unknown",
            ),
        )
    owner.close_admission("demo")
    retained = owner.snapshot()
    with pytest.raises(ContractError, match="PENDING_NATIVE_WORK"):
        owner.observation_request("demo", owner_approved=True)
    assert owner.snapshot() == retained


def test_new_containment_work_invalidates_a_scan_even_with_the_same_admission_generation():
    owner, _ = coordinator()
    owner.close_admission("demo")
    previous = fresh_observation(owner)
    attempt = containment(owner)
    owner.dispatch("demo", attempt["attempt_id"])
    owner.settle(attempt["attempt_id"], *result(owner, attempt))
    with pytest.raises(ContractError, match="OBSERVATION_BARRIER_REQUIRED"):
        owner.prove_quiescent("demo", previous, owner_approved=True)
    current = fresh_observation(owner)
    assert current["admission_generation"] == previous["admission_generation"]
    assert current["barrier"]["id"] != previous["barrier"]["id"]
    with pytest.raises(ContractError, match="STALE_OBSERVATION_BARRIER"):
        owner.prove_quiescent("demo", previous, owner_approved=True)
    owner.prove_quiescent("demo", current, owner_approved=True)


@pytest.mark.parametrize("executor", ["runtime", "service"])
def test_new_accepted_work_invalidates_a_proved_clearance(executor):
    owner, _ = coordinator()
    if executor == "service":
        delegated(owner)
    owner.close_admission("demo")
    owner.prove_quiescent("demo", fresh_observation(owner), owner_approved=True)
    assert owner.snapshot()["quiescent"]["demo"] is True
    attempt = containment(owner) if executor == "runtime" else prepare_service(owner, "stopped")
    assert owner.snapshot()["quiescent"]["demo"] is False
    with pytest.raises(ContractError, match="QUIESCENCE_REQUIRED"):
        owner.open_admission("demo", owner_approved=True)
    owner.cancel_prepared(attempt["attempt_id"], owner_approved=True)
    with pytest.raises(ContractError, match="QUIESCENCE_REQUIRED"):
        owner.open_admission("demo", owner_approved=True)
    owner.prove_quiescent("demo", fresh_observation(owner), owner_approved=True)
    owner.open_admission("demo", owner_approved=True)


def test_challenges_are_replaced_and_consumed_once():
    owner, _ = coordinator()
    owner.close_admission("demo")
    first = fresh_observation(owner)
    second = fresh_observation(owner, method="inventory")
    with pytest.raises(ContractError, match="STALE_OBSERVATION_BARRIER"):
        owner.prove_quiescent("demo", first, owner_approved=True)
    owner.prove_quiescent("demo", second, owner_approved=True)
    with pytest.raises(ContractError, match="OBSERVATION_BARRIER_REQUIRED"):
        owner.prove_quiescent("demo", second, owner_approved=True)


@pytest.mark.parametrize("phase", ["issue", "result", "consume"])
def test_native_exclusion_is_required_at_each_authority_boundary(phase):
    owner, _ = coordinator()
    acquisition = {"id": identifier(90)}
    owner.native_exclusion = lambda scope: acquisition["id"]
    owner.close_admission("demo")
    if phase != "issue":
        current = fresh_observation(owner)
    if phase == "consume":
        owner.prove_quiescent("demo", current, owner_approved=True)
    acquisition["id"] = None
    with pytest.raises(ContractError, match="NATIVE_EXCLUSION_REQUIRED"):
        if phase == "issue":
            owner.observation_request("demo", owner_approved=True)
        elif phase == "result":
            owner.prove_quiescent("demo", current, owner_approved=True)
        else:
            owner.open_admission("demo", owner_approved=True)
    assert owner.snapshot()["admission"]["demo"] is False


@pytest.mark.parametrize("phase", ["result", "consume"])
def test_reacquired_native_exclusion_requires_a_new_scan(phase):
    owner, _ = coordinator()
    acquisition = {"id": identifier(90)}
    owner.native_exclusion = lambda scope: acquisition["id"]
    owner.close_admission("demo")
    previous = fresh_observation(owner)
    if phase == "consume":
        owner.prove_quiescent("demo", previous, owner_approved=True)
    acquisition["id"] = identifier(91)
    expected = "STALE_OBSERVATION_BARRIER" if phase == "result" else "STALE_QUIESCENCE_PROOF"
    with pytest.raises(ContractError, match=expected):
        if phase == "result":
            owner.prove_quiescent("demo", previous, owner_approved=True)
        else:
            owner.open_admission("demo", owner_approved=True)
    current = fresh_observation(owner)
    assert current["barrier"]["exclusion_id"] != previous["barrier"]["exclusion_id"]
    owner.prove_quiescent("demo", current, owner_approved=True)
    owner.open_admission("demo", owner_approved=True)


@pytest.mark.parametrize("phase", ["issue", "result"])
def test_request_data_cannot_replace_current_owner_permission(phase):
    owner, _ = coordinator()
    owner.close_admission("demo")
    if phase == "result":
        current = fresh_observation(owner)
    with pytest.raises(ContractError, match="OBSERVATION_NOT_AUTHORIZED"):
        if phase == "issue":
            owner.observation_request("demo", owner_approved=False)
        else:
            owner.prove_quiescent("demo", current, owner_approved=False)
    query = owner.observation_request("demo", owner_approved=True)
    query["input"]["native_exclusion"] = True
    with pytest.raises(ContractError):
        check_request("runtime", query)


def test_changed_executor_permission_cannot_consume_an_outstanding_scan():
    owner, _ = coordinator()
    owner.close_admission("demo")
    current = fresh_observation(owner)
    _, descriptor, instance = runtime_registry()
    instance["grants"][0].update(access=["observe"], mutation=None)
    replacement = Registry()
    replacement.install(
        {
            "implementation": descriptor["id"],
            "artifact": {"digest": D, "media_type": "application/zip", "size_bytes": 100},
            "descriptor_digest": digest(descriptor),
            "enabled": True,
        },
        descriptor,
        owner_approved=True,
    )
    replacement.enroll(instance, owner_approved=True)
    owner.registry = replacement
    with pytest.raises(ContractError, match="RUNTIME_MUTATION_AUTHORITY"):
        owner.prove_quiescent("demo", current, owner_approved=True)
    assert owner.snapshot()["quiescent"]["demo"] is False


def test_restore_preserves_work_but_cannot_restore_a_challenge_or_clearance():
    owner, _ = coordinator()
    attempt = prepare(owner)
    owner.dispatch("demo", attempt["attempt_id"])
    owner.settle(attempt["attempt_id"], *result(owner, attempt))
    owner.close_admission("demo")
    previous = fresh_observation(owner)
    owner.prove_quiescent("demo", previous, owner_approved=True)
    saved = owner.snapshot()
    restored = AdapterCoordinator(
        OWNER, owner.registry, lambda value: None, native_exclusion=native_exclusion
    )
    restored.restore(copy.deepcopy(saved))
    assert restored.snapshot()["attempts"] == saved["attempts"]
    assert restored.snapshot()["requests"] == saved["requests"]
    assert restored.snapshot()["results"] == saved["results"]
    assert restored.snapshot()["quiescent"]["demo"] is False
    with pytest.raises(ContractError, match="QUIESCENCE_REQUIRED"):
        restored.open_admission("demo", owner_approved=True)
    with pytest.raises(ContractError, match="OBSERVATION_IDENTITY"):
        restored.prove_quiescent("demo", previous, owner_approved=True)
    restored.prove_quiescent("demo", fresh_observation(restored), owner_approved=True)
    restored.open_admission("demo", owner_approved=True)
