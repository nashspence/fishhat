"""Independent runtime observation targets are explicit and owner-approved."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import (
    ObservationSequence,
    check_request,
    check_response,
    instance_reference,
    runtime_binding_digest,
)
from fishhat_adapters.process import validate_process_launch
from fishhat_contracts.validation import ContractError, canonical, digest, strict_json
from fishhat_owner.adapter_state import AdapterCoordinator

from tests.adapter_support import (
    OWNER,
    SCOPE,
    binding,
    identifier,
    native_exclusion,
    observation,
    runtime_registry,
    runtime_sources,
)
from tests.test_adapter_process import identity

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/runtime-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter-process.schema.json",
    ],
    "scope": "complete independent runtime observation context, current owner approval and exact response correlation",
    "relationship": "candidate",
    "reason": "Fresh serialized request handoffs and independent expected-target substitutions exercise correlation and disclosure boundaries, not native incarnation verification, exclusion or quiescence.",
    "claims": [],
}


def observation_case(method="observe"):
    registry, descriptor, instance = runtime_registry()
    target = binding()
    target.update(generation=17, native_incarnation=identifier(717), admission_generation=23)
    query = {
        "contract": "fishhat.runtime",
        "method": method,
        "input": {
            "scope": copy.deepcopy(SCOPE),
            "cursor": None,
            "limit": 10,
            "barrier": None,
            "binding": instance_reference(instance, SCOPE),
            "target": copy.deepcopy(target),
        },
    }
    observed = observation(target["admission_generation"])
    observed.update(
        generation=target["generation"], native_incarnation=target["native_incarnation"]
    )
    reply = {
        "contract": query["contract"],
        "method": method,
        "request_digest": digest(query),
        "scope": copy.deepcopy(SCOPE),
        "coverage": "complete",
        "continuation": None,
        "proposal": None,
        "problem": None,
        "output": {"deployment": None, "observation": observed, "objects": []},
    }
    return registry, descriptor, instance, target, query, reply


@pytest.mark.parametrize("method", ["observe", "inventory"])
def test_runtime_observation_requires_the_complete_pinned_target(method):
    _, _, _, _, query, _ = observation_case(method)
    check_request("runtime", query)
    del query["input"]["target"]["instance_digest"]
    with pytest.raises(ContractError):
        check_request("runtime", query)
    del query["input"]["target"]
    with pytest.raises(ContractError):
        check_request("runtime", query)


@pytest.mark.parametrize("method", ["observe", "inventory"])
@pytest.mark.parametrize(
    "field",
    [
        "instance",
        "installation_digest",
        "configuration_digest",
        "instance_generation",
        "instance_digest",
        "subject",
        "scope",
    ],
)
def test_runtime_target_cannot_substitute_its_observer_or_scope(method, field):
    _, _, _, _, query, _ = observation_case(method)
    target = query["input"]["target"]
    if field == "instance_generation":
        target[field] += 1
    elif field == "scope":
        target[field]["handle"] = "another-app"
    elif field.endswith("digest"):
        target[field] = digest("another-binding")
    else:
        target[field] = "another-app"
    with pytest.raises(ContractError, match="OBSERVATION_TARGET_IDENTITY"):
        check_request("runtime", query)


@pytest.mark.parametrize("method", ["observe", "inventory"])
@pytest.mark.parametrize("field", ["generation", "native_incarnation", "admission_generation"])
def test_ordinary_runtime_observation_matches_exact_target_without_a_barrier(method, field):
    _, _, _, _, query, reply = observation_case(method)
    check_response("runtime", query, reply)
    observed = reply["output"]["observation"]
    observed[field] = identifier(818) if field == "native_incarnation" else observed[field] + 1
    with pytest.raises(ContractError, match="OBSERVATION_TARGET_IDENTITY"):
        check_response("runtime", query, reply)


@pytest.mark.parametrize("method", ["observe", "inventory"])
@pytest.mark.parametrize("field", ["binding_digest", "admission_generation"])
def test_runtime_barrier_cannot_name_another_target_or_fence(method, field):
    _, _, _, target, query, _ = observation_case(method)
    barrier = {
        "id": identifier(80),
        "owner": copy.deepcopy(OWNER),
        "scope": copy.deepcopy(SCOPE),
        "binding_digest": runtime_binding_digest(target),
        "admission_generation": target["admission_generation"],
        "exclusion_id": identifier(90),
    }
    query["input"]["barrier"] = barrier
    check_request("runtime", query)
    barrier[field] = digest("another-target") if field == "binding_digest" else barrier[field] + 1
    with pytest.raises(ContractError, match="OBSERVATION_BARRIER_TARGET"):
        check_request("runtime", query)


@pytest.mark.parametrize("method", ["observe", "inventory"])
@pytest.mark.parametrize("changed", [False, True], ids=["missing", "substituted"])
def test_runtime_request_target_cannot_supply_its_own_approval(method, changed):
    registry, descriptor, instance, target, query, _ = observation_case(method)
    expected = copy.deepcopy(target) if changed else None
    if expected is not None:
        expected["generation"] += 1
    with pytest.raises(ContractError, match="OBSERVATION_APPROVED_TARGET"):
        registry.authorize_request(
            instance["id"],
            "runtime",
            query,
            owner_approved=True,
            expected_runtime_binding=expected,
        )
    with pytest.raises(ContractError, match="OBSERVATION_APPROVED_TARGET"):
        ObservationSequence(
            "runtime",
            query,
            approved_binding=query["input"]["binding"],
            approved_runtime_binding=expected,
        )
    installation = registry._installations[instance["installation_digest"]][0]
    manifest = {
        "format": "fishhat.adapter-process/v1",
        "mode": "query",
        "role": "runtime",
        "executor": query["input"]["binding"],
        "request": identity(canonical(query)),
        "configuration": identity(canonical(instance["configuration"])),
        "inputs": identity(b"", "application/x-ndjson"),
        "private_inputs": None,
    }
    with pytest.raises(ContractError, match="runtime observation target is not approved"):
        validate_process_launch(
            manifest,
            query,
            instance["configuration"],
            descriptor=descriptor,
            approved_installation=installation,
            expected_executor=query["input"]["binding"],
            expected_private_use=None,
            expected_runtime_binding=expected,
        )
    validate_process_launch(
        manifest,
        query,
        instance["configuration"],
        descriptor=descriptor,
        approved_installation=installation,
        expected_executor=query["input"]["binding"],
        expected_private_use=None,
        expected_runtime_binding=target,
    )


@pytest.mark.parametrize("method", ["observe", "inventory"])
def test_fresh_runtime_process_gets_binding_context_before_any_mutation(method):
    registry, _, _ = runtime_registry()
    owner = AdapterCoordinator(OWNER, registry, lambda _: None, native_exclusion=native_exclusion)
    owner.bind(binding(), **runtime_sources(registry), owner_approved=True)
    assert not owner.state["attempts"]
    query = owner.observation_request("demo", owner_approved=True, method=method)
    wire_request = strict_json(canonical(query))
    assert wire_request["input"]["target"] == owner.state["bindings"]["demo"]
    assert wire_request["input"]["target"] is not owner.state["bindings"]["demo"]
    target = wire_request["input"]["target"]
    assert target["generation"] >= 0
    assert target["native_incarnation"]
    assert (
        target["admission_generation"] == wire_request["input"]["barrier"]["admission_generation"]
    )


@pytest.mark.parametrize("field", ["generation", "native_incarnation", "admission_generation"])
def test_runtime_page_replay_keeps_original_target_and_rejects_changed_continuation(field):
    _, _, _, target, query, reply = observation_case()
    sequence = ObservationSequence(
        "runtime",
        query,
        approved_binding=query["input"]["binding"],
        approved_runtime_binding=target,
    )
    reply.update(coverage="incomplete", continuation="page:next")
    assert sequence.accept(query, reply)
    assert not sequence.accept(copy.deepcopy(query), copy.deepcopy(reply))
    continued = copy.deepcopy(query)
    continued["input"]["cursor"] = "page:next"
    changed = continued["input"]["target"]
    changed[field] = identifier(818) if field == "native_incarnation" else changed[field] + 1
    response = copy.deepcopy(reply)
    response.update(request_digest=digest(continued), coverage="complete", continuation=None)
    response["output"]["observation"][field] = changed[field]
    with pytest.raises(ContractError, match="OBSERVATION_SEQUENCE_QUERY"):
        sequence.accept(continued, response)
