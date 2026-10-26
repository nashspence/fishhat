"""Exact service events, boot policy and software selection across owner handoffs."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import Registry, check_request, check_response, instance_reference
from fishhat_contracts.validation import ContractError, digest

from tests.adapter_support import (
    OWNER,
    identifier,
    runtime_sources,
    service_instance,
    service_request,
)
from tests.test_adapter_effects import coordinator
from tests.test_adapter_handoffs import artifact, invocation_for, response_for
from tests.test_adapter_invocations import recovered

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/service-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/software-adapter.schema.json",
    ],
    "scope": "exact target, independent software version and boot/hold policy, and attempt-bound service-event custody",
    "relationship": "candidate",
    "reason": "Synthetic native evidence tests the contract and durable reference boundary, not actual supervisors or package managers.",
    "claims": [],
}


def selected(role="service", names=("web",)):
    empty = {"type": "object", "properties": {}, "additionalProperties": False}
    source = {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
        "additionalProperties": False,
    }
    methods = (
        ["plan", "apply", "observe", "reconcile"]
        if role == "service"
        else ["resolve", "install", "retire", "observe", "reconcile"]
    )
    descriptor = {
        "format": "deployment-ops/adapter/v1",
        "id": "independent.example-" + role,
        "roles": [role],
        "entrypoint": "bin/adapter",
        "configuration_schema": empty,
        "component_schema": empty,
        "source_schema": source,
        "implemented": [role + "." + method for method in methods],
        "native_qualified": False,
    }
    scope = {
        "authority": OWNER["id"],
        "kind": "application" if role == "service" else "software",
        "handle": "demo",
    }
    namespaces = [
        {
            "authority": OWNER["id"],
            "resource": name,
            "facet": "lifecycle" if role == "service" else "software",
        }
        for name in names
    ]
    instance = {
        "id": "selected",
        "implementation": descriptor["id"],
        "installation_digest": artifact("a")["digest"],
        "role": role,
        "schema_digest": digest(empty),
        "configuration": {},
        "generation": 1,
        "grants": [
            {
                "scope": scope,
                "access": ["observe", "change"],
                "mutation": {"controller": "selected", "namespaces": namespaces},
            }
        ],
    }
    registry = Registry()
    registry.install(
        {
            "implementation": descriptor["id"],
            "artifact": artifact("a"),
            "descriptor_digest": digest(descriptor),
            "enabled": True,
        },
        descriptor,
        owner_approved=True,
    )
    registry.enroll(instance, owner_approved=True)
    targets = []
    for name, namespace in zip(names, namespaces, strict=True):
        target = {
            "selection": {
                "instance": "selected",
                "source_schema_digest": digest(source),
                "source": {"name": name},
            },
            "executor": instance_reference(instance, scope),
            "namespace": namespace,
        }
        registry.enroll_source_target(target, owner_approved=True)
        targets.append(target)
    return registry, targets


def service_query(target, *, enabled=False, transition="ensure"):
    return {
        "contract": "fishhat.service",
        "method": "apply",
        "input": {
            "scope": target["executor"]["scope"],
            "target": target,
            "intent": {"enabled": enabled, "activity": "running", "transition": transition},
        },
    }


def service_output(query, attempt, *, mode="native"):
    inputs = query["input"]
    action = inputs["intent"]["transition"]
    transition = None
    if action != "ensure":
        steps = [action] if mode == "native" else ["stop", "start"]
        transition = {
            "attempt_id": attempt["attempt_id"],
            "target": copy.deepcopy(inputs["target"]),
            "transition": action,
            "outcome": "succeeded",
            "mode": mode,
            "confirmations": [
                {"action": step, "receipt": artifact(letter)}
                for step, letter in zip(steps, "cd", strict=False)
            ],
        }
    return {
        "services": [
            {
                "target": copy.deepcopy(inputs["target"]),
                "enabled": inputs["intent"]["enabled"],
                "activity": inputs["intent"]["activity"],
            }
        ],
        "transition": transition,
    }


def test_running_disabled_service_has_independent_boot_policy_intent_and_evidence():
    registry, (target,) = selected()
    query = service_query(target)
    original = invocation_for(query)
    registry.authorize_invocation("service", original, owner_approved=True)
    response = response_for(query, original["attempt"], service_output(query, original["attempt"]))
    check_response("service", query, response, invocation=original)
    changed = copy.deepcopy(query)
    changed["input"]["intent"]["enabled"] = True
    assert digest(changed) != digest(query)
    new = invocation_for(changed)
    stale = response_for(changed, new["attempt"], response["output"])
    with pytest.raises(ContractError, match="SERVICE_INTENT_NOT_OBSERVED"):
        check_response("service", changed, stale, invocation=new)
    stale["output"]["services"][0]["enabled"] = True
    check_response("service", changed, stale, invocation=new)


@pytest.mark.parametrize(
    "action,mode", [("reload", "native"), ("restart", "native"), ("restart", "stop-start")]
)
@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "lost-reply"])
def test_service_event_requires_exact_attempt_bound_completion(action, mode, reconcile):
    _, (target,) = selected()
    original = service_query(target, transition=action)
    invocation = invocation_for(original)
    query = recovered(invocation) if reconcile else original
    output = service_output(original, invocation["attempt"], mode=mode)
    response = response_for(query, invocation["attempt"], output)
    check_response("service", query, response, invocation=invocation)
    missing = copy.deepcopy(response)
    missing["output"]["transition"] = None
    with pytest.raises(ContractError, match="SERVICE_EVENT_EVIDENCE_REQUIRED"):
        check_response("service", query, missing, invocation=invocation)
    output["transition"]["attempt_id"] = identifier(99)
    with pytest.raises(ContractError, match="SERVICE_EVENT_IDENTITY"):
        check_response("service", query, response, invocation=invocation)


def test_compound_restart_requires_ordered_stop_then_start_confirmations():
    _, (target,) = selected()
    query = service_query(target, transition="restart")
    invocation = invocation_for(query)
    output = service_output(query, invocation["attempt"], mode="stop-start")
    response = response_for(query, invocation["attempt"], output)
    output["transition"]["confirmations"].reverse()
    with pytest.raises(ContractError, match="SERVICE_EVENT_CONFIRMATIONS"):
        check_response("service", query, response, invocation=invocation)
    output["transition"]["confirmations"] = output["transition"]["confirmations"][-1:]
    with pytest.raises(ContractError, match="SERVICE_EVENT_CONFIRMATIONS"):
        check_response("service", query, response, invocation=invocation)


def test_unsupported_reload_is_explicit_no_effect_rejection_and_never_a_restart():
    _, (target,) = selected()
    query = service_query(target, transition="reload")
    invocation = invocation_for(query)
    output = service_output(query, invocation["attempt"])
    output["transition"].update(outcome="unsupported", mode=None, confirmations=[])
    response = response_for(query, invocation["attempt"], output)
    response["effect"].update(
        acknowledgment="rejected", effect_certainty="none", postcondition="not-satisfied"
    )
    check_response("service", query, response, invocation=invocation)
    output["transition"]["confirmations"] = [{"action": "restart", "receipt": artifact("e")}]
    with pytest.raises(ContractError, match="UNSUPPORTED_SERVICE_EVENT_HAS_EFFECT"):
        check_response("service", query, response, invocation=invocation)


def test_delegated_reload_lost_reply_reconciles_without_a_second_dispatch():
    owner, _ = coordinator()
    owner.registry.enroll(service_instance(owner.registry), owner_approved=True)
    query = service_request(registry=owner.registry)
    query["input"]["intent"]["transition"] = "reload"
    attempt = owner.prepare_service(
        "demo",
        "service-demo",
        query,
        **runtime_sources(owner.registry),
        operation_id=identifier(20),
        effect_id=identifier(21),
        attempt_id=identifier(22),
        owner_approved=True,
    )
    invocation = owner.dispatch("demo", attempt["attempt_id"])
    with pytest.raises(ContractError, match="RECONCILE_REQUIRED"):
        owner.dispatch("demo", attempt["attempt_id"])
    reconcile = recovered(invocation)
    response = response_for(reconcile, attempt, service_output(query, attempt))
    owner.settle(attempt["attempt_id"], reconcile, response)
    assert owner.snapshot()["attempts"][attempt["attempt_id"]]["outcome"] == "succeeded"


def test_service_observation_keeps_mixed_states_keyed_and_paged():
    registry, targets = selected(names=("web", "worker"))
    query = {
        "contract": "fishhat.service",
        "method": "observe",
        "input": {
            "scope": targets[0]["executor"]["scope"],
            "binding": targets[0]["executor"],
            "cursor": None,
            "limit": 1,
        },
    }
    registry.authorize_request("selected", "service", query, owner_approved=True)
    records = [
        {"target": target, "enabled": enabled, "activity": activity}
        for target, enabled, activity in zip(
            targets, [False, True], ["running", "stopped"], strict=True
        )
    ]
    response = {
        "contract": query["contract"],
        "method": "observe",
        "request_digest": digest(query),
        "scope": query["input"]["scope"],
        "coverage": "incomplete",
        "continuation": "page:second",
        "proposal": None,
        "output": {"services": records[:1], "transition": None},
    }
    check_response("service", query, response)
    query["input"]["cursor"] = "page:second"
    response.update(request_digest=digest(query), coverage="complete", continuation=None)
    response["output"]["services"] = records[1:]
    check_response("service", query, response)
    response["output"]["services"] = records
    with pytest.raises(ContractError, match="OBSERVATION_PAGE_CAPACITY"):
        check_response("service", query, response)


@pytest.mark.parametrize("method", ["install", "retire"])
@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "lost-reply"])
def test_software_hold_policy_round_trips_without_artifact_inference(method, reconcile):
    registry, (target,) = selected("software", ("package",))
    original = {
        "contract": "fishhat.software",
        "method": method,
        "input": {
            "scope": target["executor"]["scope"],
            "target": target,
            "artifacts": [artifact("b")],
            "held": True,
        },
    }
    invocation = invocation_for(original)
    registry.authorize_invocation("software", invocation, owner_approved=True)
    query = recovered(invocation) if reconcile else original
    output = {
        "packages": [
            {
                "target": target,
                "state": "present" if method == "install" else "absent",
                "held": True,
                "artifacts": [artifact("b")] if method == "install" else [],
            }
        ]
    }
    response = response_for(query, invocation["attempt"], output)
    check_response("software", query, response, invocation=invocation)
    output["packages"][0]["held"] = False
    with pytest.raises(ContractError, match="SOFTWARE_POLICY_NOT_OBSERVED"):
        check_response("software", query, response, invocation=invocation)
    changed = copy.deepcopy(original)
    changed["input"]["held"] = False
    assert digest(changed) != digest(original)


@pytest.mark.parametrize("version", [None, "1:2.3-4"], ids=["provider-selection", "exact-version"])
def test_software_resolution_echoes_requested_policy_without_claiming_it_is_enforced(version):
    registry, (target,) = selected("software", ("package",))
    query = {
        "contract": "fishhat.software",
        "method": "resolve",
        "input": {
            "scope": target["executor"]["scope"],
            "target": target,
            "artifacts": [],
            "held": True,
            "version": version,
        },
    }
    registry.authorize_request("selected", "software", query, owner_approved=True)
    response = {
        "contract": query["contract"],
        "method": "resolve",
        "request_digest": digest(query),
        "scope": query["input"]["scope"],
        "coverage": "complete",
        "continuation": None,
        "proposal": None,
        "output": {
            "target": target,
            "requested_held": True,
            "requested_version": version,
            "state": "resolved",
            "artifacts": [artifact("b")],
        },
    }
    check_response("software", query, response)
    response["output"]["held"] = True
    with pytest.raises(ContractError):
        check_response("software", query, response)


def test_software_version_selection_changes_request_without_rebinding_target():
    registry, (target,) = selected("software", ("package",))
    requests = []
    for version in ["1", "2", None]:
        query = {
            "contract": "fishhat.software",
            "method": "resolve",
            "input": {
                "scope": target["executor"]["scope"],
                "target": copy.deepcopy(target),
                "artifacts": [],
                "held": False,
                "version": version,
            },
        }
        registry.authorize_request("selected", "software", query, owner_approved=True)
        assert (
            registry.source_target(target["selection"], "software", target["executor"]["scope"])
            == target
        )
        requests.append(query)
    assert len({digest(query) for query in requests}) == 3
    assert all(query["input"]["target"] == target for query in requests)
    # Resolution carries an explicit selection, including provider selection as null.
    missing = copy.deepcopy(requests[0])
    del missing["input"]["version"]
    with pytest.raises(ContractError):
        check_request("software", missing)


@pytest.mark.parametrize("state", ["resolved", "absent", "unknown"])
@pytest.mark.parametrize("version", [None, "1"], ids=["provider-selection", "exact-version"])
def test_software_resolution_cannot_substitute_another_requested_version(state, version):
    _, (target,) = selected("software", ("package",))
    query = {
        "contract": "fishhat.software",
        "method": "resolve",
        "input": {
            "scope": target["executor"]["scope"],
            "target": target,
            "artifacts": [],
            "held": False,
            "version": version,
        },
    }
    response = {
        "contract": query["contract"],
        "method": "resolve",
        "request_digest": digest(query),
        "scope": query["input"]["scope"],
        "coverage": "unknown" if state == "unknown" else "complete",
        "continuation": None,
        "proposal": None,
        "output": {
            "target": target,
            "requested_held": False,
            "requested_version": version,
            "state": state,
            "artifacts": [artifact("b")] if state == "resolved" else [],
        },
    }
    check_response("software", query, response)
    response["output"]["requested_version"] = "2"
    with pytest.raises(ContractError, match="SOFTWARE_RESOLUTION_IDENTITY"):
        check_response("software", query, response)
    del response["output"]["requested_version"]
    with pytest.raises(ContractError):
        check_response("software", query, response)


@pytest.mark.parametrize("role", ["service", "software"])
def test_target_mapping_cannot_be_replaced_inside_accepted_intent(role):
    registry, (target,) = selected(role)
    query = (
        service_query(target)
        if role == "service"
        else {
            "contract": "fishhat.software",
            "method": "install",
            "input": {
                "scope": target["executor"]["scope"],
                "target": target,
                "artifacts": [artifact("b")],
                "held": True,
            },
        }
    )
    changed = copy.deepcopy(query)
    changed["input"]["target"]["namespace"]["resource"] = "other"
    check_request(role, changed)
    with pytest.raises(ContractError, match="SOURCE_TARGET_MAPPING_IDENTITY"):
        registry.authorize_invocation(role, invocation_for(changed), owner_approved=True)
