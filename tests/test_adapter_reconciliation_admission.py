"""Mutation admission includes a usable, currently authorized recovery route."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import ROLES, Registry, check_descriptor, instance_reference
from fishhat_contracts.validation import ContractError, digest

from tests.adapter_support import SCOPE, D, request, runtime_registry
from tests.test_adapter_handoffs import invocation_for
from tests.test_adapter_invocations import recovered

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": ["packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json"],
    "scope": "per-method reconciliation capability and same-instance scoped observation authority at mutation admission",
    "relationship": "candidate",
    "reason": "Synthetic approved registries demonstrate admission and revocation checks, not native recovery or authentication.",
    "claims": [],
}


@pytest.mark.parametrize(
    "role,method",
    [
        (role, method)
        for role, methods in ROLES.items()
        for method, semantics in methods.items()
        if semantics["effect"]
    ],
)
def test_every_implemented_mutator_requires_its_role_reconciliation_method(role, method):
    _, descriptor, _ = runtime_registry()
    descriptor.update(roles=[role], implemented=[role + "." + method])
    with pytest.raises(ContractError, match="MISSING_RECONCILIATION_METHOD"):
        check_descriptor(descriptor)
    descriptor["implemented"].append(role + ".reconcile")
    check_descriptor(descriptor)
    descriptor["implemented"] = [role + ".reconcile"]
    check_descriptor(descriptor)


def enrollment(*, observe, other_scope=False):
    _, descriptor, instance = runtime_registry()
    if not observe:
        instance["grants"][0]["access"] = ["change"]
    if other_scope:
        instance["grants"].append(
            {
                "scope": {**SCOPE, "handle": "another-application"},
                "access": ["observe"],
                "mutation": None,
            }
        )
    registry = Registry()
    registry.install(
        {
            "implementation": descriptor["id"],
            "artifact": {"digest": D, "media_type": "application/zip", "size_bytes": 100},
            "descriptor_digest": digest(descriptor),
            "enabled": True,
        },
        descriptor,
        owner_approved=True,
    )
    registry.enroll(instance, owner_approved=True)
    invocation = invocation_for(request())
    invocation["attempt"]["executor"] = instance_reference(instance, SCOPE)
    return registry, invocation


@pytest.mark.parametrize("other_scope", [False, True], ids=["no-observe", "different-scope"])
def test_mutation_admission_rejects_without_observation_in_the_same_scope(other_scope):
    registry, invocation = enrollment(observe=False, other_scope=other_scope)
    with pytest.raises(ContractError, match="SCOPE_NOT_GRANTED"):
        registry.authorize_invocation("runtime", invocation, owner_approved=True)


def test_accepted_executor_can_reconcile_without_rebinding_or_reissuing_the_mutation():
    registry, invocation = enrollment(observe=True)
    original = copy.deepcopy(invocation)
    accepted = registry.authorize_invocation("runtime", invocation, owner_approved=True)
    inspected = registry.authorize_request(
        accepted["id"], "runtime", recovered(invocation), owner_approved=True, invocation=invocation
    )
    assert inspected == accepted
    assert invocation == original


def test_admission_does_not_override_current_recovery_permission_or_owner_approval():
    registry, invocation = enrollment(observe=True)
    registry.authorize_invocation("runtime", invocation, owner_approved=True)
    query = recovered(invocation)
    with pytest.raises(ContractError, match="OPERATION_NOT_AUTHORIZED"):
        registry.authorize_request(
            "native-demo", "runtime", query, owner_approved=False, invocation=invocation
        )
    current, _ = enrollment(observe=False)
    with pytest.raises(ContractError, match="SCOPE_NOT_GRANTED"):
        current.authorize_request(
            "native-demo", "runtime", query, owner_approved=True, invocation=invocation
        )
