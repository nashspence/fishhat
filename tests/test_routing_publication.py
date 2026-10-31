"""Exact native predecessor joins for complete owned-domain routing replacement."""

from __future__ import annotations

import copy
from functools import partial

import pytest
from fishhat_adapters import check_invocation, check_request, check_response
from fishhat_adapters.process import validate_process_launch
from fishhat_contracts.validation import ContractError, canonical, digest

from tests.adapter_support import identifier
from tests.linear_support import assert_linear, measure
from tests.test_adapter_handoffs import installed, invocation_for, response_for
from tests.test_adapter_process import identity
from tests.test_adapter_routing_identity import generation_digest, query

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/routing-publication.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ingress-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/network-adapter.schema.json",
    ],
    "scope": "complete replacement, explicit absence and exact native predecessor/result identities",
    "relationship": "candidate",
    "reason": "Independent original attempts and altered predecessor/incarnation/revision/receipt vectors test rejection and retained reconciliation; native atomic replacement, alias resolution and exclusion remain unqualified.",
    "claims": [],
}


def publication(role, *, absent=False, records=None):
    request = query(role, "publish", [] if records is None else records)
    if absent:
        request["input"]["expected_previous"] = None
    call = invocation_for(request)
    before = request["input"]["expected_previous"]
    after = {
        "native_incarnation": identifier(302) if absent else before["native_incarnation"],
        "revision": "publication:two",
        "digest": request["input"]["generation_digest" if role == "ingress" else "policy_digest"],
    }
    target = request["input"]["target"]
    reply = response_for(
        request,
        call["attempt"],
        {
            "observed": {"target": copy.deepcopy(target), "generation": copy.deepcopy(after)},
            "publication": {
                "attempt_id": call["attempt"]["attempt_id"],
                "target": copy.deepcopy(target),
                "before": copy.deepcopy(before),
                "after": after,
            },
        },
    )
    return request, call, reply


@pytest.mark.parametrize("role", ["ingress", "network"])
@pytest.mark.parametrize("absent", [False, True], ids=["replace", "create-if-absent"])
def test_empty_owned_replacement_has_an_explicit_present_generation(role, absent):
    request, call, reply = publication(role, absent=absent)
    registry, _ = installed(role)
    registry.authorize_invocation(role, call, owner_approved=True)
    check_response(role, request, reply, invocation=call)
    assert reply["output"]["observed"]["generation"] is not None
    assert (reply["output"]["publication"]["before"] is None) == absent


@pytest.mark.parametrize("role", ["ingress", "network"])
@pytest.mark.parametrize("field", ["target", "expected_previous"])
def test_publication_requires_explicit_domain_and_predecessor(role, field):
    request, _, _ = publication(role)
    del request["input"][field]
    with pytest.raises(ContractError):
        check_request(role, request)


@pytest.mark.parametrize("role", ["ingress", "network"])
@pytest.mark.parametrize("field", ["native_incarnation", "revision", "digest"])
def test_receipt_cannot_substitute_any_part_of_the_original_predecessor(role, field):
    request, call, reply = publication(role)
    before = reply["output"]["publication"]["before"]
    before[field] = (
        identifier(399)
        if field == "native_incarnation"
        else digest("other state")
        if field == "digest"
        else "publication:other"
    )
    with pytest.raises(ContractError, match="PUBLICATION_RECEIPT_IDENTITY"):
        check_response(role, request, reply, invocation=call)


@pytest.mark.parametrize("role", ["ingress", "network"])
@pytest.mark.parametrize("field", ["native_incarnation", "revision", "digest"])
def test_new_state_cannot_recreate_the_domain_reuse_revision_or_change_desired_bytes(role, field):
    request, call, reply = publication(role)
    receipt = reply["output"]["publication"]
    receipt["after"][field] = (
        identifier(399)
        if field == "native_incarnation"
        else digest("other content")
        if field == "digest"
        else receipt["before"]["revision"]
    )
    reply["output"]["observed"]["generation"] = copy.deepcopy(receipt["after"])
    with pytest.raises(ContractError, match=r"PUBLICATION_(RECEIPT|PREDECESSOR)_IDENTITY"):
        check_response(role, request, reply, invocation=call)


@pytest.mark.parametrize("role", ["ingress", "network"])
@pytest.mark.parametrize("field", ["attempt_id", "target", "before"])
def test_create_if_absent_receipt_binds_the_original_attempt_and_absence(role, field):
    request, call, reply = publication(role, absent=True)
    receipt = reply["output"]["publication"]
    if field == "attempt_id":
        receipt[field] = identifier(399)
    elif field == "target":
        receipt[field]["namespace"]["resource"] = "foreign-domain"
    else:
        receipt[field] = copy.deepcopy(receipt["after"])
    with pytest.raises(ContractError, match="PUBLICATION_RECEIPT_IDENTITY"):
        check_response(role, request, reply, invocation=call)


@pytest.mark.parametrize("role", ["ingress", "network"])
@pytest.mark.parametrize("field", ["observed", "publication"])
def test_success_cannot_be_just_the_desired_content_digest(role, field):
    request, call, reply = publication(role)
    reply["output"][field] = None
    with pytest.raises(ContractError, match="PUBLICATION_SUCCESS_EVIDENCE"):
        check_response(role, request, reply, invocation=call)


@pytest.mark.parametrize("role", ["ingress", "network"])
def test_success_requires_observation_of_the_exact_after_generation(role):
    request, call, reply = publication(role)
    reply["output"]["observed"]["generation"]["revision"] = "publication:other"
    with pytest.raises(ContractError, match="PUBLICATION_SUCCESS_EVIDENCE"):
        check_response(role, request, reply, invocation=call)


@pytest.mark.parametrize("role", ["ingress", "network"])
def test_native_namespace_must_be_in_the_exact_enrolled_mutation_grant(role):
    request, _, _ = publication(role)
    request["input"]["target"]["namespace"]["resource"] = "foreign-domain"
    request["input"]["generation_digest" if role == "ingress" else "policy_digest"] = (
        generation_digest(role, request["input"])
    )
    call = invocation_for(request)
    registry, _ = installed(role)
    with pytest.raises(ContractError, match="PUBLICATION_NAMESPACE_NOT_GRANTED"):
        registry.authorize_invocation(role, call, owner_approved=True)


@pytest.mark.parametrize("role", ["ingress", "network"])
@pytest.mark.parametrize("changed", [False, True], ids=["missing", "substituted"])
def test_routing_query_requires_independent_target_approval(role, changed):
    request = query(role, "plan", [])
    registry, executor = installed(role)
    target = copy.deepcopy(request["input"]["target"]) if changed else None
    if target is not None:
        target["namespace"]["resource"] = "another-domain"
    with pytest.raises(ContractError, match="PUBLICATION_APPROVED_TARGET"):
        registry.authorize_request(
            executor["instance"],
            role,
            request,
            owner_approved=True,
            expected_publication_target=target,
        )
    instance = registry.inspect_instance(executor["instance"])
    installation, descriptor = registry._installations[executor["installation_digest"]]
    manifest = {
        "format": "fishhat.adapter-process/v1",
        "mode": "query",
        "role": role,
        "executor": executor,
        "request": identity(canonical(request)),
        "configuration": identity(canonical(instance["configuration"])),
        "inputs": identity(b"", "application/x-ndjson"),
        "private_inputs": None,
    }
    with pytest.raises(ContractError, match="publication target is not approved"):
        validate_process_launch(
            manifest,
            request,
            instance["configuration"],
            descriptor=descriptor,
            approved_installation=installation,
            expected_executor=executor,
            expected_private_use=None,
            expected_publication_target=target,
        )
    registry.authorize_request(
        executor["instance"],
        role,
        request,
        owner_approved=True,
        expected_publication_target=request["input"]["target"],
    )


@pytest.mark.parametrize("role", ["ingress", "network"])
def test_lost_publication_reply_reconciles_the_original_native_precondition(role):
    request, call, reply = publication(role)
    original = copy.deepcopy(call)
    recovered = {
        "contract": request["contract"],
        "method": "reconcile",
        "input": {"scope": copy.deepcopy(request["input"]["scope"]), "invocation": call},
    }
    reply.update(method="reconcile", request_digest=digest(recovered))
    check_response(role, recovered, reply, invocation=original)
    call["request"]["input"]["expected_previous"]["revision"] = "publication:replacement"
    call["attempt"]["input_digest"] = digest(call["request"])
    reply["request_digest"] = digest(recovered)
    with pytest.raises(ContractError, match="RECONCILIATION_IDENTITY"):
        check_response(role, recovered, reply, invocation=original)


@pytest.mark.parametrize("role", ["ingress", "network"])
@pytest.mark.parametrize("changed", ["digest", "records", "target"])
def test_generation_digest_pins_the_complete_desired_artifact(role, changed):
    request, _, _ = publication(role)
    inputs = request["input"]
    if changed == "digest":
        inputs["generation_digest" if role == "ingress" else "policy_digest"] = digest("other")
    elif changed == "target":
        inputs["target"]["namespace"]["resource"] = "other-domain"
    elif role == "ingress":
        inputs["routes"] = [
            {
                "name": "web",
                "listener": "https",
                "upstream": "app:web",
                "policy_digest": digest("p"),
            }
        ]
    else:
        inputs["rules"] = [
            {"handle": "web", "direction": "ingress", "action": "allow", "endpoint": "web"}
        ]
    with pytest.raises(ContractError, match="PUBLICATION_GENERATION_DIGEST"):
        check_request(role, request)


@pytest.mark.parametrize("role", ["ingress", "network"])
def test_rejected_precondition_does_not_create_a_publication_receipt(role):
    request, call, reply = publication(role)
    receipt = copy.deepcopy(reply["output"]["publication"])
    reply["output"]["publication"] = None
    reply["output"]["observed"]["generation"] = {
        **request["input"]["expected_previous"],
        "revision": "publication:concurrent-writer",
    }
    reply["effect"].update(
        acknowledgment="rejected", effect_certainty="none", postcondition="not-satisfied"
    )
    check_response(role, request, reply, invocation=call)
    reply["output"]["publication"] = receipt
    with pytest.raises(ContractError, match="PUBLICATION_RECEIPT_WITHOUT_EFFECT"):
        check_response(role, request, reply, invocation=call)


@pytest.mark.parametrize("role", ["ingress", "network"])
def test_routing_publication_linear_work(role):
    for name in ("check_request", "check_invocation", "check_response"):
        samples = []
        for count in (16, 64, 256):
            records = (
                [
                    {
                        "name": f"route-{index:04d}",
                        "listener": f"listener:{index:04d}",
                        "upstream": f"app:{index:04d}",
                        "policy_digest": digest("approved policy"),
                    }
                    for index in range(count)
                ]
                if role == "ingress"
                else [
                    {
                        "handle": f"rule:{index:04d}",
                        "direction": "ingress",
                        "action": "allow",
                        "endpoint": f"endpoint:{index:04d}",
                    }
                    for index in range(count)
                ]
            )
            request, call, reply = publication(role, records=records)
            operation = {
                "check_request": partial(check_request, role, request),
                "check_invocation": partial(check_invocation, role, call),
                "check_response": partial(check_response, role, request, reply, invocation=call),
            }[name]
            result, work = measure(operation)
            assert result is None
            samples.append((count, work))
        assert_linear(samples)


CHECK_OVERRIDES = {
    "test_routing_publication_linear_work": {
        "purpose": "implementation",
        "authority": [
            "release.toml#/engineering",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_semantics.py",
            "packages/fishhat-contracts/src/fishhat_contracts/targets.py",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_semantics.py#check_request",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_semantics.py#check_invocation",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_semantics.py#check_response",
        ],
        "scope": "complete ingress/network vectors, canonical generation digest and retained result joins",
        "relationship": "scoped-witness",
        "reason": "Measure each public semantic boundary independently over 16, 64 and 256 records; this establishes local linear work only, not native replacement or exclusion.",
        "claims": [
            "engineering:adapters.check_request",
            "engineering:adapters.check_invocation",
            "engineering:adapters.check_response",
        ],
    }
}
