"""Exact compute targets and complete resource observation snapshot intake."""

from __future__ import annotations

import copy
import hashlib

import pytest
from fishhat_adapters import ObservationSequence, check_invocation, check_request, check_response
from fishhat_adapters.process import validate_process_launch
from fishhat_contracts.validation import ContractError, canonical, digest

from tests.linear_support import assert_linear, measure
from tests.test_adapter_handoffs import installed, invocation_for, response_for
from tests.test_adapter_invocations import recovered
from tests.test_adapter_quantities import counter, limit, observe, request

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/compute-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/storage-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resources.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter-process.schema.json",
    ],
    "scope": "exact allocation incarnations and consistent complete resource observations",
    "relationship": "candidate",
    "reason": "Recreation and adversarial page substitutions exercise receiver joins without claiming native enforcement or isolation.",
    "claims": [],
}


def compute_query(method):
    value = request()
    value["method"] = method
    if method == "observe":
        del value["input"]["limits"]
        value["input"].update(cursor=None, limit=8)
    return value


def compute_page(*, limits=(), counters=(), cursor=None, continuation=None):
    query, reply = observe(list(counters))
    query["input"].update(cursor=cursor, limit=8)
    reply.update(
        request_digest=digest(query),
        coverage="complete" if continuation is None else "incomplete",
        continuation=continuation,
    )
    reply["output"]["limits"] = list(limits)
    return query, reply


def storage_page(*, index=0, count=1, cursor=None, continuation=None):
    _, binding = installed("storage")
    query = {
        "contract": "fishhat.storage",
        "method": "observe",
        "input": {"scope": binding["scope"], "binding": binding, "cursor": cursor, "limit": 8},
    }
    reply = {
        "contract": query["contract"],
        "method": "observe",
        "request_digest": digest(query),
        "scope": binding["scope"],
        "coverage": "complete" if continuation is None else "incomplete",
        "continuation": continuation,
        "proposal": None,
        "problem": None,
        "output": {
            "allocations": [
                {
                    "handle": f"allocation:{value}",
                    "accounting_domain": "domain:approved",
                    "native_identity_digest": digest(["native-allocation", value]),
                    "purposes": ["state"],
                    "counters": [counter("storage-used", 0, allocation=f"allocation:{value}")],
                    "hard_isolation": True,
                    "capacity_bytes": 2048,
                    "capacity_inodes": 64,
                }
                for value in range(index, index + count)
            ]
        },
    }
    return query, reply


def sequence(role, query):
    target = query["input"].get("target")
    return ObservationSequence(
        role,
        query,
        approved_binding=target["executor"] if role == "compute" else query["input"]["binding"],
        approved_compute_target=target,
    )


def process_case(registry, executor, payload, *, mode="query"):
    configuration = registry.inspect_instance(executor["instance"])["configuration"]
    installation, descriptor = registry._installations[executor["installation_digest"]]

    def artifact(value):
        return {
            "digest": digest(value),
            "size_bytes": len(canonical(value)),
            "media_type": "application/json",
        }

    manifest = {
        "format": "fishhat.adapter-process/v1",
        "mode": mode,
        "role": executor["role"],
        "executor": executor,
        "request": artifact(payload),
        "configuration": artifact(configuration),
        "inputs": {
            "digest": "sha256:" + hashlib.sha256(b"").hexdigest(),
            "size_bytes": 0,
            "media_type": "application/x-ndjson",
        },
        "private_inputs": None,
    }
    return (
        manifest,
        configuration,
        {
            "descriptor": descriptor,
            "approved_installation": installation,
            "expected_executor": executor,
            "expected_private_use": None,
        },
    )


@pytest.mark.parametrize("method", ["plan", "set-limits", "observe"])
def test_compute_request_requires_complete_target_and_rejects_handle_only_form(method):
    query = compute_query(method)
    check_request("compute", query)
    original = digest(query)
    query["input"]["target"]["incarnation"] = "incarnation:replacement"
    assert digest(query) != original
    query["input"]["allocation"] = query["input"].pop("target")["handle"]
    with pytest.raises(ContractError):
        check_request("compute", query)


@pytest.mark.parametrize("method", ["plan", "set-limits", "observe"])
def test_compute_target_scope_cannot_differ_from_request_scope(method):
    query = compute_query(method)
    query["input"]["target"]["executor"]["scope"] = {
        **query["input"]["scope"],
        "handle": "allocation:foreign",
    }
    with pytest.raises(ContractError, match="COMPUTE_TARGET_IDENTITY"):
        check_request("compute", query)


@pytest.mark.parametrize("method", ["plan", "observe", "set-limits", "reconcile"])
@pytest.mark.parametrize("approval", ["missing", "replacement"])
def test_compute_launch_requires_independent_exact_allocation_approval(method, approval):
    registry, executor = installed("compute")
    mutation = request()
    invocation = invocation_for(mutation)
    query = recovered(invocation) if method == "reconcile" else compute_query(method)
    target = copy.deepcopy(mutation["input"]["target"])
    selected = copy.deepcopy(target)
    if approval == "missing":
        selected = None
    else:
        selected["incarnation"] = "incarnation:replacement"
    if method == "set-limits":
        registry.authorize_invocation(
            "compute", invocation, owner_approved=True, expected_compute_target=target
        )
        with pytest.raises(ContractError, match="COMPUTE_APPROVED_TARGET"):
            registry.authorize_invocation(
                "compute", invocation, owner_approved=True, expected_compute_target=selected
            )
    else:
        kwargs = {"invocation": invocation} if method == "reconcile" else {}
        registry.authorize_request(
            executor["instance"],
            "compute",
            query,
            owner_approved=True,
            expected_compute_target=target,
            **kwargs,
        )
        with pytest.raises(ContractError, match="COMPUTE_APPROVED_TARGET"):
            registry.authorize_request(
                executor["instance"],
                "compute",
                query,
                owner_approved=True,
                expected_compute_target=selected,
                **kwargs,
            )
    payload = invocation if method == "set-limits" else query
    manifest, configuration, kwargs = process_case(
        registry, executor, payload, mode="mutation" if method == "set-limits" else "query"
    )
    kwargs["retained_invocation"] = invocation
    validate_process_launch(
        manifest, payload, configuration, expected_compute_target=target, **kwargs
    )
    with pytest.raises(ContractError, match="process compute allocation target is not approved"):
        validate_process_launch(
            manifest, payload, configuration, expected_compute_target=selected, **kwargs
        )


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
@pytest.mark.parametrize("field", ["incarnation", "handle", "executor"])
def test_compute_result_cannot_substitute_same_handle_replacement_or_other_target(field, reconcile):
    original = request()
    invocation = invocation_for(original)
    query = recovered(invocation) if reconcile else original
    reply = response_for(
        query,
        invocation["attempt"],
        {"target": copy.deepcopy(original["input"]["target"]), "limits": [limit()], "counters": []},
    )
    check_response("compute", query, reply, invocation=invocation)
    target = reply["output"]["target"]
    if field == "executor":
        target["executor"]["instance_generation"] += 1
    else:
        target[field] += ":replacement"
    with pytest.raises(ContractError, match="COMPUTE_TARGET_IDENTITY"):
        check_response("compute", query, reply, invocation=invocation)


def test_compute_reconciliation_preserves_original_target_instead_of_current_binding():
    invocation = invocation_for(request())
    query = recovered(invocation)
    invocation["request"]["input"]["target"]["incarnation"] = "incarnation:replacement"
    with pytest.raises(ContractError, match="INVOCATION_IDENTITY"):
        check_invocation("compute", invocation)
    invocation["attempt"]["input_digest"] = digest(invocation["request"])
    reply = response_for(
        query,
        invocation["attempt"],
        {"target": invocation["request"]["input"]["target"], "limits": [limit()], "counters": []},
    )
    with pytest.raises(ContractError, match="RECONCILIATION_IDENTITY"):
        check_response("compute", query, reply, invocation=invocation)


def test_compute_observation_cannot_supply_its_own_incarnation_approval():
    query, reply = compute_page()
    approved = copy.deepcopy(query["input"]["target"])
    query["input"]["target"]["incarnation"] = "incarnation:replacement"
    reply["output"]["target"] = copy.deepcopy(query["input"]["target"])
    reply["request_digest"] = digest(query)
    check_response("compute", query, reply)
    with pytest.raises(ContractError, match="COMPUTE_APPROVED_TARGET"):
        ObservationSequence(
            "compute",
            query,
            approved_binding=approved["executor"],
            approved_compute_target=approved,
        )


def test_storage_observation_requires_independently_approved_observer():
    registry, observer = installed("storage")
    query, _ = storage_page()
    registry.authorize_request(observer["instance"], "storage", query, owner_approved=True)
    ObservationSequence("storage", query, approved_binding=observer)
    manifest, configuration, kwargs = process_case(registry, observer, query)
    validate_process_launch(manifest, query, configuration, **kwargs)

    query["input"]["binding"]["instance_generation"] += 1
    check_request("storage", query)
    with pytest.raises(ContractError, match="HANDOFF_INSTANCE_IDENTITY"):
        registry.authorize_request(observer["instance"], "storage", query, owner_approved=True)
    with pytest.raises(ContractError, match="OBSERVATION_APPROVED_BINDING"):
        ObservationSequence("storage", query, approved_binding=observer)
    manifest, configuration, kwargs = process_case(registry, observer, query)
    with pytest.raises(ContractError, match="process query binding is not approved"):
        validate_process_launch(manifest, query, configuration, **kwargs)
    del query["input"]["binding"]
    with pytest.raises(ContractError):
        check_request("storage", query)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
def test_compute_success_requires_verified_nonnull_target(reconcile):
    original = request()
    invocation = invocation_for(original)
    query = recovered(invocation) if reconcile else original
    reply = response_for(
        query, invocation["attempt"], {"target": None, "limits": [limit()], "counters": []}
    )
    with pytest.raises(ContractError):
        check_response("compute", query, reply, invocation=invocation)


@pytest.mark.parametrize("coverage", ["complete", "unknown"])
def test_compute_missing_target_is_explicit_empty_and_never_retargeted(coverage):
    query, reply = compute_page()
    reply["coverage"] = coverage
    reply["output"]["target"] = None
    check_response("compute", query, reply)
    traversal = sequence("compute", query)
    assert traversal.accept(query, reply)
    assert traversal.complete == (coverage == "complete")
    reply["output"]["limits"] = [limit()]
    with pytest.raises(ContractError, match="UNKNOWN_ALLOCATION_QUANTITIES"):
        check_response("compute", query, reply)


@pytest.mark.parametrize("kind", ["limit", "counter", "allocation"])
def test_resource_snapshot_rejects_cross_page_conflicts_without_consuming_failed_page(kind):
    role = "storage" if kind == "allocation" else "compute"
    if kind == "allocation":
        first, reply = storage_page(continuation="page:two")
        second, other = storage_page(cursor="page:two")
        other["output"]["allocations"][0]["capacity_bytes"] += 1
    else:
        initial = {"limits": [limit()]} if kind == "limit" else {"counters": [counter()]}
        first, reply = compute_page(continuation="page:two", **initial)
        second, other = compute_page(cursor="page:two", **copy.deepcopy(initial))
        other["output"]["limits" if kind == "limit" else "counters"][0]["value"] += 1
    traversal = sequence(role, first)
    assert traversal.accept(first, reply)
    assert not traversal.accept(first, reply)
    with pytest.raises(ContractError, match="OBSERVATION_DUPLICATE_IDENTITY"):
        traversal.accept(second, other)
    assert not traversal.complete
    if kind == "allocation":
        second, other = storage_page(index=1, cursor="page:two")
    elif kind == "limit":
        second, other = compute_page(limits=[limit("tasks-max", 64, "tasks")], cursor="page:two")
    else:
        second, other = compute_page(counters=[counter("swap-used")], cursor="page:two")
    assert traversal.accept(second, other)
    assert traversal.complete
    assert not traversal.accept(first, reply)
    assert not traversal.accept(second, other)


@pytest.mark.parametrize("first_quantity", ["memory-high", "memory-max"])
def test_compute_snapshot_joins_memory_limits_across_pages_without_rescanning(first_quantity):
    second_quantity = "memory-max" if first_quantity == "memory-high" else "memory-high"
    first, reply = compute_page(limits=[limit(first_quantity, 2048)], continuation="page:two")
    traversal = sequence("compute", first)
    traversal.accept(first, reply)
    second, other = compute_page(
        limits=[limit(second_quantity, 1024 if second_quantity == "memory-max" else 4096)],
        cursor="page:two",
    )
    check_response("compute", second, other)
    with pytest.raises(ContractError, match="INCONSISTENT_MEMORY_LIMITS"):
        traversal.accept(second, other)
    other["output"]["limits"][0]["value"] = 2048
    assert traversal.accept(second, other)
    assert traversal.complete


def test_compute_snapshot_cannot_end_with_absence_after_returning_quantities():
    first, reply = compute_page(limits=[limit()], continuation="page:two")
    traversal = sequence("compute", first)
    traversal.accept(first, reply)
    second, other = compute_page(cursor="page:two")
    other["output"]["target"] = None
    with pytest.raises(ContractError, match="COMPUTE_OBSERVATION_TARGET_CHANGED"):
        traversal.accept(second, other)
    other["output"]["target"] = copy.deepcopy(first["input"]["target"])
    assert traversal.accept(second, other)


def test_compute_snapshot_failure_does_not_turn_unavailable_identity_into_absence():
    first, reply = compute_page(limits=[limit()], continuation="page:two")
    traversal = sequence("compute", first)
    traversal.accept(first, reply)
    second, other = compute_page(cursor="page:two")
    other["output"]["target"] = None
    other["coverage"] = "unknown"
    assert traversal.accept(second, other)
    assert not traversal.complete
    assert not traversal.accept(second, other)


def test_compute_observation_rejects_replaced_incarnation_and_resumable_absence():
    query, reply = compute_page()
    reply["output"]["target"]["incarnation"] = "incarnation:replacement"
    with pytest.raises(ContractError, match="COMPUTE_TARGET_IDENTITY"):
        check_response("compute", query, reply)
    reply["output"]["target"] = None
    reply.update(coverage="incomplete", continuation="page:two")
    with pytest.raises(ContractError, match="UNKNOWN_COMPUTE_TARGET_NOT_RESUMABLE"):
        check_response("compute", query, reply)


@pytest.mark.parametrize("role", ["compute", "storage"])
def test_resource_page_retry_cannot_replace_the_accepted_reply(role):
    query, reply = compute_page(limits=[limit()]) if role == "compute" else storage_page()
    traversal = sequence(role, query)
    assert traversal.accept(query, reply)
    changed = copy.deepcopy(reply)
    if role == "compute":
        changed["output"]["limits"][0]["value"] += 1
    else:
        changed["output"]["allocations"][0]["native_identity_digest"] = digest("replacement")
    with pytest.raises(ContractError, match="OBSERVATION_PAGE_REPLAY_CHANGED"):
        traversal.accept(query, changed)
    assert not traversal.accept(query, reply)
    assert traversal.complete


@pytest.mark.parametrize("field", ["native_identity_digest", "capacity_bytes", "hard_isolation"])
def test_storage_snapshot_rejects_conflicting_logical_allocations_in_one_page(field):
    query, reply = storage_page(count=2)
    records = reply["output"]["allocations"]
    records[1] = copy.deepcopy(records[0])
    records[1][field] = {
        "native_identity_digest": digest("replacement"),
        "capacity_bytes": 4096,
        "hard_isolation": False,
    }[field]
    with pytest.raises(ContractError, match="OBSERVATION_DUPLICATE_IDENTITY"):
        check_response("storage", query, reply)


@pytest.mark.parametrize("role", ["compute", "storage"])
def test_resource_observation_sequence_linear_work(role):
    samples = []
    for count in (16, 64, 256):
        pages = []
        for index in range(0, count, 8):
            cursors = {
                "cursor": None if index == 0 else f"page:{index}",
                "continuation": None if index + 8 == count else f"page:{index + 8}",
            }
            pages.append(
                storage_page(index=index, count=8, **cursors)
                if role == "storage"
                else compute_page(
                    limits=[
                        limit("io-read-rate", 4096, "bytes-per-second", f"device:{value}")
                        for value in range(index, index + 8)
                    ],
                    **cursors,
                )
            )

        def traverse(pages=pages):
            traversal = sequence(role, pages[0][0])
            accepted = 0
            for query, reply in pages:
                accepted += traversal.accept(query, reply)
                assert not traversal.accept(query, reply)
            assert traversal.complete
            return accepted

        accepted, work = measure(traverse)
        assert accepted == count // 8
        samples.append((count, work))
    assert_linear(samples)


CHECK_OVERRIDES = {
    "test_resource_observation_sequence_linear_work": {
        "purpose": "implementation",
        "authority": [
            "release.toml#/engineering",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_observations.py#ObservationSequence.__init__",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_observations.py#ObservationSequence.accept",
        ],
        "scope": "complete compute and storage observation traversals with exact retries",
        "relationship": "scoped-witness",
        "reason": "Measured full traversal intake at increasing extents; no native snapshot, isolation or authorization qualification.",
        "claims": [
            "engineering:adapters.observation-sequence.start",
            "engineering:adapters.observation-sequence.accept",
        ],
    }
}
