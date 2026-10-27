"""Complete resource-operation work, including every cleanup batch and retry."""

import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from types import FunctionType

import pytest
from fishhat_contracts import resources
from fishhat_contracts.resources import (
    ReservationModel,
    plan_cleanup,
    resource_bindings_digest,
    retained_runtime_handles,
    revalidate_cleanup,
    validate_host_resources,
    validate_inventory,
)
from fishhat_contracts.validation import ContractError, digest

from tests.linear_support import assert_linear, measure
from tests.test_resources import load
from tests.test_retention_authority import NOW, inputs

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": ["release.toml#/engineering"],
    "scope": "complete resource-reference operations with deterministic container and Python work",
    "relationship": "scoped-witness",
    "reason": "Growing full graphs, custody and account sets challenge all batches and retries together; no native lock, accounting, deletion or invalidation continuation is established.",
    "claims": [],
}

SCALES = (16, 64, 256)


def growing_inventory(count):
    policy, retention, inventory = inputs()
    template = inventory["items"][5]
    for index in range(count):
        inventory["items"].append(
            {
                **deepcopy(template),
                "handle": "sha256:" + f"{1000 + index:064x}",
                "native_id": f"{1000 + index:064x}",
            }
        )
        inventory["items"].append(
            {
                **deepcopy(template),
                "handle": "sha256:" + f"{100000 + index:064x}",
                "native_id": f"{100000 + index:064x}",
                "references": [] if index == 0 else ["sha256:" + f"{99999 + index:064x}"],
            }
        )
    inventory["protected_roots"].append("sha256:" + f"{99999 + count:064x}")
    inventory["max_objects"] = 3
    return policy, retention, inventory


def test_inventory_linear_work():
    samples = []
    for count in SCALES:
        _, _, inventory = growing_inventory(count)
        result, work = measure(
            lambda inventory=inventory: validate_inventory(inventory), modules=(resources,)
        )
        assert len(result) == 2 * count + 8
        samples.append((count, work))
    assert_linear(samples)


def complete_cleanup(policy, retention, inventory):
    plan = plan_cleanup(inventory, accepted_policy=policy, retention_inventory=retention, now=NOW)
    traversal = revalidate_cleanup(
        plan,
        inventory,
        accepted_policy=policy,
        retention_inventory=retention,
        now=NOW,
        exclusion=object(),
    )
    current = traversal.custody
    removed = []
    while batch := traversal.next_batch():
        assert 1 <= len(batch) <= 3
        for candidate in batch:
            # A confirmed no-effect attempt may retry in the same custody.
            traversal.before_delete(candidate, current=current, now=NOW)
            traversal.record_outcome(candidate["handle"], "not-removed", current=current, now=NOW)
            traversal.before_delete(candidate, current=current, now=NOW)
            current = replace(current, generation=current.generation + 1)
            traversal.record_outcome(candidate["handle"], "removed", current=current, now=NOW)
            removed.append(candidate["handle"])
    assert len(removed) == len(set(removed)) == len(plan["candidates"])
    return removed


def test_cleanup_complete_traversal_linear_work():
    samples = []
    for count in SCALES:
        policy, retention, inventory = growing_inventory(count)
        removed, work = measure(
            lambda policy=policy, retention=retention, inventory=inventory: complete_cleanup(
                policy, retention, inventory
            ),
            modules=(resources,),
        )
        assert len(removed) == count + 3
        samples.append((count, work))
    assert_linear(samples)


def test_retention_linear_work():
    samples = []
    for count in SCALES:
        policy, retention, _ = inputs()
        template = retention["releases"][1]
        retention["releases"].extend(
            {
                **deepcopy(template),
                "release_digest": "sha256:" + f"{index:064x}",
                "runtime_handles": ["sha256:" + f"{1000 + index:064x}"],
                "blocking_refs": [f"retained-operation-{index:04d}"],
            }
            for index in range(count)
        )
        value, work = measure(
            lambda policy=policy, retention=retention: retained_runtime_handles(
                retention, accepted_policy=policy, now=NOW
            ),
            modules=(resources,),
        )
        assert len(value["protected_roots"]) == count + 2
        samples.append((count, work))
    assert_linear(samples)
    samples = []
    for count in SCALES:
        policy, retention, _ = inputs()
        release = retention["releases"][0]
        retention["releases"] = [release]
        release["runtime_handles"] = ["sha256:" + f"{index:064x}" for index in range(count)]
        release["blocking_refs"] = [f"retained-operation-{index:04d}" for index in range(count)]
        value, work = measure(
            lambda policy=policy, retention=retention: retained_runtime_handles(
                retention, accepted_policy=policy, now=NOW
            ),
            modules=(resources,),
        )
        assert len(value["protected_roots"]) == count
        assert value["release_reasons"][release["release_digest"]] == sorted(
            [
                *release["blocking_refs"],
                "accepted-target-active-or-inactive",
                "minimum-retention-age",
            ]
        )
        assert all(
            value["handle_releases"][handle] == [release["release_digest"]]
            for handle in release["runtime_handles"]
        )
        # Preserve every reason and incidence once, never their cross-product.
        assert sum(map(len, value["release_reasons"].values())) == count + 2
        assert sum(map(len, value["handle_releases"].values())) == count
        samples.append((count, work))
    assert_linear(samples)


def test_host_resources_linear_work():
    samples = []
    for count in SCALES:
        host = load("examples/host-node-a/host.yaml")
        template = host["resources"]["accounts"]["maintainer"]
        host["resources"]["accounts"] = {}
        host["app_accounts"] = {}
        compute = host["adapter_instances"][template["compute"]["instance"]]
        grant = deepcopy(compute["grants"][0])
        compute["grants"] = []
        for index in range(count):
            name = f"user-{index:04d}"
            account = deepcopy(template)
            account.update(login=name, subject=name)
            account["compute"]["allocation"] = name
            compute["grants"].append(
                {**deepcopy(grant), "scope": {"kind": "allocation", "handle": name}}
            )
            for kind, quota in account["storage"].items():
                quota.update(root=f"/srv/ops/{name}/{kind}", allocation=f"{name}-{kind}")
            host["resources"]["accounts"][name] = account
        for pool in host["resources"]["pools"].values():
            pool["allocation_budget_bytes"] = pool["allocation_budget_inodes"] = 2**52
        _, work = measure(lambda host=host: validate_host_resources(host), modules=(resources,))
        samples.append((count, work))
    assert_linear(samples)


def test_reservation_request_linear_work():
    samples = []
    for count in SCALES:
        snapshot = load("examples/resources/capacity-snapshot.json")
        request = load("examples/resources/capacity-request.json")
        template = snapshot["pools"][0]
        snapshot["pools"] = []
        for index in sorted(range(count), key=digest):
            pool = deepcopy(template)
            name = f"pool-{index:04d}"
            pool["pool"] = name
            pool["storage"].update(handle=name, capacity_domain=f"domain-{index:04d}")
            pool["storage"]["executor"]["scope"]["handle"] = name
            snapshot["pools"].append(pool)
        # All four semantic buckets participate; only admitted pool extent grows.
        for quota, pool in zip(snapshot["quotas"], snapshot["pools"][-4:], strict=True):
            quota["pool"] = pool["pool"]
            quota["storage"]["pool"] = deepcopy(pool["storage"])
        request["growth"] = [
            {"bucket": quota["bucket"], "bytes": 1024, "inodes": 1} for quota in snapshot["quotas"]
        ]
        # Independent previous-format encoding pins protected binding identity.
        projection = {
            key: snapshot[key]
            for key in ("owner", "account", "resource_generation", "control_pool")
        }
        projection["pools"] = sorted(
            [
                {key: pool[key] for key in ("pool", "storage", "reserve_bytes", "reserve_inodes")}
                for pool in snapshot["pools"]
            ],
            key=lambda pool: pool["pool"],
        )
        projection["quotas"] = sorted(
            [
                {
                    key: quota[key]
                    for key in (
                        "bucket",
                        "pool",
                        "storage",
                        "root",
                        "max_bytes",
                        "max_inodes",
                        "headroom_bytes",
                        "headroom_inodes",
                    )
                }
                for quota in snapshot["quotas"]
            ],
            key=lambda quota: quota["bucket"],
        )
        encoded = json.dumps(
            projection, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode()
        approved = "sha256:" + hashlib.sha256(encoded).hexdigest()
        assert resource_bindings_digest(snapshot) == approved
        request["bindings_digest"] = approved

        def complete(snapshot=snapshot, request=request, approved=approved):
            book = ReservationModel(snapshot, approved_bindings_digest=approved)
            first = book.reserve(request, now=NOW)
            assert book.reserve(request, now=NOW) == first
            reserved = deepcopy(book.snapshot)
            book.timeout(request["operation_id"])
            with pytest.raises(ContractError, match="cessation evidence"):
                book.release(request["operation_id"], writer_stopped=False)
            assert book.snapshot == reserved
            # A refreshed snapshot with unchanged bindings must be read anew;
            # an index retained from reserve would mutate this detached object.
            detached = book.snapshot
            book.snapshot = deepcopy(detached)
            book.snapshot["pools"].reverse()
            book.snapshot["quotas"].reverse()
            book.release(request["operation_id"], writer_stopped=True)
            book.release(request["operation_id"], writer_stopped=True)
            assert book.reserve(request, now=NOW)["phase"] == "released"
            return book.snapshot, detached, reserved

        (released, detached, reserved), work = measure(complete, modules=(resources,))
        assert detached == reserved
        expected = deepcopy(snapshot)
        expected["pools"].reverse()
        expected["quotas"].reverse()
        assert released == expected
        samples.append((count, work))
    assert_linear(samples)


def test_inventory_witness_rejects_repeated_complete_key_rebuild(monkeypatch):
    original = resources.validate_inventory

    def regressed(value):
        items = original(value)
        assert all(set(item["references"]) <= set(items) for item in items.values())
        return items

    # Run the faulty body in the real owner's namespace so its C constructors
    # are observed by exactly the same witness as the real implementation.
    replacement = FunctionType(regressed.__code__, vars(resources), closure=regressed.__closure__)
    monkeypatch.setattr(resources, "validate_inventory", replacement)
    with pytest.raises(AssertionError):
        test_cleanup_complete_traversal_linear_work()


def test_complete_traversal_witness_rejects_full_state_copy_per_deletion(monkeypatch):
    original = resources.CleanupTraversal.before_delete

    def regressed(self, candidate, *, current, now):
        # The full reviewed index is unchanged; copying it once per deletion
        # must be charged even though the copy executes wholly in C.
        self._candidates.copy()
        return original(self, candidate, current=current, now=now)

    monkeypatch.setattr(resources.CleanupTraversal, "before_delete", regressed)
    with pytest.raises(AssertionError):
        test_cleanup_complete_traversal_linear_work()


CHECK_OVERRIDES = {
    name: {
        **CHECK_PURPOSE,
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/resources.py#" + symbol
            for symbol in symbols
        ]
        + ["release.toml#/engineering"],
        "claims": ["engineering:" + identity for identity in identities],
    }
    for name, (identities, symbols) in {
        "test_inventory_linear_work": (["resources.inventory"], ["validate_inventory"]),
        "test_cleanup_complete_traversal_linear_work": (
            ["resources.cleanup-plan", "resources.cleanup-traversal"],
            ["plan_cleanup", "revalidate_cleanup"],
        ),
        "test_retention_linear_work": (["resources.retention"], ["retained_runtime_handles"]),
        "test_host_resources_linear_work": (["resources.host"], ["validate_host_resources"]),
        "test_reservation_request_linear_work": (
            ["resources.reservation.reserve", "resources.reservation.release"],
            ["ReservationModel.reserve", "ReservationModel.release"],
        ),
    }.items()
}

for _name in (
    "test_inventory_witness_rejects_repeated_complete_key_rebuild",
    "test_complete_traversal_witness_rejects_full_state_copy_per_deletion",
):
    CHECK_OVERRIDES[_name] = {
        "purpose": "validation-tooling",
        "authority": ["tests/test_resource_growth.py#test_cleanup_complete_traversal_linear_work"],
        "scope": "resource growth regression detection",
        "relationship": "no-product-claim",
        "reason": "Deliberately reinstated quadratic C-level work must fail the same complete-operation witness; this self-check grants no implementation qualification.",
        "claims": [],
    }
