"""Synthetic resource identity handoffs, without native enforcement claims."""

import json
from copy import deepcopy

import pytest
from fishhat_contracts.resources import (
    ReservationModel,
    check_capacity,
    resource_bindings_digest,
    validate_host_resources,
    validate_snapshot,
)
from fishhat_contracts.validation import ContractError, strict_yaml, validate

from tests.support import fixture_path

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resources.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json",
    ],
    "scope": "portable resource selection and exact capacity binding joins",
    "relationship": "candidate",
    "reason": "Synthetic provider selections, alias collisions and replaced identities exercise pure reference validators, not native quota enforcement or admission authority.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_capacity_snapshot_rejects_duplicate_buckets_even_for_distinct_allocations": {
        "purpose": "public-contract",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json#/$defs/CapacitySnapshot"
        ],
        "scope": "one approved native allocation for each logical capacity bucket",
        "relationship": "candidate",
        "reason": "Independent extra-allocation and replaced-bucket cases must reject at both schema and semantic boundaries; this does not qualify native quota enforcement.",
        "claims": [],
    },
}

NOW = "2026-10-19T12:00:00Z"


def snapshot():
    return json.loads(fixture_path("examples/resources/capacity-snapshot.json").read_text())


def request():
    return json.loads(fixture_path("examples/resources/capacity-request.json").read_text())


def host():
    return strict_yaml(fixture_path("examples/host-node-a/host.yaml").read_text())


@pytest.mark.parametrize("implementation", ["fixture.project-quota", "fixture.dataset-quota"])
def test_generic_source_accepts_distinct_selected_storage_implementations(implementation):
    value = host()
    value["adapter_instances"]["workload-storage"]["implementation"] = implementation
    validate_host_resources(value)


@pytest.mark.parametrize("field", ["instance", "allocation"])
def test_compute_selection_requires_declared_role_and_scope(field):
    value = host()
    value["resources"]["accounts"]["app-demo-app"]["compute"][field] = "quadlet"
    with pytest.raises(ContractError):
        validate_host_resources(value)


def test_two_buckets_cannot_claim_the_same_opaque_allocation():
    value = host()
    storage = value["resources"]["accounts"]["app-demo-app"]["storage"]
    storage["scratch"]["allocation"] = storage["runtime"]["allocation"]
    with pytest.raises(ContractError, match="duplicate storage allocation"):
        validate_host_resources(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("instance", "other-storage"),
        ("installation_digest", "sha256:" + "b" * 64),
        ("configuration_digest", "sha256:" + "b" * 64),
        ("instance_generation", 2),
        ("instance_digest", "sha256:" + "b" * 64),
        (
            "scope",
            {
                "authority": "00000000-0000-4000-8000-000000000009",
                "kind": "allocation",
                "handle": "workload-pool",
            },
        ),
    ],
    ids=["instance", "installation", "configuration", "generation", "enrollment", "scope"],
)
def test_quota_cannot_substitute_any_part_of_pool_executor(field, value):
    observed = snapshot()
    observed["quotas"][0]["storage"]["pool"]["executor"][field] = value
    with pytest.raises(ContractError, match="pool binding mismatch"):
        validate_snapshot(observed)


def test_distinct_adapter_names_do_not_prove_independent_pool_capacity():
    observed = snapshot()
    other = deepcopy(observed["pools"][0])
    other["pool"] = "alias-pool"
    other["storage"]["executor"]["instance"] = "other-storage"
    other["storage"]["handle"] = "alias-handle"
    observed["pools"].append(other)
    with pytest.raises(ContractError, match="duplicate pool capacity domain"):
        validate_snapshot(observed)


def test_control_pool_alias_cannot_share_workload_capacity():
    observed = snapshot()
    observed["control_pool"]["capacity_domain"] = observed["pools"][0]["storage"]["capacity_domain"]
    with pytest.raises(ContractError, match="control and workload capacity domain overlap"):
        validate_snapshot(observed)


@pytest.mark.parametrize("change", ["pool", "allocation", "instance", "owner-epoch"])
def test_internally_consistent_replacement_cannot_reuse_approved_capacity_request(change):
    approved = request()
    observed = snapshot()
    if change == "pool":
        observed["pools"][0]["storage"]["incarnation"] = "pool-recreated"
        for quota in observed["quotas"]:
            quota["storage"]["pool"] = deepcopy(observed["pools"][0]["storage"])
    elif change == "allocation":
        observed["quotas"][0]["storage"]["incarnation"] = "allocation-recreated"
    elif change == "instance":
        observed["pools"][0]["storage"]["executor"]["instance_generation"] += 1
        for quota in observed["quotas"]:
            quota["storage"]["pool"] = deepcopy(observed["pools"][0]["storage"])
    else:
        observed["owner"]["epoch"] = "00000000-0000-4000-8000-000000000009"
    validate_snapshot(observed)
    with pytest.raises(ContractError, match="approved resource bindings"):
        check_capacity(
            observed, approved, approved_bindings_digest=approved["bindings_digest"], now=NOW
        )


def test_caller_cannot_recompute_the_expected_owner_approval():
    observed = snapshot()
    proposed = request()
    approved_digest = proposed["bindings_digest"]
    observed["quotas"][0]["storage"]["incarnation"] = "replacement-allocation"
    proposed["bindings_digest"] = resource_bindings_digest(observed)
    with pytest.raises(ContractError, match="approved resource bindings"):
        check_capacity(observed, proposed, approved_bindings_digest=approved_digest, now=NOW)


@pytest.mark.parametrize("field", ["max_bytes", "headroom_bytes", "reserve_bytes", "root"])
def test_accounting_cannot_rewrite_approved_capacity_policy(field):
    observed, proposed = snapshot(), request()
    if field == "reserve_bytes":
        observed["pools"][0][field] = 0
    elif field == "root":
        observed["quotas"][0][field] = "/srv/other/runtime"
    elif field == "headroom_bytes":
        observed["quotas"][0][field] = 0
    else:
        observed["quotas"][0][field] *= 2
    with pytest.raises(ContractError, match="approved resource bindings"):
        check_capacity(
            observed, proposed, approved_bindings_digest=proposed["bindings_digest"], now=NOW
        )


def test_writer_cessation_cannot_release_a_claim_on_a_replacement_allocation():
    proposed = request()
    book = ReservationModel(snapshot(), approved_bindings_digest=proposed["bindings_digest"])
    book.reserve(proposed, now=NOW)
    book.timeout(proposed["operation_id"])
    book.snapshot["quotas"][0]["storage"]["incarnation"] = "replacement-allocation"
    before = deepcopy(book.snapshot)
    with pytest.raises(ContractError, match="approved resource bindings"):
        book.release(proposed["operation_id"], writer_stopped=True)
    assert book.snapshot == before
    assert book.requests[proposed["operation_id"]]["phase"] == "reconciling"


def test_accounting_updates_and_order_do_not_change_approved_binding_identity():
    observed = snapshot()
    expected = request()["bindings_digest"]
    observed["quotas"].reverse()
    observed["quotas"][0]["used_bytes"] += 1
    observed["pools"][0]["available_bytes"] -= 1
    observed["observed_at"] = "2026-10-19T12:00:01Z"
    assert resource_bindings_digest(observed) == expected


@pytest.mark.parametrize("shape", ["extra-allocation", "replaced-bucket"])
def test_capacity_snapshot_rejects_duplicate_buckets_even_for_distinct_allocations(shape):
    observed = snapshot()
    other = deepcopy(observed["quotas"][0])
    other["storage"]["handle"] = "separate-runtime-allocation"
    other["root"] = "/srv/ops/separate-runtime"
    if shape == "extra-allocation":
        observed["quotas"].append(other)
    else:
        observed["quotas"][1] = other
    with pytest.raises(ContractError):
        validate("resource-records.schema.json", observed, "CapacitySnapshot")
    with pytest.raises(ContractError):
        validate_snapshot(observed)


def test_reordered_capacity_buckets_reserve_and_release_the_same_allocations():
    observed, proposed = snapshot(), request()
    observed["quotas"].reverse()
    before = {quota["bucket"]: deepcopy(quota) for quota in observed["quotas"]}
    book = ReservationModel(observed, approved_bindings_digest=proposed["bindings_digest"])
    book.reserve(proposed, now=NOW)
    growth = {item["bucket"]: item for item in proposed["growth"]}
    for quota in book.snapshot["quotas"]:
        for unit in ("bytes", "inodes"):
            assert quota["reserved_remaining_" + unit] == (
                before[quota["bucket"]]["reserved_remaining_" + unit]
                + growth.get(quota["bucket"], {}).get(unit, 0)
            )
    book.release(proposed["operation_id"], writer_stopped=True)
    assert {quota["bucket"]: quota for quota in book.snapshot["quotas"]} == before


def test_resource_bindings_cannot_hide_a_native_provider_field():
    observed = snapshot()
    observed["quotas"][0]["storage"]["project_id"] = 10001
    with pytest.raises(ContractError):
        validate_snapshot(observed)


@pytest.mark.parametrize("collection", ["accounts", "pools"])
@pytest.mark.parametrize("name", ["a" * 25, "account-"], ids=["too-long", "trailing-hyphen"])
def test_resource_source_names_cannot_exceed_their_record_identifier_type(collection, name):
    resources = host()["resources"]
    entries = resources[collection]
    entries[name] = entries.pop(next(iter(entries)))
    with pytest.raises(ContractError, match=r"schema resources\.schema\.json"):
        validate("resources.schema.json", resources, "HostResources")


@pytest.mark.parametrize("name", ["a", "a" * 24], ids=["minimum", "maximum"])
def test_resource_account_name_round_trips_from_source_to_accounting(name):
    source = host()
    accounts = source["resources"]["accounts"]
    accounts[name] = accounts.pop("maintainer")
    validate_host_resources(source)
    observed = snapshot()
    observed["account"] = name
    validate_snapshot(observed)
    assert observed["account"] in source["resources"]["accounts"]
