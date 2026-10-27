"""Owner policy and custody bindings for cleanup; no native deletion or authentication."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest
from fishhat_contracts.resources import (
    plan_cleanup,
    retained_runtime_handles,
    revalidate_cleanup,
)
from fishhat_contracts.validation import ContractError, digest, strict_yaml

from tests.support import FIXTURES

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resources.schema.json#/$defs/RetentionPolicy",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json#/$defs/AcceptedRetentionPolicy",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json#/$defs/RetentionInventory",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json#/$defs/ColdDemotionReceipt",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json#/$defs/CleanupPlan",
    ],
    "scope": "exact current owner policy, retention closure and cleanup protection bindings",
    "relationship": "candidate",
    "reason": "Positive and substitution cases check offline policy derivation and fail-closed cleanup; trusted owner inputs do not demonstrate native authorization, receipt authentication or deletion.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_keep_local_policy_cannot_be_overridden_by_demotion_receipt": {
        **CHECK_PURPOSE,
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/resources.py#retained_runtime_handles"
        ],
        "relationship": "scoped-witness",
        "claims": ["engineering:resources.retention"],
    }
}

NOW = "2026-10-19T12:00:00Z"


def load(name):
    return json.loads((FIXTURES / "resources" / name).read_text())


def inputs():
    return (
        load("accepted-retention-policy.json"),
        load("retention-inventory.json"),
        load("cleanup-inventory.json"),
    )


def bind_current(policy, retention, inventory):
    """Model independently accepted owner state and a new matching native scan."""
    retention["policy_digest"] = digest(policy)
    inventory.update(
        policy_digest=digest(policy),
        retention_inventory_digest=digest(retention),
        protection_generation=retention["protection_generation"],
    )


def plan(policy, retention, inventory):
    return plan_cleanup(inventory, accepted_policy=policy, retention_inventory=retention, now=NOW)


def revalidate(value, policy, retention, inventory):
    revalidate_cleanup(
        value,
        inventory,
        accepted_policy=policy,
        retention_inventory=retention,
        now=NOW,
    )


def test_policy_fixture_is_exact_accepted_app_retention():
    policy, _, _ = inputs()
    app = strict_yaml((FIXTURES / "demo-app/app.yaml").read_text())
    assert policy["policy"] == app["resources"]["retention"]


@pytest.mark.parametrize("field,value", [("prior_releases", 1), ("minimum_prior_age_seconds", 0)])
def test_inventory_cannot_supply_replacement_policy(field, value):
    policy, retention, _ = inputs()
    retention[field] = value
    with pytest.raises(ContractError):
        retained_runtime_handles(retention, accepted_policy=policy, now=NOW)


def test_keep_local_policy_cannot_be_overridden_by_demotion_receipt():
    policy, retention, inventory = inputs()
    policy["policy"]["cold_archive"] = "keep-local"
    policy["generation"] += 1
    old = retention["releases"][2]
    old["cold_demotion_receipt"]["policy_digest"] = digest(policy)
    bind_current(policy, retention, inventory)
    decision = retained_runtime_handles(retention, accepted_policy=policy, now=NOW)
    assert not decision["cold_demoted_releases"]
    assert old["runtime_handles"][0] in decision["protected_roots"]
    assert old["runtime_handles"][0] not in {
        c["handle"] for c in plan(policy, retention, inventory)["candidates"]
    }


def test_retention_rejects_previous_accepted_policy_generation():
    policy, retention, _ = inputs()
    policy["generation"] += 1
    with pytest.raises(ContractError, match="policy authority changed"):
        retained_runtime_handles(retention, accepted_policy=policy, now=NOW)


def test_retention_rejects_another_accepted_release():
    policy, retention, _ = inputs()
    policy["release_digest"] = retention["releases"][1]["release_digest"]
    retention["policy_digest"] = digest(policy)
    with pytest.raises(ContractError, match="accepted retention release changed"):
        retained_runtime_handles(retention, accepted_policy=policy, now=NOW)


@pytest.mark.parametrize("field", ["owner", "account"])
def test_current_policy_must_belong_to_inventory_owner_and_account(field):
    policy, retention, _ = inputs()
    if field == "owner":
        policy[field]["epoch"] = "00000000-0000-4000-8000-000000000099"
    else:
        policy[field] = "other-account"
    retention["policy_digest"] = digest(policy)
    with pytest.raises(ContractError, match="policy authority changed"):
        retained_runtime_handles(retention, accepted_policy=policy, now=NOW)


@pytest.mark.parametrize(
    "field",
    [
        "owner",
        "account",
        "policy_digest",
        "release_digest",
        "archive_digest",
        "protection_generation",
    ],
)
def test_cold_demotion_receipt_cannot_be_substituted(field):
    policy, retention, _ = inputs()
    receipt = retention["releases"][2]["cold_demotion_receipt"]
    if field == "owner":
        receipt[field]["epoch"] = "00000000-0000-4000-8000-000000000099"
    elif field == "account":
        receipt[field] = "other-account"
    elif field == "protection_generation":
        receipt[field] += 1
    else:
        receipt[field] = "sha256:" + "f" * 64
    with pytest.raises(ContractError, match="receipt binding changed"):
        retained_runtime_handles(retention, accepted_policy=policy, now=NOW)


def test_native_scan_cannot_remove_owner_retention_protection():
    policy, retention, inventory = inputs()
    owner_roots = {r["runtime_handles"][0] for r in retention["releases"][:2]}
    inventory["protected_roots"] = [h for h in inventory["protected_roots"] if h not in owner_roots]
    for item in inventory["items"]:
        if item["handle"] in owner_roots:
            item["protected_by"] = []
    assert not owner_roots & {c["handle"] for c in plan(policy, retention, inventory)["candidates"]}


def test_native_scan_omitting_a_retained_handle_fails_closed():
    policy, retention, inventory = inputs()
    missing = retention["releases"][0]["runtime_handles"][0]
    inventory["protected_roots"].remove(missing)
    inventory["items"] = [item for item in inventory["items"] if item["handle"] != missing]
    with pytest.raises(ContractError, match="missing retained native object"):
        plan(policy, retention, inventory)


def test_cleanup_plan_binds_current_policy_and_protection_generation():
    policy, retention, inventory = inputs()
    result = plan(policy, retention, inventory)
    assert result["policy_digest"] == digest(policy)
    assert result["retention_inventory_digest"] == digest(retention)
    assert result["protection_generation"] == retention["protection_generation"]
    revalidate(result, policy, retention, inventory)


@pytest.mark.parametrize("field", ["kind", "native_id"])
def test_cleanup_candidate_cannot_substitute_a_protected_native_object(field):
    policy, retention, inventory = inputs()
    reviewed = plan(policy, retention, inventory)
    protected_handle = retention["releases"][0]["runtime_handles"][0]
    protected = next(item for item in inventory["items"] if item["handle"] == protected_handle)
    candidate = reviewed["candidates"][0]
    assert candidate[field] != protected[field]
    candidate[field] = protected[field]
    with pytest.raises(ContractError, match="cleanup candidate no longer safe"):
        revalidate(reviewed, policy, retention, inventory)


def test_cleanup_plan_cannot_repeat_a_candidate_handle():
    policy, retention, inventory = inputs()
    reviewed = plan(policy, retention, inventory)
    reviewed["candidates"].append(deepcopy(reviewed["candidates"][0]))
    with pytest.raises(ContractError, match="duplicate cleanup candidate handle"):
        revalidate(reviewed, policy, retention, inventory)


@pytest.mark.parametrize("indices", [[], [1], [0, 2]], ids=["empty", "single", "multiple"])
def test_cleanup_plan_can_retain_a_strict_subset_of_exact_safe_candidates(indices):
    policy, retention, inventory = inputs()
    reviewed = plan(policy, retention, inventory)
    original = deepcopy(reviewed["candidates"])
    reviewed["candidates"] = [original[index] for index in indices]
    assert len(reviewed["candidates"]) < len(original)
    revalidate(reviewed, policy, retention, inventory)


def test_new_owner_hold_rejects_stale_native_inventory():
    policy, retention, inventory = inputs()
    original = plan(policy, retention, inventory)
    retention["releases"][2]["blocking_refs"].append("new-recovery-hold")
    retention["protection_generation"] += 1
    with pytest.raises(ContractError, match="retention authority changed"):
        revalidate(original, policy, retention, inventory)


def test_new_owner_hold_survives_a_fresh_native_scan_and_invalidates_old_plan():
    policy, retention, inventory = inputs()
    original = plan(policy, retention, inventory)
    old = retention["releases"][2]
    old["blocking_refs"].append("new-recovery-hold")
    retention["protection_generation"] += 1
    bind_current(policy, retention, inventory)
    current = plan(policy, retention, inventory)
    assert old["runtime_handles"][0] not in {c["handle"] for c in current["candidates"]}
    with pytest.raises(ContractError):
        revalidate(original, policy, retention, inventory)


def test_changed_policy_invalidates_a_previously_reviewed_cleanup_plan():
    policy, retention, inventory = inputs()
    original = plan(policy, retention, inventory)
    policy["policy"]["cold_archive"] = "keep-local"
    policy["generation"] += 1
    retention["releases"][2]["cold_demotion_receipt"] = None
    bind_current(policy, retention, inventory)
    with pytest.raises(ContractError):
        revalidate(original, policy, retention, inventory)


def test_native_inventory_cannot_weaken_accepted_candidate_grace():
    policy, retention, inventory = inputs()
    inventory["minimum_age_seconds"] = 3600
    item = inventory["items"][6]
    item["last_used_at"] = "2026-10-19T10:00:00Z"
    assert item["handle"] not in {
        c["handle"] for c in plan(policy, retention, inventory)["candidates"]
    }


def test_stricter_native_protection_remains_in_force():
    policy, retention, inventory = inputs()
    target = inventory["items"][5]["handle"]
    baseline = plan(policy, retention, inventory)
    assert target in {c["handle"] for c in baseline["candidates"]}
    stricter = deepcopy(inventory)
    stricter["protected_roots"].append(target)
    assert target not in {c["handle"] for c in plan(policy, retention, stricter)["candidates"]}


@pytest.mark.parametrize(
    "first,second,newest",
    [
        ("00Z", "00.9Z", 2),
        ("00.1Z", "00.9Z", 2),
        ("00.10Z", "00.1Z", 1),
        ("00Z", "00.000000Z", 1),
    ],
    ids=["whole-second", "fraction-order", "equal-fraction", "equal-zero"],
)
def test_hot_predecessor_uses_instants_and_digest_ties_before_cleanup(first, second, newest):
    policy, retention, inventory = inputs()
    retention["releases"][1]["verified_at"] = "2026-09-01T12:00:" + first
    retention["releases"][2]["verified_at"] = "2026-09-01T12:00:" + second
    bind_current(policy, retention, inventory)
    decision = retained_runtime_handles(retention, accepted_policy=policy, now=NOW)
    selected = retention["releases"][newest]
    other = retention["releases"][3 - newest]
    selected_handle = selected["runtime_handles"][0]
    assert selected["release_digest"] in decision["handle_releases"][selected_handle]
    assert "hot-predecessor-count" in decision["release_reasons"][selected["release_digest"]]
    assert "hot-predecessor-count" not in decision["release_reasons"].get(
        other["release_digest"], []
    )
    assert selected["release_digest"] not in decision["cold_demoted_releases"]
    assert selected_handle not in {
        c["handle"] for c in plan(policy, retention, inventory)["candidates"]
    }
