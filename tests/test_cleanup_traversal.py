"""Indexed cleanup custody and exact progress, without native deletion."""

from dataclasses import replace

import pytest
from fishhat_contracts.resources import CleanupTraversal, plan_cleanup, revalidate_cleanup
from fishhat_contracts.validation import ContractError, digest

from tests.test_cleanup_observations import later
from tests.test_retention_authority import NOW, bind_current, inputs

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json#/$defs/CleanupPlan"
    ],
    "scope": "indexed reference cleanup under exact trusted owner custody",
    "relationship": "candidate",
    "reason": "Identity, generation, exclusion, expiry and uncertainty substitutions challenge continuation; no native locks or authentication are supplied by the pure model.",
    "claims": [],
}


def traversal(exclusion=True):
    policy, retention, inventory = inputs()
    inventory["max_objects"] = 1
    plan = plan_cleanup(inventory, accepted_policy=policy, retention_inventory=retention, now=NOW)
    return revalidate_cleanup(
        plan,
        inventory,
        accepted_policy=policy,
        retention_inventory=retention,
        now=NOW,
        exclusion=object() if exclusion else None,
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("owner", ("app-ops", "another-owner", "another-epoch")),
        ("account", "another-account"),
        ("store_binding", "sha256:" + "f" * 64),
        ("generation", 99),
        ("policy_digest", "sha256:" + "f" * 64),
        ("retention_custody_digest", "sha256:" + "f" * 64),
        ("protection_generation", 99),
        ("exclusion", None),
        ("coverage_complete", False),
        ("exclusive_control", False),
        ("busy", True),
        ("control_writable", False),
    ],
    ids=[
        "owner",
        "account",
        "store",
        "native-generation",
        "policy",
        "retention",
        "protection-generation",
        "exclusion",
        "coverage",
        "exclusive",
        "busy",
        "durability",
    ],
)
def test_exact_custody_and_candidate_identity_are_required(field, value):
    view = traversal()
    candidate = view.next_batch()[0]
    with pytest.raises(ContractError):
        view.before_delete(candidate, current=replace(view.custody, **{field: value}), now=NOW)
    with pytest.raises(ContractError, match="invalidated"):
        view.before_delete(candidate, current=view.custody, now=NOW)


def test_exact_observed_native_candidate_and_explicit_exclusion_are_required():
    for field in ("handle", "kind", "native_id"):
        view = traversal()
        candidate = view.next_batch()[0]
        with pytest.raises(ContractError, match="candidate no longer safe"):
            view.before_delete({**candidate, field: "substituted"}, current=view.custody, now=NOW)
    view = traversal(exclusion=False)
    with pytest.raises(ContractError, match="exclusion lost"):
        view.before_delete(view.next_batch()[0], current=view.custody, now=NOW)


def test_unverified_construction_cannot_bypass_complete_inventory_check():
    policy, retention, inventory = inputs()
    plan = plan_cleanup(inventory, accepted_policy=policy, retention_inventory=retention, now=NOW)
    plan["candidates"].append({"handle": "arbitrary", "kind": "image", "native_id": "arbitrary"})
    with pytest.raises(ContractError, match="requires complete revalidation"):
        CleanupTraversal(plan, inventory, retention, policy, set(), object())


def test_confirmed_removal_cannot_overflow_exact_generation_domain():
    policy, retention, inventory = inputs()
    inventory["generation"] = 9_007_199_254_740_991
    plan = plan_cleanup(inventory, accepted_policy=policy, retention_inventory=retention, now=NOW)
    view = revalidate_cleanup(
        plan,
        inventory,
        accepted_policy=policy,
        retention_inventory=retention,
        now=NOW,
        exclusion=object(),
    )
    candidate = view.next_batch()[0]
    with pytest.raises(ContractError, match="generation"):
        view.before_delete(candidate, current=view.custody, now=NOW)


def test_unknown_outcome_and_external_invalidation_never_blindly_retry():
    view = traversal()
    candidate = view.next_batch()[0]
    view.before_delete(candidate, current=view.custody, now=NOW)
    with pytest.raises(ContractError, match="unresolved"):
        view.before_delete(candidate, current=view.custody, now=NOW)
    view.record_outcome(candidate["handle"], "unknown", current=view.custody, now=NOW)
    with pytest.raises(ContractError, match="invalidated"):
        view.before_delete(candidate, current=view.custody, now=NOW)


def test_confirmed_outcome_must_join_current_generation_under_same_exclusion():
    view = traversal()
    candidate = view.next_batch()[0]
    view.before_delete(candidate, current=view.custody, now=NOW)
    with pytest.raises(ContractError, match="generation"):
        view.record_outcome(candidate["handle"], "removed", current=view.custody, now=NOW)


@pytest.mark.parametrize("observation", ["native_observed_at", "retention_observed_at"])
def test_each_attempt_requires_current_accepted_observation_freshness(observation):
    view = traversal()
    candidate = view.next_batch()[0]
    current = replace(view.custody, **{observation: NOW})
    with pytest.raises(ContractError, match="observation stale"):
        view.before_delete(candidate, current=current, now=later(31))


def test_fresh_observations_do_not_extend_cold_archive_validity():
    policy, retention, inventory = inputs()
    old = retention["releases"][2]
    old["archive"]["valid_until"] = later(15)
    old["cold_demotion_receipt"]["archive_digest"] = digest(old["archive"])
    bind_current(policy, retention, inventory)
    plan = plan_cleanup(inventory, accepted_policy=policy, retention_inventory=retention, now=NOW)
    view = revalidate_cleanup(
        plan,
        inventory,
        accepted_policy=policy,
        retention_inventory=retention,
        now=NOW,
        exclusion=object(),
    )
    with pytest.raises(ContractError, match="archive validity expired"):
        view.before_delete(view.next_batch()[0], current=view.custody, now=later(15))


CHECK_OVERRIDES = {
    "test_exact_custody_and_candidate_identity_are_required": {
        **CHECK_PURPOSE,
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/resources.py#revalidate_cleanup",
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json#/$defs/CleanupPlan",
        ],
        "relationship": "scoped-witness",
        "claims": ["engineering:resources.cleanup-traversal"],
    }
}
