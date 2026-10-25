"""Cleanup observation refresh under exact retained authority, without native deletion."""

from datetime import datetime, timedelta

import pytest
from fishhat_contracts.resources import plan_cleanup, retained_runtime_handles, revalidate_cleanup
from fishhat_contracts.validation import ContractError, digest

from tests.test_retention_authority import NOW, bind_current, inputs

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json#/$defs/AcceptedRetentionPolicy",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json#/$defs/CleanupPlan",
    ],
    "scope": "observation freshness and stable complete custody during reviewed cleanup",
    "relationship": "candidate",
    "reason": "Pure refresh, expiry and substitution cases preserve exact current authority; no native accounting, exclusion or deletion is established.",
    "claims": [],
}


def later(seconds):
    return (
        (datetime.fromisoformat(NOW) + timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z")
    )


def refresh(policy, retention, inventory, when):
    retention["observed_at"] = inventory["observed_at"] = when
    bind_current(policy, retention, inventory)


def accepted_freshness(policy, retention, inventory, seconds):
    policy["max_observation_age_seconds"] = seconds
    policy["generation"] += 1
    for release in retention["releases"]:
        if release["cold_demotion_receipt"] is not None:
            release["cold_demotion_receipt"]["policy_digest"] = digest(policy)
    bind_current(policy, retention, inventory)


@pytest.mark.parametrize("elapsed", [31, 120, 299])
def test_fresh_retention_observation_preserves_reviewed_custody(elapsed):
    policy, retention, inventory = inputs()
    reviewed = plan_cleanup(
        inventory, accepted_policy=policy, retention_inventory=retention, now=NOW
    )
    refresh(policy, retention, inventory, later(elapsed))
    current = retained_runtime_handles(retention, accepted_policy=policy, now=later(elapsed))
    assert reviewed["retention_inventory_digest"] != current["inventory_digest"]
    assert reviewed["retention_custody_digest"] == current["custody_digest"]
    revalidate_cleanup(
        reviewed,
        inventory,
        accepted_policy=policy,
        retention_inventory=retention,
        now=later(elapsed),
    )


def test_retention_refresh_does_not_extend_reviewed_plan_expiry():
    policy, retention, inventory = inputs()
    reviewed = plan_cleanup(
        inventory, accepted_policy=policy, retention_inventory=retention, now=NOW
    )
    refresh(policy, retention, inventory, later(300))
    with pytest.raises(ContractError, match="plan expired"):
        revalidate_cleanup(
            reviewed,
            inventory,
            accepted_policy=policy,
            retention_inventory=retention,
            now=later(300),
        )


@pytest.mark.parametrize("seconds", [5, 90])
@pytest.mark.parametrize("stale", ["retention", "native"])
def test_planning_and_deletion_use_the_same_accepted_freshness(seconds, stale):
    policy, retention, inventory = inputs()
    accepted_freshness(policy, retention, inventory, seconds)
    reviewed = plan_cleanup(
        inventory, accepted_policy=policy, retention_inventory=retention, now=NOW
    )
    revalidate_cleanup(
        reviewed,
        inventory,
        accepted_policy=policy,
        retention_inventory=retention,
        now=later(seconds),
    )
    if stale == "native":
        retention["observed_at"] = later(seconds + 1)
    else:
        inventory["observed_at"] = later(seconds + 1)
    bind_current(policy, retention, inventory)
    with pytest.raises(ContractError, match=r"stale retention accounting|cleanup now blocked"):
        revalidate_cleanup(
            reviewed,
            inventory,
            accepted_policy=policy,
            retention_inventory=retention,
            now=later(seconds + 1),
        )


def test_freshness_relaxation_requires_a_new_reviewed_policy():
    policy, retention, inventory = inputs()
    reviewed = plan_cleanup(
        inventory, accepted_policy=policy, retention_inventory=retention, now=NOW
    )
    accepted_freshness(policy, retention, inventory, 90)
    with pytest.raises(ContractError, match="cleanup owner protection changed"):
        revalidate_cleanup(
            reviewed,
            inventory,
            accepted_policy=policy,
            retention_inventory=retention,
            now=later(31),
        )


def test_confirmed_deletion_can_resume_after_retention_refresh():
    policy, retention, inventory = inputs()
    reviewed = plan_cleanup(
        inventory, accepted_policy=policy, retention_inventory=retention, now=NOW
    )
    removed = reviewed["candidates"][0]["handle"]
    inventory["items"] = [item for item in inventory["items"] if item["handle"] != removed]
    inventory["generation"] += 1
    refresh(policy, retention, inventory, later(120))
    with pytest.raises(ContractError, match="without confirmed outcome"):
        revalidate_cleanup(
            reviewed,
            inventory,
            accepted_policy=policy,
            retention_inventory=retention,
            now=later(120),
        )
    revalidate_cleanup(
        reviewed,
        inventory,
        accepted_policy=policy,
        retention_inventory=retention,
        now=later(120),
        confirmed_removed={removed},
    )
    candidate = reviewed["candidates"][1]
    next(item for item in inventory["items"] if item["handle"] == candidate["handle"])[
        "native_id"
    ] = "substituted-native-object"
    with pytest.raises(ContractError, match="candidate no longer safe"):
        revalidate_cleanup(
            reviewed,
            inventory,
            accepted_policy=policy,
            retention_inventory=retention,
            now=later(120),
            confirmed_removed={removed},
        )


@pytest.mark.parametrize(
    "changed", ["release-time", "hold", "archive-evidence", "archive-validity"]
)
def test_refresh_cannot_disguise_changed_custody(changed):
    policy, retention, inventory = inputs()
    reviewed = plan_cleanup(
        inventory, accepted_policy=policy, retention_inventory=retention, now=NOW
    )
    old = retention["releases"][2]
    if changed == "release-time":
        retention["releases"][1]["verified_at"] = "2026-10-09T12:00:01Z"
    elif changed == "hold":
        retention["releases"][0]["blocking_refs"].append("accepted-recovery-work")
    else:
        if changed == "archive-evidence":
            old["archive"]["evidence_digest"] = "sha256:" + "f" * 64
        else:
            old["archive"]["valid_until"] = "2026-10-20T12:00:00Z"
        old["cold_demotion_receipt"]["archive_digest"] = digest(old["archive"])
    refresh(policy, retention, inventory, later(120))
    # Each changed closure remains independently well formed and currently usable.
    current = retained_runtime_handles(retention, accepted_policy=policy, now=later(120))
    assert current["custody_digest"] != reviewed["retention_custody_digest"]
    with pytest.raises(ContractError, match="cleanup owner protection changed"):
        revalidate_cleanup(
            reviewed,
            inventory,
            accepted_policy=policy,
            retention_inventory=retention,
            now=later(120),
        )
