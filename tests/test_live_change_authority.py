"""Reviewed host effects resolve live edits before any native executor is involved."""

import copy

import pytest
from fishhat_contracts.live_change import require_current_host_preimages
from fishhat_contracts.validation import ContractError, digest, validate_plan

from tests.test_contracts import plan, uid
from tests.test_plan_review import reseal

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/HostPreimage",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Plan",
    ],
    "scope": "offline three-way host review, exact effect coverage and stale-live rejection",
    "relationship": "candidate",
    "reason": "Synthetic projections and separately supplied custody facts exercise plan and comparison rules; they do not establish native observations, atomic mutation exclusion, capture durability or source adoption.",
    "claims": [],
}


def projection(content):
    return digest({"target": "/etc/motd", "present": True, "content": content, "mode": "0644"})


def host_plan(disposition="overwrite", baseline="accepted", live="edited", proposed="proposed"):
    value = copy.deepcopy(plan())
    owner = {"tool": "host-ops", "id": uid("host-owner"), "epoch": uid("host-epoch")}
    resource = {"kind": "host", "id": "node-a"}
    value["owner"] = owner
    value["witness"]["owner"] = owner
    value["subject"] = {
        "action": "host.apply",
        "resource": resource,
        "arguments": {
            "source": {
                "source_id": "host-node-a",
                "repository": {
                    "instance": uid("repository-instance"),
                    "repository_id": 1,
                    "name": "synthetic/host-node-a",
                },
                "commit": "a" * 40,
                "entrypoint": "host.yaml",
                "closure_digest": digest({"synthetic-source": proposed}),
            }
        },
    }
    value["summary"] = "Apply the reviewed host configuration on node-a."
    value["data_consequences"] = "Resolve the reviewed edit to the managed host message."
    value["input_digests"] = [
        digest(value["subject"]),
        value["subject"]["arguments"]["source"]["closure_digest"],
    ]
    value["preconditions"][0].update(owner=owner, resource=resource)
    value["effects"][0].update(
        step="apply-message",
        executor=owner,
        resource=resource,
        action="admitted-host-configuration",
        input_digest=value["input_digests"][0],
        summary="Apply the exact reviewed message and its live-change disposition.",
    )
    value["host_preimages"] = [
        {
            "disclosure": "public",
            "effect_step": "apply-message",
            "baseline_digest": projection(baseline),
            "live_digest": projection(live),
            "proposed_digest": projection(proposed),
            "disposition": disposition,
            "capture_digest": digest({"captured": live}) if disposition == "capture" else None,
        }
    ]
    return reseal(value)


def current_state(value):
    return {item["effect_step"]: item["live_digest"] for item in value["host_preimages"]}


def verified_captures(value):
    return {
        item["effect_step"]: (item["capture_digest"], item["live_digest"])
        for item in value["host_preimages"]
        if item["disposition"] == "capture"
    }


@pytest.mark.parametrize(
    ("baseline", "live", "proposed", "disposition"),
    [
        ("accepted", "accepted", "proposed", "overwrite"),
        ("accepted", "edited", "edited", "preserve"),
        ("accepted", "edited", "proposed", "capture"),
        ("accepted", "edited", "proposed", "overwrite"),
        ("accepted", "edited", "accepted", "overwrite"),
    ],
)
def test_exact_reviewed_disposition_resolves_the_three_way_comparison(
    baseline, live, proposed, disposition
):
    value = host_plan(disposition, baseline, live, proposed)
    before = copy.deepcopy(value)
    require_current_host_preimages(
        value, current_state(value), verified_captures(value), confidential_steps=set()
    )
    assert value == before


@pytest.mark.parametrize("action", ["host.apply", "admitted-host-configuration", "custom-effect"])
def test_host_apply_cannot_omit_preimages_by_changing_executor_action_name(action):
    value = host_plan()
    value["effects"][0]["action"] = action
    del value["host_preimages"]
    with pytest.raises(ContractError, match=r"schema records\.schema\.json rejected"):
        validate_plan(reseal(value))


@pytest.mark.parametrize(
    "field", ["baseline_digest", "live_digest", "proposed_digest", "capture_digest"]
)
def test_review_binds_every_preimage_and_retained_capture(field):
    value = host_plan("capture")
    value["host_preimages"][0][field] = projection("unreviewed")
    with pytest.raises(ContractError, match="plan digest mismatch"):
        validate_plan(value)


@pytest.mark.parametrize(
    ("field", "replacement"), [("effect_step", "unreviewed-step"), ("disposition", "preserve")]
)
def test_review_binds_the_effect_join_and_disposition(field, replacement):
    value = host_plan()
    value["host_preimages"][0][field] = replacement
    with pytest.raises(ContractError, match="plan digest mismatch"):
        validate_plan(value)


def test_preserve_cannot_claim_to_apply_a_source_that_differs_from_live_state():
    value = host_plan("preserve")
    with pytest.raises(ContractError, match="preserved live state differs from proposed state"):
        validate_plan(value)


def test_duplicate_preimages_cannot_create_competing_dispositions():
    value = host_plan()
    value["host_preimages"].append({**value["host_preimages"][0], "disposition": "preserve"})
    with pytest.raises(ContractError, match="duplicate host preimage step"):
        validate_plan(reseal(value))


def test_preimage_cannot_reference_an_effect_outside_the_reviewed_plan():
    value = host_plan()
    value["host_preimages"][0]["effect_step"] = "another-step"
    with pytest.raises(ContractError, match="host preimages must cover every effect exactly"):
        validate_plan(reseal(value))


def test_delegated_effect_needs_its_own_preimage_even_with_an_arbitrary_action_name():
    value = host_plan()
    effect = copy.deepcopy(value["effects"][0])
    effect.update(step="delegated", action="executor-defined-action")
    effect["executor"] = {"tool": "app-ops", "id": uid("delegate"), "epoch": uid("delegate-epoch")}
    effect["resource"] = {"kind": "app", "id": "delegated-app"}
    value["effects"].append(effect)
    value["preconditions"].append(
        {**value["preconditions"][0], "owner": effect["executor"], "resource": effect["resource"]}
    )
    with pytest.raises(ContractError, match="host preimages must cover every effect exactly"):
        validate_plan(reseal(value))
    value["host_preimages"].append({**value["host_preimages"][0], "effect_step": "delegated"})
    require_current_host_preimages(reseal(value), current_state(value), confidential_steps=set())


@pytest.mark.parametrize("disposition", ["preserve", "capture", "overwrite"])
def test_a_later_live_edit_invalidates_every_disposition(disposition):
    value = host_plan(disposition, proposed="edited" if disposition == "preserve" else "proposed")
    current = {"apply-message": projection("later administrator edit")}
    with pytest.raises(ContractError, match="live host state changed after review"):
        require_current_host_preimages(
            value, current, verified_captures(value), confidential_steps=set()
        )


@pytest.mark.parametrize("observation", [{}, {"wrong-step": projection("edited")}])
def test_unknown_or_misbound_native_observation_is_not_treated_as_unchanged(observation):
    value = host_plan()
    with pytest.raises(
        ContractError, match="current host preimages must cover every effect exactly"
    ):
        require_current_host_preimages(value, observation, confidential_steps=set())


def test_interruption_requires_a_fresh_comparison_before_retry():
    value = host_plan()
    current = current_state(value)
    require_current_host_preimages(value, current, confidential_steps=set())
    current["apply-message"] = projection("edit during interruption")
    with pytest.raises(ContractError, match="live host state changed after review"):
        require_current_host_preimages(value, current, confidential_steps=set())


def test_capture_digest_in_a_review_does_not_establish_custody():
    value = host_plan("capture")
    with pytest.raises(ContractError, match="verified captures must cover capture dispositions"):
        require_current_host_preimages(value, current_state(value), confidential_steps=set())


@pytest.mark.parametrize("changed_index", [0, 1])
def test_capture_requires_the_exact_artifact_and_exact_reviewed_live_state(changed_index):
    value = host_plan("capture")
    captures = verified_captures(value)
    wrong = list(captures["apply-message"])
    wrong[changed_index] = projection("different capture")
    captures["apply-message"] = tuple(wrong)
    with pytest.raises(ContractError, match="capture does not preserve reviewed live state"):
        require_current_host_preimages(
            value, current_state(value), captures, confidential_steps=set()
        )


@pytest.mark.parametrize("disposition", ["preserve", "overwrite"])
def test_non_capture_dispositions_cannot_smuggle_in_capture_authority(disposition):
    value = host_plan(disposition, proposed="edited")
    value["host_preimages"][0]["capture_digest"] = projection("unreviewed capture")
    with pytest.raises(ContractError, match=r"schema records\.schema\.json rejected"):
        validate_plan(reseal(value))


def test_capture_disposition_requires_a_retained_artifact_identity():
    value = host_plan("capture")
    value["host_preimages"][0]["capture_digest"] = None
    with pytest.raises(ContractError, match=r"schema records\.schema\.json rejected"):
        validate_plan(reseal(value))


def test_host_dispositions_do_not_change_other_action_contracts():
    value = plan()
    validate_plan(value)
    with pytest.raises(ContractError, match=r"host preimage check requires a host\.apply plan"):
        require_current_host_preimages(value, {}, confidential_steps=set())
    value["host_preimages"] = host_plan()["host_preimages"]
    with pytest.raises(ContractError, match=r"schema records\.schema\.json rejected"):
        validate_plan(reseal(value))
