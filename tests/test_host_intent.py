"""Host source patches preserve accepted custody and unrelated live membership."""

from __future__ import annotations

from copy import deepcopy
from functools import partial

import pytest
from fishhat_contracts.host_intent import (
    project_destinations,
    project_supplementary_memberships,
    validate_supplementary_patch,
)
from fishhat_contracts.live_change import require_current_host_preimages
from fishhat_contracts.validation import ContractError, digest, validate, validate_host

from tests.linear_support import assert_linear, measure
from tests.test_live_change_authority import host_plan
from tests.test_plan_review import reseal
from tests.test_source_authority import host_source, target_entry

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json#/$defs/Host",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json#/$defs/HostDestinationRetirement",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json#/$defs/HostSupplementaryGroups",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/host.apply",
    ],
    "scope": "explicit host destination retirement, source omission, supplementary ownership and complete linear projection",
    "relationship": "candidate",
    "reason": "Contrasting accepted/live/proposed synthetic inputs demonstrate the declared review projections and rejection paths. They do not establish native identity, authorization, atomic effects, persistence or release of accepted custody.",
    "claims": [],
}

_IMPLEMENTATIONS = {
    "destinations": "project_destinations",
    "supplementary-patch": "validate_supplementary_patch",
    "supplementary": "project_supplementary_memberships",
}
CHECK_OVERRIDES = {
    test: {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/host_intent.py#"
            + _IMPLEMENTATIONS[operation],
            *CHECK_PURPOSE["authority"],
        ],
        "scope": "complete host intent projection and exact accepted/live/proposed joins",
        "relationship": "scoped-witness",
        "reason": "The offline implementation retains complete claims and rejects unauthorized intent; native custody, identity, permission and effects remain independent owner obligations.",
        "claims": ["engineering:host-intent." + operation],
    }
    for test, operation in (
        ("test_omission_and_destination_move_retain_original_claims", "destinations"),
        ("test_supplementary_patch_rejects_conflicts_and_legacy_shape", "supplementary-patch"),
        ("test_membership_patch_preserves_unowned_and_omitted_memberships", "supplementary"),
    )
}
CHECK_OVERRIDES["test_host_intent_linear_work"] = {
    "purpose": "implementation",
    "authority": [
        "release.toml#/engineering",
        *[
            "packages/fishhat-contracts/src/fishhat_contracts/host_intent.py#" + symbol
            for symbol in _IMPLEMENTATIONS.values()
        ],
    ],
    "scope": "complete host intent projection work across growing accepted targets and membership patches",
    "relationship": "scoped-witness",
    "reason": "Deterministic operation counts cover each implementation's complete inputs and output cardinality at increasing extents; they do not establish native effects, custody or timing guarantees.",
    "claims": ["engineering:host-intent." + name for name in _IMPLEMENTATIONS],
}


def source():
    host, _ = host_source()
    for concern in host["concerns"].values():
        for kind in ("files", "secret_files", "artifacts"):
            concern[kind].clear()
    return host


def initial_claims():
    host = source()
    host["concerns"]["base"]["files"]["message"] = target_entry("files", "/etc/motd")
    return project_destinations({}, host, source_closure_digest=digest({"source": "initial"}))


def retirement(path="/etc/motd"):
    return {"state": "retired", "destination": path, "reason": "Retire the exact managed object"}


def patch(add=(), remove=()):
    return {
        "user": "synthetic-agent",
        "supplementary": {"add": list(add), "remove": list(remove)},
        "reason": "Exact supplementary membership change",
    }


def membership_projection(intent, *, managed=(), retired=(), live=(), primary="synthetic-primary"):
    return project_supplementary_memberships(
        intent,
        expected_user="synthetic-agent",
        managed=managed,
        retired=retired,
        live_supplementary=live,
        primary_group=primary,
    )


def test_omission_and_destination_move_retain_original_claims():
    accepted = initial_claims().effective
    before = deepcopy(accepted)
    omitted = project_destinations(
        accepted, source(), source_closure_digest=digest({"source": "empty"})
    )
    assert omitted.effective == before
    assert omitted.selected == frozenset()
    assert omitted.retirements == {}

    moved = source()
    moved["concerns"]["base"]["files"]["message"] = target_entry("files", "/etc/new-message")
    reviewed = project_destinations(
        accepted, moved, source_closure_digest=digest({"source": "moved"})
    )
    assert set(reviewed.effective) == {"/etc/motd", "/etc/new-message"}
    assert reviewed.effective["/etc/motd"] == before["/etc/motd"]
    assert reviewed.selected == {"/etc/new-message"}
    assert reviewed.retirements == {}
    assert accepted == before


def test_same_target_concern_and_binding_rename_does_not_retire_or_recreate_identity():
    accepted = initial_claims().effective
    proposed = source()
    proposed["concerns"]["renamed"] = proposed["concerns"].pop("base")
    proposed["concerns"]["renamed"]["files"]["new-label"] = deepcopy(
        accepted["/etc/motd"]["declaration"]
    )
    reviewed = project_destinations(
        accepted, proposed, source_closure_digest=digest({"source": "renamed"})
    )
    assert set(reviewed.effective) == set(accepted)
    assert reviewed.effective["/etc/motd"]["declaration"] == accepted["/etc/motd"]["declaration"]
    assert reviewed.retirements == {}


def test_explicit_retirement_keeps_original_material_separate_from_the_proposed_tombstone():
    accepted = initial_claims().effective
    proposed = source()
    proposed["concerns"]["base"]["files"]["retire-message"] = retirement()
    reviewed = project_destinations(
        accepted, proposed, source_closure_digest=digest({"source": "retired"})
    )
    assert reviewed.retirements == accepted
    assert reviewed.effective["/etc/motd"]["declaration"] == retirement()
    assert reviewed.selected == frozenset()
    assert accepted["/etc/motd"]["declaration"]["state"] == "present"
    repeated = project_destinations(
        reviewed.effective, proposed, source_closure_digest=digest({"source": "later"})
    )
    # Settled old removal is inert even if a human later reuses the pathname.
    assert repeated.retirements == {}
    assert repeated.effective == reviewed.effective


@pytest.mark.parametrize("kind", ["files", "secret_files", "artifacts"])
def test_retirement_requires_the_same_previously_managed_destination_kind(kind):
    proposed = source()
    proposed["concerns"]["base"][kind]["retire-message"] = retirement()
    validate_host(proposed)
    accepted = {} if kind == "files" else initial_claims().effective
    with pytest.raises(ContractError, match="exact accepted managed destination"):
        project_destinations(accepted, proposed, source_closure_digest=digest({}))


def test_retired_secret_does_not_require_or_resolve_a_new_secret_catalogue():
    proposed = source()
    proposed["repository_secrets"] = None
    proposed["concerns"]["base"]["secret_files"]["old-secret"] = retirement("/run/old-secret")
    validate_host(proposed)


@pytest.mark.parametrize(
    "field,value",
    [("source", "files/motd"), ("entry", "token"), ("notify", [])],
    ids=["replacement-source", "secret-entry", "service-notification"],
)
def test_retirement_cannot_carry_a_replacement_or_ambient_side_effect(field, value):
    with pytest.raises(ContractError):
        validate("source.schema.json", {**retirement(), field: value}, "HostDestinationRetirement")


def test_presence_is_explicit_and_legacy_file_declarations_are_rejected():
    value = target_entry("files", "/etc/motd")
    del value["state"]
    with pytest.raises(ContractError):
        validate("source.schema.json", value, "HostFile")


def test_retirement_still_requires_the_reviewed_live_preimage_and_capture_custody():
    value = host_plan("capture")
    item = value["host_preimages"][0]
    item["proposed_digest"] = digest({"target": "/etc/motd", "present": False})
    value = reseal(value)
    current = {item["effect_step"]: item["live_digest"]}
    captures = {item["effect_step"]: (item["capture_digest"], item["live_digest"])}
    require_current_host_preimages(value, current, captures, confidential_steps=set())
    with pytest.raises(ContractError, match="verified captures must cover"):
        require_current_host_preimages(value, current, confidential_steps=set())
    current[item["effect_step"]] = digest(
        {"target": "/etc/motd", "present": True, "content": "later edit", "incarnation": "new"}
    )
    with pytest.raises(ContractError, match="live host state changed after review"):
        require_current_host_preimages(value, current, captures, confidential_steps=set())


def test_membership_patch_preserves_unowned_and_omitted_memberships():
    reviewed = membership_projection(
        patch(add=["monitor"], remove=["retire-me"]),
        managed=["deploy", "retire-me"],
        live=["sudo", "deploy", "retire-me", "wheel"],
    )
    assert reviewed.supplementary == {"sudo", "deploy", "wheel", "monitor"}
    assert reviewed.managed == {"deploy", "monitor"}
    assert reviewed.retired == {"retire-me"}
    assert reviewed.additions == {"monitor"}
    assert reviewed.removals == {"retire-me"}
    assert reviewed.unmanaged == {"sudo", "wheel"}


def test_addition_discloses_adoption_of_an_existing_unmanaged_membership():
    reviewed = membership_projection(patch(add=["deploy"]), live=["deploy", "sudo"])
    assert reviewed.managed == {"deploy"}
    assert reviewed.adoptions == {"deploy"}
    assert reviewed.additions == frozenset()
    assert reviewed.unmanaged == {"sudo"}


def test_unrequested_missing_managed_membership_is_drift_without_implicit_repair():
    reviewed = membership_projection(patch(), managed=["deploy"], live=["sudo"])
    assert reviewed.supplementary == {"sudo"}
    assert reviewed.managed == {"deploy"}
    assert reviewed.missing_managed == {"deploy"}
    assert reviewed.additions == reviewed.removals == frozenset()
    explicit = membership_projection(patch(add=["deploy"]), managed=["deploy"], live=["sudo"])
    assert explicit.supplementary == {"deploy", "sudo"}
    assert explicit.additions == {"deploy"}
    assert explicit.missing_managed == frozenset()


def test_live_presence_does_not_authorize_revoking_an_unowned_membership():
    with pytest.raises(ContractError, match="cannot revoke unowned"):
        membership_projection(patch(remove=["sudo"]), managed=["deploy"], live=["sudo", "deploy"])


def test_settled_removal_cannot_revoke_a_later_unmanaged_membership():
    reviewed = membership_projection(patch(remove=["deploy"]), retired=["deploy"], live=["deploy"])
    assert reviewed.managed == frozenset()
    assert reviewed.retired == {"deploy"}
    assert reviewed.supplementary == reviewed.unmanaged == {"deploy"}
    assert reviewed.removals == frozenset()
    adopted = membership_projection(patch(add=["deploy"]), retired=["deploy"], live=["deploy"])
    assert adopted.adoptions == adopted.managed == {"deploy"}
    assert adopted.retired == frozenset()


@pytest.mark.parametrize("field", ["add", "remove"])
def test_primary_group_cannot_enter_the_supplementary_surface(field):
    intent = patch()
    intent["supplementary"][field] = ["primary"]
    with pytest.raises(ContractError, match="primary group is outside"):
        membership_projection(intent, primary="primary")


def test_another_users_claims_cannot_authorize_the_patch():
    intent = patch(remove=["deploy"])
    intent["user"] = "another-user"
    with pytest.raises(ContractError, match="user identity mismatch"):
        membership_projection(intent, managed=["deploy"], live=["deploy"])


def test_supplementary_patch_rejects_conflicts_and_legacy_shape():
    with pytest.raises(ContractError, match="add/remove overlap"):
        validate_supplementary_patch(patch(add=["deploy"], remove=["deploy"]))
    legacy = {"user": "synthetic-agent", "memberships": ["deploy"], "reason": "Legacy shape"}
    with pytest.raises(ContractError):
        validate_supplementary_patch(legacy)
    with pytest.raises(ContractError):
        validate_supplementary_patch(patch(add=["deploy", "deploy"]))
    host = source()
    host["concerns"]["base"]["groups"]["patch"] = patch(add=["deploy"], remove=["deploy"])
    with pytest.raises(ContractError, match="add/remove overlap"):
        validate_host(host)


def _host_intent_linear_work(kind):
    samples = []
    for count in (16, 64, 256):
        names = [f"group-{index:04d}" for index in range(count)]
        intent = patch(add=names, remove=["old-" + name for name in names])
        if kind == "destinations":
            proposed = source()
            accepted = {}
            for index in range(count):
                path = f"/etc/synthetic-{index:04d}"
                accepted[path] = {
                    "kind": "files",
                    "declaration": target_entry("files", path),
                    "source_closure_digest": digest({"initial": index}),
                }
                proposed["concerns"]["base"]["files"][f"retire-{index:04d}"] = retirement(path)
            result, work = measure(
                partial(project_destinations, accepted, proposed, source_closure_digest=digest({}))
            )
            assert len(result.effective) == len(result.retirements) == count
        elif kind == "supplementary":
            managed = ["old-" + name for name in names]
            live = [*managed, *["unowned-" + name for name in names]]
            result, work = measure(
                partial(membership_projection, intent, managed=managed, live=live)
            )
            assert len(result.managed) == len(result.retired) == count
            assert len(result.supplementary) == 2 * count
        else:
            result, work = measure(partial(validate_supplementary_patch, intent))
            assert result is None
        samples.append((count, work))
    assert_linear(samples)


def test_host_intent_linear_work():
    for kind in _IMPLEMENTATIONS:
        _host_intent_linear_work(kind)
