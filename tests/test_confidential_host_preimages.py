"""Confidential host review exports opaque metadata and checks private custody."""

import copy
import hashlib
import json
from dataclasses import replace
from unittest.mock import patch

import pytest
from fishhat_contracts import live_change
from fishhat_contracts.live_change import (
    ProtectedHostCapture,
    ProtectedHostPreimage,
    require_current_host_preimages,
)
from fishhat_contracts.validation import ContractError, validate_plan

from tests.linear_support import assert_linear, measure
from tests.test_contracts import uid
from tests.test_live_change_authority import host_plan
from tests.test_plan_review import reseal

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/host-preimages.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Plan",
    ],
    "scope": "opaque confidential preimages, independent disclosure classification and private comparison/capture joins",
    "relationship": "candidate",
    "reason": "Synthetic private projections and trusted-context inputs exercise fail-closed contract rules; they do not establish native secrecy classification, random reference generation, private storage, encryption, custody durability or atomic mutation exclusion.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_private_comparison_linear_work": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/live_change.py#require_current_host_preimages",
            "release.toml#/engineering",
        ],
        "scope": "complete effect traversal and separately counted private byte comparisons across increasing metadata and projection extents",
        "relationship": "scoped-witness",
        "reason": "Executed Python/container/serialization work and bytes passed to native comparison are counted on each full check and retry; synthetic custody supplies no native or elapsed-time qualification.",
        "claims": ["engineering:host-preimages.current"],
    },
}

STEP = "apply-message"
SECRET = b"administrator-password=small-dictionary-secret"


def confidential_plan(
    disposition="overwrite", *, proposed=b"replacement", protection="owner-private"
):
    value = host_plan()
    effect = value["effects"][0]

    def reference(role):
        return {
            "id": uid("private-" + role),
            "owner": copy.deepcopy(effect["executor"]),
            "resource": copy.deepcopy(effect["resource"]),
            "effect_step": STEP,
        }

    item = {
        "disclosure": "confidential",
        "effect_step": STEP,
        "baseline": reference("baseline"),
        "live": reference("live"),
        "proposed": reference("proposed"),
        "disposition": disposition,
        "capture": None,
    }
    projections = {"baseline": b"accepted-secret", "live": SECRET, "proposed": proposed}
    store = {
        item[role]["id"]: ProtectedHostPreimage(copy.deepcopy(item[role]), projection)
        for role, projection in projections.items()
    }
    captures = {}
    if disposition == "capture":
        item["capture"] = {
            **reference("capture"),
            "live": copy.deepcopy(item["live"]),
            "protection": protection,
        }
        captures[STEP] = ProtectedHostCapture(copy.deepcopy(item["capture"]), SECRET)
    value["host_preimages"] = [item]
    return reseal(value), {STEP: SECRET}, store, captures


def check(value, current, store, captures):
    require_current_host_preimages(
        value,
        current,
        confidential_steps={STEP},
        protected_preimages=store,
        protected_captures=captures,
    )


@pytest.mark.parametrize("disposition", ["preserve", "capture", "overwrite"])
def test_review_contains_no_secret_bytes_or_guessable_plaintext_commitment(disposition):
    value, current, store, captures = confidential_plan(disposition, proposed=SECRET)
    before = copy.deepcopy(value)
    check(value, current, store, captures)
    serialized = json.dumps(value)
    assert SECRET.decode() not in serialized
    assert hashlib.sha256(SECRET).hexdigest() not in serialized
    assert SECRET.decode() not in repr(store)
    assert SECRET.decode() not in repr(captures)
    assert value["host_preimages"][0]["live"] != value["host_preimages"][0]["proposed"]
    assert value == before


def test_plan_cannot_downgrade_a_secret_scope_to_public_hashes():
    value = host_plan()
    with pytest.raises(ContractError, match="independent classification"):
        require_current_host_preimages(
            value, {STEP: value["host_preimages"][0]["live_digest"]}, confidential_steps={STEP}
        )


def test_private_shape_cannot_authenticate_its_own_sensitivity_classification():
    value, current, store, captures = confidential_plan()
    with pytest.raises(ContractError, match="independent classification"):
        require_current_host_preimages(
            value,
            current,
            confidential_steps=set(),
            protected_preimages=store,
            protected_captures=captures,
        )


def test_preimage_requires_explicit_disclosure_classification():
    value = host_plan()
    del value["host_preimages"][0]["disclosure"]
    with pytest.raises(ContractError, match="schema records"):
        validate_plan(reseal(value))


@pytest.mark.parametrize(
    "field", ["baseline_digest", "live_digest", "proposed_digest", "plaintext"]
)
def test_confidential_wire_record_cannot_add_plaintext_or_digest_fields(field):
    value, _, _, _ = confidential_plan()
    value["host_preimages"][0][field] = SECRET.decode()
    with pytest.raises(ContractError, match="schema records"):
        validate_plan(reseal(value))


@pytest.mark.parametrize("role", ["baseline", "live", "proposed", "capture"])
@pytest.mark.parametrize("field", ["owner", "resource", "effect_step"])
def test_private_reference_cannot_cross_owner_epoch_resource_or_effect(role, field):
    value, _, _, _ = confidential_plan("capture")
    reference = value["host_preimages"][0][role]
    if field == "owner":
        reference[field]["epoch"] = uid("later-owner-epoch")
    elif field == "resource":
        reference[field]["id"] = "other-host"
    else:
        reference[field] = "other-effect"
    with pytest.raises(ContractError, match=r"protected.*(effect scope|live reference)"):
        validate_plan(reseal(value))


@pytest.mark.parametrize("role", ["baseline", "live", "proposed"])
def test_missing_private_custody_cannot_fall_back_to_a_wire_claim(role):
    value, current, store, captures = confidential_plan()
    del store[value["host_preimages"][0][role]["id"]]
    with pytest.raises(ContractError, match="custody is absent or misbound"):
        check(value, current, store, captures)


def test_opaque_id_alone_cannot_substitute_for_the_authenticated_reference():
    value, current, store, captures = confidential_plan()
    reference = value["host_preimages"][0]["live"]
    retained = store[reference["id"]]
    changed = copy.deepcopy(retained.reference)
    changed["owner"]["epoch"] = uid("other-private-custodian")
    store[reference["id"]] = replace(retained, reference=changed)
    with pytest.raises(ContractError, match="custody is absent or misbound"):
        check(value, current, store, captures)


def test_reference_replacement_is_bound_by_review_and_private_custody():
    value, current, store, captures = confidential_plan()
    value["host_preimages"][0]["live"]["id"] = uid("unreviewed-live-reference")
    with pytest.raises(ContractError, match="plan digest mismatch"):
        validate_plan(value)
    with pytest.raises(ContractError, match="custody is absent or misbound"):
        check(reseal(value), current, store, captures)


@pytest.mark.parametrize("disposition", ["preserve", "capture", "overwrite"])
def test_interrupted_work_rechecks_private_native_bytes_before_every_retry(disposition):
    value, current, store, captures = confidential_plan(disposition, proposed=SECRET)
    check(value, current, store, captures)
    current[STEP] += b"-later-edit"
    with pytest.raises(ContractError, match="live host state changed after review"):
        check(value, current, store, captures)


def test_private_comparison_does_not_accept_a_public_hash_as_the_native_observation():
    value, _, store, captures = confidential_plan()
    with pytest.raises(ContractError, match="live host state changed after review"):
        check(value, {STEP: hashlib.sha256(SECRET).hexdigest()}, store, captures)


def test_preserve_checks_actual_proposed_bytes_in_private():
    value, current, store, captures = confidential_plan("preserve")
    validate_plan(value)
    with pytest.raises(ContractError, match="preserved live state differs"):
        check(value, current, store, captures)


@pytest.mark.parametrize("protection", ["owner-private", "encrypted"])
def test_confidential_capture_requires_separately_verified_exact_recovery_custody(protection):
    value, current, store, captures = confidential_plan("capture", protection=protection)
    check(value, current, store, captures)
    with pytest.raises(ContractError, match="protected captures must cover"):
        check(value, current, store, {})
    captures[STEP] = replace(captures[STEP], projection=b"different captured bytes")
    with pytest.raises(ContractError, match="protected capture does not preserve"):
        check(value, current, store, captures)


def test_confidential_capture_cannot_be_an_ordinary_source_proposal():
    value, _, _, _ = confidential_plan("capture")
    value["host_preimages"][0]["capture"]["protection"] = "source-proposal"
    with pytest.raises(ContractError, match="schema records"):
        validate_plan(reseal(value))


def test_capture_cannot_claim_a_different_live_reference():
    value, _, _, _ = confidential_plan("capture")
    value["host_preimages"][0]["capture"]["live"]["id"] = uid("other-live")
    with pytest.raises(ContractError, match="bind the reviewed live reference"):
        validate_plan(reseal(value))


def test_protected_preimages_have_no_new_private_content_size_cap():
    value, current, store, captures = confidential_plan("preserve")
    large_projection = SECRET * 100_000
    for role in ("live", "proposed"):
        reference = value["host_preimages"][0][role]
        store[reference["id"]] = replace(store[reference["id"]], projection=large_projection)
    current[STEP] = large_projection
    check(value, current, store, captures)


@pytest.mark.parametrize("axis", ["effects", "projection-bytes"])
def test_private_comparison_linear_work(axis):
    samples = []
    for size in (4, 32, 128):
        value, _, _, _ = confidential_plan("capture")
        template_effect = copy.deepcopy(value["effects"][0])
        template_preimage = copy.deepcopy(value["host_preimages"][0])
        value["effects"], value["host_preimages"] = [], []
        current, store, captures = {}, {}, {}
        private_bytes = SECRET * (size * 64 if axis == "projection-bytes" else 1)
        for index in range(size if axis == "effects" else 1):
            step = f"private-{index:05d}"
            item = copy.deepcopy(template_preimage)
            item["effect_step"] = step
            for role in ("baseline", "live", "proposed", "capture"):
                reference = item[role]
                reference.update(id=uid(f"{step}-{role}"), effect_step=step)
                if role != "capture":
                    store[reference["id"]] = ProtectedHostPreimage(
                        copy.deepcopy(reference), private_bytes
                    )
            item["capture"]["live"] = copy.deepcopy(item["live"])
            captures[step] = ProtectedHostCapture(copy.deepcopy(item["capture"]), private_bytes)
            current[step] = private_bytes
            value["effects"].append({**template_effect, "step": step})
            value["host_preimages"].append(item)
        value = reseal(value)
        compared = 0
        original = live_change.compare_digest

        def counted(left, right, original=original):
            nonlocal compared
            compared += len(left) + len(right)
            return original(left, right)

        def run(value=value, current=current, store=store, captures=captures):
            for _ in range(2):
                require_current_host_preimages(
                    value,
                    current,
                    confidential_steps=set(current),
                    protected_preimages=store,
                    protected_captures=captures,
                )

        with patch.object(live_change, "compare_digest", counted):
            _, work = measure(run, modules=(live_change,))
        work["private_compared_bytes"] = compared
        assert compared == 8 * len(current) * len(private_bytes)
        # Each effect has fixed-width metadata and fixed-size private bytes on
        # the effects axis. The other axis fixes metadata and varies byte extent.
        extent = len(current) if axis == "effects" else len(private_bytes)
        samples.append((extent, work))
    assert_linear(samples)
