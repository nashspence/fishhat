"""Complete audit projections preserve original child history and exact reviewed Plans."""

from copy import deepcopy
from random import Random

import pytest
from fishhat_contracts.handoffs import validate_workflow
from fishhat_contracts.record_delivery import RecordSnapshot, validate_record_payload
from fishhat_contracts.validation import ContractError, canonical, digest
from fishhat_contracts.workflow_recovery import validate_recovery_proposal
from fishhat_contracts.workflows import _validate_operation_history

from tests.linear_support import assert_linear, measure
from tests.operation_support import seal_operation
from tests.test_contracts import uid
from tests.test_plan_review import reseal
from tests.test_workflow_evidence import relocation
from tests.test_workflow_recovery import commit, evidence, prepare, scenario
from tests.test_workflow_retained_acceptance import _phase_outcomes, _replace_origin
from tests.workflow_evidence_support import (
    advance_request,
    advance_with_evidence,
    seal_phase_participant,
    synthetic_operation,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/states.json#/rules",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Operation",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-recovery.schema.json",
    ],
    "scope": "ordered child progress and exact retained Plan joins across complete audit and recovery records",
    "relationship": "candidate",
    "reason": "Signed synthetic histories challenge backward progress, changed identities, lost known facts, conflicting independent origins and Plan substitution. Positive controls preserve repeats, missed observations and epoch custody. No native admission, effects or recovery authority is established.",
    "claims": [],
}
CHECK_OVERRIDES = {
    "test_complete_observation_reconciliation_is_linear": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflows.py#_validate_operation_history",
            "release.toml#/engineering",
        ],
        "scope": "complete ordered and independently enumerated observation reconciliation with repeated snapshots and high-bit generations",
        "relationship": "scoped-witness",
        "reason": "Counts executed indexing, all generation-byte passes, repeated observations and cumulative-effect knowledge across sixteenfold child/history extent. Inputs model already validated snapshots; this is work evidence, not authentication or a timing guarantee.",
        "claims": ["engineering:workflow.operation-history"],
    }
}


def retained(state="running", effect="known"):
    value = relocation()
    value = advance_with_evidence(advance_request(value, "source-quiescing"), value)
    participant = value["proposal"]["participants"][0]
    slot = participant["requests"][0]
    reference = {"owner": participant["owner"], "request_id": slot["request_id"]}
    first = synthetic_operation(value, participant, slot, state=state)
    first.update(generation=5, last_event=5, effect_certainty=effect)
    seal_operation(first)
    value = advance_with_evidence(
        advance_request(value, "source-fenced", operations={canonical(reference): first}), value
    )
    return value, reference, first


def later_snapshot(first, **changes):
    value = {**deepcopy(first), "generation": first["generation"] + 1, **changes}
    return seal_operation(value)


def next_phase(value, reference, operation):
    return advance_request(
        value, "destination-restoring", operations={canonical(reference): operation}
    )


def roundtrip(value):
    snapshot = RecordSnapshot(value, uid("complete-audit-history"))
    decoded = validate_record_payload(
        snapshot.reference, canonical(value), expected_owner=value["owner"]
    )
    assert canonical(decoded) == canonical(value)


@pytest.mark.parametrize(
    "change",
    [
        "known-to-none",
        "state",
        "generation",
        "event",
        "identity",
        "created",
        "principal",
        "terminal",
    ],
)
def test_audit_history_refuses_impossible_signed_child_progress_without_mutation(change):
    value, reference, first = retained(state="succeeded" if change == "terminal" else "running")
    later = later_snapshot(first)
    if change == "known-to-none":
        later["effect_certainty"] = "none"
    elif change == "state":
        later["state"] = "accepted"
    elif change == "generation":
        later["generation"] = 4
    elif change == "event":
        later["last_event"] = 4
    elif change == "identity":
        later["id"] = uid("substituted-child-operation")
    elif change == "created":
        later["created_at"] = "2026-10-23T00:00:01Z"
    elif change == "principal":
        later["authenticated_principal"] = "different-operator"
    else:
        later.update(state="running", result_handle=None)
    seal_operation(later)
    query = next_phase(value, reference, later)
    before = canonical(value), canonical(query)
    with pytest.raises(ContractError, match=r"known effect facts|regressed|terminal child"):
        advance_with_evidence(query, value)
    assert (canonical(value), canonical(query)) == before
    accepted = advance_with_evidence(
        next_phase(
            value, reference, deepcopy(first) if change == "terminal" else later_snapshot(first)
        ),
        value,
    )
    record_reference = RecordSnapshot(accepted, uid("adverse-audit-history")).reference
    malformed = deepcopy(accepted)
    replace_latest_phase(malformed, later)
    _phase_outcomes(malformed)
    data = canonical(malformed)
    record_reference.update(digest=digest(malformed), size=len(data))
    with pytest.raises(ContractError, match=r"known effect facts|regressed|terminal child"):
        validate_workflow(malformed)
    with pytest.raises(ContractError, match=r"known effect facts|regressed|terminal child"):
        validate_record_payload(record_reference, data, expected_owner=malformed["owner"])
    assert canonical(malformed) == data


@pytest.mark.parametrize("progress", ["repeat", "same-state", "missed-transition", "no-effects"])
def test_audit_history_preserves_legal_observations_and_public_record_roundtrip(progress):
    value, reference, first = retained(effect="none" if progress == "no-effects" else "known")
    later = deepcopy(first) if progress == "repeat" else later_snapshot(first)
    if progress == "missed-transition":
        later.update(state="succeeded", effect_certainty="known")
        # A relocation has a required result on success; use its complete fixture handle.
        participant = value["proposal"]["participants"][0]
        successful = synthetic_operation(value, participant, participant["requests"][0])
        later["result_handle"] = successful["result_handle"]
        seal_operation(later)
    result = advance_with_evidence(next_phase(value, reference, later), value)
    validate_workflow(result)
    _phase_outcomes(result)
    roundtrip(result)


@pytest.mark.parametrize("historical", [False, True], ids=["current", "restored"])
@pytest.mark.parametrize("kind", ["completed", "recovered"])
def test_recovery_view_requires_exact_operation_plan_id(historical, kind):
    proposal, records = scenario(historical=historical, kinds=[kind])
    validate_recovery_proposal(proposal, verified_origins=records)
    if kind == "completed":
        selected = proposal["successor"]["participants"][0]["requests"][0]["completed"]
    else:
        selected = proposal["children"][0]["recovery"]
    selected["operation"]["plan_id"] = uid("different-retained-plan")
    seal_operation(selected["operation"])
    if kind == "completed":
        proposal["children"][0]["operation"] = evidence(selected["operation"])
    else:
        proposal["children"][0]["recovery"] = {
            **evidence(selected["operation"]),
            "plan": selected["plan"],
        }
    before = canonical(proposal), canonical(records)
    with pytest.raises(ContractError, match="Plan identity mismatch"):
        validate_recovery_proposal(proposal, verified_origins=records)
    with pytest.raises(ContractError, match="Plan identity mismatch"):
        prepare(proposal, records)
    assert (canonical(proposal), canonical(records)) == before


@pytest.mark.parametrize("historical", [False, True], ids=["current", "restored"])
@pytest.mark.parametrize("kind", ["completed", "recovered"])
def test_recovery_view_retains_exact_original_plan_and_epoch_custody(historical, kind):
    proposal, records = scenario(historical=historical, kinds=[kind])
    before = canonical(records)
    _, result = commit(prepare(proposal, records), proposal)
    roundtrip(result)
    assert canonical(records) == before


def replace_latest_phase(record, operation):
    phase = record["advances"][-1]["request"]["phase_evidence"]
    participant = phase["participants"][0]
    participant["operations"][0]["operation"] = deepcopy(operation)
    seal_phase_participant(phase, participant)
    record["advances"][-1]["request_digest"] = digest(record["advances"][-1]["request"])


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("generation", [6, 6.0], ids=["integer", "integral-number"])
def test_recovery_views_reconcile_independent_observation_order(reverse, generation):
    value, _reference, first = retained()
    later = later_snapshot(first, generation=generation)
    proposal, records = scenario(original=value, kinds=["recovered"])
    # Keep two independently retained capsules for the same logical workflow.
    # Their full owner closure is unchanged; their child observations have different revisions.
    # The fixture's relocation has a source and destination owner.
    assert len(records) == 2
    replace_latest_phase(records[1]["record"], later)
    _replace_origin(proposal, records, 1, records[1]["record"])
    disposition = proposal["children"][0]
    failure = later_snapshot(
        first, state="failed", effect_certainty="unknown", generation=7, last_event=7
    )
    disposition["operation"] = evidence(failure)
    recovery = disposition["recovery"]
    recovery["plan"]["subject"]["arguments"]["operation_id"] = failure["id"]
    reseal(recovery["plan"])
    recovery["operation"].update(
        subject=deepcopy(recovery["plan"]["subject"]), plan_digest=recovery["plan"]["digest"]
    )
    seal_operation(recovery["operation"])
    disposition["recovery"] = {**evidence(recovery["operation"]), "plan": recovery["plan"]}
    if reverse:
        records.reverse()
        proposal["origins"].reverse()
    validate_recovery_proposal(proposal, verified_origins=records)


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("conflict", ["effect", "state", "same-generation", "identity", "terminal"])
def test_recovery_views_refuse_contradictions_across_individually_valid_origins(reverse, conflict):
    value, _reference, first = retained(state="succeeded" if conflict == "terminal" else "running")
    later = later_snapshot(first)
    if conflict == "effect":
        later["effect_certainty"] = "none"
    elif conflict == "state":
        later["state"] = "accepted"
    elif conflict == "same-generation":
        later.update(generation=5, last_event=6)
    elif conflict == "identity":
        later["id"] = uid("conflicting-independent-operation")
    else:
        later.update(state="running", result_handle=None)
    seal_operation(later)
    proposal, records = scenario(original=value, kinds=["recovered"])
    replace_latest_phase(records[1]["record"], later)
    _replace_origin(proposal, records, 1, records[1]["record"])
    for record in records:
        validate_workflow(record["record"])
        _phase_outcomes(record["record"])
    if reverse:
        records.reverse()
        proposal["origins"].reverse()
    before = canonical(records), canonical(proposal)
    with pytest.raises(ContractError, match=r"known effect facts|regressed|terminal child"):
        validate_recovery_proposal(proposal, verified_origins=records)
    assert (canonical(records), canonical(proposal)) == before


@pytest.mark.parametrize("unordered", [False, True], ids=["ordered", "independent"])
def test_complete_observation_reconciliation_is_linear(unordered):
    samples = []
    for extent in (16, 64, 256):
        observations = []
        for index in range(extent):
            key = f"child-{index:08d}".encode()
            common = {
                "id": key.decode(),
                "owner": "synthetic-owner",
                "request_id": key.decode(),
                "plan_id": "plan",
                "plan_digest": "plan-digest",
                "subject": {},
                "authenticated_principal": "operator",
                "claimed_actor": None,
                "created_at": "2026-11-01T00:00:00Z",
                "witness": {"workflow_id": "workflow"},
            }
            for offset, (state, effect) in enumerate(
                [
                    ("running", "none"),
                    ("running", "known"),
                    ("waiting", "unknown"),
                    ("running", "known"),
                ]
            ):
                operation = {
                    **common,
                    "generation": (1 << 52) + 4 * index + offset,
                    "last_event": offset,
                    "state": state,
                    "effect_certainty": effect,
                }
                observations.extend([(key, operation), (key, deepcopy(operation))])
        if unordered:
            Random(17).shuffle(observations)
        before = canonical(observations_as_json(observations))

        def complete(observations=observations, extent=extent):
            latest, known = _validate_operation_history(observations, ordered=not unordered)
            assert len(latest) == len(known) == extent
            assert all(operation["last_event"] == 3 for operation in latest.values())
            return latest

        _, work = measure(complete)
        assert canonical(observations_as_json(observations)) == before
        samples.append((extent, work))
    assert_linear(samples)


def observations_as_json(observations):
    return [[key.decode(), operation] for key, operation in observations]
