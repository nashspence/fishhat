"""Exclusive successor selection and explicit closure of an unused partial attempt."""

from __future__ import annotations

import copy
import io
from collections import Counter

import pytest
from fishhat_client.wire import frame, read_frame
from fishhat_contracts import workflow_abandonment
from fishhat_contracts.handoffs import validate_cli_result
from fishhat_contracts.validation import (
    MAX_BYTES,
    ContractError,
    canonical,
    digest,
    validate,
    validate_cli,
)
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_abandonment import (
    abandon_workflow_recovery,
    record_workflow_abandonment,
    recovery_selection,
    validate_abandonment,
    validate_abandonment_closure,
)
from fishhat_contracts.workflow_recovery import (
    commit_workflow_recovery,
    validate_recovery_proposal,
)

from tests.linear_support import assert_linear, measure
from tests.test_contracts import uid
from tests.test_owner_handoffs import cli, operation, request, staged_workflow_input, wire
from tests.test_owner_history import custody_for
from tests.test_plan_review import reseal
from tests.test_workflow_recovery import KEY, commit, prepare, remap_children, scenario

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-recovery.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/cli-output.schema.json",
    ],
    "scope": "exclusive successor reservation, immutable replay and complete current-authority abandonment",
    "relationship": "candidate",
    "reason": "Independent protected context challenges simultaneous selections, absent peers, stale outcomes, restoration and lost-client replay. Bounded transport and retained lineage are checked without claiming native negative proofs, atomic fencing, durability or execution.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_recovery_abandonment_linear_owner_and_selection_work": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_recovery.py#validate_recovery_proposal",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_abandonment.py#validate_abandonment_closure",
            "release.toml#/engineering",
        ],
        "scope": "complete public recovery validation and independently verified abandonment closure over separate sixteenfold owner and selection extents",
        "relationship": "scoped-witness",
        "reason": "Valid complete inputs measure executed work, actual selection owner visits and exact verified-proof membership visits. Synthetic setup is outside measurement and supplies no native authentication or fencing qualification.",
        "claims": ["engineering:workflow.recovery-proposal"],
    },
}


def abandon_proof(proposal, owner, custody=None):
    origin = next(
        p["owner"]
        for p in proposal["participants"]
        if all(p["owner"][k] == owner[k] for k in ("tool", "id"))
    )
    query = {"owner": owner, "phase": "abandon", "proposal": proposal, "custody": custody}
    value = {
        "format": "deployment-ops/workflow-abandonment/v1",
        "kind": "WorkflowAbandonment",
        "owner": copy.deepcopy(owner),
        "origin": copy.deepcopy(origin),
        "custody": copy.deepcopy(custody),
        "workflow_id": proposal["workflow_id"],
        "recovery_id": proposal["recovery_id"],
        "proposal_digest": digest(proposal),
        "request_digest": digest(query),
        "native_evidence": digest({"positive-native-proof": "never-admitted-and-closed"}),
        "retained_closure_digest": digest({"ancestors": "retained-with-holds"}),
        "state": "abandoned",
    }
    body = {k: v for k, v in operation()["witness"].items() if k != "signature"}
    body.update(
        owner=owner,
        kind="approval",
        state="workflow-supersession-abandoned",
        workflow_id=proposal["workflow_id"],
        subject_digest=digest(value),
        evidence_digests=[],
    )
    value["witness"] = sign(body, KEY)
    return query, value


def abandon(proposal, owner, *, custody=None, **overrides):
    query, proof = abandon_proof(proposal, owner, custody)
    context = {
        "expected_owner": owner,
        "recovery_authorized": True,
        "verified_proposal": copy.deepcopy(proposal),
        "verified_abandonment": proof,
        "verified_no_child_admission": True,
    }
    context.update(overrides)
    return query, abandon_workflow_recovery(query, **context)


def alternative(proposal, tag):
    result = copy.deepcopy(proposal)
    result["workflow_id"] = uid("replacement-workflow-" + tag)
    result["recovery_id"] = uid("replacement-recovery-" + tag)
    result["successor"]["workflow_id"] = result["workflow_id"]
    changed = {}
    for participant in result["successor"]["participants"]:
        for slot in participant["requests"]:
            old = {"owner": participant["owner"], "request_id": slot["request_id"]}
            slot["request_id"] = uid(tag + slot["request_id"])
            changed[canonical(old)] = {
                "owner": participant["owner"],
                "request_id": slot["request_id"],
            }
            if "plan" in slot:
                slot["plan"]["id"] = uid(tag + slot["plan"]["id"])
                reseal(slot["plan"])
    result["successor"]["target"] = remap_children(result["successor"]["target"], changed)
    for participant in result["successor"]["participants"]:
        for slot in participant["requests"]:
            if "intent" in slot:
                slot["intent"] = remap_children(slot["intent"], changed)
    for disposition in result["children"]:
        disposition["successor"] = changed[canonical(disposition["successor"])]
    result["abandonments"] = []
    return result


def closed_selection(proposal):
    proofs = [abandon(proposal, p["owner"])[1] for p in proposal["participants"]]
    return {"selection": recovery_selection(proposal), "proofs": proofs}


def test_exclusive_selection_requires_all_owner_abandonment_before_replacement():
    proposal, records = scenario(multiple=True)
    a = prepare(proposal, records)
    replacement = alternative(proposal, "after-partial-selection")
    with pytest.raises(ContractError, match="reserved by another"):
        prepare(replacement, records, reserved_successor=a)
    closure = closed_selection(proposal)
    replacement["abandonments"] = [closure]
    proofs = closure["proofs"]
    abandoned = record_workflow_abandonment(a, proofs[0])
    assert abandoned["recovery"]["request"] == a["recovery"]["request"]
    assert abandoned["state"] == "cancelled"
    assert abandoned["recovery"]["phase"] == "abandoned"
    assert prepare(proposal, records, reserved_successor=abandoned) == abandoned
    s2 = prepare(
        replacement,
        records,
        reserved_successor=abandoned,
        verified_abandonments=proofs,
        local_abandonments=[proofs[0]],
    )
    _, committed = commit(s2, replacement)
    assert committed["id"] != a["id"]
    assert committed["recovery"]["request"]["proposal"]["abandonments"] == [closure]
    assert (
        prepare(
            proposal,
            records,
            retained_preparation=abandoned,
            reserved_successor=committed,
            local_abandonments=[proofs[0]],
            verified_proposal={},
        )
        == abandoned
    )
    changed = copy.deepcopy(proposal)
    changed["successor"]["initial_driver"]["principal"] = "other-recovery-operator"
    with pytest.raises(ContractError, match="accepted workflow recovery preparation input changed"):
        prepare(changed, records, retained_preparation=abandoned, reserved_successor=committed)
    assert (
        records[0]["record"]["proposal"]["workflow_id"]
        == proposal["origins"][0]["reference"]["record"]["id"]
    )


@pytest.mark.parametrize("change", ["missing-peer", "unverified", "changed-selection", "old-epoch"])
def test_partial_or_substituted_abandonment_cannot_release_selection(change):
    proposal, records = scenario(multiple=True)
    value = prepare(proposal, records)
    replacement = alternative(proposal, change)
    closure = closed_selection(proposal)
    verified = copy.deepcopy(closure["proofs"])
    replacement["abandonments"] = [closure]
    if change == "missing-peer":
        closure["proofs"].pop()
    elif change == "unverified":
        verified.pop()
    elif change == "changed-selection":
        closure["selection"]["proposal_digest"] = digest({"another": "proposal"})
    else:
        closure["proofs"][-1]["owner"]["epoch"] = uid("unproven-current-epoch")
    with pytest.raises(ContractError):
        prepare(replacement, records, reserved_successor=value, verified_abandonments=verified)


def test_verified_abandonment_membership_requires_the_complete_exact_proof():
    proposal, _ = scenario(multiple=True)
    closure = {
        "selection": recovery_selection(proposal),
        "proofs": [abandon_proof(proposal, p["owner"])[1] for p in proposal["participants"]],
    }
    replacement = alternative(proposal, "exact-verified-abandonment")
    replacement["abandonments"] = [closure]
    verified = copy.deepcopy(list(reversed(closure["proofs"])))
    validate_abandonment_closure(replacement, verified_abandonments=verified)
    substituted = verified[0]
    substituted["native_evidence"] = digest({"different": "independently-selected-native-proof"})
    body = {key: value for key, value in substituted["witness"].items() if key != "signature"}
    body["subject_digest"] = digest(
        {key: value for key, value in substituted.items() if key != "witness"}
    )
    substituted["witness"] = sign(body, KEY)
    validate_abandonment(substituted, selection=closure["selection"])
    with pytest.raises(ContractError, match="not independently authenticated"):
        validate_abandonment_closure(replacement, verified_abandonments=verified)


def test_abandoned_absent_peer_cannot_later_prepare_the_old_successor():
    proposal, records = scenario(multiple=True)
    peer = proposal["participants"][1]["owner"]
    _, proof = abandon(proposal, peer)
    with pytest.raises(ContractError, match="cannot prepare again"):
        prepare(proposal, records, owner=peer, reserved_successor=None, local_abandonments=[proof])


def test_abandonment_refuses_any_accepted_child_and_replay_never_revives_commit():
    proposal, records = scenario()
    value = prepare(proposal, records)
    with pytest.raises(ContractError, match="accepted successor child"):
        abandon(proposal, value["owner"], verified_no_child_admission=False)
    query, committed = commit(value, proposal)
    _, proof = abandon(proposal, value["owner"])
    closed = record_workflow_abandonment(committed, proof)
    assert closed["recovery"]["commit"] == committed["recovery"]["commit"]
    assert (
        commit_workflow_recovery(query, closed, recovery_authorized=True, verified_preparations=[])
        == closed
    )
    prepared_closed = record_workflow_abandonment(value, proof)
    with pytest.raises(ContractError, match="cannot commit"):
        commit_workflow_recovery(
            query,
            prepared_closed,
            recovery_authorized=True,
            verified_preparations=query["preparations"],
        )


def test_stale_peer_outcome_can_be_reviewed_only_after_unused_selection_is_closed():
    proposal, records = scenario(multiple=True)
    value = prepare(proposal, records)
    closure = closed_selection(proposal)
    later, latest = scenario(multiple=True, kinds=["unaccepted", "recovered"])
    replacement = alternative(later, "peer-accepted-before-prepare")
    replacement["abandonments"] = [closure]
    successor = prepare(
        replacement,
        latest,
        reserved_successor=value,
        verified_abandonments=closure["proofs"],
        local_abandonments=[closure["proofs"][0]],
    )
    assert successor["recovery"]["request"]["proposal"]["children"][1]["kind"] == "recovered"
    assert value["recovery"]["request"]["proposal"]["children"][1]["kind"] == "unaccepted"


def test_restoration_during_partial_preparation_keeps_historical_bytes_and_closes_selection():
    proposal, records = scenario(multiple=True)
    partial = prepare(proposal, records)
    original_bytes = canonical(partial)
    custody = custody_for(partial)
    _, proof = abandon(proposal, custody["custodian"], custody=custody)
    assert proof["origin"] == partial["owner"]
    assert proof["owner"]["epoch"] != partial["owner"]["epoch"]
    assert canonical(partial) == original_bytes
    with pytest.raises(ContractError, match="cannot be retargeted"):
        record_workflow_abandonment(partial, proof)
    replacement, restored = scenario(multiple=True, historical=True)
    replacement = alternative(replacement, "restored-partial-selection")
    proofs = []
    for participant in replacement["participants"]:
        current = participant["owner"]
        retained = next(
            o["custody"]
            for o in replacement["origins"]
            if o["reference"]["owner"] == participant["origin"]
        )
        proofs.append(abandon(proposal, current, custody=retained)[1])
    replacement["abandonments"] = [{"selection": recovery_selection(proposal), "proofs": proofs}]
    successor = prepare(
        replacement,
        restored,
        reserved_successor=partial,
        verified_abandonments=proofs,
        local_abandonments=[proofs[0]],
    )
    _, result = commit(successor, replacement)
    assert result["owner"]["epoch"] != partial["owner"]["epoch"]
    assert result["recovery"]["phase"] == "committed"
    assert canonical(partial) == original_bytes


def test_abandonment_bounded_route_replay_and_observed_cli_result():
    proposal, _ = scenario(multiple=True)
    owner = proposal["participants"][0]["owner"]
    query, proof = abandon(proposal, owner)
    reference, _ = staged_workflow_input("workflow.recover", query)
    validate("ssh-request.schema.json", request("workflow.recover", reference))
    envelope = wire("workflow.recover", proof)
    validate("ssh-response.schema.json", envelope)
    encoded = frame(envelope)
    assert len(encoded) <= MAX_BYTES + 4
    assert read_frame(io.BytesIO(encoded)) == envelope
    validate_cli(cli(proof))
    for state in ("planned", "accepted"):
        result = cli(proof)
        result.update(state=state, complete=state == "planned")
        with pytest.raises(ContractError):
            validate_cli(result)
    assert abandon(proposal, owner, retained=proof, verified_no_child_admission=False)[1] == proof
    corrupted = copy.deepcopy(proof)
    corrupted["native_evidence"] = digest({"wrong": "native-proof"})
    with pytest.raises(ContractError, match="witness"):
        validate_cli_result(corrupted)


def test_repeated_selection_summaries_do_not_nest_previous_proposals():
    proposal, records = scenario()
    for index in range(20):
        closure = closed_selection(proposal)
        value = alternative(proposal, "retry-" + str(index))
        value["abandonments"] = [closure]
        reference, payload = staged_workflow_input(
            "workflow.recover",
            {"owner": value["participants"][0]["owner"], "phase": "prepare", "proposal": value},
        )
        assert reference["input"]["size"] == len(payload)
        assert "proposal" not in closure
        assert len(canonical(value)) < 2 * len(canonical(proposal))
        proposal = value
    assert records[0]["record"]["id"] == closure["selection"]["original_workflow_id"]


class ObservedProofs(list):
    """Count unchanged proof visits, including list membership's equality scan."""

    def __init__(self, values, counts):
        super().__init__(values)
        self.counts = counts

    def __iter__(self):
        for value in super().__iter__():
            self.counts["verified_proof_visits"] += 1
            yield value

    def __contains__(self, value):
        return any(candidate == value for candidate in self)


@pytest.mark.parametrize("extent", ["owners", "selections"])
def test_recovery_abandonment_linear_owner_and_selection_work(monkeypatch, extent):
    from tests.workflow_growth_support import unprepared_owners

    recovery_samples, closure_samples, visits = [], [], []
    for count in (2, 8, 32):
        owner_count = count if extent == "owners" else 2
        selection_count = 1 if extent == "owners" else count
        initial, records = unprepared_owners(owner_count - 1)
        replacement = alternative(initial, "measured-abandonment-replacement")
        verified = []
        for index in range(selection_count):
            previous = alternative(initial, "measured-abandoned-" + str(index))
            proofs = [abandon_proof(previous, p["owner"])[1] for p in previous["participants"]]
            replacement["abandonments"].append(
                {"selection": recovery_selection(previous), "proofs": proofs}
            )
            verified.extend(copy.deepcopy(proofs))
        counts = Counter(selection_validations=0, selection_owner_visits=0, proof_validations=0)
        actual_validate = workflow_abandonment.validate

        def observed_validate(
            schema, value, definition=None, counts=counts, actual_validate=actual_validate
        ):
            if schema == "workflow-recovery.schema.json":
                if definition == "Selection":
                    counts["selection_validations"] += 1
                    counts["selection_owner_visits"] += len(value["participants"])
                elif definition == "Abandonment":
                    counts["proof_validations"] += 1
            return actual_validate(schema, value, definition)

        with monkeypatch.context() as patch:
            patch.setattr(workflow_abandonment, "validate", observed_validate)
            _, recovery_work = measure(
                lambda replacement=replacement, records=records: validate_recovery_proposal(
                    replacement, verified_origins=records
                ),
                modules=(workflow_abandonment,),
            )
            observed_proofs = ObservedProofs(verified, counts)
            _, closure_work = measure(
                lambda replacement=replacement, observed_proofs=observed_proofs: (
                    validate_abandonment_closure(replacement, verified_abandonments=observed_proofs)
                ),
                modules=(workflow_abandonment,),
            )
        assert len(replacement["participants"]) == owner_count
        assert len(replacement["abandonments"]) == selection_count
        assert counts["selection_validations"] == 2 * selection_count
        assert counts["selection_owner_visits"] == 2 * selection_count * owner_count
        assert counts["proof_validations"] == 2 * selection_count * owner_count
        assert counts["verified_proof_visits"] == len(verified)
        recovery_samples.append((count, recovery_work))
        closure_samples.append((count, closure_work))
        visits.append((count, counts))
    assert_linear(recovery_samples)
    assert_linear(closure_samples)
    assert_linear(visits)
