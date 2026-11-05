"""Partitioned workflow custody, exact replay and independently protected native gates."""

from contextlib import contextmanager
from copy import deepcopy

import pytest
from fishhat_contracts.validation import ContractError, digest
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_journal import verify_journal_signature
from fishhat_owner.workflow_journal import WorkflowJournal

from tests.test_contracts import uid
from tests.workflow_journal_support import (
    DRIVER,
    NEXT_DRIVER,
    Endpoint,
    LogicalWorkload,
    WorkflowRun,
    WorkMeter,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json",
        "fishhat/owner-support/src/fishhat_owner/workflow_journal.py",
    ],
    "scope": "complete distributed journal execution, immutable retry and real disk restoration under independent owner keys and native context",
    "relationship": "candidate",
    "reason": "Adverse native fences, incomplete owner votes, changed accepted input and corrupt physical custody challenge the public reference protocol. Synthetic native facts do not qualify production native execution or platform crash durability.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_uncertain_tail_repair_cost_and_custody": {
        **CHECK_PURPOSE,
        "purpose": "implementation",
        "relationship": "scoped-witness",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json",
            "fishhat/owner-support/src/fishhat_owner/workflow_journal.py#WorkflowJournal.repair_tail",
        ],
        "scope": "Reference repair and measured I/O and hash extent for increasing torn suffixes",
        "reason": "Checks exact quarantine, refusal and positive closure against real store bytes.",
        "claims": ["engineering:workflow.journal-store.repair-tail"],
    },
    "test_complete_workflow_survives_disk_restart_and_lost_replies": {
        **CHECK_PURPOSE,
        "purpose": "implementation",
        "relationship": "scoped-witness",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#WorkflowGate.__init__",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#WorkflowMember.__init__",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#_JournalTarget.record",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#dispatch_journal_command",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#initialize_workflow_journal",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#_JournalTarget.replay_reference",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#WorkflowMember.require_operation_admission",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal_recovery.py#JournalRecovery.outcome",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal_recovery.py#JournalRecovery.apply",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal_recovery.py#JournalRecovery.blocks_work",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal_recovery.py#JournalRecovery.context",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal_recovery.py#JournalRecovery.initialize_gate",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal_recovery.py#JournalRecovery.initialize_member",
            "fishhat/owner-support/src/fishhat_owner/workflow_journal.py#validate_journal_genesis",
            "fishhat/owner-support/src/fishhat_owner/workflow_journal.py#WorkflowJournal.create",
            "fishhat/owner-support/src/fishhat_owner/workflow_journal.py#WorkflowJournal.open",
            "fishhat/owner-support/src/fishhat_owner/workflow_journal.py#WorkflowJournal.lookup",
            "fishhat/owner-support/src/fishhat_owner/workflow_journal.py#WorkflowJournal.outcome_bytes",
            "fishhat/owner-support/src/fishhat_owner/workflow_journal.py#WorkflowJournal.command_bytes",
            "fishhat/owner-support/src/fishhat_owner/workflow_journal.py#WorkflowJournal.guard",
            "fishhat/owner-support/src/fishhat_owner/workflow_journal.py#WorkflowJournal.append",
            "fishhat/owner-support/src/fishhat_owner/workflow_journal.py#WorkflowJournal.iter_events",
            "fishhat/owner-support/src/fishhat_owner/workflow_journal.py#WorkflowJournal.close",
        ],
        "claims": [
            "engineering:workflow.journal.gate-initialize",
            "engineering:workflow.journal.member-initialize",
            "engineering:workflow.journal.get",
            "engineering:workflow.journal.submit",
            "engineering:workflow.journal.initialize",
            "engineering:workflow.journal.replay-reference",
            "engineering:workflow.journal.operation-admission",
            "engineering:workflow.journal-recovery.outcome",
            "engineering:workflow.journal-recovery.apply",
            "engineering:workflow.journal-recovery.blocks_work",
            "engineering:workflow.journal-recovery.context",
            "engineering:workflow.journal-recovery.initialize_gate",
            "engineering:workflow.journal-recovery.initialize_member",
            "engineering:workflow.journal-store.genesis",
            "engineering:workflow.journal-store.create",
            "engineering:workflow.journal-store.open",
            "engineering:workflow.journal-store.lookup",
            "engineering:workflow.journal-store.outcome_bytes",
            "engineering:workflow.journal-store.command_bytes",
            "engineering:workflow.journal-store.guard",
            "engineering:workflow.journal-store.append",
            "engineering:workflow.journal-store.iter_events",
            "engineering:workflow.journal-store.close",
        ],
    },
}


def test_complete_workflow_survives_disk_restart_and_lost_replies(tmp_path):
    from tests.workflow_journal_support import execute_workflow

    result = execute_workflow(tmp_path, LogicalWorkload())
    assert result["completed_owners"] == 2
    assert result["completed_children"] == 4
    assert result["cold_restores"] >= 3
    assert result["lost_reply_replays"] >= 4
    assert result["metrics"]["bytes_read"] > 0
    assert result["metrics"]["bytes_written"] > 0
    assert result["metrics"]["signature_verifications"] > 0
    assert result["metrics"]["artifact_bytes_read"] > 0
    assert result["metrics"]["retained_bytes"] > 0
    assert result["metrics"]["completed_transfers"] == 1
    assert result["metrics"]["completed_recoveries"] == 1
    assert result["metrics"]["completed_nonexecutions"] == 4
    assert result["metrics"]["bounded_reference_replays"] >= 4


@pytest.fixture
def journal_run(tmp_path):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(), meter)
        try:
            yield run
        finally:
            run.close()


def test_missing_or_duplicate_preparations_and_votes_cannot_complete_barrier(journal_run):
    run = journal_run
    first = run.members[0].call("prepare", fresh=True)
    run.gate.call("preparation", {"preparation": first})
    with pytest.raises(ContractError, match="incomplete"):
        run.gate.call("agreement")
    with pytest.raises(ContractError, match="already accepted"):
        run.gate.call("preparation", {"preparation": first})
    second = run.members[1].call("prepare", fresh=True)
    run.gate.call("preparation", {"preparation": second})
    agreement = run.gate.call("agreement")
    for member in run.members:
        member.call("agreement", {"agreement": agreement})
    round_record = run.gate.call("round", {"to_phase": "draining"}, fresh=True)
    vote = run.members[0].call("vote", {"round": round_record}, fresh=True)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    signature = vote["signature"]
    altered = {
        **vote,
        "signature": signature[:-3] + alphabet[alphabet.index(signature[-3]) + 1] + "==",
    }
    with pytest.raises(ContractError):
        run.gate.call("vote", {"vote": altered})
    with pytest.raises(ContractError):
        verify_journal_signature(altered, run.gate.target.keys)
    run.gate.call("vote", {"vote": vote})
    with pytest.raises(ContractError, match="duplicated"):
        run.gate.call("vote", {"vote": vote})
    with pytest.raises(ContractError, match="closure"):
        run.gate.call("decision")
    other_vote = run.members[1].call("vote", {"round": round_record}, fresh=True)
    run.gate.call("vote", {"vote": other_vote})
    run.gate.call("decision")
    with pytest.raises(ContractError, match=r"certificate|mint"):
        run.gate.call("round", {"to_phase": "quiescent"}, fresh=True)
    run.gate.call(
        "certificate", {"owner": run.members[0].target.owner, "round_id": round_record["id"]}
    )
    with pytest.raises(ContractError, match=r"certificate|mint"):
        run.gate.call("round", {"to_phase": "quiescent"}, fresh=True)
    run.gate.call(
        "certificate", {"owner": run.members[1].target.owner, "round_id": round_record["id"]}
    )
    assert (
        run.gate.call("round", {"to_phase": "quiescent"}, fresh=True)["body"]["to_phase"]
        == "quiescent"
    )


def test_unapproved_gate_signature_never_creates_native_reservation(journal_run):
    run = journal_run
    run.prepare()
    round_record = run.gate.call("round", {"to_phase": "draining"}, fresh=True)
    substituted = deepcopy(round_record)
    substituted["signature"] = "A" * 86 + "=="
    before = run.meter.values["native_reserve_visits"]
    with pytest.raises(ContractError, match="signature"):
        run.members[0].call("vote", {"round": substituted}, fresh=True)
    assert run.meter.values["native_reserve_visits"] == before


def test_member_rejects_signed_projection_with_different_installed_procedure(
    journal_run, monkeypatch
):
    from fishhat_contracts.validation import CATALOGUES

    run, member = journal_run, journal_run.members[0]
    assert run.clone_member(0).workflow_id == member.target.workflow_id
    head = member.target.journal.head
    uri = "https://fishhat.invalid/contracts/states.json"
    installed = deepcopy(CATALOGUES[uri])
    installed["workflow_phases"]["host-drain"][1:3] = ["quiescent", "draining"]
    monkeypatch.setitem(CATALOGUES, uri, installed)
    with pytest.raises(
        ContractError, match="workflow requirements or independent gate grant changed"
    ):
        run.clone_member(0)
    assert member.target.journal.head == head
    assert not run.native[0].reservations


def test_vote_once_per_common_round_survives_cold_restart(tmp_path):
    meter, workload = WorkMeter(), LogicalWorkload()
    with meter.account():
        run = WorkflowRun(tmp_path, workload, meter)
        try:
            run.prepare()
            original, votes, _, certificates = run.round("draining", apply=False)
            member = run.members[0]
            reference = member.inputs[votes[0]["id"]][0]
            count = meter.values["native_reserve_visits"]
            with pytest.raises(ContractError, match="already voted"):
                member.call("vote", {"round": original}, fresh=True)
            assert meter.values["native_reserve_visits"] == count
        finally:
            run.close()
        restored = WorkflowRun(tmp_path, workload, meter, restore=True)
        try:
            member = restored.members[0]
            assert member.retry(reference) == votes[0]
            with pytest.raises(ContractError, match="already voted"):
                member.call("vote", {"round": original}, fresh=True)
            assert meter.values["native_reserve_visits"] == count
            for endpoint, certificate in zip(restored.members, certificates, strict=True):
                endpoint.call("apply", {"certificate": certificate}, fresh=True)
            refreshed, _, _, _ = restored.round("draining")
            assert refreshed["id"] != original["id"]
            count = meter.values["native_reserve_visits"]
            with pytest.raises(ContractError, match="already voted"):
                member.call("vote", {"round": original}, fresh=True)
            assert member.retry(reference) == votes[0]
            assert meter.values["native_reserve_visits"] == count
        finally:
            restored.close()


def test_lost_native_fence_survives_cold_restart_and_blocks_new_apply(tmp_path):
    """Loss of the local effect guard closes admission and retains shared exclusion."""
    meter, workload = WorkMeter(), LogicalWorkload()
    with meter.account():
        run = WorkflowRun(tmp_path, workload, meter)
        try:
            run.prepare()
            _, _, _, certificates = run.round("draining", apply=False)
            certificate_id = certificates[0]["id"]
            run.native[0].lose_fence(run.members[0].target._reservation)
            protection_id = run.members[0].target._reservation["id"]
        finally:
            run.close()
        del run, certificates
        restored = WorkflowRun(tmp_path, workload, meter, restore=True)
        try:
            certificate = restored.gate.read(certificate_id)
            with pytest.raises(ContractError, match="native fence"):
                restored.members[0].call("apply", {"certificate": certificate}, fresh=True)
            assert not restored.native[0].admissions
            assert protection_id in restored.native[0].protection_holds
        finally:
            restored.close()


def test_issuer_cannot_revoke_shared_protection_while_dependents_remain_open(journal_run):
    run = journal_run
    run.prepare()
    run.round("draining")
    actor, member = run.native[0], run.members[0]
    reservation = member.target._reservation
    assert member.target.phase == run.members[1].target.phase == "draining"
    with pytest.raises(ContractError, match="nonrevocable native protection"):
        actor.revoke_protection(reservation)
    assert reservation["id"] in actor.protection_holds
    actor.check(reservation, member.target._round["body"])


def test_accepted_request_rejects_changed_input_and_replay_requires_current_permission(journal_run):
    run, member = journal_run, journal_run.members[0]
    command = member.command("prepare", fresh=True)
    accepted = member.submit(command)
    changed = deepcopy(command)
    changed["payload"]["driver_term"] += 1
    another_transport = Endpoint(member.target, run.root / "changed-input", run.meter)
    with pytest.raises(ContractError, match=r"changed accepted|retained journal command changed"):
        another_transport.submit(changed)
    changed["payload"]["driver_term"] = True
    with pytest.raises(ContractError, match="changed accepted input"):
        member.target._run(changed, DRIVER)
    reference = member.inputs[command["id"]][0]
    changed_size = deepcopy(reference)
    changed_size["input"]["size"] += 1
    with pytest.raises(ContractError, match=r"changed accepted|size|length"):
        member.retry(changed_size)
    (member.root / (command["id"] + ".input")).unlink()
    assert member.retry(reference) == accepted
    gate_command_id = uid("initial-gate-command")
    retained = run.gate.target.journal.lookup(gate_command_id, read_authorized=True)
    command_bytes = run.gate.target.journal.command_bytes(gate_command_id, read_authorized=True)
    assert len(command_bytes) > 4096
    large_reference = {
        "owner": run.gate_owner,
        "workflow_id": run.manifest["workflow_id"],
        "command_id": gate_command_id,
        "input": {
            "owner": run.gate_owner,
            "id": uid("handle-" + gate_command_id),
            "purpose": "workflow-input",
            "binding": {"kind": "staging", "staging_id": uid("staging-" + gate_command_id)},
            "digest": retained["outcome"]["body"]["command_digest"],
            "size": len(command_bytes),
        },
    }
    (run.root / "gate-initialize.input").unlink()
    retry_samples = []
    for count in (1, 4, 16):
        before = run.meter.values.copy()
        for _ in range(count):
            assert run.gate.retry(large_reference) == retained["outcome"]
        work = run.meter.values - before
        assert work["artifact_bytes_read"] == 0
        assert work["wire_bytes"] > 0 and work["gate_authorization_visits"] > 0
        retry_samples.append((count, dict(work)))
    first_count, first = retry_samples[0]
    for count, work in retry_samples[1:]:
        for metric in first.keys() | work.keys():
            assert work.get(metric, 0) * first_count <= 1.25 * first.get(metric, 0) * count, (
                metric,
                retry_samples,
            )
    run.native[0].denied_principals.add(DRIVER)
    with pytest.raises(ContractError, match="permission denied"):
        member.retry(reference)


def test_partial_driver_transfer_closes_both_old_and_new_admission(journal_run):
    run = journal_run
    run.prepare()
    for phase in ("draining", "quiescent", "host-effect"):
        run.round(phase)
    proposal_record = run.gate.call("transfer.propose", {"new_driver": NEXT_DRIVER})
    frozen = run.members[0].call("transfer.freeze", {"proposal": proposal_record})
    run.gate.call("transfer.collect_freeze", {"freeze": frozen})
    with pytest.raises(ContractError, match="closure"):
        run.gate.call("transfer.commit")
    for principal in (DRIVER, NEXT_DRIVER):
        with pytest.raises(ContractError, match=r"frozen|driver"):
            run.members[0].call(
                "admit", {"child": run.workload.child(0, 0)}, fresh=True, principal=principal
            )
    assert not run.native[0].admissions


def test_unknown_accepted_operation_blocks_successor_commit(journal_run):
    run = journal_run
    run.prepare()
    for phase in ("draining", "quiescent", "host-effect"):
        run.round(phase)
    run.children(unknown_at=(0, 0))
    run.recover(commit=False)
    with pytest.raises(ContractError, match=r"unknown|active original"):
        run.gate.call("recover.commit")
    assert run.native[0].retired
    assert run.native[0].operations
    with pytest.raises(ContractError, match=r"retired|frozen"):
        run.members[1].call("admit", {"child": run.workload.child(1, 0)}, fresh=True)


@pytest.mark.parametrize("state", ["succeeded", "failed", "cancelled", "quarantined"])
def test_retained_terminal_child_cannot_be_replaced_by_a_new_signed_outcome(journal_run, state):
    run, member, native = journal_run, journal_run.members[0], journal_run.native[0]
    run.prepare()
    for phase in ("draining", "quiescent", "host-effect"):
        run.round(phase)
    child = run.workload.child(0, 0)
    member.call("admit", {"child": child}, fresh=True)
    run.submit_native(0, run.native_submission(0, 0))
    original = native.finish(child, unknown=state == "quarantined")

    def signed_state(operation, destination, generation):
        changed = deepcopy(operation)
        changed.update(state=destination, generation=generation, last_event=generation)
        changed["effect_certainty"] = "unknown" if destination == "quarantined" else "known"
        witness = {key: value for key, value in changed["witness"].items() if key != "signature"}
        witness.update(
            state=destination,
            generation=generation,
            subject_digest=digest(
                {key: value for key, value in changed.items() if key != "witness"}
            ),
        )
        changed["witness"] = sign(witness, native.key)
        return changed

    original = signed_state(original, state, original["generation"])
    command = member.command("complete", {"operation": original})
    retained = member.submit(command)
    head = member.target.journal.head
    replacement = signed_state(original, "succeeded", original["generation"] + 1)
    with pytest.raises(ContractError, match="terminal child outcome cannot be replaced"):
        member.call("complete", {"operation": replacement})
    assert member.target.journal.head == head
    assert member.submit(command) == retained
    assert list(member.target.outcomes.values()) == [original]


def test_preparation_and_initial_resume_preserve_lifecycle_until_phase_progress(journal_run):
    run = journal_run
    endpoints = [run.gate, *run.members]
    accepted_resumes = []
    for endpoint in endpoints:
        assert endpoint.target.state == "prepared"
        endpoint.call("pause", fresh=True)
        command = endpoint.command("resume", fresh=True)
        receipt = endpoint.submit(command)
        assert receipt["body"]["state"] == endpoint.target.state == "prepared"
        accepted_resumes.append((endpoint, command, receipt))
    run.prepare()
    assert all(endpoint.target.state == "prepared" for endpoint in endpoints)
    run.round("draining")
    assert all(endpoint.target.state == "active" for endpoint in endpoints)
    for endpoint, command, receipt in accepted_resumes:
        assert endpoint.submit(command) == receipt
        assert endpoint.target.state == "active"


@pytest.mark.parametrize("boundary", ["round", "vote", "decision", "apply"])
def test_cancelled_workflow_cannot_advance_native_final_settlement(journal_run, boundary):
    run = journal_run
    run.prepare()
    for phase in ("draining", "quiescent", "host-effect"):
        run.round(phase)
    run.children()
    run.round("reconciling")
    if boundary == "round":
        endpoint, action, payload, fresh = run.gate, "settle", {"to_phase": "completed"}, True
    else:
        round_record = run.gate.call("settle", {"to_phase": "completed"}, fresh=True)
        if boundary == "vote":
            endpoint, action, payload, fresh = run.members[0], "vote", {"round": round_record}, True
        else:
            for member in run.members:
                vote = member.call("vote", {"round": round_record}, fresh=True)
                run.gate.call("vote", {"vote": vote})
            if boundary == "decision":
                endpoint, action, payload, fresh = run.gate, "decision", {}, False
            else:
                run.gate.call("decision")
                certificate = run.gate.call(
                    "certificate",
                    {"owner": run.members[0].target.owner, "round_id": round_record["id"]},
                )
                endpoint, action, payload, fresh = (
                    run.members[0],
                    "apply",
                    {"certificate": certificate},
                    True,
                )
    endpoint.call("cancel", fresh=True)
    head = endpoint.target.journal.head
    with pytest.raises(ContractError, match="restricted workflow lifecycle"):
        endpoint.call(action, payload, fresh=fresh)
    assert endpoint.target.journal.head == head
    assert endpoint.target.state == "cancelled"
    assert endpoint.target.phase == "reconciling"


@pytest.mark.parametrize("state", ["cancelled", "completed"])
def test_terminal_workflow_cannot_start_or_join_a_driver_transfer(journal_run, state):
    run = journal_run
    run.prepare()
    for phase in ("draining", "quiescent", "host-effect"):
        run.round(phase)
    run.children()
    run.round("reconciling")
    proposal = run.gate.call("transfer.propose", {"new_driver": NEXT_DRIVER})
    if state == "cancelled":
        run.gate.call("cancel", fresh=True)
        for member in run.members:
            member.call("cancel", fresh=True)
    else:
        round_record = run.gate.call("settle", {"to_phase": "completed"}, fresh=True)
        for member in run.members:
            vote = member.call("vote", {"round": round_record}, fresh=True)
            run.gate.call("vote", {"vote": vote})
        run.gate.call("decision")
        for member in run.members:
            certificate = run.gate.call(
                "certificate", {"owner": member.target.owner, "round_id": round_record["id"]}
            )
            member.call("apply", {"certificate": certificate}, fresh=True)
    with pytest.raises(ContractError, match="terminal workflow lifecycle cannot transfer"):
        run.gate.call("transfer.propose", {"new_driver": NEXT_DRIVER})
    for member in run.members:
        with pytest.raises(ContractError, match="terminal workflow lifecycle cannot transfer"):
            member.call("transfer.freeze", {"proposal": proposal})
        assert member.target.state == state


def test_completed_workflow_final_barrier_refresh_keeps_child_admission_closed(journal_run):
    run = journal_run
    run.prepare()
    for phase in ("draining", "quiescent", "host-effect"):
        run.round(phase)
    run.children()
    run.round("reconciling")
    run.round("completed")
    outcomes = [deepcopy(actor.operations) for actor in run.native]
    round_record = run.gate.call("settle", {"to_phase": "completed"}, fresh=True)
    for member in run.members:
        vote = member.call("vote", {"round": round_record}, fresh=True)
        run.gate.call("vote", {"vote": vote})
    run.gate.call("decision")
    for index, member in enumerate(run.members):
        certificate = run.gate.call(
            "certificate", {"owner": member.target.owner, "round_id": round_record["id"]}
        )
        member.call("apply", {"certificate": certificate}, fresh=True)
        assert member.target.state == "completed"
        assert member.target.phase == "completed"
        with pytest.raises(ContractError, match="admission"):
            member.call("admit", {"child": run.workload.child(index, 0)}, fresh=True)
    assert run.gate.target.state == "completed"
    assert [actor.operations for actor in run.native] == outcomes


@pytest.mark.parametrize("delayed", ["admit", "_accept_native"], ids=["during-review", "at-commit"])
def test_native_acceptance_rechecks_certificate_deadline(journal_run, monkeypatch, delayed):
    run = journal_run
    deadline = "2026-11-01T00:30:00Z"
    # A peer's shorter reservation determines the shared certificate expiry.
    run.native[1].reservation_expires_at = deadline
    run.prepare()
    for phase in ("draining", "quiescent", "host-effect"):
        run.round(phase)
    for index, member in enumerate(run.members):
        member.call("admit", {"child": run.workload.child(index, 0)}, fresh=True)
    accepted_submission = run.native_submission(1, 0)
    accepted = run.submit_native(1, accepted_submission)

    member = run.members[0].target
    actor = run.native[0]
    before = "2026-11-01T00:29:59Z"
    now = before
    monkeypatch.setattr(member, "clock", lambda: now)
    original = getattr(actor, delayed)

    def cross_deadline(*args, **kwargs):
        nonlocal now
        now = deadline
        return original(*args, **kwargs)

    monkeypatch.setattr(actor, delayed, cross_deadline)
    with pytest.raises(ContractError, match="admission expired"):
        run.submit_native(0, run.native_submission(0, 0))
    assert not actor.admissions
    monkeypatch.setattr(run.members[1].target, "clock", lambda: now)
    assert run.submit_native(1, accepted_submission) == accepted


@pytest.mark.parametrize("control", ["pause", "transfer"])
@pytest.mark.parametrize("already_accepted", [False, True], ids=["permit-only", "native-accepted"])
def test_native_acceptance_rechecks_control_after_journal_permit(
    journal_run, control, already_accepted
):
    run, member = journal_run, journal_run.members[0]
    run.prepare()
    for phase in ("draining", "quiescent", "host-effect"):
        run.round(phase)
    child = run.workload.child(0, 0)
    member.call("admit", {"child": child}, fresh=True)
    assert not run.native[0].admissions
    submission = run.native_submission(0, 0)
    original = run.submit_native(0, submission) if already_accepted else None
    alias = run.clone_member(0)
    if control == "pause":
        member.call("pause", fresh=True)
    else:
        proposal_record = run.gate.call("transfer.propose", {"new_driver": NEXT_DRIVER})
        member.call("transfer.freeze", {"proposal": proposal_record})
    with pytest.raises(ContractError, match=r"head|predecessor|stale|custody"):
        alias.require_operation_admission(submission, principal=DRIVER)
    with pytest.raises(ContractError, match=r"head|predecessor|stale|custody"):
        with alias.operation_admission_guard(submission, principal=DRIVER):
            raise AssertionError("stale aliased target entered native admission")
    if already_accepted:
        assert run.submit_native(0, submission) == original
        settled = run.native[0].finish(child)
        member.call("complete", {"operation": settled})
        assert settled["state"] == "succeeded"
    else:
        with pytest.raises(ContractError, match=r"paused|frozen|admission closed"):
            run.submit_native(0, submission)
        assert not run.native[0].admissions


def store_identity():
    return {
        "uri": "https://fishhat.invalid/contracts/workflow-journal.schema.json#/$defs/JournalRecord",
        "digest": digest("independently-installed-synthetic-journal-profile"),
    }


@pytest.mark.parametrize(
    "damage",
    ["missing", "empty", "partial-frame", "whole-frame", "changed-byte", "consistent-rollback"],
)
def test_missing_or_corrupt_accepted_journal_never_becomes_empty_custody(tmp_path, damage):
    path = tmp_path / "accepted.journal"
    owner, schema, meter = LogicalWorkload().owner(0), store_identity(), WorkMeter()
    journal = meter.store(path, owner, schema)
    prior_size = path.stat().st_size
    head_path = path.with_name(path.name + ".head")
    old_head_file = head_path.read_bytes()
    journal.append(
        "accepted-command",
        {"native": "original"},
        {"result": "retained"},
        expected_head=journal.head,
    )
    journal.close()
    original = path.read_bytes()
    if damage == "missing":
        path.unlink()
    elif damage == "empty":
        path.write_bytes(b"")
    elif damage == "partial-frame":
        path.write_bytes(original[:-7])
    elif damage in {"whole-frame", "consistent-rollback"}:
        path.write_bytes(original[:prior_size])
        if damage == "consistent-rollback":
            head_path.write_bytes(old_head_file)
            with pytest.raises(ContractError, match="independent checkpoint"):
                WorkflowJournal.open(path, expected_owner=owner, expected_schema=schema)
    else:
        changed = bytearray(original)
        changed[-1] ^= 1
        path.write_bytes(changed)
    with pytest.raises((ContractError, OSError)):
        meter.store(path, owner, schema, restore=True)


def test_journal_replay_preserves_original_bytes_and_requires_current_read_permission(tmp_path):
    path = tmp_path / "accepted.journal"
    owner, schema = LogicalWorkload().owner(0), store_identity()
    meter = WorkMeter()
    journal = meter.store(path, owner, schema)
    first = journal.append(
        "first", {"request": "one"}, {"outcome": "one"}, expected_head=journal.head
    )
    old_head = journal.head
    journal.append("later", {"request": "two"}, {"outcome": "two"}, expected_head=old_head)
    journal.close()
    restored = meter.store(path, owner, schema, restore=True)
    try:
        assert (
            restored.append("first", {"request": "one"}, {"outcome": "one"}, expected_head=old_head)
            == first
        )
        assert restored.lookup("first", read_authorized=True) == first
        with pytest.raises(ContractError):
            restored.lookup("first", read_authorized=False)
        with pytest.raises(ContractError, match="changed accepted"):
            restored.append(
                "first", {"request": "changed"}, {"outcome": "one"}, expected_head=restored.head
            )
        changed = deepcopy(owner)
        changed["epoch"] = LogicalWorkload().owner(1)["epoch"]
    finally:
        restored.close()
    with pytest.raises(ContractError, match="owner"):
        meter.store(path, changed, schema, restore=True)


def test_journal_requires_one_writer_and_explicit_new_custody(tmp_path):
    path = tmp_path / "accepted.journal"
    owner, schema = LogicalWorkload().owner(0), store_identity()
    meter = WorkMeter()
    journal = meter.store(path, owner, schema)
    try:
        with pytest.raises((ContractError, OSError)):
            meter.store(path, owner, schema)
        with pytest.raises((ContractError, OSError)):
            meter.store(path, owner, schema, restore=True)
        # Separate inodes can pass flock and authenticate the same checkpoint.
        clone = tmp_path / "cloned.journal"
        clone.write_bytes(path.read_bytes())
        clone.with_name(clone.name + ".head").write_bytes(
            path.with_name(path.name + ".head").read_bytes()
        )
        with (
            journal.guard(journal.head),
            pytest.raises(ContractError, match="writer already active"),
        ):
            WorkflowJournal.open(
                clone,
                expected_owner=owner,
                expected_schema=schema,
                writer_lease=meter.writer_lease(path),
            )
    finally:
        journal.close()

    @contextmanager
    def unavailable():
        with meter.writer_lease(path) as retain_head:

            def fail_advance(previous, current):
                if previous != current:
                    raise OSError("independent checkpoint unavailable")
                retain_head(previous, current)

            yield fail_advance

    writer = WorkflowJournal.open(
        path, expected_owner=owner, expected_schema=schema, writer_lease=unavailable()
    )
    try:
        with pytest.raises(OSError, match="independent checkpoint unavailable"):
            writer.append("uncertain", {}, {}, expected_head=writer.head)
        with pytest.raises(ContractError, match="writer unavailable"), writer.guard(writer.head):
            pytest.fail("unacknowledged checkpoint publication reopened admission")
    finally:
        writer.close()
    with pytest.raises(ContractError, match="independent checkpoint"):
        meter.store(path, owner, schema, restore=True)


@pytest.mark.parametrize("failure", ["fsync", "head-replace", "independent-checkpoint"])
def test_failed_append_preserves_tail_and_old_custody_without_reopening_writer(
    tmp_path, monkeypatch, failure
):
    from fishhat_owner import workflow_journal as store_module

    path = tmp_path / "accepted.journal"
    owner, schema = LogicalWorkload().owner(0), store_identity()
    meter = WorkMeter()
    journal = meter.store(path, owner, schema)
    original = journal.append(
        "original", {"request": "accepted"}, {"outcome": "retained"}, expected_head=journal.head
    )
    checkpoint = original["receipt"]["digest"]
    accepted_bytes = path.read_bytes()
    local_head_path = path.with_name(path.name + ".head")
    accepted_head_bytes = local_head_path.read_bytes()

    def fail(*args):
        raise OSError("injected durable publication failure")

    try:
        with monkeypatch.context() as fault:
            if failure == "independent-checkpoint":
                fault.setattr(journal, "_retain_head", fail)
            else:
                fault.setattr(store_module.os, "fsync" if failure == "fsync" else "replace", fail)
            with pytest.raises(OSError, match="durable publication failure"):
                journal.append(
                    "uncertain",
                    {"request": "new"},
                    {"outcome": "not acknowledged"},
                    expected_head=journal.head,
                )
        tail = path.read_bytes()
        local_head_before_repair = local_head_path.read_bytes()
        assert (local_head_before_repair != accepted_head_bytes) == (
            failure == "independent-checkpoint"
        )
        assert meter.checkpoints[path] == checkpoint
        assert tail.startswith(accepted_bytes) and len(tail) > len(accepted_bytes)
        assert journal.lookup("original", read_authorized=True) == original
        assert journal.lookup("uncertain", read_authorized=True) is None
        with pytest.raises(ContractError, match="writer unavailable"):
            journal.append("later", {}, {}, expected_head=journal.head)
    finally:
        journal.close()
    with pytest.raises(ContractError):
        meter.store(path, owner, schema, restore=True)
    assert path.read_bytes() == tail
    options = {"expected_owner": owner, "expected_schema": schema}
    with pytest.raises(ContractError, match="independent checkpoint"):
        WorkflowJournal.open(path, **options, verified_prefix_head=digest("stale checkpoint"))
    prefix = WorkflowJournal.open(path, **options, verified_prefix_head=checkpoint)
    try:
        with pytest.raises(ContractError, match="permission"):
            prefix.lookup("original", read_authorized=False)
        assert prefix.lookup("original", read_authorized=True) == original
        assert prefix.lookup("uncertain", read_authorized=True) is None
        with pytest.raises(ContractError, match="writer unavailable"), prefix.guard(checkpoint):
            pytest.fail("prefix inspection opened native admission")
        with pytest.raises(ContractError, match="writer unavailable"):
            prefix.append("later", {}, {}, expected_head=checkpoint)
        with pytest.raises(ContractError, match="lacks native closure"):
            prefix.repair_tail(
                writer_lease=meter.writer_lease(path), reconcile=lambda evidence, archive: False
            )
        assert path.read_bytes() == tail
        assert local_head_path.read_bytes() == local_head_before_repair

        def reconcile(evidence, archive):
            from hashlib import sha256

            uncertain = tail[len(accepted_bytes) :]
            assert archive.read_bytes() == uncertain
            assert evidence == {
                "owner": owner,
                "journal_id": original["receipt"]["journal_id"],
                "head": checkpoint,
                "sequence": 1,
                "tail_size": len(uncertain),
                "tail_digest": "sha256:" + sha256(uncertain).hexdigest(),
            }
            return True

        prefix.repair_tail(writer_lease=meter.writer_lease(path), reconcile=reconcile)
        assert path.read_bytes() == accepted_bytes
        assert local_head_path.read_bytes() == accepted_head_bytes
        with pytest.raises(ContractError, match="writer unavailable"):
            prefix.append("later", {}, {}, expected_head=checkpoint)
    finally:
        prefix.close()
    assert [p.read_bytes() for p in tmp_path.glob("*.quarantine-*")] == [
        tail[len(accepted_bytes) :]
    ]
    reopened = meter.store(path, owner, schema, restore=True)
    try:
        assert reopened.lookup("original", read_authorized=True) == original
        assert reopened.lookup("uncertain", read_authorized=True) is None
        assert (
            reopened.append(
                "original", original["request"], original["outcome"], expected_head=checkpoint
            )
            == original
        )
        reopened.append("later", {}, {}, expected_head=checkpoint)
    finally:
        reopened.close()


def test_uncertain_tail_repair_cost_and_custody(tmp_path):
    owner, schema = LogicalWorkload().owner(0), store_identity()
    overhead = None
    for extent in (1000, 66000, 265000):
        path = tmp_path / f"journal-{extent}"
        meter = WorkMeter()
        journal = meter.store(path, owner, schema)
        checkpoint = journal.head
        journal.close()
        torn = b"!" * extent
        with path.open("ab") as stream:
            stream.write(torn)
        prefix = WorkflowJournal.open(
            path, expected_owner=owner, expected_schema=schema, verified_prefix_head=checkpoint
        )
        try:

            def approve(evidence, archive, *, checkpoint=checkpoint, extent=extent, torn=torn):
                assert evidence["head"] == checkpoint and evidence["tail_size"] == extent
                assert archive.read_bytes() == torn
                return True

            measured = prefix.metrics
            measured.clear()
            prefix.repair_tail(writer_lease=meter.writer_lease(path), reconcile=approve)
            assert measured["bytes_written"] == extent
            fixed = (measured["bytes_read"] - extent, measured["bytes_hashed"] - extent)
            assert all(0 < value < 1024 for value in fixed)
            if overhead is None:
                overhead = fixed
            assert fixed == overhead
        finally:
            prefix.close()


def test_successor_gate_and_phase_proof_use_installed_publisher_reader(journal_run, monkeypatch):
    from types import SimpleNamespace

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from fishhat_contracts.handoffs import PHASES
    from fishhat_contracts.validation import canonical
    from fishhat_contracts.workflow_journal import WorkflowGate, _reservation
    from fishhat_contracts.workflow_journal_recovery import JournalRecovery, RecoveryContext

    from tests.test_workflow_continuations import adoption_stage
    from tests.test_workflow_inputs import material_handle
    from tests.test_workflow_recovery import scenario
    from tests.test_workflow_recovery_compatibility import editorial_change, installed_readers
    from tests.workflow_journal_support import NOW

    original, adoption = adoption_stage()
    issued = original["bindings"][0]["request"]["predecessors"][0]
    published = adoption["predecessors"][0]
    proposal, _ = scenario(
        original=original,
        historical=True,
        kinds=["completed", "completed", "unaccepted"],
        outcomes={op["request_id"]: op for op in (issued, published)},
    )
    successor = proposal["successor"]
    retained, qualified = installed_readers(proposal)
    editorial_change(monkeypatch)
    schema = published["result_handle"]["schema"]
    missing = qualified.copy()
    del missing[(schema["uri"], schema["digest"])]
    old = journal_run.gate.target
    certificate = old._sign(
        {
            "type": "recovery-certificate",
            "header_digest": old.header_digest,
            "command_digest": digest([]),
            "recovery": {
                "id": uid("historical-recovery"),
                "origin_workflow_id": old.workflow_id,
                "origin_proposal_digest": old.header["proposal_digest"],
                "successor_workflow_id": successor["workflow_id"],
                "successor_proposal_digest": digest(successor),
                "successor_driver": successor["initial_driver"]["principal"],
                "mapping_digest": digest(proposal["children"]),
            },
            "owner_count": len({canonical(p["owner"]) for p in successor["participants"]}),
            "disposition_closure_digest": digest([]),
            "supersedes": None,
        },
        uid("historical-certificate"),
    )
    context = RecoveryContext(old.owner, old.key_id, old.private_key.public_key(), certificate)
    publisher_key = Ed25519PrivateKey.from_private_bytes(b"\x17" * 32).public_key()
    keys = {(canonical(published["owner"]), published["witness"]["key_id"]): publisher_key}
    journal = journal_run.store(journal_run.root / "historical.journal", old.owner, restore=False)

    def initialize(readers):
        return WorkflowGate(
            successor,
            owner=old.owner,
            key_id=old.key_id,
            private_key=old.private_key,
            member_keys=keys,
            authorize=old.authorize,
            check_reservation=old.check_reservation,
            journal=journal,
            principal=DRIVER,
            extension=JournalRecovery(retained_readers=retained, recovery_readers=readers),
            recovery_context=context,
        )

    try:
        with pytest.raises(ContractError, match="action result schema substitution"):
            initialize(missing)
        gate = initialize(qualified)
        issuer = successor["participants"][1]
        binding = issuer["requests"][0]
        assert binding["completed"]["operation"] == published
        phases = PHASES[gate.header["procedure"]]
        round_id = uid("historical-phase")
        barrier = {"round_id": round_id, "to_phase": phases[phases.index(binding["phase"]) + 1]}
        expires = "2026-11-02T00:00:00Z"
        child = {"owner": issuer["owner"], "request_id": binding["request_id"]}
        reservation = {
            "id": uid("historical-reservation"),
            "round_id": round_id,
            "owner": issuer["owner"],
            "generation": 1,
            "protection": "durable-until-verified-release",
            "issued_at": NOW,
            "expires_at": expires,
            "participants": [
                {
                    "owner": issuer["owner"],
                    "resource": issuer["resource"],
                    "resource_generation": issuer["expected_generation"],
                    "operations": [{"child": child, "operation": published}],
                    "native_evidence": [material_handle(issuer["owner"], digest([]))],
                    "expires_at": expires,
                }
            ],
        }

        def check_proof(readers):
            _reservation(
                reservation,
                owner=issuer["owner"],
                round=barrier,
                participants=[issuer],
                children=gate.children,
                ready=gate.ready,
                outcomes=None,
                header=gate.header,
                keys=keys,
                now=NOW,
                recovery_readers=readers,
            )

        check_proof(qualified)
        with pytest.raises(ContractError, match="action result schema substitution"):
            check_proof(missing)

        receipt = canonical(adoption["materials"][0]["publication_receipt"])
        native = SimpleNamespace(result_payload=lambda operation: receipt)
        member = SimpleNamespace(
            children=gate.children,
            ready=gate.ready,
            keys=keys,
            outcomes={},
            native=native,
            workflow_id=gate.workflow_id,
        )
        fact = {
            "origin": child,
            "kind": "completed",
            "operation": published,
            "operation_reference": proposal["children"][1]["operation"]["reference"],
            "recovery": None,
            "native_stopped": True,
        }
        gate.extension._fact(
            member, {"origin_owner": issuer["owner"]}, fact, issuer, binding, native=True
        )
        native.result_payload = lambda operation: b"{}"
        with pytest.raises(ContractError, match="result content identity mismatch"):
            gate.extension._fact(
                member, {"origin_owner": issuer["owner"]}, fact, issuer, binding, native=True
            )
    finally:
        journal.close()
