"""Partitioned workflow custody, exact replay and independently protected native gates."""

from copy import deepcopy

import pytest
from fishhat_contracts.validation import ContractError, digest
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
    }
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
    "damage", ["missing", "empty", "partial-frame", "whole-frame", "changed-byte"]
)
def test_missing_or_corrupt_accepted_journal_never_becomes_empty_custody(tmp_path, damage):
    path = tmp_path / "accepted.journal"
    owner, schema, meter = LogicalWorkload().owner(0), store_identity(), WorkMeter()
    journal = WorkflowJournal.create(path, owner=owner, schema=schema, metrics=meter.values)
    prior_size = path.stat().st_size
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
    elif damage == "whole-frame":
        path.write_bytes(original[:prior_size])
    else:
        changed = bytearray(original)
        changed[-1] ^= 1
        path.write_bytes(changed)
    with pytest.raises((ContractError, OSError)):
        WorkflowJournal.open(path, expected_owner=owner, expected_schema=schema)


def test_journal_replay_preserves_original_bytes_and_requires_current_read_permission(tmp_path):
    path = tmp_path / "accepted.journal"
    owner, schema = LogicalWorkload().owner(0), store_identity()
    journal = WorkflowJournal.create(path, owner=owner, schema=schema)
    first = journal.append(
        "first", {"request": "one"}, {"outcome": "one"}, expected_head=journal.head
    )
    old_head = journal.head
    journal.append("later", {"request": "two"}, {"outcome": "two"}, expected_head=old_head)
    journal.close()
    restored = WorkflowJournal.open(path, expected_owner=owner, expected_schema=schema)
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
        WorkflowJournal.open(path, expected_owner=changed, expected_schema=schema)


def test_journal_requires_one_writer_and_explicit_new_custody(tmp_path):
    path = tmp_path / "accepted.journal"
    owner, schema = LogicalWorkload().owner(0), store_identity()
    journal = WorkflowJournal.create(path, owner=owner, schema=schema)
    try:
        with pytest.raises((ContractError, OSError)):
            WorkflowJournal.create(path, owner=owner, schema=schema)
        with pytest.raises((ContractError, OSError)):
            WorkflowJournal.open(path, expected_owner=owner, expected_schema=schema)
    finally:
        journal.close()


@pytest.mark.parametrize("failure", ["fsync", "head-replace"])
def test_failed_append_preserves_tail_and_old_custody_without_reopening_writer(
    tmp_path, monkeypatch, failure
):
    from fishhat_owner import workflow_journal as store_module

    path = tmp_path / "accepted.journal"
    owner, schema = LogicalWorkload().owner(0), store_identity()
    journal = WorkflowJournal.create(path, owner=owner, schema=schema)
    original = journal.append(
        "original", {"request": "accepted"}, {"outcome": "retained"}, expected_head=journal.head
    )
    accepted_bytes = path.read_bytes()

    def fail(*args):
        raise OSError("injected durable publication failure")

    try:
        with monkeypatch.context() as fault:
            fault.setattr(store_module.os, "fsync" if failure == "fsync" else "replace", fail)
            with pytest.raises(OSError, match="durable publication failure"):
                journal.append(
                    "uncertain",
                    {"request": "new"},
                    {"outcome": "not acknowledged"},
                    expected_head=journal.head,
                )
        tail = path.read_bytes()
        assert tail.startswith(accepted_bytes) and len(tail) > len(accepted_bytes)
        assert journal.lookup("original", read_authorized=True) == original
        assert journal.lookup("uncertain", read_authorized=True) is None
        with pytest.raises(ContractError, match="writer unavailable"):
            journal.append("later", {}, {}, expected_head=journal.head)
    finally:
        journal.close()
    with pytest.raises(ContractError):
        WorkflowJournal.open(path, expected_owner=owner, expected_schema=schema)
    assert path.read_bytes() == tail
