"""Unused permits can advance protection without turning accepted work into a retry."""

import json
from copy import deepcopy

import pytest
from fishhat_contracts.validation import ContractError, digest

from tests.linear_support import assert_linear
from tests.workflow_journal_support import (
    DRIVER,
    LogicalWorkload,
    WorkflowRun,
    WorkMeter,
    child_key,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#WorkflowMember._accept",
    ],
    "scope": "append-only unused admission renewal across current barrier refresh and complete driver transfer, exact predecessor and native request-index exclusion",
    "relationship": "candidate",
    "reason": "Real journal persistence and independently retained synthetic native acceptance challenge renewal safety and liveness; these checks do not qualify a production native fence.",
    "claims": [],
}


CHECK_OVERRIDES = {
    "test_unused_permit_renewal_history_is_linear": {
        **CHECK_PURPOSE,
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#dispatch_journal_command",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#NativeWorkflowContext.renew_admission",
            "release.toml#/engineering",
        ],
        "scope": "complete repeated permit-renewal histories, original-result reads, staged lost-reply replay and final native acceptance",
        "relationship": "scoped-witness",
        "reason": "All actual wire, serialization, signature, durable journal and native index work is measured across sixteenfold retained-history and background local-child growth. Setup is outside this selected operation; the complete workflow keeps its separate aggregate proof. Synthetic native facts do not qualify a production fence.",
        "claims": ["engineering:workflow.journal.submit"],
    }
}


def permit(run):
    run.prepare()
    for phase in ("draining", "quiescent", "host-effect"):
        run.round(phase)
    return run.members[0].call("admit", {"child": run.workload.child(0, 0)}, fresh=True)


def renewal(run, previous):
    return run.members[0].command(
        "admit.renew",
        {
            "child": run.workload.child(0, 0),
            "previous_permit_id": previous["id"],
            "previous_permit_digest": digest(previous),
        },
        fresh=True,
    )


@pytest.mark.parametrize("control", ["refresh", "transfer"], ids=["refresh", "transfer"])
def test_unused_permit_renews_after_refresh_or_completed_transfer(tmp_path, control):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(children=1), meter)
        try:
            original = permit(run)
            if control == "transfer":
                run.transfer()
            run.round("host-effect")
            with pytest.raises(ContractError, match=r"reservation|stale|nonexecutable"):
                run.submit_native(0, run.native_submission(0, 0))
            command = renewal(run, original)
            replacement = run.members[0].submit(command, principal=run.principal, lost_reply=True)
            assert replacement["body"]["renewal"]["previous_permit_id"] == original["id"]
            assert replacement["body"]["renewal"]["previous_permit_digest"] == digest(original)
            assert replacement["body"]["renewal"]["unaccepted"] is True
            assert replacement["body"]["round_id"] != original["body"]["round_id"]
            assert meter.values["native_renewal_index_visits"] == 1
            assert run.members[0].read(original["id"], principal=run.principal) == original
            accepted = run.submit_native(0, run.native_submission(0, 0))
            assert accepted["authenticated_principal"] == run.principal
            assert len(run.native[0].admissions) == 1
            assert run.submit_native(0, run.native_submission(0, 0)) == accepted
            assert run.members[0].submit(command, principal=run.principal) == replacement
            assert meter.values["native_renewal_index_visits"] == 1
        finally:
            run.close()


@pytest.mark.parametrize("reported", [False, True], ids=["unreported", "reported"])
def test_renewal_never_reexecutes_an_accepted_native_operation(tmp_path, reported):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(children=1), meter)
        try:
            original = permit(run)
            submission = run.native_submission(0, 0)
            accepted = run.submit_native(0, submission)
            if reported:
                run.members[0].call("complete", {"operation": accepted})
            run.round("host-effect")
            with pytest.raises(ContractError, match=r"accepted|unaccepted proof"):
                run.members[0].submit(renewal(run, original))
            assert run.submit_native(0, submission) == accepted
            assert len(run.native[0].admissions) == 1
            assert not run.native[0].retired_permits
        finally:
            run.close()


def test_renewal_cas_rejects_substitution_and_preserves_lost_reply(tmp_path):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(children=1), meter)
        try:
            original = permit(run)
            run.round("host-effect")
            bad = renewal(run, original)
            bad["payload"]["previous_permit_digest"] = "sha256:" + "0" * 64
            with pytest.raises(ContractError, match="predecessor permit"):
                run.members[0].submit(bad)
            command = renewal(run, original)
            accepted = run.members[0].submit(command)
            before = meter.values["native_renewal_index_visits"]
            stale = renewal(run, original)
            with pytest.raises(ContractError, match="predecessor permit"):
                run.members[0].submit(stale)
            assert meter.values["native_renewal_index_visits"] == before
            assert run.members[0].submit(command) == accepted
            changed = deepcopy(command)
            changed["payload"]["driver_term"] += 1
            with pytest.raises(ContractError, match=r"changed accepted|staged retry"):
                run.members[0].submit(changed)
            key = child_key(run.workload.child(0, 0))
            assert run.members[0].target._admissions[key] == accepted
            assert original["id"] in run.native[0].retired_permits
        finally:
            run.close()


def test_renewal_failed_journal_write_keeps_native_predecessor_closed(tmp_path, monkeypatch):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(children=1), meter)
        try:
            original = permit(run)
            command = renewal(run, original)
            target = run.members[0].target
            append = target.journal.append

            def fail(*args, **kwargs):
                raise OSError("synthetic journal failure")

            monkeypatch.setattr(target.journal, "append", fail)
            with pytest.raises(OSError, match="journal failure"):
                target._run(command, DRIVER)
            assert original["id"] in run.native[0].retired_permits
            assert not run.native[0].admissions
            monkeypatch.setattr(target.journal, "append", append)
            restored = run.clone_member(0)
            with pytest.raises(ContractError, match="permanently closed"):
                run.native[0].submit_native(run.native_submission(0, 0), restored, principal=DRIVER)
            replacement = restored._run(command, DRIVER)
            assert replacement["body"]["renewal"]["previous_permit_id"] == original["id"]
            assert len(run.native[0].retired_permits) == 1
        finally:
            run.close()


def test_unused_permit_renewal_history_is_linear(tmp_path):
    samples = []
    for count in (2, 8, 32):
        meter = WorkMeter()
        with meter.account():
            run = WorkflowRun(tmp_path / str(count), LogicalWorkload(children=count), meter)
            try:
                previous = permit(run)
                original = previous
                before = meter.values.copy()
                for _ in range(count):
                    previous = run.members[0].submit(renewal(run, previous), lost_reply=True)
                submission = run.native_submission(0, 0)
                accepted = run.submit_native(0, submission)
                assert run.submit_native(0, submission) == accepted
                assert len(run.native[0].admissions) == 1
                assert len(run.native[0].retired_permits) == count
                assert run.members[0].read(original["id"]) == original
                assert run.members[0].read(previous["id"]) == previous
                work = meter.values - before
                assert work["native_renewal_index_visits"] == count
                assert work["lost_reply_replays"] == count
                assert work["bytes_written"] > 0 and work["wire_bytes"] > 0
                samples.append((count, work))
            finally:
                run.close()
    (tmp_path / "renewal-work.json").write_text(json.dumps(samples, indent=2) + "\n")
    assert_linear(samples)
