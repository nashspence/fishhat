"""Whole-run aggregate bounds, including transport, cryptography and durable custody."""

import json

import pytest

from tests.workflow_journal_support import LogicalWorkload, execute_workflow

CHECK_PURPOSE = {
    "purpose": "implementation",
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
        "release.toml#/engineering",
    ],
    "scope": "complete aggregate work from empty custody through preparation, all installed phases, "
    "child native acceptance and outcomes, transfer, cold restore and preserved successor "
    "recovery",
    "relationship": "scoped-witness",
    "reason": "Independent owner, child and real material byte axes span sixteenfold. Logical B, N "
    "and E are fixed before execution. Every actual bounded frame, signature input, "
    "canonical/hash byte, journal and artifact read/write, native protected index visit and "
    "retained physical byte is counted across all owners. Setup is included. Line counts cover workflow/native reference algorithms; all schema validation calls and complete validation input bytes are separately measured and compose with installed validator linear proofs. Normal pytest CPU statistics cover the whole run. Synthetic "
    "protected native facts exercise reference behavior without qualifying a production "
    "runtime.",
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

CHECK_OVERRIDES = {
    "test_aggregate_oracle_detects_replicated_manifest_and_all_owner_proof_fanout": {
        **CHECK_PURPOSE,
        "purpose": "validation-tooling",
        "relationship": "no-product-claim",
        "authority": [
            "tests/test_workflow_journal_growth.py#assert_aggregate_linear",
            "release.toml#/engineering",
        ],
        "scope": "sensitivity of the complete aggregate oracle to actual injected quadratic wire and custody work",
        "reason": "The complete valid workload still succeeds; adding measured full-proposal copies or all-owner proof delivery must violate the same per-metric linear envelope. No injected metric count replaces actual frame construction or storage.",
        "claims": [],
    }
}


def assert_aggregate_linear(samples):
    """Every observed cost needs a constant envelope; no byte class can hide another."""
    assert len(samples) == 3 and samples[-1][0] >= 16 * samples[0][0]
    initial_scale, initial = samples[0]
    for scale, result in samples[1:]:
        # B, N and E are logical pre-execution inputs, never generated replicas.
        assert result["extent"]["logical_bytes"] > 0
        assert result["extent"]["owners"] > 0
        assert result["extent"]["semantic_edges"] > 0
        for metric in initial["metrics"].keys() | result["metrics"].keys():
            observed = result["metrics"].get(metric, 0)
            baseline = initial["metrics"].get(metric, 0)
            if metric == "native_bind_visits":
                # The first reviewed Plan needs no continuation binding. Check
                # this count exactly against logical causal edges, including
                # zero, rather than deriving a slope from an inactive branch.
                assert baseline == initial["extent"]["continuation_edges"]
                assert observed == result["extent"]["continuation_edges"]
                continue
            assert observed * initial_scale <= 1.25 * baseline * scale, (
                metric,
                [(n, item["metrics"].get(metric, 0), item["extent"]) for n, item in samples],
            )


@pytest.mark.parametrize("axis", ["owners", "children", "evidence-bytes"])
def test_complete_multi_owner_workflow_is_linear(tmp_path, axis):
    samples = []
    scales = (
        (2, 8, 32)
        if axis == "owners"
        else ((1, 4, 16) if axis == "children" else (131072, 524288, 2097152))
    )
    for scale in scales:
        workload = LogicalWorkload(
            owners=scale if axis == "owners" else 2,
            children=scale if axis == "children" else 2,
            evidence_bytes=scale if axis == "evidence-bytes" else 128,
        )
        denominator = workload.extent()
        result = execute_workflow(tmp_path / str(scale), workload)
        assert result["extent"] == denominator
        assert result["metrics"].get("native_bind_visits", 0) == denominator["continuation_edges"]
        assert result["completed_owners"] == workload.owners
        assert result["completed_children"] == workload.owners * workload.children
        assert result["metrics"]["completed_nonexecutions"] == workload.owners * workload.children
        assert (
            result["metrics"]["completed_transfers"]
            == result["metrics"]["completed_recoveries"]
            == 1
        )
        for metric in (
            "wire_bytes",
            "bytes_written",
            "bytes_read",
            "artifact_bytes_read",
            "artifact_bytes_written",
            "retained_bytes",
            "canonical_bytes",
            "hash_bytes",
            "signature_created_bytes",
            "signature_verified_bytes",
            "protected_index_visits",
            "validation_calls",
            "validation_input_bytes",
            "native_scope_visits",
            "reference_python_steps",
        ):
            assert result["metrics"][metric] > 0
        samples.append((scale, result))
    (tmp_path / "aggregate-work.json").write_text(json.dumps(samples, indent=2) + "\n")
    assert_aggregate_linear(samples)


@pytest.mark.parametrize("regression", ["replicated-proposal", "all-owner-votes"])
def test_aggregate_oracle_detects_replicated_manifest_and_all_owner_proof_fanout(
    tmp_path, regression
):
    samples = []
    for owners in (2, 8, 32):
        workload = LogicalWorkload(owners=owners, children=2, evidence_bytes=128)
        result = execute_workflow(tmp_path / str(owners), workload, regression=regression)
        assert result["completed_children"] == owners * 2
        samples.append((owners, result))
    (tmp_path / "aggregate-work.json").write_text(json.dumps(samples, indent=2) + "\n")
    with pytest.raises(AssertionError):
        assert_aggregate_linear(samples)
    metric = (
        "manifest_wire_bytes"
        if regression == "replicated-proposal"
        else "phase-evidence_wire_bytes"
    )
    with pytest.raises(AssertionError):
        assert_aggregate_linear(
            [
                (scale, {**result, "metrics": {metric: result["metrics"][metric]}})
                for scale, result in samples
            ]
        )
