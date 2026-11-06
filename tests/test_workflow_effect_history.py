"""Signed child progress retains confirmed facts through uncertainty and replay."""

from copy import deepcopy

import pytest
from fishhat_contracts import workflow_journal as journal_module
from fishhat_contracts.validation import ContractError, digest
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_journal import WorkflowMember

from tests.linear_support import assert_linear, measure
from tests.workflow_journal_support import LogicalWorkload, WorkflowRun, WorkMeter

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/states.json#/rules",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json",
    ],
    "scope": "signed child cumulative knowledge, refused contradictory progress and exact retained replay across restart",
    "relationship": "candidate",
    "reason": "Enrolled synthetic keys and temporary protected journals challenge contradictory no-effect progress, including valid uncertainty and restoration of conflicting historical inputs. This does not authenticate native effects or qualify cessation, fencing or production storage.",
    "claims": [],
}
CHECK_OVERRIDES = {
    "test_gate_intake_refuses_none_against_independently_retained_known_context": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#WorkflowGate._accept",
        ],
        "scope": "gate vote intake cumulative-effect consistency under fixed independent reservation context",
        "relationship": "scoped-witness",
        "reason": "The separate reservation verifier is held fixed to isolate the actual gate intake guard against signed contradictory child data. This is not a native reservation, phase-evidence or authorization proof.",
        "claims": [],
    },
    "test_complete_effect_index_replay_and_refusal_work_is_linear": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#WorkflowGate.__init__",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal.py#WorkflowMember.__init__",
        ],
        "scope": "complete cumulative index reconstruction and contradictory-lookup sequences at increasing retained extents",
        "relationship": "scoped-witness",
        "reason": "Counts executed indexing and lookup work across every retained observation and child, complementing complete workflow proofs; supplies no native or timing guarantee.",
        "claims": [
            "engineering:workflow.journal.gate-initialize",
            "engineering:workflow.journal.member-initialize",
        ],
    },
}


@pytest.fixture
def scenario(tmp_path):
    meter, workload = WorkMeter(), LogicalWorkload(owners=1, children=1)
    with meter.account():
        context = {"run": WorkflowRun(tmp_path, workload, meter)}
        try:
            run = context["run"]
            run.prepare()
            for phase in ("draining", "quiescent", "host-effect"):
                run.round(phase)
            child = workload.child(0, 0)
            run.members[0].call("admit", {"child": child}, fresh=True)
            run.submit_native(0, run.native_submission(0, 0))
            context["operation"] = run.native[0].finish(child)
            yield context
        finally:
            context["run"].close()


def observed(context, state, effect, generation):
    value = deepcopy(context["operation"])
    value.update(state=state, effect_certainty=effect, generation=generation, last_event=generation)
    witness = {k: v for k, v in value["witness"].items() if k != "signature"}
    witness.update(
        state=state,
        kind="effect",
        generation=generation,
        subject_digest=digest({k: v for k, v in value.items() if k != "witness"}),
    )
    value["witness"] = sign(witness, context["run"].native[0].key)
    return value


def restart(context):
    run = context["run"]
    root, workload, meter = run.root, run.workload, run.meter
    run.close()
    context["run"] = WorkflowRun(root, workload, meter, restore=True)


@pytest.mark.parametrize("reopen", [False, True])
@pytest.mark.parametrize(
    "destination,intermediate", [("failed", False), ("cancelled", False), ("running", True)]
)
def test_retained_known_child_cannot_become_none(scenario, destination, intermediate, reopen):
    member = scenario["run"].members[0]
    command = member.command("complete", {"operation": observed(scenario, "running", "known", 1)})
    receipt = member.submit(command)
    generation = 2
    if intermediate:
        member.call("complete", {"operation": observed(scenario, "waiting", "unknown", 2)})
        generation = 3
    if reopen:
        restart(scenario)
        member = scenario["run"].members[0]
    target = member.target
    path = target.journal._path
    before = (target.journal.head, target.generation, deepcopy(target.outcomes), path.read_bytes())
    with pytest.raises(ContractError, match="retained known effect facts"):
        member.call("complete", {"operation": observed(scenario, destination, "none", generation)})
    assert (target.journal.head, target.generation, target.outcomes, path.read_bytes()) == before
    assert member.submit(command) == receipt
    changed = deepcopy(command)
    changed["payload"]["operation"] = observed(scenario, "waiting", "unknown", generation + 1)
    with pytest.raises(ContractError, match="changed accepted input"):
        journal_module.dispatch_journal_command(
            target,
            changed,
            principal=scenario["run"].principal,
            admission_pin=scenario["run"].meter.approved_admission,
        )


@pytest.mark.parametrize("earlier_known", [False, True])
def test_uncertainty_and_noncontradictory_signed_resolution_remain_readable(
    scenario, earlier_known
):
    member = scenario["run"].members[0]
    member.call(
        "complete",
        {"operation": observed(scenario, "running", "known" if earlier_known else "unknown", 1)},
    )
    member.call("complete", {"operation": observed(scenario, "waiting", "unknown", 2)})
    restart(scenario)
    member = scenario["run"].members[0]
    assert next(iter(member.target.outcomes.values()))["effect_certainty"] == "unknown"
    # An enrolled owner supplies its independently verified summary. This fixture
    # establishes no native proof of absence or cessation.
    effect = "known" if earlier_known else "none"
    value = observed(scenario, "running", effect, 3)
    member.call("complete", {"operation": value})
    restart(scenario)
    assert next(iter(scenario["run"].members[0].target.outcomes.values())) == value


def test_conflicting_signed_history_refuses_reconstruction_without_rewriting_custody(
    scenario, monkeypatch
):
    run = scenario["run"]
    member = run.members[0]
    # Construct an earlier-writer history through the normal signed/committed
    # journal rail; restore the current guard before attempting reconstruction.
    with monkeypatch.context() as previous_writer:
        previous_writer.setattr(journal_module, "_known_outcome", lambda *args, **kwargs: None)
        for generation, (state, effect) in enumerate(
            [("running", "known"), ("waiting", "unknown"), ("running", "none")], start=1
        ):
            member.call("complete", {"operation": observed(scenario, state, effect, generation)})
    original = member.target
    path = original.journal._path
    owner, schema = original.journal.owner, original.journal.schema
    before = (path.read_bytes(), path.with_name(path.name + ".head").read_bytes())
    genesis = next(original.journal.iter_events(read_authorized=True))["request"]
    member.close()
    store = run.meter.store(path, owner, schema, restore=True)
    try:
        with pytest.raises(ContractError, match="retained known effect facts"):
            WorkflowMember(
                original.signed_projection,
                owner=original.owner,
                key_id=original.key_id,
                private_key=original.private_key,
                enrollment=original.enrollment,
                operation_keys=original.keys,
                native=run.native[0],
                journal=store,
                principal=run.principal,
                clock=original.clock,
                extension=original.extension,
                command=genesis,
            )
    finally:
        store.close()
    assert (path.read_bytes(), path.with_name(path.name + ".head").read_bytes()) == before


def test_complete_effect_index_replay_and_refusal_work_is_linear():
    samples = []
    for extent in (16, 64, 256):
        events = []
        for index in range(extent):
            identity = f"child-{index:08d}"
            common = {
                "id": identity,
                "owner": "owner",
                "request_id": identity,
                "plan_id": identity,
                "plan_digest": identity,
                "subject": {},
                "authenticated_principal": "operator",
                "claimed_actor": None,
                "created_at": "2026-11-01T00:00:00Z",
                "witness": {"workflow_id": "workflow"},
            }
            for generation, (state, effect) in enumerate(
                [("running", "known"), ("waiting", "unknown")], start=1
            ):
                events.append(
                    (
                        identity.encode(),
                        {
                            **common,
                            "generation": generation,
                            "last_event": generation,
                            "state": state,
                            "effect_certainty": effect,
                        },
                    )
                )

        def complete(events=events):
            # The same complete event stream rebuilds the gate/member index.
            for _ in range(2):
                latest, known = {}, set()
                for key, value in events:
                    journal_module._remember_outcome(latest, known, key, value)
                for key, previous in latest.items():
                    proposed = {
                        **previous,
                        "generation": 3,
                        "last_event": 3,
                        "state": "running",
                        "effect_certainty": "none",
                    }
                    with pytest.raises(ContractError, match="retained known effect facts"):
                        journal_module._known_outcome(
                            previous, proposed, known_effects=key in known
                        )
                assert len(latest) == len(known) == len(events) // 2

        _, work = measure(complete)
        samples.append((extent, work))
    assert_linear(samples)


@pytest.mark.parametrize("previous_effect", ["known", "unknown"])
def test_gate_intake_refuses_none_against_independently_retained_known_context(
    scenario, monkeypatch, previous_effect
):
    run = scenario["run"]
    member, gate = run.members[0], run.gate
    member.call("complete", {"operation": scenario["operation"]})
    round_record = gate.call("round", {"to_phase": "reconciling"}, fresh=True)
    vote = member.call("vote", {"round": round_record}, fresh=True)
    operation = observed(scenario, "running", "none", 3)
    key = journal_module._key({"owner": operation["owner"], "request_id": operation["request_id"]})
    gate.target._known_outcomes[key] = observed(scenario, "running", previous_effect, 2)
    gate.target._known_effects.add(key)
    # Reservation/native truth has its independent checks. Hold that context
    # fixed here so the oracle specifically detects a missing gate history guard.
    monkeypatch.setattr(journal_module, "_reservation", lambda *args, **kwargs: None)
    monkeypatch.setattr(gate.target, "check_reservation", lambda *args: None)
    body = deepcopy(vote["body"])
    body["reservation"]["participants"][0]["operations"][0]["operation"] = operation
    changed = member.target._sign(body, vote["id"])
    before = (
        gate.target.journal.head,
        gate.target.generation,
        deepcopy(gate.target._known_outcomes),
    )
    with pytest.raises(ContractError, match="retained known effect facts"):
        gate.call("vote", {"vote": changed})
    assert (gate.target.journal.head, gate.target.generation, gate.target._known_outcomes) == before
