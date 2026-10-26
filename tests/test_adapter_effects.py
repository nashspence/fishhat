from __future__ import annotations

import copy
import json

import pytest
from fishhat_contracts.validation import ContractError, digest
from fishhat_owner.adapter_state import AdapterCoordinator

from tests.adapter_support import (
    OWNER,
    binding,
    fresh_observation,
    identifier,
    native_exclusion,
    request,
    runtime_registry,
    runtime_sources,
)

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": ["fishhat/owner-support/src/fishhat_owner/adapter_state.py"],
    "scope": "owner reference commit/dispatch and restoration ordering only",
    "relationship": "candidate",
    "reason": "Injected commit boundary is not a native supervisor or durable production journal.",
    "claims": [],
}


def coordinator(commit=None):
    registry, _, _ = runtime_registry()
    commits = []
    c = AdapterCoordinator(
        OWNER,
        registry,
        commit or (lambda value: commits.append(copy.deepcopy(value))),
        native_exclusion=native_exclusion,
    )
    c.bind(binding(), **runtime_sources(registry), owner_approved=True)
    c.prove_quiescent("demo", fresh_observation(c), owner_approved=True)
    c.open_admission("demo", owner_approved=True)
    return c, commits


def prepare(c, number=10):
    return c.prepare(
        "demo",
        request(),
        **runtime_sources(c.registry),
        operation_id=identifier(8),
        effect_id=identifier(9),
        attempt_id=identifier(number),
        owner_approved=True,
    )


def result(owner, attempt, **overrides):
    query = copy.deepcopy(owner.snapshot()["requests"][attempt["attempt_id"]])
    effect = {
        "attempt_id": attempt["attempt_id"],
        "input_digest": attempt["input_digest"],
        "acknowledgment": "accepted",
        "task_state": "terminal",
        "effect_certainty": "known",
        "postcondition": "satisfied",
        "native_task": None,
        **overrides,
    }
    output = (
        {"deployment": query["input"]["deployment"], "observation": None, "objects": []}
        if query["contract"] == "fishhat.runtime"
        else {
            "services": [
                {
                    "target": copy.deepcopy(query["input"]["target"]),
                    "enabled": query["input"]["intent"]["enabled"],
                    "activity": query["input"]["intent"]["activity"],
                }
            ],
            "transition": None,
        }
    )
    return query, {
        "contract": query["contract"],
        "method": query["method"],
        "request_digest": digest(query),
        "scope": query["input"]["scope"],
        "coverage": "complete",
        "continuation": None,
        "proposal": None,
        "effect": effect,
        "output": output,
    }


def test_dispatch_commits_unknown_before_releasing_native_attempt():
    c, commits = coordinator()
    attempt = prepare(c)
    returned = c.dispatch("demo", attempt["attempt_id"])
    assert commits[-1]["attempts"][attempt["attempt_id"]] == returned["attempt"]
    assert returned["attempt"]["certainty"] == "unknown"
    with pytest.raises(ContractError, match="RECONCILE_REQUIRED"):
        c.dispatch("demo", attempt["attempt_id"])


def test_failed_commit_makes_owner_stop_dispatching():
    c, _ = coordinator()
    attempt = prepare(c)

    def fail(_):
        raise OSError("synthetic disk failure")

    c.commit = fail
    with pytest.raises(OSError):
        c.dispatch("demo", attempt["attempt_id"])
    with pytest.raises(ContractError, match="OWNER_COMMIT_UNCERTAIN"):
        c.dispatch("demo", attempt["attempt_id"])


def test_close_racing_dispatched_start_is_not_quiescence():
    c, _ = coordinator()
    attempt = prepare(c)
    c.dispatch("demo", attempt["attempt_id"])
    c.close_admission("demo")
    with pytest.raises(ContractError, match="PENDING_NATIVE_WORK"):
        c.observation_request("demo", owner_approved=True)
    c.settle(attempt["attempt_id"], *result(c, attempt))
    # Only a separate complete native cessation observation can now establish quiescence.
    c.prove_quiescent("demo", fresh_observation(c), owner_approved=True)
    assert c.snapshot()["quiescent"]["demo"] is True


def test_unknown_result_cannot_succeed_or_be_blindly_retried():
    c, _ = coordinator()
    attempt = prepare(c)
    c.dispatch("demo", attempt["attempt_id"])
    with pytest.raises(ContractError, match="UNKNOWN_EFFECT_CANNOT_SUCCEED"):
        c.settle(attempt["attempt_id"], *result(c, attempt, effect_certainty="unknown"))
    c.settle(
        attempt["attempt_id"],
        *result(
            c, attempt, effect_certainty="unknown", postcondition="unknown", task_state="unknown"
        ),
    )
    assert c.snapshot()["attempts"][attempt["attempt_id"]]["state"] == "reconciling"
    with pytest.raises(ContractError, match="UNCERTAIN_EFFECT_RETRY"):
        prepare(c, 11)


def test_attempt_identity_replay_preserves_actual_status():
    c, _ = coordinator()
    attempt = prepare(c)
    c.dispatch("demo", attempt["attempt_id"])
    assert prepare(c)["state"] == "dispatched"
    changed = request()
    changed["input"]["deployment"]["handle"] = "other"
    with pytest.raises(ContractError, match="ATTEMPT_IDENTITY_CONFLICT"):
        c.prepare(
            "demo",
            changed,
            **runtime_sources(c.registry),
            operation_id=identifier(8),
            effect_id=identifier(9),
            attempt_id=identifier(10),
            owner_approved=True,
        )


def test_wrong_result_identity_is_rejected():
    c, _ = coordinator()
    attempt = prepare(c)
    c.dispatch("demo", attempt["attempt_id"])
    with pytest.raises(ContractError, match="RESULT_IDENTITY"):
        c.settle(attempt["attempt_id"], *result(c, attempt, attempt_id=identifier(77)))


@pytest.mark.parametrize(
    "field,value",
    [
        ("coverage", "incomplete"),
        ("continuation", "page:next"),
        ("activity", "unknown"),
        ("native_incarnation", identifier(33)),
    ],
    ids=["incomplete", "continuation", "unknown-activity", "stale-incarnation"],
)
def test_incomplete_or_stale_observation_never_proves_cessation(field, value):
    c, _ = coordinator()
    c.close_admission("demo")
    value = {**fresh_observation(c), field: value}
    with pytest.raises(ContractError):
        c.prove_quiescent("demo", value, owner_approved=True)


def test_retained_state_preserves_uncertainty_and_restores_under_hold(tmp_path):
    state = tmp_path / "owner-record.json"
    c, _ = coordinator(lambda value: state.write_text(json.dumps(value)))
    attempt = prepare(c)
    c.dispatch("demo", attempt["attempt_id"])
    registry, _, _ = runtime_registry()
    recovered = AdapterCoordinator(OWNER, registry, lambda value: None)
    recovered.restore(json.loads(state.read_text()))
    assert recovered.snapshot()["admission"]["demo"] is False
    assert recovered.snapshot()["attempts"][attempt["attempt_id"]]["certainty"] == "unknown"
    with pytest.raises(ContractError, match="ADMISSION_CLOSED"):
        recovered.dispatch("demo", attempt["attempt_id"])


def test_host_local_effect_records_reject_other_owner_epoch():
    c, _ = coordinator()
    value = c.snapshot()
    value["owner"]["epoch"] = identifier(66)
    with pytest.raises(ContractError, match="RESTORE_OWNER_IDENTITY"):
        c.restore(value)


def test_closing_admission_does_not_disable_containment_effects():
    c, _ = coordinator()
    c.close_admission("demo")
    attempt = c.prepare(
        "demo",
        request("deactivate"),
        **runtime_sources(c.registry),
        operation_id=identifier(80),
        effect_id=identifier(81),
        attempt_id=identifier(82),
        owner_approved=True,
    )
    assert c.dispatch("demo", attempt["attempt_id"])["attempt"]["state"] == "dispatched"


def test_prepared_start_can_be_cancelled_but_dispatched_start_cannot():
    c, _ = coordinator()
    attempt = prepare(c)
    c.close_admission("demo")
    c.cancel_prepared(attempt["attempt_id"], owner_approved=True)
    assert c.snapshot()["attempts"][attempt["attempt_id"]]["certainty"] == "none"
    c.prove_quiescent("demo", fresh_observation(c), owner_approved=True)
    c.open_admission("demo", owner_approved=True)
    next_attempt = c.prepare(
        "demo",
        request(),
        **runtime_sources(c.registry),
        operation_id=identifier(30),
        effect_id=identifier(31),
        attempt_id=identifier(32),
        owner_approved=True,
    )
    c.dispatch("demo", next_attempt["attempt_id"])
    with pytest.raises(ContractError, match="CANNOT_CANCEL_DISPATCHED_EFFECT"):
        c.cancel_prepared(next_attempt["attempt_id"], owner_approved=True)


def test_resolved_effect_is_not_permission_to_repeat_the_native_mutation():
    c, _ = coordinator()
    attempt = prepare(c)
    c.dispatch("demo", attempt["attempt_id"])
    c.settle(attempt["attempt_id"], *result(c, attempt))
    with pytest.raises(ContractError, match="EFFECT_RETRY_REQUIRES_NEW_PLAN"):
        prepare(c, 11)


def test_observation_from_previous_admission_generation_cannot_release_hold():
    c, _ = coordinator()
    c.close_admission("demo")
    old = fresh_observation(c)
    old["admission_generation"] = 0
    with pytest.raises(ContractError, match="OBSERVATION_IDENTITY"):
        c.prove_quiescent("demo", old, owner_approved=True)


@pytest.mark.parametrize(
    "field,value", [("handle", "other"), ("kind", "dataset")], ids=["subject-handle", "scope-kind"]
)
def test_restore_rejects_binding_with_wrong_subject_scope(field, value):
    c, _ = coordinator()
    snapshot = c.snapshot()
    snapshot["bindings"]["demo"]["scope"][field] = value
    with pytest.raises(ContractError, match="RESTORE_BINDING_IDENTITY"):
        c.restore(snapshot)
