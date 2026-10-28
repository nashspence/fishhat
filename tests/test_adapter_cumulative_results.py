"""Original-attempt evidence survives weaker observations, conflicts and restore."""

from __future__ import annotations

import copy
from itertools import permutations

import pytest
from fishhat_contracts.adapter_semantics import accumulate_result
from fishhat_contracts.validation import ContractError, digest

from tests.linear_support import assert_linear, measure
from tests.test_adapter_effects import coordinator, prepare, result

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
    ],
    "scope": "cumulative original-invocation facts, coherent terminal evidence, accepted replay and order-independent restored history",
    "relationship": "candidate",
    "reason": "Synthetic exact receipts exercise shared evidence semantics and the reference owner's pending-work gate, without asserting native cessation or durable production recovery.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_cumulative_result_history_linear_work": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_semantics.py#accumulate_result",
            "release.toml#/engineering",
        ],
        "scope": "measured cumulative evidence joins across complete retained histories, including repeated and unknown observations",
        "relationship": "scoped-witness",
        "reason": "Increasing exact response counts measure the maintained cumulative join independently of native adapter execution.",
        "claims": ["engineering:adapters.accumulate_result"],
    },
}


def running(acknowledgment="accepted"):
    owner, commits = coordinator()
    attempt = prepare(owner)
    owner.dispatch("demo", attempt["attempt_id"])
    first = result(
        owner,
        attempt,
        acknowledgment=acknowledgment,
        task_state="running",
        native_task="task:one",
        postcondition="unknown",
    )
    owner.settle(attempt["attempt_id"], *first)
    return owner, commits, attempt, first


def reconciliation(owner, attempt, **changes):
    snapshot = owner.snapshot()
    invocation = {
        "attempt": snapshot["attempts"][attempt["attempt_id"]],
        "request": snapshot["requests"][attempt["attempt_id"]],
    }
    query = {
        "contract": invocation["request"]["contract"],
        "method": "reconcile",
        "input": {"scope": invocation["attempt"]["scope"], "invocation": invocation},
    }
    _, response = result(owner, attempt, **changes)
    response.update(method="reconcile", request_digest=digest(query))
    return query, response


def assert_pending(owner):
    with pytest.raises(ContractError, match="PENDING_NATIVE_WORK"):
        owner.observation_request("demo", owner_approved=True)


@pytest.mark.parametrize(
    "acknowledgment,changes,code",
    [
        (
            "accepted",
            {
                "acknowledgment": "rejected",
                "effect_certainty": "none",
                "postcondition": "not-satisfied",
            },
            "RESULT_ACKNOWLEDGMENT_CONFLICT",
        ),
        (
            "unknown",
            {
                "acknowledgment": "rejected",
                "effect_certainty": "none",
                "postcondition": "not-satisfied",
            },
            "RESULT_RUNNING_REJECTION",
        ),
        ("accepted", {"native_task": None}, "RESULT_TASK_CESSATION_IDENTITY"),
        ("accepted", {"native_task": "task:other"}, "RESULT_NATIVE_TASK_CONFLICT"),
    ],
    ids=["accepted-cannot-be-rejected", "running-cannot-be-rejected", "missing-task", "other-task"],
)
def test_conflicting_results_cannot_clear_pending_work(acknowledgment, changes, code):
    owner, commits, attempt, _ = running(acknowledgment)
    owner.close_admission("demo")
    assert_pending(owner)
    before = owner.snapshot()
    commit_count = len(commits)
    query, response = reconciliation(owner, attempt, native_task="task:one")
    response["effect"].update(changes)
    with pytest.raises(ContractError, match=code):
        owner.settle(attempt["attempt_id"], query, response)
    assert owner.snapshot() == before and len(commits) == commit_count
    assert_pending(owner)
    owner.restore(before)
    assert_pending(owner)


def test_unknown_observation_preserves_facts_and_exact_accepted_replay():
    owner, commits, attempt, first = running()
    query, response = reconciliation(
        owner,
        attempt,
        acknowledgment="unknown",
        task_state="unknown",
        effect_certainty="unknown",
        postcondition="unknown",
        native_task=None,
    )
    unchanged = copy.deepcopy(response)
    owner.settle(attempt["attempt_id"], query, response)
    snapshot = owner.snapshot()
    current = snapshot["attempts"][attempt["attempt_id"]]
    assert (current["state"], current["certainty"], current["native_task"]) == (
        "reconciling",
        "known",
        "task:one",
    )
    evidence = snapshot["results"][attempt["attempt_id"]]
    assert evidence["knowledge"]["acknowledgment"] == "accepted"
    assert evidence["knowledge"]["task_state"] == "running"
    assert evidence["records"][evidence["latest"]]["response"] == unchanged == response
    count = len(commits)
    owner.settle(attempt["attempt_id"], query, response)
    owner.settle(attempt["attempt_id"], *first)
    assert owner.snapshot() == snapshot and len(commits) == count
    owner.close_admission("demo")
    assert_pending(owner)


@pytest.mark.parametrize("certainty", ["unknown", "none"])
def test_terminal_fragments_do_not_synthesize_a_complete_outcome(certainty):
    owner, _, attempt, _ = running()
    owner.close_admission("demo")
    owner.settle(
        attempt["attempt_id"],
        *reconciliation(
            owner,
            attempt,
            effect_certainty=certainty,
            postcondition="not-satisfied",
            native_task="task:one",
        ),
    )
    current = owner.snapshot()["attempts"][attempt["attempt_id"]]
    assert (current["outcome"], current["certainty"], current["native_task"]) == (
        "pending",
        "known",
        "task:one",
    )
    assert_pending(owner)
    owner.restore(owner.snapshot())
    assert_pending(owner)
    owner.settle(
        attempt["attempt_id"],
        *reconciliation(owner, attempt, postcondition="not-satisfied", native_task="task:one"),
    )
    final = owner.snapshot()["attempts"][attempt["attempt_id"]]
    assert (final["state"], final["outcome"], final["certainty"]) == ("resolved", "failed", "known")


def test_running_postcondition_cannot_substitute_for_terminal_postcondition():
    owner, _, attempt, _ = running()
    owner.settle(
        attempt["attempt_id"],
        *reconciliation(owner, attempt, task_state="running", native_task="task:one"),
    )
    owner.settle(
        attempt["attempt_id"],
        *reconciliation(owner, attempt, postcondition="unknown", native_task="task:one"),
    )
    current = owner.snapshot()["attempts"][attempt["attempt_id"]]
    assert current["outcome"] == "pending"
    owner.close_admission("demo")
    assert_pending(owner)


@pytest.mark.parametrize("asynchronous", [False, True], ids=["known-noop", "known-task"])
def test_complete_outcome_survives_exact_retries_and_later_unknown_evidence(asynchronous):
    if asynchronous:
        owner, commits, attempt, first = running()
        terminal = reconciliation(owner, attempt, native_task="task:one")
    else:
        owner, commits = coordinator()
        attempt = prepare(owner)
        owner.dispatch("demo", attempt["attempt_id"])
        first = terminal = result(owner, attempt)
    owner.settle(attempt["attempt_id"], *terminal)
    snapshot = owner.snapshot()
    completed = snapshot["attempts"][attempt["attempt_id"]]
    assert (completed["outcome"], completed["certainty"], completed["native_task"]) == (
        "succeeded",
        "known",
        "task:one" if asynchronous else None,
    )
    count = len(commits)
    owner.settle(attempt["attempt_id"], *first)
    owner.settle(attempt["attempt_id"], *terminal)
    assert owner.snapshot() == snapshot and len(commits) == count
    stale = reconciliation(
        owner,
        attempt,
        acknowledgment="unknown",
        task_state="unknown",
        effect_certainty="unknown",
        postcondition="unknown",
        native_task=None,
    )
    with pytest.raises(ContractError, match="INVALID_SETTLEMENT"):
        owner.settle(attempt["attempt_id"], *stale)
    assert owner.snapshot() == snapshot and len(commits) == count


@pytest.mark.parametrize("reverse", [False, True], ids=["original-order", "reverse-order"])
@pytest.mark.parametrize("acknowledgment", ["accepted", "unknown"])
def test_restore_rejects_contradictory_running_and_rejected_receipts(reverse, acknowledgment):
    owner, _, attempt, _ = running(acknowledgment)
    owner.close_admission("demo")
    snapshot = owner.snapshot()
    query, response = reconciliation(
        owner,
        attempt,
        acknowledgment="rejected",
        effect_certainty="none",
        postcondition="not-satisfied",
        native_task="task:one",
    )
    retained = {"request": query, "response": response}
    evidence = snapshot["results"][attempt["attempt_id"]]
    identity = digest(retained)
    evidence["records"][identity] = retained
    evidence["latest"] = identity
    if reverse:
        evidence["records"] = dict(reversed(tuple(evidence["records"].items())))
    snapshot["attempts"][attempt["attempt_id"]].update(
        state="resolved", certainty="none", outcome="failed", native_task=None
    )
    before = owner.snapshot()
    with pytest.raises(ContractError, match=r"RESULT_(ACKNOWLEDGMENT_CONFLICT|RUNNING_REJECTION)"):
        owner.restore(snapshot)
    assert owner.snapshot() == before
    assert_pending(owner)


@pytest.mark.parametrize("field", ["knowledge", "summary"])
def test_restore_recomputes_cumulative_facts_instead_of_trusting_cached_authority(field):
    owner, _, attempt, _ = running()
    snapshot = owner.snapshot()
    if field == "knowledge":
        snapshot["results"][attempt["attempt_id"]]["knowledge"]["native_task"] = None
        code = "RESTORE_RESULT_KNOWLEDGE"
    else:
        snapshot["attempts"][attempt["attempt_id"]]["certainty"] = "none"
        code = "RESTORE_RESULT_STATE"
    with pytest.raises(ContractError, match=code):
        owner.restore(snapshot)


@pytest.mark.parametrize("observation", ["unknown", "running", "terminal"])
def test_restore_cannot_discard_result_custody_for_observed_attempts(observation):
    owner, commits = coordinator()
    attempt = prepare(owner)
    owner.dispatch("demo", attempt["attempt_id"])
    if observation == "unknown":
        receipt = result(
            owner,
            attempt,
            acknowledgment="unknown",
            task_state="unknown",
            effect_certainty="unknown",
            postcondition="unknown",
        )
    elif observation == "running":
        receipt = result(
            owner, attempt, task_state="running", native_task="task:one", postcondition="unknown"
        )
    else:
        receipt = result(owner, attempt)
    owner.settle(attempt["attempt_id"], *receipt)
    owner.close_admission("demo")
    before = owner.snapshot()
    missing = copy.deepcopy(before)
    missing["results"].clear()
    count = len(commits)
    with pytest.raises(ContractError, match="RESTORE_RESULT_CUSTODY"):
        owner.restore(missing)
    assert owner.snapshot() == before and len(commits) == count
    if observation != "terminal":
        assert_pending(owner)


@pytest.mark.parametrize("state", ["prepared", "dispatched", "cancelled"])
def test_restore_preserves_reachable_attempts_without_received_results(state):
    owner, _ = coordinator()
    attempt = prepare(owner)
    if state == "dispatched":
        owner.dispatch("demo", attempt["attempt_id"])
    elif state == "cancelled":
        owner.cancel_prepared(attempt["attempt_id"], owner_approved=True)
    saved = owner.snapshot()
    assert saved["results"] == {}
    owner.restore(saved)
    assert owner.snapshot()["attempts"] == saved["attempts"]
    assert owner.snapshot()["admission"]["demo"] is False
    if state != "cancelled":
        assert_pending(owner)


def test_restored_evidence_has_no_dictionary_order_authority():
    owner, _, attempt, _ = running()
    owner.settle(
        attempt["attempt_id"],
        *reconciliation(
            owner,
            attempt,
            acknowledgment="unknown",
            task_state="unknown",
            effect_certainty="unknown",
            postcondition="unknown",
            native_task=None,
        ),
    )
    owner.settle(attempt["attempt_id"], *reconciliation(owner, attempt, native_task="task:one"))
    snapshot = owner.snapshot()
    records = tuple(snapshot["results"][attempt["attempt_id"]]["records"].items())
    for order in permutations(records):
        reordered = copy.deepcopy(snapshot)
        reordered["results"][attempt["attempt_id"]]["records"] = dict(order)
        owner.restore(reordered)
        restored = owner.snapshot()
        assert restored["attempts"] == snapshot["attempts"]
        assert restored["results"] == snapshot["results"]


def test_cumulative_result_history_linear_work():
    owner, _, attempt, first = running()
    unknown = reconciliation(
        owner,
        attempt,
        acknowledgment="unknown",
        task_state="unknown",
        effect_certainty="unknown",
        postcondition="unknown",
        native_task=None,
    )[1]["effect"]
    terminal = reconciliation(owner, attempt, native_task="task:one")[1]["effect"]
    samples = []
    for count in (16, 64, 256):
        observations = [first[1]["effect"] if index % 2 == 0 else unknown for index in range(count)]
        observations.append(terminal)

        def consume(observed_results=observations):
            knowledge = None
            for observation in observed_results:
                knowledge = accumulate_result(attempt, observation, previous=knowledge)
            return knowledge

        knowledge, work = measure(consume)
        assert knowledge["acknowledgment"] == "accepted"
        assert knowledge["native_task"] == "task:one"
        assert knowledge["completion"] == {
            "effect_certainty": "known",
            "postcondition": "satisfied",
        }
        samples.append((count, work))
    assert_linear(samples)
