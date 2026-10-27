"""Competing owner connections preserve the first committed terminal outcome."""

from __future__ import annotations

import threading

import pytest
from fishhat_contracts.validation import ContractError
from fishhat_owner.journal import Journal

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/states.json#/owner",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/states.json#/rules",
    ],
    "scope": "atomic terminal owner transitions across independent SQLite connections",
    "relationship": "candidate",
    "reason": "A deterministic SQL trace schedule races two public transition calls against one running request, checking immutable terminal state, effect certainty and exactly one success generation increment. It exercises the reference journal's real transactions, not native execution or distributed fencing.",
    "claims": [],
}


@pytest.mark.parametrize(
    "second_state,second_effect", [("cancelled", "none"), ("succeeded", "known")]
)
def test_competing_terminal_transitions_preserve_first_outcome(
    tmp_path, second_state, second_effect
):
    path = tmp_path / "owner.sqlite"
    owner = Journal(path, "owner", "epoch", initialize=True)
    owner.submit(
        "request",
        {"action": "example"},
        principal="operator",
        authorized=True,
        expected_epoch="epoch",
        expected_generation=0,
        expires=10,
        now=0,
    )
    owner.transition("request", "running", "unknown")
    owner.close()

    ready = threading.Barrier(2)
    begins = threading.Barrier(2)
    first_finished = threading.Event()
    outcomes = {}
    coordination_errors = []

    def finish(label, state, effect):
        connection = Journal(path, "owner", "epoch")

        def trace(statement):
            if statement.startswith("BEGIN"):
                try:
                    begins.wait(timeout=10)
                    if label == "second" and not first_finished.wait(timeout=10):
                        coordination_errors.append("first transition did not finish")
                except threading.BrokenBarrierError:
                    coordination_errors.append("both transaction starts were not observed")

        connection.db.set_trace_callback(trace)
        try:
            ready.wait(timeout=10)
            connection.transition("request", state, effect)
            outcomes[label] = "committed"
        except Exception as exc:
            outcomes[label] = exc
        finally:
            connection.close()
            if label == "first":
                first_finished.set()

    # Trace callbacks run before BEGIN acquires a writer lock. Both connections
    # enter transition, then the second starts its transaction after the first
    # commits. A predecessor read outside that transaction would already be stale.
    workers = [
        threading.Thread(target=finish, args=("first", "succeeded", "known")),
        threading.Thread(target=finish, args=("second", second_state, second_effect)),
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=25)
    assert not any(worker.is_alive() for worker in workers)
    assert not coordination_errors
    assert outcomes["first"] == "committed"
    assert isinstance(outcomes["second"], ContractError)
    assert str(outcomes["second"]) == "illegal transition"

    owner = Journal(path, "owner", "epoch")
    try:
        retained = owner.submit(
            "request",
            {"action": "example"},
            principal="current-operator",
            authorized=True,
            expected_epoch="epoch",
            expected_generation=0,
            expires=10,
            now=20,
        )
        assert retained == {
            "request_id": "request",
            "principal": "operator",
            "state": "succeeded",
            "effect": "known",
        }
        assert owner.generation == 1
    finally:
        owner.close()
