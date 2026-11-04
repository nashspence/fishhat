"""Bounded owner persistence across complete accepted histories and lost acknowledgments."""

from __future__ import annotations

import copy
from io import BytesIO

import pytest
from fishhat_adapters.process import receive_process_result
from fishhat_contracts.validation import ContractError, canonical, digest, strict_json
from fishhat_owner import adapter_state
from fishhat_owner.adapter_state import AdapterCoordinator

from tests import adapter_commit_support
from tests.adapter_commit_support import CommitStore
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
from tests.linear_support import assert_linear, measure
from tests.test_adapter_effects import result
from tests.test_adapter_process import identity as artifact_identity

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": ["fishhat/owner-support/src/fishhat_owner/adapter_state.py"],
    "scope": "bounded atomic delta payloads, exact independent reconstruction, indexed recovery and commit acknowledgment uncertainty",
    "relationship": "candidate",
    "reason": "An independent synthetic append receiver exercises identity, CAS, original custody and failure ordering without native storage qualification.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_adapter_commit_history_linear_work": {
        "purpose": "implementation",
        "authority": [
            "fishhat/owner-support/src/fishhat_owner/adapter_state.py#AdapterCoordinator._publish",
            "release.toml#/engineering",
        ],
        "scope": "aggregate prepare, dispatch, complete observation history, exact retries, indexed drains and serialized storage transactions",
        "relationship": "scoped-witness",
        "reason": "Actual coordinator paths and independent append/replay storage are measured across sixteenfold input growth; full checkpoints are explicit separate operations.",
        "claims": ["engineering:owner.adapter-commits"],
    },
}


def fixture():
    registry, _, _ = runtime_registry()
    store = CommitStore(OWNER)
    owner = AdapterCoordinator(
        OWNER,
        registry,
        store,
        processes_quiescent=lambda _: True,
        native_exclusion=native_exclusion,
    )
    sources = runtime_sources(registry)
    owner.bind(binding(), **sources, owner_approved=True)
    owner.prove_quiescent("demo", fresh_observation(owner), owner_approved=True)
    owner.open_admission("demo", owner_approved=True)
    return owner, store, sources, request()


def prepare(owner, sources, original, number=0):
    return owner.prepare(
        "demo",
        original,
        **sources,
        operation_id=identifier(1000 + number),
        effect_id=identifier(2000 + number),
        attempt_id=identifier(3000 + number),
        owner_approved=True,
    )


def reply(invocation, *, running=False, observation=None):
    original, attempt = invocation["request"], invocation["attempt"]
    query = {
        "contract": original["contract"],
        "method": "reconcile",
        "input": {"scope": original["input"]["scope"], "invocation": invocation},
    }
    response = {
        "contract": query["contract"],
        "method": query["method"],
        "request_digest": digest(query),
        "scope": original["input"]["scope"],
        "coverage": "complete",
        "continuation": None,
        "proposal": None,
        "problem": None
        if observation is None
        else {
            "code": "BUSY",
            "summary": f"Synthetic observation {observation:08d}",
            "retry": "safe-read",
        },
        "effect": {
            "attempt_id": attempt["attempt_id"],
            "input_digest": attempt["input_digest"],
            "acknowledgment": "accepted",
            "task_state": "running" if running else "terminal",
            "effect_certainty": "known",
            "postcondition": "unknown" if running else "satisfied",
            "native_task": "task:" + attempt["attempt_id"],
        },
        "output": {
            "deployment": original["input"]["deployment"],
            "observation": None,
            "objects": [],
        },
    }
    return query, response


def test_delta_receiver_reconstructs_exact_custody_before_dispatch_and_after_settlement():
    owner, store, sources, original = fixture()
    attempt = prepare(owner, sources, original)
    identity = attempt["attempt_id"]
    assert store.state["requests"][identity] == original
    assert store.state["attempts"][identity] == attempt
    invocation = owner.dispatch("demo", identity)
    assert store.state["attempts"][identity] == invocation["attempt"]
    assert store.state["requests"][identity] == invocation["request"]
    assert store.state["attempts"][identity]["certainty"] == "unknown"
    pending = reply(invocation, running=True)
    owner.settle(identity, *pending)
    first = store.snapshot()["results"][identity]
    owner.settle(identity, *reply(invocation))
    assert store.state == owner.snapshot()
    assert all(
        store.state["results"][identity]["records"][key] == value
        for key, value in first["records"].items()
    )
    count, saved = len(store.records), store.snapshot()
    owner.settle(identity, *pending)
    assert len(store.records) == count and store.state == saved
    replayed = CommitStore(OWNER)
    for encoded in store.records:
        replayed(strict_json(encoded, max_bytes=len(encoded)))
    assert replayed.state == saved


@pytest.mark.parametrize("committed", [False, True], ids=["before-write", "lost-ack"])
def test_failed_delta_acknowledgment_preserves_recoverable_exact_work(committed):
    owner, store, sources, original = fixture()
    attempt = prepare(owner, sources, original)
    identity = attempt["attempt_id"]
    before = store.snapshot()

    def fail(envelope):
        if committed:
            store(envelope)
        raise OSError("synthetic commit acknowledgment failure")

    owner.commit_delta = fail
    with pytest.raises(OSError):
        owner.dispatch("demo", identity)
    with pytest.raises(ContractError, match="OWNER_COMMIT_UNCERTAIN"):
        owner.dispatch("demo", identity)
    assert store.state["requests"] == before["requests"]
    assert store.state["attempts"][identity]["state"] == ("dispatched" if committed else "prepared")
    recovered = AdapterCoordinator(
        OWNER,
        owner.registry,
        store,
        processes_quiescent=lambda _: True,
        native_exclusion=native_exclusion,
    )
    recovered.restore(store.snapshot())
    assert store.state == recovered.snapshot()
    assert store.state["admission"]["demo"] is False
    with pytest.raises(ContractError, match="PENDING_NATIVE_WORK"):
        recovered.observation_request("demo", owner_approved=True)
    if not committed:
        recovered.cancel_prepared(identity, owner_approved=True)
        recovered.observation_request("demo", owner_approved=True)
    else:
        invocation = {
            "attempt": store.state["attempts"][identity],
            "request": store.state["requests"][identity],
        }
        recovered.settle(identity, *reply(invocation))
        recovered.observation_request("demo", owner_approved=True)


def test_stale_checkpoint_cannot_replace_newer_committed_work():
    owner, store, sources, original = fixture()
    stale = store.snapshot()
    prepare(owner, sources, original)
    accepted = store.snapshot()
    with pytest.raises(AssertionError):
        owner.restore(stale)
    assert store.state == accepted
    with pytest.raises(ContractError, match="OWNER_COMMIT_UNCERTAIN"):
        owner.snapshot()


def test_interrupted_delta_acknowledgment_also_poisons_dispatch():
    owner, store, sources, original = fixture()
    attempt = prepare(owner, sources, original)
    identity = attempt["attempt_id"]

    def interrupt(envelope):
        store(envelope)
        raise KeyboardInterrupt

    owner.commit_delta = interrupt
    with pytest.raises(KeyboardInterrupt):
        owner.dispatch("demo", identity)
    assert store.state["attempts"][identity]["state"] == "dispatched"
    with pytest.raises(ContractError, match="OWNER_COMMIT_UNCERTAIN"):
        owner.dispatch("demo", identity)


def test_restored_indexes_preserve_effect_retry_and_pending_scope_rules():
    owner, store, sources, original = fixture()
    attempt = prepare(owner, sources, original)
    recovered = AdapterCoordinator(
        OWNER,
        owner.registry,
        store,
        processes_quiescent=lambda _: True,
        native_exclusion=native_exclusion,
    )
    recovered.restore(store.snapshot())
    arguments = {
        "operation_id": attempt["operation_id"],
        "effect_id": attempt["effect_id"],
        "attempt_id": identifier(9999),
        "owner_approved": True,
    }
    with pytest.raises(ContractError, match="UNCERTAIN_EFFECT_RETRY"):
        recovered.prepare("demo", original, **sources, **arguments)
    recovered.cancel_prepared(attempt["attempt_id"], owner_approved=True)
    with pytest.raises(ContractError, match="EFFECT_RETRY_REQUIRES_NEW_PLAN"):
        recovered.prepare("demo", original, **sources, **arguments)
    recovered.prove_quiescent("demo", fresh_observation(recovered), owner_approved=True)
    recovered.open_admission("demo", owner_approved=True)
    assert store.state == recovered.snapshot()


def history_case(count, history):
    owner, store, sources, original = fixture()
    baseline = (store.written_bytes, store.written_rows)

    def run():
        invocations = []
        for number in range(count if history == "attempts" else 1):
            attempt = prepare(owner, sources, original, number)
            invocation = owner.dispatch("demo", attempt["attempt_id"])
            assert prepare(owner, sources, original, number) == invocation["attempt"]
            invocations.append(invocation)
            if history == "attempts":
                pending = reply(invocation, running=True)
                owner.settle(attempt["attempt_id"], *pending)
                owner.settle(attempt["attempt_id"], *pending)
        if history == "observations":
            invocation = invocations[0]
            for number in range(count):
                pending = reply(invocation, running=True, observation=number)
                owner.settle(invocation["attempt"]["attempt_id"], *pending)
                owner.settle(invocation["attempt"]["attempt_id"], *pending)
        owner.close_admission("demo")
        with pytest.raises(ContractError, match="PENDING_NATIVE_WORK"):
            owner.observation_request("demo", owner_approved=True)
        for invocation in invocations:
            complete = reply(invocation)
            identity = invocation["attempt"]["attempt_id"]
            owner.settle(identity, *complete)
            owner.settle(identity, *complete)
        owner.prove_quiescent("demo", fresh_observation(owner), owner_approved=True)
        owner.open_admission("demo", owner_approved=True)
        assert owner.snapshot() == store.state
        return store.written_bytes - baseline[0], store.written_rows - baseline[1]

    return run


@pytest.mark.parametrize("history", ["attempts", "observations"])
def test_adapter_commit_history_linear_work(history):
    samples = []
    for count in (16, 64, 256):
        (written_bytes, written_rows), work = measure(
            history_case(count, history), modules=(adapter_state, adapter_commit_support)
        )
        work["committed_bytes"] = written_bytes
        work["committed_rows"] = written_rows
        samples.append((count, work))
    assert_linear(samples)


def test_one_observation_appends_only_new_response_history():
    owner, store, sources, original = fixture()
    attempt = prepare(owner, sources, original)
    identity = attempt["attempt_id"]
    invocation = owner.dispatch("demo", identity)
    for number in range(8):
        owner.settle(identity, *reply(invocation, running=True, observation=number))
    retained = copy.deepcopy(store.state["results"][identity]["records"])
    owner.settle(identity, *reply(invocation, running=True, observation=8))
    delta = strict_json(store.records[-1])
    assert delta["kind"] == "delta"
    assert len(delta["updates"]["results"][identity]["records"]) == 1
    assert "requests" not in delta["updates"]
    assert all(
        store.state["results"][identity]["records"][key] == value for key, value in retained.items()
    )
    assert len(store.state["results"][identity]["records"]) == 9


def test_ordinary_updates_do_not_traverse_retained_collections():
    owner, store, sources, original = fixture()
    first = prepare(owner, sources, original)
    invocation = owner.dispatch("demo", first["attempt_id"])
    owner.settle(first["attempt_id"], *reply(invocation, running=True))

    class IndexedOnly(dict):
        def traversal(self, *args, **kwargs):
            raise AssertionError("ordinary update traversed retained history")

        __iter__ = traversal
        __deepcopy__ = traversal
        keys = traversal
        values = traversal
        items = traversal
        copy = traversal

    for table in ("bindings", "attempts", "requests", "results"):
        owner.state[table] = IndexedOnly(owner.state[table])
    retained = owner.state["results"][first["attempt_id"]]
    retained["records"] = IndexedOnly(retained["records"])
    second = prepare(owner, sources, original, 1)
    next_invocation = owner.dispatch("demo", second["attempt_id"])
    assert prepare(owner, sources, original, 1) == next_invocation["attempt"]
    owner.settle(first["attempt_id"], *reply(invocation))
    owner.settle(second["attempt_id"], *reply(next_invocation))
    owner.close_admission("demo")
    owner.prove_quiescent("demo", fresh_observation(owner), owner_approved=True)
    owner.open_admission("demo", owner_approved=True)
    assert owner.state == store.state


@pytest.mark.parametrize("legacy", [False, True], ids=["durable-hold", "legacy-effect-only"])
def test_effect_settlement_waits_for_all_attempt_processes_across_recovery(legacy):
    owner, store, sources, original = fixture()
    attempt = prepare(owner, sources, original)
    key = attempt["attempt_id"]
    invocation = owner.dispatch("demo", key)
    query, response = result(owner, attempt, native_task="task:" + key)
    encoded = canonical(response)
    marker = {"format": "fishhat.adapter-process-result/v1", "response": artifact_identity(encoded)}
    receipt = receive_process_result(
        "runtime",
        query,
        stdout=canonical(marker) + b"\n",
        response_stream=BytesIO(encoded),
        retained_response=BytesIO(),
        exit_code=0,
        timed_out=False,
        children_quiescent=False,
        invocation=invocation,
    )
    assert not receipt.complete and receipt.response == response

    def lose_ack(envelope):
        store(envelope)
        raise OSError("commit acknowledged after disconnect")

    owner.commit_delta = lose_ack
    with pytest.raises(OSError):
        owner.settle(key, query, receipt)
    saved = store.snapshot()
    head = saved["results"][key]
    assert head["records"][head["latest"]]["response"] == response
    assert head["processes_quiescent"] is False
    assert saved["attempts"][key]["certainty"] == "known"
    assert saved["attempts"][key]["outcome"] == "pending"
    if legacy:
        del head["processes_quiescent"]
        saved["attempts"][key].update(state="resolved", outcome="succeeded")
    stopped = set()
    recovered = AdapterCoordinator(
        OWNER,
        owner.registry,
        store,
        native_exclusion=native_exclusion,
        processes_quiescent=lambda original: original["attempt_id"] in stopped,
    )
    recovered.restore(saved)
    with pytest.raises(ContractError, match="PENDING_NATIVE_WORK"):
        recovered.observation_request("demo", owner_approved=True)
    # A later clean reconciliation cannot certify cessation of the first launch.
    reconcile, observed = reply(invocation)
    recovered.settle(key, reconcile, observed)
    recovered.settle(key, query, response)
    assert recovered.snapshot()["attempts"][key]["outcome"] == "pending"
    with pytest.raises(ContractError):
        recovered.dispatch("demo", key)
    stopped.add(key)
    recovered.settle(key, reconcile, observed)
    assert store.snapshot()["attempts"][key]["outcome"] == "succeeded"
    recovered.observation_request("demo", owner_approved=True)
