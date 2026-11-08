"""Portable opt-in same-host authority experiment (not native qualification)."""

from __future__ import annotations

import shutil
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from research.authority_reference.model import (
    LocalEffectTarget,
    LocalOwner,
    UnsafeAuthority,
    _effect_id,
)

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "research/authority_reference/model.py",
        "fishhat/owner-support/src/fishhat_owner/journal.py",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/Owner",
    ],
    "scope": "opt-in same-host local owner/target model; no central/off-host authority",
    "relationship": "candidate",
    "reason": "The model exercises local SQLite transactions, not native IPC, filesystem, process identity, host clone exclusion, or power-loss qualification.",
    "claims": [],
}

OWNER = {
    "tool": "app-ops",
    "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "epoch": "11111111-1111-4111-8111-111111111111",
}
SCOPE = "local-application:orders"
SUBJECT = {"scope": SCOPE, "delta": 3}


def owner(path: Path, *, epoch: str = OWNER["epoch"], initialize: bool = False) -> LocalOwner:
    return LocalOwner(path, {**OWNER, "epoch": epoch}, initialize=initialize,
                      scopes=(SCOPE,) if initialize else None)


def target(path: Path, *, initialize: bool = True,
           scopes: tuple[str, ...] = (SCOPE,)) -> LocalEffectTarget:
    return LocalEffectTarget(path, OWNER, scopes, initialize=initialize)


def execute(local: LocalOwner, native: LocalEffectTarget, request: str, *,
            delta: int = 3, scope: str = SCOPE) -> int:
    local.accept(request, {"scope": scope, "delta": delta}, "alice", authorized=True)
    return local.run(request, native, authorized=True)


def test_local_acceptance_and_replay_without_target_or_client(tmp_path):
    journal = tmp_path / "owner.db"
    native = target(tmp_path / "native.db")
    native.available = False
    original = owner(journal, initialize=True)
    submitted = original.accept("request-1", SUBJECT, "alice", authorized=True)
    with pytest.raises(UnsafeAuthority, match="LOCAL_PERMISSION_DENIED"):
        original.accept("request-2", SUBJECT, "mallory", authorized=False)
    with pytest.raises(UnsafeAuthority, match="REQUEST_ID_CONFLICT"):
        original.accept("request-1", {**SUBJECT, "delta": 4}, "alice", authorized=True)
    assert submitted["principal"] == "alice"
    original.close()
    reopened = owner(journal)
    try:
        assert reopened.accept("request-1", SUBJECT, "bob", authorized=True) == submitted
        assert reopened.accept("request-3", SUBJECT, "alice", authorized=True)["state"] == "accepted"
        with pytest.raises(UnsafeAuthority, match="TARGET_UNAVAILABLE"):
            reopened.claim("activation-1", SCOPE, native, authorized=True)
    finally:
        reopened.close()


def test_lost_effect_reply_reconciled_after_process_restart(tmp_path):
    native = target(tmp_path / "native.db")
    local_file = tmp_path / "owner.db"
    first = owner(local_file, initialize=True)
    first.accept("e-1", {**SUBJECT, "delta": 7}, "alice", authorized=True)
    assert first.claim("a-1", SCOPE, native, authorized=True) == 1

    class ReplyLost:
        def effect(self, *args, **kwargs):
            assert native.effect(*args, **kwargs) == 7
            raise ConnectionError("reply lost after local commit")

    with pytest.raises(ConnectionError, match="reply lost"):
        first.run("e-1", ReplyLost(), authorized=True)
    assert first.accepted("e-1")["certainty"] == "unknown"
    first.close()
    reopened = owner(local_file)
    try:
        with pytest.raises(UnsafeAuthority, match="RECONCILIATION_REQUIRED"):
            reopened.run("e-1", native, authorized=True)
        assert reopened.reconcile("e-1", native, authorized=True)["state"] == "succeeded"
        assert reopened.run("e-1", native, authorized=True) == 7
        assert native.value(SCOPE) == 7
        with pytest.raises(UnsafeAuthority, match="REACTIVATION_REQUIRED"):
            reopened.claim("a-1", SCOPE, native, authorized=True)
    finally:
        reopened.close()


def test_unknown_local_effect_never_inferred_absent(tmp_path):
    native = target(tmp_path / "native.db")
    local = owner(tmp_path / "owner.db", initialize=True)
    try:
        local.accept("e-1", {**SUBJECT, "delta": 2}, "alice", authorized=True)
        local.claim("activation", SCOPE, native, authorized=True)
        native.available = False
        with pytest.raises(UnsafeAuthority, match="TARGET_UNAVAILABLE"):
            local.run("e-1", native, authorized=True)
        assert local.accepted("e-1")["state"] == "dispatched"
        with pytest.raises(UnsafeAuthority, match="TARGET_UNAVAILABLE"):
            local.reconcile("e-1", native, authorized=True)
        native.available = True
        with pytest.raises(UnsafeAuthority, match="EFFECT_UNRESOLVED"):
            local.reconcile("e-1", native, authorized=True)
        assert local.close_absent("e-1", native, authorized=True)["state"] == "failed"
        with pytest.raises(UnsafeAuthority, match="EFFECT_PERMANENTLY_CLOSED"):
            native.effect(
                SCOPE, 1, local.live[SCOPE][1], _effect_id(OWNER, SCOPE, "e-1"),
                {**SUBJECT, "delta": 2}, OWNER, authorized=True,
            )
        assert native.value(SCOPE) == 0
    finally:
        local.close()


def test_two_copies_of_local_journal_share_one_local_fence(tmp_path):
    native = target(tmp_path / "native.db")
    primary, copied = tmp_path / "primary.db", tmp_path / "copy.db"
    initial = owner(primary, initialize=True)
    initial.accept("historical", {**SUBJECT, "delta": 1}, "alice", authorized=True)
    initial.close()
    shutil.copyfile(primary, copied)
    a, b = owner(primary), owner(copied)
    try:
        assert a.claim("activation-a", SCOPE, native, authorized=True) == 1
        assert b.claim("activation-b", SCOPE, native, authorized=True) == 2
        a.accept("local-a", {**SUBJECT, "delta": 6}, "alice", authorized=True)
        b.accept("local-b", {**SUBJECT, "delta": 9}, "bob", authorized=True)
        with pytest.raises(UnsafeAuthority, match="FENCE_STALE"):
            a.run("local-a", native, authorized=True)
        assert b.run("local-b", native, authorized=True) == 9
        assert native.value(SCOPE) == 9
        assert a.close_absent("local-a", native, authorized=True)["state"] == "failed"
    finally:
        a.close()
        b.close()


def test_same_host_cas_claim_is_atomic(tmp_path):
    native = target(tmp_path / "native.db")

    def attempt(i: int):
        try:
            return native.claim(SCOPE, 0, f"session-{i}", f"a-{i}", OWNER, authorized=True)
        except UnsafeAuthority as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results.count(1) == 1
    assert results.count("FENCE_STALE") == 7
    assert native.generation(SCOPE, OWNER, authorized=True) == 1


def test_same_host_effect_identity_is_atomic_with_duplicate_delivery(tmp_path):
    native = target(tmp_path / "native.db")
    generation = native.claim(SCOPE, 0, "session", "activation", OWNER, authorized=True)
    eid = _effect_id(OWNER, SCOPE, "e-1")
    def attempt(_):
        return native.effect(SCOPE, generation, "session", eid, {**SUBJECT, "delta": 4}, OWNER, authorized=True)
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(attempt, range(6)))
    assert results == [4] * 6
    assert native.value(SCOPE) == 4
    with pytest.raises(UnsafeAuthority, match="EFFECT_ID_CONFLICT"):
        native.effect(SCOPE, generation, "session", eid, {**SUBJECT, "delta": 5}, OWNER, authorized=True)


def test_new_epoch_retains_history_and_locally_fences_original(tmp_path):
    native = target(tmp_path / "native.db")
    original = owner(tmp_path / "original.db", initialize=True)
    destination = tmp_path / "restored.db"
    restored_owner = {**OWNER, "epoch": "22222222-2222-4222-8222-222222222222"}
    try:
        original.accept("old-request", {**SUBJECT, "delta": 5}, "alice", authorized=True)
        original.claim("original-activation", SCOPE, native, authorized=True)
        assert original.run("old-request", native, authorized=True) == 5
        manifest, _ = original.export_manifest()
        with pytest.raises(UnsafeAuthority, match="RESTORED_EPOCH_REUSED"):
            LocalOwner.restore(original, destination, OWNER, expected_manifest=manifest, approved=True)
        with pytest.raises(UnsafeAuthority, match="RESTORE_MANIFEST_MISMATCH"):
            LocalOwner.restore(original, destination, restored_owner,
                               expected_manifest="sha256:" + "0" * 64, approved=True)
        restored = LocalOwner.restore(original, destination, restored_owner,
                                      expected_manifest=manifest, approved=True)
        try:
            assert restored.db.execute(
                "SELECT state,certainty,principal,result FROM history WHERE request_id='old-request'"
            ).fetchone() == ("succeeded", "known", "alice", 5)
            assert restored.accepted("old-request") is None
            with pytest.raises(UnsafeAuthority, match="HISTORICAL_REQUEST_ID"):
                restored.accept("old-request", {**SUBJECT, "delta": 5}, "alice", authorized=True)
            restored.accept("new-work", {**SUBJECT, "delta": 2}, "alice", authorized=True)
            with pytest.raises(UnsafeAuthority, match="FENCE_NOT_ACTIVATED"):
                restored.run("new-work", native, authorized=True)
            with pytest.raises(UnsafeAuthority, match="TARGET_EPOCH_MISMATCH"):
                restored.claim("pre-handoff", SCOPE, native, authorized=True)
            native.prepare_handoff(restored_owner, authorized=True)
            native.adopt_epoch(restored_owner, authorized=True)
            with pytest.raises(UnsafeAuthority, match="TARGET_EPOCH_MISMATCH"):
                original.claim("stale", SCOPE, native, authorized=True)
            assert restored.claim("new-activation", SCOPE, native, authorized=True) == 3
            assert restored.run("new-work", native, authorized=True) == 7
        finally:
            restored.close()
    finally:
        original.close()


def test_missing_journal_is_not_new_empty_state(tmp_path):
    with pytest.raises(UnsafeAuthority, match="OWNER_STATE_MISSING"):
        owner(tmp_path / "missing.db")
    with pytest.raises(UnsafeAuthority, match="TARGET_MISSING"):
        LocalEffectTarget(tmp_path / "missing-target.db", OWNER, (SCOPE,))


def test_multiple_local_restores_preserve_every_origin(tmp_path):
    first = owner(tmp_path / "first.db", initialize=True)
    first.accept("first-work", {**SUBJECT, "delta": 1}, "alice", authorized=True)
    first_manifest, _ = first.export_manifest()
    second = LocalOwner.restore(first, tmp_path / "second.db",
                                {**OWNER, "epoch": "22222222-2222-4222-8222-222222222222"},
                                expected_manifest=first_manifest, approved=True)
    second.accept("second-work", {**SUBJECT, "delta": 2}, "alice", authorized=True)
    second_manifest, _ = second.export_manifest()
    third = LocalOwner.restore(second, tmp_path / "third.db",
                               {**OWNER, "epoch": "33333333-3333-4333-8333-333333333333"},
                               expected_manifest=second_manifest, approved=True)
    try:
        assert third.db.execute(
            "SELECT request_id,state FROM history ORDER BY request_id"
        ).fetchall() == [("first-work", "accepted"), ("second-work", "accepted")]
        with pytest.raises(UnsafeAuthority, match="RESTORED_EPOCH_REUSED"):
            LocalOwner.restore(third, tmp_path / "reused.db", OWNER,
                               expected_manifest=third.export_manifest()[0], approved=True)
    finally:
        first.close()
        second.close()
        third.close()


def test_reconciliation_checks_exact_intent_not_just_effect_name(tmp_path):
    other = "local-application:another"
    native = target(tmp_path / "native.db", scopes=(SCOPE, other))
    local = owner(tmp_path / "owner.db", initialize=True)
    try:
        local.accept("e-1", {**SUBJECT, "delta": 2}, "alice", authorized=True)
        local.claim("activation", SCOPE, native, authorized=True)
        native.available = False
        with pytest.raises(UnsafeAuthority, match="TARGET_UNAVAILABLE"):
            local.run("e-1", native, authorized=True)
        native.available = True
        generation = native.claim(other, 0, "other", "other-activation", OWNER, authorized=True)
        native.effect(other, generation, "other", _effect_id(OWNER, SCOPE, "e-1"),
                      {"scope": other, "delta": 2}, OWNER, authorized=True)
        with pytest.raises(UnsafeAuthority, match="EFFECT_ID_CONFLICT"):
            local.reconcile("e-1", native, authorized=True)
    finally:
        local.close()


def test_unauthorized_claim_effect_and_tombstone_fail_closed(tmp_path):
    native = target(tmp_path / "native.db")
    local = owner(tmp_path / "owner.db", initialize=True)
    try:
        with pytest.raises(UnsafeAuthority, match="SCOPE_NOT_ENROLLED"):
            native.claim("unapproved-local-target", 0, "session", "unauthorized", OWNER,
                         authorized=True)
        with pytest.raises(UnsafeAuthority, match="LOCAL_PERMISSION_DENIED"):
            native.claim(SCOPE, 0, "session", "act", OWNER, authorized=False)
        with pytest.raises(UnsafeAuthority, match="LOCAL_PERMISSION_DENIED"):
            native.close_absent(SCOPE, _effect_id(OWNER, SCOPE, "e-1"), SUBJECT,
                                OWNER, authorized=False)
        with pytest.raises(UnsafeAuthority, match="LOCAL_PERMISSION_DENIED"):
            local.claim("act", SCOPE, native, authorized=False)
        local.accept("e-1", SUBJECT, "alice", authorized=True)
        with pytest.raises(UnsafeAuthority, match="LOCAL_PERMISSION_DENIED"):
            local.run("e-1", native, authorized=False)
        assert native.value(SCOPE) == 0
    finally:
        local.close()


def test_lost_local_claim_reply_is_idempotent_without_cold_session_restore(tmp_path):
    native = target(tmp_path / "native.db")
    local_file = tmp_path / "owner.db"
    local = owner(local_file, initialize=True)

    class ClaimReplyLost:
        def generation(self, *args, **kwargs):
            return native.generation(*args, **kwargs)
        def claim(self, *args, **kwargs):
            assert native.claim(*args, **kwargs) == 1
            raise ConnectionError("claim reply lost")

    with pytest.raises(ConnectionError, match="claim reply lost"):
        local.claim("activation", SCOPE, ClaimReplyLost(), authorized=True)
    assert native.observe_claim(SCOPE, "activation", OWNER, authorized=True) == 1
    assert local.claim("activation", SCOPE, native, authorized=True) == 1
    local.close()
    reopened = owner(local_file)
    try:
        with pytest.raises(UnsafeAuthority, match="REACTIVATION_REQUIRED"):
            reopened.claim("activation", SCOPE, native, authorized=True)
        assert reopened.claim("new-activation", SCOPE, native, authorized=True) == 2
    finally:
        reopened.close()


def test_claim_committed_but_owner_crashes_before_ack_is_not_reanimated(tmp_path):
    native = target(tmp_path / "native.db")
    path = tmp_path / "owner.db"
    first = owner(path, initialize=True)

    class Lost:
        def generation(self, *args, **kwargs):
            return native.generation(*args, **kwargs)
        def claim(self, *args, **kwargs):
            native.claim(*args, **kwargs)
            raise ConnectionError("lost")

    with pytest.raises(ConnectionError, match="lost"):
        first.claim("pending", SCOPE, Lost(), authorized=True)
    first.close()
    reopened = owner(path)
    try:
        assert native.observe_claim(SCOPE, "pending", OWNER, authorized=True) == 1
        with pytest.raises(UnsafeAuthority, match="REACTIVATION_REQUIRED"):
            reopened.claim("pending", SCOPE, native, authorized=True)
        assert reopened.claim("fresh", SCOPE, native, authorized=True) == 2
    finally:
        reopened.close()


def test_result_corruption_changes_checkpoint_root(tmp_path):
    path = tmp_path / "owner.db"
    local = owner(path, initialize=True)
    native = target(tmp_path / "native.db")
    try:
        local.claim("activation", SCOPE, native, authorized=True)
        assert execute(local, native, "e-1", delta=7) == 7
        checkpoint, _ = local.export_manifest()
        local.db.execute("UPDATE requests SET result=999 WHERE id='e-1'")
        assert local.export_manifest()[0] != checkpoint
    finally:
        local.close()


def test_snapshot_stays_consistent_during_concurrent_local_write(tmp_path):
    path = tmp_path / "owner.db"
    local = owner(path, initialize=True)
    local.accept("a", SUBJECT, "alice", authorized=True)
    second_write = []
    def concurrent_writer(statement):
        if "FROM history ORDER BY" in statement and not second_write:
            with sqlite3.connect(path, timeout=5) as other:
                other.execute("UPDATE requests SET certainty='known' WHERE id='a'")
            second_write.append(True)
    local.db.set_trace_callback(concurrent_writer)
    try:
        snapshot_root, records = local.export_manifest()
        assert second_write
        assert records[0][4] == "none"  # The snapshot held the earlier read view.
        local.db.set_trace_callback(None)
        assert local.export_manifest()[0] != snapshot_root
    finally:
        local.close()


def test_full_host_clone_has_independent_local_effects_no_global_claim(tmp_path):
    """Two host images can each run locally; neither can elect a global winner."""
    first_root = tmp_path / "host-a"
    second_root = tmp_path / "host-b"
    first_root.mkdir()
    second_root.mkdir()
    a = owner(first_root / "owner.db", initialize=True)
    native_a = target(first_root / "target.db")
    a.close()
    shutil.copyfile(first_root / "owner.db", second_root / "owner.db")
    shutil.copyfile(first_root / "target.db", second_root / "target.db")
    one, two = owner(first_root / "owner.db"), owner(second_root / "owner.db")
    native_b = target(second_root / "target.db", initialize=False)
    try:
        assert one.claim("activation", SCOPE, native_a, authorized=True) == 1
        assert two.claim("activation", SCOPE, native_b, authorized=True) == 1
        assert execute(one, native_a, "work", delta=5) == 5
        assert execute(two, native_b, "work", delta=5) == 5
        assert (native_a.value(SCOPE), native_b.value(SCOPE)) == (5, 5)
    finally:
        one.close()
        two.close()


@pytest.mark.parametrize("tool", ["host-ops", "app-ops"])
def test_both_local_owner_kinds_require_no_off_host_authority(tmp_path, tool):
    configured = {**OWNER, "tool": tool}
    own = LocalOwner(tmp_path / "owner.db", configured, initialize=True, scopes=(SCOPE,))
    native = LocalEffectTarget(tmp_path / "native.db", configured, (SCOPE,), initialize=True)
    try:
        own.accept("work", SUBJECT, "alice", authorized=True)
        assert own.claim("activation", SCOPE, native, authorized=True) == 1
        assert own.run("work", native, authorized=True) == 3
    finally:
        own.close()


def test_distinct_local_processes_cas_one_same_host_generation(tmp_path):
    """Use actual OS processes, not only Python threads; no POSIX-only primitives."""
    native = target(tmp_path / "native.db")
    code = (
        "from research.authority_reference.model import LocalEffectTarget, UnsafeAuthority; "
        "from pathlib import Path; import sys; "
        "owner={'tool':'app-ops','id':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',"
        "'epoch':'11111111-1111-4111-8111-111111111111'}; "
        "native=LocalEffectTarget(Path(sys.argv[1]),owner,('local-application:orders',)); "
        "native.claim('local-application:orders',0,sys.argv[2],sys.argv[2],owner,authorized=True)"
    )
    processes = [
        subprocess.Popen([sys.executable, "-c", code, str(native.path), f"p-{i}"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for i in range(4)
    ]
    results = [process.communicate(timeout=20) for process in processes]
    codes = [process.returncode for process in processes]
    assert codes.count(0) == 1
    assert codes.count(1) == 3
    assert all("FENCE_STALE" in err for (_, err), code in zip(results, codes) if code == 1)
    assert native.generation(SCOPE, OWNER, authorized=True) == 1


def test_owner_scope_enrollment_is_local_and_survives_restore(tmp_path):
    native = target(tmp_path / "native.db")
    native.available = False
    first = owner(tmp_path / "first.db", initialize=True)
    try:
        assert first.accept("offline", SUBJECT, "alice", authorized=True)["state"] == "accepted"
        with pytest.raises(UnsafeAuthority, match="SCOPE_NOT_ENROLLED"):
            first.accept("unapproved", {"scope": "other-host-resource", "delta": 1},
                         "alice", authorized=True)
        with pytest.raises(UnsafeAuthority, match="SCOPE_NOT_ENROLLED"):
            first.claim("unapproved-claim", "other-host-resource", native, authorized=True)
        with pytest.raises(UnsafeAuthority, match="OWNER_SCOPE_MISMATCH"):
            LocalOwner(first.path, OWNER, scopes=("other-host-resource",))
        manifest, _ = first.export_manifest()
        restored = LocalOwner.restore(first, tmp_path / "restored.db",
                                      {**OWNER, "epoch": "44444444-4444-4444-8444-444444444444"},
                                      expected_manifest=manifest, approved=True)
        try:
            assert restored.scopes == frozenset((SCOPE,))
            with pytest.raises(UnsafeAuthority, match="SCOPE_NOT_ENROLLED"):
                restored.accept("unapproved", {"scope": "other-host-resource", "delta": 1},
                                "alice", authorized=True)
        finally:
            restored.close()
    finally:
        first.close()


def test_owner_scope_enrollment_changes_checkpoint_root(tmp_path):
    local = owner(tmp_path / "owner.db", initialize=True)
    try:
        root, _ = local.export_manifest()
        local.db.execute("INSERT INTO enrolled VALUES(?)", ("extra-local-scope",))
        assert local.export_manifest()[0] != root
    finally:
        local.close()


def test_historical_replay_lookup_uses_request_id_index(tmp_path):
    local = owner(tmp_path / "owner.db", initialize=True)
    try:
        # Synthetic retained history: query-plan evidence, not native scale qualification.
        rows = [
            ("prior-origin", f"historical-{i}", b'{}', "alice", "succeeded", "known", i)
            for i in range(10000)
        ]
        with local.db:
            local.db.executemany("INSERT INTO history VALUES(?,?,?,?,?,?,?)", rows)
        plan = local.db.execute(
            "EXPLAIN QUERY PLAN SELECT 1 FROM history WHERE request_id=? LIMIT 1",
            ("missing-id",),
        ).fetchall()
        assert any("SEARCH history USING" in str(row[-1]) and
                   "history_request_id" in str(row[-1]) for row in plan), plan
        with pytest.raises(UnsafeAuthority, match="HISTORICAL_REQUEST_ID"):
            local.accept("historical-9999", SUBJECT, "alice", authorized=True)
        assert local.accept("fresh", SUBJECT, "alice", authorized=True)["state"] == "accepted"
    finally:
        local.close()


def test_handoff_preparation_is_durable_and_fences_old_local_effects(tmp_path):
    path = tmp_path / "native.db"
    native = target(path)
    local = owner(tmp_path / "owner.db", initialize=True)
    next_owner = {**OWNER, "epoch": "55555555-5555-4555-8555-555555555555"}
    try:
        gen = local.claim("old-claim", SCOPE, native, authorized=True)
        local.accept("old-work", SUBJECT, "alice", authorized=True)
        with pytest.raises(UnsafeAuthority, match="HANDOFF_NOT_PREPARED"):
            native.adopt_epoch(next_owner, authorized=True)
        with pytest.raises(UnsafeAuthority, match="LOCAL_PERMISSION_DENIED"):
            native.prepare_handoff(next_owner, authorized=False)
        native.prepare_handoff(next_owner, authorized=True)
        recovered = target(path, initialize=False)
        recovered.prepare_handoff(next_owner, authorized=True)  # Lost prepare reply.
        with pytest.raises(UnsafeAuthority, match="TARGET_HANDOFF_PENDING"):
            native.claim(SCOPE, gen, "stale", "stale-activation", OWNER, authorized=True)
        with pytest.raises(UnsafeAuthority, match="TARGET_HANDOFF_PENDING"):
            native.effect(SCOPE, gen, local.live[SCOPE][1],
                          _effect_id(OWNER, SCOPE, "old-work"), SUBJECT, OWNER,
                          authorized=True)
        with pytest.raises(UnsafeAuthority, match="TARGET_HANDOFF_PENDING"):
            native.close_absent(SCOPE, _effect_id(OWNER, SCOPE, "old-work"),
                                SUBJECT, OWNER, authorized=True)
        recovered.adopt_epoch(next_owner, authorized=True)
        with pytest.raises(UnsafeAuthority, match="TARGET_EPOCH_MISMATCH"):
            native.generation(SCOPE, OWNER, authorized=True)
        successor = LocalEffectTarget(path, next_owner, (SCOPE,))
        assert successor.claim(SCOPE, gen + 1, "new-session", "new-claim", next_owner,
                               authorized=True) == gen + 2
    finally:
        local.close()


def test_prepared_handoff_conflict_or_abort_never_revives_old_session(tmp_path):
    native = target(tmp_path / "native.db")
    old_gen = native.claim(SCOPE, 0, "old-session", "old-activation", OWNER, authorized=True)
    next_owner = {**OWNER, "epoch": "66666666-6666-4666-8666-666666666666"}
    wrong_owner = {**OWNER, "epoch": "77777777-7777-4777-8777-777777777777"}
    native.prepare_handoff(next_owner, authorized=True)
    with pytest.raises(UnsafeAuthority, match="HANDOFF_TARGET_CONFLICT"):
        native.prepare_handoff(wrong_owner, authorized=True)
    with pytest.raises(UnsafeAuthority, match="HANDOFF_NOT_PREPARED"):
        native.adopt_epoch(wrong_owner, authorized=True)
    native.abort_handoff(next_owner, authorized=True)
    with pytest.raises(UnsafeAuthority, match="FENCE_STALE"):
        native.effect(SCOPE, old_gen, "old-session", _effect_id(OWNER, SCOPE, "old-work"),
                      SUBJECT, OWNER, authorized=True)
    assert native.claim(SCOPE, old_gen + 1, "recovery-session", "recovery-claim",
                        OWNER, authorized=True) == old_gen + 2
