"""Portable executable proof obligations for a test-only owner/resource model."""

from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from research.authority_reference.model import LocalOwner, TransactionalResource, UnsafeAuthority

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "research/authority_reference/model.py",
        "fishhat/owner-support/src/fishhat_owner/journal.py",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/Owner",
    ],
    "scope": "test-only portable local accepted-work persistence and resource-side atomic fencing model",
    "relationship": "candidate",
    "reason": "These SQLite reference scenarios exercise an isolated serialized resource and separate owner databases, not native SSH, filesystem, OS, multi-host enforcement, or power-loss qualification.",
    "claims": [],
}

OWNER = {"tool": "app-ops", "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "epoch": "11111111-1111-4111-8111-111111111111"}
SCOPE = "database:orders"


def owner(path: Path, *, epoch: str = "11111111-1111-4111-8111-111111111111", initialize: bool = False) -> LocalOwner:
    return LocalOwner(path, {**OWNER, "epoch": epoch}, initialize=initialize)


def test_local_acceptance_and_replay_without_resource_or_client(tmp_path):
    journal = tmp_path / "owner.db"
    resource = TransactionalResource(tmp_path / "resource.db", initialize=True)
    resource.available = False
    first = owner(journal, initialize=True)
    subject = {"scope": SCOPE, "delta": 3}
    original = first.accept("request-1", subject, "alice", authorized=True)
    with pytest.raises(UnsafeAuthority, match="LOCAL_PERMISSION_DENIED"):
        first.accept("request-2", subject, "mallory", authorized=False)
    with pytest.raises(UnsafeAuthority, match="REQUEST_ID_CONFLICT"):
        first.accept("request-1", {**subject, "delta": 4}, "alice", authorized=True)
    assert original["principal"] == "alice"
    first.close()
    restarted = owner(journal)
    try:
        assert restarted.accept("request-1", subject, "bob", authorized=True) == original
        assert restarted.accept("request-3", subject, "alice", authorized=True)["state"] == "accepted"
        with pytest.raises(UnsafeAuthority, match="RESOURCE_UNAVAILABLE"):
            restarted.claim("activate-1", SCOPE, resource, authorized=True)
    finally:
        restarted.close()


def test_effect_is_journaled_unknown_before_native_dispatch_and_reconciled(tmp_path):
    local = tmp_path / "owner.db"
    external = TransactionalResource(tmp_path / "resource.db", initialize=True)
    first = owner(local, initialize=True)
    first.accept("e-1", {"scope": SCOPE, "delta": 7}, "alice", authorized=True)
    generation = first.claim("activation-1", SCOPE, external, authorized=True)
    assert generation == 1

    class ReplyLost:
        def effect(self, *args):
            value = external.effect(*args)
            assert value == 7
            raise ConnectionError("reply lost after resource commit")

    with pytest.raises(ConnectionError, match="reply lost"):
        first.run("e-1", ReplyLost())
    assert first.accepted("e-1")["state"] == "dispatched"
    assert first.accepted("e-1")["certainty"] == "unknown"
    first.close()  # simulates process death and the loss of its live session
    fresh = owner(local)
    try:
        with pytest.raises(UnsafeAuthority, match="RECONCILIATION_REQUIRED"):
            fresh.run("e-1", external)
        assert fresh.reconcile("e-1", external)["state"] == "succeeded"
        assert fresh.accepted("e-1")["certainty"] == "known"
        assert fresh.run("e-1", external) == 7  # exact replay; no second effect
        assert external.value(SCOPE) == 7
        with pytest.raises(UnsafeAuthority, match="REACTIVATION_REQUIRED"):
            fresh.claim("activation-1", SCOPE, external, authorized=True)
    finally:
        fresh.close()


def test_unknown_before_external_execution_is_never_inferred_absent(tmp_path):
    external = TransactionalResource(tmp_path / "resource.db", initialize=True)
    local = owner(tmp_path / "owner.db", initialize=True)
    try:
        local.accept("e-1", {"scope": SCOPE, "delta": 2}, "alice", authorized=True)
        local.claim("activation", SCOPE, external, authorized=True)
        external.available = False
        with pytest.raises(UnsafeAuthority, match="RESOURCE_UNAVAILABLE"):
            local.run("e-1", external)
        assert local.accepted("e-1")["state"] == "dispatched"
        with pytest.raises(UnsafeAuthority, match="RESOURCE_UNAVAILABLE"):
            local.reconcile("e-1", external)
        external.available = True
        with pytest.raises(UnsafeAuthority, match="EFFECT_UNRESOLVED"):
            local.reconcile("e-1", external)
        closed = local.close_absent("e-1", external)
        assert closed["state"] == "failed" and closed["certainty"] == "none"
        with pytest.raises(UnsafeAuthority, match="EFFECT_PERMANENTLY_CLOSED"):
            external.effect(SCOPE, 1, local.live[SCOPE][1], "e-1", 2)
        assert external.value(SCOPE) == 0
    finally:
        local.close()


def test_cloned_owner_files_have_independent_management_but_stale_effects_fail(tmp_path):
    external = TransactionalResource(tmp_path / "resource.db", initialize=True)
    primary_file, copy_file = tmp_path / "primary.db", tmp_path / "copy.db"
    original = owner(primary_file, initialize=True)
    original.accept("historical", {"scope": SCOPE, "delta": 1}, "alice", authorized=True)
    original.close()
    shutil.copyfile(primary_file, copy_file)  # exact owner-state clone, same epoch and keys
    a, b = owner(primary_file), owner(copy_file)
    try:
        assert a.accepted("historical") == b.accepted("historical")
        assert a.claim("activation-a", SCOPE, external, authorized=True) == 1
        assert b.claim("activation-b", SCOPE, external, authorized=True) == 2
        a.accept("local-a", {"scope": SCOPE, "delta": 6}, "alice", authorized=True)
        b.accept("local-b", {"scope": SCOPE, "delta": 9}, "bob", authorized=True)
        with pytest.raises(UnsafeAuthority, match="FENCE_STALE"):
            a.run("local-a", external)
        assert a.accepted("local-a")["state"] == "dispatched"
        assert b.run("local-b", external) == 9
        assert external.value(SCOPE) == 9
        # The source owner can still inspect and accept *local* management work.
        assert a.accept("new-local", {"scope": SCOPE, "delta": 1}, "alice", authorized=True)
        assert a.close_absent("local-a", external)["state"] == "failed"
    finally:
        a.close()
        b.close()


def test_fence_claim_compare_and_swap_is_atomic(tmp_path):
    external = TransactionalResource(tmp_path / "resource.db", initialize=True)
    def attempt(session):
        try:
            return external.claim(SCOPE, 0, session)
        except UnsafeAuthority as exc:
            return str(exc)
    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(attempt, (f"session-{i}" for i in range(8))))
    assert results.count(1) == 1
    assert results.count("FENCE_STALE") == 7
    assert external.generation(SCOPE) == 1


def test_resource_effect_identity_is_atomic_even_with_duplicate_delivery(tmp_path):
    external = TransactionalResource(tmp_path / "resource.db", initialize=True)
    gen = external.claim(SCOPE, 0, "session")
    with ThreadPoolExecutor(max_workers=6) as workers:
        values = list(workers.map(
            lambda _: external.effect(SCOPE, gen, "session", "e-1", 4), range(6)
        ))
    assert values == [4] * 6
    assert external.value(SCOPE) == 4
    with pytest.raises(UnsafeAuthority, match="EFFECT_ID_CONFLICT"):
        external.effect(SCOPE, gen, "session", "e-1", 5)


def test_explicit_restore_new_epoch_keeps_history_but_no_old_execution(tmp_path):
    external = TransactionalResource(tmp_path / "resource.db", initialize=True)
    source = owner(tmp_path / "original.db", initialize=True)
    destination = tmp_path / "restored.db"
    try:
        source.accept("old-request", {"scope": SCOPE, "delta": 5}, "alice", authorized=True)
        source.claim("original-activation", SCOPE, external, authorized=True)
        assert source.run("old-request", external) == 5
        manifest, _ = source.export_manifest()
        with pytest.raises(UnsafeAuthority, match="RESTORED_EPOCH_REUSED"):
            LocalOwner.restore(source, destination, OWNER, expected_manifest=manifest, approved=True)
        with pytest.raises(UnsafeAuthority, match="RESTORE_MANIFEST_MISMATCH"):
            LocalOwner.restore(
                source, destination, {**OWNER, "epoch": "22222222-2222-4222-8222-222222222222"},
                expected_manifest="sha256:" + "0" * 64, approved=True,
            )
        restored = LocalOwner.restore(
            source, destination, {**OWNER, "epoch": "22222222-2222-4222-8222-222222222222"},
            expected_manifest=manifest, approved=True,
        )
        try:
            historical = restored.db.execute(
                "SELECT state,certainty,principal FROM history WHERE request_id='old-request'"
            ).fetchone()
            assert historical == ("succeeded", "known", "alice")
            assert restored.accepted("old-request") is None
            with pytest.raises(UnsafeAuthority, match="HISTORICAL_REQUEST_ID"):
                restored.accept(
                    "old-request", {"scope": SCOPE, "delta": 5}, "alice", authorized=True
                )
            restored.accept("recovery-request", {"scope": SCOPE, "delta": 2}, "alice", authorized=True)
            with pytest.raises(UnsafeAuthority, match="FENCE_NOT_ACTIVATED"):
                restored.run("recovery-request", external)
            assert restored.claim("successor-activation", SCOPE, external, authorized=True) == 2
            assert restored.run("recovery-request", external) == 7
        finally:
            restored.close()
    finally:
        source.close()


def test_missing_journal_is_not_new_empty_state(tmp_path):
    with pytest.raises(UnsafeAuthority, match="OWNER_STATE_MISSING"):
        owner(tmp_path / "lost.db")
    with pytest.raises(UnsafeAuthority, match="RESOURCE_MISSING"):
        TransactionalResource(tmp_path / "lost-resource.db")


def test_multiple_restores_preserve_every_origin_without_reusing_epoch(tmp_path):
    first = owner(tmp_path / "first.db", initialize=True)
    first.accept("first-work", {"scope": SCOPE, "delta": 1}, "alice", authorized=True)
    one_manifest, _ = first.export_manifest()
    second = LocalOwner.restore(
        first, tmp_path / "second.db", {**OWNER, "epoch": "22222222-2222-4222-8222-222222222222"},
        expected_manifest=one_manifest, approved=True,
    )
    second.accept("second-work", {"scope": SCOPE, "delta": 2}, "alice", authorized=True)
    second_manifest, _ = second.export_manifest()
    third = LocalOwner.restore(
        second, tmp_path / "third.db", {**OWNER, "epoch": "33333333-3333-4333-8333-333333333333"},
        expected_manifest=second_manifest, approved=True,
    )
    try:
        origins = third.db.execute(
            "SELECT request_id,state FROM history ORDER BY request_id"
        ).fetchall()
        assert origins == [("first-work", "accepted"), ("second-work", "accepted")]
        with pytest.raises(UnsafeAuthority, match="RESTORED_EPOCH_REUSED"):
            LocalOwner.restore(
                third, tmp_path / "reused.db", {**OWNER, "epoch": "11111111-1111-4111-8111-111111111111"},
                expected_manifest=third.export_manifest()[0], approved=True,
            )
    finally:
        first.close()
        second.close()
        third.close()


def test_effect_reconciliation_rejects_same_id_from_different_resource_scope(tmp_path):
    external = TransactionalResource(tmp_path / "resource.db", initialize=True)
    local = owner(tmp_path / "owner.db", initialize=True)
    try:
        local.accept("e-1", {"scope": SCOPE, "delta": 2}, "alice", authorized=True)
        local.claim("activation", SCOPE, external, authorized=True)
        external.available = False
        with pytest.raises(UnsafeAuthority, match="RESOURCE_UNAVAILABLE"):
            local.run("e-1", external)
        external.available = True
        other = "database:another-instance"
        external.effect(other, external.claim(other, 0, "other"), "other", "e-1", 2)
        with pytest.raises(UnsafeAuthority, match="EFFECT_ID_CONFLICT"):
            local.reconcile("e-1", external)
        assert local.accepted("e-1")["state"] == "dispatched"
    finally:
        local.close()
