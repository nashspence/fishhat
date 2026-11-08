"""Deliberately FALSE local-only guarantees; run separately and expect failures.

These are counterexamples, not regressions to make green. An owner-local
architecture cannot distinguish full host clones or a fully rolled-back
journal without independent protected evidence. Nor can a copyable live
session prove physical process exclusivity. No off-host authority is assumed.
"""

import shutil

from research.authority_reference.model import LocalEffectTarget, LocalOwner, _effect_id

OWNER = {
    "tool": "app-ops",
    "id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "epoch": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
}
SCOPE = "local-application:orders"
INTENT = {"scope": SCOPE, "delta": 1}


def test_false_guarantee_local_state_detects_its_own_complete_rollback(tmp_path):
    current, backup = tmp_path / "local.db", tmp_path / "old.db"
    original = LocalOwner(current, OWNER, initialize=True, scopes=(SCOPE,))
    original.accept("before", INTENT, "alice", authorized=True)
    original.close()
    shutil.copyfile(current, backup)
    updated = LocalOwner(current, OWNER)
    updated.accept("after", INTENT, "alice", authorized=True)
    updated.close()
    shutil.copyfile(backup, current)
    rolled_back = LocalOwner(current, OWNER)
    try:
        assert rolled_back.accepted("after") is not None, "local data cannot detect a missing tail"
    finally:
        rolled_back.close()


def test_false_guarantee_identical_cold_clones_elect_unique_owner_locally(tmp_path):
    first_path, copy_path = tmp_path / "a.db", tmp_path / "b.db"
    initial = LocalOwner(first_path, OWNER, initialize=True, scopes=(SCOPE,))
    initial.close()
    shutil.copyfile(first_path, copy_path)
    a, b = LocalOwner(first_path, OWNER), LocalOwner(copy_path, OWNER)
    try:
        a.accept("a", INTENT, "alice", authorized=True)
        b.accept("b", INTENT, "bob", authorized=True)
        assert a.accepted("a") is None or b.accepted("b") is None, "both locally accept"
    finally:
        a.close()
        b.close()


def test_false_guarantee_copied_live_session_proves_physical_uniqueness(tmp_path):
    native = LocalEffectTarget(tmp_path / "target.db", OWNER, (SCOPE,), initialize=True)
    same_session = "copyable-live-process-credential"
    generation = native.claim(SCOPE, 0, same_session, "activation", OWNER, authorized=True)
    native.effect(SCOPE, generation, same_session, _effect_id(OWNER, SCOPE, "physical-a"),
                  INTENT, OWNER, authorized=True)
    native.effect(SCOPE, generation, same_session, _effect_id(OWNER, SCOPE, "physical-b"),
                  INTENT, OWNER, authorized=True)
    assert native.value(SCOPE) == 1, "idempotency does not exclude two physical processes"


def test_false_guarantee_unavailable_local_target_can_authorize_effect(tmp_path):
    native = LocalEffectTarget(tmp_path / "target.db", OWNER, (SCOPE,), initialize=True)
    native.available = False
    local = LocalOwner(tmp_path / "owner.db", OWNER, initialize=True, scopes=(SCOPE,))
    try:
        local.accept("offline-local-work", INTENT, "alice", authorized=True)
        assert local.claim("takeover", SCOPE, native, authorized=True) == 1
    finally:
        local.close()


def test_false_guarantee_lost_reply_proves_effect_absent(tmp_path):
    native = LocalEffectTarget(tmp_path / "target.db", OWNER, (SCOPE,), initialize=True)
    local = LocalOwner(tmp_path / "owner.db", OWNER, initialize=True, scopes=(SCOPE,))
    try:
        local.accept("request", {**INTENT, "delta": 4}, "alice", authorized=True)
        local.claim("activation", SCOPE, native, authorized=True)
        native.available = False
        try:
            local.run("request", native, authorized=True)
        except RuntimeError:
            pass
        assert local.reconcile("request", native, authorized=True)["certainty"] == "none"
    finally:
        local.close()


def test_false_guarantee_full_host_clones_have_unique_global_writer(tmp_path):
    """Two independent machines with copied local authority can both write."""
    a_dir, b_dir = tmp_path / "machine-a", tmp_path / "machine-b"
    a_dir.mkdir()
    b_dir.mkdir()
    initial = LocalOwner(a_dir / "owner.db", OWNER, initialize=True, scopes=(SCOPE,))
    initial.close()
    LocalEffectTarget(a_dir / "target.db", OWNER, (SCOPE,), initialize=True)
    shutil.copyfile(a_dir / "owner.db", b_dir / "owner.db")
    shutil.copyfile(a_dir / "target.db", b_dir / "target.db")
    a, b = LocalOwner(a_dir / "owner.db", OWNER), LocalOwner(b_dir / "owner.db", OWNER)
    native_a = LocalEffectTarget(a_dir / "target.db", OWNER, (SCOPE,))
    native_b = LocalEffectTarget(b_dir / "target.db", OWNER, (SCOPE,))
    try:
        for local, native in [(a, native_a), (b, native_b)]:
            local.accept("same", INTENT, "alice", authorized=True)
            local.claim("activation", SCOPE, native, authorized=True)
            assert local.run("same", native, authorized=True) == 1
        assert native_a.value(SCOPE) + native_b.value(SCOPE) == 1, "clones each write locally"
    finally:
        a.close()
        b.close()
