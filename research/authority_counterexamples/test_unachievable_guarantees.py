"""INTENTIONALLY FAILING counterexamples; run explicitly, never in standard CI.

These tests assert *false* guarantees. They must fail for the specified reasons.
They are not known bugs in the positive model and must not be made to pass by
weakening resource-side enforcement or fabricating restored-owner identity.
"""

import shutil

from research.authority_reference.model import LocalOwner, TransactionalResource

OWNER = {"tool": "app-ops", "id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "epoch": "cccccccc-cccc-4ccc-8ccc-cccccccccccc"}
SCOPE = "shared-production-resource"


def test_false_guarantee_local_state_detects_its_own_complete_rollback(tmp_path):
    path, backup = tmp_path / "local.db", tmp_path / "old.db"
    local = LocalOwner(path, OWNER, initialize=True)
    local.accept("before", {"scope": SCOPE, "delta": 1}, "alice", authorized=True)
    local.close()
    shutil.copyfile(path, backup)
    changed = LocalOwner(path, OWNER)
    changed.accept("after", {"scope": SCOPE, "delta": 1}, "alice", authorized=True)
    changed.close()
    shutil.copyfile(backup, path)  # valid, internally consistent rollback of local state
    rolled_back = LocalOwner(path, OWNER)
    try:
        assert rolled_back.accepted("after") is not None, "local state cannot detect missing tail"
    finally:
        rolled_back.close()


def test_false_guarantee_identical_cold_clones_can_elect_unique_owner_locally(tmp_path):
    original, cloned = tmp_path / "original.db", tmp_path / "clone.db"
    initial = LocalOwner(original, OWNER, initialize=True)
    initial.close()
    shutil.copyfile(original, cloned)
    a, b = LocalOwner(original, OWNER), LocalOwner(cloned, OWNER)
    try:
        a.accept("a", {"scope": SCOPE, "delta": 1}, "alice", authorized=True)
        b.accept("b", {"scope": SCOPE, "delta": 1}, "bob", authorized=True)
        assert a.accepted("a") is None or b.accepted("b") is None, "both clones independently accepted"
    finally:
        a.close()
        b.close()


def test_false_guarantee_copied_live_writer_session_is_physically_unique(tmp_path):
    resource = TransactionalResource(tmp_path / "resource.db", initialize=True)
    session = "same-live-process-image-and-credential"
    generation = resource.claim(SCOPE, 0, session)
    # Two copies of a running session are observationally identical to this enforcer.
    resource.effect(SCOPE, generation, session, "physical-copy-a", 1)
    resource.effect(SCOPE, generation, session, "physical-copy-b", 1)
    assert resource.value(SCOPE) == 1, "session identity is not physical-process exclusion"


def test_false_guarantee_unreachable_resource_can_authorize_takeover(tmp_path):
    resource = TransactionalResource(tmp_path / "resource.db", initialize=True)
    resource.available = False
    local = LocalOwner(tmp_path / "owner.db", OWNER, initialize=True)
    try:
        local.accept("local-work", {"scope": SCOPE, "delta": 1}, "alice", authorized=True)
        # Local management above is available; exclusive production activation is not.
        assert local.claim("takeover", SCOPE, resource, authorized=True) == 1
    finally:
        local.close()


def test_false_guarantee_lost_reply_proves_external_effect_did_not_happen(tmp_path):
    resource = TransactionalResource(tmp_path / "resource.db", initialize=True)
    local = LocalOwner(tmp_path / "owner.db", OWNER, initialize=True)
    try:
        local.accept("request", {"scope": SCOPE, "delta": 4}, "alice", authorized=True)
        local.claim("writer", SCOPE, resource, authorized=True)
        resource.available = False
        try:
            local.run("request", resource)
        except RuntimeError:
            pass
        # No resource observation is possible. Claiming absence here is impossible.
        assert local.reconcile("request", resource)["certainty"] == "none"
    finally:
        local.close()
