"""Local continuity capabilities at the reference journal boundary, not native qualification."""

import socket
from contextlib import closing, contextmanager

import pytest
from fishhat_contracts.validation import ContractError
from fishhat_owner.workflow_journal import WorkflowJournal

from tests.test_workflow_journal import store_identity
from tests.workflow_journal_support import LogicalWorkload, WorkMeter

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json#/$defs/ProtocolRules",
        "fishhat/owner-support/src/fishhat_owner/workflow_journal.py",
    ],
    "scope": "reference local admission/replay, authorized restart, cross-copy exclusion and preserved custody on unavailable or stale independent continuity",
    "relationship": "candidate",
    "reason": "Real journal/HEAD files exercise commissioned callback boundaries with network connection attempts forbidden. Independently retained in-memory authority simulates the protected local failure domain; it does not qualify authentication, physical fencing, power loss or whole-authority rollback detection.",
    "claims": [],
}


@pytest.fixture
def disconnected(monkeypatch):
    def refuse(*args, **kwargs):
        pytest.fail("local owner operation attempted an off-host authority connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def custody(path):
    return path.read_bytes(), path.with_name(path.name + ".head").read_bytes()


def restore_bytes(path, snapshot):
    path.write_bytes(snapshot[0])
    path.with_name(path.name + ".head").write_bytes(snapshot[1])


@pytest.mark.parametrize("tool", ["host-ops", "app-ops"])
def test_local_checkpoint_allows_verified_restart_without_remote_authority(
    tmp_path, disconnected, tool
):
    path = tmp_path / "owner.journal"
    owner = {**LogicalWorkload().owner(0), "tool": tool}
    schema, authority = store_identity(), WorkMeter()
    with closing(authority.store(path, owner, schema)) as journal:
        outcome = journal.append(
            "accepted",
            {"request": "local"},
            {"effect": "unknown", "hold": "retained"},
            expected_head=journal.head,
        )
        checkpoint = journal.head
    retained = custody(path)
    # Only journal objects restart. Independent local authority survives outside
    # the restored file set; it is not reconstructed from those files.
    with closing(authority.store(path, owner, schema, restore=True)) as journal:
        assert journal.head == checkpoint == authority.checkpoints[path]
        with pytest.raises(ContractError, match="permission"):
            journal.lookup("accepted", read_authorized=False)
        assert journal.lookup("accepted", read_authorized=True) == outcome
        assert (
            journal.append(
                "accepted",
                {"request": "local"},
                {"effect": "unknown", "hold": "retained"},
                expected_head=checkpoint,
            )
            == outcome
        )
        assert custody(path) == retained
        journal.append("later", {}, {"result": "accepted"}, expected_head=journal.head)
        assert journal.head != checkpoint
        assert authority.checkpoints[path] == journal.head


@pytest.mark.parametrize("authority_state", ["absent", "uncommissioned", "writer-active"])
def test_copied_custody_cannot_supply_its_own_writer_authority(
    tmp_path, disconnected, authority_state
):
    path, copy = tmp_path / "owner.journal", tmp_path / "copied.journal"
    owner, schema, authority = LogicalWorkload().owner(0), store_identity(), WorkMeter()
    with closing(authority.store(path, owner, schema)) as original:
        original.append("accepted", {}, {"effect": "unknown"}, expected_head=original.head)
        snapshot = custody(path)
        restore_bytes(copy, snapshot)
        options = {}
        expected = "independent checkpoint"
        if authority_state == "uncommissioned":
            # Copied owner/epoch and consistent HEAD do not establish continuity
            # in another authority domain, even after the original closes.
            original.close()
            options["writer_lease"] = WorkMeter().writer_lease(copy)
        elif authority_state == "writer-active":
            # The commissioned lease covers the logical journal, not just one
            # pathname/inode. The real file lock on the copy cannot protect it.
            options["writer_lease"] = authority.writer_lease(path)
            expected = "writer already active"
        with pytest.raises(ContractError, match=expected):
            WorkflowJournal.open(copy, expected_owner=owner, expected_schema=schema, **options)
        assert custody(path) == custody(copy) == snapshot


@pytest.mark.parametrize("continuity", ["survives", "unavailable"])
def test_consistent_backup_restore_stays_fenced_without_current_continuity(
    tmp_path, disconnected, continuity
):
    path = tmp_path / "owner.journal"
    owner, schema, authority = LogicalWorkload().owner(0), store_identity(), WorkMeter()
    with closing(authority.store(path, owner, schema)) as journal:
        journal.append("before-backup", {}, {"result": "known"}, expected_head=journal.head)
        backup = custody(path)
        journal.append(
            "after-backup",
            {},
            {"effect": "unknown", "hold": "retained"},
            expected_head=journal.head,
        )
    current_checkpoint = authority.checkpoints[path]
    current_bytes = custody(path)
    restore_bytes(path, backup)
    selected = authority if continuity == "survives" else WorkMeter()
    with pytest.raises(ContractError, match="independent checkpoint"):
        selected.store(path, owner, schema, restore=True)
    # Refusal neither adopts the old HEAD as current nor erases recoverable bytes.
    assert custody(path) == backup
    assert authority.checkpoints[path] == current_checkpoint
    # Supplying the preserved current bytes permits verified restart; the old
    # backup alone could not authorize it or erase the uncertain accepted work.
    restore_bytes(path, current_bytes)
    with closing(authority.store(path, owner, schema, restore=True)) as journal:
        assert journal.lookup("after-backup", read_authorized=True)["outcome"] == {
            "effect": "unknown",
            "hold": "retained",
        }


@pytest.mark.parametrize("tool", ["host-ops", "app-ops"])
@pytest.mark.parametrize("boundary", ["genesis", "reopen", "guard", "publication"])
def test_writer_lease_excludes_copies_through_each_journal_transition(
    tmp_path, disconnected, tool, boundary
):
    path, copied = tmp_path / "owner.journal", tmp_path / "copied.journal"
    canary = tmp_path / "unrelated.bin"
    canary.write_bytes(b"unrelated native state remains outside journal custody")
    canary_bytes = canary.read_bytes()
    owner = {**LogicalWorkload().owner(0), "tool": tool}
    schema, authority = store_identity(), WorkMeter()
    phase, probes, comparisons = "genesis", [], []

    def competing_copy():
        snapshot = custody(path)
        checkpoint_before = authority.checkpoints.get(path)
        restore_bytes(copied, snapshot)
        assert path.stat().st_ino != copied.stat().st_ino
        with pytest.raises(ContractError, match="independent writer already active"):
            with closing(
                WorkflowJournal.open(
                    copied,
                    expected_owner=owner,
                    expected_schema=schema,
                    writer_lease=authority.writer_lease(path),
                )
            ):
                pytest.fail("a copied journal acquired the active logical writer lease")
        assert custody(path) == custody(copied) == snapshot
        assert authority.checkpoints.get(path) == checkpoint_before
        assert canary.read_bytes() == canary_bytes
        probes.append((phase, snapshot))

    @contextmanager
    def commissioned_lease():
        with authority.writer_lease(path) as retain_head:

            def checkpoint(previous, current):
                if phase == boundary:
                    competing_copy()
                comparisons.append((phase, previous, current))
                retain_head(previous, current)

            yield checkpoint

    with closing(
        WorkflowJournal.create(path, owner=owner, schema=schema, writer_lease=commissioned_lease())
    ) as journal:
        genesis = journal.head
        phase = "guard"
        with journal.guard(genesis):
            if phase == boundary:
                competing_copy()
            phase = "publication"
            accepted = journal.append(
                "accepted",
                {"request": "retained"},
                {"effect": "unknown", "hold": "retained"},
                expected_head=genesis,
            )
        committed = journal.head
        assert authority.checkpoints[path] == committed != genesis
        retained = custody(path)

    phase = "reopen"
    with closing(
        WorkflowJournal.open(
            path,
            expected_owner=owner,
            expected_schema=schema,
            writer_lease=commissioned_lease(),
        )
    ) as journal:
        assert journal.head == authority.checkpoints[path] == committed
        assert journal.lookup("accepted", read_authorized=True) == accepted
        assert accepted["outcome"] == {"effect": "unknown", "hold": "retained"}
        assert custody(path) == retained

    assert [probe[0] for probe in probes] == [boundary]
    assert custody(copied) == probes[0][1]
    assert comparisons == [
        ("genesis", None, genesis),
        ("publication", genesis, committed),
        ("reopen", committed, committed),
    ]
    with authority.writer_lease(path) as retained_checkpoint:
        retained_checkpoint(committed, committed)
    assert custody(path) == retained
    assert authority.checkpoints[path] == committed
    assert canary.read_bytes() == canary_bytes
