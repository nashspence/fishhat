"""In-process administrative command mechanics, without native enrollment."""

import json
import os

import pytest
from fishhat_host.cli import main
from fishhat_owner import identity_store

from tests.test_owner_identity_store import OWNER, snapshot
from tests.test_owner_identity_store import enrolled as enrolled

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "fishhat/host-ops/src/fishhat_host/cli.py",
        "fishhat/owner-support/src/fishhat_owner/identity_store.py",
    ],
    "scope": "explicit administrative argument routing, identity/schema checks and private-error redaction",
    "relationship": "candidate",
    "reason": "Imported command functions and replaced administrative enrollment exercise ordinary temporary SQLite files only; actual installed command/runtime/credential custody needs enrolled-guest witnesses.",
    "claims": [],
}


def arguments(action, path, owner=OWNER):
    return [
        "state",
        action,
        str(path),
        "--owner-id",
        owner["id"],
        "--owner-epoch",
        owner["epoch"],
        "--json",
    ]


def test_explicit_initialize_then_inspect_preserves_state(enrolled, capsys):
    path = enrolled()
    assert main(arguments("initialize", path)) == 0
    created = json.loads(capsys.readouterr().out)
    assert created["status"] == "initialized" and created["owner"] == OWNER
    assert created["native_mutations"] is created["production_qualified"] is False
    before = snapshot(path)
    assert main(arguments("inspect", path)) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["status"] == "verified"
    assert inspected["owner"] == created["owner"] and inspected["generation"] == 0
    assert snapshot(path) == before


@pytest.mark.parametrize("change", ["invalid-id", "other-id", "other-epoch"])
def test_identity_errors_do_not_echo_private_paths_or_values(enrolled, capsys, change):
    path = enrolled()
    identity_store.initialize(path, OWNER)
    changed = dict(OWNER)
    if change == "invalid-id":
        changed["id"] = "SYNTHETIC_PRIVATE_SENTINEL"
    elif change == "other-id":
        changed["id"] = "9ae5fa20-bc76-4cd1-8fb0-f278f5cb5666"
    else:
        changed["epoch"] = "e3e17faf-5ab5-424b-bcdf-cb779bcb0b28"
    before = snapshot(path)
    assert main(arguments("inspect", path, changed)) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err) == {
        "tool": "host-ops",
        "status": "invalid",
        "error": "OWNER_STATE_REJECTED",
    }
    assert str(path) not in output.err and "SYNTHETIC_PRIVATE_SENTINEL" not in output.err
    assert snapshot(path) == before


def test_help_and_info_keep_native_operations_unavailable(capsys, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("help/info attempted owner storage access")

    monkeypatch.setattr(identity_store, "_directory", forbidden)
    assert main(["info", "--json"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["capabilities"] == ["local-contract-validation", "owner-state-identity"]
    assert info["native_mutations"] is info["production_qualified"] is False
    with pytest.raises(SystemExit) as stopped:
        main(["state", "--help"])
    assert stopped.value.code == 0
    help_text = capsys.readouterr().out
    assert "initialize" in help_text and "inspect" in help_text
    with pytest.raises(SystemExit) as stopped:
        main(["apply"])
    assert stopped.value.code == 2


def test_unprivileged_command_cannot_initialize(tmp_path, capsys):
    if os.geteuid() == 0:
        pytest.skip("requires an ordinary caller")
    path = tmp_path / "private"
    path.mkdir(mode=0o700)
    assert main(arguments("initialize", path)) == 2
    assert json.loads(capsys.readouterr().err)["error"] == "OWNER_INITIALIZATION_UNCONFIRMED"
    assert not list(path.iterdir())


def test_unconfirmed_publication_is_reconciled_by_inspection_not_reinitialization(
    enrolled, capsys, monkeypatch
):
    path = enrolled()
    original = os.fsync

    def interrupted(descriptor):
        import stat

        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("controlled acknowledgement boundary failure")
        original(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(identity_store.os, "fsync", interrupted)
        assert main(arguments("initialize", path)) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["status"] == "unconfirmed"
    assert error["error"] == "OWNER_INITIALIZATION_UNCONFIRMED"
    before = snapshot(path)
    assert main(arguments("inspect", path)) == 0
    assert json.loads(capsys.readouterr().out)["owner"] == OWNER
    assert snapshot(path) == before
    assert main(arguments("initialize", path)) == 2
    assert json.loads(capsys.readouterr().err)["status"] == "unconfirmed"
    assert snapshot(path) == before


def test_posttransaction_database_failure_retains_attempt_and_redacts_errors(
    enrolled, capsys, monkeypatch
):
    import sqlite3

    path = enrolled()

    def fail(*args, **kwargs):
        raise sqlite3.DatabaseError("SYNTHETIC_PRIVATE_DATABASE_SENTINEL")

    monkeypatch.setattr(identity_store, "_inspect", fail)
    assert main(arguments("initialize", path)) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err)["error"] == "OWNER_INITIALIZATION_UNCONFIRMED"
    assert "SYNTHETIC_PRIVATE_DATABASE_SENTINEL" not in output.err and str(path) not in output.err
    assert (path / identity_store.PENDING).is_file()
    assert not (path / identity_store.DATABASE).exists()
