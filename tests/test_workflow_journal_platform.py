"""Portable imports do not grant unsupported native journal custody."""

import json
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest

from scripts.validation_timeouts import watchdog

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": ["fishhat/owner-support/src/fishhat_owner/workflow_journal.py"],
    "scope": "importable reference storage with explicit refusal of unavailable POSIX custody",
    "relationship": "candidate",
    "reason": "A fresh interpreter without fcntl imports the module and rejects create/open before touching custody. This checks platform behavior without qualifying a native filesystem.",
    "claims": [],
}


@pytest.mark.parametrize("action", ["create", "open"])
def test_journal_without_posix_locking_refuses_custody_before_touching_files(tmp_path, action):
    fixture_path = Path(__file__).resolve().parents[1] / "state/fixtures/v1/workflow-journal.json"
    fixture = json.loads(fixture_path.read_text())
    identity = {"owner": fixture["owner"], "schema": fixture["schema"]}
    probe = dedent(
        """
        import importlib.abc
        import json
        import sys
        from pathlib import Path

        class MissingPosixLocking(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "fcntl":
                    raise ModuleNotFoundError("fcntl unavailable", name=fullname)

        sys.modules.pop("fcntl", None)
        sys.meta_path.insert(0, MissingPosixLocking())
        from fishhat_owner.workflow_journal import WorkflowJournal
        from fishhat_contracts.validation import ContractError

        directory, action, encoded_identity = sys.argv[1:]
        path = Path(directory) / "journal"
        identity = json.loads(encoded_identity)
        arguments = identity if action == "create" else {
            "expected_owner": identity["owner"],
            "expected_schema": identity["schema"],
        }
        try:
            getattr(WorkflowJournal, action)(path, **arguments)
        except ContractError as error:
            assert str(error) == "workflow journal requires POSIX file custody"
        else:
            raise AssertionError("unsupported custody was accepted")
        assert list(Path(directory).iterdir()) == []
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", probe, str(tmp_path), action, json.dumps(identity)],
        capture_output=True,
        text=True,
        timeout=watchdog(20),
    )
    assert result.returncode == 0, result.stderr
    assert list(tmp_path.iterdir()) == []
