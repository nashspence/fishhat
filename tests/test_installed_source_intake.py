"""Adversarial checks for the installed source-validation witness, not owner admission."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.smoke_installed import check_source_validation
from scripts.validation_timeouts import watchdog
from tests.support import FIXTURES

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/smoke_installed.py",
        "fishhat/cli-support/src/fishhat_cli/validation.py",
    ],
    "scope": "controlled wrong local CLI implementations and complete read-only validation witness",
    "relationship": "scoped-witness",
    "reason": "Actual unprivileged subprocesses must fail the witness for always-accept, always-reject, schema-only, disclosure or changed-input behavior. The maintained installed smoke separately runs the witness against isolated wheel entrypoints; these unit checks do not qualify native owner admission or repository/provider authority.",
    "claims": [],
}


FAKE = """\
import contextlib
import io
import json
import sys
from pathlib import Path
from fishhat_cli import validation

tool, mode = sys.argv[1:3]
args = sys.argv[3:]
if mode == "schema-only":
    validation.validate_domain = lambda *a: None
    validation.validate_host = lambda *a: None
    validation.validate_app = lambda *a: None
if mode == "yaml-unchecked":
    import yaml
    validation.strict_yaml = yaml.safe_load
out, err = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
    if mode == "always-accept":
        print(json.dumps({"tool": tool, "status": "valid", "scope": "local-contracts-only", "production_qualified": False}))
        code = 0
    elif mode == "always-reject":
        print(json.dumps({"tool": tool, "status": "invalid", "error": "INPUT_REJECTED"}), file=sys.stderr)
        code = 2
    else:
        code = validation.main(tool, args)
if mode == "leak-source" and code == 2:
    err.write(args[1])
if mode == "rewrite-source" and code == 0:
    path = Path(args[1])
    path.write_bytes(path.read_bytes() + b" ")
sys.stdout.write(out.getvalue())
sys.stderr.write(err.getvalue())
raise SystemExit(code)
"""


def run_command(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=watchdog(15))


@pytest.mark.parametrize("tool", ["domain-ops", "host-ops", "app-ops"])
@pytest.mark.parametrize(
    "mode,case",
    [
        ("always-accept", "duplicate-key"),
        ("always-reject", "domain"),
        ("schema-only", "domain-source-join"),
        ("leak-source", "duplicate-key"),
        ("rewrite-source", "input-custody"),
        ("yaml-unchecked", "duplicate-yaml-key"),
    ],
)
def test_wrong_source_command_cannot_satisfy_installed_witness(tmp_path, tool, mode, case):
    fake = tmp_path / "wrong_command.py"
    fake.write_text(FAKE)
    with pytest.raises(AssertionError, match="installed source witness failed: " + case):
        check_source_validation(
            [sys.executable, "-I", str(fake), tool, mode], tool, FIXTURES, run_command
        )


@pytest.mark.parametrize("tool", ["domain-ops", "host-ops", "app-ops"])
def test_current_read_only_command_satisfies_complete_witness(tool):
    executable = Path(sys.executable).parent / (tool + ".exe" if sys.platform == "win32" else tool)
    result = check_source_validation([str(executable)], tool, FIXTURES, run_command)
    assert result == {
        "scope": "installed-local-contract-validation-only",
        "tool": tool,
        "valid_cases": 4,
        "invalid_cases": 15,
        "input_bytes_preserved": True,
        "unrelated_canary_preserved": True,
        "native_qualified": False,
    }
