"""Execute smoke diagnostics with unprivileged tools and real watchdog termination."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.validation_timeouts import VARIABLE, watchdog
from tests.support import ROOT

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/ci/native_smoke.sh", "scripts/validation_timeouts.py"],
    "scope": "real shell stage diagnostics, deadline termination, refusal propagation and cleanup with isolated unprivileged external-tool fixtures",
    "relationship": "no-product-claim",
    "reason": "Real GNU timeout kills controlled hung children. Fake package/account tools exercise script failures without privileged native actions or native owner qualification.",
    "claims": [],
}


@pytest.fixture
def fixture_tools(tmp_path):
    tools = tmp_path / "bin"
    tools.mkdir()
    scripts = {
        "python3": f'exec {shlex.quote(sys.executable)} "$@"\n',
        "sudo": '[ "$1" = -n ] && shift\nexec "$@"\n',
        "ps": "echo systemd\n",
        "stat": "echo cgroup2fs\n",
        "id": '[ "$1" = -u ] && [ "$#" = 1 ] && { echo 1000; exit 0; }\nexit 1\n',
        "mktemp": 'mkdir "$NATIVE_FIXTURE/work"\nprintf "%s\\n" "$NATIVE_FIXTURE/work"\n',
        "useradd": 'echo useradd >> "$NATIVE_TRACE"\nexit 23\n',
        "rm": 'echo cleanup-rm >> "$NATIVE_TRACE"\n[ "$NATIVE_MODE" = cleanup-failure ] && exit 31\nexec /bin/rm "$@"\n',
        "apt-get": r"""echo "$*" >> "$NATIVE_TRACE"
for argument in "$@"; do
  if [[ "$argument" == update ]]; then
    case "$NATIVE_MODE" in
      update-failure) exit 17 ;;
      update-hang)
        exec "$NATIVE_PYTHON" -c 'import os,signal,time; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path(os.environ["NATIVE_FIXTURE"],"hung-pid").write_text(str(os.getpid())); time.sleep(60)'
        ;;
    esac
  fi
  if [[ "$argument" == install && "$NATIVE_MODE" == install-failure ]]; then exit 19; fi
done
exit 0
""",
    }
    for name, body in scripts.items():
        executable = tools / name
        executable.write_text("#!/bin/bash\n" + body)
        executable.chmod(0o700)
    return tools


def run_smoke(tmp_path, tools, mode, scale="0.01"):
    environment = {
        "PATH": f"{tools}:/usr/bin:/bin",
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "ImageOS": "ubuntu24",
        "RUNNER_TEMP": str(tmp_path),
        VARIABLE: scale,
        "NATIVE_FIXTURE": str(tmp_path),
        "NATIVE_TRACE": str(tmp_path / "trace"),
        "NATIVE_MODE": mode,
        "NATIVE_PYTHON": sys.executable,
        "NATIVE_TEST_SECRET": "inherited-value-must-stay-private",
    }
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/ci/native_smoke.sh"), "--github-hosted-only"],
        env=environment,
        text=True,
        capture_output=True,
        timeout=watchdog(30),
    )
    assert environment["NATIVE_TEST_SECRET"] not in result.stdout + result.stderr
    return result


@pytest.mark.parametrize(
    "mode,status,stage",
    [("update-failure", 17, "package-update"), ("install-failure", 19, "package-install")],
)
def test_failed_package_stage_records_failure_and_runs_cleanup(
    tmp_path, fixture_tools, mode, status, stage
):
    result = run_smoke(tmp_path, fixture_tools, mode)
    assert result.returncode == status, (result.stdout, result.stderr)
    assert f"stage={stage} status=started" in result.stdout
    assert re.search(
        rf"stage={stage} status=failed exit={status} elapsed_seconds=\d+", result.stdout
    )
    assert "stage=cleanup status=started" in result.stdout
    assert "stage=cleanup status=passed exit=0" in result.stdout
    assert "native_tools_qualified" not in result.stdout
    trace = (tmp_path / "trace").read_text()
    assert "Acquire::http::Timeout=1" in trace and "Acquire::https::Timeout=1" in trace
    assert "Acquire::Retries=0" in trace and "DPkg::Lock::Timeout=1" in trace
    assert "useradd" not in trace
    if mode == "update-failure":
        assert " install " not in trace


def test_stage_deadline_kills_term_ignoring_command_and_keeps_failure(tmp_path, fixture_tools):
    result = run_smoke(tmp_path, fixture_tools, "update-hang")
    assert result.returncode in {124, 137}, (result.stdout, result.stderr)
    assert "stage=package-update status=failed" in result.stdout
    assert "stage=cleanup status=passed exit=0" in result.stdout
    pid = int((tmp_path / "hung-pid").read_text())
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    else:
        # An orphan killed with its timeout group can await init's reap; it
        # must not retain an executing process after the shell reports failure.
        assert (Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[0]) == "Z"
    assert " install " not in (tmp_path / "trace").read_text()


@pytest.mark.parametrize(
    "mode,cleanup_status",
    [("account-failure", "passed exit=0"), ("cleanup-failure", "failed exit=1")],
    ids=["cleanup-success", "cleanup-failure"],
)
def test_account_failure_preserves_primary_exit_and_reports_cleanup(
    tmp_path, fixture_tools, mode, cleanup_status
):
    result = run_smoke(tmp_path, fixture_tools, mode, "0.02")
    assert result.returncode == 23, (result.stdout, result.stderr)
    assert "stage=package-update status=passed exit=0" in result.stdout
    assert "stage=package-install status=passed exit=0" in result.stdout
    assert "stage=account status=failed exit=23" in result.stdout
    assert f"stage=cleanup status={cleanup_status}" in result.stdout
    trace = (tmp_path / "trace").read_text()
    assert "useradd" in trace and "cleanup-rm" in trace
    assert (tmp_path / "work").exists() == (mode == "cleanup-failure")
