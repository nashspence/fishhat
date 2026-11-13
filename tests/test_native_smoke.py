"""Execute smoke diagnostics with unprivileged tools and real watchdog termination."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_smoke_observation as observation
from scripts.validation_timeouts import VARIABLE, watchdog
from tests.support import ROOT

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/ci/native_smoke.sh",
        "scripts/native_smoke_observation.py",
        "scripts/validation_timeouts.py",
    ],
    "scope": "owned executable-generator placement, first account transition and selected manager-service environment identity, numeric metadata and fixed safe observations, real shell deadline/failure/cleanup controls with isolated unprivileged external tools",
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
      update-acquisition-failure)
        [[ " $* " == *" --error-on=any "* ]] && exit 100
        ;;
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
    scripts.update(
        {
            "python3": r"""if [[ "$1" == */native_smoke_observation.py ]]; then
  [[ "${2##*/}" == 99-fishhat-probe-2000 ]] || exit 98
  printf '%s\n' 'native-prerequisite generator-observation={"native_qualified": false, "scope": "owned-smoke-generator-observation-only", "status": "observed"}'
  exit 0
fi
exec "$NATIVE_PYTHON" "$@"
""",
            "id": r"""if [[ "$1" == -u && "$#" == 1 ]]; then echo 1000; exit 0; fi
if [[ "$1" == -u && "$2" == dtci1000 && -f "$NATIVE_FIXTURE/account-present" ]]; then echo 2000; exit 0; fi
exit 1
""",
            "useradd": r"""echo useradd >> "$NATIVE_TRACE"
case "$NATIVE_MODE" in
  generator-denied|generator-denied-cleanup-failure|manager-start-failure|executable-generator|generator-denied-access-failure|manager-context-mismatch|generator-directory-unavailable)
    : > "$NATIVE_FIXTURE/account-present"; exit 0 ;;
esac
exit 23
""",
            "grep": r"""for value in "$@"; do
  case "$value" in /etc/subuid|/etc/subgid) exit 0 ;; esac
done
exec /usr/bin/grep "$@"
""",
            "install": 'echo install >> "$NATIVE_TRACE"\nexit 0\n',
            "test": r"""if [[ "$1" == -d && "$2" == /usr/lib/systemd/user-environment-generators ]]; then
  [[ "$NATIVE_MODE" != generator-directory-unavailable ]]; exit "$?"
fi
exec /usr/bin/test "$@"
""",
            "tee": r"""[[ "${1##*/}" == 99-fishhat-probe-2000 ]] || exit 98
printf '%s\n' "$1" > "$NATIVE_FIXTURE/generator-path"
/bin/cat > "$NATIVE_FIXTURE/generator"
""",
            "chmod": r"""[[ "$1" == 0755 && "${2##*/}" == 99-fishhat-probe-2000 ]] || exit 98
exec /bin/chmod "$1" "$NATIVE_FIXTURE/generator"
""",
            "runuser": r"""[[ "$1" == -u && "$2" == dtci1000 ]] || exit 98
while [[ "$#" -gt 0 && "$1" != -- ]]; do shift; done
[[ "$1" == -- ]] || exit 98
shift
case "$1" in
  /bin/sh)
    echo generator-access >> "$NATIVE_TRACE"
    for role in prefix library manager-library generator-directory generator interpreter; do
      probe_execute=allowed
      if [[ "$role" == generator && "$NATIVE_MODE" == generator-denied* ]]; then probe_execute=denied; fi
      printf 'native-prerequisite generator-access role=%s read=allowed execute=%s\n' "$role" "$probe_execute" >&2
    done
    [[ "$NATIVE_MODE" == generator-denied-access-failure ]] && exit 29
    exit 0 ;;
  */99-fishhat-probe-2000)
    echo generator-execute >> "$NATIVE_TRACE"
    if [[ "$1" == /run/* && "$NATIVE_MODE" != manager-start-failure ]]; then exit 1; fi
    case "$NATIVE_MODE" in
      manager-start-failure|executable-generator|manager-context-mismatch|generator-directory-unavailable)
        printf '%s\n' HOME=/home/dtci1000 USER=dtci1000 LOGNAME=dtci1000 PATH=/usr/bin:/bin XDG_RUNTIME_DIR=/run/user/2000
        exit 0 ;;
    esac
    exit 1 ;;
  env)
    shift
    [[ "$1" == -i ]] || exit 98
    shift
    bindings=()
    while [[ "$1" == *=* ]]; do bindings+=("$1"); shift; done
    case "$1" in
      systemd-run)
        echo manager-environment >> "$NATIVE_TRACE"
        while [[ "$#" -gt 0 && "$1" != /usr/bin/printenv ]]; do shift; done
        [[ "$1" == /usr/bin/printenv ]] || exit 98
        shift
        for key do
          found=0
          for binding in "${bindings[@]}"; do
            if [[ "${binding%%=*}" == "$key" ]]; then
              if [[ "$NATIVE_MODE" == manager-context-mismatch && "$key" == HOME ]]; then
                printf '%s\n' unexpected-public-fixture-value
              else
                printf '%s\n' "${binding#*=}"
              fi
              found=1
              break
            fi
          done
          ((found)) || exit 98
        done
        exit 0 ;;
      podman)
        [[ "$2" == system && "$3" == reset ]] && exit 0
        exit 7 ;;
      systemctl) exit 7 ;;
    esac ;;
esac
exit 98
""",
            "loginctl": r"""echo "loginctl-$1" >> "$NATIVE_TRACE"
if [[ "$1" == terminate-user && "$NATIVE_MODE" == generator-denied-cleanup-failure ]]; then exit 29; fi
exit 0
""",
            "systemctl": r"""echo "systemctl-$1" >> "$NATIVE_TRACE"
if [[ "$1" == start && "$NATIVE_MODE" == manager-start-failure ]]; then exit 27; fi
exit 0
""",
            "userdel": 'echo userdel >> "$NATIVE_TRACE"\nexec /bin/rm -f "$NATIVE_FIXTURE/account-present"\n',
            "rm": r"""echo cleanup-rm >> "$NATIVE_TRACE"
[[ "$NATIVE_MODE" == cleanup-failure ]] && exit 31
for value in "$@"; do
  if [[ "${value##*/}" == 99-fishhat-probe-2000 ]]; then
    exec /bin/rm -f "$NATIVE_FIXTURE/generator"
  fi
done
exec /bin/rm "$@"
""",
        }
    )
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
    [
        ("update-failure", 17, "package-update"),
        ("update-acquisition-failure", 100, "package-update"),
        ("install-failure", 19, "package-install"),
    ],
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
    assert "update --error-on=any -qq" in trace
    assert "Acquire::http::Timeout=1" in trace and "Acquire::https::Timeout=1" in trace
    assert "Acquire::Retries=0" in trace and "DPkg::Lock::Timeout=1" in trace
    assert "useradd" not in trace
    if mode in {"update-failure", "update-acquisition-failure"}:
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
    assert "native-prerequisite control=account-create status=failed exit=23" in result.stderr
    assert "stage=package-update status=passed exit=0" in result.stdout
    assert "stage=package-install status=passed exit=0" in result.stdout
    assert "stage=account status=failed exit=23" in result.stdout
    assert f"stage=cleanup status={cleanup_status}" in result.stdout
    trace = (tmp_path / "trace").read_text()
    assert "update --error-on=any -qq" in trace
    assert "useradd" in trace and "cleanup-rm" in trace
    assert (tmp_path / "work").exists() == (mode == "cleanup-failure")


@pytest.mark.parametrize(
    "mode,status,cleanup_status,failed_control",
    [
        ("generator-denied", 1, "passed exit=0", "generator-execute"),
        ("generator-denied-cleanup-failure", 1, "failed exit=1", "generator-execute"),
        ("manager-start-failure", 27, "passed exit=0", "manager-start"),
    ],
    ids=["generator-denied", "generator-denied-cleanup-failure", "manager-start-failure"],
)
def test_partial_account_setup_keeps_named_failure_and_cleanup_evidence(
    tmp_path, fixture_tools, mode, status, cleanup_status, failed_control
):
    unrelated = tmp_path / "unrelated"
    unrelated.write_text("keep")
    result = run_smoke(tmp_path, fixture_tools, mode, "0.1")
    assert result.returncode == status
    assert f"control={failed_control} status=failed exit={status}" in result.stderr
    assert "control=generator-metadata status=passed exit=0" in result.stderr
    assert "control=generator-access status=passed exit=0" in result.stderr
    assert (
        'generator-observation={"native_qualified": false, "scope": "owned-smoke-generator-observation-only", "status": "observed"}'
        in result.stdout
    )
    observed_execute = "allowed" if mode == "manager-start-failure" else "denied"
    assert (
        f"generator-access role=generator read=allowed execute={observed_execute}" in result.stderr
    )
    assert "control=cleanup-user-service-stop status=failed exit=7" in result.stderr
    assert "control=cleanup-account-remove status=passed exit=0" in result.stderr
    assert "control=cleanup-generator-remove status=passed exit=0" in result.stderr
    assert "control=cleanup-work-remove status=passed exit=0" in result.stderr
    assert f"stage=cleanup status={cleanup_status}" in result.stdout
    if mode == "generator-denied-cleanup-failure":
        assert "control=cleanup-terminate-user status=failed exit=29" in result.stderr
    assert "stage=rootless-runtime" not in result.stdout
    assert not (tmp_path / "work").exists()
    assert not (tmp_path / "generator").exists()
    assert not (tmp_path / "account-present").exists()
    assert unrelated.read_text() == "keep"


@pytest.mark.parametrize("noexec", [False, True])
def test_metadata_records_mode_owner_type_and_mount_fact(tmp_path, monkeypatch, noexec):
    file = tmp_path / "private-fixture-value"
    file.write_bytes(b"private-content-not-an-observation")
    file.chmod(0o750)
    monkeypatch.setattr(
        observation.os,
        "statvfs",
        lambda _: SimpleNamespace(f_flag=os.ST_NOEXEC if noexec else 0),
    )
    result = observation.observe_path("generator", file)
    assert result == {
        "role": "generator",
        "status": "observed",
        "mode": 0o750,
        "uid": os.getuid(),
        "gid": os.getgid(),
        "directory": False,
        "regular": True,
        "symlink": False,
        "target_mode": 0o750,
        "target_regular": True,
        "mount_noexec": noexec,
    }
    assert "private" not in json.dumps(result)
    assert file.read_bytes() == b"private-content-not-an-observation"


def test_symlink_and_target_metadata_stay_distinct(tmp_path):
    file = tmp_path / "target"
    file.write_text("keep")
    file.chmod(0o700)
    link = tmp_path / "link"
    link.symlink_to(file)
    result = observation.observe_path("interpreter", link)
    assert result["symlink"] is True and result["regular"] is False
    assert result["target_regular"] is True and result["target_mode"] == 0o700
    assert file.read_text() == "keep" and link.is_symlink()


@pytest.mark.parametrize("failure", ["missing", "denied", "malformed"])
def test_unavailable_metadata_is_explicit_and_never_exposes_payload(tmp_path, monkeypatch, failure):
    file = tmp_path / "private-fixture-value"
    if failure != "missing":
        file.write_text("keep")
    if failure == "denied":

        def denied(_):
            raise PermissionError("private-fixture-value")

        monkeypatch.setattr(observation.os, "statvfs", denied)
    if failure == "malformed":
        monkeypatch.setattr(
            observation.os, "statvfs", lambda _: SimpleNamespace(f_flag="private-fixture-value")
        )
    result = observation.observe_path("generator", file)
    assert result == {
        "role": "generator",
        "status": "unavailable",
        "reason": "metadata-unavailable",
    }
    assert "private" not in json.dumps(result)


def test_all_owned_roles_are_observed_once_without_inventing_missing_evidence(monkeypatch):
    calls = []

    def observed(role, path):
        calls.append((role, path))
        return {"role": role, "status": "unavailable" if role == "generator" else "observed"}

    monkeypatch.setattr(observation, "observe_path", observed)
    file = Path("/usr/lib/systemd/user-environment-generators/99-fishhat-probe-2000")
    result = observation.observe_generator(file)
    assert [role for role, _ in calls] == [
        "prefix",
        "library",
        "manager-library",
        "generator-directory",
        "generator",
        "interpreter",
    ]
    assert [path for _, path in calls] == [
        Path("/usr"),
        Path("/usr/lib"),
        Path("/usr/lib/systemd"),
        file.parent,
        file,
        Path("/bin/sh"),
    ]
    assert result["status"] == "unavailable" and result["native_qualified"] is False


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["private-fixture-value"],
        ["/tmp/99-fishhat-probe-1"],
        ["/usr/lib/systemd/user-environment-generators/private-fixture-value"],
    ],
)
def test_cli_refuses_unowned_paths_before_inspection(arguments, monkeypatch, capsys):
    def forbidden(_):
        pytest.fail("unowned path reached metadata inspection")

    monkeypatch.setattr(observation, "observe_generator", forbidden)
    assert observation.main(arguments) == 1
    logs = capsys.readouterr()
    assert logs.err == "" and "private-fixture-value" not in logs.out
    assert json.loads(logs.out.split("=", 1)[1]) == {
        "status": "unavailable",
        "reason": "owned-generator-path-required",
    }


@pytest.mark.parametrize("status", ["observed", "unavailable"])
def test_cli_retains_observation_status_without_native_claim(monkeypatch, capsys, status):
    value = {
        "scope": "owned-smoke-generator-observation-only",
        "status": status,
        "native_qualified": False,
    }
    monkeypatch.setattr(observation, "observe_generator", lambda _: dict(value))
    assert observation.main(
        ["/usr/lib/systemd/user-environment-generators/99-fishhat-probe-2000"]
    ) == (0 if status == "observed" else 1)
    logs = capsys.readouterr()
    assert logs.err == "" and json.loads(logs.out.split("=", 1)[1]) == value


def test_generator_uses_executable_lookup_storage_and_first_account_transition(
    tmp_path, fixture_tools
):
    result = run_smoke(tmp_path, fixture_tools, "executable-generator", "0.1")
    assert "stage=account status=passed exit=0" in result.stdout
    assert "stage=rootless-runtime status=failed" in result.stdout
    assert (tmp_path / "generator-path").read_text().strip() == (
        "/usr/lib/systemd/user-environment-generators/99-fishhat-probe-2000"
    )
    trace = (tmp_path / "trace").read_text().splitlines()
    assert trace.index("generator-execute") < trace.index("generator-access")
    assert trace.index("generator-access") < trace.index("manager-environment")
    assert "control=manager-environment-check status=passed exit=0" in result.stderr
    assert not (tmp_path / "generator").exists()
    assert not (tmp_path / "account-present").exists()


@pytest.mark.parametrize("mode", ["generator-denied", "generator-denied-access-failure"])
def test_first_generator_transition_keeps_primary_failure_after_follow_on_observation(
    tmp_path, fixture_tools, mode
):
    result = run_smoke(tmp_path, fixture_tools, mode, "0.1")
    assert result.returncode == 1
    trace = (tmp_path / "trace").read_text().splitlines()
    assert trace.index("generator-execute") < trace.index("generator-access")
    assert "control=generator-execute status=failed exit=1" in result.stderr
    if mode == "generator-denied-access-failure":
        assert "control=generator-access status=failed exit=29" in result.stderr
    assert "stage=account status=failed exit=1" in result.stdout
    assert "systemctl-start" not in trace and "manager-environment" not in trace


def test_manager_environment_mismatch_refuses_before_rootless_work(tmp_path, fixture_tools):
    result = run_smoke(tmp_path, fixture_tools, "manager-context-mismatch", "0.1")
    assert result.returncode == 1
    assert "control=manager-environment-check status=failed exit=1" in result.stderr
    assert "stage=account status=failed exit=1" in result.stdout
    assert "stage=rootless-runtime" not in result.stdout
    assert "unexpected-public-fixture-value" not in result.stdout + result.stderr


def test_missing_generator_lookup_directory_refuses_without_shared_directory_changes(
    tmp_path, fixture_tools
):
    result = run_smoke(tmp_path, fixture_tools, "generator-directory-unavailable", "0.1")
    assert result.returncode == 1
    assert "control=generator-directory-check status=failed exit=1" in result.stderr
    assert "control=generator-write" not in result.stderr
    assert "generator-execute" not in (tmp_path / "trace").read_text().splitlines()
    assert "stage=rootless-runtime" not in result.stdout
