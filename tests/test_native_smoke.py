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

from scripts import native_smoke_cleanup as cleanup_observation
from scripts import native_smoke_observation as observation
from scripts.validation_timeouts import VARIABLE, watchdog
from tests.support import ROOT

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/ci/native_smoke.sh",
        "scripts/native_smoke_observation.py",
        "scripts/native_smoke_cleanup.py",
        "scripts/validation_timeouts.py",
    ],
    "scope": "owned executable-generator placement, first account transition and selected manager-service environment identity, numeric metadata, independent exact account cleanup and fresh identity/state-guided conditional owned teardown through typed facility/process/filesystem observations, failure preservation and shared deadlines and real shell failure controls with isolated unprivileged tools",
    "relationship": "no-product-claim",
    "reason": "Real GNU timeout kills controlled hung children. Fake package/account tools and isolated facility/filesystem observations exercise failures and leftover-state refusal without privileged native actions or native owner qualification.",
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
            "python3": r"""if [[ "$1" == -m && "$2" == scripts.native_smoke_cleanup && "$3" == teardown-state ]]; then
  echo teardown-state >> "$NATIVE_TRACE"
  if [[ ! -f "$NATIVE_FIXTURE/account-present" ]]; then
    echo 'absent absent absent absent absent absent absent'; exit 0
  fi
  manager=absent; login=absent; linger=absent
  case "$NATIVE_MODE" in
    executable-generator|manager-context-mismatch|manager-start-failure)
      if [[ ! -f "$NATIVE_FIXTURE/managers-stopped" ]]; then
        manager=present; login=present; linger=present
      fi ;;
    generator-denied-cleanup-failure) login=present ;;
  esac
  echo "owned $manager $manager $login $linger absent absent"
  exit 0
fi
if [[ "$1" == -m && "$2" == scripts.native_smoke_cleanup ]]; then
  printf '%s\n' 'native-prerequisite cleanup-observation={"complete_absence_verified": true, "native_qualified": false, "scope": "owned-smoke-cleanup-observation-only", "status": "absent"}'
  exit 0
fi
if [[ "$1" == */native_smoke_observation.py ]]; then
  [[ "${2##*/}" == 99-fishhat-probe-2000 ]] || exit 98
  printf '%s\n' 'native-prerequisite generator-observation={"native_qualified": false, "scope": "owned-smoke-generator-observation-only", "status": "observed"}'
  exit 0
fi
exec "$NATIVE_PYTHON" "$@"
""",
            "id": r"""if [[ "$1" == -u && "$#" == 1 ]]; then echo 1000; exit 0; fi
if [[ ( "$1" == -u || "$1" == -g ) && "$2" == dtci1000 && -f "$NATIVE_FIXTURE/account-present" ]]; then echo 2000; exit 0; fi
if [[ "$1" == -gn && "$2" == dtci1000 && -f "$NATIVE_FIXTURE/account-present" ]]; then echo dtci1000; exit 0; fi
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
[[ "$1" == stop ]] && : > "$NATIVE_FIXTURE/managers-stopped"
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


def run_smoke(tmp_path, tools, mode, scale="0.01", *, code=None):
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
        (
            ["bash", "-c", code]
            if code is not None
            else ["bash", str(ROOT / "scripts/ci/native_smoke.sh"), "--github-hosted-only"]
        ),
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
    assert "control=cleanup-user-service-stop" not in result.stderr
    assert "control=cleanup-state-initial status=passed exit=0" in result.stderr
    if mode == "generator-denied-cleanup-failure":
        assert "control=cleanup-account-remove" not in result.stderr
    else:
        assert "control=cleanup-account-remove status=passed exit=0" in result.stderr
    assert "control=cleanup-generator-remove status=passed exit=0" in result.stderr
    assert "control=cleanup-work-remove status=passed exit=0" in result.stderr
    assert f"stage=cleanup status={cleanup_status}" in result.stdout
    if mode == "generator-denied-cleanup-failure":
        assert "control=cleanup-terminate-user status=failed exit=29" in result.stderr
    assert "stage=rootless-runtime" not in result.stdout
    assert not (tmp_path / "work").exists()
    assert not (tmp_path / "generator").exists()
    assert (tmp_path / "account-present").exists() is (mode == "generator-denied-cleanup-failure")
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


@pytest.mark.parametrize("observation_status", ["absent", "present", "unavailable"])
def test_cleanup_requires_independent_observation_without_masking_primary_failure(
    tmp_path, fixture_tools, observation_status
):
    executable = fixture_tools / "python3"
    original = executable.read_text()
    status = 0 if observation_status == "absent" else 1
    output = json.dumps(
        {
            "scope": "owned-smoke-cleanup-observation-only",
            "status": observation_status,
            "complete_absence_verified": observation_status == "absent",
            "native_qualified": False,
        },
        sort_keys=True,
    )
    body = (
        'if [[ "$1" == -m && "$2" == scripts.native_smoke_cleanup && "$3" == observe ]]; then\n'
        '  echo independent-cleanup-observer >> "$NATIVE_TRACE"\n'
        f"  printf '%s\\n' {shlex.quote('native-prerequisite cleanup-observation=' + output)}\n"
        f"  exit {status}\nfi\n"
    )
    executable.write_text(original.replace("#!/bin/bash\n", "#!/bin/bash\n" + body, 1))
    unrelated = tmp_path / "unrelated"
    unrelated.write_text("keep")
    result = run_smoke(tmp_path, fixture_tools, "generator-denied", "0.1")
    assert result.returncode == 1
    assert "control=generator-execute status=failed exit=1" in result.stderr
    assert "independent-cleanup-observer" in (tmp_path / "trace").read_text().splitlines()
    outcome = "passed exit=0" if observation_status == "absent" else "failed exit=1"
    assert f"control=cleanup-observation status={outcome}" in result.stderr
    assert f"stage=cleanup status={outcome}" in result.stdout
    assert "cleanup-observation=" + output in result.stdout
    assert unrelated.read_text() == "keep"


@pytest.fixture
def cleanup_system(tmp_path, monkeypatch):
    paths = cleanup_observation.Paths(
        **{
            name: tmp_path / name
            for name in ("proc", "etc", "run", "home", "var", "usr", "sys", "tmp")
        }
    )
    for path in vars(paths).values():
        path.mkdir()
    for path in (
        paths.proc / "self",
        paths.var / "lib/systemd",
        paths.usr / "lib/systemd/user-environment-generators",
        paths.sys / "fs/cgroup",
    ):
        path.mkdir(parents=True, exist_ok=True)
    (paths.proc / "self/status").write_text("Uid:\t0 0 0 0\nGid:\t0 0 0 0\n")
    (paths.sys / "fs/cgroup/cgroup.controllers").write_text("cpu memory pids\n")
    for name in ("subuid", "subgid"):
        (paths.etc / name).write_text("unrelated:400000:65536\n")
    identity = cleanup_observation.Identity(
        "dtci1000", 2000, 2000, Path("/tmp/fishhat-native.ABCD1234")
    )

    def query(command, end):
        if command[0] == "/usr/bin/getent":
            database, key = command[1:]
            if key == "0":
                return (
                    0,
                    "root:x:0:0:root:/root:/bin/sh\n" if database == "passwd" else "root:x:0:\n",
                )
            return 2, ""
        if command[0] == "/usr/bin/busctl":
            return 0, json.dumps({"type": "a(uso)", "data": [[]]})
        assert command[0] == "/usr/bin/systemctl"
        return 0, "LoadState=loaded\nActiveState=inactive\n"

    monkeypatch.setattr(cleanup_observation, "query", query)
    return SimpleNamespace(paths=paths, identity=identity, query=query)


def cleanup_once(system):
    return cleanup_observation.observe_once(
        system.identity, cleanup_observation.Deadline.after(10).end, system.paths
    )


def test_cleanup_observer_checks_actual_empty_owned_state_and_preserves_unrelated_files(
    cleanup_system,
):
    system = cleanup_system
    canary = system.paths.home / "unrelated"
    canary.write_text("private-fixture-value")
    result = cleanup_once(system)
    assert result["status"] == "absent" and result["complete_absence_verified"] is True
    assert result["native_qualified"] is False
    roles = [r["role"] for r in result["observations"]]
    assert len(roles) == len(set(roles)) == 19
    assert all(r["status"] == "absent" for r in result["observations"])
    assert canary.read_text() == "private-fixture-value"
    assert "private-fixture-value" not in json.dumps(result)
    assert (system.paths.etc / "subuid").read_text() == "unrelated:400000:65536\n"


@pytest.mark.parametrize(
    "role",
    [
        "home",
        "runtime-directory",
        "linger",
        "generator",
        "work",
        "user-cgroup",
        "runtime-properties",
        "transient-slice",
        "transient-slice-properties",
        "broken-owned-link",
    ],
)
def test_cleanup_observer_refuses_each_leftover_owned_path(cleanup_system, role):
    system = cleanup_system
    paths = cleanup_observation.owned_paths(system.identity, system.paths)
    path = paths["work" if role == "broken-owned-link" else role]
    path.parent.mkdir(parents=True, exist_ok=True)
    if role == "broken-owned-link":
        path.symlink_to("private-fixture-value")
    else:
        path.write_text("private-fixture-value")
    result = cleanup_once(system)
    assert result["status"] == "present" and result["complete_absence_verified"] is False
    assert (
        next(
            r
            for r in result["observations"]
            if r["role"] == ("work" if role == "broken-owned-link" else role)
        )["status"]
        == "present"
    )
    assert "private-fixture-value" not in json.dumps(result)
    assert (
        path.is_symlink()
        if role == "broken-owned-link"
        else path.read_text() == "private-fixture-value"
    )


@pytest.mark.parametrize("kind", ["Uid", "Gid"])
@pytest.mark.parametrize("index", [0, 1, 2, 3])
def test_cleanup_observer_checks_real_effective_saved_and_filesystem_credentials(
    cleanup_system, kind, index
):
    system = cleanup_system
    process = system.paths.proc / "42"
    process.mkdir()
    rows = {"Uid": [3000] * 4, "Gid": [3000] * 4}
    rows[kind][index] = 2000
    (process / "status").write_text(
        "\n".join(k + ": " + " ".join(map(str, v)) for k, v in rows.items()) + "\n"
    )
    result = cleanup_once(system)
    assert result["status"] == "present" and result["complete_absence_verified"] is False
    assert (
        next(r for r in result["observations"] if r["role"] == "process-credentials")["status"]
        == "present"
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"type": "v", "data": [[]]},
        {"type": "a(uso)", "data": []},
        {"type": "a(uso)", "data": [[None]]},
        {"type": "a(uso)", "data": [[[True, "private-fixture-value", "/x"]]]},
        {"type": "a(uso)", "data": [[[3000, "private-fixture-value", "invalid"]]]},
        {
            "type": "a(uso)",
            "data": [
                [[3000, "private-fixture-value", "/x"], [3000, "private-fixture-value", "/x"]]
            ],
        },
    ],
)
def test_cleanup_observer_refuses_malformed_typed_login_observations(
    cleanup_system, monkeypatch, payload
):
    system = cleanup_system
    monkeypatch.setattr(
        cleanup_observation,
        "query",
        lambda command, end: (
            (0, json.dumps(payload))
            if command[0] == "/usr/bin/busctl"
            else system.query(command, end)
        ),
    )
    result = cleanup_once(system)
    assert result["status"] == "unavailable" and result["complete_absence_verified"] is False
    assert (
        next(r for r in result["observations"] if r["role"] == "login-user")["status"]
        == "unavailable"
    )
    assert "private-fixture-value" not in json.dumps(result)


@pytest.mark.parametrize(
    "kind",
    [
        "name-service",
        "login-manager",
        "system-manager",
        "process-status",
        "process-permission",
        "process-self",
        "cgroup-controllers",
        "generator-parent",
        "subuid",
        "subgid",
    ],
)
def test_cleanup_observer_missing_facility_is_never_absence(cleanup_system, monkeypatch, kind):
    system = cleanup_system
    if kind in {"name-service", "login-manager", "system-manager"}:
        executable = {
            "name-service": "getent",
            "login-manager": "busctl",
            "system-manager": "systemctl",
        }[kind]
        monkeypatch.setattr(
            cleanup_observation,
            "query",
            lambda command, end: (
                (9, "private-fixture-value")
                if command[0] == "/usr/bin/" + executable
                else system.query(command, end)
            ),
        )
    elif kind in {"process-status", "process-permission"}:
        process = system.paths.proc / "42"
        process.mkdir()
        (process / "status").write_text("Uid: 3000\nGid: 3000 3000 3000 3000\n")
        if kind == "process-permission":
            real = cleanup_observation.credentials

            def denied(path):
                if path == process / "status":
                    raise PermissionError("private-fixture-value")
                return real(path)

            monkeypatch.setattr(cleanup_observation, "credentials", denied)
    elif kind == "process-self":
        (system.paths.proc / "self/status").unlink()
    elif kind == "cgroup-controllers":
        (system.paths.sys / "fs/cgroup/cgroup.controllers").unlink()
    elif kind == "generator-parent":
        (system.paths.usr / "lib/systemd/user-environment-generators").rmdir()
    else:
        (system.paths.etc / kind).unlink()
    result = cleanup_once(system)
    assert result["status"] == "unavailable" and result["complete_absence_verified"] is False
    assert "private-fixture-value" not in json.dumps(result)


@pytest.mark.parametrize("directory_remains", [False, True])
def test_cleanup_observer_distinguishes_process_exit_race_from_missing_status(
    cleanup_system, monkeypatch, directory_remains
):
    system = cleanup_system
    directory = system.paths.proc / "42"
    directory.mkdir()
    original = cleanup_observation.credentials

    def disappeared(path):
        if path == directory / "status":
            if not directory_remains:
                directory.rmdir()
            raise FileNotFoundError("private-fixture-value")
        return original(path)

    monkeypatch.setattr(cleanup_observation, "credentials", disappeared)
    result = cleanup_once(system)
    assert result["status"] == ("unavailable" if directory_remains else "absent")
    assert result["complete_absence_verified"] is (not directory_remains)


@pytest.mark.parametrize(
    "database,key",
    [("passwd", "dtci1000"), ("passwd", "2000"), ("group", "dtci1000"), ("group", "2000")],
)
def test_cleanup_observer_checks_both_name_and_numeric_resolution(
    cleanup_system, monkeypatch, database, key
):
    system = cleanup_system
    reply = (
        "dtci1000:x:2000:2000:private-fixture-value:/home/dtci1000:/bin/sh\n"
        if database == "passwd"
        else "dtci1000:x:2000:private-fixture-value\n"
    )
    monkeypatch.setattr(
        cleanup_observation,
        "query",
        lambda command, end: (
            (0, reply)
            if command == ["/usr/bin/getent", database, key]
            else system.query(command, end)
        ),
    )
    result = cleanup_once(system)
    assert result["status"] == "present" and result["complete_absence_verified"] is False
    assert "private-fixture-value" not in json.dumps(result)


@pytest.mark.parametrize(
    "kind", ["mode", "account", "uid", "gid", "work", "expired", "infinite", "huge", "missing"]
)
def test_cleanup_observer_cli_refuses_invalid_identity_before_reading_native_state(
    monkeypatch, capsys, kind
):
    arguments = [
        "observe",
        "dtci1000",
        "2000",
        "2000",
        "/tmp/fishhat-native.ABCD1234",
        str(cleanup_observation.Deadline.after(10).end),
    ]
    changes = {
        "mode": (0, "private-fixture-value"),
        "account": (1, "private-fixture-value"),
        "uid": (2, "0"),
        "gid": (3, "0"),
        "work": (4, "/tmp/private-fixture-value"),
        "expired": (5, "0"),
        "infinite": (5, "inf"),
        "huge": (5, "1e300"),
    }
    if kind == "missing":
        arguments.pop()
    else:
        index, value = changes[kind]
        arguments[index] = value
    monkeypatch.setattr(cleanup_observation.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        cleanup_observation,
        "observe",
        lambda *_: pytest.fail("invalid identity reached native observation"),
    )
    assert cleanup_observation.main(arguments) == 1
    logs = capsys.readouterr()
    assert logs.err == "" and "private-fixture-value" not in logs.out
    assert json.loads(logs.out.split("=", 1)[1])["complete_absence_verified"] is False


def test_cleanup_observer_settlement_reuses_one_deadline_and_never_retries_unavailable(monkeypatch):
    identity = cleanup_observation.Identity(
        "dtci1000", 2000, 2000, Path("/tmp/fishhat-native.ABCD1234")
    )
    values = iter([{"status": "present"}, {"status": "absent"}])
    calls = []
    sleeps = []

    def observed(actual, end):
        calls.append((actual, end))
        return next(values)

    monkeypatch.setattr(cleanup_observation, "observe_once", observed)
    monkeypatch.setattr(cleanup_observation, "time", SimpleNamespace(sleep=sleeps.append))
    end = cleanup_observation.Deadline.after(10).end
    assert cleanup_observation.observe(identity, end)["status"] == "absent"
    assert calls == [(identity, end), (identity, end)] and sleeps == [0.25]
    calls.clear()
    monkeypatch.setattr(
        cleanup_observation,
        "observe_once",
        lambda actual, end: calls.append((actual, end)) or {"status": "unavailable"},
    )
    assert cleanup_observation.observe(identity, end)["status"] == "unavailable"
    assert calls == [(identity, end)] and sleeps == [0.25]


@pytest.mark.parametrize("owned_match", ["uid", "name", "neither"])
def test_cleanup_observer_filters_valid_login_records_without_disclosing_them(
    cleanup_system, monkeypatch, owned_match
):
    system = cleanup_system
    row = [
        2000 if owned_match == "uid" else 3000,
        "dtci1000" if owned_match == "name" else "private-fixture-value",
        "/org/freedesktop/login1/user/_3000",
    ]
    monkeypatch.setattr(
        cleanup_observation,
        "query",
        lambda command, end: (
            (0, json.dumps({"type": "a(uso)", "data": [[row]]}))
            if command[0] == "/usr/bin/busctl"
            else system.query(command, end)
        ),
    )
    result = cleanup_once(system)
    assert result["status"] == ("absent" if owned_match == "neither" else "present")
    assert result["complete_absence_verified"] is (owned_match == "neither")
    assert "private-fixture-value" not in json.dumps(result)


@pytest.mark.parametrize(
    "unit",
    ["user" + "@" + "2000.service", "user-runtime-dir" + "@" + "2000.service"],
    ids=["user-manager", "runtime-manager"],
)
@pytest.mark.parametrize("state", ["active", "activating", "deactivating", "failed"])
def test_cleanup_observer_requires_both_user_units_to_be_inactive(
    cleanup_system, monkeypatch, unit, state
):
    system = cleanup_system
    monkeypatch.setattr(
        cleanup_observation,
        "query",
        lambda command, end: (
            (0, "LoadState=loaded\nActiveState=" + state + "\n")
            if command[0] == "/usr/bin/systemctl" and unit in command
            else system.query(command, end)
        ),
    )
    result = cleanup_once(system)
    assert result["status"] == "present" and result["complete_absence_verified"] is False


@pytest.mark.parametrize("name", ["subuid", "subgid"])
def test_cleanup_observer_refuses_leftover_subordinate_mapping_without_changing_neighbors(
    cleanup_system, name
):
    system = cleanup_system
    file = system.paths.etc / name
    text = file.read_text() + "dtci1000:500000:65536\n"
    file.write_text(text)
    result = cleanup_once(system)
    assert result["status"] == "present" and result["complete_absence_verified"] is False
    assert file.read_text() == text


@pytest.mark.parametrize("reply", [(0, ""), (0, "private-fixture-value"), (2, "")])
def test_cleanup_observer_requires_valid_name_service_health_control(
    cleanup_system, monkeypatch, reply
):
    system = cleanup_system
    monkeypatch.setattr(
        cleanup_observation,
        "query",
        lambda command, end: (
            reply
            if command[:3] == ["/usr/bin/getent", "passwd", "0"]
            else system.query(command, end)
        ),
    )
    result = cleanup_once(system)
    assert result["status"] == "unavailable" and result["complete_absence_verified"] is False
    assert "private-fixture-value" not in json.dumps(result)


def test_cleanup_observer_cli_emits_only_observed_exact_scope(cleanup_system, monkeypatch, capsys):
    system = cleanup_system
    end = cleanup_observation.Deadline.after(10).end
    seen = []

    def observed(identity, actual_end):
        seen.append((identity, actual_end))
        return cleanup_observation.observe_once(identity, actual_end, system.paths)

    monkeypatch.setattr(cleanup_observation.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cleanup_observation, "observe", observed)
    assert (
        cleanup_observation.main(
            ["observe", "dtci1000", "2000", "2000", "/tmp/fishhat-native.ABCD1234", str(end)]
        )
        == 0
    )
    assert seen == [(system.identity, end)]
    output = capsys.readouterr()
    value = json.loads(output.out.split("=", 1)[1])
    assert output.err == "" and value["complete_absence_verified"] is True
    assert value["native_qualified"] is False and len(value["observations"]) == 19
    assert "dtci1000" not in output.out and "ABCD1234" not in output.out


def test_cleanup_observer_uses_only_read_only_noninteractive_facility_calls(
    cleanup_system, monkeypatch
):
    system = cleanup_system
    calls = []

    def observed(command, end):
        calls.append(command)
        return system.query(command, end)

    monkeypatch.setattr(cleanup_observation, "query", observed)
    assert cleanup_once(system)["complete_absence_verified"] is True
    assert len(calls) == 9
    for command in calls:
        if command[0] == "/usr/bin/getent":
            assert command[1] in {"passwd", "group"}
            assert command[2] in {"0", "dtci1000", "2000"} and len(command) == 3
        elif command[0] == "/usr/bin/busctl":
            assert command[-1] == "ListUsers" and "call" in command
            assert "--system" in command and "--json=short" in command
            assert (
                "--auto-start=no" in command and "--allow-interactive-authorization=no" in command
            )
        else:
            assert command[:4] == ["/usr/bin/systemctl", "--no-pager", "--no-ask-password", "show"]
            assert command[4] in {
                "user" + "@" + "2000.service",
                "user-runtime-dir" + "@" + "2000.service",
            }


def test_cleanup_query_reconstructs_shared_end_without_rescaling_or_launching_after_expiry(
    monkeypatch,
):
    constructed = []
    calls = []
    remaining = [1.25]

    class SuppliedDeadline:
        def __init__(self, end):
            constructed.append(end)

        def remaining(self):
            return remaining[0]

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="captured-only")

    monkeypatch.setattr(cleanup_observation, "Deadline", SuppliedDeadline)
    monkeypatch.setattr(cleanup_observation.subprocess, "run", run)
    assert cleanup_observation.query(["read-only-fixture"], 98765.25) == (0, "captured-only")
    assert constructed == [98765.25]
    assert calls == [
        (["read-only-fixture"], {"capture_output": True, "text": True, "timeout": 1.25})
    ]
    remaining[0] = 0
    with pytest.raises(ValueError, match="observation-deadline-expired"):
        cleanup_observation.query(["read-only-fixture"], 98765.25)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "owned,revert_status",
    [(False, 0), (True, 0), (True, 37)],
    ids=["foreign-untouched", "owned-reverted", "revert-failed"],
)
def test_normal_cleanup_reverts_only_claimed_slice_properties_and_keeps_failure(
    tmp_path, fixture_tools, owned, revert_status
):
    tool = fixture_tools / "systemctl"
    text = tool.read_text()
    stub = """while [[ "${1:-}" == --quiet ]]; do shift; done
if [[ "$1" == revert ]]; then
  [[ "$#" == 2 && "$2" == user-2000.slice ]] || exit 98
  echo owned-slice-revert >> "$NATIVE_TRACE"
  [[ "$NATIVE_MODE" == slice-revert-failure ]] && exit 37
  /bin/rm -f "$NATIVE_FIXTURE/slice-properties"
  exit 0
fi
"""
    tool.write_text(text.replace("#!/bin/bash\n", "#!/bin/bash\n" + stub, 1))
    source = (ROOT / "scripts/ci/native_smoke.sh").read_text()
    functions = source[source.index("probe_stage=") : source.index("trap cleanup EXIT")]
    code = (
        "set -euo pipefail\n"
        + "timeout_helper="
        + shlex.quote(str(ROOT / "scripts/validation_timeouts.py"))
        + "\n"
        + "kill_timeout=1\n"
        + functions
        + '\nwork="$NATIVE_FIXTURE/work"; mkdir "$work"\n'
        + "account_created=1; saved_uid=2000; saved_gid=2000; uid=2000\n"
        + f"slice_properties_owned={int(owned)}\n"
        + "trap cleanup EXIT\nexit 0\n"
    )
    (tmp_path / "account-present").touch()
    properties = tmp_path / "slice-properties"
    properties.write_text("owned" if owned else "foreign")
    unrelated = tmp_path / "unrelated"
    unrelated.write_text("keep")
    result = run_smoke(
        tmp_path,
        fixture_tools,
        "slice-revert-failure" if revert_status else "generator-denied",
        "0.1",
        code=code,
    )
    assert result.returncode == (1 if revert_status else 0)
    trace = (tmp_path / "trace").read_text().splitlines()
    assert ("owned-slice-revert" in trace) is owned
    assert properties.exists() is (not owned or revert_status != 0)
    assert unrelated.read_text() == "keep"
    if revert_status:
        assert "control=cleanup-slice-properties status=failed exit=37" in result.stderr
        assert "stage=cleanup status=failed exit=1" in result.stdout


@pytest.fixture
def slice_system(cleanup_system, monkeypatch):
    system = cleanup_system
    for root in (system.paths.etc / "systemd", system.paths.run / "systemd"):
        root.mkdir(parents=True, exist_ok=True)
    previous = system.query

    def query(command, end):
        if command[0] == "/usr/bin/systemctl" and "--property=Id" in command:
            assert command[:4] == ["/usr/bin/systemctl", "--no-pager", "--no-ask-password", "show"]
            assert command[4] == "user-2000.slice"
            return 0, "Id=user-2000.slice\n"
        return previous(command, end)

    monkeypatch.setattr(cleanup_observation, "query", query)
    system.query = query
    return system


@pytest.mark.parametrize(
    "role",
    [
        "persistent-unit",
        "persistent-dropins",
        "persistent-control-unit",
        "persistent-control-dropins",
        "runtime-unit",
        "runtime-dropins",
        "runtime-control-unit",
        "runtime-control-dropins",
        "broken-config-link",
    ],
)
def test_slice_configuration_custody_refuses_every_foreign_override_and_preserves_it(
    slice_system, role
):
    system = slice_system
    files = cleanup_observation.configuration_paths(system.identity, system.paths)
    path = files["runtime-control-dropins" if role == "broken-config-link" else role]
    path.parent.mkdir(parents=True, exist_ok=True)
    if role == "broken-config-link":
        path.symlink_to("private-fixture-value")
    else:
        path.write_text("private-fixture-value")
    result = cleanup_observation.configuration_clear(
        system.identity, cleanup_observation.Deadline.after(10).end, system.paths
    )
    assert result["status"] == "present" and result["complete_absence_verified"] is False
    assert result["canonical_unit_verified"] is True
    assert (
        path.is_symlink()
        if role == "broken-config-link"
        else path.read_text() == "private-fixture-value"
    )
    assert "private-fixture-value" not in json.dumps(result)


@pytest.mark.parametrize(
    "reply",
    [(9, "private-fixture-value"), (0, "Id=other.slice\n"), (0, "")],
    ids=["unavailable", "alias", "missing-identity"],
)
def test_slice_configuration_custody_requires_exact_canonical_unit(
    slice_system, monkeypatch, reply
):
    system = slice_system
    monkeypatch.setattr(cleanup_observation, "query", lambda *_: reply)
    result = cleanup_observation.configuration_clear(
        system.identity, cleanup_observation.Deadline.after(10).end, system.paths
    )
    assert result["status"] == "unavailable" and result["complete_absence_verified"] is False
    assert result["canonical_unit_verified"] is False
    assert "private-fixture-value" not in json.dumps(result)


def test_slice_configuration_custody_preserves_unrelated_instance_and_template_files(slice_system):
    system = slice_system
    other = system.paths.run / "systemd/system.control/user-3000.slice.d/control.conf"
    template = system.paths.etc / "systemd/system/user-.slice.d/control.conf"
    for path in (other, template):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("keep")
    result = cleanup_observation.configuration_clear(
        system.identity, cleanup_observation.Deadline.after(10).end, system.paths
    )
    assert result["complete_absence_verified"] is True and result["canonical_unit_verified"] is True
    assert result["native_qualified"] is False and len(result["observations"]) == 8
    assert all(r["status"] == "absent" for r in result["observations"])
    assert all(path.read_text() == "keep" for path in (other, template))


def test_slice_configuration_cli_keeps_custody_observer_read_only(
    slice_system, monkeypatch, capsys
):
    system = slice_system
    end = cleanup_observation.Deadline.after(10).end
    original = cleanup_observation.configuration_clear
    monkeypatch.setattr(cleanup_observation.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        cleanup_observation,
        "configuration_clear",
        lambda identity, actual_end: original(identity, actual_end, system.paths),
    )
    assert (
        cleanup_observation.main(
            [
                "configuration-clear",
                "dtci1000",
                "2000",
                "2000",
                "/tmp/fishhat-native.ABCD1234",
                str(end),
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert output.err == "" and output.out.startswith(
        "native-prerequisite slice-configuration-observation="
    )
    value = json.loads(output.out.split("=", 1)[1])
    assert value["complete_absence_verified"] is True and value["canonical_unit_verified"] is True
    assert value["native_qualified"] is False and value["observer_uid"] == 0
    assert len(value["observations"]) == 8 and "dtci1000" not in output.out


def install_teardown_state_stub(tools, words, *, status=0, settle=False):
    executable = tools / "python3"
    original = executable.read_text()
    settled = "owned absent absent absent absent absent absent"
    branch = (
        'if [[ "$1" == -m && "$2" == scripts.native_smoke_cleanup && "$3" == teardown-state ]]; then\n'
        '  echo teardown-state >> "$NATIVE_TRACE"\n'
        f"  result={shlex.quote(words)}\n"
        + (
            f'  [[ -f "$NATIVE_FIXTURE/managers-stopped" ]] && result={shlex.quote(settled)}\n'
            if settle
            else ""
        )
        + '  printf "%s\\n" "$result"\n'
        + f"  exit {status}\nfi\n"
    )
    executable.write_text(original.replace("#!/bin/bash\n", "#!/bin/bash\n" + branch, 1))


def test_state_aware_partial_cleanup_never_opens_absent_user_bus(tmp_path, fixture_tools):
    install_teardown_state_stub(fixture_tools, "owned absent absent absent absent absent absent")
    canary = tmp_path / "unrelated"
    canary.write_text("keep")
    result = run_smoke(tmp_path, fixture_tools, "generator-denied", "0.1")
    assert result.returncode == 1
    trace = (tmp_path / "trace").read_text().splitlines()
    assert "control=cleanup-user-service-stop" not in result.stderr
    assert "loginctl-terminate-user" not in trace and "systemctl-stop" not in trace
    assert "loginctl-disable-linger" not in trace
    assert trace.count("teardown-state") >= 2
    assert "userdel" in trace and "stage=cleanup status=passed exit=0" in result.stdout
    assert not (tmp_path / "account-present").exists()
    assert not (tmp_path / "generator").exists() and not (tmp_path / "work").exists()
    assert canary.read_text() == "keep"


def test_state_aware_unavailable_facility_cannot_authorize_account_removal(tmp_path, fixture_tools):
    install_teardown_state_stub(fixture_tools, "", status=41)
    result = run_smoke(tmp_path, fixture_tools, "generator-denied", "0.1")
    assert result.returncode == 1
    assert "control=generator-execute status=failed exit=1" in result.stderr
    assert "stage=cleanup status=failed exit=1" in result.stdout
    trace = (tmp_path / "trace").read_text().splitlines()
    assert "userdel" not in trace and (tmp_path / "account-present").is_file()
    assert not (tmp_path / "generator").exists() and not (tmp_path / "work").exists()
    assert "control=cleanup-observation" in result.stderr


def test_state_aware_owned_service_stop_failure_remains_blocking(tmp_path, fixture_tools):
    install_teardown_state_stub(
        fixture_tools, "owned present present present present present absent", settle=True
    )
    systemctl = fixture_tools / "systemctl"
    systemctl.write_text(
        systemctl.read_text().replace(
            "#!/bin/bash\n",
            '#!/bin/bash\n[[ "$1" == stop ]] && : > "$NATIVE_FIXTURE/managers-stopped"\n',
            1,
        )
    )
    source = (ROOT / "scripts/ci/native_smoke.sh").read_text()
    functions = source[source.index("probe_stage=") : source.index("trap cleanup EXIT")]
    code = (
        "set -euo pipefail\n"
        + "timeout_helper="
        + shlex.quote(str(ROOT / "scripts/validation_timeouts.py"))
        + "\nkill_timeout=1\n"
        + functions
        + '\nwork="$NATIVE_FIXTURE/work"; mkdir "$work"\n'
        + "account_created=1; saved_uid=2000; saved_gid=2000; uid=2000\n"
        + "user_service_attempted=1; podman_attempted=0\n"
        + "trap cleanup EXIT\nexit 0\n"
    )
    (tmp_path / "account-present").touch()
    result = run_smoke(tmp_path, fixture_tools, "generator-denied", "0.1", code=code)
    assert "control=cleanup-user-service-stop status=failed exit=7" in result.stderr
    assert result.returncode == 1
    assert "stage=cleanup status=failed exit=1" in result.stdout
    assert "control=cleanup-account-remove status=passed exit=0" in result.stderr
    assert not (tmp_path / "account-present").exists() and not (tmp_path / "work").exists()


@pytest.fixture
def teardown_system(cleanup_system, monkeypatch):
    system = cleanup_system
    previous = system.query
    calls = []

    def query(command, end):
        calls.append((command, end))
        if command[0] == "/usr/bin/getent" and command[2] != "0":
            return (
                0,
                "dtci1000:x:2000:2000::/home/dtci1000:/bin/bash\n"
                if command[1] == "passwd"
                else "dtci1000:x:2000:\n",
            )
        if command[0] == "/usr/sbin/runuser":
            assert "-i" in command and "--no-ask-password" in command
            if command[-1] == "--property=Version":
                return 0, "Version=255\n"
            return (
                0,
                "LoadState=loaded\nActiveState=inactive\nFragmentPath=/run/user/2000/systemd/generator/ci-probe.service\n",
            )
        return previous(command, end)

    monkeypatch.setattr(cleanup_observation, "query", query)
    system.query, system.calls = query, calls
    return system


@pytest.mark.parametrize("manager", [False, True], ids=["absent-manager", "present-manager"])
@pytest.mark.parametrize(
    "attempted", [False, True], ids=["unattempted-service", "attempted-service"]
)
def test_teardown_state_queries_user_service_only_with_owned_attempt_and_live_manager(
    teardown_system, monkeypatch, manager, attempted
):
    system = teardown_system

    def query(command, end):
        if command[0] == "/usr/bin/systemctl" and command[4].startswith("user@"):
            system.calls.append((command, end))
            return 0, "LoadState=loaded\nActiveState=" + (
                "active" if manager else "inactive"
            ) + "\n"
        return system.query(command, end)

    monkeypatch.setattr(cleanup_observation, "query", query)
    end = cleanup_observation.Deadline.after(10).end
    result = cleanup_observation.teardown_state(system.identity, end, attempted, system.paths)
    assert result["state_verified"] is True and result["account"] == "owned"
    assert result["states"]["manager"] is manager
    assert result["states"]["service_stop_required"] is False
    assert any(c[0][0] == "/usr/sbin/runuser" for c in system.calls) is (manager and attempted)
    assert all(actual_end == end for _, actual_end in system.calls)
    assert result["native_qualified"] is False
    assert "dtci1000" not in json.dumps(result) and "2000" not in json.dumps(result)


@pytest.mark.parametrize(
    "conflict",
    [
        "uid",
        "gid",
        "home",
        "shell",
        "group",
        "members",
        "numeric-account",
        "numeric-group",
        "missing-account",
        "missing-group",
    ],
)
def test_teardown_state_refuses_conflicting_identity_before_other_facilities(
    teardown_system, monkeypatch, conflict
):
    system = teardown_system
    replacements = {
        "uid": ("passwd", "dtci1000", 2, "2001"),
        "gid": ("passwd", "dtci1000", 3, "2001"),
        "home": ("passwd", "dtci1000", 5, "/home/unrelated"),
        "shell": ("passwd", "dtci1000", 6, "/bin/sh"),
        "group": ("group", "dtci1000", 2, "2001"),
        "members": ("group", "dtci1000", 3, "unrelated"),
        "numeric-account": ("passwd", "2000", 0, "unrelated"),
        "numeric-group": ("group", "2000", 0, "unrelated"),
    }

    def query(command, end):
        status, text = system.query(command, end)
        if command[0] == "/usr/bin/getent":
            if conflict == "missing-account" and command[1:] == ["passwd", "dtci1000"]:
                return 2, ""
            if conflict == "missing-group" and command[1:] == ["group", "dtci1000"]:
                return 2, ""
            if conflict in replacements:
                database, key, position, value = replacements[conflict]
                if command[1:] == [database, key]:
                    fields = text.strip().split(":")
                    fields[position] = value
                    return status, ":".join(fields) + "\n"
        return status, text

    monkeypatch.setattr(cleanup_observation, "query", query)
    result = cleanup_observation.teardown_state(
        system.identity, cleanup_observation.Deadline.after(10).end, True, system.paths
    )
    assert result["state_verified"] is False and result["failed_role"] == "account-custody"
    assert all(command[0] == "/usr/bin/getent" for command, _ in system.calls)
    assert "unrelated" not in json.dumps(result) and "dtci1000" not in json.dumps(result)


@pytest.mark.parametrize("kind", ["account-absent", "process-present", "process-unavailable"])
def test_teardown_state_distinguishes_absence_owned_processes_and_unavailable_observer(
    teardown_system, monkeypatch, kind
):
    system = teardown_system
    if kind == "account-absent":
        monkeypatch.setattr(cleanup_observation, "owned_account_state", lambda *_: "absent")
    elif kind == "process-present":
        proc = system.paths.proc / "1234"
        proc.mkdir()
        (proc / "status").write_text("Uid:\t0 0 0 2000\nGid:\t0 0 0 0\n")
    else:
        (system.paths.proc / "self/status").write_text("private-fixture-value")
    result = cleanup_observation.teardown_state(
        system.identity, cleanup_observation.Deadline.after(10).end, False, system.paths
    )
    if kind == "process-unavailable":
        assert result["state_verified"] is False and result["failed_role"] == "process-credentials"
    else:
        assert result["state_verified"] is True
        assert result["account"] == ("absent" if kind == "account-absent" else "owned")
        assert result["states"]["processes"] is (kind == "process-present")
    assert "private-fixture-value" not in json.dumps(result)


@pytest.mark.parametrize("conflict", ["numeric", "name"])
def test_teardown_state_refuses_conflicting_registered_login_identity(
    teardown_system, monkeypatch, conflict
):
    system = teardown_system

    def query(command, end):
        if command[0] == "/usr/bin/busctl":
            row = (
                [2000, "unrelated", "/user/_2000"]
                if conflict == "numeric"
                else [2001, "dtci1000", "/user/_2001"]
            )
            return 0, json.dumps({"type": "a(uso)", "data": [[row]]})
        return system.query(command, end)

    monkeypatch.setattr(cleanup_observation, "query", query)
    result = cleanup_observation.teardown_state(
        system.identity, cleanup_observation.Deadline.after(10).end, False, system.paths
    )
    assert result["state_verified"] is False and result["failed_role"] == "login-user"
    assert "unrelated" not in json.dumps(result)


@pytest.mark.parametrize(
    "case,reply,expected",
    [
        (
            "active",
            (
                0,
                "LoadState=loaded\nActiveState=active\nFragmentPath=/run/user/2000/systemd/generator/ci-probe.service\n",
            ),
            True,
        ),
        (
            "failed",
            (
                0,
                "LoadState=loaded\nActiveState=failed\nFragmentPath=/run/user/2000/systemd/generator/ci-probe.service\n",
            ),
            True,
        ),
        (
            "inactive",
            (
                0,
                "LoadState=loaded\nActiveState=inactive\nFragmentPath=/run/user/2000/systemd/generator/ci-probe.service\n",
            ),
            False,
        ),
        ("missing-zero", (0, "LoadState=not-found\nActiveState=inactive\nFragmentPath=\n"), False),
        ("missing-one", (1, "LoadState=not-found\nActiveState=inactive\nFragmentPath=\n"), False),
        ("missing-error", (9, "LoadState=not-found\nActiveState=inactive\nFragmentPath=\n"), None),
        (
            "foreign",
            (0, "LoadState=loaded\nActiveState=active\nFragmentPath=/unrelated/unit\n"),
            None,
        ),
        ("malformed", (0, "private-fixture-value"), None),
        ("duplicate", (0, "LoadState=loaded\nLoadState=loaded\nFragmentPath=\n"), None),
        ("masked", (0, "LoadState=masked\nActiveState=inactive\nFragmentPath=\n"), None),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_teardown_service_requires_healthy_manager_and_exact_owned_fragment(
    teardown_system, monkeypatch, case, reply, expected
):
    system = teardown_system

    def query(command, end):
        if command[0] == "/usr/sbin/runuser" and command[-1] != "--property=Version":
            return reply
        return system.query(command, end)

    monkeypatch.setattr(cleanup_observation, "query", query)
    end = cleanup_observation.Deadline.after(10).end
    if expected is None:
        with pytest.raises(ValueError, match="user-service-observation-unavailable"):
            cleanup_observation.user_service_present(system.identity, end)
    else:
        assert cleanup_observation.user_service_present(system.identity, end) is expected
    assert "unrelated" not in json.dumps({"case": case, "required": expected})


@pytest.mark.parametrize(
    "reply",
    [
        (7, "private-fixture-value"),
        (0, ""),
        (0, "Version=\n"),
        (0, "Version=255\nExtra=private-fixture-value\n"),
    ],
    ids=["error", "missing", "empty", "extra"],
)
def test_teardown_service_never_treats_missing_user_bus_as_absence(
    teardown_system, monkeypatch, reply
):
    calls = []

    def query(command, end):
        calls.append(command)
        return reply

    monkeypatch.setattr(cleanup_observation, "query", query)
    with pytest.raises(ValueError, match="user-manager-unavailable"):
        cleanup_observation.user_service_present(
            teardown_system.identity, cleanup_observation.Deadline.after(10).end
        )
    assert len(calls) == 1


@pytest.mark.parametrize(
    "words",
    [
        "owned absent",
        "owned absent absent absent absent absent absent extra",
        "unknown absent absent absent absent absent absent",
        "owned unknown absent absent absent absent absent",
        "owned absent absent absent absent absent absent\nextra",
    ],
    ids=["missing", "extra", "unknown-identity", "unknown-state", "multiline"],
)
def test_teardown_shell_refuses_malformed_state_before_destructive_actions(
    tmp_path, fixture_tools, words
):
    install_teardown_state_stub(fixture_tools, words)
    result = run_smoke(tmp_path, fixture_tools, "generator-denied", "0.1")
    assert result.returncode == 1 and "stage=cleanup status=failed exit=1" in result.stdout
    trace = (tmp_path / "trace").read_text().splitlines()
    assert "userdel" not in trace and "systemctl-stop" not in trace
    assert "loginctl-terminate-user" not in trace
    assert not (tmp_path / "work").exists() and not (tmp_path / "generator").exists()


@pytest.mark.parametrize("attempted", [False, True])
def test_teardown_cli_separates_fixed_action_words_from_safe_observation(
    teardown_system, monkeypatch, capsys, attempted
):
    system = teardown_system
    end = cleanup_observation.Deadline.after(10).end
    seen = []
    original = cleanup_observation.teardown_state

    def observed(identity, actual_end, service):
        seen.append((identity, actual_end, service))
        return original(identity, actual_end, service, system.paths)

    monkeypatch.setattr(cleanup_observation, "teardown_state", observed)
    monkeypatch.setattr(cleanup_observation.os, "geteuid", lambda: 0)
    assert (
        cleanup_observation.main(
            [
                "teardown-state",
                "dtci1000",
                "2000",
                "2000",
                "/tmp/fishhat-native.ABCD1234",
                str(end),
                str(int(attempted)),
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert output.out == "owned absent absent absent absent absent absent\n"
    value = json.loads(output.err.split("=", 1)[1])
    assert (
        value["state_verified"] is True
        and value["observer_uid"] == 0
        and value["native_qualified"] is False
    )
    assert seen == [(system.identity, end, attempted)]
    assert "dtci1000" not in output.err and "2000" not in output.err


@pytest.mark.parametrize(
    "extra",
    [[], ["private-fixture-value"], ["0", "extra"]],
    ids=["missing-flag", "invalid-flag", "extra-field"],
)
def test_teardown_cli_rejects_invalid_selection_without_observation(monkeypatch, capsys, extra):
    monkeypatch.setattr(cleanup_observation.os, "geteuid", lambda: 0)

    def forbidden(*_):
        pytest.fail("invalid selection reached native observation")

    monkeypatch.setattr(cleanup_observation, "teardown_state", forbidden)
    end = cleanup_observation.Deadline.after(10).end
    assert (
        cleanup_observation.main(
            [
                "teardown-state",
                "dtci1000",
                "2000",
                "2000",
                "/tmp/fishhat-native.ABCD1234",
                str(end),
                *extra,
            ]
        )
        == 1
    )
    output = capsys.readouterr()
    assert output.out == "" and "private-fixture-value" not in output.err
    assert json.loads(output.err.split("=", 1)[1])["state_verified"] is False


@pytest.mark.parametrize("role", ["user-manager", "runtime-manager", "login-user", "linger"])
def test_teardown_state_fails_when_required_facility_observation_is_unavailable(
    teardown_system, monkeypatch, role
):
    system = teardown_system

    def query(command, end):
        if (
            role == "user-manager"
            and command[0] == "/usr/bin/systemctl"
            and command[4].startswith("user@")
        ):
            return 9, "private-fixture-value"
        if (
            role == "runtime-manager"
            and command[0] == "/usr/bin/systemctl"
            and command[4].startswith("user-runtime-dir@")
        ):
            return 0, "LoadState=not-found\nActiveState=inactive\n"
        if role == "login-user" and command[0] == "/usr/bin/busctl":
            return 9, "private-fixture-value"
        return system.query(command, end)

    if role == "linger":
        (system.paths.var / "lib/systemd").rmdir()
    monkeypatch.setattr(cleanup_observation, "query", query)
    result = cleanup_observation.teardown_state(
        system.identity, cleanup_observation.Deadline.after(10).end, False, system.paths
    )
    assert result["state_verified"] is False and result["failed_role"] == role
    assert "private-fixture-value" not in json.dumps(result)


@pytest.mark.parametrize(
    "failure",
    [
        "disable-linger",
        "terminate-user",
        "manager-stop",
        "runtime-stop",
        "account-remove",
        "busy-once",
    ],
)
def test_teardown_each_actual_failure_stays_failed_after_later_absence(
    tmp_path, fixture_tools, failure
):
    install_teardown_state_stub(
        fixture_tools, "owned present present present present absent absent", settle=True
    )
    loginctl = fixture_tools / "loginctl"
    loginctl.write_text(
        loginctl.read_text().replace(
            "#!/bin/bash\n",
            "#!/bin/bash\n"
            + (
                f'[[ "$1" == {shlex.quote(failure)} ]] && exit 37\n'
                if failure in {"disable-linger", "terminate-user"}
                else ""
            ),
            1,
        )
    )
    systemctl = fixture_tools / "systemctl"
    branch = 'if [[ "$1" == stop ]]; then\n  : > "$NATIVE_FIXTURE/managers-stopped"\n'
    if failure == "manager-stop":
        branch += '  [[ "$2" == user@* ]] && exit 37\n'
    elif failure == "runtime-stop":
        branch += '  [[ "$2" == user-runtime-dir@* ]] && exit 37\n'
    branch += "fi\n"
    systemctl.write_text(
        systemctl.read_text().replace("#!/bin/bash\n", "#!/bin/bash\n" + branch, 1)
    )
    if failure in {"account-remove", "busy-once"}:
        userdel = fixture_tools / "userdel"
        if failure == "account-remove":
            branch = "echo private-fixture-value >&2\nexit 37\n"
        else:
            branch = 'if [[ ! -f "$NATIVE_FIXTURE/busy-seen" ]]; then\n : > "$NATIVE_FIXTURE/busy-seen"\n echo busy-refusal >> "$NATIVE_TRACE"\n exit 8\nfi\n'
        userdel.write_text(
            userdel.read_text().replace("#!/bin/bash\n", "#!/bin/bash\n" + branch, 1)
        )
    canary = tmp_path / "unrelated"
    canary.write_text("keep")
    result = run_smoke(tmp_path, fixture_tools, "generator-denied", "0.1")
    assert result.returncode == 1
    assert "control=generator-execute status=failed exit=1" in result.stderr
    assert "stage=cleanup status=failed exit=1" in result.stdout
    assert "control=cleanup-observation status=passed exit=0" in result.stderr
    assert "private-fixture-value" not in result.stdout + result.stderr
    assert not (tmp_path / "generator").exists() and not (tmp_path / "work").exists()
    assert (tmp_path / "account-present").exists() is (failure == "account-remove")
    assert canary.read_text() == "keep"
    control = {
        "disable-linger": "cleanup-disable-linger",
        "terminate-user": "cleanup-terminate-user",
        "manager-stop": "cleanup-manager-stop",
        "runtime-stop": "cleanup-runtime-manager-stop",
        "account-remove": "cleanup-account-remove",
        "busy-once": "cleanup-account-remove",
    }[failure]
    assert (
        f"control={control} status=failed exit={8 if failure == 'busy-once' else 37}"
        in result.stderr
    )
    if failure == "busy-once":
        assert "control=cleanup-account-remove status=passed exit=0" in result.stderr


def test_teardown_observes_asynchronous_process_settlement_before_account_deletion(
    tmp_path, fixture_tools
):
    python = fixture_tools / "python3"
    branch = """if [[ "$1" == -m && "$2" == scripts.native_smoke_cleanup && "$3" == teardown-state ]]; then
  n=0
  [[ -f "$NATIVE_FIXTURE/state-count" ]] && n=$(cat "$NATIVE_FIXTURE/state-count")
  n=$((n + 1)); echo "$n" > "$NATIVE_FIXTURE/state-count"
  echo state-observed >> "$NATIVE_TRACE"
  if [[ "$n" == 3 ]]; then
    echo 'owned absent absent absent absent absent present'
  else
    echo 'owned absent absent absent absent absent absent'
  fi
  exit 0
fi
"""
    python.write_text(python.read_text().replace("#!/bin/bash\n", "#!/bin/bash\n" + branch, 1))
    result = run_smoke(tmp_path, fixture_tools, "generator-denied", "0.1")
    assert result.returncode == 1 and "stage=cleanup status=passed exit=0" in result.stdout
    trace = (tmp_path / "trace").read_text().splitlines()
    assert trace[: trace.index("userdel")].count("state-observed") == 4
    assert not (tmp_path / "account-present").exists()
