"""Validation budgets preserve semantic expiry, complete work and required evidence."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import time

import pytest
import yaml
from filelock import FileLock, Timeout

from scripts import validation
from scripts.project_policy import ROOT
from scripts.validation_timeouts import (
    VARIABLE,
    Deadline,
    Policy,
    current,
    invocation,
    using,
    valid_report,
    watchdog,
)
from scripts.validation_watchdogs import check, python_errors, shell_errors, workflow_errors
from scripts.validation_workflows import plan
from tests import test_validation as runner_tests
from tests.test_adapter_process import expiry_probe
from tests.test_validation import latest

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/validation_timeouts.py",
        "scripts/validation_watchdogs.py",
        "scripts/validation_workflows.py",
    ],
    "scope": "watchdog arithmetic, propagation, guard failures, evidence and cleanup",
    "relationship": "no-product-claim",
    "reason": "Actual held work, child processes, file locks and synthetic bypasses challenge validation tooling without qualifying product timeouts or native execution.",
    "claims": [],
}


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    return runner_tests.checkout.__wrapped__(tmp_path, monkeypatch)


@pytest.mark.parametrize(
    "value",
    ["", " ", "no", "0", "-1", "NaN", "Infinity", "-Infinity", "1e400", "1e-400"],
    ids=[
        "empty",
        "whitespace",
        "malformed",
        "zero",
        "negative",
        "nan",
        "infinity",
        "negative-infinity",
        "overflow",
        "underflow",
    ],
)
def test_invalid_environment_is_rejected(value):
    with pytest.raises(ValueError, match="finite, positive and representable"):
        Policy.resolve({VARIABLE: value})


@pytest.mark.parametrize("factor", [1, 4, 0.5])
def test_watchdog_arithmetic_and_budget_receipt(factor):
    policy = Policy.resolve({VARIABLE: str(factor)})
    assert Policy.resolve({}).scale == 1
    with using(policy):
        assert watchdog(10) == 10 * factor
        assert current() is policy
    assert valid_report(policy.report())
    assert policy.report()["budgets_seconds"] == {"10": 10 * factor}
    changed = copy.deepcopy(policy.report())
    changed["budgets_seconds"]["10"] *= 2
    assert not valid_report(changed)


@pytest.mark.parametrize(
    "factor,nominal,maximum",
    [(1e300, 1e300, 1e308), (1e-300, 1e-300, 10), (1, 11, 10)],
    ids=["multiplication-overflow", "multiplication-underflow", "backend-ceiling"],
)
def test_overflow_underflow_and_backend_limits_reject(factor, nominal, maximum):
    with pytest.raises(ValueError):
        Policy(factor).seconds(nominal, maximum=maximum)


def test_integer_units_round_up_without_disabling_or_clamping():
    policy = Policy(0.001)
    assert policy.units(1, unit_seconds=1, maximum=10) == 1
    assert valid_report(policy.report())
    report = policy.report()
    report["unit_budgets"]["1/1/10"]["effective_units"] = 2
    assert not valid_report(report)
    assert Policy(1).units(0.14, unit_seconds=0.01, maximum=14) == 14
    assert Policy(0.5).units(3, unit_seconds=1, maximum=10) == 2
    assert Policy(4).units(45 * 60, unit_seconds=60, maximum=360) == 180
    with pytest.raises(ValueError):
        Policy(9).units(45 * 60, unit_seconds=60, maximum=360)
    with pytest.raises(ValueError):
        Policy(True)


def test_invocation_captures_policy_before_environment_changes(monkeypatch):
    monkeypatch.setenv(VARIABLE, "4")

    @invocation
    def observe():
        monkeypatch.setenv(VARIABLE, "2")
        return watchdog(3), current().report()

    value, receipt = observe()
    assert value == 12 and receipt["scale"] == 4


def test_deadline_spends_one_budget_instead_of_restarting(monkeypatch):
    moments = iter([10, 11, 15, 30])
    monkeypatch.setattr(time, "monotonic", lambda: next(moments))
    with using(Policy(4)):
        deadline = Deadline.after(2)
        assert deadline.remaining() == 7
        assert deadline.remaining() == 3
        assert deadline.remaining() == 0


def test_unrepresentable_monotonic_deadline_rejects(monkeypatch):
    monkeypatch.setattr(time, "monotonic", lambda: 1e9)
    with using(Policy(1e-300)), pytest.raises(ValueError, match="representable"):
        Deadline.after(1)


@pytest.mark.parametrize("factor", [1, 4])
def test_factor_crosses_real_child_boundary_once(factor):
    code = "import json; from scripts.validation_timeouts import Policy, using, watchdog; p=Policy.resolve(); t=using(p); t.__enter__(); value=watchdog(2); print(json.dumps([value,p.report()]))"
    result = subprocess.run(
        [sys.executable, "-c", code],
        env={**os.environ, VARIABLE: str(factor)},
        capture_output=True,
        text=True,
        check=True,
        timeout=watchdog(10),
    )
    value, report = json.loads(result.stdout)
    assert value == 2 * factor and report["scale"] == factor and valid_report(report)


@pytest.mark.parametrize("factor", [1, 4])
def test_held_child_still_expires_and_is_reaped(tmp_path, factor):
    ready = tmp_path / "ready"
    code = "import signal,sys; from pathlib import Path; Path(sys.argv[1]).touch(); signal.pause()"
    child = subprocess.Popen([sys.executable, "-c", code, str(ready)])
    try:
        with using(Policy(factor)):
            deadline = Deadline.after(10)
            while not ready.exists() and child.poll() is None:
                assert deadline.remaining(), "child never established readiness"
                time.sleep(0.005)
            assert ready.exists() and child.poll() is None
            with pytest.raises(subprocess.TimeoutExpired):
                expiry_probe(child)
    finally:
        child.kill()
        child.wait()
    assert child.returncode is not None


@pytest.mark.parametrize("factor", [1, 4])
def test_contended_evidence_lock_fails_then_releases(tmp_path, factor):
    with using(Policy(factor)):
        holder = FileLock(str(tmp_path / "lock"), timeout=watchdog(1))
        contender = FileLock(str(tmp_path / "lock"), timeout=watchdog(0.02))
        with holder, pytest.raises(Timeout), contender:
            pytest.fail("held lock was incorrectly acquired")
        with contender:
            assert contender.is_locked
        assert not holder.is_locked and not contender.is_locked


def test_nondefault_factor_is_an_execution_condition_in_actual_receipt(checkout, monkeypatch):
    monkeypatch.setenv(VARIABLE, "4")
    assert validation.run("unit", validation.CANONICAL["unit"], checkout) == 0
    receipt = latest(checkout)
    assert receipt["full_check_passed"] is True
    assert receipt["watchdogs"]["scale"] == 4
    assert receipt["profile"]["watchdog_scale"] == 4
    assert receipt["tests"]["watchdogs"]["scale"] == 4
    assert receipt["tests"]["profile"] == receipt["profile"]
    receipt["tests"]["profile"]["watchdog_scale"] = 2
    assert not validation.full_check_passed(receipt)


@pytest.mark.parametrize(
    "body",
    [
        "import subprocess; subprocess.run(['x'], timeout=2)",
        "from subprocess import run as execute; budget=2; execute(['x'], timeout=budget)",
        "def old_test():\n    worker.wait(2)",
        """import pytest
@pytest.mark.timeout(2)
def old_test(): pass""",
        "import time; start=time.monotonic(); elapsed=time.monotonic()-start; assert elapsed < 0.5",
        "import time; start=time.perf_counter(); test.assertLess(time.perf_counter()-start, 0.5)",
    ],
    ids=[
        "direct-timeout",
        "assigned-constant-alias",
        "positional-wait",
        "pytest-timeout",
        "elapsed-assertion",
        "elapsed-unittest",
    ],
)
def test_python_guard_rejects_new_raw_waits_and_speed_gates(body):
    assert python_errors(body, "tests/test_new.py")


def test_guard_accepts_policy_derived_alias_without_per_literal_catalogue():
    body = "from scripts.validation_timeouts import watchdog as budget; from subprocess import run as execute; limit=budget(2); execute(['x'], timeout=limit)"
    assert not python_errors(body, "tests/test_new.py")


@pytest.mark.parametrize(
    "body",
    [
        "from scripts.validation_timeouts import watchdog",
        "import os; os.environ['FISHHAT_VALIDATION_TIMEOUT_SCALE']",
    ],
    ids=["import", "environment"],
)
def test_guard_rejects_runtime_policy_leakage(body):
    assert python_errors(body, "packages/new/src/new/runtime.py", runtime=True)


@pytest.mark.parametrize(
    "body",
    [
        "curl --max-time 4 https://example.invalid",
        'budget=4\ncurl --connect-timeout "$budget" https://example.invalid',
        "for attempt in $(seq 1 10); do sleep 1; done",
        "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['x'], timeout=3)\nPY",
    ],
    ids=["curl", "assigned-curl", "retry-loop", "embedded-python"],
)
def test_shell_guard_rejects_hidden_watchdogs(body):
    assert shell_errors(body, "scripts/new.sh")


@pytest.mark.parametrize("factor", [1, 4, 0.5])
def test_all_workflows_plan_before_jobs_start_with_platform_limits(factor):
    for path in (ROOT / ".github/workflows").glob("*.y*ml"):
        text = path.read_text()
        assert not workflow_errors(text, str(path))
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        value = plan(workflow, {VARIABLE: str(factor)})
        for name, effective in value["budgets"].items():
            nominal = float(workflow["jobs"][name]["env"]["FISHHAT_VALIDATION_NOMINAL_MINUTES"])
            if name == "watchdog-regressions":
                assert effective == {"1": int(nominal), "4": int(nominal * 4)}
                assert value["contacts"][name] == {
                    "1": {"uv": 30, "audit": 15},
                    "4": {"uv": 120, "audit": 60},
                }
            else:
                assert effective >= nominal * factor and 0 < effective <= 360
        workflow["jobs"]["unreviewed"] = {
            "runs-on": "ubuntu-24.04",
            "timeout-minutes": 1,
            "steps": [],
        }
        assert workflow_errors(yaml.safe_dump(workflow), str(path))
    with pytest.raises(ValueError):
        plan(workflow, {VARIABLE: ""})


def test_maintained_sources_use_owned_watchdog_boundaries():
    assert not check(ROOT)


@pytest.mark.parametrize("factor", [1, 4])
def test_real_workflow_planner_records_effective_budgets_without_other_variables(tmp_path, factor):
    output = tmp_path / "output"
    command = [
        sys.executable,
        "-m",
        "scripts.validation_workflows",
        "--workflow",
        str(ROOT / ".github/workflows/ci.yml"),
        "--github-output",
        str(output),
    ]
    env = {
        **os.environ,
        "FISHHAT_VALIDATION_SCALE_DEFINED": "true",
        "FISHHAT_VALIDATION_SCALE_VALUE": str(factor),
    }
    result = subprocess.run(
        command, env=env, capture_output=True, text=True, check=True, timeout=watchdog(10)
    )
    report = json.loads(result.stdout)
    assert report["scale"] == factor and report["budgets"]["tests"] == 45 * factor
    assert "budgets=" in output.read_text() and "scale=" in output.read_text()
    assert valid_report(report["job_policies"]["tests"])
    output.unlink()
    env["FISHHAT_VALIDATION_SCALE_VALUE"] = ""
    rejected = subprocess.run(
        command, env=env, capture_output=True, text=True, timeout=watchdog(10)
    )
    assert rejected.returncode != 0 and not output.exists()
    env["FISHHAT_VALIDATION_SCALE_DEFINED"] = "false"
    absent = subprocess.run(
        command, env=env, capture_output=True, text=True, check=True, timeout=watchdog(10)
    )
    assert json.loads(absent.stdout)["scale"] == 1


def test_guard_rejects_shadowed_watchdog_and_dynamic_runtime_import():
    text = "from scripts.validation_timeouts import watchdog; watchdog=lambda x:x; child.wait(timeout=watchdog(10))"
    assert python_errors(text, "tests/test_new.py")
    assert python_errors(
        "import importlib; importlib.import_module('scripts.validation_timeouts')",
        "packages/new/src/new/runtime.py",
        runtime=True,
    )


def test_invalid_policy_prevents_direct_pytest_start(checkout):
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "scripts.validation_pytest", "-q", "tests"],
        cwd=checkout,
        env={**os.environ, VARIABLE: ""},
        capture_output=True,
        text=True,
        timeout=watchdog(10),
    )
    assert result.returncode != 0 and VARIABLE in result.stderr
    assert "1 passed" not in result.stdout
