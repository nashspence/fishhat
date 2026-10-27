from __future__ import annotations

import errno
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import validation
from scripts.project_policy import ROOT

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/validation.py"],
    "scope": "receipt runner",
    "relationship": "no-product-claim",
    "reason": "Actual child executions and synthetic repositories verify source, selection, outcomes and retention; no deployment effect is established.",
    "claims": [],
}


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    for key in validation.OVERRIDES:
        monkeypatch.delenv(key, raising=False)
    (tmp_path / ".gitignore").write_text("artifacts/\n__pycache__/\n.pytest_cache/\n")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/__init__.py").touch()
    shutil.copyfile(
        ROOT / "scripts/validation_pytest.py", tmp_path / "scripts/validation_pytest.py"
    )
    shutil.copyfile(ROOT / "scripts/run_stats.py", tmp_path / "scripts/run_stats.py")
    shutil.copyfile(ROOT / "scripts/check_evidence.py", tmp_path / "scripts/check_evidence.py")
    (tmp_path / "Makefile").write_text("# check-purpose: validation-tooling\nunit:\n")
    (tmp_path / "policy").mkdir()
    shutil.copyfile(ROOT / "policy/performance.toml", tmp_path / "policy/performance.toml")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_example.py").write_text("def test_pass():\n    assert True\n")
    from scripts.check_evidence import FORMAT, encode_inventory, entrypoints, fingerprint

    group = {
        "purpose": "validation-tooling",
        "authority": ["Makefile"],
        "scope": "synthetic runner fixture",
        "relationship": "no-product-claim",
        "reason": "Controlled child outcomes exercise receipt integrity",
        "claims": [],
    }
    (tmp_path / "conftest.py").write_text(
        "def pytest_collection_modifyitems(items):\n"
        f"    for item in items: item.module.CHECK_PURPOSE = {group!r}\n"
    )
    (tmp_path / "policy/checks.json").write_text(
        json.dumps(
            encode_inventory(
                {
                    "format": FORMAT,
                    "entrypoints": entrypoints(tmp_path),
                    "pytest": {"tests/test_example.py::test_pass": fingerprint({"check": group})},
                }
            )
        )
    )
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture Maintainer",
            "-c",
            "user.email=maintainer@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "Synthetic fixture",
        ],
        cwd=tmp_path,
        check=True,
    )
    return tmp_path


def latest(root):
    path = max((root / "artifacts/validation").glob("*.json"), key=lambda p: p.stat().st_mtime_ns)
    return json.loads(path.read_text())


def test_complete_unit_run_records_actual_nodes_and_source(checkout):
    assert validation.run("unit", validation.CANONICAL["unit"], checkout) == 0
    value = latest(checkout)
    assert value["full_check_passed"] is True
    assert value["source_before"] == value["source_after"]
    assert value["tests"]["outcomes"] == {"tests/test_example.py::test_pass": "passed"}
    assert value["duration_seconds"] > 0


def test_filtered_success_does_not_become_full_qualification(checkout):
    command = [*validation.CANONICAL["unit"], "-k", "pass"]
    assert validation.run("unit", command, checkout) == 0
    assert latest(checkout)["full_check_passed"] is False
    assert latest(checkout)["tests"]["outcomes"]


def test_failed_child_status_and_no_sensitive_values_are_preserved(checkout, monkeypatch):
    monkeypatch.setenv("PYTEST_ADDOPTS", "SYNTHETIC_PRIVATE_SENTINEL")
    command = ["python", "-c", "import sys; sys.exit(17)", "SYNTHETIC_PRIVATE_ARGUMENT"]
    assert validation.run("ruff", command, checkout) == 17
    value = latest(checkout)
    assert value["exit_status"] == 17 and not value["full_check_passed"]
    assert "SYNTHETIC_PRIVATE" not in json.dumps(value)
    assert value["selection"]["environment_overrides"] == ["PYTEST_ADDOPTS"]


def test_changed_or_dirty_sources_cannot_qualify(checkout):
    before = validation.source_identity(checkout)
    (checkout / "tests/test_example.py").write_text("def test_pass():\n    assert 1 == 1\n")
    after = validation.source_identity(checkout)
    assert before["fingerprint"] != after["fingerprint"] and not after["clean"]
    assert validation.run("unit", validation.CANONICAL["unit"], checkout) == 0
    assert not latest(checkout)["full_check_passed"]


def test_receipts_capture_source_changes_during_execution(checkout):
    command = [
        "python",
        "-c",
        'from pathlib import Path; Path("new-source.py").write_text("changed")',
    ]
    assert validation.run("ruff", command, checkout) == 0
    value = latest(checkout)
    assert value["source_before"] != value["source_after"]
    assert not value["full_check_passed"]


def test_teardown_failure_cannot_leave_a_passing_test_proof(checkout):
    (checkout / "tests/test_example.py").write_text(
        """import pytest
@pytest.fixture
def broken():
    yield
    raise ValueError("synthetic failure")
def test_pass(broken):
    assert True
"""
    )
    assert validation.run("unit", validation.CANONICAL["unit"], checkout) == 1
    assert latest(checkout)["tests"]["outcomes"]["tests/test_example.py::test_pass"] == "failed"
    assert not latest(checkout)["full_check_passed"]


def test_receipt_retention_preserves_unrelated_files(checkout):
    folder = checkout / "artifacts/validation"
    folder.mkdir(parents=True)
    unrelated = folder / "keep.json"
    unrelated.write_text('{"preserved":true}')
    for _ in range(65):
        assert validation.run("ruff", ["python", "-c", "pass"], checkout) == 0
    assert len(list(folder.glob("*.json"))) == 66
    assert unrelated.read_text() == '{"preserved":true}'


def test_reporting_options_keep_the_default_selection(monkeypatch):
    for key in validation.OVERRIDES:
        monkeypatch.delenv(key, raising=False)
    assert validation.selection(
        "unit", [*validation.CANONICAL["unit"], "--junitxml=artifacts/unit-tests.xml"]
    )["canonical"]
    assert not validation.selection("unit", [*validation.CANONICAL["unit"], "--collect-only"])[
        "canonical"
    ]


@pytest.mark.parametrize("stage", ["write_text", "chmod", "replace"])
def test_failed_receipt_publication_keeps_prior_evidence_and_can_resume(
    tmp_path, monkeypatch, stage
):
    directory = tmp_path / "artifacts/validation"
    directory.mkdir(parents=True)
    path = directory / ("a" * 32 + ".json")
    prior = {"state": "running", "full_check_passed": False}
    validation.write_receipt(path, prior)
    original = getattr(Path, stage)

    def fail_temporary(self, *args, **kwargs):
        if self == path.with_suffix(".tmp"):
            if stage == "write_text":
                original(self, "partial")
            raise OSError(errno.ENOSPC, "synthetic evidence capacity exhausted")
        return original(self, *args, **kwargs)

    completed = {"state": "completed", "full_check_passed": True}
    with monkeypatch.context() as scoped:
        scoped.setattr(Path, stage, fail_temporary)
        with pytest.raises(OSError):
            validation.write_receipt(path, completed)
    assert json.loads(path.read_text()) == prior
    assert list(directory.glob("*.json")) == [path]
    validation.write_receipt(path, completed)
    assert json.loads(path.read_text()) == completed


def test_parallel_complete_run_retains_worker_phases_fixtures_subtests_and_scoped_proofs(checkout):
    from scripts.check_evidence import encode_inventory, fingerprint, inventory
    from scripts.run_stats import valid_stats

    group = {
        "purpose": "validation-tooling",
        "authority": ["Makefile"],
        "scope": "synthetic parallel assertions",
        "relationship": "no-product-claim",
        "reason": "Controlled independent assertion groups exercise worker evidence transfer",
        "claims": [],
    }
    groups = {"first": group, "second": group}
    (checkout / "tests/test_example.py").write_text(
        "import pytest\nfrom scripts.check_evidence import evidence_group\n"
        f"CHECK_OVERRIDES = {{'test_pass': {groups!r}}}\n"
        "@pytest.fixture\ndef sample(): return 1\n"
        "@pytest.mark.parametrize('case', range(8), ids=[f'case{i}' for i in range(8)])\n"
        "def test_pass(case, sample, subtests):\n"
        "    with evidence_group('first'): assert case >= 0\n"
        "    with evidence_group('second'):\n"
        "        for part in range(2):\n"
        "            with subtests.test(part=part): assert sample == 1\n"
    )
    expected = {f"tests/test_example.py::test_pass[case{i}]" for i in range(8)}
    inv = inventory(checkout)
    inv["pytest"] = {node: fingerprint(groups) for node in expected}
    (checkout / "policy/checks.json").write_text(json.dumps(encode_inventory(inv)))
    subprocess.run(["git", "add", "."], cwd=checkout, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture Maintainer",
            "-c",
            "user.email=maintainer@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "Synthetic parallel fixture",
        ],
        cwd=checkout,
        check=True,
    )
    command = [
        *validation.CANONICAL["unit"],
        "-n",
        "4",
        "--dist=worksteal",
        "--max-worker-restart=0",
    ]
    assert validation.run("unit", command, checkout) == 0
    value = latest(checkout)
    assert value["full_check_passed"]
    tests = value["tests"]
    assert set(tests["outcomes"]) == expected
    assert all(outcome == "passed" for outcome in tests["outcomes"].values())
    assert set(tests["stats"]["processes"]) == {"controller", "gw0", "gw1", "gw2", "gw3"}
    assert valid_stats(tests["stats"])
    assert {
        phase["process"] for phases in tests["phases"].values() for phase in phases.values()
    } == {
        "gw0",
        "gw1",
        "gw2",
        "gw3",
    }
    assert tests["fixtures"]["sample"]["count"] == 8
    assert sum(len(cases) for cases in tests["subtests"].values()) == 16
    assert all(
        group["outcome"] == "passed"
        for groups in tests["evidence"]["groups"].values()
        for group in groups.values()
    )


@pytest.mark.parametrize(
    "failure",
    [
        "assertion",
        "teardown",
        "skip",
        "crash",
        "missing-evidence",
        "duplicate",
        "missing-phase",
        "invalid-metrics",
    ],
)
def test_parallel_failure_or_lost_evidence_cannot_qualify(checkout, failure):
    bodies = {
        "assertion": "def test_pass(): assert False\n",
        "teardown": "import pytest\n"
        "@pytest.fixture\ndef broken():\n    yield\n    assert False\ndef test_pass(broken): pass\n",
        "skip": "import pytest\ndef test_pass(): pytest.skip('synthetic skip')\n",
        "crash": "import os\ndef test_pass(): os._exit(13)\n",
        "missing-evidence": "def test_pass(): pass\n",
    }
    (checkout / "tests/test_example.py").write_text(bodies.get(failure, "def test_pass(): pass\n"))
    mutations = {
        "missing-evidence": "session.config.workeroutput.pop('fishhat_results', None)",
        "duplicate": "session.config.workeroutput['fishhat_results']['phases']['tests/test_example.py::test_pass'] = {'call': {}}",
        "missing-phase": "session.config.workeroutput['fishhat_results']['phases']['tests/test_example.py::test_pass'] = {}",
        "invalid-metrics": "session.config.workeroutput['fishhat_results']['stats']['cpu_user_seconds'] = -1",
    }
    if failure in mutations:
        with (checkout / "conftest.py").open("a") as stream:
            stream.write(
                "import pytest\n"
                "@pytest.hookimpl(trylast=True)\n"
                "def pytest_sessionfinish(session):\n"
                "    if hasattr(session.config, 'workeroutput'):\n"
                f"        {mutations[failure]}\n"
            )
    status = validation.run(
        "unit",
        [*validation.CANONICAL["unit"], "-n4", "--dist=worksteal", "--max-worker-restart=0"],
        checkout,
    )
    value = latest(checkout)
    assert not value["full_check_passed"]
    if failure == "crash" or failure in mutations:
        assert status != 0 and value["tests"] is None
    else:
        assert status == (0 if failure == "skip" else 1)
        node = "tests/test_example.py::test_pass"
        assert value["tests"]["outcomes"][node] == ("skipped" if failure == "skip" else "failed")
        assert value["tests"]["evidence"]["groups"][node]["check"]["outcome"] != "passed"


def test_parallel_distribution_flags_preserve_selection_but_filtering_and_duplication_do_not(
    monkeypatch,
):
    for key in validation.OVERRIDES:
        monkeypatch.delenv(key, raising=False)
    for flags in (
        ["-n", "4", "--dist=worksteal"],
        ["-n0"],
        ["--numprocesses=4", "--max-worker-restart=0"],
    ):
        selected = validation.selection("unit", [*validation.CANONICAL["unit"], *flags])
        assert selected["canonical"]
        assert selected["work_sha256"] == validation.digest(validation.CANONICAL["unit"])
    for flags in (["-n4", "-k", "pass"], ["-n4", "--dist=each"], ["-n", "auto"], ["-n4", "--lf"]):
        assert not validation.selection("unit", [*validation.CANONICAL["unit"], *flags])[
            "canonical"
        ]
