"""Complete distributed observations must retain their actual work and raw evidence."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys

import pytest
import yaml

from scripts import unit_shards, validation
from scripts.check_evidence import (
    current_run,
    encode_inventory,
    entrypoints,
    inventory,
)
from scripts.project_policy import ROOT
from scripts.run_stats import sharded_stats, valid_stats
from scripts.validation_timeouts import watchdog
from tests import test_validation as runner_tests

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/unit_shards.py", "scripts/run_stats.py", ".github/workflows/ci.yml"],
    "scope": "complete shard selection, receipt assembly, failure propagation and observational statistics",
    "relationship": "no-product-claim",
    "reason": "Real small subprocess suites and altered evidence verify validation tooling without qualifying native operations or numerical performance.",
    "claims": [],
}


@pytest.fixture(scope="module")
def assembled(tmp_path_factory):
    with pytest.MonkeyPatch.context() as patch:
        for key in (
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "GITHUB_JOB",
            "FISHHAT_TEST_REPORT",
            "FISHHAT_TEST_ORIGIN",
        ):
            patch.delenv(key, raising=False)
        root = runner_tests.checkout.__wrapped__(tmp_path_factory.mktemp("unit-shards"), patch)
        for name in ("unit_shards.py", "validation.py", "project_policy.py"):
            shutil.copyfile(ROOT / "scripts" / name, root / "scripts" / name)
        (root / "tests/test_example.py").write_text(
            "\n".join(
                [
                    "import pytest",
                    "@pytest.mark.parametrize('case', range(16))",
                    "def test_pass(case):",
                    "    assert case >= 0",
                    "",
                ]
            )
        )
        old = inventory(root)
        group_hash = next(iter(old["pytest"].values()))
        old["pytest"] = {f"tests/test_example.py::test_pass[{i}]": group_hash for i in range(16)}
        old["entrypoints"] = entrypoints(root)
        (root / "policy/checks.json").write_text(json.dumps(encode_inventory(old)))
        subprocess.run(["git", "add", "."], cwd=root, check=True)
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
                "Synthetic distributed suite",
            ],
            cwd=root,
            check=True,
        )
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-p",
                "scripts.validation_pytest",
                "--collect-only",
                "-q",
                "tests",
                "--unit-shard-plan-output=artifacts/unit-plan.json",
            ],
            cwd=root,
            check=True,
            timeout=watchdog(30),
        )
        plan = unit_shards.read_plan(root / unit_shards.PLAN, root)
        python = ".".join(plan["profile"]["python"].split(".")[:2])
        raw_bytes = {}
        for index in range(unit_shards.SHARDS):
            before = set((root / "artifacts/validation").glob("*.json"))
            assert validation.run("unit", unit_shards.command(index), root) == 0
            fresh = set((root / "artifacts/validation").glob("*.json")) - before
            assert len(fresh) == 1
            source = fresh.pop()
            raw = json.loads(source.read_text())
            assert not raw["selection"]["canonical"] and not raw["full_check_passed"]
            folder = root / "artifacts/unit-shards" / f"unit-shard-{python}-{index}-local"
            (folder / "validation").mkdir(parents=True)
            shutil.copyfile(source, folder / "validation" / source.name)
            shutil.copyfile(root / "artifacts/unit-plan.json", folder / "unit-plan.json")
            shutil.copyfile(root / "artifacts/unit-tests.xml", folder / "unit-tests.xml")
            raw_bytes[source.name] = source.read_bytes()
        assert unit_shards.aggregate(root) == 0
        receipt = runner_tests.latest(root)
        assert receipt["assembly"] and receipt["full_check_passed"]
        yield {"root": root, "receipt": receipt, "plan": plan, "raw": raw_bytes}


@pytest.fixture
def cloned(assembled, tmp_path):
    root = tmp_path / "repository"
    shutil.copytree(assembled["root"], root)
    return root, copy.deepcopy(assembled["receipt"])


def test_real_shards_assemble_once_and_retain_raw_receipts(assembled):
    root, receipt = assembled["root"], assembled["receipt"]
    assert validation.full_check_passed(receipt, root)
    assert current_run(root, validation.source_identity(root))["id"] == receipt["id"]
    assert len(receipt["tests"]["outcomes"]) == 16
    assert len(receipt["tests"]["worker_watchdogs"]) == 8
    for name, data in assembled["raw"].items():
        assert (root / "artifacts/validation" / name).read_bytes() == data
        forged = json.loads(data)
        forged["selection"]["canonical"] = True
        assert not validation.full_check_passed(forged, root)
    assert (
        len(
            unit_shards.checked_cases(root / "artifacts/unit-tests.xml", assembled["plan"]["nodes"])
        )
        == 16
    )


def test_observed_resource_scopes_are_not_summed_elapsed_or_simultaneous_rss(assembled):
    stats = assembled["receipt"]["tests"]["stats"]
    assert valid_stats(stats)
    assert stats["elapsed_seconds"] == max(v["elapsed_seconds"] for v in stats["shards"].values())
    assert stats["cpu_user_seconds"] == sum(v["cpu_user_seconds"] for v in stats["shards"].values())
    assert "maximum-shard" in stats["elapsed_scope"]
    assert "upper-bound" in stats["rss_high_water_scope"]
    changed = copy.deepcopy(stats)
    changed["elapsed_seconds"] += 1
    assert not valid_stats(changed)
    for shard in changed["shards"].values():
        shard["scope"] = "process-excludes-children"
    with pytest.raises(ValueError):
        sharded_stats(changed["shards"])


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-result",
        "duplicate-result",
        "raw-receipt",
        "raw-xml",
        "assembled-cpu",
        "assembled-case",
        "assembled-origin",
        "plan",
        "wrong-selection",
    ],
)
def test_partial_stale_or_altered_assemblies_cannot_qualify(cloned, mutation):
    root, receipt = cloned
    first = receipt["assembly"]["inputs"][0]
    if mutation == "missing-result":
        (root / "artifacts/validation" / (first["receipt_id"] + ".json")).unlink()
    elif mutation == "duplicate-result":
        receipt["assembly"]["inputs"][1] = copy.deepcopy(first)
    elif mutation == "raw-receipt":
        (root / "artifacts/validation" / (first["receipt_id"] + ".json")).write_text("{}")
    elif mutation == "raw-xml":
        (root / first["xml_path"]).write_text("<testsuites/>")
    elif mutation == "assembled-cpu":
        receipt["tests"]["stats"]["cpu_user_seconds"] += 1
    elif mutation == "assembled-case":
        receipt["tests"]["outcomes"].pop(next(iter(receipt["tests"]["outcomes"])))
    elif mutation == "assembled-origin":
        receipt["execution_origin"] = {
            "kind": "github-actions",
            "run_id": "7",
            "attempt": "2",
            "job": "tests",
        }
    elif mutation == "plan":
        (root / "artifacts/unit-plans" / (receipt["assembly"]["plan_id"] + ".json")).unlink()
    else:
        receipt["selection"]["canonical"] = False
    assert not validation.full_check_passed(receipt, root)


@pytest.mark.parametrize(
    "mutation",
    [
        "source",
        "profile",
        "attempt",
        "command",
        "coverage",
        "phase",
        "worker",
        "stats",
        "origin",
        "subtest",
        "shard-index",
    ],
)
def test_constituent_semantics_are_rechecked_after_digest_changes(cloned, mutation):
    root, receipt = cloned
    entry = receipt["assembly"]["inputs"][0]
    path = root / "artifacts/validation" / (entry["receipt_id"] + ".json")
    raw = json.loads(path.read_text())
    tests = raw["tests"]
    if mutation == "source":
        raw["source_before"]["commit"] = "0" * 40
    elif mutation == "profile":
        raw["profile"]["python"] = "0.0.0"
    elif mutation == "attempt":
        raw["execution_origin"] = {
            "kind": "github-actions",
            "run_id": "7",
            "attempt": "9",
            "job": "unit-shards",
        }
    elif mutation == "command":
        raw["selection"]["invocation_sha256"] = "0" * 64
    elif mutation == "coverage":
        tests["outcomes"].pop(next(iter(tests["outcomes"])))
    elif mutation == "phase":
        next(iter(tests["phases"].values())).pop("teardown")
    elif mutation == "worker":
        tests["worker_watchdogs"].pop(next(iter(tests["worker_watchdogs"])))
    elif mutation == "stats":
        tests["stats"]["cpu_user_seconds"] += 1
    elif mutation == "origin":
        tests["evidence"]["origin"] = "0" * 32
    elif mutation == "subtest":
        tests["subtests"] = {
            next(iter(tests["outcomes"])): [{"outcome": "failed", "expected_failure": False}]
        }
    else:
        tests["shard"]["index"] = 1
    path.write_text(json.dumps(raw))
    entry["receipt_sha256"] = unit_shards.file_sha(path)
    assert not validation.full_check_passed(receipt, root)


@pytest.mark.parametrize(
    "failure", ["missing-artifact", "failed-receipt", "skipped-case", "foreign-plan"]
)
def test_failed_assembly_records_latest_canonical_failure_without_fallback(cloned, failure):
    root, previous = cloned
    folder = sorted((root / "artifacts/unit-shards").iterdir())[0]
    if failure == "missing-artifact":
        shutil.rmtree(folder)
    elif failure == "foreign-plan":
        (folder / "unit-plan.json").write_text("{}")
    else:
        path = next((folder / "validation").glob("*.json"))
        raw = json.loads(path.read_text())
        if failure == "failed-receipt":
            raw["exit_status"] = 1
        else:
            raw["tests"]["outcomes"][next(iter(raw["tests"]["outcomes"]))] = "skipped"
        path.write_text(json.dumps(raw))
    assert unit_shards.aggregate(root) == 2
    latest = runner_tests.latest(root)
    assert latest["id"] != previous["id"] and latest["selection"]["canonical"]
    assert not latest["full_check_passed"]
    assert current_run(root, validation.source_identity(root)) is None


def test_plan_is_deterministic_and_starts_heavy_work_early(assembled):
    plan = assembled["plan"]
    assert plan["shards"] == unit_shards.partition(plan["weights_seconds"])
    assert sorted(n for shard in plan["shards"] for n in shard) == plan["nodes"]
    assert not set(plan["shards"][0]) & set(plan["shards"][1])
    weights = {str(i): float(i + 1) for i in range(16)}
    order = unit_shards.execution_order(list(weights), weights)
    assert order[:4] == ["15", "0", "14", "1"]
    assert unit_shards.partition(weights) == unit_shards.partition(
        dict(reversed(list(weights.items())))
    )


@pytest.mark.parametrize(
    "body",
    [
        None,
        "malformed",
        '<testsuites><testcase classname="tests.a" name="test_a" time="NaN"/></testsuites>',
    ],
    ids=["missing", "malformed", "nonfinite"],
)
def test_unavailable_duration_reference_never_omits_current_tests(tmp_path, body):
    path = tmp_path / "reference.xml"
    if body is not None:
        path.write_text(body)
    nodes = [f"tests/a.py::test_{i}" for i in range(16)]
    weights, report = unit_shards.observations(nodes, path)
    assert set(weights) == set(nodes) and set(weights.values()) == {1.0}
    assert report["unobserved_nodes"] == len(nodes)
    assert sorted(n for shard in unit_shards.partition(weights) for n in shard) == sorted(nodes)


def test_optional_reference_contact_failure_is_explicit_and_nonblocking(tmp_path, monkeypatch):
    def unavailable(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ["gh"])

    monkeypatch.setattr(unit_shards.subprocess, "run", unavailable)
    unit_shards.reference("example/project", tmp_path / "reference")
    report = json.loads((tmp_path / "reference/reference.json").read_text())
    assert report == {"advisory_only": True, "status": "unavailable", "files": {}}


def test_workflow_requires_complete_aggregation_and_attempt_scoped_raw_artifacts():
    workflow = yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
    jobs = workflow["jobs"]
    shards, aggregate = jobs["unit-shards"], jobs["tests"]
    assert shards["strategy"]["matrix"] == {"python": ["3.11", "3.12", "3.13"], "shard": ["0", "1"]}
    assert aggregate["strategy"]["matrix"]["python"] == ["3.11", "3.12", "3.13"]
    assert aggregate["name"] == "Contracts and unit tests (Python ${{ matrix.python }})"
    assert "unit-shards" in aggregate["needs"] and aggregate["if"] == "${{ always() }}"
    assembly = next(
        s for s in aggregate["steps"] if "scripts.unit_shards aggregate" in s.get("run", "")
    )
    assert assembly["if"] == "${{ always() }}"
    for job in (shards, aggregate):
        assert job["env"]["FISHHAT_VALIDATION_NOMINAL_MINUTES"] == "45"
        assert not any(step.get("continue-on-error") for step in job["steps"])
    upload = next(
        s for s in shards["steps"] if s.get("uses", "").startswith("actions/upload-artifact@")
    )
    assert "github.run_attempt" in upload["with"]["name"] and "always()" in upload["if"]
    assert "artifacts/unit-plan.json" in upload["with"]["path"]
    assert "make unit" in (ROOT / ".githooks/pre-commit").read_text()
