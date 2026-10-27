from __future__ import annotations

import copy
import errno
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import profile, run_stats, validation
from scripts.engineering import proof_passed
from scripts.project_policy import ROOT
from scripts.validation_pytest import safe_node, write_stats
from tests.test_validation import checkout, latest  # noqa: F401

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/run_stats.py"],
    "scope": "observational instrumentation",
    "relationship": "no-product-claim",
    "reason": "Required statistics integrity and advisory comparisons; no machine-dependent numerical result is a correctness promise.",
    "claims": [],
}


def test_measurements_include_required_units_and_scopes():
    observed = run_stats.RunStats().finish()
    assert run_stats.valid_stats(observed)
    assert observed["rss_high_water_bytes"] > 0
    assert observed["rss_high_water_scope"] == "process-lifetime"
    assert observed["non_contractual"] is True
    for field in ("elapsed_seconds", "cpu_user_seconds", "rss_high_water_bytes"):
        invalid = {**observed, field: float("nan")}
        assert not run_stats.valid_stats(invalid)
    assert not run_stats.valid_stats(None)


def test_performance_targets_are_report_only_even_when_missed():
    observed = run_stats.RunStats().finish()
    for metric in ("elapsed_seconds", "cpu_user_seconds", "rss_high_water_bytes"):
        observed[metric] = 10**12
    result = run_stats.comparison(ROOT, ["tests"], observed, success=True, filtered=False)
    assert result["report_only"] and result["status"] == "compared"
    assert all(m["status"] == "missed" for m in result["metrics"].values())
    assert run_stats.valid_stats(observed)
    for success, filtered in ((False, False), (True, True)):
        result = run_stats.comparison(ROOT, ["tests"], observed, success=success, filtered=filtered)
        assert result["status"] == "not-compared"
    assert (
        run_stats.comparison(
            ROOT, ["tests/test_missing.py"], observed, success=True, filtered=False
        )["status"]
        == "not-compared"
    )


def test_missing_required_stats_blocks_complete_run_but_large_metrics_do_not(checkout):  # noqa: F811
    assert validation.run("unit", validation.CANONICAL["unit"], checkout) == 0
    receipt = latest(checkout)
    assert receipt["full_check_passed"]
    assert run_stats.valid_phases(receipt["tests"]["phases"])
    assert not run_stats.valid_phases({"node": {"call": {"seconds": 1.0}}})
    large = copy.deepcopy(receipt)
    large["tests"]["stats"]["elapsed_seconds"] = 10**12
    large["tests"]["stats"]["rss_high_water_bytes"] = 10**15
    assert validation.full_check_passed(large)
    large["tests"]["stats"] = None
    assert not validation.full_check_passed(large)
    with patch.object(validation, "read_test_results", return_value=None):
        assert validation.run("unit", validation.CANONICAL["unit"], checkout) == 2
    assert not latest(checkout)["full_check_passed"]


def test_test_stats_complete_retention_and_sanitization(tmp_path):
    unrelated = tmp_path / "artifacts/test-stats/keep.json"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_text("retained")
    for _ in range(35):
        write_stats(tmp_path, {"format": "fishhat-pytest-timing/v1"})
    assert len(list(unrelated.parent.glob("*.json"))) == 36
    assert unrelated.read_text() == "retained"
    assert "PRIVATE_SENTINEL" not in safe_node("tests/example.py::test_a[PRIVATE_SENTINEL/invalid]")
    large = write_stats(tmp_path, {"value": "x" * 2_000_001})
    assert len(json.loads(large.read_text())["value"]) == 2_000_001
    assert len(list(unrelated.parent.glob("*.json"))) == 37


def test_profile_is_bounded_non_contractual_and_cannot_qualify(tmp_path, monkeypatch):
    monkeypatch.setattr(profile, "ROOT", tmp_path)
    monkeypatch.setattr(profile, "source_identity", lambda: {"clean": False})
    assert profile.run("canonical", 256, 3) == 0
    value = json.loads((tmp_path / "artifacts/profiles/canonical.json").read_text())
    assert value["non_contractual"] is True
    assert value["qualification_eligible"] is False
    assert value["production_qualified"] is False
    assert run_stats.valid_stats(value["stats"])
    assert value["functions"] and len(value["functions"]) <= 30
    assert all(not row["file"].startswith("/") for row in value["functions"])
    for size, repeats in ((0, 1), (65537, 1), (1, 1001)):
        with pytest.raises(ValueError, match="unbounded"):
            profile.run("canonical", size, repeats)
    with pytest.raises(ValueError):
        profile.run("arbitrary-command", 1, 1)


def test_parameterized_proofs_require_all_executed_cases_and_no_skips():
    reference = "tests/example.py::test_a"
    assert proof_passed(reference, {reference + "[a]": "passed", reference + "[b]": "passed"})
    assert not proof_passed(reference, {reference + "[a]": "passed", reference + "[b]": "skipped"})
    assert not proof_passed(reference, {})


@pytest.mark.parametrize("stage", ["write_text", "chmod", "replace"])
def test_failed_stats_publication_retains_complete_history(tmp_path, monkeypatch, stage):
    prior = write_stats(tmp_path, {"observation": "complete"})
    original = getattr(Path, stage)

    def fail_temporary(self, *args, **kwargs):
        if self.parent == prior.parent and self.suffix == ".tmp":
            if stage == "write_text":
                original(self, "partial")
            raise OSError(errno.ENOSPC, "synthetic stats capacity exhausted")
        return original(self, *args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, stage, fail_temporary)
        with pytest.raises(OSError):
            write_stats(tmp_path, {"observation": "new"})
    assert list(prior.parent.glob("*.json")) == [prior]
    assert json.loads(prior.read_text()) == {"observation": "complete"}
    recovered = write_stats(tmp_path, {"observation": "new"})
    assert recovered != prior and prior.exists()


def test_parallel_metrics_account_for_workers_without_claiming_a_simultaneous_peak():
    controller = run_stats.RunStats().finish()
    worker = {**controller, "cpu_user_seconds": controller["cpu_user_seconds"] + 2}
    observed = run_stats.parallel_stats({"controller": controller, "gw0": worker})
    assert run_stats.valid_stats(observed)
    assert observed["elapsed_seconds"] == controller["elapsed_seconds"]
    assert (
        observed["cpu_user_seconds"] == controller["cpu_user_seconds"] + worker["cpu_user_seconds"]
    )
    assert observed["rss_high_water_bytes"] == 2 * controller["rss_high_water_bytes"]
    assert observed["rss_high_water_scope"] == "sum-of-process-lifetimes-upper-bound"
    assert observed["rss_sampled_peak_scope"] == "sum-of-per-process-samples-upper-bound"
    assert observed["scope"] == "pytest-controller-and-workers-excludes-other-children"
    assert run_stats.comparison(ROOT, ["tests"], observed, success=True, filtered=False) == {
        "report_only": True,
        "status": "not-compared",
        "reason": "measurement-scope",
    }
    for key in ("cpu_user_seconds", "rss_high_water_bytes", "elapsed_seconds"):
        assert not run_stats.valid_stats({**observed, key: observed[key] + 1})
    unavailable = {**worker, "io_available": False, "io_bytes": None}
    assert (
        run_stats.parallel_stats({"controller": controller, "gw0": unavailable})["io_bytes"] is None
    )
    with pytest.raises(ValueError):
        run_stats.parallel_stats({"controller": controller, "gw0": {}})


def test_parallel_cpu_totals_survive_worker_order_and_sorted_receipt_json(monkeypatch):
    from itertools import permutations

    def python311_sum(values):
        total = 0
        for value in values:
            total += value
        return total

    # Exercise the supported interpreter's addition semantics on every Python.
    monkeypatch.setattr(run_stats, "sum", python311_sum, raising=False)
    base = run_stats.RunStats().finish()
    processes = {
        name: {**base, "cpu_user_seconds": cpu, "cpu_system_seconds": cpu}
        for name, cpu in zip(("controller", "gw0", "gw1", "gw2"), (0.1, 0.2, 0.3, 0.4), strict=True)
    }
    for order in permutations(processes):
        observed = run_stats.parallel_stats({name: processes[name] for name in order})
        restored = json.loads(json.dumps(observed, sort_keys=True))
        assert observed["cpu_user_seconds"] == observed["cpu_system_seconds"] == 1.0
        assert run_stats.valid_stats(restored)
        assert run_stats.parallel_stats(restored["processes"]) == observed
