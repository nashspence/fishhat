from __future__ import annotations

import copy
import json
import shutil
from unittest.mock import patch

import pytest

from scripts import check_evidence as evidence
from scripts.project_policy import ROOT
from scripts.validation import full_check_passed
from tests.evidence_support import reviewed_groups, sample_run
from tests.test_validation import checkout, latest  # noqa: F401

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/check_evidence.py"],
    "scope": "purpose and evidence accounting",
    "relationship": "no-product-claim",
    "reason": "Actual collectors and consumers are challenged without establishing any deployment effect.",
    "claims": [],
}


@pytest.fixture
def accounted(tmp_path):
    for name in ("policy", ".github"):
        shutil.copytree(ROOT / name, tmp_path / name)
    shutil.copyfile(ROOT / "Makefile", tmp_path / "Makefile")
    shutil.copyfile(ROOT / "release.toml", tmp_path / "release.toml")
    (tmp_path / "scripts").mkdir(exist_ok=True)
    for helper in ("validation_timeouts.py", "validation_workflows.py"):
        shutil.copyfile(ROOT / "scripts" / helper, tmp_path / "scripts" / helper)
    source = {"commit": "a" * 40, "clean": True, "fingerprint": "b" * 64}
    run = sample_run(tmp_path, source)
    folder = tmp_path / "artifacts/validation"
    folder.mkdir(parents=True)
    return tmp_path, source, run


def write_run(root, run):
    (root / "artifacts/validation" / (run["id"] + ".json")).write_text(json.dumps(run))


def test_maintained_entrypoints_and_real_collection_have_reviewed_dispositions():
    inv = evidence.inventory()
    groups = reviewed_groups()
    assert inv["entrypoints"] == evidence.entrypoints(ROOT)
    assert {g["purpose"] for gs in groups.values() for g in gs.values()} == evidence.PURPOSES
    assert all(
        g["authority"] and g["reason"] and g["scope"] for gs in groups.values() for g in gs.values()
    )
    assert all(
        "work_sha256" in v for k, v in inv["entrypoints"].items() if k.startswith(".github/")
    )
    evidence.reconcile_relationships(groups, ROOT)


@pytest.mark.parametrize(
    "change", ["new-node", "missing-node", "parameter", "purpose", "authority"]
)
def test_unreviewed_collection_or_authority_is_rejected(change):
    nodes = copy.deepcopy(reviewed_groups())
    node = next(iter(nodes))
    if change == "new-node":
        nodes[node + "[new]"] = nodes[node]
    elif change == "missing-node":
        del nodes[node]
    elif change == "parameter":
        nodes[node + "[renamed]"] = nodes.pop(node)
    elif change == "purpose":
        nodes[node]["check"]["purpose"] = "guessed-from-filename"
    else:
        nodes[node]["check"]["authority"] = ["release.toml#/retired_rule"]
    with pytest.raises(ValueError):
        evidence.reconcile(nodes, ROOT, complete=True)


def test_new_or_changed_workflow_requires_review(accounted):
    root, _, _ = accounted
    path = root / ".github/workflows/ci.yml"
    path.write_text(
        path.read_text().replace(
            "FISHHAT_VALIDATION_NOMINAL_MINUTES: '15'",
            "FISHHAT_VALIDATION_NOMINAL_MINUTES: '16'",
            1,
        )
    )
    with pytest.raises(ValueError, match="stale"):
        evidence.inventory(root)
    path.write_text(
        path.read_text() + "\n  unreviewed:\n    runs-on: ubuntu-24.04\n    steps: []\n"
    )
    with pytest.raises(ValueError, match="unclassified"):
        evidence.entrypoints(root)


@pytest.mark.parametrize(
    "damage",
    [
        "missing-case",
        "skip",
        "xfail",
        "xpass",
        "setup",
        "teardown",
        "origin",
        "source",
        "interrupted",
        "group",
        "authority",
        "purpose",
        "duplicate",
        "conditions",
        "child-conditions",
        "work",
        "override",
    ],
)
def test_consumers_cannot_promote_incomplete_wrong_or_failed_evidence(accounted, damage):
    root, source, run = accounted
    node = "tests/test_engineering.py::test_owner_crash_replay_preserves_state[uncommitted]"
    tests = run["tests"]
    if damage == "missing-case":
        for key in ("outcomes", "phases"):
            del tests[key][node]
        del tests["evidence"]["groups"][node]
        tests["collected_sha256"] = evidence.fingerprint(sorted(tests["outcomes"]))
    elif damage == "skip":
        tests["outcomes"][node] = "skipped"
    elif damage in {"xfail", "xpass"}:
        tests["phases"][node]["call"]["expected_failure"] = True
    elif damage in {"setup", "teardown"}:
        tests["phases"][node][damage]["outcome"] = "failed"
    elif damage == "origin":
        tests["evidence"]["origin"] = "d" * 32
    elif damage == "source":
        run["source_after"] = {**source, "fingerprint": "e" * 64}
    elif damage == "interrupted":
        run["state"], run["exit_status"] = "interrupted", 130
    elif damage == "group":
        del tests["evidence"]["groups"][node]
    elif damage == "authority":
        tests["evidence"]["groups"][node]["check"]["authority"] = ["Makefile"]
    elif damage == "purpose":
        tests["evidence"]["groups"][node]["check"]["purpose"] = "repository-policy"
    elif damage == "conditions":
        run["profile"]["platform"] = "unrelated-platform"
        tests["profile"] = run["profile"]
    elif damage == "child-conditions":
        tests["profile"]["python"] = "0.0.0"
    elif damage == "work":
        run["selection"]["work_sha256"] = "0" * 64
    elif damage == "override":
        run["selection"]["environment_overrides"] = ["PYTEST_ADDOPTS"]
    else:
        # A second artifact cannot impersonate the selected run's origin.
        (root / "artifacts/validation" / ("d" * 32 + ".json")).write_text(json.dumps(run))
        return assert_no_duplicate_origin(root, source)
    write_run(root, run)
    assert evidence.current_run(root, source) is None
    assert not evidence.proof(
        node.split("[")[0],
        "engineering:journal.submit",
        evidence.current_run(root, source),
        purpose="implementation",
    )["passed"]


def assert_no_duplicate_origin(root, source):
    assert evidence.current_run(root, source) is None


def test_latest_required_failure_cannot_be_hidden_by_older_success_or_union(accounted):
    root, source, passed = accounted
    write_run(root, passed)
    assert evidence.current_run(root, source)["id"] == passed["id"]
    failed = copy.deepcopy(passed)
    failed.update(id="d" * 32, started_at="2026-01-02T00:00:00+00:00", exit_status=1)
    failed["tests"]["evidence"]["origin"] = failed["id"]
    write_run(root, failed)
    assert evidence.current_run(root, source) is None
    # An unrelated failed iteration does not replace the selected complete run.
    failed["selection"]["canonical"] = False
    write_run(root, failed)
    assert evidence.current_run(root, source)["id"] == passed["id"]


def test_candidate_and_policy_checks_do_not_support_public_claims(accounted):
    root, source, run = accounted
    write_run(root, run)
    selected = evidence.current_run(root, source)
    assert evidence.proof(
        "tests/test_operation_coverage.py::test_info_success_for_every_tool",
        "cli:domain-ops:info",
        selected,
        purpose="public-contract",
    )["passed"]
    assert not evidence.proof(
        "tests/test_ci_config.py::WorkflowSafety::test_read_only_token",
        "cli:domain-ops:info",
        selected,
        purpose="repository-policy",
    )["passed"]
    assert not evidence.proof(
        "tests/test_contracts.py::Parsing::test_json_roundtrip",
        "cli:domain-ops:info",
        selected,
        purpose="public-contract",
    )["passed"]
    counts = evidence.summary(selected["tests"]["evidence"]["groups"])
    assert counts["selected_checks"] != counts["candidate_associations"]
    assert counts["production_qualified"] is False


def test_mixed_groups_need_their_actual_assertion_execution():
    groups = {"tests/test_example.py::test_a": {"product": CHECK_PURPOSE, "policy": CHECK_PURPOSE}}
    phases = {
        "tests/test_example.py::test_a": {
            p: {"outcome": "passed", "expected_failure": False}
            for p in ("setup", "call", "teardown")
        }
    }
    observed = set()
    token = evidence.ACTIVE.set(observed)
    try:
        with evidence.evidence_group("policy"):
            assert 2 + 2 == 4
        with pytest.raises(AssertionError), evidence.evidence_group("product"):
            raise AssertionError("synthetic failing group")
    finally:
        evidence.ACTIVE.reset(token)
    result = evidence.group_results(
        groups,
        phases,
        {"tests/test_example.py::test_a": observed},
        {"tests/test_example.py::test_a": "passed"},
    )
    assert result["tests/test_example.py::test_a"]["policy"]["outcome"] == "passed"
    assert result["tests/test_example.py::test_a"]["product"]["outcome"] == "not-executed"


def test_actual_cli_oracle_rejects_wrong_output_with_other_checks_green():
    from fishhat_cli import validation

    from tests import test_operation_coverage as cli

    original = validation.json.dumps

    def corrupt(value, *args, **kwargs):
        if isinstance(value, dict) and "capabilities" in value:
            value = {**value, "production_qualified": True}
        return original(value, *args, **kwargs)

    token = evidence.ACTIVE.set(set())
    try:
        with patch.object(validation.json, "dumps", corrupt), pytest.raises(AssertionError):
            cli.test_info_success_for_every_tool()
    finally:
        evidence.ACTIVE.reset(token)


def test_actual_growth_oracle_rejects_silent_extent_loss(tmp_path):
    from fishhat_reporting.store import EventStore

    from tests.test_engineering import (
        test_event_pages_use_bounded_indexed_work_and_preserve_full_extent,
    )

    original = EventStore.events

    def truncated(self, *args, **kwargs):
        value = original(self, *args, **kwargs)
        return {**value, "next_after": None}

    with patch.object(EventStore, "events", truncated), pytest.raises(AssertionError):
        test_event_pages_use_bounded_indexed_work_and_preserve_full_extent(tmp_path)


def test_targets_never_change_required_work_identity_or_eligibility(accounted):
    root, source, run = accounted
    write_run(root, run)
    baseline = evidence.current_run(root, source)
    (root / "policy/performance.toml").write_text("[targets]\n")
    assert evidence.current_run(root, source) == baseline
    run["tests"]["stats"]["elapsed_seconds"] = 10**12
    run["tests"]["stats"]["rss_high_water_bytes"] = 10**15
    write_run(root, run)
    assert full_check_passed(run)
    assert evidence.current_run(root, source)["id"] == baseline["id"]


def test_failed_setup_skip_and_expected_failure_are_truthful_records(checkout):  # noqa: F811
    from scripts import validation

    for body, expected in [
        (
            """import pytest
@pytest.mark.xfail(reason="fixture")
def test_pass(): assert False
""",
            "skipped",
        ),
        (
            """import pytest
@pytest.mark.xfail(reason="")
def test_pass(): assert True
""",
            "passed",
        ),
        (
            """import pytest
@pytest.fixture
def broken(): raise ValueError("fixture")
def test_pass(broken): assert True
""",
            "failed",
        ),
    ]:
        (checkout / "tests/test_example.py").write_text(body)
        code = validation.run("unit", validation.CANONICAL["unit"], checkout)
        value = latest(checkout)
        assert code == (1 if expected == "failed" else 0)
        assert value["tests"]["outcomes"]["tests/test_example.py::test_pass"] == expected
        assert value["tests"]["evidence"]["groups"]["tests/test_example.py::test_pass"]["check"][
            "outcome"
        ] in {"expected-failure", "not-executed"}


def test_onboarding_preserves_the_evidence_principle():
    text = (ROOT / "AGENTS.md").read_text()
    assert "Passing a test establishes only what its checks actually show." in text
    assert (
        "Agreement between implementations proves only agreement unless that agreement is itself promised."
        in text
    )
    assert (
        "Keep promises without sufficient proof visible, and preserve other required checks."
        in text
    )
    assert "(scripts/validation.py)" in text and "(scripts/check_evidence.py)" in text


@pytest.mark.parametrize("interrupted", [False, True], ids=["stop-on-failure", "interrupted"])
def test_partial_runs_preserve_unexecuted_cases_and_exit_status(checkout, interrupted):  # noqa: F811
    from scripts import validation

    body = (
        'import pytest\ndef test_pass(): pytest.exit("controlled exit", returncode=2)\n'
        if interrupted
        else "def test_pass(): assert 1 == 2\n"
    )
    (checkout / "tests/test_example.py").write_text(body + "def test_remaining(): assert True\n")
    path = checkout / "policy/checks.json"
    inv = json.loads(path.read_text())
    inv["pytest"].append(
        {
            "node": "tests/test_example.py::test_remaining",
            "purpose_sha256": inv["pytest"][0]["purpose_sha256"],
        }
    )
    path.write_text(json.dumps(inv))
    assert validation.run("unit", [*validation.CANONICAL["unit"], "-x"], checkout) == (
        2 if interrupted else 1
    )
    value = latest(checkout)
    assert value["tests"]["outcomes"]["tests/test_example.py::test_remaining"] == "not-executed"
    assert not value["full_check_passed"]
    assert (
        value["tests"]["evidence"]["groups"]["tests/test_example.py::test_remaining"]["check"][
            "outcome"
        ]
        == "not-executed"
    )


@pytest.mark.parametrize("outcome", ["failed", "skipped"])
def test_subtest_failures_and_skips_cannot_be_hidden_by_a_passing_call(checkout, outcome):  # noqa: F811
    from scripts import validation

    statement = "assert i == 0" if outcome == "failed" else 'pytest.skip("controlled skip")'
    (checkout / "tests/test_example.py").write_text(
        "import pytest\ndef test_pass(subtests):\n    for i in range(2):\n        with subtests.test(i=i):\n            "
        + statement
        + "\n"
    )
    assert validation.run("unit", validation.CANONICAL["unit"], checkout) == (
        1 if outcome == "failed" else 0
    )
    value = latest(checkout)
    assert value["tests"]["outcomes"]["tests/test_example.py::test_pass"] == outcome
    assert len(value["tests"]["subtests"]["tests/test_example.py::test_pass"]) == 2
    assert (
        value["tests"]["evidence"]["groups"]["tests/test_example.py::test_pass"]["check"]["outcome"]
        != "passed"
    )


def test_a_real_binding_rejects_an_unrelated_but_existing_authority():
    declarations = copy.deepcopy(reviewed_groups())
    node = "tests/test_engineering.py::test_frame_work_tracks_current_frame_not_stream_extent"
    declarations[node]["check"]["authority"] = ["Makefile"]
    with pytest.raises(ValueError, match="unrelated expectation authority"):
        evidence.reconcile_relationships(declarations, ROOT)
    declarations = copy.deepcopy(reviewed_groups())
    declarations[node]["check"]["claims"] = ["engineering:retired-operation"]
    with pytest.raises(ValueError, match="unbound or unrelated"):
        evidence.reconcile_relationships(declarations, ROOT)


def test_promised_structural_agreement_is_scoped_product_evidence(accounted):
    root, source, run = accounted
    write_run(root, run)
    witness = evidence.proof(
        "tests/test_component_policy.py::test_components_and_public_contracts_are_current",
        "interface:public-snapshot",
        evidence.current_run(root, source),
        purpose="public-contract",
    )
    assert witness["passed"]
    groups = next(iter(witness["cases"].values()))
    assert set(groups) == {"interface"}
    assert "structural agreement" in groups["interface"]["scope"]
    assert not evidence.proof(
        "tests/test_component_policy.py::test_components_and_public_contracts_are_current",
        "cli:domain-ops:info",
        evidence.current_run(root, source),
        purpose="public-contract",
    )["passed"]


@pytest.mark.parametrize("change", ["new-node", "parameter", "retired-override"])
def test_real_collection_requires_review_for_new_cases_and_retired_overrides(checkout, change):  # noqa: F811
    from scripts import validation

    if change == "new-node":
        path = checkout / "tests/test_example.py"
        path.write_text(path.read_text() + "\ndef test_new(): assert True\n")
    elif change == "parameter":
        (checkout / "tests/test_example.py").write_text(
            """import pytest
@pytest.mark.parametrize("case",[1],ids=["new"])
def test_pass(case): assert case == 1
"""
        )
    else:
        path = checkout / "conftest.py"
        path.write_text(
            path.read_text()
            + '\n    for item in items: item.module.CHECK_OVERRIDES = {"test_retired": {}}\n'
        )
    assert validation.run("unit", validation.CANONICAL["unit"], checkout) != 0
    assert not latest(checkout)["full_check_passed"]


@pytest.mark.parametrize("state", ["running", "interrupted", "completed"])
def test_incomplete_latest_publication_blocks_prior_success(accounted, state):
    root, source, passed = accounted
    write_run(root, passed)
    assert evidence.current_run(root, source)["id"] == passed["id"]
    unfinished = copy.deepcopy(passed)
    unfinished.update(
        id="d" * 32,
        started_at="2026-01-02T00:00:00+00:00",
        state=state,
        source_after=None,
        full_check_passed=False,
    )
    write_run(root, unfinished)
    assert evidence.current_run(root, source) is None


def test_large_current_receipt_requires_complete_passing_evidence(accounted):
    root, source, run = accounted
    run["observation"] = "x" * (4 * 1024 * 1024 + 1)
    write_run(root, run)
    assert evidence.current_run(root, source)["id"] == run["id"]
    last = next(reversed(run["tests"]["outcomes"]))
    run["tests"]["outcomes"][last] = "failed"
    write_run(root, run)
    assert evidence.current_run(root, source) is None
