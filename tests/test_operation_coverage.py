from __future__ import annotations

import contextlib
import copy
import io
import json
import shutil
import sys
from importlib.metadata import entry_points
from unittest.mock import patch

import pytest

from scripts.check_evidence import evidence_group
from scripts.operation_qualification import REGISTRY, build_map, check, report
from scripts.project_policy import ROOT
from tests.support import FIXTURES

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/operation_qualification.py"],
    "scope": "coverage accounting",
    "relationship": "no-product-claim",
    "reason": "Coverage discovery, drift rejection and receipt interpretation protect validation, not the operations named in the map.",
    "claims": [],
}


TOOLS = {
    entry.name: entry.load()
    for entry in entry_points(group="console_scripts")
    if entry.name in {"domain-ops", "host-ops", "app-ops"}
}
assert set(TOOLS) == {"domain-ops", "host-ops", "app-ops"}


def invoke(main, arguments):
    with patch.object(sys, "argv", ["tool", *arguments]):
        return main()


def test_info_success_for_every_tool():
    interface = json.loads((ROOT / "policy/interfaces.json").read_text())["cli"]
    values = []
    with evidence_group("interface"):
        for tool, main in TOOLS.items():
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                assert invoke(main, ["info", "--json"]) == interface["exit_status"]["success"]
            value = json.loads(output.getvalue())
            assert set(value) == set(interface["info_keys"])
            assert value["tool"] == tool
            assert value["production_qualified"] is False
            values.append(value)
    with evidence_group("scaffold"):
        for value in values:
            assert value["capabilities"] == ["local-contract-validation"]
            assert value["native_mutations"] is False


def test_info_failure_for_every_tool():
    for main in TOOLS.values():
        with contextlib.redirect_stderr(io.StringIO()), pytest.raises(SystemExit) as error:
            invoke(main, ["info", "--unsupported-option"])
        assert error.value.code == 2


def test_validate_success_for_every_tool():
    for main in TOOLS.values():
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            assert invoke(main, ["validate", str(FIXTURES / "domain/domain.yaml"), "--json"]) == 0
        assert json.loads(output.getvalue())["status"] == "valid"


def test_validate_failure_for_every_tool(tmp_path):
    source = tmp_path / "input.json"
    source.write_text('{"SYNTHETIC_PRIVATE_SENTINEL":true}')
    original = source.read_bytes()
    for main in TOOLS.values():
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            assert invoke(main, ["validate", str(source), "--json"]) == 2
        assert json.loads(output.getvalue())["error"] == "INPUT_REJECTED"
        assert "SYNTHETIC_PRIVATE_SENTINEL" not in output.getvalue()
        assert str(source) not in output.getvalue()
    assert source.read_bytes() == original


def copy_sources(tmp_path):
    for name in ("packages", "fishhat", "some-implementations", "policy", "tests"):
        shutil.copytree(
            ROOT / name,
            tmp_path / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", "build"),
        )
    shutil.copyfile(ROOT / "release.toml", tmp_path / "release.toml")
    (tmp_path / "scripts").mkdir(exist_ok=True)
    for helper in ("validation_timeouts.py", "validation_workflows.py"):
        shutil.copyfile(ROOT / "scripts" / helper, tmp_path / "scripts" / helper)
    return tmp_path


def test_map_exhaustively_tracks_current_surfaces_and_native_gaps():
    coverage = check()
    rows = {row["id"]: row for row in coverage["operations"]}
    assert len([key for key in rows if key.startswith("action:")]) == 35
    assert len([key for key in rows if key.startswith("rpc:")]) == 32
    assert {
        "rpc:workflow.list",
        "rpc:workflow.journal.submit",
        "rpc:workflow.journal.get",
        "rpc:workflow.journal.list",
        "rpc:workflow.journal.events",
        "rpc:operation.cancellation.get",
        "rpc:operation.cancellation.list",
        "rpc:content.status",
        "rpc:record.read",
        "rpc:owner.history",
        "rpc:history.list",
        "rpc:history.read",
        "rpc:history.input",
        "rpc:history.content",
        "rpc:lifecycle.evidence.prepare",
    } <= rows.keys()
    assert rows["action:operation.recover"]["tools"] == ["app-ops", "host-ops"]
    assert all(
        row["status"] == "unimplemented" and row["implementation"] is None
        for key, row in rows.items()
        if key.startswith(("action:", "rpc:"))
    )
    assert all(
        row["implementation"]["stage"] == "scaffold"
        for row in rows.values()
        if row["implementation"]
    )


def test_new_catalogue_operation_requires_map_review(tmp_path):
    root = copy_sources(tmp_path)
    path = root / "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.json"
    catalogue = json.loads(path.read_text())
    item = copy.deepcopy(catalogue["actions"][0])
    item["name"] = "app.future"
    catalogue["actions"].append(item)
    path.write_text(json.dumps(catalogue))
    with pytest.raises(ValueError, match="coverage changed"):
        check(root)


def test_missing_test_binding_and_incomplete_recovery_fail(tmp_path):
    root = copy_sources(tmp_path)
    registry = root / REGISTRY
    original = registry.read_text()
    registry.write_text(original.replace("read_only = true", "read_only = false", 1))
    with pytest.raises(ValueError, match="proof requirements"):
        build_map(root)
    registry.write_text(original.replace("::test_info_success_for_every_tool", "::test_missing", 1))
    with pytest.raises(ValueError, match="definition"):
        build_map(root)


def test_unknown_implementation_binding_fails(tmp_path):
    root = copy_sources(tmp_path)
    registry = root / REGISTRY
    registry.write_text(
        registry.read_text().replace("cli:domain-ops:info", "cli:domain-ops:missing", 1)
    )
    with pytest.raises(ValueError, match="unknown operation"):
        build_map(root)


def test_report_requires_current_complete_executed_proofs(monkeypatch, tmp_path):
    import scripts.operation_qualification as operations
    from tests.evidence_support import sample_run

    coverage = build_map()
    source = {"commit": "a" * 40, "clean": True, "fingerprint": "b" * 64}
    monkeypatch.setattr(operations, "check", lambda root: coverage)
    monkeypatch.setattr(operations, "source_identity", lambda root: source)
    for name in ("policy", ".github"):
        shutil.copytree(ROOT / name, tmp_path / name)
    shutil.copyfile(ROOT / "Makefile", tmp_path / "Makefile")
    shutil.copyfile(ROOT / "release.toml", tmp_path / "release.toml")
    (tmp_path / "scripts").mkdir(exist_ok=True)
    for helper in ("validation_timeouts.py", "validation_workflows.py"):
        shutil.copyfile(ROOT / "scripts" / helper, tmp_path / "scripts" / helper)
    folder = tmp_path / "artifacts/validation"
    folder.mkdir(parents=True)
    receipt = sample_run(tmp_path, source)
    nodes = receipt["tests"]["outcomes"]
    path = folder / (receipt["id"] + ".json")
    path.write_text(json.dumps(receipt))
    result = report(tmp_path)
    assert sum(row["required_proofs_passed"] for row in result["operations"]) == 7
    assert all(not row["native_qualified"] for row in result["operations"])
    receipt["selection"]["canonical"] = False
    path.write_text(json.dumps(receipt))
    assert not any(row["required_proofs_passed"] for row in report(tmp_path)["operations"])
    receipt["selection"]["canonical"] = True
    receipt["source_after"] = {**source, "commit": "d" * 40}
    path.write_text(json.dumps(receipt))
    assert not any(row["required_proofs_passed"] for row in report(tmp_path)["operations"])
    receipt["source_after"] = source
    receipt["tests"]["outcomes"] = dict.fromkeys(nodes, "skipped")
    path.write_text(json.dumps(receipt))
    assert not any(row["required_proofs_passed"] for row in report(tmp_path)["operations"])


CHECK_OVERRIDES = {
    "test_info_success_for_every_tool": {
        "interface": {
            "purpose": "public-contract",
            "authority": ["policy/interfaces.json#/cli", "release.toml#/production_qualified"],
            "scope": "installed entrypoints in-process; local read-only scaffold",
            "relationship": "scoped-witness",
            "reason": "Independent interface exit status and fixed synthetic info success expectations; no native effects or recovery.",
            "claims": [
                "cli:domain-ops:info",
                "cli:host-ops:info",
                "cli:app-ops:info",
                "client:info",
            ],
        },
        "scaffold": {
            "purpose": "implementation",
            "authority": ["release.toml#/stage"],
            "scope": "in-process scaffold capability details",
            "relationship": "no-product-claim",
            "reason": "Literal capability and native-mutation flags protect scaffold implementation details without extending the frozen public interface.",
            "claims": [],
        },
    },
    "test_info_failure_for_every_tool": {
        "purpose": "public-contract",
        "authority": ["policy/interfaces.json#/cli"],
        "scope": "installed entrypoints in-process; local read-only scaffold",
        "relationship": "scoped-witness",
        "reason": "Independent interface exit status and fixed synthetic info failure expectations; no native effects or recovery.",
        "claims": ["cli:domain-ops:info", "cli:host-ops:info", "cli:app-ops:info", "client:info"],
    },
    "test_validate_success_for_every_tool": {
        "purpose": "public-contract",
        "authority": ["policy/interfaces.json#/cli"],
        "scope": "installed entrypoints in-process; local read-only scaffold",
        "relationship": "scoped-witness",
        "reason": "Independent interface exit status and fixed synthetic validate success expectations; no native effects or recovery.",
        "claims": ["cli:domain-ops:validate", "cli:host-ops:validate", "cli:app-ops:validate"],
    },
    "test_validate_failure_for_every_tool": {
        "purpose": "public-contract",
        "authority": ["policy/interfaces.json#/cli"],
        "scope": "installed entrypoints in-process; local read-only scaffold",
        "relationship": "scoped-witness",
        "reason": "Independent interface exit status and fixed synthetic validate failure expectations; no native effects or recovery.",
        "claims": ["cli:domain-ops:validate", "cli:host-ops:validate", "cli:app-ops:validate"],
    },
}


def test_every_implementation_binding_requires_growth_tests(tmp_path):
    root = copy_sources(tmp_path)
    registry = root / REGISTRY
    registry.write_text(
        registry.read_text().replace(
            'growth = ["tests/test_linear_growth.py::test_cli_linear_work"]', "growth = []", 1
        )
    )
    with pytest.raises(ValueError, match="proof requirements"):
        build_map(root)
