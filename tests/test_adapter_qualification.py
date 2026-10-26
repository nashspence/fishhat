from __future__ import annotations

import contextlib
import importlib
import io
import json

import pytest
from fishhat_adapter_support import main
from fishhat_adapters import require_qualification
from fishhat_contracts.validation import ContractError

from tests.adapter_support import D, descriptors

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": ["packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json"],
    "scope": "qualification identity and truthful installed-scaffold command results",
    "relationship": "candidate",
    "reason": "Scaffold commands and evidence validation do not prove real native behavior.",
    "claims": [],
}


def qualification():
    return {
        "installation_digest": D,
        "contract_digest": D,
        "configuration_digest": D,
        "environment_digest": D,
        "runner": "local.disposable-runner",
        "cases": [
            {"id": name, "outcome": "passed"}
            for name in ("failure-reconciliation", "linear-growth", "complete-extent")
        ],
        "external_accounts": False,
        "native_dependencies": [{"digest": D, "media_type": "application/zip", "size_bytes": 1}],
    }


def check(value):
    require_qualification(
        value,
        expected={
            k: D
            for k in (
                "installation_digest",
                "contract_digest",
                "configuration_digest",
                "environment_digest",
            )
        },
        required_cases={"failure-reconciliation"},
        trusted_runner="local.disposable-runner",
    )


@pytest.mark.parametrize("outcome", ["failed", "skipped", "not-executed"])
def test_native_gate_rejects_missing_execution(outcome):
    value = qualification()
    value["cases"][0]["outcome"] = outcome
    with pytest.raises(ContractError, match="UNQUALIFIED_NATIVE_BEHAVIOR"):
        check(value)


@pytest.mark.parametrize(
    "field",
    ["installation_digest", "contract_digest", "configuration_digest", "environment_digest"],
)
def test_native_evidence_is_bound_to_exact_artifacts_and_environment(field):
    value = qualification()
    value[field] = "sha256:" + "b" * 64
    with pytest.raises(ContractError, match="QUALIFICATION_IDENTITY"):
        check(value)


def test_declaration_cannot_replace_an_independently_selected_required_case():
    value = qualification()
    value["cases"][0]["id"] = "easy-smoke"
    with pytest.raises(ContractError, match="MISSING_QUALIFICATION_CASE"):
        check(value)


def test_required_local_test_identity_cannot_inherit_external_provider_accounts():
    value = qualification()
    value["external_accounts"] = True
    with pytest.raises(ContractError):
        check(value)


@pytest.mark.parametrize("path", descriptors(), ids=lambda p: p.parts[-4])
def test_scaffold_never_masquerades_as_native_qualification(path):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert main(str(path.with_name("cli.py")), ["qualify", "--json"]) == 2
    assert json.loads(out.getvalue())["native_qualified"] is False


@pytest.mark.parametrize("path", descriptors(), ids=lambda p: p.parts[-4])
def test_all_supplied_scaffolds_are_importable_with_independent_entrypoints(path):
    module = importlib.import_module(path.parent.name + ".cli")
    assert callable(module.main)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert main(str(path.with_name("cli.py")), ["info", "--json"]) == 0
    assert json.loads(out.getvalue())["native_mutations"] is False


@pytest.mark.parametrize("case", ["linear-growth", "complete-extent"])
@pytest.mark.parametrize("outcome", ["missing", "failed", "skipped", "not-executed"])
def test_engineering_cases_cannot_be_omitted_by_the_receiving_caller(case, outcome):
    value = qualification()
    if outcome == "missing":
        value["cases"] = [item for item in value["cases"] if item["id"] != case]
    else:
        next(item for item in value["cases"] if item["id"] == case)["outcome"] = outcome
    with pytest.raises(
        ContractError, match=r"MISSING_QUALIFICATION_CASE|UNQUALIFIED_NATIVE_BEHAVIOR"
    ):
        check(value)
