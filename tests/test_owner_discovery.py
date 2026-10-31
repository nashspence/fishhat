"""Owner discovery pins the exact boundaries selected by independent caller policy."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.discovery import owner_contract_schemas, require_owner_contracts
from fishhat_contracts.validation import ContractError, validate

from tests.test_owner_handoffs import V, operation

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Info",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/SchemaIdentity",
    ],
    "scope": "exact advertised owner contract identities before new boundary use",
    "relationship": "candidate",
    "reason": "Independent expected identities reject same-label incompatible schemas and owner-epoch substitutions while incompatible discovery remains inspectable. No native transport, permission or qualification is asserted.",
    "claims": [],
}


def info():
    return {
        "owner": operation()["owner"],
        "wire": "deployment-ops/owner/v1",
        "contract_schemas": owner_contract_schemas(),
        "source_formats": ["deployment-ops/source/v2"],
        "actions": ["app.restart"],
        "adapters": [],
    }


def test_installed_owner_contracts_match_independently_selected_boundaries():
    advertised = info()
    expected = copy.deepcopy(advertised["contract_schemas"])
    require_owner_contracts(
        advertised, expected_owner=operation()["owner"], expected_contracts=expected
    )


@pytest.mark.parametrize("boundary", ["request", "response", "cli", "source"])
def test_same_v1_label_does_not_approve_a_changed_contract(boundary):
    advertised = info()
    expected = copy.deepcopy(advertised["contract_schemas"])
    advertised["contract_schemas"][boundary]["digest"] = "sha256:" + "f" * 64
    # Discovery is an observation. Reading an incompatible advertisement is safe;
    # accepting it as the independently approved contract is not.
    validate("records.schema.json", advertised, "Info")
    with pytest.raises(ContractError, match="contract identity"):
        require_owner_contracts(
            advertised, expected_owner=operation()["owner"], expected_contracts=expected
        )


def test_discovery_requires_explicit_boundaries_and_current_owner():
    advertised = info()
    with pytest.raises(ContractError, match="explicit"):
        require_owner_contracts(
            advertised, expected_owner=operation()["owner"], expected_contracts={}
        )
    with pytest.raises(ContractError, match="epoch"):
        require_owner_contracts(
            advertised,
            expected_owner={**operation()["owner"], "epoch": V},
            expected_contracts=advertised["contract_schemas"],
        )


def test_legacy_discovery_without_exact_identities_is_rejected():
    advertised = info()
    del advertised["contract_schemas"]
    with pytest.raises(ContractError):
        validate("records.schema.json", advertised, "Info")
