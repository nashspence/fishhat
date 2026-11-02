"""Independent scalar-language expectations for public path and reference grammar."""

import json

import pytest
from fishhat_client.bootstrap import validate_catalogue, validate_receipt, validate_selection
from fishhat_contracts.validation import ContractError, validate, validate_domain

from tests.support import FIXTURES
from tests.test_source_bootstrap_refs import bound_records

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/RelativePath",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/AbsolutePath",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/GitRef",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/bootstrap-recovery.schema.json",
    ],
    "scope": "fixed path-segment and literal Git-ref language, including Unicode separators and whitespace",
    "relationship": "candidate",
    "reason": "Independent accepted/rejected scalar vectors exercise the public Python schema validator and bootstrap consumers. The standalone probe additionally checks ECMAScript-u without adding Node to Python CI prerequisites; lexical checks do not qualify native filesystem or Git effects.",
    "claims": [],
}

VECTORS = json.loads((FIXTURES / "core-regex/expected.json").read_text())


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["id"])
def test_core_string_grammar_has_explicit_expected_language(vector):
    if vector["valid"]:
        validate("common.schema.json", vector["value"], vector["definition"])
    else:
        with pytest.raises(ContractError):
            validate("common.schema.json", vector["value"], vector["definition"])


def test_bootstrap_consumers_use_the_frozen_ref_whitespace_policy():
    for vector in VECTORS:
        if vector["definition"] != "GitRef" or "-excluded-U" not in vector["id"]:
            continue
        domain, selection, catalogue, receipt = bound_records(vector["value"])
        for check, arguments in (
            (validate_domain, (domain,)),
            (validate_selection, (selection,)),
            (validate_catalogue, (catalogue,)),
            (validate_receipt, (receipt, selection)),
        ):
            with pytest.raises(ContractError):
                check(*arguments)
