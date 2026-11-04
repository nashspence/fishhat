"""Reuse of installed core commitments under complete mutable source checks."""

from __future__ import annotations

from copy import deepcopy

import pytest
from fishhat_contracts import handoffs
from fishhat_contracts.validation import CATALOGUES, SCHEMAS, ContractError

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": ["packages/fishhat-contracts/src/fishhat_contracts/handoffs.py"],
    "scope": "core schema digest reuse, complete source changes and fresh custom admission",
    "relationship": "candidate",
    "reason": "Cache mutation and fresh-path comparisons exercise the implementation without independently qualifying public schema semantics or native authority.",
    "claims": [],
}

COMMON = "https://fishhat.invalid/contracts/common.schema.json"
UUID = COMMON + "#/$defs/UUID"


@pytest.mark.parametrize(
    "change",
    ["annotation", "unreachable-reference", "missing-document", "boolean-number", "unsafe-integer"],
)
def test_core_identity_rechecks_complete_document_sources(monkeypatch, change):
    schema = SCHEMAS["common.schema.json"]
    if change == "boolean-number":
        monkeypatch.setitem(schema, "default", True)
    elif change == "unsafe-integer":
        monkeypatch.setitem(schema, "default", float(2**53))
    original = handoffs.schema_identity(UUID)
    assert handoffs.schema_identity(UUID) == original == handoffs.schema_identity(UUID, {})
    if change == "annotation":
        monkeypatch.setitem(schema, "description", schema["description"] + " Additional context.")
    elif change == "unreachable-reference":
        monkeypatch.setitem(schema["$defs"], "UnusedCacheCheck", {"$ref": "#/$defs/NotInstalled"})
    elif change == "missing-document":
        monkeypatch.delitem(SCHEMAS, "common.schema.json")
    elif change == "boolean-number":
        monkeypatch.setitem(schema, "default", 1)
    else:
        monkeypatch.setitem(schema, "default", 2**53)
    if change in {"unreachable-reference", "missing-document", "unsafe-integer"}:
        with pytest.raises(ContractError):
            handoffs.schema_identity(UUID)
        with pytest.raises(ContractError):
            handoffs.schema_identity(UUID, {})
    else:
        updated = handoffs.schema_identity(UUID)
        assert updated != original
        assert updated == handoffs.schema_identity(UUID, {})


@pytest.mark.parametrize("remove", [False, True], ids=["changed-catalogue", "missing-catalogue"])
def test_core_identity_rechecks_catalogue_sources(monkeypatch, remove):
    uri = "https://fishhat.invalid/contracts/actions.schema.json"
    catalogue = "https://fishhat.invalid/contracts/actions.json"
    original = handoffs.schema_identity(uri)
    assert handoffs.schema_identity(uri) == original
    if remove:
        monkeypatch.delitem(CATALOGUES, catalogue)
        with pytest.raises(ContractError, match="catalogue is not installed"):
            handoffs.schema_identity(uri)
    else:
        current = CATALOGUES[catalogue]
        monkeypatch.setitem(current, "format", current["format"] + "-changed")
        updated = handoffs.schema_identity(uri)
        assert updated != original
        assert updated == handoffs.schema_identity(uri, {})


def test_core_digest_reuse_does_not_admit_a_custom_core_replacement():
    handoffs.schema_identity(UUID)
    with pytest.raises(ContractError, match="replaces core contract"):
        handoffs.schema_identity(UUID, {COMMON: deepcopy(SCHEMAS["common.schema.json"])})


def test_identity_result_mutation_cannot_change_a_later_commitment():
    first = handoffs.schema_identity(UUID)
    expected = first.copy()
    first.update(uri="https://fishhat.invalid/other", digest="sha256:" + "0" * 64)
    assert handoffs.schema_identity(UUID) == expected == handoffs.schema_identity(UUID, {})
