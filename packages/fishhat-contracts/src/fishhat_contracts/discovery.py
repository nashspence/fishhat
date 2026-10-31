"""Exact owner contract discovery; advertisements never approve new work."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .handoffs import schema_identity
from .validation import SCHEMAS, ContractError, validate

OWNER_CONTRACTS = {
    "request": "ssh-request.schema.json",
    "response": "ssh-response.schema.json",
    "cli": "cli-output.schema.json",
    "source": "source.schema.json",
}


def owner_contract_schemas() -> dict[str, dict[str, str]]:
    """Publish installed identities without asserting interoperability or authority."""
    return {
        name: schema_identity(SCHEMAS[schema]["$id"]) for name, schema in OWNER_CONTRACTS.items()
    }


def require_owner_contracts(
    info: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    expected_contracts: Mapping[str, dict[str, str]],
) -> None:
    """Check selected boundaries against independently approved caller policy.

    Callers select every boundary used by their next operation. This comparison
    cannot establish transport authentication, current permissions or native
    qualification, and must not displace retained readers for accepted work.
    """
    validate("records.schema.json", info, "Info")
    if info["owner"] != expected_owner:
        raise ContractError("discovery owner epoch mismatch")
    if not expected_contracts or not set(expected_contracts) <= OWNER_CONTRACTS.keys():
        raise ContractError("discovery requires explicit approved contract boundaries")
    for name, expected in expected_contracts.items():
        validate("common.schema.json", expected, "SchemaIdentity")
        if info["contract_schemas"][name] != expected:
            raise ContractError("owner contract identity mismatch")
