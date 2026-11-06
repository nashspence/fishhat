"""Exact owner contract discovery; advertisements never approve new work."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .handoffs import schema_document_digest, schema_identity
from .validation import CATALOGUES, SCHEMAS, ContractError, digest, validate

OWNER_CONTRACTS = {
    "request": "ssh-request.schema.json",
    "response": "ssh-response.schema.json",
    "cli": "cli-output.schema.json",
    "source": "source.schema.json",
}

FRESH_ADMISSION_METHODS = frozenset(
    CATALOGUES["https://fishhat.invalid/contracts/ssh-methods.json"]["fresh_admission"]["methods"]
)

_DECISION_SCHEMA = "owner-decision-v1.schema.json"
# A different decision format needs a new reader while v1 custody is retained.
# Updating an ordinary release/interface snapshot cannot replace this identity.
_V1_DECISION_READER = "sha256:25e0abd9ed3564ab409d259883c0a59b3bbbbc72d7099568989fe6c3e329e932"


def require_v1_decision_reader() -> None:
    """Fence an incompatible installation before it opens original v1 decision custody."""
    for schema, local, frozen in (
        ("records.schema.json", "SubmissionRefusal", "SubmissionRefusal"),
        ("records.schema.json", "Problem", "Problem"),
        ("cancellation.schema.json", "Receipt", "CancellationReceipt"),
    ):
        if SCHEMAS[schema]["$defs"].get(local) != {"$ref": f"{_DECISION_SCHEMA}#/$defs/{frozen}"}:
            raise ContractError("incompatible v1 decision reader")
    uri = "https://fishhat.invalid/contracts/" + _DECISION_SCHEMA
    installed = SCHEMAS.get(_DECISION_SCHEMA, {})
    if installed.get("$id") != uri or schema_document_digest(uri) != _V1_DECISION_READER:
        raise ContractError("incompatible v1 decision reader")


def admission_contract(schemas: Mapping[str, dict[str, str]]) -> str:
    """Commit independently approved boundaries on the caller, installed boundaries on the owner."""
    if schemas.keys() != OWNER_CONTRACTS.keys():
        raise ContractError("all owner contract boundaries are required")
    for name, value in schemas.items():
        validate("common.schema.json", value, "SchemaIdentity")
        if value["uri"] != SCHEMAS[OWNER_CONTRACTS[name]]["$id"]:
            raise ContractError("owner contract boundary URI changed")
    return digest(dict(schemas))


def require_admission_contract(supplied: str | None, installed: str) -> None:
    """Run under native upgrade/admission exclusion before any fresh write, after exact replay."""
    if supplied is None or supplied != installed:
        raise ContractError("CONFLICT: owner contract revision mismatch")


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
    The full selected boundary, including its normative catalogue dependencies,
    must match one independently approved revision. New work across a changed
    boundary requires a coordinated installation and policy update; this is not
    automatic negotiation or permission to discard an accepted-work reader.
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
