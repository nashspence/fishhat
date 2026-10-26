"""Exact participant agreement before workflow child admission; no native signing.

An owner supplies its preparation witness only after independently authorizing and
durably retaining the complete proposal. Native receivers authenticate every
peer witness. These checks establish identity joins, not that native boundary.
"""

from __future__ import annotations

from typing import Any

from .validation import ContractError, canonical, digest, validate


def _preparation_identity(
    witness: dict[str, Any],
    workflow_id: str,
    proposal_digest: str,
    owners: set[bytes],
) -> None:
    validate("workflow.schema.json", witness, "PreparationWitness")
    if not (
        canonical(witness["owner"]) in owners
        and witness["workflow_id"] == workflow_id
        and witness["subject_digest"] == proposal_digest
    ):
        raise ContractError("workflow preparation witness changed proposal or participant")


def validate_preparation_witness(
    witness: dict[str, Any], proposal: dict[str, Any], *, owner: dict[str, Any] | None = None
) -> None:
    _preparation_identity(
        witness,
        proposal["workflow_id"],
        digest(proposal),
        {canonical(p["owner"]) for p in proposal["participants"]},
    )
    if owner is not None and witness["owner"] != owner:
        raise ContractError("workflow preparation witness changed proposal or participant")


def validate_workflow_agreement(
    workflow: dict[str, Any],
    *,
    witnesses: list[dict[str, Any]] | None = None,
    require_complete: bool = False,
) -> None:
    """Retain the original local proof and require the exact complete owner closure.

    Recovery successors instead use their complete committed preparation closure,
    which already signs the same immutable successor proposal under current owners.
    An incomplete recovery preparation never establishes agreement or admission.
    """
    recovery = workflow.get("recovery")
    if recovery is not None:
        if require_complete and recovery["phase"] != "committed":
            raise ContractError("workflow recovery agreement is not committed")
        return
    found: dict[bytes, bytes] = {}
    proposal = workflow["proposal"]
    expected = {canonical(p["owner"]) for p in proposal["participants"]}
    proposal_digest = digest(proposal)
    local = canonical(workflow["owner"])
    retained_local = False
    for source in (workflow["prerequisite_witnesses"], witnesses or []):
        for witness in source:
            if witness["state"] != "workflow-prepared":
                continue
            _preparation_identity(witness, proposal["workflow_id"], proposal_digest, expected)
            owner, encoded = canonical(witness["owner"]), canonical(witness)
            if owner in found and found[owner] != encoded:
                raise ContractError("workflow preparation replaced a retained owner witness")
            found[owner] = encoded
            if source is workflow["prerequisite_witnesses"] and owner == local:
                retained_local = True
    if not retained_local:
        raise ContractError("workflow lacks its retained local preparation witness")
    if require_complete and set(found) != expected:
        raise ContractError("workflow lacks complete same-proposal participant agreement")


def require_verified_preparations(
    request: dict[str, Any],
    workflow: dict[str, Any],
    verified_preparations: list[dict[str, Any]] | None,
) -> None:
    """New peer attestations must come from independent owner authentication."""
    retained = {canonical(w) for w in workflow["prerequisite_witnesses"]}
    trusted = {canonical(w) for w in verified_preparations or []}
    for witness in request["witnesses"]:
        if witness["state"] == "workflow-prepared" and canonical(witness) not in retained | trusted:
            raise ContractError("workflow preparation is not independently authenticated")
