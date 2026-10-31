"""Pure relocation recovery-basis checks, without ownership transfer or native recovery."""

from __future__ import annotations

from typing import Any

from .datasets import require_dataset_source
from .validation import ContractError, digest, validate


def validate_relocation(
    arguments: dict[str, Any],
    *,
    accepted_app: dict[str, Any],
    accepted_release_digest: str,
    accepted_inventory: dict[str, Any],
    expected_owner: dict[str, Any],
    expected_resource: dict[str, Any],
    expected_app_instance: str,
) -> None:
    """Join a proposal to independently loaded accepted source and release identity.

    Callers cannot supply a replacement source to reclassify preserved datasets.
    Checkpoint custody, external owners, reconstruction verification, destination
    admission and the fenced ownership handoff remain the receiving owner's work.
    """
    validate("actions.schema.json", arguments, "app.relocate")
    validate("source.schema.json", accepted_app, "App")
    validate("common.schema.json", accepted_release_digest, "Digest")
    require_dataset_source(
        accepted_inventory,
        accepted_app=accepted_app,
        accepted_release_digest=accepted_release_digest,
    )
    if not (
        accepted_inventory["owner"] == expected_owner
        and accepted_inventory["resource"] == expected_resource
        and accepted_inventory["app_instance"] == expected_app_instance
        and digest(accepted_inventory) == arguments["dataset_inventory_digest"]
    ):
        raise ContractError("relocation differs from retained dataset inventory")
    basis = arguments["recovery_basis"]
    if basis["kind"] == "checkpoint":
        return
    if basis["release_digest"] != accepted_release_digest:
        raise ContractError("relocation release differs from accepted release")
    if any(
        entry["discharge"] is None and entry["obligation"]["declaration"]["recovery"] == "preserve"
        for entry in accepted_inventory["entries"]
    ):
        raise ContractError("preserved application data requires a checkpoint")
