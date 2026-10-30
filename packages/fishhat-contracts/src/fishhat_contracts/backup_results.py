"""Exact backup producer and accepted-context joins, without native authority."""

from __future__ import annotations

from typing import Any

from .bounds import Bounds, bounds
from .checkpoints import validate_checkpoint
from .validation import ContractError, validate


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def validate_backup_selection(
    selection: dict[str, Any],
    *,
    resource: dict[str, Any],
    expected_resource: dict[str, Any],
    expected_selection: dict[str, Any],
) -> None:
    """Join independently loaded accepted state before review and native admission.

    Expected arguments come from protected owner state, never the proposed request.
    Native owners resolve resource-to-instance identity and preserve exclusion while
    checking current release, complete datasets and secrets. This helper neither
    authenticates that state nor performs source adoption, capture or admission.
    """
    validate("backup-result.schema.json", selection, "BackupSelection")
    validate("backup-result.schema.json", expected_selection, "BackupSelection")
    validate("common.schema.json", resource, "Resource")
    validate("common.schema.json", expected_resource, "Resource")
    _require(
        resource == expected_resource and resource["kind"] == "app",
        "backup application resource changed",
    )
    _require(selection == expected_selection, "backup accepted application selection changed")


@bounds(
    Bounds(
        id="backup.result",
        work="O(B + D + S) complete result and Operation bytes with indexed dataset/secret joins",
        extent="Every selected preserved dataset, secret generation and complete checkpoint result",
        limits=(),
        capacity=("receiving owner may refuse new capacity without dropping accepted results",),
        proofs=(
            "tests/test_backup_results.py::test_backup_result_retains_exact_producer_and_checkpoint",
        ),
        linear_proofs=(
            "tests/test_backup_results.py::test_backup_result_complete_selection_linear_work",
        ),
    )
)
def validate_backup_result(
    value: dict[str, Any], *, operation: dict[str, Any] | None = None
) -> None:
    """Join a validated Operation; standalone inspection grants no producing authority."""
    validate("backup-result.schema.json", value, "BackupResult")
    checkpoint, selection = value["checkpoint"], value["selection"]
    validate_checkpoint(checkpoint)
    _require(
        checkpoint["owner"] == value["owner"]
        and checkpoint["app_instance"] == selection["app_instance"]
        and checkpoint["release_digest"] == selection["release_digest"]
        and set(checkpoint["datasets"]) == set(selection["preserved_datasets"])
        and set(checkpoint["secret_generations"]) == set(selection["secret_generations"]),
        "backup checkpoint differs from accepted application selection",
    )
    if operation is not None:
        subject = operation["subject"]
        _require(
            subject["action"] == "app.backup"
            and value["owner"] == operation["owner"]
            and value["operation_id"] == operation["id"]
            and value["request_id"] == operation["request_id"]
            and value["plan_digest"] == operation["plan_digest"]
            and value["resource"] == subject["resource"]
            and selection == subject["arguments"]["selection"],
            "backup result differs from producing operation or reviewed selection",
        )
