"""Explicit synthetic backup producer context, separate from native acceptance."""

from copy import deepcopy

from fishhat_contracts.validation import digest

from tests.dataset_support import dataset_inventory


def backup_inventory(checkpoint):
    declaration = {
        "custody": "app",
        "recovery": "preserve",
        "native_format": "synthetic-capture-v1",
        "writers": [],
        "readers": [],
        "grant": "synthetic-data",
        "capture": "capture",
        "restore": "restore",
        "verify_restore": "verify-restore",
        "rebuild": None,
        "verify_rebuild": None,
        "owner": None,
    }
    app = {
        "id": "accepted-application",
        "datasets": {name: deepcopy(declaration) for name in checkpoint["datasets"]},
    }
    return dataset_inventory(
        app,
        checkpoint["owner"],
        checkpoint["release_digest"],
        app_instance=checkpoint["app_instance"],
    )


def backup_selection(checkpoint):
    return {
        "app_instance": checkpoint["app_instance"],
        "release_digest": checkpoint["release_digest"],
        "preserved_datasets": list(checkpoint["datasets"]),
        "secret_generations": list(checkpoint["secret_generations"]),
        "dataset_inventory_digest": digest(backup_inventory(checkpoint)),
    }


def backup_result(checkpoint, operation):
    return {
        "format": "deployment-ops/backup-result/v1",
        "kind": "BackupResult",
        "owner": deepcopy(operation["owner"]),
        "operation_id": operation["id"],
        "request_id": operation["request_id"],
        "plan_digest": operation["plan_digest"],
        "resource": deepcopy(operation["subject"]["resource"]),
        "selection": deepcopy(operation["subject"]["arguments"]["selection"]),
        "checkpoint": deepcopy(checkpoint),
    }
