"""Explicit synthetic backup producer context, separate from native acceptance."""

from copy import deepcopy


def backup_selection(checkpoint):
    return {
        "app_instance": checkpoint["app_instance"],
        "release_digest": checkpoint["release_digest"],
        "preserved_datasets": list(checkpoint["datasets"]),
        "secret_generations": list(checkpoint["secret_generations"]),
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
