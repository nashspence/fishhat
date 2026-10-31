"""Synthetic independently selected dataset state; no native admission or custody."""

from copy import deepcopy
from uuid import NAMESPACE_DNS, uuid5

from fishhat_contracts.validation import digest


def obligation(name, declaration, release, owner):
    return {
        "id": str(uuid5(NAMESPACE_DNS, "synthetic-dataset.invalid/" + name)),
        "origin_release_digest": release,
        "origin_dataset": name,
        "declaration": deepcopy(declaration),
        "native_identity": {
            "scope": {"authority": owner["id"], "kind": "dataset", "handle": "dataset:" + name},
            "incarnation": digest({"synthetic-native-dataset": name}),
        },
        "recovery_closure": [release],
    }


def dataset_inventory(app, owner, release, *, resource=None, app_instance=None):
    return {
        "format": "deployment-ops/dataset-obligations/v1",
        "kind": "DatasetInventory",
        "owner": deepcopy(owner),
        "resource": resource or {"kind": "app", "id": app["id"]},
        "app_instance": app_instance or "prod:" + "a" * 64,
        "generation": 1,
        "accepted_release_digest": release,
        "entries": [
            {
                "obligation": obligation(name, declaration, release, owner),
                "dataset": name,
                "discharge": None,
            }
            for name, declaration in app["datasets"].items()
        ],
    }


def selected_bindings(inventory):
    return {
        entry["dataset"]: deepcopy(entry["obligation"]["native_identity"])
        for entry in inventory["entries"]
        if entry["discharge"] is None
    }
