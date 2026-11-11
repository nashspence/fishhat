"""Finite synthetic host control admissions; never native launch authorization."""

from copy import deepcopy

from tests.adapter_support import OWNER, D, identifier


def process_admission(executor, request_digest):
    """Create the independent bounded-host record used by process codec fixtures."""
    owner = {**OWNER, "id": executor["scope"]["authority"]}
    return {
        "use_id": identifier(701),
        "owner": owner,
        "executor": deepcopy(executor),
        "request_digest": request_digest,
        "host": "node-a",
        "domain": {
            "owner": {**owner, "tool": "host-ops"},
            "host": "node-a",
            "capacity_domain": "synthetic-capacity",
            "incarnation": "synthetic-boot",
            "generation": 1,
        },
        "policy_digest": D,
        "class": "control",
        "admission_generation": 1,
        "control_budget": {
            "id": "synthetic-control",
            "generation": 1,
            "maximum": {"cpu_millis": 1000, "memory_bytes": 268435456, "devices": {}},
            "limits": {
                "cpu_max_millis": 1000,
                "memory_max_bytes": 268435456,
                "tasks_max": 64,
                "walltime_seconds": 30,
            },
        },
        "grant": None,
    }
