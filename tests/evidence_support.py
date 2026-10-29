"""Synthetic receipt records for challenging the real consumers, not product proof."""

import importlib
from types import SimpleNamespace

from scripts.check_evidence import (
    FORMAT,
    ROOT,
    conditions,
    fingerprint,
    group_results,
    inventory,
    item_groups,
)
from scripts.run_stats import RunStats
from scripts.validation import CANONICAL, digest
from scripts.validation import FORMAT as RECEIPT_FORMAT
from scripts.validation_timeouts import current


def reviewed_groups(root=ROOT):
    return {
        node: item_groups(
            SimpleNamespace(
                nodeid=node,
                module=importlib.import_module(node.split("::")[0][:-3].replace("/", ".")),
            ),
            ROOT,
        )
        for node in inventory(root)["pytest"]
    }


def sample_run(root, source):
    reviewed = inventory(root)
    declarations = reviewed_groups(root)
    outcomes = dict.fromkeys(declarations, "passed")
    phases = {
        node: {
            when: {
                "seconds": 0.001,
                "outcome": "passed",
                "rss_sample_bytes": 1024,
                "rss_scope": "process-snapshot-not-test-allocation",
                "expected_failure": False,
            }
            for when in ("setup", "call", "teardown")
        }
        for node in declarations
    }
    return {
        "format": RECEIPT_FORMAT,
        "id": "c" * 32,
        "started_at": "2026-01-01T00:00:00+00:00",
        "target": "unit",
        "state": "completed",
        "exit_status": 0,
        "source_before": source,
        "source_after": source,
        "selection": {
            "canonical": True,
            "invocation_sha256": digest(CANONICAL["unit"]),
            "work_sha256": digest(CANONICAL["unit"]),
            "environment_overrides": [],
        },
        "watchdogs": current().report(),
        "profile": conditions(),
        "tests": {
            "watchdogs": current().report(),
            "profile": conditions(),
            "exit_status": 0,
            "outcomes": outcomes,
            "phases": phases,
            "subtests": {},
            "collected_sha256": fingerprint(sorted(declarations)),
            "stats": RunStats().finish(),
            "evidence": {
                "format": FORMAT,
                "origin": "c" * 32,
                "inventory_sha256": fingerprint(reviewed),
                "groups": group_results(
                    declarations,
                    phases,
                    {node: set(groups) for node, groups in declarations.items()},
                    outcomes,
                ),
            },
        },
        "full_check_passed": True,
        "production_qualified": False,
    }
