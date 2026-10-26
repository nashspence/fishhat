"""Pure application-hook handoff checks; no materialization, grants or native execution."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

from .validation import ContractError, canonical, validate


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _path(value: str) -> PurePosixPath:
    _require(
        value.startswith("/") and all(part not in ("", ".", "..") for part in value[1:].split("/")),
        "noncanonical hook path",
    )
    return PurePosixPath(value)


def _disjoint(first: PurePosixPath, second: PurePosixPath) -> bool:
    return first != second and first not in second.parents and second not in first.parents


def _output_targets(value: dict[str, Any]) -> list[PurePosixPath]:
    output = _path(value["output_directory"])
    datasets = [_path(target["path"]) for target in value["dataset_handles"].values()]
    inputs = datasets + [_path(path) for path in value["secret_paths"].values()]
    _require(
        all(_disjoint(output, path) for path in inputs),
        "hook output overlaps dataset target or secret",
    )
    return [output, *datasets]


def validate_hook_request(value: dict[str, Any]) -> None:
    """Validate the closed request and exact snapshot/materialization joins.

    These lexical checks do not establish filesystem identity or authority. The
    receiving owner independently verifies accepted procedure grants, selected
    input custody, actual artifact bytes, native aliases and read-only isolation.
    """
    validate("hook-request.schema.json", value)
    targets = _output_targets(value)
    selected = value["restore_input"]
    if selected is None:
        return
    _require(
        set(selected["datasets"]) == set(value["dataset_handles"]),
        "restore input must cover every dataset target exactly",
    )
    paths: dict[PurePosixPath, bytes] = {}
    for dataset, item in selected["datasets"].items():
        snapshot = item["snapshot"]
        _require(
            snapshot["dataset"] == dataset and snapshot["producer"]["role"] == "capture",
            "restore snapshot dataset or producer mismatch",
        )
        expected = {canonical(artifact) for artifact in snapshot["artifacts"]}
        supplied = [canonical(entry["artifact"]) for entry in item["materializations"]]
        _require(
            len(supplied) == len(expected) and set(supplied) == expected,
            "restore materialization differs from complete snapshot artifacts",
        )
        for materialization in item["materializations"]:
            path = _path(materialization["path"])
            identity = canonical(materialization["artifact"])
            _require(
                path not in paths or paths[path] == identity,
                "restore materialization path selects different artifacts",
            )
            _require(
                all(_disjoint(path, target) for target in targets),
                "restore materialization overlaps dataset target or output",
            )
            paths[path] = identity


def require_selected_restore_input(
    value: dict[str, Any],
    *,
    checkpoint_digest: str,
    snapshots: Mapping[str, dict[str, Any]],
) -> None:
    """Compare with independently retained owner inputs, never request-derived pins.

    The owner supplies the checkpoint and snapshot closure selected by accepted
    work, after authenticating their custody. A matching result supplies neither
    continuing dispatch permission nor evidence of native materialization.
    """
    validate_hook_request(value)
    validate("common.schema.json", checkpoint_digest, "Digest")
    for snapshot in snapshots.values():
        validate("adapter.schema.json", snapshot, "Snapshot")
    selected = value["restore_input"]
    _require(selected is not None, "selected restore input requires a restore hook")
    _require(selected["checkpoint_digest"] == checkpoint_digest, "selected checkpoint changed")
    _require(
        {dataset: item["snapshot"] for dataset, item in selected["datasets"].items()}
        == dict(snapshots),
        "selected snapshot closure changed",
    )
