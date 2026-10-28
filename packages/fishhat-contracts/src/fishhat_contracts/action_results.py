"""Exact cleanup and captured-source result joins, without native authorization."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any, BinaryIO

from .bounds import Bounds, bounds
from .validation import ContractError, digest, validate


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _bounds(name: str) -> Bounds:
    proof = f"tests/test_action_results.py::test_{name.replace('-', '_')}_result_linear_work"
    return Bounds(
        id="action-results." + name,
        work="O(B) complete selected items, path bytes, metadata and distinct handle content bytes; indexed joins",
        extent="complete selected candidate/file collections without a total-count ceiling",
        limits=(),
        capacity=("receiving owner metadata memory and immutable content custody",),
        proofs=(proof,),
        linear_proofs=(proof,),
    )


@bounds(_bounds("cleanup"))
def validate_cleanup_result(value: dict[str, Any], operation: dict[str, Any]) -> None:
    """Join complete accounting to a validated Operation and its reviewed selection.

    Admission independently checks the inventory and application/account mapping.
    These structural joins neither authenticate the owner nor prove native removal.
    """
    validate("resource-records.schema.json", value, "CleanupReceipt")
    subject = operation["subject"]
    arguments = subject["arguments"]
    _require(
        subject["action"] == "app.cleanup"
        and value["owner"] == operation["owner"]
        and value["operation_id"] == operation["id"]
        and value["plan_digest"] == operation["plan_digest"]
        and value["account"] == arguments["account"],
        "cleanup result identity mismatch",
    )
    selected = set(arguments["candidates"])
    seen: set[str] = set()
    outcomes: set[str] = set()
    for item in value["items"]:
        _require(
            item["handle"] in selected and item["handle"] not in seen,
            "cleanup candidate substituted or duplicated",
        )
        seen.add(item["handle"])
        outcomes.add(item["outcome"])
    _require(seen == selected, "cleanup result omits selected candidates")
    _require(
        value["state"] != "verified-complete" or outcomes <= {"removed", "already-absent"},
        "complete cleanup contains unfinished outcomes",
    )
    _require(
        "unknown" not in outcomes or value["state"] == "effect-unknown",
        "unknown cleanup outcome lacks unknown aggregate state",
    )
    _require(
        value["state"] != "effect-unknown" or operation["effect_certainty"] == "unknown",
        "unknown cleanup result contradicts operation certainty",
    )
    _require(
        operation["state"] != "succeeded"
        or (value["state"] == "verified-complete" and operation["effect_certainty"] == "known"),
        "successful cleanup lacks complete known accounting",
    )


def _scope(paths: list[str]) -> dict[str, Any]:
    root: dict[str, Any] = {}
    for path in paths:
        branch = root
        for part in path.split("/"):
            branch = branch.setdefault(part, {})
        branch[""] = True
    return root


def _selected(path: str, scope: dict[str, Any]) -> bool:
    if not scope:
        return True
    branch = scope
    for part in path.split("/"):
        if "" in branch:
            return True
        if part not in branch:
            return False
        branch = branch[part]
    return "" in branch


def _tree_digest(files: list[dict[str, Any]]) -> str:
    return digest(
        {
            "format": "deployment-ops/captured-tree/v1",
            "files": [
                {
                    "path": item["path"],
                    "mode": item["mode"],
                    "digest": item["content"]["digest"],
                    "size": item["content"]["size"],
                }
                for item in files
            ],
        }
    )


def _captured_files(value: dict[str, Any], scope: dict[str, Any]) -> dict[str, dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    previous = ""
    branches: dict[str, Any] = {}
    handles: dict[str, dict[str, Any]] = {}
    sizes: dict[str, int] = {}
    for item in value["files"]:
        path, content = item["path"], item["content"]
        _require(
            path > previous and _selected(path, scope), "captured file order or scope mismatch"
        )
        previous = path
        branch = branches
        for part in path.split("/"):
            _require("" not in branch, "captured file overlaps a descendant")
            branch = branch.setdefault(part, {})
        _require(not branch, "captured file overlaps a descendant")
        branch[""] = True
        _require(
            content["owner"] == value["owner"]
            and content["purpose"] == "capture"
            and content["binding"] == {"kind": "operation", "operation_id": value["operation_id"]},
            "captured file custody identity mismatch",
        )
        _require(
            handles.get(content["id"], content) == content
            and sizes.get(content["digest"], content["size"]) == content["size"],
            "captured content identity has conflicting bytes",
        )
        handles[content["id"]] = content
        sizes[content["digest"]] = content["size"]
        files[path] = item
    return files


def _changes(
    value: dict[str, Any], files: dict[str, dict[str, Any]], scope: dict[str, Any]
) -> None:
    seen: set[str] = set()
    for change in value["changes"]:
        path, kind = change["path"], change["operation"]
        _require(
            path not in seen and _selected(path, scope), "capture change duplicated or out of scope"
        )
        seen.add(path)
        old, new = change["old_digest"], change["new_digest"]
        _require(
            (old is None) == (kind == "add") and (new is None) == (kind == "delete"),
            "capture change digest tuple contradicts operation",
        )
        item = files.get(path)
        if kind == "delete":
            _require(item is None, "deleted capture path remains in resulting tree")
        else:
            _require(
                item is not None
                and item["content"]["digest"] == new
                and item["mode"] == change["mode"],
                "capture change differs from resulting file",
            )


@bounds(_bounds("capture"))
def validate_source_proposal(
    value: dict[str, Any], *, operation: dict[str, Any] | None = None
) -> None:
    """Validate complete manifest relationships, not native completeness or signatures."""
    validate("records.schema.json", value, "SourceProposal")
    witness = value["witness"]
    _require(
        witness["owner"] == value["owner"]
        and witness["kind"] == "effect"
        and witness["state"] == "succeeded"
        and witness["subject_digest"] == digest({k: v for k, v in value.items() if k != "witness"}),
        "capture witness identity mismatch",
    )
    scope = _scope(value["paths"])
    files = _captured_files(value, scope)
    _require(value["tree_digest"] == _tree_digest(value["files"]), "captured tree digest mismatch")
    _changes(value, files, scope)
    if operation is not None:
        subject = operation["subject"]
        arguments = subject["arguments"]
        _require(
            subject["action"] == "host.capture-changes"
            and value["owner"] == operation["owner"]
            and value["operation_id"] == operation["id"]
            and value["base_commit"] == arguments["base"]
            and value["paths"] == arguments["paths"]
            and value["source_id"] == arguments["source_id"]
            and value["repository"] == arguments["repository"]
            and witness["generation"] == operation["generation"]
            and witness["workflow_id"] == operation["witness"]["workflow_id"],
            "capture result differs from producing operation",
        )


@bounds(_bounds("capture-material"))
def verify_source_proposal_material(
    value: dict[str, Any], *, open_content: Callable[[dict[str, Any]], BinaryIO]
) -> None:
    """Verify every captured file through the existing protected content-handle contract.

    The receiving owner supplies independently authorized immutable streams, then
    commits their complete custody and the exact base snapshot before publication
    admission. Retained receiving copies may satisfy a handle without the original
    client. This function proves bytes only, not confinement, retention or permission.
    """
    validate_source_proposal(value)
    verified: set[str] = set()
    for item in value["files"]:
        handle = item["content"]
        if handle["id"] in verified:
            continue
        checksum, size = hashlib.sha256(), 0
        with open_content(handle) as stream:
            while chunk := stream.read(65536):
                size += len(chunk)
                _require(size <= handle["size"], "captured content size changed")
                checksum.update(chunk)
        _require(
            size == handle["size"] and "sha256:" + checksum.hexdigest() == handle["digest"],
            "captured content identity mismatch",
        )
        verified.add(handle["id"])
