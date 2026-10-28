"""Operation/result joins and complete captured-file custody after client loss."""

from __future__ import annotations

import copy
import hashlib
import io
import json
from functools import partial

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_contracts import action_results
from fishhat_contracts.action_results import (
    validate_cleanup_result,
    validate_source_proposal,
    verify_source_proposal_material,
)
from fishhat_contracts.handoffs import schema_identity, validate_result_payload
from fishhat_contracts.validation import ContractError, canonical, digest
from fishhat_contracts.witness import sign

from tests.linear_support import assert_linear, measure
from tests.operation_support import seal_operation
from tests.test_contracts import uid
from tests.test_operation_semantics import FIXTURES, producer

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/SourceProposal",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json#/$defs/CleanupReceipt",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/Handle",
    ],
    "scope": "complete result identity, selected-item accounting, captured-file manifests and exact bytes",
    "relationship": "candidate",
    "reason": "Resealed contradictory results reject through the public result boundary. Complete captured bytes remain retrievable from owner handles after client loss; substituted or missing bytes reject. Synthetic streams do not establish native scope completeness, authentication, confinement or durable custody.",
    "claims": [],
}

CHECK_OVERRIDES = {
    f"test_{kind.replace('-', '_')}_result_linear_work": {
        "purpose": "implementation",
        "authority": [
            f"packages/fishhat-contracts/src/fishhat_contracts/action_results.py#{function}",
            "release.toml#/engineering",
        ],
        "scope": "complete selected items, manifest paths and file bytes over increasing extents",
        "relationship": "scoped-witness",
        "reason": "Executed work covers complete result validation or material reads across sixteenfold extent; synthetic bytes do not qualify native custody, scope inspection or authorization.",
        "claims": [f"engineering:action-results.{kind}"],
    }
    for kind, function in (
        ("cleanup", "validate_cleanup_result"),
        ("capture", "validate_source_proposal"),
        ("capture-material", "verify_source_proposal_material"),
    )
}


def tree_digest(files):
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


def seal_source(value, operation):
    body = {key: item for key, item in value.items() if key != "witness"}
    witness = {key: item for key, item in operation["witness"].items() if key != "signature"}
    witness.update(
        owner=copy.deepcopy(value["owner"]),
        kind="effect",
        state="succeeded",
        subject_digest=digest(body),
    )
    value["witness"] = sign(witness, Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))


def attach_result(operation, result, definition):
    schema = (
        "records.schema.json" if definition == "SourceProposal" else "resource-records.schema.json"
    )
    data = canonical(result)
    operation["result_handle"] = {
        "handle": {
            "owner": copy.deepcopy(operation["owner"]),
            "id": uid("result"),
            "purpose": "content",
            "binding": {"kind": "operation", "operation_id": operation["id"]},
            "digest": digest(result),
            "size": len(data),
        },
        "schema": schema_identity(
            f"https://fishhat.invalid/contracts/{schema}#/$defs/{definition}"
        ),
    }
    seal_operation(operation)
    return data


def cleanup_pair(count=3):
    operation = producer("app.cleanup")
    result = json.loads((FIXTURES / "resources/cleanup-receipt.json").read_text())
    result.update(
        owner=copy.deepcopy(operation["owner"]),
        operation_id=operation["id"],
        plan_digest=operation["plan_digest"],
    )
    result["items"] = [
        {"handle": digest({"candidate": index}), "outcome": "removed", "evidence": []}
        for index in range(count)
    ]
    operation["subject"]["arguments"]["candidates"] = [item["handle"] for item in result["items"]]
    operation.update(state="succeeded", effect_certainty="known")
    return operation, result


def capture_pair(count=2):
    operation = producer("host.capture-changes")
    operation["subject"]["arguments"]["paths"] = ["settings"]
    operation.update(state="succeeded", effect_certainty="known")
    arguments = operation["subject"]["arguments"]
    files, changes, retained = [], [], {}
    for index in range(count):
        data = f"captured file {index:06d}\n".encode()
        handle = {
            "owner": copy.deepcopy(operation["owner"]),
            "id": uid(f"captured-{index}"),
            "purpose": "capture",
            "binding": {"kind": "operation", "operation_id": operation["id"]},
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
        path = f"settings/file-{index:06d}"
        files.append({"path": path, "mode": "0644", "content": handle})
        changes.append(
            {
                "path": path,
                "mode": "0644",
                "operation": "add",
                "old_digest": None,
                "new_digest": handle["digest"],
            }
        )
        retained[handle["id"]] = data
    result = {
        "format": "deployment-ops/record/v1",
        "kind": "SourceProposal",
        "id": uid("proposal"),
        "operation_id": operation["id"],
        "repository": copy.deepcopy(arguments["repository"]),
        "source_id": arguments["source_id"],
        "base_commit": arguments["base"],
        "paths": list(arguments["paths"]),
        "ref": "refs/heads/captured-source",
        "files": files,
        "tree_digest": tree_digest(files),
        "changes": changes,
        "owner": copy.deepcopy(operation["owner"]),
    }
    seal_source(result, operation)
    return operation, result, retained


@pytest.mark.parametrize(
    "change",
    [
        "owner",
        "operation",
        "plan",
        "account",
        "candidate",
        "duplicate",
        "empty",
        "missing",
        "unknown",
        "skipped",
        "failed",
        "partial",
    ],
)
def test_cleanup_rejects_resealed_contradictory_result(change):
    operation, value = cleanup_pair()
    if change == "owner":
        value["owner"]["id"] = uid("other-owner")
    elif change == "operation":
        value["operation_id"] = uid("other-operation")
    elif change == "plan":
        value["plan_digest"] = digest({"other": "plan"})
    elif change == "account":
        value["account"] = "other-account"
    elif change == "candidate":
        value["items"][0]["handle"] = digest({"unselected": True})
    elif change == "duplicate":
        value["items"].append(copy.deepcopy(value["items"][0]))
    elif change == "empty":
        value["items"] = []
    elif change == "missing":
        value["items"].pop()
    elif change == "partial":
        value["state"] = "partial"
    else:
        value["items"][0]["outcome"] = change
        if change == "unknown":
            value["state"] = "effect-unknown"
    data = attach_result(operation, value, "CleanupReceipt")
    with pytest.raises(ContractError):
        validate_result_payload(operation, data)


@pytest.mark.parametrize(
    "state,outcome,certainty",
    [
        ("partial", "skipped", "known"),
        ("blocked", "failed", "known"),
        ("effect-unknown", "unknown", "unknown"),
    ],
)
def test_cleanup_preserves_complete_unfinished_accounting(state, outcome, certainty):
    operation, value = cleanup_pair()
    operation.update(
        state="quarantined" if certainty == "unknown" else "failed", effect_certainty=certainty
    )
    value["state"] = state
    value["items"][0]["outcome"] = outcome
    data = attach_result(operation, value, "CleanupReceipt")
    assert validate_result_payload(operation, data) == value


@pytest.mark.parametrize(
    "change",
    [
        "owner",
        "operation",
        "base",
        "repository",
        "source",
        "scope",
        "workflow",
        "generation",
        "witness",
        "ref",
        "duplicate-change",
        "digest-tuple",
        "out-of-scope",
        "new-digest",
        "tree-digest",
        "missing-file",
        "deleted-present",
        "file-order",
        "duplicate-file",
        "file-overlap",
        "content-owner",
        "content-operation",
        "content-purpose",
    ],
)
def test_capture_rejects_resealed_contradictory_result(change):
    operation, value, _ = capture_pair()
    replacements = {
        "base": ("base_commit", "b" * 40),
        "source": ("source_id", "other-source"),
        "scope": ("paths", []),
        "ref": ("ref", "refs/heads/../../invalid\nref"),
    }
    if change in replacements:
        key, replacement = replacements[change]
        value[key] = replacement
    elif change == "owner":
        value["owner"]["id"] = uid("other-owner")
        for item in value["files"]:
            item["content"]["owner"] = copy.deepcopy(value["owner"])
    elif change == "operation":
        value["operation_id"] = uid("other-operation")
        for item in value["files"]:
            item["content"]["binding"]["operation_id"] = value["operation_id"]
    elif change == "repository":
        value["repository"]["repository_id"] += 1
    elif change == "duplicate-change":
        value["changes"].append(copy.deepcopy(value["changes"][0]))
    elif change == "digest-tuple":
        value["changes"][0]["operation"] = "delete"
    elif change == "out-of-scope":
        value["changes"][0]["path"] = "settings-elsewhere/file"
    elif change == "new-digest":
        value["changes"][0]["new_digest"] = digest("different")
    elif change == "missing-file":
        value["files"].pop()
    elif change == "deleted-present":
        value["changes"][0].update(operation="delete", old_digest=digest("old"), new_digest=None)
    elif change == "file-order":
        value["files"].reverse()
    elif change == "duplicate-file":
        value["files"].insert(1, copy.deepcopy(value["files"][0]))
    elif change == "file-overlap":
        value["files"][1]["path"] = value["files"][0]["path"] + "/child"
    elif change == "content-owner":
        value["files"][0]["content"]["owner"]["id"] = uid("other-owner")
    elif change == "content-operation":
        value["files"][0]["content"]["binding"]["operation_id"] = uid("other-operation")
    elif change == "content-purpose":
        value["files"][0]["content"]["purpose"] = "content"
    value["tree_digest"] = (
        digest("different") if change == "tree-digest" else tree_digest(value["files"])
    )
    seal_source(value, operation)
    if change in {"workflow", "generation", "witness"}:
        body = {key: item for key, item in value["witness"].items() if key != "signature"}
        key, replacement = {
            "workflow": ("workflow_id", uid("other-workflow")),
            "generation": ("generation", operation["generation"] + 1),
            "witness": ("subject_digest", digest("other-subject")),
        }[change]
        body[key] = replacement
        value["witness"] = sign(body, Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))
    data = attach_result(operation, value, "SourceProposal")
    with pytest.raises(ContractError):
        validate_result_payload(operation, data)


def test_complete_results_survive_client_loss():
    operation, value = cleanup_pair()
    value["items"][0]["outcome"] = "already-absent"
    assert (
        validate_result_payload(operation, attach_result(operation, value, "CleanupReceipt"))
        == value
    )
    operation, proposal, retained = capture_pair()
    original_bytes = attach_result(operation, proposal, "SourceProposal")
    # Reconstruct only from owner-held Operation/result bytes and owner content.
    del proposal
    recovered = validate_result_payload(operation, original_bytes)
    opened = []

    def open_content(handle):
        opened.append(handle["id"])
        return io.BytesIO(retained[handle["id"]])

    verify_source_proposal_material(recovered, open_content=open_content)
    assert set(opened) == set(retained)
    assert len(recovered["files"]) == 2
    assert recovered["tree_digest"] == tree_digest(recovered["files"])


@pytest.mark.parametrize("damage", ["missing", "changed", "short", "long"])
def test_capture_material_rejects_incomplete_or_changed_owner_bytes(damage):
    _, value, retained = capture_pair()
    first = value["files"][0]["content"]["id"]
    if damage == "missing":
        del retained[first]
    else:
        retained[first] = {
            "changed": b"x" * len(retained[first]),
            "short": retained[first][:-1],
            "long": retained[first] + b"x",
        }[damage]

    def open_content(handle):
        if handle["id"] not in retained:
            raise ContractError("owner content unavailable")
        return io.BytesIO(retained[handle["id"]])

    with pytest.raises(ContractError):
        verify_source_proposal_material(value, open_content=open_content)


def test_capture_modify_delete_and_unchanged_files_have_explicit_manifest():
    operation, value, retained = capture_pair()
    value["changes"][0].update(operation="modify", old_digest=digest("old-value"))
    value["changes"][1].update(
        operation="delete", old_digest=digest("deleted-value"), new_digest=None
    )
    value["files"].pop()
    value["tree_digest"] = tree_digest(value["files"])
    seal_source(value, operation)
    validate_result_payload(operation, attach_result(operation, value, "SourceProposal"))
    value["changes"] = []
    seal_source(value, operation)
    validate_result_payload(operation, attach_result(operation, value, "SourceProposal"))
    verify_source_proposal_material(
        value, open_content=lambda handle: io.BytesIO(retained[handle["id"]])
    )


@pytest.mark.parametrize("change", ["handle", "digest-size"])
def test_captured_content_identity_cannot_declare_conflicting_bytes(change):
    operation, value, _ = capture_pair()
    first, second = (item["content"] for item in value["files"])
    if change == "handle":
        second["id"] = first["id"]
    else:
        second["digest"] = first["digest"]
        second["size"] = first["size"] + 1
        value["changes"][1]["new_digest"] = second["digest"]
    value["tree_digest"] = tree_digest(value["files"])
    seal_source(value, operation)
    with pytest.raises(ContractError, match="conflicting bytes"):
        validate_result_payload(operation, attach_result(operation, value, "SourceProposal"))


def test_multiple_paths_can_share_one_exact_immutable_content_handle():
    operation, value, retained = capture_pair()
    value["files"][1]["content"] = copy.deepcopy(value["files"][0]["content"])
    value["changes"][1]["new_digest"] = value["files"][1]["content"]["digest"]
    value["tree_digest"] = tree_digest(value["files"])
    seal_source(value, operation)
    validate_result_payload(operation, attach_result(operation, value, "SourceProposal"))
    opened = []

    def open_content(handle):
        opened.append(handle["id"])
        return io.BytesIO(retained[handle["id"]])

    verify_source_proposal_material(value, open_content=open_content)
    assert opened == [value["files"][0]["content"]["id"]]


def result_linear_work(kind):
    samples = []
    for count in (8, 32, 128):
        if kind == "cleanup":
            operation, value = cleanup_pair(count)
            call = partial(validate_cleanup_result, value, operation)
        else:
            operation, value, retained = capture_pair(count)
            if kind == "capture":
                call = partial(validate_source_proposal, value, operation=operation)
            else:
                call = partial(
                    verify_source_proposal_material,
                    value,
                    open_content=lambda handle, retained=retained: io.BytesIO(
                        retained[handle["id"]]
                    ),
                )
        _, work = measure(call, modules=(action_results,))
        samples.append((count, work))
    assert_linear(samples)


def test_cleanup_result_linear_work():
    result_linear_work("cleanup")


def test_capture_result_linear_work():
    result_linear_work("capture")


def test_capture_material_result_linear_work():
    result_linear_work("capture-material")
