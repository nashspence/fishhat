"""Exact synthetic restore inputs and observation access, without native execution."""

from __future__ import annotations

from copy import deepcopy

import pytest
from fishhat_contracts.hooks import require_selected_restore_input, validate_hook_request
from fishhat_contracts.validation import ContractError, validate

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/hook-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json#/$defs/Snapshot",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json#/$defs/App",
    ],
    "scope": "exact selected restore snapshots, complete immutable materializations, role access and disjoint output paths",
    "relationship": "candidate",
    "reason": "Adverse request substitutions and omitted input cases exercise pure schema and reference joins, without establishing materialization, native path identity or authority.",
    "claims": [],
}

D = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
ROLES = [
    "health",
    "configure",
    "verify-config",
    "dependency-check",
    "busy",
    "quiesce",
    "transition-assess",
    "transition-apply",
    "transition-verify",
    "capture",
    "restore",
    "verify-restore",
    "rebuild",
    "verify-rebuild",
]


def request(role="restore"):
    artifact = {"digest": D, "media_type": "application/octet-stream", "size_bytes": 64}
    snapshot = {
        "handle": "snapshot:selected",
        "dataset": "state",
        "format": "independent.snapshot",
        "consistency": "quiesced",
        "recovery_point": None,
        "artifacts": [deepcopy(artifact)],
        "restore_requirements": [],
        "producer": {
            "instance": "capture",
            "role": "capture",
            "installation_digest": D,
            "configuration_digest": D,
            "instance_generation": 1,
            "instance_digest": D,
            "scope": {
                "authority": "00000000-0000-4000-8000-000000000003",
                "kind": "dataset",
                "handle": "state",
            },
        },
    }
    return {
        "format": "deployment-ops/hook/v1",
        "procedure_digest": "sha256:" + "a" * 64,
        "runtime_binding_digest": D,
        "required_checks": ["VERIFICATION_OK"],
        "id": "00000000-0000-4000-8000-000000000001",
        "operation_id": "00000000-0000-4000-8000-000000000002",
        "release_digest": D,
        "executor_component": "maintenance",
        "subject": {"kind": "dataset", "id": "state"},
        "role": role,
        "dataset_handles": {
            "state": {"path": "/synthetic/target", "mode": "write" if role == "restore" else "read"}
        },
        "secret_paths": {},
        "endpoint_bindings": {},
        "output_directory": "/synthetic/output",
        "timeout_seconds": 60,
        "restore_input": {
            "checkpoint_digest": D,
            "datasets": {
                "state": {
                    "snapshot": snapshot,
                    "materializations": [
                        {"artifact": artifact, "path": "/synthetic/input/state", "mode": "read"}
                    ],
                }
            },
        }
        if role in {"restore", "verify-restore"}
        else None,
    }


@pytest.mark.parametrize("role", ["restore", "verify-restore"])
def test_restore_handoff_preserves_selected_checkpoint_and_complete_snapshot(role):
    value = request(role)
    selected = deepcopy(value["restore_input"])
    require_selected_restore_input(
        value,
        checkpoint_digest=selected["checkpoint_digest"],
        snapshots={name: item["snapshot"] for name, item in selected["datasets"].items()},
    )
    assert value["restore_input"] == selected


@pytest.mark.parametrize("role", ["restore", "verify-restore"])
@pytest.mark.parametrize("change", ["missing", "null"])
def test_restore_cannot_omit_the_selected_input(role, change):
    value = request(role)
    if change == "missing":
        del value["restore_input"]
    else:
        value["restore_input"] = None
    with pytest.raises(ContractError):
        validate_hook_request(value)


@pytest.mark.parametrize(
    "role",
    [
        "health",
        "verify-config",
        "dependency-check",
        "busy",
        "transition-assess",
        "transition-verify",
        "capture",
        "verify-restore",
        "verify-rebuild",
    ],
)
def test_observational_hook_wire_cannot_expand_dataset_access(role):
    value = request(role)
    validate_hook_request(value)
    value["dataset_handles"]["state"]["mode"] = "write"
    with pytest.raises(ContractError):
        validate_hook_request(value)


@pytest.mark.parametrize("role", ["health", "capture", "configure", "rebuild"])
def test_other_hook_roles_cannot_borrow_restore_inputs(role):
    value = request()
    value["role"] = role
    value["dataset_handles"]["state"]["mode"] = "read"
    with pytest.raises(ContractError):
        validate_hook_request(value)


@pytest.mark.parametrize("change", ["omitted-target", "other-dataset", "wrong-producer"])
def test_restore_snapshot_cannot_change_dataset_or_capture_identity(change):
    value = request()
    snapshot = value["restore_input"]["datasets"]["state"]["snapshot"]
    if change == "omitted-target":
        value["dataset_handles"]["additional"] = {"path": "/synthetic/other", "mode": "write"}
    elif change == "other-dataset":
        snapshot["dataset"] = "other"
    else:
        snapshot["producer"]["role"] = "runtime"
    with pytest.raises(ContractError):
        validate_hook_request(value)


@pytest.mark.parametrize("change", ["missing", "additional", "duplicate", "changed-bytes"])
def test_restore_materialization_must_equal_the_complete_artifact_closure(change):
    value = request()
    selected = value["restore_input"]["datasets"]["state"]
    item = selected["materializations"][0]
    if change == "missing":
        selected["snapshot"]["artifacts"].append({**deepcopy(item["artifact"]), "digest": OTHER})
    elif change == "additional":
        selected["materializations"].append(
            {
                "artifact": {**deepcopy(item["artifact"]), "digest": OTHER},
                "path": "/input/extra",
                "mode": "read",
            }
        )
    elif change == "duplicate":
        selected["materializations"].append({**deepcopy(item), "path": "/input/duplicate"})
    else:
        item["artifact"]["size_bytes"] += 1
    with pytest.raises(ContractError):
        validate_hook_request(value)


@pytest.mark.parametrize(
    "path",
    [
        "/synthetic/target",
        "/synthetic/target/input",
        "/synthetic/output/input",
        "/synthetic/../input",
    ],
    ids=["target", "below-target", "output", "noncanonical"],
)
@pytest.mark.parametrize("role", ["restore", "verify-restore"])
def test_restore_artifacts_remain_separate_from_restored_targets_and_output(path, role):
    value = request(role)
    value["restore_input"]["datasets"]["state"]["materializations"][0]["path"] = path
    with pytest.raises(ContractError):
        validate_hook_request(value)


def test_restore_artifact_materialization_cannot_request_write_access():
    value = request()
    value["restore_input"]["datasets"]["state"]["materializations"][0]["mode"] = "write"
    with pytest.raises(ContractError):
        validate_hook_request(value)


@pytest.mark.parametrize("change", ["checkpoint", "snapshot", "producer", "artifact"])
def test_consistent_new_input_cannot_replace_retained_restore_selection(change):
    value = request()
    expected = deepcopy(value["restore_input"])
    selected = value["restore_input"]["datasets"]["state"]
    if change == "checkpoint":
        value["restore_input"]["checkpoint_digest"] = OTHER
    elif change == "snapshot":
        selected["snapshot"]["handle"] = "snapshot:other"
    elif change == "producer":
        selected["snapshot"]["producer"]["instance_generation"] += 1
    else:
        selected["snapshot"]["artifacts"][0]["digest"] = OTHER
        selected["materializations"][0]["artifact"]["digest"] = OTHER
    validate_hook_request(value)
    with pytest.raises(ContractError, match="selected"):
        require_selected_restore_input(
            value,
            checkpoint_digest=expected["checkpoint_digest"],
            snapshots={name: item["snapshot"] for name, item in expected["datasets"].items()},
        )


def test_hook_source_does_not_give_the_caller_an_extra_input_channel():
    value = request()
    value["input_directory"] = "/synthetic/unbound-input"
    with pytest.raises(ContractError):
        validate("hook-request.schema.json", value)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("protected", ["dataset", "secret"])
@pytest.mark.parametrize(
    "output",
    ["/synthetic/protected", "/synthetic", "/synthetic/protected/out"],
    ids=["equal", "ancestor", "descendant"],
)
def test_every_hook_role_keeps_output_disjoint_from_dataset_and_secret_paths(
    role, protected, output
):
    value = request(role)
    if protected == "dataset":
        value["dataset_handles"]["state"]["path"] = "/synthetic/protected"
    else:
        value["secret_paths"]["credential"] = "/synthetic/protected"
    value["output_directory"] = output
    with pytest.raises(ContractError, match="hook output overlaps"):
        validate_hook_request(value)


@pytest.mark.parametrize("role", ROLES)
def test_disjoint_hook_paths_with_common_string_prefix_remain_valid(role):
    value = request(role)
    value["dataset_handles"]["state"]["path"] = "/synthetic/output-data"
    value["secret_paths"]["credential"] = "/synthetic/output-secret"
    validate_hook_request(value)


@pytest.mark.parametrize("field", ["output", "dataset", "secret"])
@pytest.mark.parametrize(
    "path",
    ["/synthetic//input", "/synthetic/./input", "/synthetic/input/"],
    ids=["empty-component", "dot-component", "trailing-separator"],
)
def test_nonrestore_hook_paths_cannot_hide_aliases_in_noncanonical_spelling(field, path):
    value = request("capture")
    if field == "output":
        value["output_directory"] = path
    elif field == "dataset":
        value["dataset_handles"]["state"]["path"] = path
    else:
        value["secret_paths"]["credential"] = path
    location = {
        "output": "output_directory",
        "dataset": "dataset_handles/state/path",
        "secret": "secret_paths/credential",
    }[field]
    with pytest.raises(
        ContractError,
        match=rf"^schema hook-request\.schema\.json rejected input at {location}$",
    ):
        validate_hook_request(value)
