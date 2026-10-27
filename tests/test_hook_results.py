"""Owner-selected hook result gates and exact streamed artifact custody."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from io import BytesIO

import pytest
from fishhat_contracts import artifact_custody, hooks
from fishhat_contracts.artifact_custody import CHUNK_BYTES, verify_artifact_stream
from fishhat_contracts.hooks import (
    require_hook_success,
    require_selected_restore_input,
    validate_hook_result,
)
from fishhat_contracts.validation import ContractError, digest

from tests.linear_support import assert_linear, measure
from tests.test_hook_handoffs import request as hook_request

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/hook-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/hook-result.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json#/$defs/Hook",
    ],
    "scope": "exact result correlation, mandatory owner-approved checks and complete artifact bytes",
    "relationship": "candidate",
    "reason": "Independent adverse fixtures and streamed byte oracles establish reference joins, not native hook isolation or durable execution.",
    "claims": [],
}


def records(count=1, role="verify-config"):
    request = hook_request(role)
    required = [f"CHECK_{index:04d}" for index in range(count)]
    procedure = {
        "component": request["executor_component"],
        "role": role,
        "argv": ["/synthetic/verify"],
        "mode": "read" if role in hooks.READ_ROLES else "write",
        "timeout_seconds": request["timeout_seconds"],
        "datasets": ["state"],
        "secrets": [],
        "network": "none",
        "required_checks": required,
    }
    request.update(procedure_digest=digest(procedure), required_checks=required)
    result = {
        "format": "deployment-ops/hook-result/v1",
        "request_id": request["id"],
        "request_digest": digest(request),
        "outcome": "succeeded",
        "effects": "none",
        "checks": [
            {
                "code": code,
                "passed": True,
                "summary": "Verified synthetic condition",
                "requirement": "mandatory",
            }
            for code in required
        ],
        "artifacts": [],
        **{
            key: request[key]
            for key in (
                "operation_id",
                "release_digest",
                "executor_component",
                "role",
                "procedure_digest",
            )
        },
    }
    return request, result, procedure


def artifact(data):
    return {
        "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "media_type": "application/octet-stream",
    }


@pytest.mark.parametrize("change", ["failed", "omitted", "diagnostic", "downgraded-source"])
def test_mandatory_verification_cannot_be_weakened(change):
    request, result, procedure = records()
    require_hook_success(request, result, accepted_procedure=procedure, artifact_streams={})
    if change == "failed":
        result["checks"][0]["passed"] = False
    elif change == "omitted":
        result["checks"] = []
    elif change == "diagnostic":
        result["checks"][0]["requirement"] = "diagnostic"
    else:
        request["required_checks"] = ["OTHER_OK"]
        result["request_digest"] = digest(request)
        result["checks"][0]["code"] = "OTHER_OK"
    with pytest.raises(ContractError):
        require_hook_success(request, result, accepted_procedure=procedure, artifact_streams={})


@pytest.mark.parametrize(
    "field",
    [
        "request_id",
        "request_digest",
        "operation_id",
        "release_digest",
        "executor_component",
        "role",
        "procedure_digest",
    ],
)
def test_result_must_match_every_exact_request_pin(field):
    request, result, _ = records()
    if field in {"request_id", "operation_id"}:
        result[field] = "00000000-0000-4000-8000-000000000099"
    elif field.endswith("digest"):
        result[field] = "sha256:" + "f" * 64
    elif field == "role":
        result[field] = "health"
    else:
        result[field] = "other"
    with pytest.raises(ContractError, match="identity"):
        validate_hook_result(request, result)


@pytest.mark.parametrize("role", sorted(hooks.READ_ROLES))
def test_read_only_success_can_emit_artifacts_without_claiming_managed_mutation(role):
    request, result, procedure = records(role=role)
    data = b"synthetic verified output"
    result["artifacts"] = [
        {"path": "verification/result.bin", "bytes": len(data), "digest": artifact(data)["digest"]}
    ]
    require_hook_success(
        request,
        result,
        accepted_procedure=procedure,
        artifact_streams={"verification/result.bin": BytesIO(data)},
    )
    result["effects"] = "known"
    with pytest.raises(ContractError, match="observational"):
        validate_hook_result(request, result)


def test_failed_diagnostics_do_not_replace_or_fail_passing_required_checks():
    request, result, procedure = records()
    result["checks"].append(
        {
            "code": "OPTIONAL_TIMING",
            "passed": False,
            "summary": "Advisory measurement",
            "requirement": "diagnostic",
        }
    )
    require_hook_success(request, result, accepted_procedure=procedure, artifact_streams={})
    result["checks"].append(deepcopy(result["checks"][0]))
    with pytest.raises(ContractError, match="duplicate"):
        validate_hook_result(request, result)


@pytest.mark.parametrize(
    "outcome,effects",
    [
        ("failed", "known"),
        ("unknown", "unknown"),
        ("unsupported", "none"),
        ("succeeded", "unknown"),
    ],
)
def test_non_success_or_uncertainty_cannot_advance_required_phase(outcome, effects):
    request, result, procedure = records(role="configure")
    result.update(outcome=outcome, effects=effects)
    with pytest.raises(ContractError):
        require_hook_success(request, result, accepted_procedure=procedure, artifact_streams={})


@pytest.mark.parametrize(
    "path", ["out.bin", "out.bin/child", "out"], ids=["duplicate", "descendant", "ancestor"]
)
def test_duplicate_and_ancestor_artifact_paths_reject(path):
    request, result, _ = records()
    item = {"path": "out.bin", "bytes": 0, "digest": artifact(b"")["digest"]}
    result["artifacts"] = [item, {**item, "path": path}]
    if path == "out":
        result["artifacts"][0]["path"] = "out/child"
    with pytest.raises(ContractError, match="overlapping"):
        validate_hook_result(request, result)


def test_artifact_custody_checks_complete_bytes():
    data = b"x" * (2 * CHUNK_BYTES + 17)
    declared = artifact(data)
    retained = BytesIO()
    verify_artifact_stream(declared, BytesIO(data), destination=retained)
    assert retained.getvalue() == data
    for changed in (data[:-1], data + b"extra", b"y" + data[1:]):
        with pytest.raises(ContractError):
            verify_artifact_stream(declared, BytesIO(changed))
    prefixed = BytesIO(b"unverified prefix" + data)
    prefixed.seek(len(b"unverified prefix"))
    with pytest.raises(ContractError, match="byte zero"):
        verify_artifact_stream(declared, prefixed)
    with pytest.raises(ContractError, match="not empty"):
        verify_artifact_stream(declared, BytesIO(data), destination=BytesIO(b"stale"))
    verify_artifact_stream(artifact(b""), BytesIO())


def test_result_artifacts_need_exact_owner_opened_custody_and_immutable_replay():
    request, result, procedure = records()
    data = b"proof"
    result["artifacts"] = [
        {"path": "proof", "bytes": len(data), "digest": artifact(data)["digest"]}
    ]
    with pytest.raises(ContractError, match="custody"):
        require_hook_success(request, result, accepted_procedure=procedure, artifact_streams={})
    original = digest(result)
    require_hook_success(
        request,
        result,
        accepted_procedure=procedure,
        artifact_streams={"proof": BytesIO(data)},
        retained_result_digest=original,
    )
    result["checks"][0]["summary"] = "Changed after retention"
    with pytest.raises(ContractError, match="retained"):
        require_hook_success(
            request,
            result,
            accepted_procedure=procedure,
            artifact_streams={"proof": BytesIO(data)},
            retained_result_digest=original,
        )


def test_artifact_stream_linear_work():
    samples = []
    for count in (16, 64, 256):
        data = b"x" * (count * CHUNK_BYTES + 17)
        declared = artifact(data)
        _, work = measure(
            lambda declared=declared, data=data: verify_artifact_stream(declared, BytesIO(data)),
            modules=(artifact_custody,),
        )
        samples.append((count, work))
    assert_linear(samples)


def hook_growth_case(count):
    request, result, procedure = records(count, role="verify-restore")
    template = request["restore_input"]["datasets"].pop("state")
    request["dataset_handles"] = {}
    snapshots = {}
    for index in range(count):
        name = f"dataset-{index:04d}"
        item = deepcopy(template)
        item["snapshot"]["dataset"] = name
        item["snapshot"]["producer"]["scope"]["handle"] = name
        item["materializations"][0]["path"] = f"/synthetic/inputs/{name}"
        request["restore_input"]["datasets"][name] = item
        request["dataset_handles"][name] = {"path": f"/synthetic/targets/{name}", "mode": "read"}
        snapshots[name] = deepcopy(item["snapshot"])
    procedure["datasets"] = list(snapshots)
    request["procedure_digest"] = result["procedure_digest"] = digest(procedure)
    result["request_digest"] = digest(request)
    result["artifacts"] = [
        {"path": f"outputs/{index:04d}", "bytes": 0, "digest": artifact(b"")["digest"]}
        for index in range(count)
    ]
    streams = {item["path"]: BytesIO() for item in result["artifacts"]}

    def run():
        require_selected_restore_input(
            request,
            checkpoint_digest=request["restore_input"]["checkpoint_digest"],
            snapshots=snapshots,
        )
        require_hook_success(
            request, result, accepted_procedure=procedure, artifact_streams=streams
        )

    return run


def test_hook_result_linear_work():
    samples = []
    for count in (16, 64, 256):
        _, work = measure(hook_growth_case(count), modules=(hooks,))
        samples.append((count, work))
    assert_linear(samples)


CHECK_OVERRIDES = {
    name: {
        "purpose": "implementation",
        "authority": ["release.toml#/engineering", *authorities],
        "scope": "complete increasing hook and artifact extents",
        "relationship": "scoped-witness",
        "reason": "Deterministic work counts cover complete checks, paths and bytes; no native qualification.",
        "claims": claims,
    }
    for name, authorities, claims in [
        (
            "test_artifact_stream_linear_work",
            [
                "packages/fishhat-contracts/src/fishhat_contracts/artifact_custody.py#verify_artifact_stream"
            ],
            ["engineering:custody.verify-artifact-stream"],
        ),
        (
            "test_hook_result_linear_work",
            [
                "packages/fishhat-contracts/src/fishhat_contracts/hooks.py#" + name
                for name in (
                    "validate_hook_request",
                    "require_selected_restore_input",
                    "validate_hook_result",
                    "require_hook_success",
                )
            ],
            [
                "engineering:hooks." + name
                for name in (
                    "validate_hook_request",
                    "require_selected_restore_input",
                    "validate_hook_result",
                    "require_hook_success",
                )
            ],
        ),
    ]
}
