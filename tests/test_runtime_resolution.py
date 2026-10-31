"""Fresh runtime resolution binds the accepted target, release and projection bytes."""

from __future__ import annotations

import copy
from functools import partial
from io import BytesIO

import pytest
from fishhat_adapters import check_request, check_response, runtime_binding_digest
from fishhat_adapters.process import (
    validate_process_launch,
    verify_process_inputs,
    verify_process_outputs,
)
from fishhat_contracts.validation import ContractError, canonical, digest, strict_json

from tests.adapter_support import observation_target
from tests.linear_support import assert_linear, measure
from tests.test_adapter_handoffs import installed
from tests.test_adapter_process import identity

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/runtime-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter-process.schema.json",
    ],
    "scope": "independent resolution target approval, exact release/component lineage and local projection custody",
    "relationship": "candidate",
    "reason": "Serialized fresh-process inputs and substituted identities/bytes exercise typed correlation and custody gates; native projection correctness and execution remain unqualified.",
    "claims": [],
}


def resolution():
    registry, executor = installed("runtime")
    target = observation_target(executor)
    source_bytes = b"reviewed immutable native source"
    projection_bytes = b"complete resolved runtime projection"
    query = {
        "contract": "fishhat.runtime",
        "method": "resolve",
        "input": {
            "scope": copy.deepcopy(executor["scope"]),
            "source": identity(source_bytes, "application/octet-stream"),
            "release_digest": digest("independently accepted release"),
            "components": ["web", "worker"],
            "binding": executor,
            "target": target,
        },
    }
    projection = identity(projection_bytes, "application/octet-stream")
    reply = {
        "contract": query["contract"],
        "method": query["method"],
        "request_digest": digest(query),
        "scope": copy.deepcopy(executor["scope"]),
        "coverage": "complete",
        "continuation": None,
        "proposal": projection,
        "problem": None,
        "output": {
            "deployment": {
                "handle": "deployment:reviewed",
                "release_digest": query["input"]["release_digest"],
                "source_digest": query["input"]["source"]["digest"],
                "binding_digest": runtime_binding_digest(target),
                "projection_digest": projection["digest"],
                "components": ["worker", "web"],
            },
            "observation": None,
            "objects": [],
        },
    }
    return registry, query, reply, source_bytes, projection_bytes


def launch_case(registry, query):
    executor = query["input"]["binding"]
    instance = registry.inspect_instance(executor["instance"])
    installation, descriptor = registry._installations[executor["installation_digest"]]
    configuration = instance["configuration"]
    manifest = {
        "format": "fishhat.adapter-process/v1",
        "mode": "query",
        "role": "runtime",
        "executor": executor,
        "request": identity(canonical(query)),
        "configuration": identity(canonical(configuration)),
        "inputs": identity(b"", "application/x-ndjson"),
        "private_inputs": None,
    }
    return manifest, configuration, installation, descriptor


def test_resolution_supplies_complete_context_before_any_mutation():
    registry, query, reply, _, _ = resolution()
    wire = strict_json(canonical(query))
    target = copy.deepcopy(query["input"]["target"])
    registry.authorize_request(
        "selected", "runtime", wire, owner_approved=True, expected_runtime_binding=target
    )
    check_response("runtime", wire, reply)
    manifest, configuration, installation, descriptor = launch_case(registry, wire)
    validate_process_launch(
        manifest,
        wire,
        configuration,
        descriptor=descriptor,
        approved_installation=installation,
        expected_executor=wire["input"]["binding"],
        expected_private_use=None,
        expected_runtime_binding=target,
    )
    assert wire["input"]["target"] is not target
    assert reply["output"]["deployment"]["components"] != wire["input"]["components"]


@pytest.mark.parametrize("field", ["binding", "target"])
def test_resolution_cannot_omit_executor_or_owner_context(field):
    _, query, _, _, _ = resolution()
    del query["input"][field]
    with pytest.raises(ContractError):
        check_request("runtime", query)


@pytest.mark.parametrize(
    "field", ["subject", "scope", "instance", "instance_generation", "instance_digest"]
)
def test_resolution_target_cannot_substitute_scope_or_enrollment(field):
    _, query, _, _, _ = resolution()
    target = query["input"]["target"]
    if field == "scope":
        target[field]["handle"] = "another-app"
    elif field == "instance_generation":
        target[field] += 1
    elif field == "instance_digest":
        target[field] = digest("another enrollment")
    else:
        target[field] = "another-app"
    with pytest.raises(ContractError, match="RUNTIME_RESOLUTION_TARGET"):
        check_request("runtime", query)


@pytest.mark.parametrize("changed", [False, True], ids=["missing", "substituted"])
def test_resolution_cannot_approve_its_own_target(changed):
    registry, query, _, _, _ = resolution()
    target = copy.deepcopy(query["input"]["target"]) if changed else None
    if target is not None:
        target["generation"] += 1
    with pytest.raises(ContractError, match="RUNTIME_RESOLUTION_APPROVED_TARGET"):
        registry.authorize_request(
            "selected", "runtime", query, owner_approved=True, expected_runtime_binding=target
        )
    manifest, configuration, installation, descriptor = launch_case(registry, query)
    with pytest.raises(ContractError, match="runtime resolution target is not approved"):
        validate_process_launch(
            manifest,
            query,
            configuration,
            descriptor=descriptor,
            approved_installation=installation,
            expected_executor=query["input"]["binding"],
            expected_private_use=None,
            expected_runtime_binding=target,
        )


@pytest.mark.parametrize(
    "field",
    ["release_digest", "source_digest", "binding_digest", "projection_digest", "components"],
)
def test_resolution_result_cannot_change_accepted_lineage(field):
    _, query, reply, _, _ = resolution()
    deployment = reply["output"]["deployment"]
    deployment[field] = ["web"] if field == "components" else digest("substituted output")
    with pytest.raises(ContractError, match="RUNTIME_RESOLUTION_IDENTITY"):
        check_response("runtime", query, reply)


def test_resolution_unknown_has_no_usable_deployment_or_projection():
    _, query, reply, _, _ = resolution()
    reply["coverage"] = "unknown"
    with pytest.raises(ContractError, match="RUNTIME_RESOLUTION_COVERAGE"):
        check_response("runtime", query, reply)
    reply["output"]["deployment"] = None
    reply["proposal"] = None
    check_response("runtime", query, reply)
    reply["coverage"] = "complete"
    with pytest.raises(ContractError, match="RUNTIME_RESOLUTION_COVERAGE"):
        check_response("runtime", query, reply)


def test_resolution_requires_exact_source_and_projection_byte_custody():
    _, query, reply, source_bytes, projection_bytes = resolution()
    source = query["input"]["source"]
    path = "inputs/" + source["digest"].removeprefix("sha256:")
    rows = canonical({"artifact": source, "path": path}) + b"\n"
    verify_process_inputs(
        BytesIO(rows),
        identity=identity(rows, "application/x-ndjson"),
        expected_artifacts=[source],
        open_artifact=lambda selected: BytesIO(source_bytes if selected == path else b"wrong"),
    )
    check_response("runtime", query, reply)
    projection_path = "output/artifacts/" + reply["proposal"]["digest"].removeprefix("sha256:")
    verify_process_outputs(
        [reply["proposal"]],
        open_artifact=lambda selected: BytesIO(
            projection_bytes if selected == projection_path else b"wrong"
        ),
    )
    original = copy.deepcopy(reply)
    with pytest.raises(ContractError):
        verify_process_outputs(
            [reply["proposal"]], open_artifact=lambda _: BytesIO(b"substituted projection")
        )
    assert reply == original


def test_runtime_resolution_linear_work():
    for name in ("check_request", "check_response"):
        samples = []
        for count in (16, 64, 256):
            _, request, reply, _, _ = resolution()
            request["input"]["components"] = [f"component-{index:04d}" for index in range(count)]
            reply["request_digest"] = digest(request)
            reply["output"]["deployment"]["components"] = list(
                reversed(request["input"]["components"])
            )
            operation = (
                partial(check_request, "runtime", request)
                if name == "check_request"
                else partial(check_response, "runtime", request, reply)
            )
            result, work = measure(operation)
            assert result is None
            samples.append((count, work))
        assert_linear(samples)


CHECK_OVERRIDES = {
    "test_runtime_resolution_linear_work": {
        "purpose": "implementation",
        "authority": [
            "release.toml#/engineering",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_semantics.py",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_semantics.py#check_request",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_semantics.py#check_response",
        ],
        "scope": "complete selected runtime component sets and exact returned deployment correspondence",
        "relationship": "scoped-witness",
        "reason": "Measure request and response checks independently over 16, 64 and 256 components; this establishes local linear work only, not native resolution or execution.",
        "claims": ["engineering:adapters.check_request", "engineering:adapters.check_response"],
    }
}
