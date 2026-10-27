"""Complete exported data/registry operations over increasing actual input extents."""

from __future__ import annotations

import copy
import json
from functools import partial

import pytest
from fishhat_adapters import (
    ROLES,
    Registry,
    check_configuration,
    check_descriptor,
    check_invocation,
    check_request,
    check_response,
    check_result,
    check_schema,
    instance_reference,
    require_qualification,
    runtime_binding_digest,
)
from fishhat_contracts import canonical, digest, strict_json, strict_yaml, validate

from scripts.project_policy import ROOT
from tests.adapter_support import INCARNATION, OWNER, D, identifier
from tests.linear_support import assert_linear, measure
from tests.source_target_support import host_target
from tests.test_adapter_handoffs import handoff, invocation_for, response_for
from tests.test_bootstrap import records

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": ["release.toml#/engineering"],
    "scope": "exported reference APIs; complete varied values, selected retained records and resolved targets",
    "relationship": "scoped-witness",
    "reason": "Each exported operation is measured independently over a sixteenfold input range; these witnesses do not qualify native effects or unmeasured input families.",
    "claims": [],
}

SCALES = (16, 64, 256)
DATA_APIS = ("canonical", "digest", "strict_json", "strict_yaml", "validate")
ADAPTER_APIS = (
    "runtime_binding_digest",
    "check_schema",
    "check_descriptor",
    "check_configuration",
    "instance_reference",
    "require_qualification",
)
SEMANTIC_APIS = ("check_request", "check_invocation", "check_response", "check_result")
REGISTRY_APIS = (
    "install",
    "enroll",
    "enroll_repository",
    "enroll_source_target",
    "source_target",
    "resolve_host_targets",
    "inspect_instance",
    "resolve",
    "resolve_source",
    "authorize_request",
    "authorize_invocation",
    "authorize",
    "inspect_delegation",
)


def bundle(count, role="capture"):
    schema = {
        "type": "object",
        "properties": {f"entry-{i:04d}": {"type": "integer"} for i in range(count)},
        "additionalProperties": False,
    }
    selector = {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
        "additionalProperties": False,
    }
    descriptor = {
        "format": "deployment-ops/adapter/v1",
        "id": "independent.growth-" + role,
        "roles": [role],
        "entrypoint": "bin/adapter",
        "process_protocol": "fishhat.adapter-process/v1",
        "configuration_schema": schema,
        "component_schema": selector,
        "source_schema": selector,
        "implemented": [role + "." + method for method in ROLES[role]],
        "native_qualified": False,
    }
    scope = {
        "authority": OWNER["id"],
        "kind": {"capture": "dataset", "runtime": "application"}.get(role, role),
        "handle": "data",
    }
    instance = {
        "id": "selected",
        "implementation": descriptor["id"],
        "installation_digest": D,
        "role": role,
        "schema_digest": digest(schema),
        "configuration": {f"entry-{i:04d}": i for i in range(count)},
        "grants": [
            {
                "scope": scope,
                "access": ["observe", "change"],
                "mutation": {
                    "controller": "selected",
                    "namespaces": [
                        {"authority": OWNER["id"], "resource": "data", "facet": "content"}
                    ],
                },
            }
        ],
        "generation": 1,
    }
    installation = {
        "implementation": descriptor["id"],
        "artifact": {"digest": D, "media_type": "application/zip", "size_bytes": 100},
        "descriptor_digest": digest(descriptor),
        "enabled": True,
    }
    return descriptor, installation, instance, scope


def selected_registry(count, role="capture"):
    descriptor, installation, instance, scope = bundle(count, role)
    registry = Registry()
    registry.install(installation, descriptor, owner_approved=True)
    registry.enroll(instance, owner_approved=True)
    return registry, descriptor, instance, scope


@pytest.mark.parametrize("name", DATA_APIS)
def test_data_exports_linear_work(name):
    samples = []
    for count in SCALES:
        value = records("git-bundle")["catalogue"]
        template = value["sources"][0]
        value["sources"] = [
            {**copy.deepcopy(template), "source_id": f"source-{i:04d}"} for i in range(count)
        ]
        if name in {"canonical", "digest"}:
            # Wide objects and long common prefixes exercise actual key ordering,
            # including Unicode scalar order and nested mapping/list preservation.
            value = {
                "é🙂" + "x" * 64 + f"{index:04d}": {
                    "z": [index, {"😀": None, "é": True}],
                    "a": "value",
                }
                for index in sorted(range(count), key=digest)
            }
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        calls = {
            "canonical": partial(canonical, value),
            "digest": partial(digest, value),
            "strict_json": partial(strict_json, encoded),
            "strict_yaml": partial(strict_yaml, encoded.decode()),
            "validate": partial(validate, "bootstrap-catalogue.schema.json", value),
        }
        result, work = measure(calls[name])
        if name in {"strict_json", "strict_yaml"}:
            assert result == value and len(result["sources"]) == count
        elif name == "canonical":
            assert result == encoded
        elif name == "digest":
            assert result == digest(value)
        else:
            assert result is None
        samples.append((count, work))
    assert_linear(samples)


@pytest.mark.parametrize("name", ADAPTER_APIS)
def test_adapter_exports_linear_work(name):
    samples = []
    for count in SCALES:
        descriptor, _, instance, scope = bundle(count)
        schema = descriptor["configuration_schema"]
        expected = {
            key: D
            for key in (
                "installation_digest",
                "contract_digest",
                "configuration_digest",
                "environment_digest",
            )
        }
        evidence = {
            **expected,
            "runner": "local.disposable-runner",
            "cases": [
                {"id": item, "outcome": "passed"}
                for item in [
                    "linear-growth",
                    "complete-extent",
                    *[f"case-{i}" for i in range(count)],
                ]
            ],
            "external_accounts": False,
            "native_dependencies": [
                {"digest": D, "media_type": "application/zip", "size_bytes": 1}
            ],
        }
        runtime = {
            "subject": "demo",
            "instance": "selected",
            "generation": 1,
            "installation_digest": D,
            "configuration_digest": D,
            "scope": {**scope, "kind": "application", "handle": "a" * (count // 2)},
            "native_incarnation": INCARNATION,
            "admission_generation": 0,
            "instance_generation": 1,
            "instance_digest": D,
        }
        calls = {
            "runtime_binding_digest": partial(runtime_binding_digest, runtime),
            "check_schema": partial(check_schema, schema),
            "check_descriptor": partial(check_descriptor, descriptor),
            "check_configuration": partial(
                check_configuration, schema, instance["configuration"], instance["schema_digest"]
            ),
            "instance_reference": partial(instance_reference, instance, scope),
            "require_qualification": partial(
                require_qualification,
                evidence,
                expected=expected,
                implemented={"capture.assess"},
                required_cases={f"case-{i}" for i in range(count)},
                trusted_runner="local.disposable-runner",
            ),
        }
        result, work = measure(calls[name])
        if name == "instance_reference":
            assert result["instance_digest"] == digest(instance)
        elif name == "runtime_binding_digest":
            assert result == digest(
                {k: v for k, v in runtime.items() if k != "admission_generation"}
            )
        else:
            assert result is None
        samples.append((count, work))
    assert_linear(samples)


def capture(count):
    registry, request = handoff("capture", "restore")
    request["input"]["snapshot"]["artifacts"] = [
        {"digest": f"sha256:{i:064x}", "media_type": "application/octet-stream", "size_bytes": 64}
        for i in range(count)
    ]
    invocation = invocation_for(request)
    response = response_for(
        request,
        invocation["attempt"],
        {"snapshots": [copy.deepcopy(request["input"]["snapshot"])], "verification": "consistent"},
    )
    return registry, request, invocation, response


@pytest.mark.parametrize("name", SEMANTIC_APIS)
def test_adapter_semantics_linear_work(name):
    samples = []
    for count in SCALES:
        _, request, invocation, response = capture(count)
        # EffectResult is a fixed-field record; vary its actual bounded task handle.
        invocation["attempt"]["native_task"] = "task:" + "a" * (count // 2)
        response["effect"]["native_task"] = invocation["attempt"]["native_task"]
        calls = {
            "check_request": partial(check_request, "capture", request),
            "check_invocation": partial(check_invocation, "capture", invocation),
            "check_response": partial(
                check_response, "capture", request, response, invocation=invocation
            ),
            "check_result": partial(check_result, invocation["attempt"], response["effect"]),
        }
        result, work = measure(calls[name])
        assert result is None
        samples.append((count, work))
    assert_linear(samples)


def registry_call(name, count):
    role = (
        "runtime"
        if name == "resolve"
        else "service"
        if name in {"enroll_source_target", "source_target"}
        else "repository"
        if name == "enroll_repository"
        else "capture"
    )
    registry, descriptor, instance, scope = selected_registry(count, role)
    reference = instance_reference(instance, scope)
    selection = {
        "instance": "selected",
        "source_schema_digest": digest(descriptor["source_schema"]),
        "source": {"name": "selected"},
    }
    if name == "install":
        descriptor, installation, _, _ = bundle(count)
        target = Registry()
        return lambda: target.install(
            installation, descriptor, owner_approved=True
        ), lambda result: result is None
    if name == "enroll":
        descriptor, installation, instance, _ = bundle(count)
        target = Registry()
        target.install(installation, descriptor, owner_approved=True)
        return lambda: target.enroll(instance, owner_approved=True), lambda result: result is None
    if name == "enroll_repository":
        repository = {
            "canonical": {"instance": identifier(51), "repository_id": 7, "name": "source/demo"},
            "provider_handle": "repository:demo",
            "binding": reference,
        }
        return lambda: registry.enroll_repository(
            repository, owner_approved=True
        ), lambda result: result is None
    if name in {"enroll_source_target", "source_target"}:
        target = {
            "selection": selection,
            "executor": reference,
            "namespace": instance["grants"][0]["mutation"]["namespaces"][0],
        }
        if name == "enroll_source_target":
            return lambda: registry.enroll_source_target(
                target, owner_approved=True
            ), lambda result: result is None
        registry.enroll_source_target(target, owner_approved=True)
        return lambda: registry.source_target(
            selection, role, scope
        ), lambda result: result == target
    if name == "resolve_host_targets":
        host = strict_yaml((ROOT / "tests/fixtures/host-node-a/host.yaml").read_text())
        host["adapter_instances"] = {}
        concern = host["concerns"]["base"]
        concern["services"], concern["packages"] = {}, {}
        registry = Registry()
        for i in range(count):
            _, declaration, _ = host_target(
                host,
                "systemd",
                {"unit": f"service-{i:04d}.service"},
                registry=registry,
                instance_id=f"service-{i:04d}",
            )
            concern["services"][f"service-{i:04d}"] = declaration
        return lambda: registry.resolve_host_targets(host), lambda result: len(result) == count
    if name == "inspect_instance":
        return lambda: registry.inspect_instance("selected"), lambda result: result == instance
    if name == "resolve":
        components = {
            f"component-{i:04d}": {"native": {"name": f"native-{i:04d}"}} for i in range(count)
        }
        return lambda: registry.resolve(selection, components), lambda result: result == instance
    if name == "resolve_source":
        return lambda: registry.resolve_source(
            selection, role, scope
        ), lambda result: result == instance
    if name in {"authorize_request", "authorize_invocation"}:
        registry, request, invocation, _ = capture(count)
        if name == "authorize_invocation":
            return lambda: registry.authorize_invocation(
                "capture", invocation, owner_approved=True
            ), lambda result: result["id"] == "selected"
        query = {
            "contract": request["contract"],
            "method": "reconcile",
            "input": {"scope": scope, "invocation": invocation},
        }
        return lambda: registry.authorize_request(
            "selected", "capture", query, owner_approved=True, invocation=invocation
        ), lambda result: result["id"] == "selected"
    if name == "authorize":
        return lambda: registry.authorize(
            "selected", role, "restore", scope, owner_approved=True
        ), lambda result: result == instance
    if name == "inspect_delegation":
        delegate = copy.deepcopy(instance)
        delegate["id"] = "delegate"
        registry.enroll(delegate, owner_approved=True)
        return lambda: registry.inspect_delegation(
            "selected", "delegate", role, "restore", scope
        ), lambda result: result == delegate
    raise AssertionError(name)


@pytest.mark.parametrize("name", REGISTRY_APIS)
def test_registry_exports_linear_work(name):
    samples = []
    for count in SCALES:
        operation, check = registry_call(name, count)
        result, work = measure(operation)
        assert check(result)
        samples.append((count, work))
    assert_linear(samples)


CHECK_OVERRIDES = {
    "test_data_exports_linear_work": {
        **CHECK_PURPOSE,
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/validation.py",
            "release.toml#/engineering",
        ]
        + [
            "packages/fishhat-contracts/src/fishhat_contracts/validation.py#" + name
            for name in DATA_APIS
        ],
        "claims": ["engineering:data." + name for name in DATA_APIS],
    },
    "test_adapter_exports_linear_work": {
        **CHECK_PURPOSE,
        "authority": [
            "packages/fishhat-adapter-protocol/src/fishhat_adapters/protocol.py",
            "release.toml#/engineering",
        ]
        + [
            "packages/fishhat-adapter-protocol/src/fishhat_adapters/protocol.py#" + name
            for name in ADAPTER_APIS
        ],
        "claims": ["engineering:adapters." + name for name in ADAPTER_APIS],
    },
    "test_adapter_semantics_linear_work": {
        **CHECK_PURPOSE,
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_semantics.py",
            "release.toml#/engineering",
        ]
        + [
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_semantics.py#" + name
            for name in SEMANTIC_APIS
        ],
        "claims": ["engineering:adapters." + name for name in SEMANTIC_APIS],
    },
    "test_registry_exports_linear_work": {
        **CHECK_PURPOSE,
        "authority": [
            "packages/fishhat-adapter-protocol/src/fishhat_adapters/protocol.py",
            "release.toml#/engineering",
        ]
        + [
            "packages/fishhat-adapter-protocol/src/fishhat_adapters/protocol.py#Registry." + name
            for name in REGISTRY_APIS
        ],
        "claims": ["engineering:adapters.Registry." + name for name in REGISTRY_APIS],
    },
}
