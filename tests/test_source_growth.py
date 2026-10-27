"""Complete semantic source checks with independently growing reference collections."""

from __future__ import annotations

from copy import deepcopy

import pytest
from fishhat_contracts import validation
from fishhat_contracts.validation import (
    ContractError,
    canonical,
    require_acyclic,
    strict_yaml,
    validate_app,
    validate_domain,
    validate_host,
)

from tests.linear_support import assert_linear, measure
from tests.support import FIXTURES
from tests.test_dataset_contracts import application

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "release.toml#/engineering",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json",
    ],
    "scope": "complete source semantic validation with shared grants and recovery procedures, growing consumers and references, and deep dependency graphs",
    "relationship": "scoped-witness",
    "reason": "Deterministic work covers every declared source entry and reference over increasing complete inputs, including the shared-list shapes that can cause cross-product scans. These checks establish no native authorization or recovery.",
    "claims": [],
}


def app_source(count, *, shared):
    app = application("preserve" if shared else "external")
    catalogue = strict_yaml((FIXTURES / "demo-app/secrets.yaml").read_text())
    template = deepcopy(app["datasets"]["state"])
    component = deepcopy(app["components"]["database"])
    hook = deepcopy(app["hooks"]["health"])
    for index in range(count):
        name = f"entry-{index:05d}"
        app["components"][name] = {**component, "native": {"unit": name + ".container"}}
        app["datasets"][name] = {**deepcopy(template), "writers": [name]}
        app["secret_bindings"][name] = {
            **app["secret_bindings"]["database-password"],
            "component": name,
        }
        app["hooks"][name] = {
            **deepcopy(hook),
            "component": name,
            "datasets": [name],
            "secrets": [name],
        }
    if shared:
        for name in ("capture", "restore", "verify-restore"):
            app["hooks"][name]["datasets"] = list(app["datasets"])
    return app, catalogue


def host_source(count):
    host = strict_yaml((FIXTURES / "host-node-a/host.yaml").read_text())
    catalogue = strict_yaml((FIXTURES / "host-node-a/secrets.yaml").read_text())
    template = deepcopy(host["concerns"]["base"]["services"]["agent"])
    instance = host["adapter_instances"][template["adapter"]["instance"]]
    grant = deepcopy(instance["grants"][0])
    for index in range(count):
        name = f"service-{index:05d}"
        scope = {**template["scope"], "handle": name}
        instance["grants"].append({**deepcopy(grant), "scope": scope})
        value = deepcopy(template)
        value["scope"] = scope
        value["adapter"]["source"] = {"unit": name + ".service"}
        host["concerns"]["base"]["services"][name] = value
    return host, catalogue


def domain_source(count):
    domain = strict_yaml((FIXTURES / "domain/domain.yaml").read_text())
    template = deepcopy(domain["sources"]["host-node-a"])
    host = deepcopy(domain["hosts"]["node-a"])
    for index in range(count):
        name = f"host-{index:05d}"
        source = deepcopy(template)
        source["repository"]["repository_id"] = 1000 + index
        source["repository"]["name"] = "host/" + name
        domain["sources"][name] = source
        domain["hosts"][name] = {**host, "source": name}
    return domain, None


def complete_source_semantics(kind):
    samples = []
    sizes = []
    for count in (16, 64, 256):
        if kind.startswith("app"):
            source, catalogue = app_source(count, shared=kind == "app-shared-procedures")
            validate_source = validate_app
        elif kind == "host":
            source, catalogue = host_source(count)
            validate_source = validate_host
        else:
            source, catalogue = domain_source(count)
            validate_source = validate_domain
        result, work = measure(
            lambda source=source, catalogue=catalogue, validate_source=validate_source: (
                validate_source(source, catalogue)
            ),
        )
        assert result is None
        sizes.append(len(canonical(source)))
        samples.append((count, work))
    assert sizes[0] < sizes[1] < sizes[2]
    assert_linear(samples)


@pytest.mark.parametrize("shared", [False, True])
def test_app_semantics_linear_work(shared):
    complete_source_semantics("app-shared-procedures" if shared else "app-consumers")


def test_host_semantics_linear_work():
    complete_source_semantics("host")


def test_domain_semantics_linear_work():
    complete_source_semantics("domain")


def graph(count):
    return {f"node-{index:05d}": [f"node-{index + 1:05d}"] for index in range(count)} | {
        f"node-{count:05d}": []
    }


def test_dependency_graph_complete_depth_and_cycles():
    edges = graph(4096)
    require_acyclic(edges)
    edges["node-04096"].append("node-00000")
    with pytest.raises(ContractError, match="hard dependency cycle"):
        require_acyclic(edges)
    edges["node-04096"] = ["absent"]
    with pytest.raises(ContractError, match="unknown graph prerequisite"):
        require_acyclic(edges)


def test_dependency_graph_linear_work():
    samples = []
    for count in (256, 1024, 4096):
        edges = graph(count)
        _, work = measure(lambda edges=edges: require_acyclic(edges), modules=(validation,))
        samples.append((count, work))
    assert_linear(samples)


CHECK_OVERRIDES = {
    name: {
        **CHECK_PURPOSE,
        "authority": [
            *CHECK_PURPOSE["authority"],
            "packages/fishhat-contracts/src/fishhat_contracts/validation.py#" + operation,
        ],
        "claims": ["engineering:source." + bound],
    }
    for name, operation, bound in (
        ("test_app_semantics_linear_work", "validate_app", "app"),
        ("test_host_semantics_linear_work", "validate_host", "host"),
        ("test_domain_semantics_linear_work", "validate_domain", "domain"),
        ("test_dependency_graph_complete_depth_and_cycles", "require_acyclic", "dependencies"),
        ("test_dependency_graph_linear_work", "require_acyclic", "dependencies"),
    )
}
