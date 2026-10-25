"""Source prescriptions identify one target; native alias checks remain with adapters."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.validation import ContractError, strict_yaml, validate_app, validate_host

from tests.source_target_support import host_target
from tests.support import FIXTURES

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json#/$defs/Host",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json#/$defs/App",
    ],
    "scope": "offline source target identity and conflicting prescriptions",
    "relationship": "candidate",
    "reason": "Synthetic conflicting targets and independent namespaces exercise source rejection; these checks do not qualify native path resolution or adapter mutation isolation.",
    "claims": [],
}


def source(name):
    return strict_yaml((FIXTURES / name).read_text())


def host_source():
    return source("host-node-a/host.yaml"), source("host-node-a/secrets.yaml")


def app_source():
    return source("demo-app/app.yaml"), source("demo-app/secrets.yaml")


def concern():
    return {
        "purpose": "Independent synthetic host concern",
        "files": {},
        "secret_files": {},
        "packages": {},
        "artifacts": {},
        "groups": {},
        "services": {},
    }


def target_entry(kind, destination):
    if kind == "artifacts":
        return {
            "url": "https://artifacts.example.invalid/tool",
            "digest": "sha256:" + "a" * 64,
            "platform": "linux",
            "destination": destination,
            "mode": "0755",
            "reason": "Synthetic installed artifact",
        }
    value = {
        "destination": destination,
        "mode": "0600" if kind == "secret_files" else "0644",
        "user": "root",
        "group": "root",
        "validator": None,
        "notify": [],
        "reason": "Synthetic declared target",
    }
    value.update({"entry": "agent-token"} if kind == "secret_files" else {"source": "files/motd"})
    return value


@pytest.mark.parametrize("another_concern", [False, True])
@pytest.mark.parametrize("contradictory", [False, True])
def test_service_binding_names_cannot_claim_the_same_native_unit(another_concern, contradictory):
    host, catalogue = host_source()
    services = host["concerns"]["base"]["services"]
    duplicate = copy.deepcopy(services["agent"])
    if contradictory:
        duplicate.update(enabled=False, activity="stopped")
    if another_concern:
        host["concerns"]["maintenance"] = concern()
        services = host["concerns"]["maintenance"]["services"]
    services["another-agent"] = duplicate
    with pytest.raises(ContractError, match="duplicate native service target"):
        validate_host(host, catalogue)


def test_independent_native_units_and_cross_concern_notifications_are_valid():
    host, catalogue = host_source()
    host["concerns"]["maintenance"] = concern()
    timer = copy.deepcopy(host["concerns"]["base"]["services"]["agent"])
    timer["adapter"]["source"]["unit"] = "example-agent.timer"
    timer["reason"] = "Independent synthetic timer"
    host["concerns"]["maintenance"]["services"]["agent-timer"] = timer
    host["concerns"]["base"]["files"]["motd"]["notify"] = [
        {"service": "agent-timer", "action": "restart"}
    ]
    validate_host(host, catalogue)


@pytest.mark.parametrize("change", [{}, {"version": "2"}, {"state": "retired"}])
def test_package_aliases_cannot_compete_across_concerns(change):
    host, catalogue = host_source()
    _, package, _ = host_target(host, "apt", {"package": "example-package"})
    host["concerns"]["base"]["packages"]["first"] = package
    host["concerns"]["maintenance"] = concern()
    host["concerns"]["maintenance"]["packages"]["second"] = {**package, **change}
    with pytest.raises(ContractError, match="duplicate package target"):
        validate_host(host, catalogue)


def test_package_identity_preserves_the_declared_manager_namespace():
    host, catalogue = host_source()
    for manager, selector in (("apt", "package"), ("homebrew", "formula")):
        _, package, _ = host_target(host, manager, {selector: "example-package"})
        package["version"] = None
        host["concerns"]["base"]["packages"][manager] = package
    validate_host(host, catalogue)


@pytest.mark.parametrize("another_concern", [False, True])
@pytest.mark.parametrize("contradictory", [False, True])
def test_group_binding_names_cannot_compete_for_the_same_user(another_concern, contradictory):
    host, catalogue = host_source()
    groups = host["concerns"]["base"]["groups"]
    groups["first-membership"] = {
        "user": "synthetic-agent",
        "memberships": ["synthetic-operators"],
        "reason": "Synthetic declared membership",
    }
    duplicate = copy.deepcopy(groups["first-membership"])
    if contradictory:
        duplicate["memberships"] = []
    if another_concern:
        host["concerns"]["maintenance"] = concern()
        groups = host["concerns"]["maintenance"]["groups"]
    groups["second-membership"] = duplicate
    with pytest.raises(ContractError, match="duplicate group membership target"):
        validate_host(host, catalogue)


def test_group_memberships_for_distinct_users_remain_independent():
    host, catalogue = host_source()
    host["concerns"]["maintenance"] = concern()
    for scope, user in (("base", "synthetic-agent"), ("maintenance", "synthetic-other")):
        host["concerns"][scope]["groups"]["membership"] = {
            "user": user,
            "memberships": ["synthetic-operators"],
            "reason": "Independent user membership declaration",
        }
    validate_host(host, catalogue)


@pytest.mark.parametrize(
    "first,second",
    [
        ("files", "files"),
        ("files", "secret_files"),
        ("files", "artifacts"),
        ("secret_files", "secret_files"),
        ("secret_files", "artifacts"),
        ("artifacts", "artifacts"),
    ],
)
def test_all_host_destination_kinds_share_one_target_namespace(first, second):
    host, catalogue = host_source()
    host["concerns"]["base"][first]["first-target"] = target_entry(first, "/opt/example/target")
    host["concerns"]["maintenance"] = concern()
    host["concerns"]["maintenance"][second]["second-target"] = target_entry(
        second, "/opt/example/target"
    )
    with pytest.raises(ContractError, match="destination collision"):
        validate_host(host, catalogue)


@pytest.mark.parametrize("kind", ["files", "secret_files", "artifacts"])
@pytest.mark.parametrize(
    "path",
    ["/etc//motd", "/etc/./motd", "/etc/motd/", "//etc/motd"],
    ids=["empty-segment", "dot-segment", "trailing-slash", "double-root"],
)
def test_host_target_aliases_are_rejected_before_native_resolution(kind, path):
    host, catalogue = host_source()
    host["concerns"]["base"][kind]["alias"] = target_entry(kind, path)
    with pytest.raises(ContractError):
        validate_host(host, catalogue)


def test_distinct_host_destination_kinds_remain_independent():
    host, catalogue = host_source()
    for kind in ("files", "secret_files", "artifacts"):
        host["concerns"]["base"][kind]["new-target"] = target_entry(kind, "/opt/example/" + kind)
    validate_host(host, catalogue)


@pytest.mark.parametrize("delivery", ["file", "environment-file"])
@pytest.mark.parametrize("another_entry", [False, True])
def test_secret_binding_names_cannot_compete_for_a_component_target(delivery, another_entry):
    app, catalogue = app_source()
    duplicate = copy.deepcopy(app["secret_bindings"]["database-password"])
    duplicate["delivery"] = delivery
    if another_entry:
        catalogue["entries"]["other-password"] = {"value_policy": "replaceable"}
        duplicate["entry"] = "other-password"
    app["secret_bindings"]["second-password"] = duplicate
    with pytest.raises(ContractError, match="secret delivery target collision"):
        validate_app(app, catalogue)


@pytest.mark.parametrize(
    "path",
    ["/run//secrets/key", "/run/./secrets/key", "/run/secrets/key/"],
    ids=["empty-segment", "dot-segment", "trailing-slash"],
)
def test_secret_delivery_requires_a_canonical_target(path):
    app, catalogue = app_source()
    app["secret_bindings"]["database-password"]["target"] = path
    with pytest.raises(ContractError):
        validate_app(app, catalogue)


@pytest.mark.parametrize("independent", ["component", "target"])
def test_secret_targets_preserve_component_namespaces_and_distinct_paths(independent):
    app, catalogue = app_source()
    duplicate = copy.deepcopy(app["secret_bindings"]["database-password"])
    if independent == "component":
        duplicate["component"] = "web"
    else:
        duplicate["target"] = "/run/secrets/another-password"
    app["secret_bindings"]["second-password"] = duplicate
    validate_app(app, catalogue)
