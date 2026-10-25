"""Host source selectors retain provider ownership and exact native target mappings."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.validation import ContractError, validate_host

from tests.source_target_support import host_target
from tests.test_source_authority import host_source

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json#/$defs/Host",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json#/$defs/SourceTargetBinding",
    ],
    "scope": "explicit host adapter selection, provider schemas and approved native namespace joins",
    "relationship": "candidate",
    "reason": "Contrasting provider selectors and independently supplied alias mappings exercise source admission; synthetic mappings do not qualify native discovery, notification dispatch or alias exclusion.",
    "claims": [],
}


def selected(provider="systemd", source=None):
    host, catalogue = host_source()
    source = source or {"unit": "example-agent.service"}
    registry, declaration, target = host_target(host, provider, source)
    host["concerns"]["base"]["services"].clear()
    host["concerns"]["base"]["secret_files"]["agent-token"]["notify"].clear()
    kind = "services" if target["executor"]["role"] == "service" else "packages"
    host["concerns"]["base"][kind]["agent"] = declaration
    return host, catalogue, registry, declaration, target


@pytest.mark.parametrize(
    "platform,provider,selector",
    [
        ("linux", "systemd", {"unit": "example-agent.service"}),
        ("macos", "launchd", {"label": "com.example.agent"}),
        ("appliance", "procd", {"service": "example_agent"}),
        ("linux", "apt", {"package": "example-agent:amd64"}),
        ("macos", "homebrew", {"formula": "example/tap/agent@2"}),
        ("appliance", "archive-slots", {"slot": "example-agent"}),
    ],
)
def test_host_targets_use_the_selected_provider_grammar(platform, provider, selector):
    host, catalogue, registry, _, target = selected(provider, selector)
    host["platform"] = platform
    validate_host(host, catalogue)
    assert registry.resolve_host_targets(host) == [target]


@pytest.mark.parametrize(
    "provider,selector",
    [
        ("systemd", {"label": "com.example.agent"}),
        ("launchd", {"unit": "example-agent.service"}),
        ("procd", {"service": "example/agent"}),
        ("apt", {"formula": "agent"}),
        ("homebrew", {"package": "agent"}),
        ("archive-slots", {"slot": "../../agent"}),
    ],
)
def test_provider_selectors_cannot_enter_another_providers_closed_schema(provider, selector):
    host, _ = host_source()
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        host_target(host, provider, selector)


@pytest.mark.parametrize("field", ["unit", "manager", "name"])
def test_host_source_does_not_keep_implicit_provider_alias_fields(field):
    host, catalogue, _, declaration, _ = selected()
    declaration[field] = "example-agent.service"
    with pytest.raises(ContractError):
        validate_host(host, catalogue)


@pytest.mark.parametrize("change", ["instance", "role", "scope", "schema", "selector"])
def test_selected_source_cannot_bypass_enrollment_or_its_pinned_schema(change):
    host, catalogue, registry, declaration, _ = selected()
    if change == "instance":
        declaration["adapter"]["instance"] = "unapproved"
    elif change == "role":
        host["adapter_instances"]["selected-systemd"]["role"] = "software"
    elif change == "scope":
        declaration["scope"]["handle"] = "unapproved"
    elif change == "schema":
        declaration["adapter"]["source_schema_digest"] = "sha256:" + "b" * 64
    else:
        declaration["adapter"]["source"]["command"] = "unapproved"
    with pytest.raises(ContractError):
        validate_host(host, catalogue)
        registry.resolve_host_targets(host)


def test_source_cannot_reconfigure_its_approved_instance():
    host, catalogue, registry, _, _ = selected()
    host["adapter_instances"]["selected-systemd"]["configuration"]["manager_handle"] = "other"
    validate_host(host, catalogue)
    with pytest.raises(ContractError, match="SOURCE_INSTANCE_REBIND_REQUIRED"):
        registry.resolve_host_targets(host)


def test_valid_new_selector_still_needs_an_independently_approved_native_mapping():
    host, catalogue, registry, declaration, _ = selected()
    declaration["adapter"]["source"]["unit"] = "another-agent.service"
    validate_host(host, catalogue)
    with pytest.raises(ContractError, match="UNAPPROVED_SOURCE_TARGET_MAPPING"):
        registry.resolve_host_targets(host)


@pytest.mark.parametrize("another_instance", [False, True])
def test_native_aliases_cannot_become_two_host_writers(another_instance):
    host, catalogue, registry, first, target = selected()
    if another_instance:
        _, second, _ = host_target(
            host,
            "systemd",
            {"unit": "alias-agent.service"},
            registry=registry,
            instance_id="delegated-service",
            namespace=target["namespace"],
            scope=target["executor"]["scope"],
            controller=target["executor"]["instance"],
        )
    else:
        second = copy.deepcopy(first)
        second["adapter"]["source"]["unit"] = "alias-agent.service"
        registry.enroll_source_target(
            {**target, "selection": second["adapter"]}, owner_approved=True
        )
    host["concerns"]["base"]["services"]["alias"] = second
    validate_host(host, catalogue)
    with pytest.raises(ContractError, match="DUPLICATE_NATIVE_SOURCE_TARGET"):
        registry.resolve_host_targets(host)


def test_native_mapping_requires_owner_approval_and_an_existing_mutation_grant():
    _, _, registry, _, target = selected()
    with pytest.raises(ContractError, match="SOURCE_TARGET_MAPPING_NOT_AUTHORIZED"):
        registry.enroll_source_target(target, owner_approved=False)
    changed = copy.deepcopy(target)
    changed["namespace"]["resource"] = "ungranted.service"
    with pytest.raises(ContractError, match="SOURCE_TARGET_NAMESPACE"):
        registry.enroll_source_target(changed, owner_approved=True)


def test_notifications_keep_the_same_approved_service_target():
    host, catalogue, registry, declaration, target = selected(
        "launchd", {"label": "com.example.agent"}
    )
    notifications = host["concerns"]["base"]["files"]["motd"]["notify"]
    notifications.append({"service": "agent", "action": "restart"})
    validate_host(host, catalogue)
    assert registry.resolve_host_targets(host) == [target]
    declaration["adapter"]["source"]["label"] = "com.example.other"
    with pytest.raises(ContractError, match="UNAPPROVED_SOURCE_TARGET_MAPPING"):
        registry.resolve_host_targets(host)
    notifications[0]["service"] = "unknown"
    with pytest.raises(ContractError, match="unknown notification service"):
        validate_host(host, catalogue)
