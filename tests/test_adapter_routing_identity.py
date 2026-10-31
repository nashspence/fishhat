"""Unambiguous native routing identities; declaration order grants no priority."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import check_request
from fishhat_contracts.validation import ContractError, digest

from tests.adapter_support import OWNER, identifier
from tests.test_adapter_handoffs import installed

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/network-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ingress-adapter.schema.json",
    ],
    "scope": "semantic rule/route uniqueness and conflict rejection before native routing",
    "relationship": "candidate",
    "reason": "Contradictory typed policy vectors test the common boundary; native alias resolution and actual packet/routing behavior remain unqualified.",
    "claims": [],
}


def query(role, method, records):
    _, executor = installed(role)
    value = {
        "contract": "fishhat." + role,
        "method": method,
        "input": {
            "scope": copy.deepcopy(executor["scope"]),
            "target": {
                "binding": executor,
                "namespace": {"authority": OWNER["id"], "resource": "data", "facet": "content"},
            },
            "expected_previous": {
                "native_incarnation": identifier(301),
                "revision": "publication:one",
                "digest": "sha256:" + "b" * 64,
            },
            "policy_digest" if role == "network" else "generation_digest": "sha256:" + "a" * 64,
            "rules" if role == "network" else "routes": records,
        },
    }
    value["input"]["policy_digest" if role == "network" else "generation_digest"] = (
        generation_digest(role, value["input"])
    )
    return value


def generation_digest(role, inputs):
    records = "rules" if role == "network" else "routes"
    return digest(
        {
            "format": "fishhat.routing-generation/v1",
            "role": role,
            "target": inputs["target"],
            records: inputs[records],
        }
    )


@pytest.mark.parametrize("method", ["plan", "publish"])
@pytest.mark.parametrize("reverse", [False, True], ids=["forward", "reversed"])
def test_contradictory_network_decisions_cannot_depend_on_array_order(method, reverse):
    rules = [
        {"handle": "web", "direction": "ingress", "action": "allow", "endpoint": "web"},
        {"handle": "web", "direction": "ingress", "action": "deny", "endpoint": "web"},
    ]
    if reverse:
        rules.reverse()
    with pytest.raises(ContractError, match="DUPLICATE_NETWORK_RULE"):
        check_request("network", query("network", method, rules))
    rules[1]["handle"] = "other"
    with pytest.raises(ContractError, match="OVERLAPPING_NETWORK_DECISION"):
        check_request("network", query("network", method, rules))


@pytest.mark.parametrize("method", ["plan", "publish"])
def test_ingress_names_and_listener_targets_are_unique_independently(method):
    routes = [
        {
            "name": "web",
            "listener": "https",
            "upstream": "app:one",
            "policy_digest": "sha256:" + "b" * 64,
        },
        {
            "name": "web",
            "listener": "https",
            "upstream": "app:two",
            "policy_digest": "sha256:" + "b" * 64,
        },
    ]
    with pytest.raises(ContractError, match="DUPLICATE_INGRESS_ROUTE"):
        check_request("ingress", query("ingress", method, routes))
    routes[1]["name"] = "other"
    with pytest.raises(ContractError, match="OVERLAPPING_INGRESS_LISTENER"):
        check_request("ingress", query("ingress", method, routes))


@pytest.mark.parametrize("role", ["network", "ingress"])
def test_disjoint_routing_records_have_no_array_order_precedence(role):
    records = (
        [
            {"handle": name, "direction": "ingress", "action": "allow", "endpoint": name}
            for name in ["a", "b"]
        ]
        if role == "network"
        else [
            {
                "name": name,
                "listener": name,
                "upstream": "app:" + name,
                "policy_digest": "sha256:" + "b" * 64,
            }
            for name in ["a", "b"]
        ]
    )
    check_request(role, query(role, "publish", records))
    check_request(role, query(role, "publish", list(reversed(copy.deepcopy(records)))))
