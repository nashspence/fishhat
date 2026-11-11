"""Host source grants stay separate from native scheduling identity and evidence."""

from copy import deepcopy

import pytest
from fishhat_contracts.resources import validate_host_resources
from fishhat_contracts.validation import ContractError

from tests.test_resources import load

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resources.schema.json"
    ],
    "scope": "host-approved admission selection and account budget joins",
    "relationship": "candidate",
    "reason": "Synthetic source authority and aggregate budget checks; no native capacity evidence.",
    "claims": [],
}


def host_with_admission():
    host = load("examples/host-node-a/host.yaml")
    resources = host["resources"]
    first = next(iter(resources["accounts"].values()))
    scheduler = deepcopy(host["adapter_instances"][first["compute"]["instance"]])
    scheduler.update(id="scheduler", role="scheduler")
    scheduler["grants"][0]["scope"].update(kind="allocation", handle="host-capacity")
    host["adapter_instances"]["scheduler"] = scheduler
    resources["admission"] = {
        "instance": "scheduler",
        "allocation": "host-capacity",
        "capacity": {"cpu_millis": 64000, "memory_bytes": 68719476736, "devices": {}},
        "control_reserve": {
            "cpu_millis": 1000,
            "memory_bytes": resources["control"]["host_memory_reserve_bytes"],
            "devices": {},
        },
        "resident_reserve": {"cpu_millis": 0, "memory_bytes": 0, "devices": {}},
        "accounts": {
            key: {
                "maximum": {
                    "cpu_millis": account["compute"]["cpu_millis"],
                    "memory_bytes": account["compute"]["memory_max_bytes"],
                    "devices": {},
                },
                "classes": ["maintenance"],
            }
            for key, account in resources["accounts"].items()
        },
    }
    return host


def test_explicit_source_selection_preserves_account_envelopes():
    validate_host_resources(host_with_admission())


def test_account_ceilings_share_capacity_without_reserving_it_in_advance():
    host = host_with_admission()
    admission = host["resources"]["admission"]
    maxima = [account["maximum"] for account in admission["accounts"].values()]
    for quantity in ("cpu_millis", "memory_bytes"):
        available = max(value[quantity] for value in maxima)
        assert sum(value[quantity] for value in maxima) > available
        admission["capacity"][quantity] = available + admission["control_reserve"][quantity]
    validate_host_resources(host)


def test_missing_admission_selection_does_not_mean_unbounded_execution():
    host = load("examples/host-node-a/host.yaml")
    assert host["resources"]["admission"] is None
    validate_host_resources(host)
    del host["resources"]["admission"]
    with pytest.raises(ContractError):
        validate_host_resources(host)


@pytest.mark.parametrize(
    "change",
    [
        "unapproved-instance",
        "unapproved-scope",
        "account",
        "ceiling",
        "reserve",
        "reserved-account-ceiling",
        "device",
    ],
)
def test_host_rejects_unauthorized_or_overcommitted_scheduling_policy(change):
    host = host_with_admission()
    admission = host["resources"]["admission"]
    account = next(iter(admission["accounts"].values()))
    if change == "unapproved-instance":
        admission["instance"] = "other"
    elif change == "unapproved-scope":
        admission["allocation"] = "other"
    elif change == "account":
        admission["accounts"]["unknown"] = deepcopy(account)
    elif change == "ceiling":
        account["maximum"]["memory_bytes"] += 1
    elif change == "reserve":
        admission["control_reserve"]["memory_bytes"] = admission["capacity"]["memory_bytes"] + 1
    elif change == "reserved-account-ceiling":
        admission["capacity"]["memory_bytes"] = (
            account["maximum"]["memory_bytes"] + admission["control_reserve"]["memory_bytes"] - 1
        )
    else:
        admission["resident_reserve"]["devices"] = {"unapproved-gpu": 1}
    with pytest.raises(ContractError):
        validate_host_resources(host)


def test_source_cannot_supply_observed_native_scheduler_authority():
    host = host_with_admission()
    host["resources"]["admission"]["incarnation"] = "caller-asserted-native-id"
    with pytest.raises(ContractError):
        validate_host_resources(host)
