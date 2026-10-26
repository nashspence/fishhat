from __future__ import annotations

import copy

import pytest
from fishhat_adapters import check_request, check_response
from fishhat_contracts.validation import ContractError, digest

from tests.test_adapter_handoffs import installed, invocation_for, response_for

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/compute-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/storage-adapter.schema.json",
    ],
    "scope": "named compute requirements, exact approved storage ceilings and allocation-bound usage evidence",
    "relationship": "candidate",
    "reason": "Quantity/target, unit, coverage and time checks establish common data semantics, not native enforcement.",
    "claims": [],
}


def limit(quantity="memory-max", value=2048, unit="bytes", target=None):
    return {"quantity": quantity, "value": value, "unit": unit, "target": target}


def request(limits=None):
    _, executor = installed("compute")
    return {
        "contract": "fishhat.compute",
        "method": "set-limits",
        "input": {
            "scope": executor["scope"],
            "allocation": "allocation:demo",
            "limits": [limit()] if limits is None else limits,
        },
    }


def counter(metric="memory-used", value=1024, unit="bytes", **changes):
    return {
        "allocation": "allocation:demo",
        "metric": metric,
        "value": value,
        "unit": unit,
        "coverage": "complete",
        "observed_at": "2026-01-01T00:00:01Z",
        "interval_start": None,
        "target": None,
        **changes,
    }


def observe(counters):
    scope = request()["input"]["scope"]
    query = {
        "contract": "fishhat.compute",
        "method": "observe",
        "input": {"scope": scope, "cursor": None, "limit": 10},
    }
    reply = {
        "contract": query["contract"],
        "method": query["method"],
        "request_digest": digest(query),
        "scope": scope,
        "coverage": "complete",
        "continuation": None,
        "proposal": None,
        "output": {"allocation": "allocation:demo", "limits": [], "counters": counters},
    }
    return query, reply


@pytest.mark.parametrize(
    "value",
    [
        limit("cpu-max", 1500, "millicpus"),
        limit("cpu-weight", 500, "weight"),
        limit("memory-high", 1024),
        limit("memory-max", 2048),
        limit("swap-max", 0),
        limit("tasks-max", 128, "tasks"),
        limit("io-weight", 100, "weight"),
        limit("io-read-rate", 4096, "bytes-per-second", "device:data"),
        limit("io-write-rate", 4096, "bytes-per-second", "device:data"),
        limit("tmpfs-max-bytes", 8192),
        limit("tmpfs-max-inodes", 128, "inodes"),
    ],
    ids=lambda value: value["quantity"],
)
def test_compute_requirements_have_specific_units_and_target_meaning(value):
    check_request("compute", request([value]))


@pytest.mark.parametrize(
    "value",
    [
        {"resource": "memory", "value": 10, "unit": "cpu-millis"},
        limit("memory-max", 10, "cpu-millis"),
        limit("cpu-max", 1000, "tasks"),
        limit("io-read-rate", 4096, "bytes", "device:data"),
        limit("io-read-rate", 4096, "bytes-per-second"),
        limit("memory-max", 1024, "bytes", "device:data"),
        limit("cpu-weight", 10001, "weight"),
    ],
)
def test_undefined_quantity_unit_combinations_and_native_target_shortcuts_reject(value):
    with pytest.raises(ContractError):
        check_request("compute", request([value]))


def test_limit_uniqueness_uses_quantity_and_target_not_whole_record():
    with pytest.raises(ContractError, match="DUPLICATE_LIMIT"):
        check_request("compute", request([limit(value=1024), limit(value=2048)]))
    check_request(
        "compute",
        request(
            [
                limit("io-read-rate", 4096, "bytes-per-second", "device:a"),
                limit("io-read-rate", 8192, "bytes-per-second", "device:b"),
            ]
        ),
    )
    with pytest.raises(ContractError, match="INCONSISTENT_MEMORY_LIMITS"):
        check_request("compute", request([limit("memory-high", 4096), limit("memory-max", 2048)]))


@pytest.mark.parametrize("change", ["missing", "extra", "changed", "allocation"])
def test_success_proves_the_exact_requested_limit_set(change):
    query = request([limit(), limit("tasks-max", 128, "tasks")])
    invocation = invocation_for(query)
    output = {
        "allocation": query["input"]["allocation"],
        "limits": copy.deepcopy(query["input"]["limits"]),
        "counters": [],
    }
    reply = response_for(query, invocation["attempt"], output)
    check_response("compute", query, reply, invocation=invocation)
    if change == "missing":
        output["limits"].pop()
    elif change == "extra":
        output["limits"].append(limit("swap-max", 0))
    elif change == "changed":
        output["limits"][0]["value"] += 1
    else:
        output["allocation"] = "allocation:other"
    with pytest.raises(ContractError, match="SUCCESS_OUTPUT_IDENTITY"):
        check_response("compute", query, reply, invocation=invocation)


def test_usage_metrics_disambiguate_equal_memory_and_swap_byte_values():
    query, reply = observe([counter(), counter("swap-used")])
    check_response("compute", query, reply)
    reply["output"]["counters"][1]["metric"] = "memory-used"
    reply["output"]["counters"][1]["value"] += 1
    with pytest.raises(ContractError, match="DUPLICATE_COUNTER"):
        check_response("compute", query, reply)


@pytest.mark.parametrize(
    "changes",
    [
        {"unit": "tasks"},
        {"allocation": "allocation:other"},
        {"value": None},
        {"coverage": "unknown"},
        {"coverage": "unsupported"},
        {"interval_start": "2026-01-01T00:00:00Z"},
    ],
)
def test_counter_identity_coverage_and_quantity_are_not_inferred(changes):
    query, reply = observe([counter(**changes)])
    with pytest.raises(ContractError):
        check_response("compute", query, reply)


def test_cpu_time_is_an_interval_quantity_and_is_not_cpu_quota():
    query, reply = observe(
        [counter("cpu-time", 500, "cpu-millis", interval_start="2026-01-01T00:00:00Z")]
    )
    check_response("compute", query, reply)
    value = reply["output"]["counters"][0]
    value.update(observed_at="2026-01-01T00:00:00.5Z")
    check_response("compute", query, reply)
    for start in [None, "2026-01-01T00:00:00.500Z", "2026-01-01T00:00:01Z"]:
        value["interval_start"] = start
        with pytest.raises(ContractError):
            check_response("compute", query, reply)
    value.update(coverage="unsupported", value=None, interval_start=None)
    check_response("compute", query, reply)


def test_io_counters_have_separate_logical_targets_and_time_windows():
    query, reply = observe(
        [
            counter(
                "io-read", 100, "bytes", target="device:a", interval_start="2026-01-01T00:00:00Z"
            ),
            counter(
                "io-read", 200, "bytes", target="device:b", interval_start="2026-01-01T00:00:00Z"
            ),
        ]
    )
    check_response("compute", query, reply)
    reply["output"]["counters"][1]["target"] = None
    with pytest.raises(ContractError):
        check_response("compute", query, reply)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
@pytest.mark.parametrize(
    "change", ["bytes-low", "bytes-high", "inodes-low", "inodes-high", "isolation"]
)
def test_storage_success_matches_exact_approved_ceiling_and_isolation(change, reconcile):
    _, executor = installed("storage")
    query = {
        "contract": "fishhat.storage",
        "method": "allocate",
        "input": {
            "scope": executor["scope"],
            "allocation": "allocation:demo",
            "capacity_bytes": 2048,
            "capacity_inodes": 10,
            "purposes": ["state"],
            "hard_isolation": True,
        },
    }
    invocation = invocation_for(query)
    allocation = {
        "handle": "allocation:demo",
        "accounting_domain": "domain:demo",
        "purposes": ["state"],
        "native_identity_digest": "sha256:" + "a" * 64,
        "counters": [counter("storage-used", 0)],
        "hard_isolation": True,
        "capacity_bytes": 2048,
        "capacity_inodes": 10,
    }
    if reconcile:
        query = {
            "contract": query["contract"],
            "method": "reconcile",
            "input": {"scope": executor["scope"], "invocation": invocation},
        }
    reply = response_for(query, invocation["attempt"], {"allocations": [allocation]})
    check_response("storage", query, reply, invocation=invocation)
    allocation.update(
        {"capacity_bytes": 2047}
        if change == "bytes-low"
        else {"capacity_bytes": 2048000}
        if change == "bytes-high"
        else {"capacity_inodes": 9}
        if change == "inodes-low"
        else {"capacity_inodes": 10000}
        if change == "inodes-high"
        else {"hard_isolation": False}
    )
    with pytest.raises(ContractError, match="SUCCESS_OUTPUT_IDENTITY"):
        check_response("storage", query, reply, invocation=invocation)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
def test_storage_quota_change_preserves_identity_and_requires_new_exact_result(reconcile):
    _, executor = installed("storage")
    original = {
        "contract": "fishhat.storage",
        "method": "allocate",
        "input": {
            "scope": executor["scope"],
            "allocation": "allocation:demo",
            "capacity_bytes": 2048,
            "capacity_inodes": 10,
            "purposes": ["state"],
            "hard_isolation": True,
        },
    }
    query = copy.deepcopy(original)
    query["input"].update(capacity_bytes=0, capacity_inodes=0)
    assert digest(query) != digest(original)
    assert query["input"]["allocation"] == original["input"]["allocation"]
    invocation = invocation_for(query)
    allocation = {
        "handle": "allocation:demo",
        "accounting_domain": "domain:demo",
        "purposes": ["state"],
        "native_identity_digest": "sha256:" + "a" * 64,
        "counters": [counter("storage-used", 0)],
        "hard_isolation": True,
        "capacity_bytes": 0,
        "capacity_inodes": 0,
    }
    if reconcile:
        query = {
            "contract": query["contract"],
            "method": "reconcile",
            "input": {"scope": executor["scope"], "invocation": invocation},
        }
    reply = response_for(query, invocation["attempt"], {"allocations": [allocation]})
    check_response("storage", query, reply, invocation=invocation)
    # A prior nonzero ceiling is not an alternative spelling for a zero quota.
    allocation.update(capacity_bytes=2048, capacity_inodes=10)
    with pytest.raises(ContractError, match="SUCCESS_OUTPUT_IDENTITY"):
        check_response("storage", query, reply, invocation=invocation)
