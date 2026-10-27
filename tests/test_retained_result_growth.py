"""Complete retained result validation with increasing native artifact custody."""

from __future__ import annotations

import copy
from unittest.mock import patch

import pytest
from fishhat_contracts import canonical, digest, handoffs
from fishhat_contracts.validation import ContractError
from jsonschema import Draft202012Validator, _utils

from tests.linear_support import assert_linear, measure
from tests.test_adapter_handoffs import invocation_for, response_for
from tests.test_adapter_retained_results import result_fixture
from tests.test_export_growth import capture
from tests.test_workflow_continuations import attach_result

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/handoffs.py#validate_result_payload",
        "release.toml#/engineering",
    ],
    "scope": "complete retained capture result validation under its fixed installed Draft 2020-12 schema closure",
    "relationship": "scoped-witness",
    "reason": "Complete growing invocation and response artifact arrays exercise selected-schema references, exact custody joins and method semantics. Separate artifact comparison counts prevent fixed schema hashing from hiding pairwise uniqueness. Duplicate artifacts still reject. This does not qualify native custody or other custom schema profiles.",
    "claims": ["engineering:handoffs.retained-result"],
}


def retained_capture(count, *, duplicate=False):
    record, _ = result_fixture("capture", "restore")
    _, request, _, _ = capture(count)
    if duplicate:
        artifacts = request["input"]["snapshot"]["artifacts"]
        artifacts.append(copy.deepcopy(artifacts[0]))
    invocation = invocation_for(request)
    response = response_for(
        request,
        invocation["attempt"],
        {"snapshots": [copy.deepcopy(request["input"]["snapshot"])], "verification": "consistent"},
    )
    value = {"invocation": invocation, "response": response}
    record["subject"]["arguments"]["input"].update(
        digest=digest(request), size=len(canonical(request))
    )
    attach_result(record, value, record["owner"])
    return record, value, canonical(value)


def test_retained_adapter_results_linear_work():
    samples = []
    for count in (16, 64, 256):
        record, value, data = retained_capture(count)
        comparisons = 0
        original = _utils.equal

        def equal(first, second, original=original):
            nonlocal comparisons
            if (
                isinstance(first, dict)
                and isinstance(second, dict)
                and "digest" in first
                and "media_type" in first
            ):
                comparisons += 1
            return original(first, second)

        with patch.object(_utils, "equal", equal):
            decoded, work = measure(
                lambda record=record, data=data: handoffs.validate_result_payload(record, data)
            )
        assert decoded == value
        assert len(decoded["response"]["output"]["snapshots"][0]["artifacts"]) == count
        work["artifact_comparisons"] = comparisons
        samples.append((count, work))
    assert_linear(samples)
    record, _, data = retained_capture(16, duplicate=True)
    with pytest.raises(ContractError, match="result payload violates action schema"):
        handoffs.validate_result_payload(record, data)


def test_retained_result_growth_witness_rejects_stock_uniqueness(monkeypatch):
    monkeypatch.setattr(handoffs, "_SCHEMA_VALIDATOR", Draft202012Validator)
    with pytest.raises(AssertionError):
        test_retained_adapter_results_linear_work()


CHECK_OVERRIDES = {
    "test_retained_result_growth_witness_rejects_stock_uniqueness": {
        "purpose": "validation-tooling",
        "authority": [
            "tests/test_retained_result_growth.py#test_retained_adapter_results_linear_work"
        ],
        "scope": "retained-result growth regression detection",
        "relationship": "no-product-claim",
        "reason": "Reinstating pairwise uniqueness at the selected retained-result boundary must fail the same complete-operation witness; this grants no implementation qualification.",
        "claims": [],
    }
}
