"""Resource observations require complete logical bucket coverage at every boundary."""

from __future__ import annotations

import copy
import json

import pytest
from fishhat_contracts.record_delivery import RecordSnapshot, validate_record_payload
from fishhat_contracts.validation import ContractError, canonical, digest, validate, validate_cli

from tests.support import ROOT
from tests.test_contracts import uid
from tests.test_owner_handoffs import cli, wire

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json#/$defs/ResourceReport",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/RecordReference",
    ],
    "scope": "one runtime, state, scratch and logs bucket per observed resource account",
    "relationship": "candidate",
    "reason": "Reordered complete reports remain valid while duplicate identities fail both inline delivery and complete referenced payload intake. No native measurement or quota enforcement is qualified.",
    "claims": [],
}


def report():
    return json.loads((ROOT / "tests/fixtures/resources/report.json").read_text())


def accept(value, boundary):
    if boundary == "schema":
        validate("resource-records.schema.json", value, "ResourceReport")
    elif boundary == "cli":
        validate_cli(cli(value))
    elif boundary == "ssh":
        validate("ssh-response.schema.json", wire("resources.observe", value))
    else:
        # Pin the received bytes as a sender would. Digest agreement alone must
        # not allow incomplete logical coverage through the payload reader.
        reference = RecordSnapshot(report(), uid("bucket-report")).reference
        data = canonical(value)
        reference.update(digest=digest(value), size=len(data))
        validate_record_payload(
            reference,
            data,
            expected_owner=value["owner"],
            expected_record=reference["record"],
        )


@pytest.mark.parametrize("boundary", ["schema", "cli", "ssh", "record"])
def test_resource_report_accepts_each_bucket_once_in_any_order(boundary):
    value = report()
    value["accounts"][0]["storage"].reverse()
    accept(value, boundary)


@pytest.mark.parametrize("boundary", ["schema", "cli", "ssh", "record"])
@pytest.mark.parametrize("different_measurements", [False, True], ids=["identical", "distinct"])
def test_duplicate_bucket_cannot_replace_missing_report_coverage(boundary, different_measurements):
    value = report()
    storage = value["accounts"][0]["storage"]
    replacement = copy.deepcopy(storage[0])
    if different_measurements:
        replacement["used_bytes"] += 1
        replacement["root"] = "/srv/ops/separate-runtime"
        replacement["storage"]["handle"] = "separate-runtime"
    storage[1] = replacement
    assert len(storage) == 4
    with pytest.raises(ContractError):
        accept(value, boundary)
    with pytest.raises(ContractError):
        RecordSnapshot(value, uid("duplicate-bucket-report"))
