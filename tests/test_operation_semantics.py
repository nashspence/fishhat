"""Operation integrity is independent of transport representation and client files."""

from __future__ import annotations

import copy
import hashlib
import io
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_client.submission import prepare_delivery, submit_once
from fishhat_client.wire import frame, read_frame
from fishhat_contracts.handoffs import validate_cli_result
from fishhat_contracts.operations import (
    operation_plan_request,
    validate_operation,
    validate_operation_plan,
)
from fishhat_contracts.planning import validate_plan_lookup
from fishhat_contracts.record_delivery import RecordSnapshot, validate_record_payload
from fishhat_contracts.validation import ContractError, canonical, digest, validate, validate_cli
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_bindings import bind_workflow
from fishhat_owner.commands import parse_command

from tests.test_owner_handoffs import FIXTURES, U, V, cli, operation, request, wire, work_page
from tests.test_plan_review import reseal
from tests.test_record_delivery import complete_record
from tests.test_workflow_continuations import context, successor_stage

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Operation",
        "packages/fishhat-contracts/src/fishhat_contracts/operations.py#validate_operation",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/plan-input.schema.json#/$defs/LookupRequest",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-cli.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/BindRequest",
    ],
    "scope": "uniform Operation invariants and exact retained Plan rediscovery",
    "relationship": "candidate",
    "reason": "The same invalid outcome and witness-owner substitutions are rejected through direct, page, chunk and submission boundaries. Original expired review is recovered solely from owner records. Synthetic fixtures do not prove signature authentication or native outcome truth.",
    "claims": [],
}


def envelope(value):
    return {
        **cli(value),
        "request_id": value["request_id"],
        "state": value["state"],
        "complete": value["state"] in {"succeeded", "failed", "cancelled", "quarantined"},
        "ok": value["state"] not in {"failed", "cancelled", "quarantined"},
    }


def delivery(value):
    template = json.loads((FIXTURES / "session/receipt-export.json").read_text())["deliveries"][0]
    template.update(
        owner=copy.deepcopy(value["owner"]),
        plan_digest=value["plan_digest"],
        subject_digest=digest(value["subject"]),
        action=value["subject"]["action"],
        resource=copy.deepcopy(value["subject"]["resource"]),
        expected_generation=value["generation"],
    )
    return prepare_delivery(template, request_id=value["request_id"])


@pytest.mark.parametrize("certainty", ["none", "unknown"])
def test_success_requires_known_effects_in_the_schema_itself(certainty):
    value = operation()
    value.update(state="succeeded", effect_certainty=certainty)
    for schema, document, definition in (
        ("records.schema.json", value, "Operation"),
        ("records.schema.json", work_page("OperationPage", [value]), "OperationPage"),
        ("ssh-response.schema.json", wire("operation.get", value), None),
    ):
        with pytest.raises(ContractError):
            validate(schema, document, definition)


@pytest.mark.parametrize("change", ["unknown-success", "witness-owner", "witness-epoch"])
def test_all_current_operation_paths_reject_the_same_invalid_record(change):
    original = operation()
    reference = RecordSnapshot(original, U).reference
    value = copy.deepcopy(original)
    if change == "unknown-success":
        value.update(state="succeeded", effect_certainty="unknown")
    elif change == "witness-owner":
        value["witness"]["owner"]["id"] = V
    else:
        value["witness"]["owner"]["epoch"] = V
    for check in (
        lambda: validate_operation(value),
        lambda: validate_cli_result(value),
        lambda: validate_cli(envelope(value)),
        lambda: validate_cli_result(work_page("OperationPage", [value])),
        lambda: validate_cli(cli(work_page("OperationPage", [value]))),
        lambda: RecordSnapshot(value, V),
    ):
        with pytest.raises(ContractError):
            check()
    # Reach the payload semantic boundary with valid size/digest/schema identity;
    # failing only a transfer digest would not exercise this invariant.
    data = canonical(value)
    reference.update(size=len(data), digest="sha256:" + hashlib.sha256(data).hexdigest())
    with pytest.raises(ContractError):
        validate_record_payload(reference, data, expected_owner=original["owner"])
    submission = submit_once(delivery(original), lambda _: value)
    assert submission["exit_code"] == 8
    assert submission["delivery"]["state"] == "acceptance_unknown"
    assert submission["owner_receipt"] is None


def test_valid_known_success_preserves_exact_operation_across_all_read_forms():
    value = operation()
    value.update(state="succeeded", effect_certainty="known")
    validate_operation(value)
    validate_cli(envelope(value))
    validate_cli_result(work_page("OperationPage", [value]))
    assert complete_record(RecordSnapshot(value, U)) == value
    assert submit_once(delivery(value), lambda _: value)["owner_receipt"] == value


@pytest.mark.parametrize("change", ["unknown-success", "witness-owner", "witness-epoch"])
def test_workflow_predecessors_enforce_the_same_operation_invariants(change):
    workflow, query = successor_stage()
    value = query["predecessors"][0]
    if change == "unknown-success":
        value["effect_certainty"] = "unknown"
    else:
        value["witness"]["owner"] = copy.deepcopy(value["owner"])
        value["witness"]["owner"]["id" if change == "witness-owner" else "epoch"] = V
    body = {key: item for key, item in value["witness"].items() if key != "signature"}
    value["witness"] = sign(body, Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))
    with pytest.raises(ContractError):
        bind_workflow(query, workflow, **context(query))


def test_accepted_plan_is_retrievable_with_only_an_owner_discovered_operation():
    value = operation()
    plan = json.loads((FIXTURES / "plan.json").read_text())
    # No client files, original Plan UUID or unexpired admission are required
    # to form the read. Its digest commits that UUID as part of the whole Plan.
    query = operation_plan_request(value)
    assert query == {"owner": value["owner"], "plan_digest": value["plan_digest"]}
    message = request("plan.get", query)
    validate("ssh-request.schema.json", message)
    assert read_frame(io.BytesIO(frame(message))) == message
    retrieved = complete_record(RecordSnapshot(plan, U))
    validate_plan_lookup(retrieved, query, expected_owner=value["owner"])
    validate_operation_plan(value, retrieved)
    assert retrieved["expires_at"] < "2026-10-26T00:00:00Z"
    assert (
        parse_command("app-ops plan show --request-stdin --json", "app-ops")["use_case"]
        == "plan.get"
    )


@pytest.mark.parametrize("field", ["owner", "digest", "subject"])
def test_plan_lookup_cannot_substitute_original_accepted_review(field):
    value = operation()
    plan = json.loads((FIXTURES / "plan.json").read_text())
    query = operation_plan_request(value)
    if field == "owner":
        query["owner"]["epoch"] = V
    elif field == "digest":
        query["plan_digest"] = "sha256:" + "f" * 64
    else:
        plan["subject"]["arguments"]["components"] = ["other-component"]
        plan = reseal(plan)
    with pytest.raises(ContractError):
        validate_plan_lookup(plan, query, expected_owner=value["owner"])
    if field == "subject":
        with pytest.raises(ContractError):
            validate_operation_plan(value, plan)


def test_plan_lookup_requires_owner_and_digest():
    with pytest.raises(ContractError):
        validate("ssh-request.schema.json", request("plan.get", {"plan_id": U}))
