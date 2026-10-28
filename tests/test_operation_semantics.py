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
from fishhat_contracts.handoffs import (
    ACTIONS,
    schema_identity,
    validate_cli_result,
    validate_result_payload,
)
from fishhat_contracts.operations import (
    operation_plan_request,
    validate_operation,
    validate_operation_plan,
)
from fishhat_contracts.planning import validate_plan_lookup
from fishhat_contracts.record_delivery import RecordSnapshot, validate_record_payload
from fishhat_contracts.validation import (
    SCHEMAS,
    ContractError,
    canonical,
    digest,
    validate,
    validate_cli,
)
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_bindings import bind_workflow
from fishhat_owner.commands import parse_command

from tests.operation_support import seal_operation
from tests.test_owner_handoffs import (
    FIXTURES,
    U,
    V,
    adapter_result,
    cli,
    operation,
    request,
    wire,
    work_page,
)
from tests.test_plan_review import reseal
from tests.test_publication import outcome
from tests.test_record_delivery import complete_record
from tests.test_workflow_continuations import context, successor_stage

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Operation",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/SourceProposal",
        "packages/fishhat-contracts/src/fishhat_contracts/operations.py#validate_operation",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/plan-input.schema.json#/$defs/LookupRequest",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-cli.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/BindRequest",
    ],
    "scope": "complete Operation attestation, mandatory producer results and exact retained Plan rediscovery",
    "relationship": "candidate",
    "reason": "The same changed body and inconsistent attestation are rejected through direct, page, chunk and submission boundaries. Successful producers cannot omit their result while unresolved records remain representable; complete typed cleanup and no-change capture outputs roundtrip. Original expired review is recovered solely from owner records. Synthetic fixtures do not prove receiving signature authentication, atomic custody or native outcome truth.",
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


@pytest.mark.parametrize(
    "change",
    [
        "unknown-success",
        "witness-owner",
        "witness-epoch",
        "witness-state",
        "witness-generation",
        "witness-kind",
        "subject",
        "request",
        "plan",
        "generation",
        "holds",
        "principal",
        "event",
        "time",
    ],
)
def test_all_current_operation_paths_reject_the_same_invalid_record(change):
    original = operation()
    reference = RecordSnapshot(original, U).reference
    value = copy.deepcopy(original)
    if change == "unknown-success":
        value.update(state="succeeded", effect_certainty="unknown")
    elif change == "witness-owner":
        value["witness"]["owner"]["id"] = V
    elif change == "witness-epoch":
        value["witness"]["owner"]["epoch"] = V
    elif change.startswith("witness-"):
        field = change.removeprefix("witness-")
        value["witness"][field] = {"state": "succeeded", "generation": 5, "kind": "plan"}[field]
        body = {key: item for key, item in value["witness"].items() if key != "signature"}
        value["witness"] = sign(body, Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))
    elif change == "subject":
        value["subject"]["arguments"]["components"] = ["another-component"]
    else:
        field, replacement = {
            "request": ("request_id", V),
            "plan": ("plan_digest", digest({"different": "review"})),
            "generation": ("generation", 1),
            "holds": ("holds", [U]),
            "principal": ("authenticated_principal", "another-principal"),
            "event": ("last_event", 1),
            "time": ("updated_at", "2026-10-17T00:01:00Z"),
        }[change]
        value[field] = replacement
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
    seal_operation(value)
    validate_operation(value)
    validate_cli(envelope(value))
    validate_cli_result(work_page("OperationPage", [value]))
    assert complete_record(RecordSnapshot(value, U)) == value
    assert submit_once(delivery(value), lambda _: value)["owner_receipt"] == value


def producer(action):
    value = operation()
    if action in {"publisher.publish", "publisher.recover"}:
        receipt, value = outcome()
        if action == "publisher.recover":
            value["subject"]["action"] = action
            value["subject"]["arguments"] = {
                "publication_id": receipt["id"],
                "candidate_digest": receipt["recovery_handle"]["digest"],
            }
    elif action == "adapter.execute":
        value, _, _ = adapter_result()
    else:
        arguments = {
            "app.backup": {},
            "app.cleanup": {
                "inventory_digest": digest({}),
                "candidates": [digest([])],
                "account": "app-demo-app",
            },
            "host.capture-changes": {
                "base": "a" * 40,
                "paths": [],
                "source_id": "demo",
                "repository": {"instance": V, "repository_id": 1, "name": "demo/config"},
            },
        }[action]
        host = action.startswith("host.")
        value["owner"]["tool"] = "host-ops" if host else "app-ops"
        value["subject"] = {
            "action": action,
            "resource": {"kind": "host" if host else "app", "id": "synthetic-resource"},
            "arguments": arguments,
        }
    value.update(state="accepted", effect_certainty="none", result_handle=None)
    return seal_operation(value)


@pytest.mark.parametrize(
    "action",
    [
        "app.backup",
        "app.cleanup",
        "host.capture-changes",
        "publisher.publish",
        "publisher.recover",
        "adapter.execute",
    ],
)
def test_successful_producers_require_results_without_losing_unresolved_records(action):
    value = producer(action)
    for state in ("accepted", "running", "waiting", "failed", "cancelled", "quarantined"):
        value["state"] = state
        seal_operation(value)
        validate_operation(value)
    value.update(state="succeeded", effect_certainty="known")
    seal_operation(value)
    for check in (
        lambda: validate("records.schema.json", value, "Operation"),
        lambda: validate("ssh-response.schema.json", wire("operation.get", value)),
        lambda: validate_operation(value),
        lambda: validate_cli(envelope(value)),
        lambda: RecordSnapshot(value, U),
    ):
        with pytest.raises(ContractError):
            check()


def test_successful_cleanup_result_is_complete_typed_and_attested():
    value = producer("app.cleanup")
    result = json.loads((FIXTURES / "resources/cleanup-receipt.json").read_text())
    result.update(owner=value["owner"], operation_id=value["id"], plan_digest=value["plan_digest"])
    value["subject"]["arguments"]["candidates"] = [item["handle"] for item in result["items"]]
    data = canonical(result)
    value.update(state="succeeded", effect_certainty="known")
    value["result_handle"] = {
        "handle": {
            "owner": copy.deepcopy(value["owner"]),
            "id": U,
            "purpose": "content",
            "binding": {"kind": "operation", "operation_id": value["id"]},
            "digest": digest(result),
            "size": len(data),
        },
        "schema": schema_identity(
            "https://fishhat.invalid/contracts/resource-records.schema.json#/$defs/CleanupReceipt"
        ),
    }
    seal_operation(value)
    assert validate_result_payload(value, data) == result
    assert complete_record(RecordSnapshot(value, U)) == value
    changed = copy.deepcopy(value)
    changed["result_handle"]["handle"]["digest"] = digest({"substitution": True})
    with pytest.raises(ContractError, match="witness snapshot mismatch"):
        validate_operation(changed)


def test_successful_no_change_capture_retains_a_complete_typed_source_proposal():
    value = producer("host.capture-changes")
    result = {
        "format": "deployment-ops/record/v1",
        "kind": "SourceProposal",
        "id": U,
        "repository": {"instance": V, "repository_id": 1, "name": "demo/config"},
        "source_id": "demo",
        "base_commit": value["subject"]["arguments"]["base"],
        "ref": "refs/heads/capture-no-change",
        "operation_id": value["id"],
        "paths": [],
        "files": [],
        "tree_digest": digest({"format": "deployment-ops/captured-tree/v1", "files": []}),
        "changes": [],
        "owner": copy.deepcopy(value["owner"]),
    }
    witness = {key: item for key, item in value["witness"].items() if key != "signature"}
    witness.update(kind="effect", state="succeeded", subject_digest=digest(result))
    result["witness"] = sign(witness, Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))
    data = canonical(result)
    value.update(state="succeeded", effect_certainty="known")
    value["result_handle"] = {
        "handle": {
            "owner": copy.deepcopy(value["owner"]),
            "id": V,
            "purpose": "content",
            "binding": {"kind": "operation", "operation_id": value["id"]},
            "digest": digest(result),
            "size": len(data),
        },
        "schema": schema_identity(
            "https://fishhat.invalid/contracts/records.schema.json#/$defs/SourceProposal"
        ),
    }
    seal_operation(value)
    assert validate_result_payload(value, data) == result
    assert complete_record(RecordSnapshot(value, U)) == value
    # The complete empty selection is explicit; omitting it is not a no-change result.
    omitted = copy.deepcopy(result)
    del omitted["changes"]
    with pytest.raises(ContractError):
        validate("records.schema.json", omitted, "SourceProposal")


def test_shape_and_semantic_boundaries_share_the_producer_result_requirement():
    expected = {
        name for name, action in ACTIONS.items() if action["result"]["mode"] != "receipt-only"
    }
    assert {
        name for name, action in ACTIONS.items() if action["result"].get("required_on_success")
    } == expected
    rules = SCHEMAS["records.schema.json"]["$defs"]["Operation"]["allOf"]
    mandatory = next(rule for rule in rules if "result_handle" in rule["then"]["properties"])
    assert set(mandatory["if"]["properties"]["subject"]["properties"]["action"]["enum"]) == expected


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
