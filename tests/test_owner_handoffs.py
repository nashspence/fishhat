"""Synthetic contract handoffs; no owner persistence, authentication or native effects."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_contracts.handoffs import (
    schema_identity,
    validate_cli_result,
    validate_result_payload,
    validate_staged_input,
    validate_staging,
    validate_workflow,
)
from fishhat_contracts.operations import validate_operation
from fishhat_contracts.validation import ContractError, canonical, digest, validate, validate_cli
from fishhat_contracts.witness import sign
from fishhat_contracts.workflows import decode_workflow_input
from fishhat_owner.commands import parse_command

from tests.operation_support import seal_operation
from tests.test_contracts import uid

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/cli-output.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.json",
    ],
    "scope": "decoded owner discovery, input custody and typed result handoffs",
    "relationship": "candidate",
    "reason": "Fixed prepared-work, page, expired-input and substituted-result cases challenge public record joins; no store durability, receiving authentication or native implementation is exercised.",
    "claims": [],
}

FIXTURES = Path(__file__).parent / "fixtures"
U = "11111111-1111-4111-8111-111111111111"
V = "22222222-2222-4222-8222-222222222222"
D = "sha256:" + "a" * 64
NOW = "2026-10-23T00:30:00Z"


def operation():
    return json.loads((FIXTURES / "operation.json").read_text())


def request(method, params):
    return {
        "format": "deployment-ops/owner/v1",
        "message_id": U,
        "method": method,
        "params": params,
    }


def wire(method, result):
    return {
        "format": "deployment-ops/owner/v1",
        "message_id": U,
        "method": method,
        "ok": True,
        "result": result,
    }


def cli(result):
    return {
        "format": "deployment-ops/cli/v1",
        "ok": True,
        "state": "observed",
        "complete": True,
        "request_id": None,
        "location": "owner",
        "result": result,
        "problem": None,
    }


def preparation_witness(proposal, owner):
    body = {k: v for k, v in operation()["witness"].items() if k != "signature"}
    body.update(
        id=uid("preparation-" + owner["id"] + digest(proposal)),
        owner=copy.deepcopy(owner),
        kind="approval",
        subject_digest=digest(proposal),
        workflow_id=proposal["workflow_id"],
        generation=0,
        state="workflow-prepared",
        evidence_digests=[],
    )
    return sign(body, Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))


def preparation_witnesses(proposal):
    owners = {canonical(p["owner"]): p["owner"] for p in proposal["participants"]}
    return [preparation_witness(proposal, owner) for owner in owners.values()]


def workflow():
    op = operation()
    owner = {**op["owner"], "tool": "host-ops"}
    value = {
        "format": "deployment-ops/record/v1",
        "kind": "Workflow",
        "id": U,
        "owner": copy.deepcopy(owner),
        "generation": 0,
        "type": "host-drain",
        "driver_term": 1,
        "driver_principal": "ops-app-operate",
        "state": "prepared",
        "phase": "prepared",
        "participants": [
            {
                "owner": copy.deepcopy(owner),
                "resource": {"kind": "host", "id": "node-a"},
                "expected_generation": 9,
                "request_ids": [V],
                "last_witness": None,
            }
        ],
        "prerequisite_witnesses": [],
        "holds": [],
        "recovery_digests": [],
        "transfer": None,
        "advances": [],
        "bindings": [],
    }
    rebind_workflow_proposal(value)
    return value


def rebind_workflow_proposal(value):
    """Build exact synthetic Plans/content when a test creates a new closure."""
    participants = []
    content = {}
    for participant in value["participants"]:
        requests = []
        for request_id in participant["request_ids"]:
            plan = json.loads((FIXTURES / "plan.json").read_text())
            plan["id"] = uid("workflow-plan-" + request_id)
            plan["owner"] = copy.deepcopy(participant["owner"])
            plan["subject"] = {
                "action": "host.reboot",
                "resource": copy.deepcopy(participant["resource"]),
                "arguments": {},
            }
            plan["summary"] = "Reboot the selected synthetic host through its exact reviewed scope."
            for condition in plan["preconditions"]:
                condition.update(
                    owner=copy.deepcopy(participant["owner"]),
                    resource=copy.deepcopy(participant["resource"]),
                    generation=participant["expected_generation"],
                )
            for effect in plan["effects"]:
                effect.update(
                    executor=copy.deepcopy(participant["owner"]),
                    resource=copy.deepcopy(participant["resource"]),
                    action="admitted-reboot",
                )
            plan["digest"] = digest(
                {k: v for k, v in plan.items() if k not in {"digest", "witness"}}
            )
            body = {k: v for k, v in plan["witness"].items() if k != "signature"}
            body.update(
                owner=copy.deepcopy(plan["owner"]),
                subject_digest=plan["digest"],
                generation=participant["expected_generation"],
            )
            plan["witness"] = sign(body, Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))
            requests.append({"request_id": request_id, "phase": "host-effect", "plan": plan})
            for input_digest in plan["input_digests"]:
                identity = canonical([plan["owner"], input_digest]).decode()
                content[identity] = {
                    "owner": copy.deepcopy(plan["owner"]),
                    "id": uid("workflow-content-" + identity),
                    "purpose": "content",
                    "binding": {"kind": "staging", "staging_id": uid("workflow-stage-" + identity)},
                    "digest": input_digest,
                    "size": 1,
                }
        participants.append(
            {
                **{
                    k: copy.deepcopy(participant[k])
                    for k in ("owner", "resource", "expected_generation")
                },
                "requests": requests,
            }
        )
    value["proposal"] = {
        "format": "deployment-ops/workflow-proposal/v1",
        "workflow_id": value["id"],
        "initial_driver": {"principal": "ops-app-operate", "term": 1},
        "type": value["type"],
        "target": {
            "host_change": {
                "owner": copy.deepcopy(participants[0]["owner"]),
                "request_id": participants[0]["requests"][0]["request_id"],
            }
        },
        "participants": participants,
        "content": list(content.values()),
    }
    value["proposal_digest"] = digest(value["proposal"])
    value["prerequisite_witnesses"] = [preparation_witness(value["proposal"], value["owner"])]


def staged_workflow_input(method, payload):
    data = canonical(payload)
    reference = {
        "owner": copy.deepcopy(payload["owner"]),
        "input": {
            "owner": copy.deepcopy(payload["owner"]),
            "id": uid(method + "-input"),
            "purpose": "workflow-input",
            "binding": {"kind": "staging", "staging_id": uid(method + "-staging")},
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "size": len(data),
        },
    }
    validate("ssh-request.schema.json", request(method, reference))
    assert (
        decode_workflow_input(method, reference, data, expected_owner=payload["owner"]) == payload
    )
    return reference, data


def work_page(kind, items):
    return {
        "format": "deployment-ops/record/v1",
        "kind": kind,
        "owner": copy.deepcopy(items[0]["owner"] if items else operation()["owner"]),
        "items": items,
        "next_cursor": "next_1",
        "history_complete": False,
    }


def staging():
    op = operation()
    return {
        "format": "deployment-ops/record/v1",
        "kind": "ContentStaging",
        "id": U,
        "owner": op["owner"],
        "resource": op["subject"]["resource"],
        "authenticated_principal": "ops-app-operate",
        "purpose": "native-config",
        "digest": "sha256:" + hashlib.sha256(b"{}").hexdigest(),
        "size": 2,
        "state": "uploading",
        "offset": 0,
        "created_at": "2026-10-23T00:00:00Z",
        "expires_at": "2026-10-23T01:00:00Z",
        "accepted_references": 0,
        "handle": None,
    }


def committed():
    value = staging()
    value.update(state="committed", offset=value["size"])
    value["handle"] = {
        "owner": copy.deepcopy(value["owner"]),
        "id": V,
        "purpose": value["purpose"],
        "binding": {"kind": "staging", "staging_id": U},
        "digest": value["digest"],
        "size": value["size"],
    }
    return value


def check_input(value, **overrides):
    context = {
        "expected_owner": operation()["owner"],
        "principal": "ops-app-operate",
        "resource": operation()["subject"]["resource"],
        "purpose": "native-config",
        "now": NOW,
    }
    context.update(overrides)
    validate_staged_input(value, value["handle"], **context)


def adapter_result():
    uri = "https://synthetic.invalid/adapter-result.schema.json"
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": uri,
        "type": "object",
        "properties": {"revision": {"type": "integer", "minimum": 0}},
        "required": ["revision"],
        "additionalProperties": False,
    }
    installed = {uri: schema}
    identity = schema_identity(uri, installed)
    op = operation()
    op["subject"] = {
        "action": "adapter.execute",
        "resource": {"kind": "adapter", "id": "selected-adapter"},
        "arguments": {
            "adapter_id": "selected-adapter",
            "adapter_release": D,
            "action": "inspect",
            "input": committed()["handle"],
            "input_schema_digest": D,
            "result_schema": identity,
        },
    }
    data = canonical({"revision": 3})
    op["result_handle"] = {
        "handle": {
            "owner": copy.deepcopy(op["owner"]),
            "id": V,
            "purpose": "content",
            "binding": {"kind": "operation", "operation_id": op["id"]},
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "size": len(data),
        },
        "schema": copy.deepcopy(identity),
    }
    return seal_operation(op), data, installed


def test_prepared_workflow_is_listable_before_any_child_is_accepted():
    value = workflow()
    validate_workflow(value)
    page = work_page("WorkflowPage", [value])
    validate("ssh-response.schema.json", wire("workflow.list", page))
    validate_cli(cli(page))
    assert page["items"][0]["state"] == "prepared"
    assert page["items"][0]["participants"][0]["request_ids"] == [V]
    assert "plan_digest" not in page["items"][0]
    assert "subject" not in page["items"][0]


def test_work_listings_cover_resource_filters_terminal_history_and_continuation():
    for method in ("operation.list", "workflow.list"):
        for active in (True, False):
            params = {
                "owner": operation()["owner"],
                "resource": {"kind": "app", "id": "demo-app"},
                "active_only": active,
                "cursor": "next_1",
                "limit": 2,
            }
            validate("ssh-request.schema.json", request(method, params))
            params["limit"] = 129
            with pytest.raises(ContractError):
                validate("ssh-request.schema.json", request(method, params))


def test_prepare_cannot_supply_observed_owner_state():
    value = workflow()
    params = {"owner": value["owner"], "proposal": value["proposal"]}
    staged_workflow_input("workflow.prepare", params)
    for field, claim in (("state", "completed"), ("generation", 9), ("driver_principal", "admin")):
        with pytest.raises(ContractError):
            staged_workflow_input("workflow.prepare", {**params, field: claim})


def test_workflow_capsule_generation_is_separate_from_participant_generation():
    from tests.workflow_evidence_support import advance_request

    value = workflow()
    value["generation"] = 4
    validate_workflow(value)
    query = advance_request(value, "draining", advance_id=U)
    staged_workflow_input("workflow.advance", query)
    assert query["expected_generation"] == 4
    assert query["phase_evidence"]["participants"][0]["resource_generation"] == 9
    assert value["participants"][0]["expected_generation"] == 9
    foreign = copy.deepcopy(value)
    foreign["owner"]["epoch"] = V
    with pytest.raises(ContractError):
        validate_workflow(foreign)


def test_nonempty_and_empty_work_pages_have_identical_wire_cli_types():
    for kind, method, item in (
        ("OperationPage", "operation.list", operation()),
        ("WorkflowPage", "workflow.list", workflow()),
    ):
        for items in ([], [item]):
            page = work_page(kind, items)
            validate("ssh-response.schema.json", wire(method, page))
            validate_cli(cli(page))
        page = work_page(kind, [item])
        page["owner"]["epoch"] = V
        with pytest.raises(ContractError):
            validate_cli_result(page)
    with pytest.raises(ContractError):
        validate_cli(cli({"items": [], "next_cursor": None}))


def test_resource_and_observation_continuations_share_cli_envelope():
    report = json.loads((FIXTURES / "resources/report.json").read_text())
    validate("ssh-response.schema.json", wire("resources.observe", report))
    validate_cli(cli(report))
    observation = {
        "resource": operation()["subject"]["resource"],
        "owner": operation()["owner"],
        "time": NOW,
        "origin": "owner-confirmed",
        "reachability": "reachable",
        "power_state": "not-applicable",
        "activity": "unknown",
        "health_check": "unknown",
        "health": "unknown",
        "protection": "unknown",
        "generation": 0,
        "source": None,
        "release_digest": None,
        "summary": "Observed without an execution or health claim.",
        "witness": None,
    }
    for items in ([], [observation]):
        page = {
            "format": "deployment-ops/record/v1",
            "kind": "ObservationPage",
            "owner": observation["owner"],
            "items": items,
            "next_cursor": "next_1",
        }
        validate("ssh-response.schema.json", wire("observe", page))
        validate_cli(cli(page))
    for command in (
        "app-ops status --cursor next_1 --json",
        "app-ops resources demo-app --cursor next_1 --json",
        "app-ops workflow list --resource-kind app --resource-id demo-app --cursor next_1 --json",
        "app-ops op list --json",
    ):
        parse_command(command, "app-ops")


def test_input_staging_precedes_plan_and_operation_identity():
    value = staging()
    params = {
        "expected_owner": value["owner"],
        "staging_id": value["id"],
        "resource": value["resource"],
        "purpose": value["purpose"],
        "digest": value["digest"],
        "size": value["size"],
    }
    validate("ssh-request.schema.json", request("content.begin", params))
    validate_staging(value)
    validate("ssh-response.schema.json", wire("content.begin", value))
    with pytest.raises(ContractError):
        validate("ssh-request.schema.json", request("content.begin", {**params, "operation_id": V}))
    with pytest.raises(ContractError):
        check_input(value)
    value = committed()
    check_input(value)
    validate("ssh-response.schema.json", wire("content.commit", value))
    validate("ssh-response.schema.json", wire("content.status", value))
    assert value["handle"]["binding"] == {"kind": "staging", "staging_id": U}


def test_committed_inputs_reject_epoch_principal_resource_and_purpose_substitution():
    value = committed()
    for context in (
        {"principal": "another-principal"},
        {"expected_owner": {**operation()["owner"], "epoch": V}},
        {"resource": {"kind": "app", "id": "another-app"}},
        {"purpose": "secret-candidate"},
    ):
        with pytest.raises(ContractError):
            check_input(value, **context)
    changed = copy.deepcopy(value)
    changed["handle"]["digest"] = D
    with pytest.raises(ContractError):
        validate_staging(changed)
    changed = copy.deepcopy(value)
    changed["offset"] -= 1
    with pytest.raises(ContractError):
        validate_staging(changed)


def test_input_expiry_blocks_new_plans_without_releasing_accepted_custody():
    value = committed()
    value["accepted_references"] = 1
    validate_staging(value)
    with pytest.raises(ContractError):
        check_input(value, now="2026-10-23T01:00:00Z")
    value.update(state="expired", handle=None)
    with pytest.raises(ContractError):
        validate_staging(value)
    value["accepted_references"] = 0
    validate_staging(value)
    with pytest.raises(ContractError):
        check_input(value)


def test_typed_adapter_result_checks_bytes_schema_and_exact_operation_binding():
    op, data, installed = adapter_result()
    assert validate_result_payload(op, data, installed=installed) == {"revision": 3}
    with pytest.raises(ContractError):
        validate_result_payload(op, b'{"revision":4}', installed=installed)
    for replacement in (
        {"kind": "operation", "operation_id": U},
        {"kind": "staging", "staging_id": U},
    ):
        changed = copy.deepcopy(op)
        changed["result_handle"]["handle"]["binding"] = replacement
        seal_operation(changed)
        with pytest.raises(ContractError):
            validate_operation(changed)
    changed = copy.deepcopy(op)
    changed["result_handle"]["schema"]["digest"] = D
    seal_operation(changed)
    with pytest.raises(ContractError):
        validate_operation(changed)


def test_valid_content_digest_cannot_substitute_a_different_result_shape():
    op, _, installed = adapter_result()
    data = canonical({"revision": 3, "undeclared": True})
    op["result_handle"]["handle"].update(
        size=len(data), digest="sha256:" + hashlib.sha256(data).hexdigest()
    )
    seal_operation(op)
    with pytest.raises(ContractError):
        validate_result_payload(op, data, installed=installed)


def test_receipt_only_action_cannot_return_an_untyped_or_adapter_payload():
    op, _, _ = adapter_result()
    op["subject"] = operation()["subject"]
    seal_operation(op)
    with pytest.raises(ContractError):
        validate_operation(op)


def test_result_schema_closure_rejects_uninstalled_nested_or_unresolved_references():
    uri = "https://synthetic.invalid/result.schema.json"
    for body in (
        {"$ref": "https://uninstalled.invalid/result.schema.json"},
        {"properties": {"child": {"$id": "https://nested.invalid/schema.json", "type": "string"}}},
        {"$ref": "#/$defs/missing"},
        {"$dynamicRef": "#dynamic"},
    ):
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": uri, **body}
        with pytest.raises(ContractError):
            schema_identity(uri, {uri: schema})
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": uri,
        "type": "object",
        "properties": {"$id": {"type": "string"}},
        "additionalProperties": False,
    }
    assert schema_identity(uri, {uri: schema})["uri"] == uri
