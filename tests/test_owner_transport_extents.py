"""Complete owner selections and read payloads across actual frame boundaries."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json

import pytest
from fishhat_client.wire import frame, read_frame
from fishhat_contracts.handoffs import validate_cli_result
from fishhat_contracts.planning import decode_plan_input, validate_plan_input_custody
from fishhat_contracts.record_delivery import RecordSnapshot, validate_record_payload
from fishhat_contracts.validation import MAX_BYTES, ContractError, canonical, digest, validate
from fishhat_owner.commands import parse_command

from tests.test_owner_handoffs import FIXTURES, NOW, U, V, committed, operation, request, wire
from tests.test_record_delivery import complete_record

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/plan-input.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/RecordReference",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
    ],
    "scope": "complete exact Plan inputs and immutable discovery/resource observation transfer",
    "relationship": "candidate",
    "reason": "Actual encoded requests and replies cross the frame limit without selection loss; substitution, incomplete bytes, custody and retained-reader checks use synthetic owner context, not native persistence or authentication.",
    "claims": [],
}


def plan_input(count=1):
    payload = {
        "format": "deployment-ops/plan-input/v1",
        "owner": operation()["owner"],
        "subject": {
            "action": "app.cleanup",
            "resource": {"kind": "app", "id": "demo-app"},
            "arguments": {
                "account": "app-demo-app",
                "inventory_digest": "sha256:" + "a" * 64,
                "candidates": ["sha256:" + f"{index:064x}" for index in range(count)],
            },
        },
    }
    data = canonical(payload)
    staging = committed()
    staging.update(purpose="plan-input", digest=digest(payload), size=len(data), offset=len(data))
    staging["handle"].update(purpose="plan-input", digest=digest(payload), size=len(data))
    reference = {"owner": copy.deepcopy(payload["owner"]), "input": staging["handle"]}
    return payload, data, staging, reference


def check_custody(payload, staging, reference, **changes):
    context = {
        "expected_owner": operation()["owner"],
        "principal": "ops-app-operate",
        "now": NOW,
    }
    context.update(changes)
    validate_plan_input_custody(reference, payload, staging, **context)


def test_large_exact_cleanup_selection_uses_one_staged_plan_input():
    payload, data, staging, reference = plan_input(15000)
    assert len(data) > MAX_BYTES
    envelope = request("plan.prepare", reference)
    validate("ssh-request.schema.json", envelope)
    assert read_frame(io.BytesIO(frame(envelope))) == envelope
    # A resumed upload retains one immutable staging identity and exact offset.
    chunks = []
    for offset in range(0, len(data), 196608):
        part = data[offset : offset + 196608]
        upload = request(
            "content.chunk",
            {
                "owner": payload["owner"],
                "staging_id": staging["id"],
                "offset": offset,
                "base64": base64.b64encode(part).decode("ascii"),
            },
        )
        validate("ssh-request.schema.json", upload)
        received = read_frame(io.BytesIO(frame(upload)))["params"]
        assert received["staging_id"] == staging["id"] and received["offset"] == offset
        chunks.append(base64.b64decode(received["base64"], validate=True))
    with pytest.raises(ContractError, match="content identity"):
        decode_plan_input(reference, b"".join(chunks[:-1]), expected_owner=payload["owner"])
    decoded = decode_plan_input(reference, b"".join(chunks), expected_owner=payload["owner"])
    assert decoded == payload
    assert len(decoded["subject"]["arguments"]["candidates"]) == 15000
    check_custody(decoded, staging, reference)
    with pytest.raises(ContractError, match="input size limit"):
        decode_plan_input(
            reference, data, expected_owner=payload["owner"], capacity_bytes=MAX_BYTES
        )
    assert (
        parse_command("app-ops plan --subject-stdin --json", "app-ops")["use_case"]
        == "plan.prepare"
    )


def test_plan_prepare_requires_committed_input_reference():
    payload, _, _, _ = plan_input()
    with pytest.raises(ContractError):
        validate(
            "ssh-request.schema.json",
            request(
                "plan.prepare", {"subject": payload["subject"], "expected_owner": payload["owner"]}
            ),
        )


@pytest.mark.parametrize("change", ["principal", "resource", "purpose", "epoch", "expired"])
def test_plan_input_requires_exact_current_custody(change):
    payload, _, staging, reference = plan_input()
    if change == "principal":
        staging["authenticated_principal"] = "other-principal"
    elif change == "resource":
        staging["resource"]["id"] = "other-app"
    elif change == "purpose":
        staging["purpose"] = staging["handle"]["purpose"] = "workflow-input"
    elif change == "epoch":
        staging["owner"]["epoch"] = V
    else:
        staging["expires_at"] = "2026-10-23T00:15:00Z"
    with pytest.raises(ContractError):
        check_custody(payload, staging, reference)


@pytest.mark.parametrize("change", ["digest", "size", "owner", "subject", "noncanonical"])
def test_plan_input_rejects_changed_bytes_and_payload(change):
    payload, data, _, reference = plan_input()
    if change == "digest":
        reference["input"]["digest"] = "sha256:" + "f" * 64
    elif change == "size":
        reference["input"]["size"] += 1
    elif change == "owner":
        reference["owner"]["epoch"] = V
    elif change == "subject":
        payload["subject"]["resource"]["id"] = "other-app"
        data = canonical(payload)
    else:
        data += b"\n"
        reference["input"].update(
            size=len(data), digest="sha256:" + hashlib.sha256(data).hexdigest()
        )
    with pytest.raises(ContractError):
        decode_plan_input(reference, data, expected_owner=operation()["owner"])


def discovery(count=1):
    from fishhat_contracts.discovery import owner_contract_schemas

    return {
        "owner": operation()["owner"],
        "wire": "deployment-ops/owner/v1",
        "contract_schemas": owner_contract_schemas(),
        "source_formats": ["deployment-ops/source/v2"],
        "actions": ["app.restart"],
        "adapters": ["sha256:" + f"{index:064x}" for index in range(count)],
    }


@pytest.mark.parametrize("method", ["discover", "resources.observe"])
def test_large_read_payload_retains_complete_typed_snapshot(method):
    if method == "discover":
        value = discovery(15000)
        kind = "Discovery"
    else:
        value = json.loads((FIXTURES / "resources/report.json").read_text())
        assert len(value["accounts"]) == 1
        value["accounts"][0]["blockers"] = [f"blocked-{i:05d}-" + "x" * 240 for i in range(4500)]
        kind = "ResourceReport"
    validate("ssh-response.schema.json", wire(method, value))
    with pytest.raises(ContractError, match="frame size"):
        frame(wire(method, value))
    snapshot = RecordSnapshot(value, U)
    reference = snapshot.delivery(max_inline_bytes=MAX_BYTES - 512)
    assert reference["record"] == {"kind": kind, "id": U, "generation": None}
    response = wire(method, reference)
    validate("ssh-response.schema.json", response)
    assert read_frame(io.BytesIO(frame(response))) == response
    validate_cli_result(reference)
    assert complete_record(snapshot) == value
    other_method = "discover" if method == "resources.observe" else "resources.observe"
    with pytest.raises(ContractError):
        validate("ssh-response.schema.json", wire(other_method, reference))


def test_observation_snapshot_never_invents_generation_or_reinterprets_a_prior_schema():
    value = discovery()
    reference = RecordSnapshot(value, U).reference
    data = canonical(value)
    reference["schema"]["digest"] = "sha256:" + "e" * 64
    readers = {
        (reference["schema"]["uri"], reference["schema"]["digest"]): lambda item: validate(
            "records.schema.json", item, "Info"
        )
    }
    with pytest.raises(ContractError, match="schema substitution"):
        validate_record_payload(reference, data, expected_owner=value["owner"])
    assert (
        validate_record_payload(
            reference, data, expected_owner=value["owner"], retained_readers=readers
        )
        == value
    )
    for field in ("schema", "id", "generation"):
        changed = copy.deepcopy(reference)
        if field == "schema":
            changed["schema"]["uri"] = changed["schema"]["uri"].replace("Info", "Operation")
        else:
            changed["record"][field] = V if field == "id" else 0
        with pytest.raises(ContractError):
            validate_record_payload(
                changed, data, expected_owner=value["owner"], retained_readers=readers
            )
