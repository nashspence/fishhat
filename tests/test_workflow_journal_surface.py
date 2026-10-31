"""The live partitioned journal surface and immutable complete-byte delivery."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_client.wire import frame, read_frame
from fishhat_contracts.record_delivery import validate_record_payload
from fishhat_contracts.validation import ROOT, ContractError, canonical, digest, validate
from fishhat_contracts.workflow_journal_delivery import (
    WorkflowRecordDelivery,
    decode_journal_command,
    validate_journal_input_custody,
)
from fishhat_owner.commands import parse_command

from tests.linear_support import assert_linear, measure
from tests.test_contracts import uid
from tests.test_owner_handoffs import request, wire, workflow
from tests.test_workflow_inputs import stage

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-cli.json",
    ],
    "scope": "closed live journal surface, exact staged input custody and bounded immutable record delivery",
    "relationship": "candidate",
    "reason": "Live method and CLI hard cuts reject whole-capsule participant mutation routes. Complete-byte handoffs join exact scope, ownership and custody; no native deployment is qualified.",
    "claims": [],
}

_DELIVERY_SYMBOLS = (
    "decode_journal_command",
    "validate_journal_input_custody",
    "WorkflowRecordDelivery.retain",
    "WorkflowRecordDelivery.get",
    "WorkflowRecordDelivery.read",
    "WorkflowRecordDelivery.events",
    "WorkflowRecordDelivery.heads",
    "WorkflowRecordDelivery.input",
    "WorkflowRecordDelivery.read_input",
)
CHECK_OVERRIDES = {
    "test_complete_journal_delivery_growth": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal_delivery.py#" + name
            for name in _DELIVERY_SYMBOLS
        ]
        + ["release.toml#/engineering"],
        "scope": "complete staged command decoding, custody, immutable record indexing, all chunks and indexed retries",
        "relationship": "scoped-witness",
        "reason": "The complete delivery path is measured over sixteenfold local evidence extent, including canonical input creation, validation, reference creation, every chunk and retries; no aggregate native execution is inferred from this transport witness.",
        "claims": [
            "engineering:workflow.journal-delivery." + name
            for name in (
                "decode",
                "custody",
                "retain",
                "get",
                "read",
                "events",
                "heads",
                "input",
                "read-input",
            )
        ],
    }
}

CHECK_OVERRIDES["test_staged_command_and_record_delivery_bind_exact_owner_and_bytes"] = dict(
    CHECK_OVERRIDES["test_complete_journal_delivery_growth"]
)


def test_workflow_live_surface_uses_partitioned_journal_commands():
    methods = {
        value["name"]
        for value in json.loads((ROOT / "contracts/ssh-methods.json").read_text())["methods"]
    }
    assert {
        "workflow.journal.submit",
        "workflow.journal.get",
        "workflow.journal.list",
        "workflow.journal.events",
        "workflow.journal.input",
    } <= methods
    rejected = {
        "workflow.prepare",
        "workflow.bind",
        "workflow.advance",
        "workflow.transfer",
        "workflow.recover",
        "workflow.lifecycle",
        "workflow.transfer.get",
        "workflow.attest",
        "workflow.attestation.get",
        "workflow.attestation.check",
        "workflow.native-attest",
        "workflow.native-attestation.check",
    }
    assert not methods & rejected
    for method in rejected:
        with pytest.raises(ContractError):
            validate("ssh-request.schema.json", request(method, {}))
        with pytest.raises(ContractError):
            validate("ssh-response.schema.json", wire(method, workflow()))
    for tool in ("app-ops", "host-ops"):
        assert (
            parse_command(tool + " workflow journal submit --input-stdin --json", tool)["use_case"]
            == "workflow.journal.submit"
        )
        assert (
            parse_command(tool + " workflow journal list --json", tool)["use_case"]
            == "workflow.journal.list"
        )
        assert (
            parse_command(
                tool
                + " workflow journal show --workflow-id "
                + uid("surface-workflow")
                + " --record-id "
                + uid("surface-record")
                + " --json",
                tool,
            )["use_case"]
            == "workflow.journal.get"
        )


def test_journal_outer_routes_reject_inline_global_state_and_caller_authority():
    owner = workflow()["owner"]
    queries = {
        "workflow.journal.get": {
            "owner": owner,
            "workflow_id": uid("surface-workflow"),
            "record_id": uid("surface-record"),
        },
        "workflow.journal.list": {"owner": owner, "cursor": None},
        "workflow.journal.events": {
            "owner": owner,
            "workflow_id": uid("surface-workflow"),
            "cursor": None,
        },
        "workflow.journal.submit": {
            "owner": owner,
            "workflow_id": uid("surface-workflow"),
            "command_id": uid("surface-command"),
            "input": {
                "owner": owner,
                "id": uid("surface-input"),
                "purpose": "workflow-input",
                "binding": {"kind": "staging", "staging_id": uid("surface-staging")},
                "digest": "sha256:" + "1" * 64,
                "size": 1,
            },
        },
    }
    for method, params in queries.items():
        envelope = request(method, params)
        validate("ssh-request.schema.json", envelope)
        assert read_frame(io.BytesIO(frame(envelope))) == envelope
        for key, value in {
            "proposal": workflow()["proposal"],
            "verified": True,
            "native_authorized": True,
            "gate_key": "caller-key",
        }.items():
            changed = copy.deepcopy(envelope)
            changed["params"][key] = value
            with pytest.raises(ContractError):
                validate("ssh-request.schema.json", changed)


def delivery_original(identifier, workflow_id):
    return {"id": identifier, "workflow_id": workflow_id, "action": "decision", "payload": {}}


def signed_delivery_sample(count):
    """Structurally valid inspection evidence; this supplies no native truth."""
    owner = workflow()["owner"]
    workflow_id, round_id = uid("delivery-workflow"), uid("delivery-round")
    handles = [
        {
            "owner": owner,
            "id": uid("delivery-evidence-" + str(index)),
            "purpose": "content",
            "binding": {"kind": "staging", "staging_id": uid("delivery-stage-" + str(index))},
            "digest": digest({"evidence": index}),
            "size": index + 1,
        }
        for index in range(count)
    ]
    record = {
        "format": "fishhat.workflow-journal/v1",
        "kind": "WorkflowJournalRecord",
        "id": uid("delivery-vote"),
        "owner": owner,
        "workflow_id": workflow_id,
        "key_id": "delivery-key",
        "body": {
            "type": "vote",
            "header_digest": digest("header"),
            "projection_digest": digest("projection"),
            "round_digest": digest("round"),
            "member_generation": 1,
            "command_digest": digest(delivery_original(uid("delivery-vote"), workflow_id)),
            "reservation": {
                "protection": "durable-until-verified-release",
                "id": uid("delivery-reservation"),
                "generation": 1,
                "round_id": round_id,
                "owner": owner,
                "issued_at": "2026-11-01T00:00:00Z",
                "expires_at": "2026-11-01T01:00:00Z",
                "participants": [
                    {
                        "owner": owner,
                        "resource": {"kind": "host", "id": "node-a"},
                        "resource_generation": 1,
                        "operations": [],
                        "native_evidence": handles,
                        "expires_at": "2026-11-01T01:00:00Z",
                    }
                ],
            },
        },
    }
    key = Ed25519PrivateKey.from_private_bytes(b"\x18" * 32)
    record["signature"] = base64.b64encode(
        key.sign(b"fishhat/workflow-journal/v1\x00" + canonical(record))
    ).decode()
    command = {
        "id": uid("delivery-command"),
        "workflow_id": workflow_id,
        "action": "vote",
        "payload": {"vote": record},
    }
    data = canonical(command)
    reference = {
        "owner": owner,
        "workflow_id": workflow_id,
        "command_id": command["id"],
        "input": {
            "owner": owner,
            "id": uid("delivery-input"),
            "purpose": "workflow-input",
            "binding": {"kind": "staging", "staging_id": uid("delivery-staging")},
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "size": len(data),
        },
    }
    return record, command, reference, data


def complete_delivery(count):
    record, command, reference, data = signed_delivery_sample(count)
    owner, workflow_id = record["owner"], record["workflow_id"]
    staging = stage(reference, workflow_id, pinned=1)
    # The retained transport is exact and pinned; deadline renewal is unnecessary.
    assert decode_journal_command(reference, data, expected_owner=owner) == command
    validate_journal_input_custody(
        reference,
        command,
        staging,
        principal="reader",
        now="2026-11-01T00:00:00Z",
        retained_command=command,
    )
    allowed = [True]
    delivery = WorkflowRecordDelivery(owner, authorize_read=lambda principal, scope: allowed[0])
    retained = delivery.retain(
        canonical(record), command_bytes=canonical(delivery_original(record["id"], workflow_id))
    )
    lookup = {"owner": owner, "workflow_id": workflow_id, "record_id": record["id"]}
    for _ in range(2):
        assert delivery.get(lookup, principal="reader") == retained
    query = {"owner": owner, "workflow_id": workflow_id, "cursor": None}
    discovered = delivery.events(query, principal="reader")
    assert discovered["items"] == [retained] and discovered["next_cursor"] is None
    assert delivery.events(query, principal="reader") == discovered
    heads = delivery.heads({"owner": owner, "cursor": None}, principal="reader")
    assert heads["items"] == [retained] and heads["next_cursor"] is None
    original = delivery.input(lookup, principal="reader")
    from fishhat_contracts.handoffs import validate_cli_result

    validate("ssh-response.schema.json", wire("workflow.journal.input", original))
    validate_cli_result(original)
    chunk = delivery.read_input(original["input"], principal="reader", offset=0, length=196608)
    validate("ssh-response.schema.json", wire("content.get", chunk))
    validate_cli_result(chunk)
    restored_input = base64.b64decode(chunk["base64"], validate=True)
    assert chunk["complete"] and restored_input == canonical(
        delivery_original(record["id"], workflow_id)
    )
    assert (
        "sha256:" + hashlib.sha256(restored_input).hexdigest() == record["body"]["command_digest"]
    )
    parts, offset = [], 0
    while offset < retained["size"]:
        chunk = delivery.read(retained, principal="reader", offset=offset, length=196608)
        encoded = frame(wire("record.read", chunk))
        received = read_frame(io.BytesIO(encoded))["result"]
        parts.append(base64.b64decode(received["base64"], validate=True))
        assert delivery.read(retained, principal="reader", offset=offset, length=196608) == chunk
        offset = chunk["next_offset"]
    recovered = validate_record_payload(retained, b"".join(parts), expected_owner=owner)
    assert recovered == record
    return record, command, reference, data, delivery, retained, lookup, allowed


def test_staged_command_and_record_delivery_bind_exact_owner_and_bytes():
    record, command, reference, data, delivery, retained, lookup, allowed = complete_delivery(3500)
    assert len(data) > 1_048_576
    assert retained["record"]["generation"] is None
    assert retained["record"]["resource"] == {"kind": "workflow", "id": record["workflow_id"]}
    validate("ssh-response.schema.json", wire("workflow.journal.get", retained))
    for method in ("workflow.journal.get", "workflow.journal.submit"):
        with pytest.raises(ContractError):
            validate("ssh-response.schema.json", wire(method, record))
    with pytest.raises(ContractError):
        decode_journal_command(reference, data + b" ", expected_owner=record["owner"])
    wrong = {**record["owner"], "epoch": uid("wrong-epoch")}
    with pytest.raises(ContractError):
        decode_journal_command(reference, data, expected_owner=wrong)
    changed = copy.deepcopy(command)
    changed["verified"] = True
    with pytest.raises(ContractError):
        validate("workflow-journal.schema.json", changed, "Command")
    staging = stage(reference, command["workflow_id"], pinned=1)
    changed = {**command, "id": uid("substituted-command")}
    with pytest.raises(ContractError):
        validate_journal_input_custody(
            reference,
            changed,
            staging,
            principal="reader",
            now="2026-11-01T00:00:00Z",
            retained_command=command,
        )
    with pytest.raises(ContractError):
        delivery.retain(canonical(record), command_bytes=canonical(command))
    original = delivery.input(lookup, principal="reader")
    changed_handle = copy.deepcopy(original["input"])
    changed_handle["binding"]["workflow_id"] = uid("wrong-input-workflow")
    with pytest.raises(ContractError):
        delivery.read_input(changed_handle, principal="reader", offset=0, length=196608)
    allowed[0] = False
    with pytest.raises(ContractError):
        delivery.input(lookup, principal="reader")
    with pytest.raises(ContractError):
        delivery.read_input(original["input"], principal="reader", offset=0, length=196608)
    with pytest.raises(ContractError):
        delivery.get(lookup, principal="reader")
    with pytest.raises(ContractError):
        delivery.read(retained, principal="reader", offset=0, length=196608)


def test_complete_journal_delivery_growth():
    samples = []
    for count in (8, 32, 128):
        result, work = measure(
            lambda count=count: (complete_delivery(count), complete_discovery(count))[0]
        )
        assert len(result[0]["body"]["reservation"]["participants"][0]["native_evidence"]) == count
        samples.append((count, work))
    assert_linear(samples)


def test_journal_tag_dispatch_preserves_closed_variant_validation(monkeypatch):
    from fishhat_contracts.validation import FORMAT_CHECKER, REGISTRY, SCHEMAS
    from jsonschema import Draft202012Validator

    schema = SCHEMAS["workflow-journal.schema.json"]
    record, command, _, _ = signed_delivery_sample(1)
    for union, sample, discriminator in (
        ("Command", command, "action"),
        ("JournalRecord", record, "body"),
    ):
        # Reconstruct the exhaustive disjunction independently from every complete
        # closed variant, including duplicate gate/member command action tags.
        variants = [
            {"$ref": schema["$id"] + "#/$defs/" + name}
            for name, definition in schema["$defs"].items()
            if (
                union == "Command" and "const" in definition.get("properties", {}).get("action", {})
            )
            or (
                union == "JournalRecord"
                and definition.get("properties", {}).get("kind", {}).get("const")
                == "WorkflowJournalRecord"
            )
        ]
        oracle = Draft202012Validator(
            {"oneOf": variants}, registry=REGISTRY, format_checker=FORMAT_CHECKER
        )
        values = [sample, None, [], {}, {**sample, "unrecognized": True}]
        values.extend(
            {key: value for key, value in sample.items() if key != field} for field in sample
        )
        values.append({**sample, discriminator: None})
        values.append(
            {**sample, discriminator: "unknown" if union == "Command" else {"type": "unknown"}}
        )
        if union == "JournalRecord":
            values.append({**sample, "body": {**sample["body"], "unrecognized": True}})
        for value in values:
            expected = oracle.is_valid(value)
            try:
                validate("workflow-journal.schema.json", value, union)
            except ContractError:
                assert not expected
            else:
                assert expected

    # The rooted record identity also commits the independently installed native
    # authority rules, even though these rules are not caller-supplied wire data.
    from fishhat_contracts.handoffs import schema_identity

    uri = schema["$id"] + "#/$defs/JournalRecord"
    original_identity = schema_identity(uri)
    changed = copy.deepcopy(schema)
    changed["$defs"]["ProtocolRules"]["const"]["native_protection"] += " Changed protection rule."
    monkeypatch.setitem(SCHEMAS, "workflow-journal.schema.json", changed)
    assert schema_identity(uri) != original_identity


def complete_discovery(count):
    record, _, _, _ = signed_delivery_sample(1)
    owner = record["owner"]
    permitted = [True]
    delivery = WorkflowRecordDelivery(owner, authorize_read=lambda principal, scope: permitted[0])
    common_workflow = uid("discovery-common-workflow")
    key = Ed25519PrivateKey.from_private_bytes(b"\x18" * 32)

    def retain(index, workflow_id):
        value = copy.deepcopy(record)
        value.pop("signature")
        value["id"] = uid("discovery-event-" + str(index))
        value["workflow_id"] = workflow_id
        original = delivery_original(value["id"], workflow_id)
        value["body"]["command_digest"] = digest(original)
        value["signature"] = base64.b64encode(
            key.sign(b"fishhat/workflow-journal/v1\x00" + canonical(value))
        ).decode()
        delivery.retain(canonical(value), command_bytes=canonical(original))

    for index in range(count):
        retain(index, common_workflow)
        retain(count + index, uid("discovery-workflow-" + str(index)))

    def traverse(method, query):
        items = []
        while True:
            page = method(query, principal="reader")
            assert method(query, principal="reader") == page
            assert page["history_complete"] and len(page["items"]) <= 64
            items.extend(page["items"])
            if page["next_cursor"] is None:
                return items
            query = {**query, "cursor": page["next_cursor"]}

    heads = traverse(delivery.heads, {"owner": owner, "cursor": None})
    assert len(heads) == count + 1
    assert len({item["record"]["resource"]["id"] for item in heads}) == count + 1
    events = traverse(
        delivery.events, {"owner": owner, "workflow_id": common_workflow, "cursor": None}
    )
    assert len(events) == count
    return delivery, retain, permitted, common_workflow


def test_journal_discovery_pages_preserve_high_water_permission_and_restart():
    delivery, retain, permitted, workflow_id = complete_discovery(130)
    owner = delivery.owner
    first = delivery.events(
        {"owner": owner, "workflow_id": workflow_id, "cursor": None}, principal="reader"
    )
    query = {"owner": owner, "workflow_id": workflow_id, "cursor": first["next_cursor"]}
    second = delivery.events(query, principal="reader")
    retain(1000, workflow_id)
    assert delivery.events(query, principal="reader") == second
    final = delivery.events({**query, "cursor": second["next_cursor"]}, principal="reader")
    assert len(final["items"]) == 2 and final["next_cursor"] is None
    permitted[0] = False
    with pytest.raises(ContractError):
        delivery.events(query, principal="reader")
    denied = delivery.heads({"owner": owner, "cursor": None}, principal="reader")
    assert denied["items"] == [] and denied["next_cursor"] is not None
    restored = WorkflowRecordDelivery(owner, authorize_read=lambda principal, scope: True)
    with pytest.raises(ContractError):
        restored.heads({"owner": owner, "cursor": denied["next_cursor"]}, principal="reader")
