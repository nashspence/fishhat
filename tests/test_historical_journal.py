"""Fresh restored-owner inspection from discovery through original accepted bytes."""

from __future__ import annotations

import base64
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_contracts.handoffs import schema_identity
from fishhat_contracts.historical_journal import (
    HistoricalJournalDelivery,
    validate_historical_journal_command,
)
from fishhat_contracts.history import validate_history_result
from fishhat_contracts.record_delivery import RecordSnapshot
from fishhat_contracts.validation import (
    SCHEMAS,
    ContractError,
    canonical,
    digest,
    validate,
    validate_cli,
)
from fishhat_contracts.workflow_journal_delivery import WorkflowRecordDelivery

from tests.linear_support import assert_linear, measure
from tests.test_contracts import uid
from tests.test_owner_handoffs import cli, request, wire
from tests.test_owner_history import custody_for, envelope, query_for
from tests.test_workflow_journal_surface import signed_delivery_sample

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-history.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/cli-output.schema.json",
    ],
    "scope": "custody-scoped historical journal discovery and exact original command retrieval",
    "relationship": "candidate",
    "reason": "Synthetic independently verified restoration custody exercises all events, bounded stable continuation, current permission, original epoch/schema/bytes and integrity joins without cached client IDs. This read-only reference model does not qualify native manifest verification, storage, signatures or execution.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_live_journal_delivery_keeps_same_command_ids_in_distinct_workflows": {
        "purpose": "public-contract",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json",
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/RecordReference",
        ],
        "scope": "exact workflow identity in live journal references and accepted input custody",
        "relationship": "candidate",
        "reason": "Distinct synthetic workflows reuse a caller command UUID while retaining independent original records, commands and disclosure permission. This reference delivery check supplies no native execution or storage qualification.",
        "claims": [],
    },
    "test_complete_historical_journal_delivery_is_linear": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/historical_journal.py#" + name
            for name in (
                "validate_historical_journal_command",
                "HistoricalJournalDelivery.register",
                "HistoricalJournalDelivery.list",
                "HistoricalJournalDelivery.input",
                "HistoricalJournalDelivery.read",
                "HistoricalJournalDelivery.content",
            )
        ]
        + ["release.toml#/engineering"],
        "scope": "complete historical registration, discovery, lookup, original bytes and exact retries",
        "relationship": "scoped-witness",
        "reason": "Measured work covers sixteenfold event and original-byte axes separately. Only independently retained source fixtures are prepared outside measurement; index construction, every page/chunk and exact replay are inside. No native recovery is qualified.",
        "claims": [
            "engineering:history.journal." + name
            for name in ("command", "register", "list", "input", "read", "content")
        ],
    },
}

COMMAND_URI = "https://fishhat.invalid/contracts/workflow-journal.schema.json#/$defs/Command"


def material(index=0, *, workflow_id=None, command_id=None, evidence=1):
    """Signed structural evidence; native acceptance and restoration are assumed."""
    original, command, _, _ = signed_delivery_sample(evidence)
    original, command = deepcopy(original), deepcopy(command)
    workflow_id = workflow_id or original["workflow_id"]
    original["workflow_id"] = command["workflow_id"] = workflow_id
    original["id"] = command["id"] = command_id or uid(f"historical-command-{index}")
    vote = command["payload"]["vote"]
    vote["workflow_id"] = workflow_id
    vote.pop("signature")
    key = Ed25519PrivateKey.from_private_bytes(b"\x18" * 32)
    vote["signature"] = base64.b64encode(
        key.sign(b"fishhat/workflow-journal/v1\x00" + canonical(vote))
    ).decode()
    command_bytes = canonical(command)
    original["body"]["command_digest"] = digest(command)
    original.pop("signature")
    original["signature"] = base64.b64encode(
        key.sign(b"fishhat/workflow-journal/v1\x00" + canonical(original))
    ).decode()
    snapshot = RecordSnapshot(original, uid(f"historical-snapshot-{index}"))
    return {
        "reference": snapshot.reference,
        "record_bytes": canonical(original),
        "input_handle": {
            "owner": deepcopy(original["owner"]),
            "id": uid(f"historical-input-{index}"),
            "purpose": "workflow-input",
            "binding": {
                "kind": "workflow-journal",
                "workflow_id": workflow_id,
                "command_id": original["id"],
            },
            "digest": digest(command),
            "size": len(command_bytes),
        },
        "input_schema": schema_identity(COMMAND_URI),
        "input_bytes": command_bytes,
    }


def setup(materials, *, authorize=lambda principal, scope: True, readers=None):
    custody = custody_for({"owner": materials[0]["reference"]["owner"]})
    delivery = HistoricalJournalDelivery(custody, authorize=authorize, retained_readers=readers)
    for item in materials:
        delivery.register(**item)
    return custody, delivery


def list_query(custody, *, scope=None, cursor=None, limit=2):
    return query_for(
        custody,
        record_kind="WorkflowJournalRecord",
        resource=None if scope is None else {"kind": "workflow", "id": scope},
        active_only=False,
        cursor=cursor,
        limit=limit,
    )


def original_bytes(delivery, custody, reference, *, check_wire=False):
    query = query_for(custody, reference=reference)
    result = delivery.input(query, principal="reader")
    validate_history_result(result, expected_request=query, verified_custody=custody)
    if check_wire:
        validate("ssh-request.schema.json", request("history.input", query))
        validate("ssh-response.schema.json", wire("history.input", result))
        validate_cli(cli(result))
    received_record, received_input = bytearray(), bytearray()
    while len(received_record) < reference["size"]:
        query = query_for(custody, reference=reference, offset=len(received_record), length=1024)
        chunk = delivery.read(query, principal="reader")
        validate_history_result(chunk, expected_request=query, verified_custody=custody)
        assert delivery.read(query, principal="reader") == chunk
        received_record.extend(base64.b64decode(chunk["chunk"]["base64"]))
    while len(received_input) < result["input"]["size"]:
        query = query_for(custody, handle=result["input"], offset=len(received_input), length=1024)
        chunk = delivery.content(query, principal="reader")
        validate_history_result(chunk, expected_request=query, verified_custody=custody)
        assert delivery.content(query, principal="reader") == chunk
        received_input.extend(base64.b64decode(chunk["base64"]))
    decoded = validate_historical_journal_command(
        result,
        bytes(received_record),
        bytes(received_input),
        expected_request=result["request"],
        verified_custody=custody,
    )
    assert decoded["id"] == reference["record"]["id"]
    return bytes(received_record), bytes(received_input)


def test_fresh_restored_client_discovers_journal_and_original_commands_without_saved_ids():
    materials = [material(i, workflow_id=uid(f"historical-workflow-{i % 2}")) for i in range(5)]
    custody, delivery = setup(materials)
    epoch_query = {"custodian": custody["custodian"], "cursor": None, "limit": 128}
    epochs = envelope(
        "OwnerHistoryPage", epoch_query, items=[custody], next_cursor=None, history_complete=True
    )
    validate_history_result(epochs, expected_request=epoch_query)
    discovered_custody = epochs["items"][0]
    query, seen = list_query(discovered_custody), []
    while True:
        page = delivery.list(query, principal="reader")
        validate("ssh-request.schema.json", request("history.list", query))
        validate("ssh-response.schema.json", wire("history.list", page))
        validate_history_result(page, expected_request=query, verified_custody=discovered_custody)
        validate_cli(cli(page))
        for reference in page["items"]:
            assert reference["owner"] == discovered_custody["origin"]
            assert reference["owner"] != discovered_custody["custodian"]
            seen.append(
                (
                    reference,
                    original_bytes(delivery, discovered_custody, reference, check_wire=True),
                )
            )
        if page["next_cursor"] is None:
            break
        query = {**query, "cursor": page["next_cursor"]}
    assert seen == [
        (item["reference"], (item["record_bytes"], item["input_bytes"])) for item in materials
    ]
    scope = materials[0]["reference"]["record"]["resource"]["id"]
    scoped = delivery.list(list_query(custody, scope=scope, limit=128), principal="reader")
    assert scoped["items"] == [item["reference"] for item in materials[::2]]


def test_historical_pages_have_no_total_event_cap_and_pin_stable_high_water():
    materials = [material(i) for i in range(129)]
    custody, delivery = setup(materials)
    query = list_query(custody, limit=128)
    first = delivery.list(query, principal="reader")
    assert len(first["items"]) == 128 and first["next_cursor"] is not None
    appended = material(129)
    delivery.register(**appended)
    query = {**query, "cursor": first["next_cursor"]}
    last = delivery.list(query, principal="reader")
    assert first["items"] + last["items"] == [item["reference"] for item in materials]
    assert last["next_cursor"] is None
    assert delivery.list(query, principal="reader") == last
    fresh = delivery.list(list_query(custody, limit=128), principal="reader")
    final = delivery.list(
        list_query(custody, limit=128, cursor=fresh["next_cursor"]), principal="reader"
    )
    assert final["items"] == [materials[-1]["reference"], appended["reference"]]


def test_historical_journal_identity_includes_workflow_when_command_ids_coincide():
    materials = [
        material(index, workflow_id=uid(f"scoped-{index}"), command_id=uid("same-command"))
        for index in range(2)
    ]
    custody, delivery = setup(materials)
    page = delivery.list(list_query(custody), principal="reader")
    validate_history_result(page, expected_request=page["request"], verified_custody=custody)
    assert page["items"] == [item["reference"] for item in materials]
    for item, reference in zip(materials, page["items"], strict=True):
        assert original_bytes(delivery, custody, reference) == (
            item["record_bytes"],
            item["input_bytes"],
        )


def test_live_journal_delivery_keeps_same_command_ids_in_distinct_workflows():
    scopes = [uid(f"live-scoped-{index}") for index in range(2)]
    materials = [
        material(index, workflow_id=scope, command_id=uid("same-live-command"))
        for index, scope in enumerate(scopes)
    ]
    permitted = set(scopes)
    owner = materials[0]["reference"]["owner"]
    delivery = WorkflowRecordDelivery(
        owner, authorize_read=lambda principal, scope: scope in permitted
    )
    references = [
        delivery.retain(item["record_bytes"], command_bytes=item["input_bytes"])
        for item in materials
    ]
    handles = []
    for item, reference, scope in zip(materials, references, scopes, strict=True):
        lookup = {"owner": owner, "workflow_id": scope, "record_id": uid("same-live-command")}
        assert delivery.get(lookup, principal="reader") == reference
        events = delivery.events(
            {"owner": owner, "workflow_id": scope, "cursor": None}, principal="reader"
        )
        assert events["items"] == [reference]
        accepted = delivery.input(lookup, principal="reader")
        assert accepted["acceptance"] == reference
        handles.append(accepted["input"])
        content = delivery.read_input(
            accepted["input"], principal="reader", offset=0, length=196608
        )
        assert base64.b64decode(content["base64"]) == item["input_bytes"]
        record = delivery.read(reference, principal="reader", offset=0, length=196608)
        assert base64.b64decode(record["base64"]) == item["record_bytes"]
    assert handles[0]["id"] != handles[1]["id"]
    heads = delivery.heads({"owner": owner, "cursor": None}, principal="reader")
    assert heads["items"] == references
    validate_cli(cli(heads))
    changed = deepcopy(handles[0])
    changed["binding"]["workflow_id"] = scopes[1]
    with pytest.raises(ContractError, match="handle changed"):
        delivery.read_input(changed, principal="reader", offset=0, length=128)
    changed_reference = deepcopy(references[0])
    changed_reference["record"]["resource"]["id"] = scopes[1]
    with pytest.raises(ContractError):
        delivery.read(changed_reference, principal="reader", offset=0, length=128)
    permitted.remove(scopes[1])
    with pytest.raises(ContractError, match="denied"):
        delivery.read_input(handles[1], principal="reader", offset=0, length=128)
    readable = delivery.read_input(handles[0], principal="reader", offset=0, length=128)
    assert readable["next_offset"] == 128


def test_original_command_schema_survives_live_lookup_and_historical_registration(monkeypatch):
    item = material()
    owner = item["reference"]["owner"]
    live = WorkflowRecordDelivery(owner, authorize_read=lambda principal, scope: True)
    reference = live.retain(item["record_bytes"], command_bytes=item["input_bytes"])
    lookup = {
        "owner": owner,
        "workflow_id": reference["record"]["resource"]["id"],
        "record_id": reference["record"]["id"],
    }
    original = live.input(lookup, principal="reader")
    assert original["input_schema"] == schema_identity(COMMAND_URI)
    incomplete = deepcopy(original)
    incomplete.pop("input_schema")
    with pytest.raises(ContractError):
        validate("workflow-journal.schema.json", incomplete, "AcceptedInput")
    monkeypatch.setitem(SCHEMAS["common.schema.json"], "description", "New installed closure")
    retained = live.input(lookup, principal="reader")
    assert retained == original
    assert retained["input_schema"] != schema_identity(COMMAND_URI)
    readers = {
        (reference["schema"]["uri"], reference["schema"]["digest"]): lambda value: validate(
            "workflow-journal.schema.json", value, "JournalRecord"
        ),
        (original["input_schema"]["uri"], original["input_schema"]["digest"]): lambda value: (
            validate("workflow-journal.schema.json", value, "Command")
        ),
    }
    validate_cli(cli(retained), retained_readers=readers)
    restored = {
        **item,
        "reference": reference,
        "input_handle": retained["input"],
        "input_schema": retained["input_schema"],
    }
    custody, historical = setup([restored], readers=readers)
    result = historical.input(query_for(custody, reference=reference), principal="reader")
    assert result["input_schema"] == original["input_schema"]
    assert result["input"] == original["input"]
    validate_history_result(
        result,
        expected_request=result["request"],
        verified_custody=custody,
        retained_readers=readers,
    )


def test_journal_history_requires_complete_events_and_exact_workflow_scope():
    custody, delivery = setup([material()])
    query = list_query(custody)
    with pytest.raises(ContractError):
        delivery.list({**query, "active_only": True}, principal="reader")
    with pytest.raises(ContractError):
        delivery.list({**query, "resource": {"kind": "host", "id": "node-a"}}, principal="reader")


def test_empty_filtered_window_continues_and_every_chunk_rechecks_current_permission():
    denied, allowed = uid("denied-workflow"), uid("allowed-workflow")
    permitted = {allowed}
    materials = [material(i, workflow_id=denied if i < 2 else allowed) for i in range(3)]
    custody, delivery = setup(
        materials, authorize=lambda principal, scope: scope is None or scope in permitted
    )
    first = delivery.list(list_query(custody), principal="reader")
    assert first["items"] == [] and first["next_cursor"] is not None
    query = list_query(custody, cursor=first["next_cursor"])
    last = delivery.list(query, principal="reader")
    assert last["items"] == [materials[-1]["reference"]]
    lookup = query_for(custody, reference=last["items"][0])
    result = delivery.input(lookup, principal="reader")
    permitted.clear()
    assert delivery.list(query, principal="reader")["items"] == []
    with pytest.raises(ContractError, match="permission"):
        delivery.input(lookup, principal="reader")
    with pytest.raises(ContractError, match="permission"):
        delivery.read({**lookup, "offset": 0, "length": 128}, principal="reader")
    with pytest.raises(ContractError, match="permission"):
        delivery.content(
            query_for(custody, handle=result["input"], offset=0, length=128), principal="reader"
        )


@pytest.mark.parametrize(
    "change", ["principal", "scope", "limit", "custody", "current-epoch", "restart"]
)
def test_historical_cursor_cannot_rebind_scope_or_survive_a_different_receiver(change):
    materials = [material(i) for i in range(3)]
    custody, delivery = setup(materials)
    first = delivery.list(list_query(custody), principal="reader")
    query = list_query(custody, cursor=first["next_cursor"])
    principal = "reader"
    if change == "principal":
        principal = "different-principal"
    elif change == "scope":
        query["resource"] = deepcopy(materials[0]["reference"]["record"]["resource"])
    elif change == "limit":
        query["limit"] = 1
    elif change == "custody":
        query["custody_id"] = uid("another-custody")
    elif change == "current-epoch":
        query["custodian"] = custody["origin"]
    else:
        _, delivery = setup(materials)
    with pytest.raises(ContractError):
        delivery.list(query, principal=principal)
    assert delivery.list(list_query(custody), principal="reader")["items"] == first["items"]


@pytest.mark.parametrize(
    "change",
    ["origin", "reference", "workflow", "handle", "schema", "digest", "truncated", "noncanonical"],
)
def test_historical_input_rejects_substitution_and_never_rebinds_original_bytes(change):
    item = material()
    custody, delivery = setup([item])
    query = query_for(custody, reference=item["reference"])
    result = delivery.input(query, principal="reader")
    data = item["input_bytes"]
    if change == "origin":
        result["input"]["owner"] = custody["custodian"]
    elif change == "reference":
        result["request"]["reference"]["snapshot_id"] = uid("different-snapshot")
    elif change == "workflow":
        result["input"]["binding"]["workflow_id"] = uid("different-workflow")
    elif change == "handle":
        result["input"]["id"] = uid("different-handle")
        with pytest.raises(ContractError, match="outside verified custody"):
            delivery.content(
                query_for(custody, handle=result["input"], offset=0, length=128), principal="reader"
            )
        return
    elif change == "schema":
        result["input_schema"]["digest"] = "sha256:" + "0" * 64
    elif change == "digest":
        result["input"]["digest"] = "sha256:" + "0" * 64
    elif change == "truncated":
        data = data[:-1]
    else:
        data += b" "
    with pytest.raises(ContractError):
        validate_historical_journal_command(
            result, item["record_bytes"], data, expected_request=query, verified_custody=custody
        )


def test_historical_command_reader_is_independent_and_preserves_original_schema(monkeypatch):
    item = material()
    old_record = item["reference"]["schema"]
    old_input = item["input_schema"]
    monkeypatch.setitem(SCHEMAS["common.schema.json"], "description", "New installed closure")
    calls = []

    def record_reader(value):
        calls.append("record")
        validate("workflow-journal.schema.json", value, "JournalRecord")

    def input_reader(value):
        calls.append("input")
        validate("workflow-journal.schema.json", value, "Command")

    readers = {
        (old_record["uri"], old_record["digest"]): record_reader,
        (old_input["uri"], old_input["digest"]): input_reader,
    }
    with pytest.raises(ContractError, match="schema substitution"):
        setup([item])
    with pytest.raises(ContractError, match="input reader"):
        setup([item], readers={(old_record["uri"], old_record["digest"]): record_reader})
    custody, delivery = setup([item], readers=readers)
    reference = delivery.list(list_query(custody), principal="reader")["items"][0]
    result = delivery.input(query_for(custody, reference=reference), principal="reader")
    assert result["input_schema"] == old_input != schema_identity(COMMAND_URI)
    assert reference == item["reference"]
    decoded = validate_historical_journal_command(
        result,
        item["record_bytes"],
        item["input_bytes"],
        expected_request=result["request"],
        verified_custody=custody,
        retained_readers=readers,
    )
    assert canonical(decoded) == item["input_bytes"]
    assert "record" in calls and "input" in calls
    validate_cli(cli(result), retained_readers=readers)


def complete_delivery(materials):
    permitted = [True]
    custody, delivery = setup(
        materials, authorize=lambda principal, scope: scope is None or permitted[0]
    )
    for item in materials:
        delivery.register(**item)
    seen, query = [], list_query(custody)
    while True:
        page = delivery.list(query, principal="reader")
        validate_history_result(page, expected_request=query, verified_custody=custody)
        assert delivery.list(query, principal="reader")["items"] == page["items"]
        for reference in page["items"]:
            seen.append(original_bytes(delivery, custody, reference))
        if page["next_cursor"] is None:
            break
        query = {**query, "cursor": page["next_cursor"]}
    assert seen == [(item["record_bytes"], item["input_bytes"]) for item in materials]
    permitted[0] = False
    query, denied_pages = list_query(custody), 0
    while True:
        page = delivery.list(query, principal="reader")
        assert page["items"] == []
        denied_pages += 1
        if page["next_cursor"] is None:
            break
        query = {**query, "cursor": page["next_cursor"]}
    assert denied_pages == (len(materials) + 1) // 2
    return len(seen)


def test_complete_historical_journal_delivery_is_linear():
    for axis in ("events", "original-bytes"):
        samples = []
        for extent in (2, 8, 32):
            materials = (
                [material(index) for index in range(extent)]
                if axis == "events"
                else [material(evidence=extent)]
            )
            count, work = measure(lambda selected=materials: complete_delivery(selected))
            assert count == len(materials)
            samples.append((extent, work))
        assert_linear(samples)
