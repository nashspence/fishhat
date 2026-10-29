"""Original-epoch custody and explicit current recovery, without a native restored store."""

from __future__ import annotations

import base64
import copy
import hashlib

import pytest
from fishhat_contracts.handoffs import schema_identity
from fishhat_contracts.history import (
    authorize_history_request,
    validate_historical_recovery,
    validate_history_result,
    validate_owner_custody,
)
from fishhat_contracts.record_delivery import RecordSnapshot, validate_record_payload
from fishhat_contracts.validation import ContractError, canonical, digest, validate, validate_cli
from fishhat_owner.commands import parse_command

from tests.operation_support import seal_operation
from tests.test_contracts import plan, uid
from tests.test_owner_handoffs import NOW, cli, operation, request, wire
from tests.test_plan_review import reseal

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-history.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-transfer-history.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/app.recover",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/host.recover",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/operation.recover",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-cli.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/cli-output.schema.json",
    ],
    "scope": "current-custodian discovery, immutable historical reads and fresh recovery provenance",
    "relationship": "candidate",
    "reason": "Synthetic verified custody and authorization context exercise complete paged discovery, preserved bytes, exact read joins and explicit current-epoch recovery. No native restoration, filtering, permission check, custody durability or effect is qualified.",
    "claims": [],
}


def seal_custody(value):
    value["digest"] = digest({k: v for k, v in value.items() if k != "digest"})
    return value


def custody_for(original=None):
    original = original or operation()
    origin = copy.deepcopy(original["owner"])
    current = {**origin, "epoch": uid("restored-authority")}
    return seal_custody(
        {
            "format": "deployment-ops/owner-history/v1",
            "kind": "OwnerCustody",
            "id": uid("retained-custody"),
            "custodian": current,
            "origin": origin,
            "manifest": {
                "schema": schema_identity(
                    "https://fishhat.invalid/contracts/recovery-set.schema.json"
                ),
                "digest": digest({"synthetic-verified-manifest": "closure"}),
            },
            "created_at": NOW,
            "digest": "sha256:" + "0" * 64,
        }
    )


def envelope(kind, query, **fields):
    return {
        "format": "deployment-ops/owner-history/v1",
        "kind": kind,
        "request": copy.deepcopy(query),
        **fields,
    }


def query_for(custody, **fields):
    return {"custodian": custody["custodian"], "custody_id": custody["id"], **fields}


def authorize(method, query, custody, *, allowed=True):
    authorize_history_request(
        method,
        query,
        current_owner=custody["custodian"],
        read_authorized=allowed,
        verified_custody=None if method == "owner.history" else custody,
    )


def record_page(custody, reference, *, cursor=None):
    query = query_for(
        custody,
        record_kind=reference["record"]["kind"],
        resource=operation()["subject"]["resource"],
        active_only=True,
        cursor=cursor,
        limit=2,
    )
    return envelope(
        "HistoricalRecordPage",
        query,
        origin=custody["origin"],
        items=[reference],
        next_cursor=None,
        history_complete=True,
    )


def test_restored_transfer_records_keep_original_epoch_and_workflow_scope():
    from tests.test_workflow_transfer_history import completed_record

    original = completed_record()
    original_bytes = canonical(original)
    custody = custody_for(original)
    snapshot = RecordSnapshot(original, uid("historical-transfer-snapshot"))
    query = query_for(
        custody,
        record_kind="WorkflowTransferRecord",
        resource=original["resource"],
        active_only=False,
        cursor=None,
        limit=2,
    )
    page = envelope(
        "HistoricalRecordPage",
        query,
        origin=custody["origin"],
        items=[snapshot.reference],
        next_cursor=None,
        history_complete=True,
    )
    authorize("history.list", query, custody)
    validate("ssh-request.schema.json", request("history.list", query))
    validate("ssh-response.schema.json", wire("history.list", page))
    validate_history_result(page, expected_request=query, verified_custody=custody)
    retained = validate_record_payload(
        snapshot.reference,
        original_bytes,
        expected_owner=custody["origin"],
        expected_record=snapshot.reference["record"],
        expected_resource=original["resource"],
    )
    assert canonical(retained) == original_bytes
    assert retained["owner"] != custody["custodian"]
    assert retained["completion"] == original["completion"]
    with pytest.raises(ContractError, match="current historical read permission"):
        authorize("history.list", query, custody, allowed=False)
    page["request"]["resource"] = {"kind": "workflow", "id": uid("other-workflow")}
    with pytest.raises(ContractError, match="historical transfer workflow substitution"):
        validate_history_result(page, verified_custody=custody)


def test_historical_transfer_identity_includes_its_workflow_scope():
    from tests.test_workflow_transfer_history import completed_record

    original = completed_record()
    custody = custody_for(original)
    reference = RecordSnapshot(original, uid("first-scoped-transfer")).reference
    # A history page carries independently retained references. Complete payload
    # verification is separate; this exercises the page's logical identity key.
    other = copy.deepcopy(reference)
    other["snapshot_id"] = uid("second-scoped-transfer")
    other["record"]["resource"]["id"] = uid("second-workflow")
    other["digest"] = "sha256:" + "b" * 64
    query = query_for(
        custody,
        record_kind="WorkflowTransferRecord",
        resource=None,
        active_only=False,
        cursor=None,
        limit=2,
    )
    page = envelope(
        "HistoricalRecordPage",
        query,
        origin=custody["origin"],
        items=[reference, other],
        next_cursor=None,
        history_complete=True,
    )
    validate_history_result(page, expected_request=query, verified_custody=custody)
    other["record"]["resource"] = copy.deepcopy(reference["record"]["resource"])
    with pytest.raises(ContractError, match="duplicate historical record"):
        validate_history_result(page, expected_request=query, verified_custody=custody)


def test_fresh_client_discovers_every_retained_epoch_without_previous_owner_identity():
    custody = custody_for()
    entries = []
    for index in range(257):
        item = copy.deepcopy(custody)
        item["id"] = uid(f"custody-{index}")
        item["origin"]["epoch"] = uid(f"origin-{index}")
        entries.append(seal_custody(item))
    seen = []
    cursor = None
    for start in range(0, len(entries), 128):
        query = {"custodian": custody["custodian"], "cursor": cursor, "limit": 128}
        authorize("owner.history", query, custody)
        next_cursor = f"page_{start + 128}" if start + 128 < len(entries) else None
        page = envelope(
            "OwnerHistoryPage",
            query,
            items=entries[start : start + 128],
            next_cursor=next_cursor,
            history_complete=True,
        )
        validate("ssh-request.schema.json", request("owner.history", query))
        validate("ssh-response.schema.json", wire("owner.history", page))
        validate_history_result(page, expected_request=query)
        validate_cli(cli(page))
        seen.extend(page["items"])
        cursor = next_cursor
    assert seen == entries and cursor is None


@pytest.mark.parametrize("state", ["accepted", "cancelled", "quarantined"])
def test_original_bytes_and_unresolved_custody_survive_current_owner_reads(state):
    original = operation()
    original.update(state=state, effect_certainty="unknown", holds=[uid("unresolved")])
    seal_operation(original)
    original_bytes = canonical(original)
    custody = custody_for(original)
    snapshot = RecordSnapshot(original, uid("retained-snapshot"))
    page = record_page(custody, snapshot.reference)
    authorize("history.list", page["request"], custody)
    validate_history_result(page, expected_request=page["request"], verified_custody=custody)
    received = bytearray()
    while len(received) < snapshot.reference["size"]:
        query = query_for(custody, reference=snapshot.reference, offset=len(received), length=256)
        authorize("history.read", query, custody)
        chunk = snapshot.chunk(snapshot.reference, offset=query["offset"], length=query["length"])
        result = envelope("HistoricalRecordChunk", query, origin=custody["origin"], chunk=chunk)
        validate("ssh-response.schema.json", wire("history.read", result))
        validate_history_result(result, expected_request=query, verified_custody=custody)
        validate_cli(cli(result))
        received.extend(base64.b64decode(chunk["base64"]))
    assert bytes(received) == original_bytes
    restored = validate_record_payload(
        snapshot.reference, bytes(received), expected_owner=custody["origin"]
    )
    assert restored == original
    assert restored["owner"] != custody["custodian"]
    assert restored["holds"] == [uid("unresolved")]


@pytest.mark.parametrize("change", ["owner-id", "same-epoch", "digest", "custodian"])
def test_custody_descriptor_cannot_substitute_identity(change):
    value = custody_for()
    expected = copy.deepcopy(value["custodian"])
    if change == "owner-id":
        value["origin"]["id"] = uid("other-owner")
    elif change == "same-epoch":
        value["origin"]["epoch"] = value["custodian"]["epoch"]
    elif change == "custodian":
        value["custodian"]["epoch"] = uid("another-current-epoch")
    else:
        value["manifest"]["digest"] = "sha256:" + "b" * 64
    if change != "digest":
        seal_custody(value)
    with pytest.raises(ContractError):
        validate_owner_custody(value, expected_custodian=expected)


@pytest.mark.parametrize(
    "change", ["permission", "custody", "current-epoch", "origin", "write-route"]
)
def test_known_historical_reference_never_supplies_current_read_or_write_authority(change):
    custody = custody_for()
    reference = RecordSnapshot(operation(), uid("snapshot")).reference
    query = query_for(custody, reference=reference, offset=0, length=128)
    if change == "custody":
        query["custody_id"] = uid("unverified-custody")
    elif change == "current-epoch":
        query["custodian"] = custody["origin"]
    elif change == "origin":
        query["reference"]["owner"] = custody["custodian"]
    method = "operation.submit" if change == "write-route" else "history.read"
    with pytest.raises(ContractError):
        authorize(method, query, custody, allowed=change != "permission")


@pytest.mark.parametrize("change", ["origin", "custody", "filter", "duplicate", "limit", "cursor"])
def test_history_pages_preserve_exact_query_origin_and_complete_continuation(change):
    custody = custody_for()
    page = record_page(
        custody, RecordSnapshot(operation(), uid("snapshot")).reference, cursor="page_1"
    )
    expected = copy.deepcopy(page["request"])
    if change == "origin":
        page["origin"]["epoch"] = uid("different-origin")
    elif change == "custody":
        page["request"]["custody_id"] = uid("different-custody")
    elif change == "filter":
        page["request"]["active_only"] = False
    elif change == "duplicate":
        page["items"].append(copy.deepcopy(page["items"][0]))
    elif change == "limit":
        page["request"]["limit"] = 1
        expected["limit"] = 1
        another = copy.deepcopy(page["items"][0])
        another["record"]["id"] = uid("another-record")
        another["snapshot_id"] = uid("another-snapshot")
        page["items"].append(another)
    else:
        page["next_cursor"] = "page_1"
    with pytest.raises(ContractError):
        validate_history_result(page, expected_request=expected, verified_custody=custody)


def test_missing_history_is_explicit_even_for_an_empty_authorized_page():
    custody = custody_for()
    page = record_page(custody, RecordSnapshot(operation(), uid("snapshot")).reference)
    page.update(items=[], history_complete=False)
    validate_history_result(page, expected_request=page["request"], verified_custody=custody)
    validate_cli(cli(page))
    assert page["next_cursor"] is None and page["history_complete"] is False


def test_history_listing_does_not_present_two_generations_as_independent_operations():
    custody = custody_for()
    reference = RecordSnapshot(operation(), uid("snapshot")).reference
    page = record_page(custody, reference)
    previous = copy.deepcopy(reference)
    previous["record"]["generation"] += 1
    previous["snapshot_id"] = uid("later-snapshot")
    page["items"].append(previous)
    with pytest.raises(ContractError, match="duplicate historical record"):
        validate_history_result(page, expected_request=page["request"], verified_custody=custody)


def test_historical_schema_reader_is_installed_independently_and_remains_read_only():
    custody = custody_for()
    reference = RecordSnapshot(operation(), uid("snapshot")).reference
    reference["schema"]["digest"] = "sha256:" + "b" * 64
    page = record_page(custody, reference)
    with pytest.raises(ContractError, match="schema substitution"):
        validate_history_result(page)
    readers = {reference["schema"]["digest"]: lambda value: None}
    validate_history_result(
        page, expected_request=page["request"], verified_custody=custody, retained_readers=readers
    )
    validate_cli(cli(page), retained_readers=readers)
    forged = cli(page)
    forged["state"] = "succeeded"
    with pytest.raises(ContractError):
        validate_cli(forged, retained_readers=readers)


def content_result():
    custody = custody_for()
    data = b"synthetic retained bytes"
    handle = {
        "id": uid("retained-content"),
        "owner": custody["origin"],
        "purpose": "content",
        "binding": {"kind": "staging", "staging_id": uid("retained-stage")},
        "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }
    query = query_for(custody, handle=handle, offset=0, length=128)
    result = envelope(
        "HistoricalContentChunk",
        query,
        origin=custody["origin"],
        base64=base64.b64encode(data).decode(),
        next_offset=len(data),
        complete=True,
    )
    return custody, query, result


def test_retained_input_content_uses_current_permission_and_original_handle_identity():
    custody, query, result = content_result()
    authorize("history.content", query, custody)
    validate("ssh-request.schema.json", request("history.content", query))
    validate("ssh-response.schema.json", wire("history.content", result))
    validate_history_result(result, expected_request=query, verified_custody=custody)
    validate_cli(cli(result))
    with pytest.raises(ContractError, match="permission"):
        authorize("history.content", query, custody, allowed=False)


@pytest.mark.parametrize("change", ["handle", "range", "completion", "no-progress"])
def test_historical_content_rejects_substitution_and_incomplete_ranges(change):
    custody, query, result = content_result()
    if change == "handle":
        result["request"]["handle"]["id"] = uid("another-handle")
    elif change == "range":
        result["next_offset"] += 1
    elif change == "completion":
        result["complete"] = False
    else:
        result.update(base64="", next_offset=0, complete=False)
    with pytest.raises(ContractError):
        validate_history_result(result, expected_request=query, verified_custody=custody)


def recovery_plan():
    original = operation()
    custody = custody_for(original)
    reference = RecordSnapshot(original, uid("recovery-snapshot")).reference
    value = plan()
    value["id"] = uid("fresh-recovery-plan")
    value["owner"] = copy.deepcopy(custody["custodian"])
    value["subject"] = {
        "action": "app.recover",
        "resource": original["subject"]["resource"],
        "arguments": {
            "operation_id": original["id"],
            "disposition": "native-reconcile",
            "checkpoint": None,
            "origin": {"custody_id": custody["id"], "reference": reference},
        },
    }
    value["input_digests"] = [reference["digest"]]
    value["preconditions"][0].update(owner=value["owner"], generation=12)
    value["effects"][0].update(executor=value["owner"], input_digest=reference["digest"])
    value["witness"]["owner"] = copy.deepcopy(value["owner"])
    reseal(value)
    return custody, original, value


def recover(custody, original, reviewed, **overrides):
    context = {
        "current_owner": custody["custodian"],
        "current_generation": 12,
        "verified_custody": custody,
        "verified_reference": reviewed["subject"]["arguments"]["origin"]["reference"],
        "recovery_authorized": True,
    }
    context.update(overrides)
    return validate_historical_recovery(reviewed, canonical(original), **context)


@pytest.mark.parametrize("action", ["app.recover", "operation.recover"])
def test_historical_recovery_is_a_new_current_plan_with_exact_original_material(action):
    custody, original, reviewed = recovery_plan()
    if action == "operation.recover":
        reviewed["subject"]["action"] = action
        del reviewed["subject"]["arguments"]["checkpoint"]
        reseal(reviewed)
    untouched = copy.deepcopy(original)
    assert recover(custody, original, reviewed) == untouched
    assert original == untouched
    assert reviewed["owner"] != original["owner"]
    assert (
        reviewed["subject"]["arguments"]["origin"]["reference"]["digest"]
        in reviewed["input_digests"]
    )


@pytest.mark.parametrize("change", ["unverified-member", "later-confirmed-work"])
def test_recovery_cannot_select_its_own_snapshot_or_forget_later_outcomes(change):
    custody, original, reviewed = recovery_plan()
    authoritative = copy.deepcopy(original)
    if change == "unverified-member":
        authoritative["id"] = uid("verified-operation")
    else:
        authoritative["generation"] += 1
        authoritative["holds"].append(uid("later-accepted-hold"))
    seal_operation(authoritative)
    verified = RecordSnapshot(authoritative, uid("authoritative-snapshot")).reference
    with pytest.raises(ContractError, match="authoritative record changed"):
        recover(custody, original, reviewed, verified_reference=verified)


@pytest.mark.parametrize(
    "change",
    [
        "permission",
        "generation",
        "current-epoch",
        "operation",
        "resource",
        "custody",
        "material",
        "bytes",
    ],
)
def test_historical_reads_cannot_bypass_new_recovery_admission(change):
    custody, original, reviewed = recovery_plan()
    context = {}
    if change == "permission":
        context["recovery_authorized"] = False
    elif change == "generation":
        context["current_generation"] = 13
    elif change == "current-epoch":
        context["current_owner"] = original["owner"]
    elif change == "operation":
        reviewed["subject"]["arguments"]["operation_id"] = uid("another-operation")
    elif change == "resource":
        reviewed["subject"]["resource"] = {"kind": "app", "id": "another-app"}
        reviewed["preconditions"][0]["resource"] = reviewed["subject"]["resource"]
        reviewed["effects"][0]["resource"] = reviewed["subject"]["resource"]
    elif change == "custody":
        reviewed["subject"]["arguments"]["origin"]["custody_id"] = uid("another-custody")
    elif change == "material":
        reviewed["input_digests"] = [digest("different-content")]
        reviewed["effects"][0]["input_digest"] = reviewed["input_digests"][0]
    else:
        original["holds"].append(uid("unverified-hold"))
    reseal(reviewed)
    with pytest.raises(ContractError):
        recover(custody, original, reviewed, **context)


@pytest.mark.parametrize(
    "method", ["owner.history", "history.list", "history.read", "history.content", "workflow.bind"]
)
def test_direct_owner_history_and_binding_commands_use_closed_stdin(method):
    command = "app-ops " + method.replace(".", " ") + " --request-stdin --json"
    assert parse_command(command, "app-ops")["use_case"] == method
    with pytest.raises(ContractError):
        parse_command(command + " --execute", "app-ops")
