"""Original cancellation intent survives uncertainty without claiming cessation."""

from __future__ import annotations

import copy
import io
import json
import uuid

import pytest
from fishhat_client.wire import frame, read_frame
from fishhat_contracts.cancellation import (
    CancellationJournal,
    validate_cancellation_page,
    validate_cancellation_receipt,
)
from fishhat_contracts.handoffs import schema_identity, validate_cli_result
from fishhat_contracts.validation import ContractError, canonical, digest, validate, validate_cli
from fishhat_owner.commands import parse_command

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/cancellation.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-history.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/cli-output.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-cli.json",
    ],
    "scope": "durable cancellation intent identity, replay, terminal races and client-independent current or restored-epoch discovery",
    "relationship": "candidate",
    "reason": "Synthetic current receiver context distinguishes intent acceptance from operation outcome, preserves original attribution across serialized restart, and exercises complete bounded discovery. Independently supplied synthetic custody permits restored read-only evidence without reviving old execution or stop flags. No native store, authentication, transaction exclusion or process termination is qualified.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_restart_and_replay_preserve_original_intent": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/cancellation.py#validate_cancellation_receipt",
            "packages/fishhat-contracts/src/fishhat_contracts/cancellation.py#CancellationJournal.__init__",
            "packages/fishhat-contracts/src/fishhat_contracts/cancellation.py#CancellationJournal.cancel",
            "packages/fishhat-contracts/src/fishhat_contracts/cancellation.py#CancellationJournal.get",
            "packages/fishhat-contracts/src/fishhat_contracts/cancellation.py#CancellationJournal.page",
            "packages/fishhat-contracts/src/fishhat_contracts/cancellation.py#CancellationJournal.snapshot",
        ],
        "scope": "one original cancellation decision through validation, admission, snapshot, same-epoch reconstruction, lookup and complete single-target discovery",
        "relationship": "scoped-witness",
        "reason": "The reference journal preserves exact decision bytes and original attribution across complete serialization and reconstruction, replays without new-decision checks, returns the retained receipt through get/list, and isolates mutable caller copies. This witnesses those reference operations for one decision; complete growth is established separately and native durability, permission enforcement and stopping remain unqualified.",
        "claims": [
            "engineering:cancellation.validate",
            "engineering:cancellation.restore",
            "engineering:cancellation.admit",
            "engineering:cancellation.lookup",
            "engineering:cancellation.list",
            "engineering:cancellation.snapshot",
        ],
    }
}

OWNER = {
    "tool": "app-ops",
    "id": "33333333-3333-4333-8333-333333333333",
    "epoch": "44444444-4444-4444-8444-444444444444",
}
REQUEST_ID = "11111111-1111-4111-8111-111111111111"
OPERATION_ID = "22222222-2222-4222-8222-222222222222"
NOW = "2026-10-23T00:30:00Z"


def identity(value):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "fishhat-cancellation-test-" + str(value)))


def request(index=0):
    return {
        "owner": copy.deepcopy(OWNER),
        "request_id": REQUEST_ID,
        "cancellation_id": identity(index),
    }


def get_request(index=0):
    return {**request(index), "custodian": copy.deepcopy(OWNER), "custody_id": None}


def restored_custody():
    value = {
        "format": "deployment-ops/owner-history/v1",
        "kind": "OwnerCustody",
        "id": identity("restored-custody"),
        "custodian": {**OWNER, "epoch": identity("restored-epoch")},
        "origin": copy.deepcopy(OWNER),
        "manifest": {
            "schema": schema_identity("https://fishhat.invalid/contracts/recovery-set.schema.json"),
            "digest": digest({"synthetic-verified-manifest": "cancellation-receipts"}),
        },
        "created_at": NOW,
    }
    value["digest"] = digest(value)
    return value


def target(state="running"):
    return {
        "owner": copy.deepcopy(OWNER),
        "request_id": REQUEST_ID,
        "operation_id": OPERATION_ID,
        "resource": {"kind": "app", "id": "demo-app"},
        "generation": 7,
        "state": state,
        "effect_certainty": "known" if state == "succeeded" else "unknown",
    }


def context(**changes):
    value = {
        "principal": "ops-app-operate",
        "expected_owner": copy.deepcopy(OWNER),
        "read_authorized": True,
        "cancel_authorized": True,
        "target": target(),
        "now": NOW,
    }
    value.update(changes)
    return value


def read_context(**changes):
    value = {
        "principal": "ops-app-observe",
        "expected_owner": copy.deepcopy(OWNER),
        "read_authorized": True,
    }
    value.update(changes)
    return value


def list_request(*, cursor=None, limit=2, request_id=REQUEST_ID):
    return {
        "owner": copy.deepcopy(OWNER),
        "custodian": copy.deepcopy(OWNER),
        "custody_id": None,
        "request_id": request_id,
        "cursor": cursor,
        "limit": limit,
    }


def wire(method, value, *, response=False):
    result = {
        "format": "deployment-ops/owner/v1",
        "message_id": identity("message"),
        "method": method,
        "result" if response else "params": value,
    }
    if response:
        result["ok"] = True
    return result


def cli(value):
    return {
        "format": "deployment-ops/cli/v1",
        "ok": True,
        "state": "observed",
        "complete": True,
        "request_id": value.get("cancellation_id"),
        "location": "owner",
        "result": value,
        "problem": None,
    }


def test_restart_and_replay_preserve_original_intent():
    journal = CancellationJournal(OWNER)
    native = target()
    original_native = copy.deepcopy(native)
    original = journal.cancel(request(), **context(target=native))
    assert original["decision"] == "stop-requested"
    assert original["operation_state"] == "running"
    assert original["effect_certainty"] == "unknown"
    assert native == original_native
    assert journal.stop_requested(REQUEST_ID)
    # An ordinary restart retains accepted stop intent even if its reply was lost.
    restored = CancellationJournal(OWNER, retained=json.loads(canonical(journal.snapshot())))
    assert restored.stop_requested(REQUEST_ID)
    assert restored.get(get_request(), **read_context()) == original
    # New authorization, time, capability and target checks cannot replace replay.
    replay = restored.cancel(
        request(),
        **context(
            principal="ops-app-observe",
            cancel_authorized=False,
            target=None,
            now="unused-on-replay",
            cancellation_supported=False,
        ),
    )
    assert replay == original
    assert replay["authenticated_principal"] == "ops-app-operate"
    discovered = restored.page(list_request(), **read_context())
    assert discovered["items"] == [original] and discovered["next_cursor"] is None
    # Caller-owned copies cannot rewrite retained decisions or internal stop intent.
    replay["authenticated_principal"] = "another-principal"
    assert restored.get(get_request(), **read_context()) == original


def test_replay_conflict_and_current_read_authority_precede_new_decision_checks():
    journal = CancellationJournal(OWNER)
    original = journal.cancel(request(), **context())
    changed = {**request(), "request_id": identity("different-target")}
    with pytest.raises(ContractError, match="PERMISSION_DENIED"):
        journal.cancel(changed, **context(read_authorized=False, cancel_authorized=False))
    with pytest.raises(ContractError, match="CONFLICT"):
        journal.cancel(changed, **context(cancel_authorized=False, target=None))
    with pytest.raises(ContractError, match="PERMISSION_DENIED"):
        journal.get(get_request(), **read_context(read_authorized=False))
    with pytest.raises(ContractError, match="NOT_FOUND"):
        journal.get({**get_request(), "request_id": changed["request_id"]}, **read_context())
    assert journal.snapshot() == [original]


@pytest.mark.parametrize("state", ["accepted", "running", "waiting"])
def test_nonterminal_decision_records_intent_without_changing_execution(state):
    journal = CancellationJournal(OWNER)
    current = target(state)
    original = copy.deepcopy(current)
    receipt = journal.cancel(request(), **context(target=current))
    assert receipt["decision"] == "stop-requested"
    assert receipt["operation_state"] == state and current == original
    validate_cancellation_receipt(receipt, expected_request=request())


@pytest.mark.parametrize("state", ["succeeded", "failed", "cancelled", "quarantined"])
def test_terminal_race_retains_original_outcome_and_never_requests_new_stopping(state):
    journal = CancellationJournal(OWNER)
    current = target(state)
    receipt = journal.cancel(request(), **context(target=current, cancellation_supported=False))
    assert receipt["decision"] == "already-terminal"
    assert receipt["operation_state"] == state
    assert receipt["effect_certainty"] == current["effect_certainty"]
    assert not journal.stop_requested(REQUEST_ID)
    # A later target view never freshens or reverses the retained terminal decision.
    assert journal.cancel(request(), **context()) == receipt


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"cancel_authorized": False}, "PERMISSION_DENIED"),
        ({"read_authorized": False}, "PERMISSION_DENIED"),
        ({"target": None}, "NOT_FOUND"),
        ({"cancellation_supported": False}, "UNSUPPORTED_CAPABILITY"),
        ({"target": {**target(), "request_id": identity("other")}}, "CANCELLATION_TARGET_CHANGED"),
        ({"expected_owner": {**OWNER, "epoch": identity("restored")}}, "OWNER_EPOCH_CHANGED"),
    ],
)
def test_refusal_accepts_no_intent(changes, code):
    journal = CancellationJournal(OWNER)
    with pytest.raises(ContractError, match=code):
        journal.cancel(request(), **context(**changes))
    assert journal.snapshot() == [] and not journal.stop_requested(REQUEST_ID)


def test_prior_epoch_and_corrupt_retained_decisions_cannot_restore_authority():
    journal = CancellationJournal(OWNER)
    receipt = journal.cancel(request(), **context())
    with pytest.raises(ContractError, match="OWNER_EPOCH_CHANGED"):
        CancellationJournal({**OWNER, "epoch": identity("new-epoch")}, retained=[receipt])
    with pytest.raises(ContractError, match="CONFLICT"):
        CancellationJournal(OWNER, retained=[receipt, receipt])
    changed = copy.deepcopy(receipt)
    changed["request_id"] = identity("changed")
    with pytest.raises(ContractError, match="CANCELLATION_REQUEST_CHANGED"):
        CancellationJournal(OWNER, retained=[changed])


def test_restored_epoch_preserves_readable_original_decisions_without_reviving_stop_intent():
    original = CancellationJournal(OWNER)
    receipts = [original.cancel(request(index), **context()) for index in range(3)]
    custody = restored_custody()
    restored = CancellationJournal(
        OWNER,
        retained=json.loads(canonical(original.snapshot())),
        custodian=custody["custodian"],
        verified_custody=custody,
    )
    receiving = read_context(expected_owner=custody["custodian"], verified_custody=custody)
    selection = {"custodian": custody["custodian"], "custody_id": custody["id"]}
    assert restored.snapshot() == receipts and not restored.stop_requested(REQUEST_ID)
    query = {**get_request(), **selection}
    assert canonical(restored.get(query, **receiving)) == canonical(receipts[0])
    first = restored.page({**list_request(), **selection}, **receiving)
    last = restored.page({**list_request(cursor=first["next_cursor"]), **selection}, **receiving)
    assert first["items"] + last["items"] == receipts and last["next_cursor"] is None
    validate_cancellation_page(
        first,
        expected_owner=OWNER,
        request_id=REQUEST_ID,
        expected_custodian=custody["custodian"],
        custody_id=custody["id"],
    )
    validate("ssh-request.schema.json", wire("operation.cancellation.get", query))
    validate("ssh-response.schema.json", wire("operation.cancellation.list", first, response=True))
    validate_cli_result(first)
    validate_cli(cli(first))
    with pytest.raises(ContractError, match="OWNER_EPOCH_CHANGED"):
        restored.cancel(request(), **context(expected_owner=custody["custodian"]))


@pytest.mark.parametrize(
    "change", ["missing-proof", "custody", "origin", "custodian", "revoked", "proof-changed"]
)
def test_restored_reads_join_current_independent_custody_and_permission_every_time(change):
    original = CancellationJournal(OWNER)
    for index in range(3):
        original.cancel(request(index), **context())
    custody = restored_custody()
    restored = CancellationJournal(
        OWNER,
        retained=original.snapshot(),
        custodian=custody["custodian"],
        verified_custody=custody,
    )
    receiving = read_context(expected_owner=custody["custodian"], verified_custody=custody)
    query = {
        **list_request(),
        "custodian": custody["custodian"],
        "custody_id": custody["id"],
    }
    query["cursor"] = restored.page(query, **receiving)["next_cursor"]
    if change == "missing-proof":
        receiving["verified_custody"] = None
    elif change == "custody":
        query["custody_id"] = identity("caller-chosen-custody")
    elif change == "origin":
        query["owner"] = {**OWNER, "epoch": identity("caller-chosen-origin")}
    elif change == "custodian":
        receiving["expected_owner"] = {**OWNER, "epoch": identity("another-restoration")}
    elif change == "revoked":
        receiving["read_authorized"] = False
    else:
        changed = copy.deepcopy(custody)
        changed["manifest"]["digest"] = digest({"another": "manifest"})
        changed["digest"] = digest({k: v for k, v in changed.items() if k != "digest"})
        receiving["verified_custody"] = changed
    with pytest.raises(ContractError):
        restored.page(query, **receiving)
    lookup = {key: query[key] for key in ("owner", "custodian", "custody_id", "request_id")}
    with pytest.raises(ContractError):
        restored.get({**lookup, "cancellation_id": request()["cancellation_id"]}, **receiving)
    assert restored.snapshot() == original.snapshot() and not restored.stop_requested(REQUEST_ID)


def test_restored_journal_cannot_be_opened_by_caller_selected_origin_or_custody():
    custody = restored_custody()
    with pytest.raises(ContractError, match="CANCELLATION_CUSTODY_REQUIRED"):
        CancellationJournal(OWNER, custodian=custody["custodian"])
    with pytest.raises(ContractError, match="CANCELLATION_CUSTODY_CHANGED"):
        CancellationJournal(
            {**OWNER, "epoch": identity("unrelated-origin")},
            custodian=custody["custodian"],
            verified_custody=custody,
        )
    with pytest.raises(ContractError, match="CANCELLATION_CUSTODY_CHANGED"):
        CancellationJournal(OWNER, verified_custody=custody)


def test_discovery_is_complete_retryable_and_pinned_across_concurrent_decisions():
    journal = CancellationJournal(OWNER)
    receipts = [journal.cancel(request(index), **context()) for index in range(5)]
    query = list_request(limit=2)
    first = journal.page(query, **read_context())
    assert first["position"] == 0 and first["items"] == receipts[:2]
    later = journal.cancel(request(5), **context())
    query["cursor"] = first["next_cursor"]
    second = journal.page(query, **read_context())
    assert second == journal.page(query, **read_context())
    assert second["traversal_id"] == first["traversal_id"]
    query["cursor"] = second["next_cursor"]
    last = journal.page(query, **read_context())
    assert last["position"] == 4 and last["next_cursor"] is None
    assert first["items"] + second["items"] + last["items"] == receipts
    # A fresh authorized client needs only the original target request identity.
    fresh = journal.page(list_request(limit=128), **read_context(principal="new-reader"))
    assert fresh["items"] == [*receipts, later]
    empty = journal.page(list_request(request_id=identity("no-decisions")), **read_context())
    assert empty["items"] == [] and empty["next_cursor"] is None


@pytest.mark.parametrize(
    "change", ["principal", "request", "limit", "epoch", "permission", "expired", "restart"]
)
def test_cursor_scope_permission_and_lost_custody_fail_explicitly(change):
    journal = CancellationJournal(OWNER)
    for index in range(3):
        journal.cancel(request(index), **context())
    page = journal.page(list_request(), **read_context())
    query = list_request(cursor=page["next_cursor"])
    receiving = read_context()
    code = "CANCELLATION_TRAVERSAL_CHANGED"
    if change == "principal":
        receiving["principal"] = "another-reader"
    elif change == "request":
        query["request_id"] = identity("other-target")
    elif change == "limit":
        query["limit"] = 1
    elif change == "epoch":
        receiving["expected_owner"]["epoch"] = identity("new-epoch")
        code = "OWNER_EPOCH_CHANGED"
    elif change == "permission":
        receiving["read_authorized"] = False
        code = "PERMISSION_DENIED"
    else:
        if change == "expired":
            journal.expire_traversals()
        else:
            journal = CancellationJournal(OWNER, retained=journal.snapshot())
        code = "RETENTION_GAP"
    with pytest.raises(ContractError, match=code):
        journal.page(query, **receiving)
    assert len(journal.snapshot()) == 3 and journal.stop_requested(REQUEST_ID)


def test_closed_wire_and_cli_surface_distinguishes_decision_from_execution():
    journal = CancellationJournal(OWNER)
    receipt = journal.cancel(request(), **context())
    page = journal.page(list_request(), **read_context())
    for method, query, result in (
        ("operation.cancel", request(), receipt),
        ("operation.cancellation.get", get_request(), receipt),
        ("operation.cancellation.list", list_request(), page),
    ):
        message = wire(method, query)
        validate("ssh-request.schema.json", message)
        assert read_frame(io.BytesIO(frame(message))) == message
        reply = wire(method, result, response=True)
        validate("ssh-response.schema.json", reply)
        assert read_frame(io.BytesIO(frame(reply))) == reply
        validate_cli_result(result)
        validate_cli(cli(result))
        with pytest.raises(ContractError):
            validate_cli({**cli(result), "state": "cancelled"})
    with pytest.raises(ContractError, match="CLI/cancellation request mismatch"):
        validate_cli({**cli(receipt), "request_id": REQUEST_ID})
    with pytest.raises(ContractError, match="CLI cancellation page"):
        validate_cli({**cli(page), "request_id": receipt["cancellation_id"]})
    for name, method in (
        ("show", "operation.cancellation.get"),
        ("list", "operation.cancellation.list"),
    ):
        command = f"app-ops op cancellation {name} --request-stdin --json"
        assert parse_command(command, "app-ops")["use_case"] == method


@pytest.mark.parametrize("field", ["actor", "state", "target", "cancel_authorized"])
def test_wire_cannot_assert_receiver_authority_or_target_facts(field):
    with pytest.raises(ContractError):
        validate("ssh-request.schema.json", wire("operation.cancel", {**request(), field: True}))


@pytest.mark.parametrize("change", ["target", "decision", "duplicate", "position", "no-progress"])
def test_receipt_and_page_validation_reject_substituted_or_incomplete_evidence(change):
    journal = CancellationJournal(OWNER)
    receipt = journal.cancel(request(), **context())
    page = journal.page(list_request(), **read_context())
    if change == "target":
        page["items"][0]["request_id"] = identity("another-target")
    elif change == "decision":
        page["items"][0]["decision"] = "already-terminal"
    elif change == "duplicate":
        page["items"].append(copy.deepcopy(receipt))
    elif change == "position":
        page["position"] = 1
    else:
        page["items"] = []
        page["next_cursor"] = "not-complete"
    with pytest.raises(ContractError):
        validate_cancellation_page(page, expected_owner=OWNER, request_id=REQUEST_ID, position=0)


def test_finite_receipts_keep_maximum_pages_inside_a_frame_without_history_limit():
    journal = CancellationJournal(OWNER)
    large = target()
    large["resource"]["id"] = "\U0001f3a9" * 160
    for index in range(129):
        journal.cancel(request(index), **context(target=large))
    page = journal.page(list_request(limit=128), **read_context())
    assert len(page["items"]) == 128 and page["next_cursor"] is not None
    assert len(frame(wire("operation.cancellation.list", page, response=True))) < 1_048_576
    last = journal.page(list_request(cursor=page["next_cursor"], limit=128), **read_context())
    assert len(last["items"]) == 1 and last["next_cursor"] is None
