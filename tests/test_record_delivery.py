"""Bounded record transport and independent read context, without a native owner store."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_client.wire import frame, read_frame
from fishhat_contracts.handoffs import validate_cli_result, validate_workflow
from fishhat_contracts.record_delivery import (
    CHUNK_BYTES,
    RecordSnapshot,
    validate_log_page,
    validate_record_chunk,
    validate_record_payload,
    validate_record_reference,
)
from fishhat_contracts.validation import (
    MAX_BYTES,
    ContractError,
    canonical,
    digest,
    validate,
    validate_cli,
    validate_plan,
)
from fishhat_contracts.witness import sign, verify
from fishhat_owner.commands import parse_command

from tests.test_contracts import uid
from tests.test_owner_handoffs import (
    FIXTURES,
    NOW,
    U,
    V,
    cli,
    operation,
    rebind_workflow_proposal,
    request,
    wire,
    work_page,
)
from tests.test_owner_handoffs import workflow as workflow_record
from tests.workflow_evidence_support import advance_request, advance_with_evidence

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/RecordReference",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/RecordChunk",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-methods.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/cli-output.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-cli.json",
    ],
    "scope": "complete large-record retrieval and owner-epoch-bound log replies",
    "relationship": "candidate",
    "reason": "Synthetic records cross the real frame limit, roundtrip every byte, and reject substituted identity or range; empty log replies retain independent query context. No native custody, transport service or authorization is implemented.",
    "claims": [],
}


def expanded_workflow(*, witnesses):
    value = workflow_record()
    first = value["participants"][0]
    key = Ed25519PrivateKey.generate()
    value["participants"] = []
    for index in range(64):
        participant = copy.deepcopy(first)
        participant["resource"]["id"] = f"app-{index}"
        participant["request_ids"] = [uid(f"participant-request-{index}")]
        if witnesses:
            body = {k: v for k, v in operation()["witness"].items() if k != "signature"}
            body["workflow_id"] = value["id"]
            body["owner"] = copy.deepcopy(participant["owner"])
            body["id"] = uid(f"participant-witness-{index}")
            body["evidence_digests"] = ["sha256:" + f"{number:064x}" for number in range(256)]
            participant["last_witness"] = sign(body, key)
        value["participants"].append(participant)
    rebind_workflow_proposal(value)
    if witnesses:
        value = advance_with_evidence(advance_request(value, "draining"), value)
    return value


def complete_record(snapshot):
    reference = snapshot.reference
    offset = 0
    pieces = []
    while offset < reference["size"]:
        query = {"reference": reference, "offset": offset, "length": CHUNK_BYTES}
        validate("ssh-request.schema.json", request("record.read", query))
        chunk = snapshot.chunk(**query)
        response = wire("record.read", chunk)
        validate("ssh-response.schema.json", response)
        encoded = frame(response)
        assert len(encoded) <= MAX_BYTES + 4
        received = read_frame(io.BytesIO(encoded))["result"]
        pieces.append(validate_record_chunk(received, **query))
        offset = received["next_offset"]
        assert received["complete"] == (offset == reference["size"])
    return validate_record_payload(
        reference,
        b"".join(pieces),
        expected_owner=reference["owner"],
        expected_record=reference["record"],
    )


def test_pre_admission_plan_larger_than_frame_is_fully_retrievable():
    plan = json.loads((FIXTURES / "plan.json").read_text())
    original = plan["preconditions"][0]
    plan["preconditions"] = [
        {
            **copy.deepcopy(original),
            "resource": {"kind": "app", "id": "demo-app" if index == 0 else f"app-{index}"},
            "source_digests": ["sha256:" + f"{number:064x}" for number in range(256)],
        }
        for index in range(256)
    ]
    plan["digest"] = digest({k: v for k, v in plan.items() if k not in ("digest", "witness")})
    plan["witness"]["subject_digest"] = plan["digest"]
    key = Ed25519PrivateKey.generate()
    plan["witness"] = sign({k: v for k, v in plan["witness"].items() if k != "signature"}, key)
    validate_plan(plan)
    with pytest.raises(ContractError, match="frame size"):
        frame(wire("plan.prepare", plan))
    snapshot = RecordSnapshot(plan, U)
    reference = snapshot.delivery(max_inline_bytes=MAX_BYTES - 512)
    assert reference["kind"] == "RecordReference"
    assert reference["record"] == {"kind": "Plan", "id": plan["id"], "generation": None}
    assert reference["size"] > MAX_BYTES
    response = wire("plan.prepare", reference)
    validate("ssh-response.schema.json", response)
    assert read_frame(io.BytesIO(frame(response))) == response
    result = complete_record(snapshot)
    assert result == plan
    verify(result["witness"], key.public_key(), plan["owner"], plan["digest"])


def test_workflow_remains_retrievable_after_evidence_grows_past_frame():
    prepared = expanded_workflow(witnesses=False)
    validate_workflow(prepared)
    assert frame(wire("workflow.prepare", prepared))
    active = expanded_workflow(witnesses=True)
    validate_workflow(active)
    with pytest.raises(ContractError, match="frame size"):
        frame(wire("workflow.get", active))
    expected = copy.deepcopy(active)
    snapshot = RecordSnapshot(active, U)
    reference = snapshot.delivery(max_inline_bytes=MAX_BYTES - 512)
    assert reference["record"]["generation"] == 1
    validate("ssh-response.schema.json", wire("workflow.get", reference))
    active["generation"] = 2
    active["participants"][0]["last_witness"] = None
    assert complete_record(snapshot) == expected
    assert snapshot.reference == reference
    with pytest.raises(ContractError, match="identity or generation"):
        validate_record_reference(
            reference, expected_record={**reference["record"], "generation": 2}
        )


def test_record_pages_keep_large_items_and_reject_duplicates_or_wrong_kind():
    value = workflow_record()
    reference = RecordSnapshot(value, U).reference
    page = work_page("WorkflowPage", [reference])
    validate_cli_result(page)
    assert page["next_cursor"] is not None
    page["items"].append(value)
    with pytest.raises(ContractError, match="repeats retained work"):
        validate_cli_result(page)
    page["items"] = [RecordSnapshot(operation(), V).reference]
    with pytest.raises(ContractError):
        validate_cli_result(page)
    page["items"] = [copy.deepcopy(reference)]
    page["items"][0]["owner"]["epoch"] = V
    with pytest.raises(ContractError, match="another owner epoch"):
        validate_cli_result(page)


@pytest.mark.parametrize("field", ["owner", "schema", "snapshot_id", "record"])
def test_record_chunk_cannot_change_the_advertised_snapshot(field):
    snapshot = RecordSnapshot(workflow_record(), U)
    reference = snapshot.reference
    chunk = snapshot.chunk(reference, offset=0, length=32)
    if field == "owner":
        chunk["reference"][field]["epoch"] = V
    elif field == "schema":
        chunk["reference"][field]["digest"] = "sha256:" + "0" * 64
    elif field == "record":
        chunk["reference"][field]["generation"] += 1
    else:
        chunk["reference"][field] = V
    with pytest.raises(ContractError, match="identity or offset"):
        validate_record_chunk(chunk, reference, offset=0, length=32)
    with pytest.raises(ContractError, match="reference changed"):
        snapshot.chunk(chunk["reference"], offset=0, length=32)


@pytest.mark.parametrize(
    "case", ["offset", "next", "early-complete", "no-progress", "encoding", "length"]
)
def test_record_chunks_reject_gaps_false_completion_and_invalid_bytes(case):
    snapshot = RecordSnapshot(workflow_record(), U)
    reference = snapshot.reference
    chunk = snapshot.chunk(reference, offset=0, length=32)
    if case == "offset":
        chunk["offset"] += 1
    elif case == "next":
        chunk["next_offset"] += 1
    elif case == "early-complete":
        chunk["complete"] = True
    elif case == "no-progress":
        chunk.update(base64="", next_offset=0)
    elif case == "encoding":
        chunk["base64"] = "A"
    else:
        chunk["base64"] = base64.b64encode(b"x" * 33).decode("ascii")
        chunk["next_offset"] = 33
    with pytest.raises(ContractError):
        validate_record_chunk(chunk, reference, offset=0, length=32)


def test_record_payload_requires_exact_digest_canonical_encoding_and_identity():
    record = workflow_record()
    reference = RecordSnapshot(record, U).reference
    data = canonical(record)
    for bad in (data[:-1], data + b" ", data.replace(b"prepared", b"draining")):
        with pytest.raises(ContractError, match="content identity"):
            validate_record_payload(reference, bad, expected_owner=record["owner"])
    altered = copy.deepcopy(record)
    altered["generation"] = 1
    changed = canonical(altered)
    substituted = {
        **reference,
        "size": len(changed),
        "digest": "sha256:" + hashlib.sha256(changed).hexdigest(),
    }
    with pytest.raises(ContractError, match="payload binding"):
        validate_record_payload(substituted, changed, expected_owner=record["owner"])
    noncanonical = data + b"\n"
    substituted.update(
        size=len(noncanonical), digest="sha256:" + hashlib.sha256(noncanonical).hexdigest()
    )
    with pytest.raises(ContractError, match="not canonical"):
        validate_record_payload(substituted, noncanonical, expected_owner=record["owner"])
    with pytest.raises(ContractError, match="owner epoch"):
        validate_record_payload(reference, data, expected_owner={**record["owner"], "epoch": V})
    substituted = copy.deepcopy(reference)
    substituted["schema"]["uri"] = substituted["schema"]["uri"].replace("Workflow", "Operation")
    with pytest.raises(ContractError, match="schema substitution"):
        validate_record_reference(substituted)


def test_cli_reference_and_chunk_only_report_completed_observation():
    snapshot = RecordSnapshot(workflow_record(), U)
    for result in (snapshot.reference, snapshot.chunk(snapshot.reference, offset=0, length=16)):
        envelope = cli(result)
        validate_cli(envelope)
        for state in ("planned", "accepted", "paused", "succeeded"):
            invalid = {**envelope, "state": state, "complete": state in ("planned", "succeeded")}
            with pytest.raises(ContractError):
                validate_cli(invalid)
    assert (
        parse_command("app-ops record read --request-stdin --json", "app-ops")["use_case"]
        == "record.read"
    )


def log_page():
    op = operation()
    return {
        "format": "deployment-ops/record/v1",
        "kind": "EventPage",
        "owner": op["owner"],
        "resource": op["subject"]["resource"],
        "events": [],
        "next_cursor": "opaque_epoch_bound_cursor",
        "gap": False,
    }


def test_empty_log_pages_and_requests_bind_owner_epoch_and_resource():
    page = log_page()
    context = {"expected_owner": page["owner"], "resource": page["resource"]}
    params = {"owner": page["owner"], "resource": page["resource"], "cursor": None, "limit": 16}
    validate("ssh-request.schema.json", request("logs", params))
    validate("ssh-response.schema.json", wire("logs", page))
    validate_log_page(page, **context)
    assert page["next_cursor"] is not None
    for field in ("owner", "resource"):
        changed = copy.deepcopy(page)
        changed[field]["epoch" if field == "owner" else "id"] = V
        with pytest.raises(ContractError, match="owner epoch or resource"):
            validate_log_page(changed, **context)
    old = {"resource": page["resource"], "after": 10, "limit": 16}
    with pytest.raises(ContractError):
        validate("ssh-request.schema.json", request("logs", old))
    for field in ("owner", "cursor"):
        invalid = copy.deepcopy(params)
        invalid.pop(field)
        with pytest.raises(ContractError):
            validate("ssh-request.schema.json", request("logs", invalid))
    page["next_cursor"] = 10
    with pytest.raises(ContractError):
        validate("ssh-response.schema.json", wire("logs", page))
    assert parse_command("app-ops logs --request-stdin --json", "app-ops")["use_case"] == "logs"


def test_log_event_positions_are_ordered_inside_the_pinned_traversal():
    page = log_page()
    event = {"operation_id": U, "cursor": 3, "time": NOW, "code": "ACCEPTED", "summary": "Accepted"}
    page["events"] = [event, {**event, "cursor": 8}]
    page.update(next_cursor=None, gap=True)
    context = {"expected_owner": page["owner"], "resource": page["resource"]}
    validate_log_page(page, **context)
    for positions in ([8, 3], [3, 3]):
        page["events"] = [{**event, "cursor": position} for position in positions]
        with pytest.raises(ContractError, match="strictly ordered"):
            validate_log_page(page, **context)


def test_record_chunk_work_tracks_requested_range(monkeypatch):
    class CountedBytes(bytes):
        def __new__(cls, data):
            value = super().__new__(cls, data)
            value.ranges = []
            return value

        def __getitem__(self, key):
            assert isinstance(key, slice)
            self.ranges.append((key.start, key.stop))
            return super().__getitem__(key)

    def no_serialization(_):
        raise AssertionError("a chunk reserialized the whole record")

    small = RecordSnapshot(workflow_record(), U)
    large = RecordSnapshot(expanded_workflow(witnesses=True), V)
    monkeypatch.setattr("fishhat_contracts.record_delivery.canonical", no_serialization)
    for snapshot in (small, large):
        snapshot._data = CountedBytes(snapshot._data)
        reference = snapshot.reference
        for length in (1, 32, CHUNK_BYTES):
            snapshot._data.ranges.clear()
            chunk = snapshot.chunk(reference, offset=0, length=length)
            assert snapshot._data.ranges == [(0, length)]
            assert len(base64.b64decode(chunk["base64"])) == min(length, reference["size"])
            assert chunk["complete"] == (reference["size"] <= length)
        end = snapshot.chunk(reference, offset=reference["size"], length=1)
        assert end["complete"] and end["base64"] == ""
        for length in (0, CHUNK_BYTES + 1):
            snapshot._data.ranges.clear()
            with pytest.raises(ContractError, match="chunk length"):
                snapshot.chunk(reference, offset=0, length=length)
            assert not snapshot._data.ranges
        with pytest.raises(ContractError, match="offset outside"):
            snapshot.chunk(reference, offset=reference["size"] + 1, length=1)
    assert small.reference["size"] < MAX_BYTES < large.reference["size"]


CHECK_OVERRIDES = {
    "test_record_chunk_work_tracks_requested_range": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/record_delivery.py#RecordSnapshot.chunk"
        ],
        "scope": "immutable-byte reference slicing; no native snapshot store or streaming service",
        "relationship": "scoped-witness",
        "reason": "Counted byte ranges and forbidden reserialization prove per-chunk work independent of snapshot extent; invalid ranges reject before slicing and complete large-record traversal is separately exercised.",
        "claims": ["engineering:record-delivery.chunk"],
    },
}


def test_retained_reader_requires_exact_digest_and_preserves_independent_identity():
    value = workflow_record()
    reference = RecordSnapshot(value, U).reference
    reference["schema"]["digest"] = "sha256:" + "e" * 64
    value["retained_extension"] = "read-only"
    data = canonical(value)
    reference.update(size=len(data), digest="sha256:" + hashlib.sha256(data).hexdigest())
    calls = []

    def retained_reader(record):
        assert record["retained_extension"] == "read-only"
        calls.append(record)

    context = {"expected_owner": value["owner"], "expected_record": reference["record"]}
    with pytest.raises(ContractError, match="schema substitution"):
        validate_record_payload(reference, data, **context)
    readers = {reference["schema"]["digest"]: retained_reader}
    result = validate_record_payload(reference, data, retained_readers=readers, **context)
    assert result == value and calls == [value]
    with pytest.raises(ContractError, match="owner epoch"):
        validate_record_payload(
            reference, data, retained_readers=readers, expected_owner={**value["owner"], "epoch": V}
        )
    substituted = copy.deepcopy(value)
    substituted["generation"] += 1
    changed_data = canonical(substituted)
    changed_ref = {
        **reference,
        "size": len(changed_data),
        "digest": "sha256:" + hashlib.sha256(changed_data).hexdigest(),
    }
    with pytest.raises(ContractError, match="payload binding"):
        validate_record_payload(changed_ref, changed_data, retained_readers=readers, **context)
    with pytest.raises(ContractError, match="content identity"):
        validate_record_payload(reference, data + b" ", retained_readers=readers, **context)
