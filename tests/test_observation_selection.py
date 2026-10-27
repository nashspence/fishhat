"""Exact observation input transfer and complete retained bounded traversals."""

from __future__ import annotations

import base64
import copy
import io
from itertools import pairwise

import pytest
from fishhat_client.wire import frame, read_frame
from fishhat_contracts.observations import (
    ObservationTraversal,
    decode_observation_selection,
    validate_observation_selection_custody,
)
from fishhat_contracts.record_delivery import (
    validate_observation_page,
    validate_record_chunk,
    validate_record_payload,
)
from fishhat_contracts.validation import MAX_BYTES, ContractError, canonical, digest, validate
from fishhat_owner.commands import parse_command

from tests.linear_support import assert_linear, measure
from tests.test_observation_delivery import observation
from tests.test_owner_handoffs import NOW, U, V, committed, operation, request, wire

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/observation.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/ObservationPage",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-cli.json",
        "release.toml#/engineering",
    ],
    "scope": "complete observation selections, explicit inventory discovery and linear complete traversal",
    "relationship": "candidate",
    "reason": "Actual framed selection transfer exceeds one MiB; full pages and retries preserve independent expected resource order. Synthetic current receiving context exercises refusal and expiry. Measured complete runs establish reference growth, not native inventory or authorization qualification.",
    "claims": [],
}


def selected(count, *, long_ids=False, method="observe", limit=256):
    payload = {
        "format": "deployment-ops/observation-selection/v1",
        "owner": copy.deepcopy(operation()["owner"]),
        "method": method,
        "resources": [
            {"kind": "app", "id": f"app-{index:07d}" + ("x" * 145 if long_ids else "")}
            for index in range(count)
        ],
    }
    data = canonical(payload)
    staging = committed()
    staging.update(purpose="content", size=len(data), offset=len(data), digest=digest(payload))
    staging["handle"].update(purpose="content", size=len(data), digest=digest(payload))
    start = {
        "owner": payload["owner"],
        "selection": {"kind": "exact", "input": staging["handle"]},
        "limit": limit,
    }
    return start, payload, data, staging


def records(payload):
    original = observation()
    return [{**copy.deepcopy(original), "resource": copy.deepcopy(r)} for r in payload["resources"]]


def context(payload, authorize=lambda resource: True):
    return {
        "method": payload["method"],
        "principal": "ops-app-operate",
        "expected_owner": payload["owner"],
        "authorize": authorize,
    }


def custody(start, payload, staging, **changes):
    arguments = {
        "expected_owner": payload["owner"],
        "method": payload["method"],
        "principal": "ops-app-operate",
        "now": NOW,
        "staging_authorized": True,
    }
    arguments.update(changes)
    validate_observation_selection_custody(start, payload, staging, **arguments)


def traverse(start, payload, observations, *, retry=False):
    receiver = context(payload)
    traversal = ObservationTraversal(
        start,
        **receiver,
        traversal_id=U,
        records=observations,
        selected_input=payload,
        input_custody_verified=True,
    )
    assert traversal.traversal["selection_digest"] == digest(payload)
    next_request = start
    identities = []
    request_bytes = 0
    selection = {canonical(resource) for resource in payload["resources"]}
    while True:
        encoded = frame(request(payload["method"], next_request))
        request_bytes += len(encoded)
        params = read_frame(io.BytesIO(encoded))["params"]
        validate("ssh-request.schema.json", request(payload["method"], params))
        page = traversal.page(params, **receiver)
        response = wire(payload["method"], page)
        validate("ssh-response.schema.json", response)
        assert read_frame(io.BytesIO(frame(response))) == response
        validate_observation_page(
            page,
            expected_owner=payload["owner"],
            selection=selection,
            expected_traversal=traversal.traversal,
            expected_position=len(identities),
        )
        if retry:
            assert traversal.page(params, **receiver) == page
            request_bytes += len(encoded)
        identities.extend(item["resource"] for item in page["items"])
        if page["next_cursor"] is None:
            break
        next_request = {
            "owner": payload["owner"],
            "cursor": page["next_cursor"],
            "limit": start["limit"],
        }
        assert set(next_request) == {"owner", "cursor", "limit"}
        assert len(canonical(next_request)) < 256
    return identities, request_bytes


@pytest.mark.parametrize("method", ["observe", "check"])
def test_large_selection_roundtrips_once(method):
    start, payload, data, staging = selected(6000, long_ids=True, method=method)
    assert len(data) > MAX_BYTES
    begin = request(
        "content.begin",
        {
            "expected_owner": payload["owner"],
            "staging_id": staging["id"],
            "resource": staging["resource"],
            "purpose": "content",
            "digest": staging["digest"],
            "size": len(data),
        },
    )
    validate("ssh-request.schema.json", begin)
    assert read_frame(io.BytesIO(frame(begin))) == begin
    parts = []
    for offset in range(0, len(data), 196608):
        upload = request(
            "content.chunk",
            {
                "owner": payload["owner"],
                "staging_id": staging["id"],
                "offset": offset,
                "base64": base64.b64encode(data[offset : offset + 196608]).decode(),
            },
        )
        validate("ssh-request.schema.json", upload)
        received = read_frame(io.BytesIO(frame(upload)))["params"]
        assert received["offset"] == offset
        parts.append(base64.b64decode(received["base64"], validate=True))
    commit = request("content.commit", {"owner": payload["owner"], "staging_id": staging["id"]})
    validate("ssh-request.schema.json", commit)
    assert read_frame(io.BytesIO(frame(commit))) == commit
    response = wire("content.commit", staging)
    validate("ssh-response.schema.json", response)
    assert read_frame(io.BytesIO(frame(response))) == response
    with pytest.raises(ContractError, match="CONTENT_IDENTITY"):
        decode_observation_selection(
            start, b"".join(parts[:-1]), expected_owner=payload["owner"], method=method
        )
    assert (
        decode_observation_selection(
            start, b"".join(parts), expected_owner=payload["owner"], method=method
        )
        == payload
    )
    custody(start, payload, staging)
    identities, continued_bytes = traverse(start, payload, records(payload))
    assert identities == payload["resources"]
    # Complete exact input was uploaded once; no output page resends its selectors.
    assert continued_bytes < len(data) // 10


@pytest.mark.parametrize(
    "change", ["principal", "method", "owner", "expiry", "permission", "bytes", "purpose"]
)
def test_selection_refuses_changed_context_and_unverified_custody(change):
    start, payload, _, staging = selected(2)
    arguments = {}
    if change == "principal":
        arguments["principal"] = "other-reader"
    elif change == "method":
        arguments["method"] = "check"
    elif change == "owner":
        arguments["expected_owner"] = {**payload["owner"], "epoch": V}
    elif change == "expiry":
        staging["expires_at"] = "2026-10-23T00:15:00Z"
    elif change == "permission":
        arguments["staging_authorized"] = False
    elif change == "bytes":
        payload["resources"].pop()
    else:
        start["selection"]["input"]["purpose"] = "capture"
    with pytest.raises(ContractError):
        custody(start, payload, staging, **arguments)


def test_all_authorized_inventory_and_empty_exact_selections_are_explicit():
    _, payload, _, _ = selected(3)
    available = records(payload)
    all_start = {"owner": payload["owner"], "selection": {"kind": "all-authorized"}, "limit": 256}
    receiver = context(payload, lambda resource: resource != payload["resources"][1])
    traversal = ObservationTraversal(all_start, **receiver, traversal_id=U, records=available)
    available[0]["summary"] = "Later native changes do not rewrite this traversal."
    page = traversal.page(all_start, **receiver)
    assert [item["resource"] for item in page["items"]] == [
        payload["resources"][0],
        payload["resources"][2],
    ]
    assert page["traversal"]["selection_digest"] == digest(
        {**payload, "resources": [payload["resources"][0], payload["resources"][2]]}
    )
    assert page["items"][0]["summary"] != available[0]["summary"]
    with pytest.raises(ContractError, match="PERMISSION_DENIED"):
        traversal.page(all_start, **context(payload, lambda resource: False))
    for inventory in ([], available):
        denied = context(payload, lambda resource: False)
        empty = ObservationTraversal(all_start, **denied, traversal_id=V, records=inventory)
        assert empty.page(all_start, **denied)["items"] == []
        assert empty.page(all_start, **denied)["next_cursor"] is None
    empty_start, empty_payload, _, staging = selected(0)
    custody(empty_start, empty_payload, staging)
    assert traverse(empty_start, empty_payload, available)[0] == []
    for method in ("observe", "check"):
        workflow_start, workflow_payload, _, _ = selected(1, method=method)
        workflow_payload["resources"] = [{"kind": "workflow", "id": U}]
        workflow_bytes = canonical(workflow_payload)
        workflow_start["selection"]["input"].update(
            size=len(workflow_bytes), digest=digest(workflow_payload)
        )
        with pytest.raises(ContractError):
            validate("observation.schema.json", workflow_payload, "SelectionInput")
        with pytest.raises(ContractError):
            decode_observation_selection(
                workflow_start,
                workflow_bytes,
                expected_owner=workflow_payload["owner"],
                method=method,
            )
        with pytest.raises(ContractError):
            validate(
                "ssh-request.schema.json",
                request(method, {"resources": payload["resources"], "cursor": None, "limit": 256}),
            )
    for command in ("app-ops status --json", "host-ops observe --request-stdin --json"):
        assert parse_command(command, command.split()[0])["use_case"] == "observe"


@pytest.mark.parametrize(
    "change", ["principal", "method", "epoch", "cursor", "expired", "revoked", "selection"]
)
def test_continuation_cannot_restart_rebind_or_omit_revoked_resources(change):
    start, payload, _, _ = selected(3, limit=1)
    receiver = context(payload)
    traversal = ObservationTraversal(
        start,
        **receiver,
        traversal_id=U,
        records=records(payload),
        selected_input=payload,
        input_custody_verified=True,
    )
    first = traversal.page(start, **receiver)
    continuation = {"owner": payload["owner"], "cursor": first["next_cursor"], "limit": 1}
    expected = traversal.page(continuation, **receiver)
    assert traversal.page(continuation, **receiver) == expected
    if change == "principal":
        receiver["principal"] = "different-reader"
    elif change == "method":
        receiver["method"] = "check"
    elif change == "epoch":
        receiver["expected_owner"] = {**payload["owner"], "epoch": V}
    elif change == "cursor":
        continuation["cursor"] = "unminted_cursor"
    elif change == "expired":
        traversal.expire()
    elif change == "revoked":
        receiver["authorize"] = lambda resource: False
    else:
        continuation["selection"] = {"kind": "all-authorized"}
    with pytest.raises(ContractError):
        traversal.page(continuation, **receiver)


def test_exact_selection_never_silently_filters_missing_or_unauthorized_resources():
    start, payload, _, _ = selected(2)
    with pytest.raises(ContractError, match="SELECTION_CUSTODY_REQUIRED"):
        ObservationTraversal(
            start,
            **context(payload),
            traversal_id=U,
            records=records(payload),
            selected_input=payload,
        )
    for available, authorize, message in [
        (records(payload)[:1], lambda resource: True, "NOT_FOUND"),
        (records(payload), lambda resource: False, "PERMISSION_DENIED"),
    ]:
        with pytest.raises(ContractError, match=message):
            ObservationTraversal(
                start,
                **context(payload, authorize),
                traversal_id=U,
                records=available,
                selected_input=payload,
                input_custody_verified=True,
            )


def test_large_snapshot_chunks_reauthorize_original_custody():
    start, payload, _, staging = selected(1)
    custody(start, payload, staging)
    value = observation(15000)
    value["resource"] = copy.deepcopy(payload["resources"][0])
    assert len(canonical(value)) > MAX_BYTES
    receiver = context(payload)
    traversal = ObservationTraversal(
        start,
        **receiver,
        traversal_id=U,
        records=[value],
        selected_input=payload,
        input_custody_verified=True,
    )
    page = traversal.page(start, **receiver)
    reference = page["items"][0]
    assert reference["kind"] == "RecordReference"
    assert read_frame(io.BytesIO(frame(wire("observe", page))))["result"] == page
    chunk_context = {name: value for name, value in receiver.items() if name != "method"}
    parts = []
    offset = 0
    while offset < reference["size"]:
        chunk = traversal.record_chunk(reference, offset=offset, length=196608, **chunk_context)
        response = wire("record.read", chunk)
        validate("ssh-response.schema.json", response)
        received = read_frame(io.BytesIO(frame(response)))["result"]
        parts.append(validate_record_chunk(received, reference, offset=offset, length=196608))
        offset = received["next_offset"]
    assert (
        validate_record_payload(
            reference,
            b"".join(parts),
            expected_owner=payload["owner"],
            expected_resource=payload["resources"][0],
        )
        == value
    )
    samples = []
    for length in (64, 256, 1024):
        chunk, work = measure(
            lambda length=length: traversal.record_chunk(
                reference, offset=0, length=length, **chunk_context
            )
        )
        assert len(validate_record_chunk(chunk, reference, offset=0, length=length)) == length
        samples.append((length, work))
    assert_linear(samples)
    chunk_context["authorize"] = lambda resource: False
    with pytest.raises(ContractError, match="PERMISSION_DENIED"):
        traversal.record_chunk(reference, offset=0, length=64, **chunk_context)


def test_complete_traversal_request_work_is_linear():
    samples = []
    transferred = []
    for count in (16, 64, 256):
        start, payload, data, staging = selected(count, limit=8)
        available = records(payload)

        def complete(start=start, payload=payload, staging=staging, available=available):
            custody(start, payload, staging)
            return traverse(start, payload, available, retry=True)

        (identities, request_bytes), work = measure(complete)
        assert identities == payload["resources"]
        samples.append((count, work))
        transferred.append((count, len(data) + request_bytes))
    assert_linear(samples)
    # Count complete selection bytes once plus actual serialized request/retry bytes.
    assert all(later / earlier < 4.1 for (_, earlier), (_, later) in pairwise(transferred))


_SELECTION_PROOFS = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/observations.py#decode_observation_selection",
        "packages/fishhat-contracts/src/fishhat_contracts/observations.py#ObservationTraversal.__init__",
        "packages/fishhat-contracts/src/fishhat_contracts/observations.py#ObservationTraversal.page",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/observation.schema.json",
        "release.toml#/engineering",
    ],
    "scope": "complete exact selection decoding and retained reference traversal across actual bounded wire frames",
    "relationship": "scoped-witness",
    "reason": "Complete independently expected resource sequences, transferred bytes and repeated pages establish reference extent and growth. Synthetic native context does not qualify receiving authorization, inventory, durable storage or actual checks.",
    "claims": [
        "engineering:observations.decode",
        "engineering:observations.start",
        "engineering:observations.page",
    ],
}

CHECK_OVERRIDES = {
    "test_large_selection_roundtrips_once": _SELECTION_PROOFS,
    "test_complete_traversal_request_work_is_linear": _SELECTION_PROOFS,
    "test_large_snapshot_chunks_reauthorize_original_custody": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/observations.py#ObservationTraversal.record_chunk",
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/observation.schema.json",
            "release.toml#/engineering",
        ],
        "scope": "complete oversized reference observation retrieval with current synthetic custody and bounded chunk work",
        "relationship": "scoped-witness",
        "reason": "Framed chunks reconstruct independently retained original bytes; measured increasing chunk lengths establish reference work and current permission revocation refuses further disclosure. No native snapshot service or authorization is qualified.",
        "claims": ["engineering:observations.record-chunk"],
    },
}
