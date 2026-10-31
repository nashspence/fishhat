"""Current owner content is readable through exact, bounded CLI and SSH ranges."""

from __future__ import annotations

import base64
import copy
import hashlib
import io

import pytest
from fishhat_client.wire import frame, read_frame
from fishhat_contracts.handoffs import validate_cli_result
from fishhat_contracts.record_delivery import (
    CHUNK_BYTES,
    validate_content_chunk,
    validate_content_payload,
)
from fishhat_contracts.validation import MAX_BYTES, ContractError, validate, validate_cli
from fishhat_owner.commands import parse_command

from tests.test_owner_handoffs import U, V, cli, operation, request, wire

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/ContentChunk",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-cli.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/cli-output.schema.json",
    ],
    "scope": "exact current-content retrieval by direct owner command and framed SSH",
    "relationship": "candidate",
    "reason": "Complete synthetic bytes exceed a wire frame and reject handle, epoch, range, encoding and digest substitutions. This does not implement or prove native owner custody or receiving-principal authorization.",
    "claims": [],
}


def content_handle(data):
    return {
        "owner": operation()["owner"],
        "id": U,
        "purpose": "capture",
        "binding": {"kind": "operation", "operation_id": V},
        "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def content_chunk(handle, data, offset=0, length=CHUNK_BYTES):
    part = data[offset : offset + length]
    return {
        "format": "deployment-ops/content-chunk/v1",
        "kind": "ContentChunk",
        "handle": copy.deepcopy(handle),
        "offset": offset,
        "base64": base64.b64encode(part).decode("ascii"),
        "next_offset": offset + len(part),
        "complete": offset + len(part) == len(data),
    }


@pytest.mark.parametrize("tool", ["app-ops", "host-ops"])
def test_current_content_has_closed_direct_owner_read_form(tool):
    command = tool + " content read --request-stdin --json"
    assert parse_command(command, tool)["use_case"] == "content.get"
    with pytest.raises(ContractError):
        parse_command(command + " --execute", tool)


@pytest.mark.parametrize(
    "data", [b"", bytes(range(256)) * (MAX_BYTES // 256 + 1)], ids=["empty", "multiple_frames"]
)
def test_complete_current_content_roundtrips_cli_and_ssh(data):
    handle = content_handle(data)
    offset = 0
    parts = []
    while True:
        query = {"handle": handle, "offset": offset, "length": CHUNK_BYTES}
        validate("ssh-request.schema.json", request("content.get", query))
        chunk = content_chunk(handle, data, offset)
        reply = wire("content.get", chunk)
        validate("ssh-response.schema.json", reply)
        encoded = frame(reply)
        assert len(encoded) <= MAX_BYTES + 4
        received = read_frame(io.BytesIO(encoded))["result"]
        validate_cli(cli(received))
        validate_cli_result(received)
        parts.append(validate_content_chunk(received, **query))
        offset = received["next_offset"]
        if received["complete"]:
            break
    complete = b"".join(parts)
    assert complete == data
    validate_content_payload(handle, complete, expected_owner=handle["owner"])


@pytest.mark.parametrize("field", ["id", "epoch", "purpose", "binding", "digest", "size", "offset"])
def test_current_content_rejects_substituted_request_identity(field):
    data = b"retained content"
    handle = content_handle(data)
    chunk = content_chunk(handle, data, length=4)
    if field == "epoch":
        chunk["handle"]["owner"]["epoch"] = V
    elif field == "offset":
        chunk["offset"] = 1
    elif field == "binding":
        chunk["handle"]["binding"]["operation_id"] = U
    else:
        chunk["handle"][field] = {
            "id": V,
            "purpose": "content",
            "digest": "sha256:" + "f" * 64,
            "size": len(data) + 1,
        }[field]
    with pytest.raises(ContractError):
        validate_content_chunk(chunk, handle, offset=0, length=4)


@pytest.mark.parametrize(
    "change",
    [
        {"base64": "!"},
        {"base64": "a"},
        {"next_offset": 3},
        {"complete": True},
        {"base64": "", "next_offset": 0},
        {"base64": "YWJjZGU=", "next_offset": 5},
    ],
)
def test_current_content_rejects_invalid_encoding_range_or_completion(change):
    data = b"abcdefgh"
    handle = content_handle(data)
    chunk = {**content_chunk(handle, data, length=4), **change}
    with pytest.raises(ContractError):
        validate_content_chunk(chunk, handle, offset=0, length=4)


def test_current_content_requires_full_digest_and_current_owner_epoch():
    data = b"retained evidence"
    handle = content_handle(data)
    for substituted in (data[:-1], b"x" + data[1:]):
        with pytest.raises(ContractError, match="content identity"):
            validate_content_payload(handle, substituted, expected_owner=handle["owner"])
    with pytest.raises(ContractError, match="epoch"):
        validate_content_payload(handle, data, expected_owner={**handle["owner"], "epoch": V})


def test_bare_legacy_content_reply_and_execution_label_are_rejected():
    chunk = content_chunk(content_handle(b"bytes"), b"bytes")
    with pytest.raises(ContractError):
        validate(
            "ssh-response.schema.json",
            wire("content.get", {key: chunk[key] for key in ("base64", "next_offset", "complete")}),
        )
    envelope = {**cli(chunk), "state": "succeeded"}
    with pytest.raises(ContractError):
        validate_cli(envelope)
