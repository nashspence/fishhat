"""Trusted historical readers survive complete CLI and SSH record retrieval."""

import base64
import copy
import hashlib
import io

import pytest
from fishhat_client.wire import frame, read_frame
from fishhat_contracts.handoffs import validate_cli_result
from fishhat_contracts.operations import validate_operation
from fishhat_contracts.record_delivery import (
    RecordSnapshot,
    validate_record_chunk,
    validate_record_payload,
)
from fishhat_contracts.validation import ContractError, canonical, validate, validate_cli

from tests.operation_support import seal_operation
from tests.test_owner_handoffs import U, V, cli, operation, wire, work_page

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/RecordReference",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/RecordChunk",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/cli-output.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/record_delivery.py#validate_record_payload",
    ],
    "scope": "exact retained schema context through envelopes, pages, chunks and payloads",
    "relationship": "candidate",
    "reason": "An independently supplied prior reader is required at every result boundary; substituted schema, owner and generation are rejected. No historical native store or authorization is implemented.",
    "claims": [],
}


def retained_record():
    value = operation()
    reference = RecordSnapshot(value, U).reference
    reference["schema"]["digest"] = "sha256:" + "e" * 64
    value["retained_extension"] = "read-only"
    seal_operation(value)
    data = canonical(value)
    reference.update(size=len(data), digest="sha256:" + hashlib.sha256(data).hexdigest())
    return value, reference, data


def test_installed_historical_reader_survives_cli_ssh_page_and_complete_retrieval():
    value, reference, data = retained_record()
    calls = []

    def reader(record):
        assert record["retained_extension"] == "read-only"
        calls.append(copy.deepcopy(record))

    readers = {(reference["schema"]["uri"], reference["schema"]["digest"]): reader}
    page = work_page("OperationPage", [reference])
    for result in (reference, page):
        validate_cli(cli(result), retained_readers=readers)
        validate_cli_result(result, retained_readers=readers)
        with pytest.raises(ContractError, match="schema substitution"):
            validate_cli(cli(result))
        with pytest.raises(ContractError, match="schema substitution"):
            validate_cli_result(result)
        with pytest.raises(ContractError, match="schema substitution"):
            validate_cli(
                cli(result),
                retained_readers={(reference["schema"]["uri"], "sha256:" + "f" * 64): reader},
            )

    received = []
    for offset in range(0, len(data), 137):
        part = data[offset : offset + 137]
        chunk = {
            "format": "deployment-ops/record-chunk/v1",
            "kind": "RecordChunk",
            "reference": reference,
            "offset": offset,
            "base64": base64.b64encode(part).decode("ascii"),
            "next_offset": offset + len(part),
            "complete": offset + len(part) == len(data),
        }
        validate_cli(cli(chunk), retained_readers=readers)
        response = wire("record.read", chunk)
        validate("ssh-response.schema.json", response)
        decoded = read_frame(io.BytesIO(frame(response)))["result"]
        validate_cli_result(decoded, retained_readers=readers)
        with pytest.raises(ContractError, match="schema substitution"):
            validate_cli_result(decoded)
        received.append(validate_record_chunk(decoded, reference, offset=offset, length=137))
    assert calls == []
    result = validate_record_payload(
        reference,
        b"".join(received),
        expected_owner=value["owner"],
        expected_record=reference["record"],
        retained_readers=readers,
    )
    assert result == value and calls == [value]


@pytest.mark.parametrize("field", ["schema", "owner", "generation"])
def test_historical_reader_cannot_override_independent_snapshot_identity(field):
    value, reference, data = retained_record()
    readers = {(reference["schema"]["uri"], reference["schema"]["digest"]): lambda record: None}
    changed = copy.deepcopy(reference)
    if field == "schema":
        changed["schema"]["digest"] = "sha256:" + "f" * 64
    elif field == "owner":
        changed["owner"]["epoch"] = V
    else:
        changed["record"]["generation"] += 1
    with pytest.raises(ContractError):
        validate_record_payload(
            changed,
            data,
            expected_owner=value["owner"],
            expected_record=reference["record"],
            retained_readers=readers,
        )
    if field == "owner":
        page = work_page("OperationPage", [reference])
        page["items"] = [changed]
        with pytest.raises(ContractError, match="another owner epoch"):
            validate_cli(cli(page), retained_readers=readers)


def test_envelope_cannot_supply_a_reader_registry_or_authorize_inline_history():
    value, reference, _ = retained_record()
    readers = {(reference["schema"]["uri"], reference["schema"]["digest"]): lambda record: None}
    injected = cli(reference)
    injected["retained_readers"] = {reference["schema"]["digest"]: "caller-selected"}
    with pytest.raises(ContractError):
        validate_cli(injected, retained_readers=readers)
    with pytest.raises(ContractError):
        validate_cli(cli(value), retained_readers=readers)
    with pytest.raises(ContractError):
        validate_cli({**cli(reference), "state": "succeeded"}, retained_readers=readers)


def test_historical_reader_registry_binds_kind_uri_as_well_as_closure_digest():
    value = operation()
    reference = RecordSnapshot(value, U).reference
    original_schema = copy.deepcopy(reference["schema"])
    calls = []

    def strict_operation_reader(record):
        validate_operation(record)
        calls.append(record)

    readers = {(original_schema["uri"], original_schema["digest"]): strict_operation_reader}
    reference["record"] = {"kind": "Plan", "id": value["id"], "generation": None}
    reference["schema"]["uri"] = original_schema["uri"].rsplit("/", 1)[0] + "/Plan"
    with pytest.raises(ContractError, match="schema substitution"):
        validate_record_payload(
            reference,
            canonical(value),
            expected_owner=value["owner"],
            expected_record=reference["record"],
            retained_readers=readers,
        )
    assert calls == []


@pytest.mark.parametrize("payload_kind", ["Operation", None])
def test_historical_payload_discriminator_must_match_pinned_record_kind(payload_kind):
    value = operation()
    reference = RecordSnapshot(value, U).reference
    reference["record"] = {"kind": "Plan", "id": value["id"], "generation": None}
    reference["schema"]["uri"] = reference["schema"]["uri"].rsplit("/", 1)[0] + "/Plan"
    reference["schema"]["digest"] = "sha256:" + "e" * 64
    if payload_kind is None:
        del value["kind"]
    data = canonical(value)
    reference.update(size=len(data), digest="sha256:" + hashlib.sha256(data).hexdigest())
    # Even an incorrectly installed permissive reader cannot replace the shared
    # discriminator join with the kind claimed only by the untrusted reference.
    readers = {(reference["schema"]["uri"], reference["schema"]["digest"]): lambda record: None}
    with pytest.raises(ContractError, match="payload kind substitution"):
        validate_record_payload(
            reference, data, expected_owner=value["owner"], retained_readers=readers
        )
