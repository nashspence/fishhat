"""Executable protocol data and byte checks; no launcher or native authority."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, BinaryIO, cast

from fishhat_contracts.adapter_semantics import (
    ROLES,
    _attempt_identity,
    check_invocation,
    check_request,
    check_response,
)
from fishhat_contracts.artifact_custody import CHUNK_BYTES, verify_artifact_stream
from fishhat_contracts.bounds import Bounds, bounds
from fishhat_contracts.protected_values import require_value_custody
from fishhat_contracts.validation import ContractError, canonical, digest, strict_json, validate

from .protocol import check_configuration, check_descriptor

PROCESS_PROTOCOL = "fishhat.adapter-process/v1"
PROCESS_ARGUMENTS = ("invoke",)
PROCESS_ENVIRONMENT = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"}


def _process_bounds(name: str) -> Bounds:
    return Bounds(
        id="adapters.process." + name,
        work="O(B) complete manifests, typed request/response and every selected artifact byte",
        extent="Complete admitted files and manifest entries; no additional transport extent ceiling",
        limits=(("chunk_bytes", CHUNK_BYTES),),
        capacity=("owner custody storage and proportional typed JSON decoding memory",),
        proofs=("tests/test_adapter_process.py::test_process_boundaries_linear_work",),
        linear_proofs=("tests/test_adapter_process.py::test_process_boundaries_linear_work",),
    )


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ContractError(reason)


def _json_identity(value: Any) -> dict[str, Any]:
    data = canonical(value)
    return {"digest": digest(value), "media_type": "application/json", "size_bytes": len(data)}


def _byte_identities(artifacts: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    expected: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        validate("adapter.schema.json", artifact, "Artifact")
        key = artifact["digest"]
        identity_for_bytes = {**artifact, "media_type": "application/octet-stream"}
        _require(
            key not in expected or expected[key] == identity_for_bytes,
            "process artifact byte identity conflicts",
        )
        expected[key] = identity_for_bytes
    return expected


@bounds(_process_bounds("validate_process_launch"))
def validate_process_launch(
    manifest: dict[str, Any],
    payload: dict[str, Any],
    configuration: Any,
    *,
    descriptor: dict[str, Any],
    approved_installation: dict[str, Any],
    expected_executor: dict[str, Any],
    expected_private_use: dict[str, Any] | None,
) -> None:
    """Join files to independently approved descriptor/executor before native launch.

    Registry authorization and the actual durable dispatch boundary remain with
    the owner. This pure function cannot turn a manifest into bearer authority.
    """
    validate("adapter-process.schema.json", manifest)
    validate("adapter.schema.json", approved_installation, "Installation")
    check_descriptor(descriptor)
    role = manifest["role"]
    executor = manifest["executor"]
    _require(
        descriptor["process_protocol"] == PROCESS_PROTOCOL
        and role in descriptor["roles"]
        and executor == expected_executor
        and executor["role"] == role
        and approved_installation["enabled"]
        and approved_installation["artifact"]["digest"] == executor["installation_digest"]
        and approved_installation["implementation"] == descriptor["id"]
        and approved_installation["descriptor_digest"] == digest(descriptor),
        "process executor identity mismatch",
    )
    _require(
        manifest["request"] == _json_identity(payload)
        and manifest["configuration"] == _json_identity(configuration)
        and digest(configuration) == executor["configuration_digest"]
        and manifest["inputs"]["media_type"] == "application/x-ndjson",
        "process input byte identity mismatch",
    )
    check_configuration(
        descriptor["configuration_schema"],
        configuration,
        digest(descriptor["configuration_schema"]),
    )
    if manifest["mode"] == "mutation":
        check_invocation(role, payload)
        attempt = payload["attempt"]
        _require(
            attempt["executor"] == executor
            and attempt["state"] == "dispatched"
            and attempt["certainty"] == "unknown"
            and attempt["outcome"] == "pending",
            "process mutation lacks released invocation",
        )
        request = payload["request"]
    else:
        check_request(role, payload)
        _require(
            not ROLES[role][payload["method"]]["effect"], "process query cannot dispatch mutation"
        )
        request = payload
        if request["method"] == "reconcile":
            _require(
                request["input"]["invocation"]["attempt"]["executor"] == executor,
                "process reconciliation executor changed",
            )
    _require(request["input"]["scope"] == executor["scope"], "process scope changed")
    _require(
        role + "." + request["method"] in descriptor["implemented"],
        "process method is not implemented",
    )
    _check_private_use(manifest, payload, expected_private_use)


def _invocation_digest(invocation: dict[str, Any]) -> str:
    return digest(
        {"attempt": _attempt_identity(invocation["attempt"]), "request": invocation["request"]}
    )


def _check_private_use(
    manifest: dict[str, Any], payload: dict[str, Any], expected: dict[str, Any] | None
) -> None:
    original: dict[str, Any] | None
    if manifest["mode"] == "mutation":
        original, kind = payload, "mutation"
    elif payload["method"] == "reconcile":
        original, kind = payload["input"]["invocation"], "reconcile"
    else:
        original, kind = None, "query"
    selected = manifest["private_inputs"]
    if selected is None:
        _require(
            expected is None
            and (original is None or "private_inputs_digest" not in original["attempt"]),
            "process required private inputs are missing",
        )
        return
    use = selected["use"]
    _require(expected is not None and use == expected, "process private use is not approved")
    _require(
        selected["manifest"]["media_type"] == "application/x-ndjson"
        and use["executor"] == manifest["executor"]
        and use["request_digest"] == digest(payload),
        "process private use identity changed",
    )
    _require(use["kind"] == kind, "process private use mode changed")
    if original is not None:
        _require(
            use["owner"] == original["attempt"]["owner"]
            and use["invocation_digest"] == _invocation_digest(original)
            and use["operation_inputs_digest"] == original["attempt"].get("private_inputs_digest"),
            "process private original invocation changed",
        )
    else:
        _require(
            use["invocation_digest"] is None
            and use["owner"]["id"] == payload["input"]["scope"]["authority"],
            "process private query owner changed",
        )


@bounds(_process_bounds("verify_process_inputs"))
def verify_process_inputs(
    stream: BinaryIO,
    *,
    identity: dict[str, Any],
    expected_artifacts: Iterable[dict[str, Any]],
    open_artifact: Callable[[str], BinaryIO],
) -> None:
    """Verify the complete manifest and protected bytes through owner-opened streams.

    expected_artifacts is the independently retained required artifact closure,
    not reconstructed from this manifest. Contextual media types stay in the
    typed request; one input file per digest supplies bytes to every reference.
    The callback confines its deterministic path and returns a stable read-only
    regular-file stream. Repeated references never cause repeated file reads.
    """
    validate("adapter.schema.json", identity, "Artifact")
    _require(stream.tell() == 0, "process input manifest does not begin at byte zero")
    _require(identity["media_type"] == "application/x-ndjson", "process input manifest media type")
    expected = _byte_identities(expected_artifacts)
    seen: set[str] = set()
    size, checksum = 0, hashlib.sha256()
    while line := stream.readline(4097):
        _require(
            isinstance(line, bytes) and len(line) <= 4096 and line.endswith(b"\n"),
            "process input manifest framing",
        )
        size += len(line)
        _require(size <= identity["size_bytes"], "process input manifest size")
        checksum.update(line)
        entry = strict_json(line, max_bytes=4096)
        validate("adapter-process.schema.json", entry, "Input")
        artifact = entry["artifact"]
        key = artifact["digest"]
        _require(canonical(entry) + b"\n" == line, "process input manifest is not canonical")
        _require(
            key not in seen
            and expected.get(key) == artifact
            and entry["path"] == "inputs/" + key.removeprefix("sha256:"),
            "process input closure changed or duplicated",
        )
        with open_artifact(entry["path"]) as source:
            verify_artifact_stream(artifact, source)
        seen.add(key)
    _require(
        seen == expected.keys()
        and size == identity["size_bytes"]
        and "sha256:" + checksum.hexdigest() == identity["digest"],
        "process input manifest incomplete or changed",
    )


@bounds(_process_bounds("verify_process_outputs"))
def verify_process_outputs(
    expected_artifacts: Iterable[dict[str, Any]],
    *,
    open_artifact: Callable[[str], BinaryIO],
    retained_artifact: Callable[[str], BinaryIO | None] | None = None,
) -> None:
    """Verify the complete role-selected local material closure without changing effects.

    The receiving owner derives expected_artifacts from the validated typed
    method result and its accepted material handoff. Remote observation metadata
    alone does not select a local material transfer or establish byte custody.
    The owner independently acquires immutable custody and supplies fresh stable
    streams after confinement, permission and native lifetime checks. Merely
    opening or hashing a still-mutable adapter output does not establish custody.

    A retained_artifact callback may return independently retained stable bytes
    for a digest, never a historical metadata assertion. Each complete digest and
    size is still verified. Otherwise open_artifact opens the fixed output path.
    Every supplied stream is closed after verification. Missing or changed bytes
    fail this separate gate; the original ProcessReceipt and confirmed native
    effects stay retained, and the mutation must not be redispatched. The owner
    cannot claim materialization or success before complete custody is committed.
    """
    expected = _byte_identities(expected_artifacts)
    for key, artifact in expected.items():
        source = retained_artifact(key) if retained_artifact is not None else None
        if source is None:
            source = open_artifact("output/artifacts/" + key.removeprefix("sha256:"))
        with source:
            verify_artifact_stream(artifact, source)


def _private_chunk_matches(original: BinaryIO, chunk: bytes) -> bool:
    offset = 0
    view = memoryview(chunk)
    while offset < len(chunk):
        part = original.read(len(chunk) - offset)
        if not isinstance(part, bytes) or not part or len(part) > len(chunk) - offset:
            return False
        if view[offset : offset + len(part)] != part:
            return False
        offset += len(part)
    return True


def _private_input_bounds(name: str, proof: str) -> Bounds:
    return Bounds(
        id="adapters.process." + name,
        work="O(B) complete metadata, retained original bindings and selected private byte streams",
        extent="Every approved private input and original operation-value binding; no total cap",
        limits=(("metadata_line_bytes", 8192), ("chunk_bytes", CHUNK_BYTES)),
        capacity=(
            "Owner-private immutable custody; failure prevents launch without discarding inputs",
        ),
        proofs=(proof,),
        linear_proofs=(proof,),
    )


@bounds(
    _private_input_bounds(
        "private_value_source",
        "tests/test_private_inputs.py::test_private_input_source_linear_work",
    )
)
def private_value_source(invocation: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    """Project original produced-value identity after checking its complete typed response.

    The owner independently authenticates the producer and commits private byte
    custody before approving this source. Available metadata is not custody or
    permission to disclose it to a consuming executor. No plaintext is hashed.
    """
    request = invocation["request"]
    role, method = invocation["attempt"]["executor"]["role"], request["method"]
    _require(
        (role == "secret-source" and method == "retrieve")
        or (role == "credential-issuer" and method in {"issue", "renew"}),
        "process private source is not a value producer",
    )
    checked_request = (
        {
            "contract": request["contract"],
            "method": "reconcile",
            "input": {"scope": request["input"]["scope"], "invocation": invocation},
        }
        if response["method"] == "reconcile"
        else request
    )
    check_response(role, checked_request, response, invocation=invocation)
    require_value_custody(role, request, response)
    output = response["output"]
    secret = role == "secret-source"
    matches = [
        value
        for value in output["versions" if secret else "leases"]
        if value["value_handle"] == output["handoff"]["value_handle"]
    ]
    _require(len(matches) == 1, "process private source identity is ambiguous")
    keys = (
        ("source", "entry", "version", "value_handle")
        if secret
        else ("issuer", "identity", "consumer", "lease", "value_handle")
    )
    result = {
        "kind": "produced",
        "invocation_digest": _invocation_digest(invocation),
        "destination": copy.deepcopy(output["handoff"]["destination"]),
        "value": {
            "kind": "secret" if secret else "credential",
            **{key: copy.deepcopy(matches[0][key]) for key in keys},
        },
    }
    validate("adapter.schema.json", result, "PrivateInputSource")
    return result


def _private_inputs_index(
    values: Iterable[dict[str, Any]], use_id: str | None = None
) -> dict[str, dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    slots: set[str] = set()
    for value in values:
        validate("adapter-process.schema.json", value, "PrivateInput")
        _require(
            (use_id is None or value["use_id"] == use_id)
            and value["path"] == "private-inputs/" + value["id"]
            and value["handle"] not in selected
            and value["id"] not in slots,
            "process private input binding conflicts",
        )
        selected[value["handle"]] = value
        slots.add(value["id"])
    return selected


def _original_private_inputs(
    use: dict[str, Any],
    selected: dict[str, dict[str, Any]],
    original_inputs: Iterable[dict[str, Any]] | None,
) -> None:
    selected_values = _operation_private_values(selected)
    _require(
        use["operation_inputs_digest"] == (digest(selected_values) if selected_values else None),
        "process private operation commitment changed",
    )
    if use["kind"] != "reconcile":
        _require(original_inputs is None, "process private inputs have no original mutation")
        return
    _require(original_inputs is not None, "process original private inputs are required")
    assert original_inputs is not None
    original = _private_inputs_index(original_inputs)

    _require(
        selected_values == _operation_private_values(original),
        "process original operation values changed",
    )


def _operation_private_values(values: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {key: item[key] for key in ("handle", "source", "size_bytes")}
        for item in values.values()
        if item["purpose"] == "operation-value"
    ]


def _verify_private_input(
    value: dict[str, Any],
    open_input: Callable[[str], BinaryIO],
    open_retained: Callable[[dict[str, Any]], BinaryIO],
) -> None:
    with open_input(value["path"]) as incoming, open_retained(value["source"]) as retained:
        _require(
            incoming.tell() == 0 and retained.tell() == 0,
            "process private input stream does not begin at byte zero",
        )
        size = 0
        while chunk := incoming.read(CHUNK_BYTES):
            _require(isinstance(chunk, bytes), "process private input is not bytes")
            size += len(chunk)
            _require(size <= value["size_bytes"], "process private input exceeds declared size")
            _require(
                _private_chunk_matches(retained, chunk),
                "process private input differs from retained original",
            )
        _require(
            size == value["size_bytes"] and retained.read(1) == b"",
            "process private input is incomplete",
        )


@bounds(
    _private_input_bounds(
        "verify_process_private_inputs",
        "tests/test_private_inputs.py::test_private_input_boundary_linear_work",
    )
)
def verify_process_private_inputs(
    stream: BinaryIO,
    *,
    private_inputs: dict[str, Any],
    expected_use: dict[str, Any],
    expected_inputs: Iterable[dict[str, Any]],
    original_inputs: Iterable[dict[str, Any]] | None,
    open_input: Callable[[str], BinaryIO],
    open_retained: Callable[[dict[str, Any]], BinaryIO],
) -> None:
    """Verify all privately provisioned bytes before launch, without public value hashes.

    expected_use and expected_inputs come from independently approved owner
    custody, never the adapter's manifest. Mutation expectations are its durable
    original private closure. Reconciliation additionally loads original_inputs
    from the original invocation and preserves all operation-value bindings;
    separately approved current provider-access credentials may change under a
    fresh use. open_retained resolves only independently trusted source identities.

    The owner confines and freezes each private input file and independently
    authenticates produced sources and current disclosure permission. This pure
    reference check proves metadata joins and complete private byte comparison;
    it does not establish native isolation, authority or durable custody.
    """
    validate("adapter-process.schema.json", private_inputs, "PrivateInputs")
    use, identity = private_inputs["use"], private_inputs["manifest"]
    _require(use == expected_use, "process private use is not approved")
    _require(
        stream.tell() == 0 and identity["media_type"] == "application/x-ndjson",
        "process private manifest identity",
    )
    expected = _private_inputs_index(expected_inputs, use["id"])
    _require(bool(expected), "process empty private closure must use null")
    _original_private_inputs(use, expected, original_inputs)
    seen: set[str] = set()
    ordered = iter(expected)
    size, checksum = 0, hashlib.sha256()
    while line := stream.readline(8193):
        _require(
            isinstance(line, bytes) and len(line) <= 8192 and line.endswith(b"\n"),
            "process private manifest framing",
        )
        size += len(line)
        _require(size <= identity["size_bytes"], "process private manifest size")
        checksum.update(line)
        entry = strict_json(line, max_bytes=8192)
        validate("adapter-process.schema.json", entry, "PrivateInput")
        handle = entry["handle"]
        _require(
            canonical(entry) + b"\n" == line
            and handle not in seen
            and next(ordered, None) == handle
            and expected.get(handle) == entry,
            "process private input closure changed or duplicated",
        )
        _verify_private_input(expected[handle], open_input, open_retained)
        seen.add(handle)
    _require(
        seen == expected.keys()
        and size == identity["size_bytes"]
        and "sha256:" + checksum.hexdigest() == identity["digest"],
        "process private input manifest incomplete or changed",
    )


def _check_private_record(
    role: str, output: dict[str, Any], original_record: dict[str, Any] | None
) -> None:
    if original_record is None:
        return
    secret = role == "secret-source"
    validate(
        "adapter.schema.json", original_record, "SecretVersion" if secret else "CredentialLease"
    )
    selected = next(
        record
        for record in output["versions" if secret else "leases"]
        if record["value_handle"] == output["handoff"]["value_handle"]
    )
    fields = (
        ("source", "entry", "version", "value_handle")
        if secret
        else ("issuer", "identity", "consumer", "lease", "value_handle")
    )
    _require(
        all(selected[field] == original_record[field] for field in fields),
        "process protected value original identity changed",
    )


@bounds(
    Bounds(
        id="adapters.process.receive_process_value",
        work="O(B) complete invocation/response metadata and exact protected value bytes",
        extent="Complete value stream; no total extent cap or public plaintext digest",
        limits=(("chunk_bytes", CHUNK_BYTES),),
        capacity=("Private receiving-owner storage; failures retain original native effects",),
        proofs=("tests/test_protected_values.py::test_protected_value_transfer_linear_work",),
        linear_proofs=(
            "tests/test_protected_values.py::test_protected_value_transfer_linear_work",
        ),
    )
)
def receive_process_value(
    invocation: dict[str, Any],
    response: dict[str, Any],
    *,
    expected_destination: dict[str, Any],
    open_value: Callable[[str], BinaryIO],
    retained_value: BinaryIO,
    original_value: BinaryIO | None,
    original_record: dict[str, Any] | None,
) -> None:
    """Stage exact original value bytes into unpublished private receiving custody.

    The owner independently selects expected_destination and confines open_value
    to stable immutable owner-private streams. The fresh sink never enters public
    artifact storage. This function verifies metadata and complete stream length;
    it cannot establish native confidentiality, authentication or immutable source
    identity. original_value is the independently selected previously committed
    private stream for this destination, required whenever that custody exists.
    original_record is its independently retained lease/version metadata whenever
    known, including when private bytes were lost. Its immutable identity fields
    cannot change during re-export; validity and expiry remain separate observations.
    Full private comparison rejects changed replay bytes without exposing a public
    plaintext digest. The owner commits the private bytes and their original Invocation
    binding atomically only after success. On failure the sink remains unpublished,
    and the separately retained response/native effects must not be discarded.
    """
    request, attempt = invocation["request"], invocation["attempt"]
    role = attempt["executor"]["role"]
    query = request
    if response["method"] == "reconcile":
        query = {
            "contract": request["contract"],
            "method": "reconcile",
            "input": {"scope": request["input"]["scope"], "invocation": invocation},
        }
    check_response(role, query, response, invocation=invocation)
    handoff = response["output"].get("handoff")
    _require(handoff is not None, "process result has no protected value handoff")
    assert handoff is not None
    require_value_custody(role, request, response)
    _require(
        handoff["destination"] == expected_destination,
        "process protected value destination changed",
    )
    _require(
        original_value is None or original_record is not None,
        "process original private bytes lack retained identity",
    )
    _check_private_record(role, response["output"], original_record)
    _require(
        retained_value is not original_value
        and retained_value.tell() == 0
        and retained_value.seek(0, 2) == 0,
        "process protected value sink is not fresh",
    )
    _require(
        original_value is None or original_value.tell() == 0,
        "process original private value does not begin at byte zero",
    )
    path = "output/values/" + expected_destination["id"]
    size = 0
    with open_value(path) as source:
        _require(source.tell() == 0, "process protected value stream does not begin at byte zero")
        while chunk := source.read(CHUNK_BYTES):
            _require(isinstance(chunk, bytes), "process protected value stream is not bytes")
            size += len(chunk)
            _require(size <= handoff["size_bytes"], "process protected value exceeds declared size")
            _require(
                original_value is None or _private_chunk_matches(original_value, chunk),
                "process protected value changed from committed original",
            )
            _require(
                retained_value.write(chunk) == len(chunk), "process private custody write failed"
            )
    _require(size == handoff["size_bytes"], "process protected value is incomplete")
    _require(
        original_value is None or original_value.read(1) == b"",
        "process protected value changed from committed original",
    )


@dataclass(frozen=True)
class ProcessReceipt:
    """Transport completion, never an operation-success assertion.

    Typed response effect certainty, task state and postcondition keep their own
    meaning even when complete is true. Verified output survives an unresolved
    process or child cessation independently of transport completion.
    Required local output artifacts pass verify_process_outputs separately under
    independently acquired immutable owner custody before material success.
    """

    complete: bool
    response: dict[str, Any] | None
    response_artifact: dict[str, Any] | None
    problem: str | None


@bounds(_process_bounds("receive_process_result"))
def receive_process_result(
    role: str,
    request: dict[str, Any],
    *,
    stdout: bytes,
    response_stream: BinaryIO,
    retained_response: BinaryIO,
    exit_code: int | None,
    timed_out: bool,
    children_quiescent: bool,
    invocation: dict[str, Any] | None = None,
) -> ProcessReceipt:
    """Consume exact output into unpublished owner custody, retaining uncertainty.

    The owner spools complete stdout/stderr and preserves those bytes and the
    raw output on every failure. retained_response is a fresh seekable sink; its
    contents are published atomically with the owner record only after successful
    byte/schema checks. Native lifetime observations are independent trusted
    inputs. This function does not start, kill, retry or qualify a process.
    """
    response = None
    artifact = None
    try:
        _require(len(stdout) <= 1024, "process completion framing")
        marker = strict_json(stdout, max_bytes=1024)
        validate("adapter-process.schema.json", marker, "Completion")
        _require(canonical(marker) + b"\n" == stdout, "process completion is not canonical")
        artifact = marker["response"]
        _require(artifact["media_type"] == "application/json", "process response media type")
        _require(retained_response.tell() == 0, "process retention sink is not fresh")
        verify_artifact_stream(artifact, response_stream, destination=retained_response)
        retained_response.seek(0)
        data = bytearray()
        while chunk := retained_response.read(CHUNK_BYTES):
            data.extend(chunk)
        value = strict_json(bytes(data), max_bytes=artifact["size_bytes"])
        _require(canonical(value) == data, "process response is not canonical")
        check_response(role, request, value, invocation=invocation)
        response = cast(dict[str, Any], value)
    except (ContractError, OSError, ValueError, MemoryError) as exc:
        return ProcessReceipt(
            False, None, artifact, "invalid process response: " + type(exc).__name__
        )
    if exit_code != 0 or timed_out or not children_quiescent:
        return ProcessReceipt(False, response, artifact, "process or child cessation unresolved")
    return ProcessReceipt(True, response, artifact, None)
