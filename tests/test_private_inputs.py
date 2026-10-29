"""Exact private input custody and consumer correlation without public value hashes."""

from __future__ import annotations

import copy
import hashlib
from functools import partial
from io import BytesIO

import pytest
from fishhat_adapters import process
from fishhat_adapters.process import (
    private_value_source,
    validate_process_launch,
    verify_process_private_inputs,
)
from fishhat_contracts.artifact_custody import CHUNK_BYTES
from fishhat_contracts.validation import ContractError, canonical, digest, validate

from tests.adapter_support import identifier
from tests.linear_support import assert_linear, measure
from tests.test_adapter_invocations import recovered
from tests.test_adapter_process import identity, invocation, launch
from tests.test_protected_values import value_fixture

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter-process.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
    ],
    "scope": "complete owner-approved private inputs, consuming use and original value identity",
    "relationship": "candidate",
    "reason": "Independent approved metadata and private streams exercise substitution, recovery and query boundaries; no native authentication, confinement, confidentiality or durable custody qualification.",
    "claims": [],
}


def private_fixture(kind="mutation", *, count=1, value=b"private-value"):
    call, installation, descriptor, configuration = invocation()
    manifest, payload = launch(call, configuration, "mutation" if kind == "mutation" else "query")
    if kind == "query":
        payload = {
            "contract": "fishhat.build",
            "method": "observe",
            "input": {"scope": call["request"]["input"]["scope"], "cursor": None, "limit": 2},
        }
        manifest["request"] = identity(canonical(payload))
    original = {
        "attempt": {
            key: field
            for key, field in call["attempt"].items()
            if key not in {"state", "certainty", "outcome", "native_task"}
        },
        "request": call["request"],
    }
    use = {
        "id": identifier(100),
        "kind": kind,
        "owner": copy.deepcopy(call["attempt"]["owner"]),
        "executor": copy.deepcopy(call["attempt"]["executor"]),
        "request_digest": digest(payload),
        "invocation_digest": None if kind == "query" else digest(original),
        "operation_inputs_digest": None,
    }
    bindings = [
        {
            "id": identifier(200 + index),
            "use_id": use["id"],
            "handle": f"credential:{index:03}",
            "purpose": "provider-access",
            "source": {
                "kind": "enrolled",
                "owner": copy.deepcopy(use["owner"]),
                "enrollment_id": identifier(400 + index),
                "version": identifier(500 + index),
            },
            "size_bytes": len(value),
            "path": "private-inputs/" + identifier(200 + index),
        }
        for index in range(count)
    ]
    rows = b"".join(canonical(binding) + b"\n" for binding in bindings)
    private = {"use": copy.deepcopy(use), "manifest": identity(rows, "application/x-ndjson")}
    manifest["private_inputs"] = private
    return {
        "call": call,
        "installation": installation,
        "descriptor": descriptor,
        "configuration": configuration,
        "manifest": manifest,
        "payload": payload,
        "use": use,
        "bindings": bindings,
        "rows": rows,
        "value": value,
    }


def seal_operation_inputs(data):
    projection = [
        {key: copy.deepcopy(binding[key]) for key in ("handle", "source", "size_bytes")}
        for binding in data["bindings"]
        if binding["purpose"] == "operation-value"
    ]
    commitment = digest(projection) if projection else None
    use = data["use"]
    use["operation_inputs_digest"] = commitment
    if use["kind"] != "query":
        original = data["call"]
        if commitment is not None:
            original["attempt"]["private_inputs_digest"] = commitment
        else:
            original["attempt"].pop("private_inputs_digest", None)
        use["invocation_digest"] = digest(
            {
                "attempt": {
                    key: value
                    for key, value in original["attempt"].items()
                    if key not in {"state", "certainty", "outcome", "native_task"}
                },
                "request": original["request"],
            }
        )
        data["payload"] = original if use["kind"] == "mutation" else recovered(original)
    use["request_digest"] = digest(data["payload"])
    data["manifest"]["request"] = identity(canonical(data["payload"]))
    data["rows"] = b"".join(canonical(item) + b"\n" for item in data["bindings"])
    data["manifest"]["private_inputs"] = {
        "use": copy.deepcopy(use),
        "manifest": identity(data["rows"], "application/x-ndjson"),
    }


def validate_launch(data):
    validate_process_launch(
        data["manifest"],
        data["payload"],
        data["configuration"],
        descriptor=data["descriptor"],
        approved_installation=data["installation"],
        expected_executor=data["call"]["attempt"]["executor"],
        expected_private_use=data["use"],
    )


def verify(data, *, original_inputs=None, bindings=None, rows=None, value=None):
    selected = data["bindings"] if bindings is None else bindings
    raw = data["rows"] if rows is None else rows
    provisioned = data["value"] if value is None else value
    verify_process_private_inputs(
        BytesIO(raw),
        private_inputs=data["manifest"]["private_inputs"],
        expected_use=data["use"],
        expected_inputs=selected,
        original_inputs=original_inputs,
        open_input=lambda _: BytesIO(provisioned),
        open_retained=lambda _: BytesIO(data["value"]),
    )


@pytest.mark.parametrize("kind", ["mutation", "query", "reconcile"])
def test_private_inputs_use_one_fixed_boundary_for_effects_queries_and_reconciliation(kind):
    data = private_fixture(kind)
    validate_launch(data)
    verify(data, original_inputs=data["bindings"] if kind == "reconcile" else None)
    encoded = canonical(data["manifest"]) + data["rows"]
    assert data["value"] not in encoded
    assert hashlib.sha256(data["value"]).hexdigest().encode() not in encoded
    assert "digest" not in data["bindings"][0]
    assert data["bindings"][0]["path"].endswith(data["bindings"][0]["id"])


@pytest.mark.parametrize(
    "change", ["missing", "unapproved", "request", "executor", "owner", "kind"]
)
def test_private_launch_cannot_substitute_the_consuming_use(change):
    data = private_fixture()
    selected = data["manifest"]["private_inputs"]["use"]
    if change == "missing":
        data["manifest"]["private_inputs"] = None
    elif change == "unapproved":
        selected["id"] = identifier(999)
    elif change == "request":
        selected["request_digest"] = "sha256:" + "f" * 64
        data["use"] = copy.deepcopy(selected)
    elif change == "executor":
        selected["executor"]["instance_generation"] += 1
        data["use"] = copy.deepcopy(selected)
    elif change == "owner":
        selected["owner"]["epoch"] = identifier(999)
        data["use"] = copy.deepcopy(selected)
    else:
        selected["kind"] = "reconcile"
        data["use"] = copy.deepcopy(selected)
    with pytest.raises(ContractError, match="private"):
        validate_launch(data)


def test_private_input_manifest_is_required_even_when_approved_closure_is_empty():
    data = private_fixture()
    data["manifest"].pop("private_inputs")
    with pytest.raises(ContractError):
        validate_launch(data)


def test_accepted_attempt_commits_private_operation_values_and_cannot_omit_the_channel():
    data = private_fixture()
    data["bindings"][0]["purpose"] = "operation-value"
    seal_operation_inputs(data)
    validate_launch(data)
    verify(data)
    data["manifest"]["private_inputs"] = None
    with pytest.raises(ContractError, match="required private inputs are missing"):
        validate_process_launch(
            data["manifest"],
            data["payload"],
            data["configuration"],
            descriptor=data["descriptor"],
            approved_installation=data["installation"],
            expected_executor=data["call"]["attempt"]["executor"],
            expected_private_use=None,
        )


def test_absent_operation_commitment_cannot_admit_a_nonempty_private_operation_closure():
    data = private_fixture()
    data["bindings"][0]["purpose"] = "operation-value"
    data["rows"] = canonical(data["bindings"][0]) + b"\n"
    data["manifest"]["private_inputs"]["manifest"] = identity(data["rows"], "application/x-ndjson")
    with pytest.raises(ContractError, match="private operation commitment changed"):
        verify(data)


def test_private_original_identity_survives_mutable_execution_state_and_replay():
    data = private_fixture("reconcile")
    data["bindings"][0]["purpose"] = "operation-value"
    seal_operation_inputs(data)
    original_use = copy.deepcopy(data["use"])
    original = copy.deepcopy(data["bindings"])
    validate_launch(data)
    verify(data, original_inputs=original)
    verify(data, original_inputs=original)
    data["call"]["attempt"].update(state="resolved", certainty="known", outcome="succeeded")
    seal_operation_inputs(data)
    assert data["use"]["invocation_digest"] == original_use["invocation_digest"]
    assert data["use"]["operation_inputs_digest"] == original_use["operation_inputs_digest"]
    assert data["use"]["request_digest"] != original_use["request_digest"]
    data["use"]["id"] = identifier(999)
    for binding in data["bindings"]:
        binding["use_id"] = data["use"]["id"]
    seal_operation_inputs(data)
    validate_launch(data)
    verify(data, original_inputs=original)


@pytest.mark.parametrize("change", ["missing", "extra", "duplicate", "source", "path", "use"])
def test_private_input_closure_rejects_omission_substitution_and_extra_credentials(change):
    data = private_fixture(count=2)
    supplied = copy.deepcopy(data["bindings"])
    if change == "missing":
        supplied.pop()
    elif change == "extra":
        supplied.append({**supplied[0], "handle": "credential:extra", "id": identifier(999)})
    elif change == "duplicate":
        supplied.append(copy.deepcopy(supplied[0]))
    elif change == "source":
        supplied[0]["source"]["version"] = identifier(999)
    elif change == "path":
        supplied[0]["path"] = "private-inputs/" + identifier(999)
    else:
        supplied[0]["use_id"] = identifier(999)
    rows = b"".join(canonical(item) + b"\n" for item in supplied)
    data["manifest"]["private_inputs"]["manifest"] = identity(rows, "application/x-ndjson")
    with pytest.raises(ContractError, match="private"):
        verify(data, rows=rows)


@pytest.mark.parametrize(
    "value",
    [b"wrong-value!!", b"short", b"private-value-extra"],
    ids=["same-size-substitution", "short", "extra"],
)
def test_private_inputs_compare_complete_bytes_against_original_custody(value):
    data = private_fixture()
    assert len(b"wrong-value!!") == len(data["value"])
    with pytest.raises(ContractError, match="private input"):
        verify(data, value=value)
    assert data["value"] == b"private-value"


def test_private_input_handles_and_slots_are_unique_even_in_owner_supplied_metadata():
    data = private_fixture(count=2)
    for field in ("handle", "id"):
        values = copy.deepcopy(data["bindings"])
        values[1][field] = values[0][field]
        values[1]["path"] = "private-inputs/" + values[1]["id"]
        with pytest.raises(ContractError, match="binding conflicts"):
            verify(data, bindings=values)


def test_private_source_reference_binds_producer_and_ignores_later_validity_observations():
    original, response = value_fixture()
    source = private_value_source(original, response)
    validate("adapter.schema.json", source, "PrivateInputSource")
    assert source["destination"] == original["request"]["input"]["value_destination"]
    assert source["value"]["lease"] == response["output"]["leases"][0]["lease"]
    observed = copy.deepcopy(response)
    observed["output"]["leases"][0]["validity"] = "expired"
    observed["effect"]["postcondition"] = "unknown"
    assert private_value_source(original, observed) == source
    assert source["value"] is not response["output"]["leases"][0]


@pytest.mark.parametrize("role", ["secret-source", "credential-issuer"])
def test_produced_private_inputs_preserve_original_result_identity_on_reconciliation(role):
    original, direct = value_fixture(role)
    recovered_response = copy.deepcopy(direct)
    recovered_response.update(method="reconcile", request_digest=digest(recovered(original)))
    source = private_value_source(original, direct)
    assert private_value_source(original, recovered_response) == source
    data = private_fixture()
    data["bindings"][0].update(purpose="operation-value", source=source)
    seal_operation_inputs(data)
    validate_launch(data)
    verify(data)
    recovered_response["output"]["handoff"]["state"] = "unavailable"
    recovered_response["output"]["handoff"]["size_bytes"] = None
    with pytest.raises(ContractError, match="REQUIRES_VALUE_CUSTODY"):
        private_value_source(original, recovered_response)


@pytest.mark.parametrize("change", ["version", "missing", "extra", "purpose", "size", "order"])
def test_reconciliation_preserves_the_complete_original_operation_value_set(change):
    data = private_fixture("reconcile", count=3)
    data["bindings"][0]["purpose"] = "operation-value"
    data["bindings"][1]["purpose"] = "operation-value"
    seal_operation_inputs(data)
    original = copy.deepcopy(data["bindings"])
    if change == "version":
        data["bindings"][0]["source"]["version"] = identifier(999)
    elif change == "missing":
        data["bindings"].pop(0)
    elif change == "extra":
        data["bindings"][2]["purpose"] = "operation-value"
    elif change == "purpose":
        data["bindings"][0]["purpose"] = "provider-access"
    elif change == "size":
        data["bindings"][0]["size_bytes"] += 1
    else:
        data["bindings"][0], data["bindings"][1] = data["bindings"][1], data["bindings"][0]
    with pytest.raises(ContractError, match="private operation commitment changed"):
        verify(data, original_inputs=original)
    seal_operation_inputs(data)
    with pytest.raises(ContractError, match="original operation values changed"):
        verify(data, original_inputs=original)


def test_reconciliation_can_use_separately_approved_current_access_credentials():
    data = private_fixture("reconcile", count=2)
    data["bindings"][0]["purpose"] = "operation-value"
    seal_operation_inputs(data)
    original = copy.deepcopy(data["bindings"])
    original[1]["source"]["version"] = identifier(999)
    original[1]["size_bytes"] = 5
    for item in original:
        item["use_id"] = identifier(998)
    validate_launch(data)
    verify(data, original_inputs=original)
    with pytest.raises(ContractError, match="original private inputs are required"):
        verify(data)


def test_private_input_streaming_handles_independent_short_reads_and_failures():
    data = private_fixture(value=b"x" * (2 * CHUNK_BYTES + 1))
    opened = []

    class ShortReader(BytesIO):
        def read(self, size=-1):
            return super().read(7 if size < 0 else min(size, 7))

    def open_input(path):
        opened.append(path)
        return ShortReader(data["value"])

    verify_process_private_inputs(
        BytesIO(data["rows"]),
        private_inputs=data["manifest"]["private_inputs"],
        expected_use=data["use"],
        expected_inputs=data["bindings"],
        original_inputs=None,
        open_input=open_input,
        open_retained=lambda _: BytesIO(data["value"]),
    )
    assert opened == [data["bindings"][0]["path"]]
    with pytest.raises(OSError):
        verify_process_private_inputs(
            BytesIO(data["rows"]),
            private_inputs=data["manifest"]["private_inputs"],
            expected_use=data["use"],
            expected_inputs=data["bindings"],
            original_inputs=None,
            open_input=lambda _: (_ for _ in ()).throw(OSError("synthetic private capacity")),
            open_retained=lambda _: BytesIO(data["value"]),
        )


def test_private_input_boundary_linear_work():
    samples = []
    for count in (1, 4, 16):
        data = private_fixture("reconcile", count=count, value=b"x" * CHUNK_BYTES)
        for binding in data["bindings"]:
            binding["purpose"] = "operation-value"
        seal_operation_inputs(data)
        raw = data["rows"]
        counts = {"bytes": 0, "files": 0}

        class Counted(BytesIO):
            def __init__(self, content, *, counter=counts):
                super().__init__(content)
                self.counter = counter

            def read(self, size=-1):
                chunk = super().read(size)
                self.counter["bytes"] += len(chunk)
                return chunk

        def open_input(_, content=data["value"], counter=counts, reader=Counted):
            counter["files"] += 1
            return reader(content)

        _, work = measure(
            partial(
                verify_process_private_inputs,
                BytesIO(raw),
                private_inputs=data["manifest"]["private_inputs"],
                expected_use=data["use"],
                expected_inputs=data["bindings"],
                original_inputs=copy.deepcopy(data["bindings"]),
                open_input=open_input,
                open_retained=lambda _, content=data["value"], reader=Counted: reader(content),
            ),
            modules=(process,),
        )
        assert counts == {"bytes": 2 * count * CHUNK_BYTES, "files": count}
        work["private_bytes"] += counts["bytes"]
        samples.append((count, work))
    assert_linear(samples)


def test_private_input_source_linear_work():
    samples = []
    for count in (1, 4, 16):
        original, response = value_fixture()
        response["effect"]["postcondition"] = "unknown"
        lease = response["output"]["leases"][0]
        for index in range(1, count):
            response["output"]["leases"].append(
                {
                    **copy.deepcopy(lease),
                    "lease": f"lease:{index}",
                    "value_handle": f"value:{index}",
                }
            )
        source, work = measure(
            partial(private_value_source, original, response), modules=(process,)
        )
        assert source["value"]["value_handle"] == lease["value_handle"]
        samples.append((count, work))
    assert_linear(samples)


CHECK_OVERRIDES = {
    name: {
        "purpose": "implementation",
        "authority": [
            "release.toml#/engineering",
            "packages/fishhat-adapter-protocol/src/fishhat_adapters/process.py#" + operation,
        ],
        "scope": "complete private input metadata and byte custody over sixteenfold extent",
        "relationship": "scoped-witness",
        "reason": "Deterministic complete byte accounting and metadata work; no native confidentiality or authorization qualification.",
        "claims": ["engineering:adapters.process." + operation],
    }
    for name, operation in (
        ("test_private_input_boundary_linear_work", "verify_process_private_inputs"),
        ("test_private_input_source_linear_work", "private_value_source"),
    )
}
