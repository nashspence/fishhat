"""Original protected value delivery remains separate from confirmed native effects."""

from __future__ import annotations

import copy
from functools import partial
from io import BytesIO

import pytest
from fishhat_adapters import check_invocation, check_request, check_response, process
from fishhat_adapters.process import receive_process_result, receive_process_value
from fishhat_contracts import protected_values
from fishhat_contracts.artifact_custody import CHUNK_BYTES
from fishhat_contracts.validation import ContractError, canonical, digest

from tests.adapter_support import identifier
from tests.linear_support import assert_linear, measure
from tests.test_adapter_handoffs import handoff, invocation_for, response_for
from tests.test_adapter_invocations import recovered
from tests.test_adapter_process import identity
from tests.test_adapter_retained_results import read_result, result_fixture

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter-process.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/secret-source-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/credential-issuer-adapter.schema.json",
    ],
    "scope": "exact original private value destination, method identity and complete delivery across lost replies",
    "relationship": "candidate",
    "reason": "Synthetic retained invocations and owner-supplied streams check semantics and byte extent; native confidentiality, stable custody, authorization and actual credential issuance remain unqualified.",
    "claims": [],
}


def value_fixture(role="credential-issuer", *, reconcile=False):
    if role == "credential-issuer":
        _, result = result_fixture(reconcile=reconcile)
        return result["invocation"], result["response"]
    _, query = handoff("secret-source", "retrieve")
    invocation = invocation_for(query)
    output = {
        "versions": [
            {
                "source": query["input"]["binding"]["instance"],
                "entry": query["input"]["entry"],
                "version": query["input"]["version"],
                "value_handle": "protected:retrieved",
                "validity": "valid",
                "expires_at": None,
            }
        ]
    }
    response = response_for(
        recovered(invocation) if reconcile else query, invocation["attempt"], output
    )
    return invocation, response


@pytest.mark.parametrize("role", ["secret-source", "credential-issuer"])
@pytest.mark.parametrize("reconcile", [False, True])
def test_exact_private_value_channel_has_no_public_plaintext_commitment(role, reconcile):
    invocation, response = value_fixture(role, reconcile=reconcile)
    value = b"synthetic-secret"
    retained = BytesIO()
    destination = invocation["request"]["input"]["value_destination"]
    opened = []

    def open_value(path):
        opened.append(path)
        return BytesIO(value)

    receive_process_value(
        invocation,
        response,
        expected_destination=destination,
        open_value=open_value,
        retained_value=retained,
        original_value=None,
        original_record=None,
    )
    assert retained.getvalue() == value
    assert opened == ["output/values/" + destination["id"]]
    assert value not in canonical(response)
    assert "digest" not in response["output"]["handoff"]


@pytest.mark.parametrize("change", ["consumer", "owner", "destination", "handle"])
def test_value_metadata_substitution_is_rejected(change):
    invocation, response = value_fixture()
    transfer = response["output"]["handoff"]
    if change == "consumer":
        transfer["destination"]["consumer"] = "other-consumer"
    elif change == "owner":
        transfer["destination"]["owner"]["epoch"] = identifier(123)
    elif change == "destination":
        transfer["destination"]["id"] = identifier(123)
    else:
        transfer["value_handle"] = "protected:another"
    with pytest.raises(ContractError, match="PROTECTED_VALUE"):
        check_response("credential-issuer", invocation["request"], response, invocation=invocation)


@pytest.mark.parametrize("change", ["consumer", "authority", "epoch"])
def test_destination_is_bound_before_native_dispatch(change):
    invocation, _ = value_fixture()
    query = invocation["request"]
    destination = query["input"]["value_destination"]
    if change == "consumer":
        destination["consumer"] = "other-consumer"
    elif change == "authority":
        destination["owner"]["id"] = identifier(123)
    else:
        destination["owner"]["epoch"] = identifier(123)
        invocation["attempt"]["input_digest"] = digest(query)
    with pytest.raises(ContractError, match="PROTECTED_VALUE_DESTINATION"):
        if change == "epoch":
            check_invocation("credential-issuer", invocation)
        else:
            check_request("credential-issuer", query)


@pytest.mark.parametrize("state", ["unknown", "unavailable"])
@pytest.mark.parametrize("reconcile", [False, True])
def test_lost_value_preserves_effect_but_cannot_satisfy_operation_success(state, reconcile):
    operation, retained = result_fixture(reconcile=reconcile)
    invocation, response = retained["invocation"], retained["response"]
    response["output"]["handoff"].update(state=state, size_bytes=None)
    query = recovered(invocation) if reconcile else invocation["request"]
    check_response("credential-issuer", query, response, invocation=invocation)
    assert response["effect"]["effect_certainty"] == "known"
    assert response["effect"]["postcondition"] == "satisfied"
    with pytest.raises(ContractError, match="REQUIRES_VALUE_CUSTODY"):
        read_result(operation, retained)
    operation.update(state="quarantined", effect_certainty="known")
    assert read_result(operation, retained) == retained


@pytest.mark.parametrize("bytes_returned", [b"short", b"synthetic-secret-extra"])
def test_private_stream_must_be_complete_and_exact_size(bytes_returned):
    invocation, response = value_fixture()
    with pytest.raises(ContractError, match=r"declared size|incomplete"):
        receive_process_value(
            invocation,
            response,
            expected_destination=invocation["request"]["input"]["value_destination"],
            open_value=lambda _: BytesIO(bytes_returned),
            retained_value=BytesIO(),
            original_value=None,
            original_record=None,
        )
    assert response["effect"]["effect_certainty"] == "known"


def test_process_failure_after_issuance_retains_original_reply_and_value_recovery():
    invocation, response = value_fixture()
    raw = canonical(response)
    marker = canonical({"format": "fishhat.adapter-process-result/v1", "response": identity(raw)})
    retained_reply = BytesIO()
    receipt = receive_process_result(
        "credential-issuer",
        invocation["request"],
        stdout=marker + b"\n",
        response_stream=BytesIO(raw),
        retained_response=retained_reply,
        exit_code=9,
        timed_out=False,
        children_quiescent=True,
        invocation=invocation,
    )
    assert not receipt.complete
    assert receipt.response == response
    assert receipt.response["effect"]["effect_certainty"] == "known"
    with pytest.raises(FileNotFoundError):
        receive_process_value(
            invocation,
            response,
            expected_destination=invocation["request"]["input"]["value_destination"],
            open_value=lambda _: (_ for _ in ()).throw(FileNotFoundError()),
            retained_value=BytesIO(),
            original_value=None,
            original_record=None,
        )
    recovered_response = copy.deepcopy(response)
    recovered_response.update(method="reconcile", request_digest=digest(recovered(invocation)))
    recovered_value = BytesIO()
    receive_process_value(
        invocation,
        recovered_response,
        expected_destination=invocation["request"]["input"]["value_destination"],
        open_value=lambda _: BytesIO(b"synthetic-secret"),
        retained_value=recovered_value,
        original_value=None,
        original_record=None,
    )
    assert recovered_value.getvalue() == b"synthetic-secret"
    assert recovered_response["effect"] == response["effect"]
    assert recovered_response["output"] == response["output"]


@pytest.mark.parametrize("reexport", [b"synthetic-secret", b"substitute-value", b"short"])
def test_reexport_cannot_replace_committed_private_bytes(reexport):
    invocation, response = value_fixture(reconcile=True)
    original = BytesIO(b"synthetic-secret")
    sink = BytesIO()
    run = partial(
        receive_process_value,
        invocation,
        response,
        expected_destination=invocation["request"]["input"]["value_destination"],
        open_value=lambda _: BytesIO(reexport),
        retained_value=sink,
        original_value=original,
        original_record=copy.deepcopy(response["output"]["leases"][0]),
    )
    if reexport == original.getvalue():
        run()
        assert sink.getvalue() == original.getvalue()
    else:
        with pytest.raises(ContractError, match="changed from committed original"):
            run()
    assert original.getvalue() == b"synthetic-secret"
    assert response["effect"]["effect_certainty"] == "known"


@pytest.mark.parametrize("field", ["lease", "value_handle", "validity"])
def test_reexport_preserves_original_value_identity_and_separates_observed_validity(field):
    invocation, response = value_fixture(reconcile=True)
    current = response["output"]["leases"][0]
    original = copy.deepcopy(current)
    if field == "validity":
        current["validity"] = "expired"
        response["effect"]["postcondition"] = "unknown"
    else:
        current[field] = "protected:replacement"
        if field == "value_handle":
            response["output"]["handoff"]["value_handle"] = current[field]
    run = partial(
        receive_process_value,
        invocation,
        response,
        expected_destination=invocation["request"]["input"]["value_destination"],
        open_value=lambda _: BytesIO(b"synthetic-secret"),
        retained_value=BytesIO(),
        original_value=BytesIO(b"synthetic-secret"),
        original_record=original,
    )
    if field == "validity":
        run()
    else:
        with pytest.raises(ContractError, match="original identity changed"):
            run()


def test_private_reexport_comparison_handles_independent_short_reads():
    invocation, response = value_fixture(reconcile=True)
    value = b"synthetic-secret"

    class ShortReader(BytesIO):
        def __init__(self, limit):
            super().__init__(value)
            self.limit = limit

        def read(self, size=-1):
            return super().read(self.limit if size < 0 else min(self.limit, size))

    retained = BytesIO()
    receive_process_value(
        invocation,
        response,
        expected_destination=invocation["request"]["input"]["value_destination"],
        open_value=lambda _: ShortReader(7),
        retained_value=retained,
        original_value=ShortReader(3),
        original_record=copy.deepcopy(response["output"]["leases"][0]),
    )
    assert retained.getvalue() == value


def test_protected_value_transfer_linear_work():
    samples = []
    for count in (1, 4, 16):
        invocation, response = value_fixture(reconcile=True)
        value = b"x" * (count * CHUNK_BYTES)
        response["output"]["handoff"]["size_bytes"] = len(value)
        counts = {"read": 0, "written": 0}

        class PrivateStream(BytesIO):
            def __init__(self, data=b"", *, counter=counts):
                super().__init__(data)
                self.counter = counter

            def read(self, size=-1):
                data = super().read(size)
                self.counter["read"] += len(data)
                return data

            def write(self, data):
                written = super().write(data)
                self.counter["written"] += written
                return written

        retained = PrivateStream()
        source = PrivateStream(value)
        original = PrivateStream(value)
        opened = []

        def open_value(path, selected=source, paths=opened):
            paths.append(path)
            return selected

        # An unresolved native result retains every discovered lease; one exact
        # value may be available even when other native facts remain unresolved.
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
        _, work = measure(
            partial(
                receive_process_value,
                invocation,
                response,
                expected_destination=invocation["request"]["input"]["value_destination"],
                open_value=open_value,
                retained_value=retained,
                original_value=original,
                original_record=copy.deepcopy(response["output"]["leases"][0]),
            ),
            modules=(process, protected_values),
        )
        assert retained.getvalue() == value
        assert counts == {"read": 2 * len(value), "written": len(value)}
        assert len(opened) == 1
        work["value_bytes_read_and_written"] += sum(counts.values())
        samples.append((len(value), work))
    assert_linear(samples)


CHECK_OVERRIDES = {
    "test_protected_value_transfer_linear_work": {
        "purpose": "implementation",
        "authority": [
            "release.toml#/engineering",
            "packages/fishhat-adapter-protocol/src/fishhat_adapters/process.py#receive_process_value",
            *[
                "packages/fishhat-contracts/src/fishhat_contracts/protected_values.py#" + name
                for name in ("check_value_request", "check_value_response", "require_value_custody")
            ],
        ],
        "scope": "complete original request/result validation and protected stream transfer over sixteenfold byte extent",
        "relationship": "scoped-witness",
        "reason": "Deterministic metadata work and complete value byte accounting; no native storage or confidentiality qualification.",
        "claims": [
            "engineering:adapters.process.receive_process_value",
            "engineering:adapters.protected-values.check_request",
            "engineering:adapters.protected-values.check_response",
            "engineering:adapters.protected-values.require_custody",
        ],
    }
}
