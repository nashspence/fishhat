"""Complete scoped observations and failure evidence across actual wire frames."""

from __future__ import annotations

import copy
import io

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_client.wire import frame, read_frame
from fishhat_contracts.handoffs import validate_cli_result
from fishhat_contracts.record_delivery import (
    RecordSnapshot,
    validate_observation,
    validate_observation_page,
    validate_problem,
    validate_record_payload,
    validate_record_reference,
)
from fishhat_contracts.validation import MAX_BYTES, ContractError, canonical, validate, validate_cli
from fishhat_contracts.witness import sign, verify
from fishhat_owner.commands import parse_command

from tests.test_owner_handoffs import NOW, U, V, cli, operation, request, wire
from tests.test_record_delivery import complete_record

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/RecordReference",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Observation",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/ObservationPage",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Problem",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/ProblemEvidence",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-cli.json",
    ],
    "scope": "complete scoped observation and failure-evidence retrieval without a total evidence cap",
    "relationship": "candidate",
    "reason": "Single records exceed the real frame limit and roundtrip without evidence loss; independent query and problem context reject owner/resource substitution, including retained-reader paths. Synthetic custody does not prove native authorization or storage.",
    "claims": [],
}


def observation(count=0):
    op = operation()
    value = {
        "resource": copy.deepcopy(op["subject"]["resource"]),
        "owner": copy.deepcopy(op["owner"]),
        "time": NOW,
        "origin": "cached-owner",
        "reachability": "reachable",
        "power_state": "not-applicable",
        "activity": "active",
        "health_check": "supported",
        "health": "healthy",
        "protection": "unknown",
        "generation": 7,
        "source": None,
        "release_digest": None,
        "summary": "Retained observation with its original time and provenance.",
        "witness": None,
    }
    if count:
        body = {key: item for key, item in op["witness"].items() if key != "signature"}
        body["evidence_digests"] = ["sha256:" + f"{index:064x}" for index in range(count)]
        value["witness"] = sign(body, Ed25519PrivateKey.from_private_bytes(b"\x37" * 32))
    return value


def observation_page(items):
    return {
        "format": "deployment-ops/record/v1",
        "kind": "ObservationPage",
        "owner": copy.deepcopy(operation()["owner"]),
        "items": items,
        "next_cursor": "retained_scope_cursor",
    }


def problem(evidence):
    return {
        "code": "CAPACITY_BLOCKED",
        "summary": "Current receiver capacity refuses this exact workflow input.",
        "retry": "same-request-after-reconcile",
        "owner": copy.deepcopy(operation()["owner"]),
        "resource": {"kind": "workflow", "id": U},
        "evidence": evidence,
    }


def error_envelope(value):
    result = cli(None)
    result.update(ok=False, state="rejected", problem=value)
    return result


def evidence_record(count):
    value = problem([])
    return {
        "format": "deployment-ops/problem-evidence/v1",
        "kind": "ProblemEvidence",
        "owner": value["owner"],
        "resource": value["resource"],
        "evidence": ["sha256:" + f"{index:064x}" for index in range(count)],
    }


def test_single_large_observation_preserves_complete_signed_evidence_and_provenance():
    value = observation(15000)
    expected = copy.deepcopy(value)
    validate_observation(value)
    with pytest.raises(ContractError, match="frame size"):
        frame(wire("observe", observation_page([value])))
    snapshot = RecordSnapshot(value, U, record_kind="Observation")
    reference = snapshot.delivery(max_inline_bytes=MAX_BYTES - 512)
    assert reference["record"] == {
        "kind": "Observation",
        "id": U,
        "generation": None,
        "resource": value["resource"],
    }
    page = observation_page([reference])
    for method in ("observe", "check"):
        response = wire(method, page)
        validate("ssh-response.schema.json", response)
        assert read_frame(io.BytesIO(frame(response))) == response
    validate_cli(cli(page))
    validate_observation_page(page, expected_owner=value["owner"], resources=[value["resource"]])
    value.update(time="2026-10-24T00:00:00Z", origin="owner-confirmed", generation=8)
    value["witness"]["evidence_digests"].pop()
    decoded = complete_record(snapshot)
    assert decoded == expected
    verify(
        decoded["witness"],
        Ed25519PrivateKey.from_private_bytes(b"\x37" * 32).public_key(),
        expected["owner"],
        expected["witness"]["subject_digest"],
    )


def test_observation_page_binds_empty_replies_and_mixed_representations_to_query():
    first = observation()
    second = copy.deepcopy(first)
    second["resource"]["id"] = "another-app"
    reference = RecordSnapshot(second, U, record_kind="Observation").reference
    page = observation_page([first, reference])
    context = {
        "expected_owner": first["owner"],
        "resources": [first["resource"], second["resource"]],
    }
    validate_observation_page(page, **context)
    with pytest.raises(ContractError, match="outside requested selection"):
        validate_observation_page(
            page, expected_owner=first["owner"], resources=[first["resource"]]
        )
    page["items"].append(second)
    with pytest.raises(ContractError, match="repeats resource"):
        validate_cli(cli(page))
    page["items"] = []
    validate_observation_page(page, **context)
    page["owner"]["epoch"] = V
    with pytest.raises(ContractError, match="owner epoch changed"):
        validate_observation_page(page, **context)
    page.pop("owner")
    with pytest.raises(ContractError):
        validate("ssh-response.schema.json", wire("observe", page))


@pytest.mark.parametrize("field", ["owner", "resource", "generation", "kind"])
def test_observation_reference_cannot_substitute_scope_or_invent_a_ledger_generation(field):
    value = observation()
    reference = RecordSnapshot(value, U, record_kind="Observation").reference
    changed = copy.deepcopy(reference)
    if field == "owner":
        changed["owner"]["epoch"] = V
    elif field == "resource":
        changed["record"]["resource"]["id"] = "another-app"
    elif field == "generation":
        changed["record"]["generation"] = value["generation"]
    else:
        changed["record"]["kind"] = "ProblemEvidence"
    with pytest.raises(ContractError):
        validate_record_payload(
            changed,
            canonical(value),
            expected_owner=value["owner"],
            expected_record=reference["record"],
            expected_resource=value["resource"],
        )
    if field in {"owner", "kind"}:
        with pytest.raises(ContractError):
            validate_cli(cli(observation_page([changed])))


def test_observation_witness_owner_join_applies_inline_and_after_snapshot_transfer():
    value = observation(1)
    value["witness"]["owner"]["epoch"] = V
    with pytest.raises(ContractError, match="witness owner mismatch"):
        validate_cli(cli(value))
    with pytest.raises(ContractError, match="witness owner mismatch"):
        validate_cli(cli(observation_page([value])))
    with pytest.raises(ContractError, match="witness owner mismatch"):
        RecordSnapshot(value, U, record_kind="Observation")


def test_workflow_error_names_exact_scope_and_large_evidence_is_fully_retrievable():
    value = evidence_record(15000)
    assert len(canonical(value)) > MAX_BYTES
    snapshot = RecordSnapshot(value, U)
    reference = snapshot.reference
    error = problem(reference)
    validate_problem(error)
    validate_cli(error_envelope(error))
    response = {
        **request("content.begin", {}),
        "ok": False,
        "problem": error,
    }
    response.pop("params")
    validate("ssh-response.schema.json", response)
    assert read_frame(io.BytesIO(frame(response))) == response
    assert complete_record(snapshot) == value
    assert reference["record"] == {
        "kind": "ProblemEvidence",
        "id": U,
        "generation": None,
        "resource": error["resource"],
    }
    assert (
        parse_command(
            f"app-ops workflow list --resource-kind workflow --resource-id {U} --json", "app-ops"
        )["use_case"]
        == "workflow.list"
    )


def test_inline_error_evidence_threshold_is_a_representation_bound_only():
    value = evidence_record(65)
    inline = problem(value["evidence"][:64])
    validate_problem(inline)
    inline["evidence"] = value["evidence"]
    with pytest.raises(ContractError):
        validate_problem(inline)
    inline["evidence"] = RecordSnapshot(value, U).reference
    validate_problem(inline)
    assert len(complete_record(RecordSnapshot(value, U))["evidence"]) == 65
    inline.update(owner=None, resource=None, evidence=[])
    validate_problem(inline)


@pytest.mark.parametrize("field", ["owner", "resource", "null-owner", "null-resource", "kind"])
def test_error_reference_requires_the_exact_non_null_problem_owner_and_resource(field):
    reference = RecordSnapshot(evidence_record(65), U).reference
    error = problem(copy.deepcopy(reference))
    if field == "owner":
        error["evidence"]["owner"]["epoch"] = V
    elif field == "resource":
        error["evidence"]["record"]["resource"]["id"] = V
    elif field.startswith("null-"):
        error[field[5:]] = None
    else:
        error["evidence"] = RecordSnapshot(observation(), U, record_kind="Observation").reference
    with pytest.raises(ContractError):
        validate_problem(error)
    with pytest.raises(ContractError):
        validate_cli(error_envelope(error))


@pytest.mark.parametrize("kind", ["Observation", "ProblemEvidence"])
def test_scoped_snapshots_require_installed_readers_without_weakening_resource_binding(kind):
    value = observation() if kind == "Observation" else evidence_record(65)
    reference = RecordSnapshot(value, U, record_kind=kind).reference
    reference["schema"]["digest"] = "sha256:" + "e" * 64
    readers = {reference["schema"]["digest"]: lambda item: None}
    if kind == "Observation":
        envelope = cli(observation_page([reference]))
    else:
        envelope = error_envelope(problem(reference))
    with pytest.raises(ContractError, match="schema substitution"):
        validate_cli(envelope)
    validate_cli(envelope, retained_readers=readers)
    validate_cli_result(reference, retained_readers=readers)
    context = {"expected_owner": value["owner"], "expected_resource": value["resource"]}
    validate_record_reference(reference, retained_readers=readers, **context)
    assert (
        validate_record_payload(reference, canonical(value), retained_readers=readers, **context)
        == value
    )
    reference["record"]["resource"]["id"] = "substituted-resource"
    with pytest.raises(ContractError, match="resource substitution"):
        validate_record_reference(reference, retained_readers=readers, **context)
    with pytest.raises(ContractError, match="payload binding"):
        validate_record_payload(
            reference,
            canonical(value),
            expected_owner=value["owner"],
            retained_readers=readers,
        )
