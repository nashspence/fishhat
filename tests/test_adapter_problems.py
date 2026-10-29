"""Typed adapter problems preserve original effect evidence and owner authority."""

from __future__ import annotations

import copy
from io import BytesIO

import pytest
from fishhat_adapters import ObservationSequence, check_response
from fishhat_adapters.process import receive_process_result
from fishhat_contracts.validation import ContractError, canonical, validate

from tests.test_adapter_cumulative_results import reconciliation, running
from tests.test_adapter_handoffs import response_for
from tests.test_adapter_invocations import recovered
from tests.test_adapter_observation_identity import query_page
from tests.test_adapter_observation_pages import ROLES, page
from tests.test_adapter_process import identity, invocation
from tests.test_adapter_retained_results import read_result, result_fixture

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter-process.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json",
    ],
    "scope": "bounded typed domain problems, observational retry hints, retained native facts and distinct process outcomes",
    "relationship": "candidate",
    "reason": "Synthetic domain failures, lost replies and rejected retry hints exercise the declared data boundary without supplying native authorization, secret redaction or execution qualification.",
    "claims": [],
}


def problem(code="UNAVAILABLE", retry="none"):
    return {"code": code, "summary": "The selected provider is unavailable.", "retry": retry}


@pytest.mark.parametrize("role", ROLES)
def test_observation_reports_typed_problem_without_claiming_complete_coverage(role):
    query, response = page(role)
    response.update(coverage="unknown", problem=problem(retry="safe-read"))
    expected = copy.deepcopy(response)
    check_response(role, query, response)
    assert response == expected
    del response["problem"]
    with pytest.raises(ContractError):
        check_response(role, query, response)


@pytest.mark.parametrize(
    "changes",
    [
        {"code": "PROVIDER_SPECIFIC_FAILURE"},
        {"code": "ACCEPTANCE_UNKNOWN"},
        {"code": "OWNER_EPOCH_CHANGED"},
        {"retry": "same-request-after-reconcile"},
        {"summary": "x" * 2049},
        {"credentials": {"token": "synthetic-value"}},
        {"owner": None},
        {"evidence": []},
    ],
    ids=[
        "unknown-code",
        "owner-acceptance",
        "owner-epoch",
        "owner-retry",
        "unbounded-summary",
        "raw-provider-material",
        "owner-attribution",
        "owner-evidence",
    ],
)
def test_adapter_problem_is_a_closed_bounded_projection_of_owner_vocabulary(changes):
    value = problem()
    validate("adapter.schema.json", value, "Problem")
    value.update(changes)
    with pytest.raises(ContractError):
        validate("adapter.schema.json", value, "Problem")


@pytest.mark.parametrize(
    "code",
    ["UNSUPPORTED_CAPABILITY", "PRECONDITION_FAILED", "AUTHENTICATION_FAILED", "CAPACITY_BLOCKED"],
)
def test_domain_rejection_reports_its_reason_without_rewriting_effect_facts(code):
    call, _, _, _ = invocation()
    response = response_for(call["request"], call["attempt"], {"artifacts": []})
    response["effect"].update(
        acknowledgment="rejected", effect_certainty="none", postcondition="not-satisfied"
    )
    response["problem"] = problem(code)
    original = copy.deepcopy(response)
    check_response("build", call["request"], response, invocation=call)
    assert response == original
    response["problem"]["retry"] = "safe-read"
    with pytest.raises(ContractError):
        check_response("build", call["request"], response, invocation=call)


def test_reconciliation_problem_preserves_known_task_and_cannot_release_redispatch():
    owner, commits, attempt, _ = running()
    query, response = reconciliation(
        owner,
        attempt,
        acknowledgment="unknown",
        task_state="unknown",
        effect_certainty="unknown",
        postcondition="unknown",
        native_task=None,
    )
    response["problem"] = problem("AUTHENTICATION_FAILED", retry="safe-read")
    expected = copy.deepcopy(response)
    owner.settle(attempt["attempt_id"], query, response)
    snapshot = owner.snapshot()
    current = snapshot["attempts"][attempt["attempt_id"]]
    assert (current["state"], current["certainty"], current["native_task"]) == (
        "reconciling",
        "known",
        "task:one",
    )
    evidence = snapshot["results"][attempt["attempt_id"]]
    assert evidence["knowledge"]["acknowledgment"] == "accepted"
    assert evidence["records"][evidence["latest"]]["response"] == expected == response
    count = len(commits)
    owner.settle(attempt["attempt_id"], query, response)
    assert len(commits) == count
    with pytest.raises(ContractError, match="RECONCILE_REQUIRED"):
        owner.dispatch("demo", attempt["attempt_id"])


@pytest.mark.parametrize("reconcile", [False, True])
def test_delivery_problem_preserves_issuance_but_does_not_satisfy_private_custody(reconcile):
    operation, retained = result_fixture(reconcile=reconcile)
    call, response = retained["invocation"], retained["response"]
    response["problem"] = problem("CAPACITY_BLOCKED", "safe-read" if reconcile else "none")
    response["output"]["handoff"].update(state="unknown", size_bytes=None)
    expected = copy.deepcopy(response)
    query = recovered(call) if reconcile else call["request"]
    check_response("credential-issuer", query, response, invocation=call)
    assert response == expected
    assert response["effect"]["effect_certainty"] == "known"
    assert response["effect"]["postcondition"] == "satisfied"
    with pytest.raises(ContractError, match="REQUIRES_VALUE_CUSTODY"):
        read_result(operation, retained)
    operation.update(state="quarantined", effect_certainty="known")
    assert read_result(operation, retained) == retained


@pytest.mark.parametrize("exit_code", [0, 9])
def test_domain_problem_and_transport_failure_remain_separate(exit_code):
    call, _, _, _ = invocation()
    response = response_for(call["request"], call["attempt"], {"artifacts": []})
    response["effect"].update(effect_certainty="unknown", postcondition="unknown")
    response["problem"] = problem()
    encoded = canonical(response)
    marker = canonical(
        {"format": "fishhat.adapter-process-result/v1", "response": identity(encoded)}
    )
    retained = BytesIO()
    receipt = receive_process_result(
        "build",
        call["request"],
        stdout=marker + b"\n",
        response_stream=BytesIO(encoded),
        retained_response=retained,
        exit_code=exit_code,
        timed_out=False,
        children_quiescent=True,
        invocation=call,
    )
    assert receipt.complete is (exit_code == 0)
    assert (receipt.problem is None) is (exit_code == 0)
    assert receipt.response == response
    assert retained.getvalue() == encoded


def test_new_null_cursor_scan_is_distinct_from_receiver_local_accepted_page_replay():
    query, first = query_page("secret-source")
    approved = query["input"]["binding"]
    old_scan = ObservationSequence("secret-source", query, approved_binding=approved)
    assert old_scan.accept(query, first)
    assert not old_scan.accept(copy.deepcopy(query), copy.deepcopy(first))
    changed = copy.deepcopy(first)
    changed["output"]["versions"][0]["validity"] = "revoked"
    with pytest.raises(ContractError, match="OBSERVATION_PAGE_REPLAY_CHANGED"):
        old_scan.accept(query, changed)
    fresh_scan = ObservationSequence("secret-source", query, approved_binding=approved)
    assert fresh_scan.accept(query, changed)
    assert fresh_scan.complete
