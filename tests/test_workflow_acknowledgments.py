"""Original finite mutation outcomes without implicit full workflow snapshots."""

from __future__ import annotations

import copy

import pytest
from fishhat_client.wire import frame
from fishhat_contracts.record_delivery import RecordSnapshot
from fishhat_contracts.validation import ContractError, digest, validate, validate_cli
from fishhat_contracts.workflow_acknowledgments import (
    validate_workflow_mutation_acknowledgment,
    workflow_mutation_acknowledgment,
)
from fishhat_contracts.workflow_bindings import bind_workflow_view

from tests.test_contracts import uid
from tests.test_owner_handoffs import cli, wire
from tests.test_workflow_continuations import context, move, successor_stage

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/MutationAcknowledgment",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/cli-output.schema.json",
    ],
    "scope": "finite exact bind/advance acknowledgment, request correlation and unchanged replay",
    "relationship": "candidate",
    "reason": "Synthetic committed individual receipts challenge changed identities, input digests and generations, with explicit full-history retrieval and hard rejection of whole-Workflow mutation replies. No native transport authentication, custody, commit or execution is qualified.",
    "claims": [],
}


def accepted(method):
    value, query = successor_stage()
    bound = bind_workflow_view(query, value, **context(query))
    if method == "workflow.bind":
        return bound, bound["bindings"][0]
    advanced = move(bound, "reconciling")
    return advanced, advanced["advances"][-1]


def expected(method, receipt):
    request = receipt["request"]
    return {
        "method": method,
        "owner": request["owner"],
        "workflow_id": request["workflow_id"],
        "mutation_id": request["bind_id" if method == "workflow.bind" else "advance_id"],
        "request_digest": digest(request),
        "expected_generation": request["expected_generation"],
    }


@pytest.mark.parametrize("method", ["workflow.bind", "workflow.advance"])
def test_original_acknowledgment_survives_later_workflow_changes(method):
    workflow, receipt = accepted(method)
    original = copy.deepcopy(receipt)
    acknowledgment = workflow_mutation_acknowledgment(method, original)
    validate_workflow_mutation_acknowledgment(acknowledgment, **expected(method, original))
    with pytest.raises(ContractError):
        validate("ssh-response.schema.json", wire(method, acknowledgment))
    validate_cli(cli(acknowledgment))
    assert len(frame(wire(method, acknowledgment))) < 4096

    # Later owner state is retrieved separately. It never supplies the original
    # acknowledgment generation or forces its history into the reply codec.
    workflow = move(workflow, "completed")
    assert workflow["generation"] > acknowledgment["generation"]
    assert workflow_mutation_acknowledgment(method, original) == acknowledgment
    assert receipt == original
    validate("ssh-response.schema.json", wire("workflow.get", workflow))
    reference = RecordSnapshot(workflow, uid("ack-full-history")).reference
    validate("ssh-response.schema.json", wire("workflow.get", reference))
    for replaced in (workflow, reference):
        with pytest.raises(ContractError):
            validate("ssh-response.schema.json", wire(method, replaced))


@pytest.mark.parametrize("method", ["workflow.bind", "workflow.advance"])
@pytest.mark.parametrize(
    "field", ["method", "owner", "workflow_id", "mutation_id", "request_digest", "generation"]
)
def test_acknowledgment_rejects_substituted_request_or_outcome(method, field):
    _, receipt = accepted(method)
    value = workflow_mutation_acknowledgment(method, receipt)
    if field == "method":
        value[field] = "workflow.advance" if method == "workflow.bind" else "workflow.bind"
    elif field == "owner":
        value[field]["epoch"] = uid("another-owner-epoch")
    elif field == "request_digest":
        value[field] = digest({"different": "decoded input"})
    elif field == "generation":
        value[field] += 1
    else:
        value[field] = uid("other-" + field)
    with pytest.raises(ContractError, match="original request or outcome"):
        validate_workflow_mutation_acknowledgment(value, **expected(method, receipt))


@pytest.mark.parametrize("method", ["workflow.bind", "workflow.advance"])
@pytest.mark.parametrize("field", ["request_digest", "generation"])
def test_acknowledgment_cannot_relabel_inconsistent_retained_receipt(method, field):
    _, original = accepted(method)
    receipt = copy.deepcopy(original)
    receipt[field] = digest({"wrong": "input"}) if field == "request_digest" else 999
    with pytest.raises(ContractError, match="committed input or generation"):
        workflow_mutation_acknowledgment(method, receipt)


def test_acknowledgment_rejects_another_response_method():
    _, receipt = accepted("workflow.bind")
    result = workflow_mutation_acknowledgment("workflow.bind", receipt)
    with pytest.raises(ContractError):
        validate("ssh-response.schema.json", wire("workflow.advance", result))
    with pytest.raises(ContractError, match="unsupported"):
        workflow_mutation_acknowledgment("workflow.prepare", receipt)
