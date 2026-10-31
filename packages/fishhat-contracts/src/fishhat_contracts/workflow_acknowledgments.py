"""Complete shared workflow inspection models; no live owner admission.

These full-value helpers construct and validate an explicitly requested audit
projection from independently retained facts. They are not a journal writer or
a participant protocol: live admission uses workflow_journal and its partitioned
owner journals. Materialize complete views only for explicit inspection, never
after each accepted child or at every participating owner.

Finite original mutation outcomes, separate from complete workflow inspection.

Inputs are individual independently validated, durably committed owner receipts.
Neither this codec nor an acknowledgment supplies native acceptance, authority or
custody. Full workflow validation and execution retain separate growth duties.
"""

from __future__ import annotations

import copy
from typing import Any

from .bounds import Bounds, bounds
from .validation import ContractError, digest, validate

_METHODS = {
    "workflow.bind": ("BindReceipt", "bind_id"),
    "workflow.advance": ("DriverAdvanceReceipt", "advance_id"),
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


@bounds(
    Bounds(
        id="workflow.mutation-acknowledgment",
        work="O(B) for one complete retained request/receipt, O(sum B) over acknowledgment creation and exact retries; no whole-workflow input, snapshot or history scan",
        extent="Every byte of the selected individual receipt and its original request; complete workflow custody and validation remain separately required",
        limits=(),
        capacity=("native owners may explicitly refuse capacity without truncating custody",),
        proofs=(
            "tests/test_workflow_acknowledgment_growth.py::test_complete_reply_sequence_and_retries_have_linear_work",
        ),
        linear_proofs=(
            "tests/test_workflow_acknowledgment_growth.py::test_complete_reply_sequence_and_retries_have_linear_work",
        ),
    )
)
def workflow_mutation_acknowledgment(method: str, receipt: dict[str, Any]) -> dict[str, Any]:
    """Encode one committed original outcome without reading its whole Workflow.

    The native owner selects this exact immutable receipt from protected indexed
    history after current permission checks. Merely supplying a receipt does not
    prove admission or persistence. Copying current workflow generation here
    would change replay; only the individual original generation is used.
    """
    _require(method in _METHODS, "unsupported workflow acknowledgment method")
    schema, identity = _METHODS[method]
    validate("workflow.schema.json", receipt, schema)
    request = receipt["request"]
    commitment = digest(request)
    _require(
        receipt["request_digest"] == commitment
        and receipt["generation"] == request["expected_generation"] + 1,
        "workflow acknowledgment changed committed input or generation",
    )
    result = {
        "format": "deployment-ops/workflow-acknowledgment/v1",
        "kind": "WorkflowMutationAcknowledgment",
        "owner": copy.deepcopy(request["owner"]),
        "workflow_id": request["workflow_id"],
        "method": method,
        "mutation_id": request[identity],
        "request_digest": commitment,
        "generation": receipt["generation"],
    }
    validate_workflow_mutation_acknowledgment(
        result,
        method=method,
        owner=request["owner"],
        workflow_id=request["workflow_id"],
        mutation_id=request[identity],
        request_digest=commitment,
        expected_generation=request["expected_generation"],
    )
    return result


@bounds(
    Bounds(
        id="workflow.mutation-acknowledgment-validation",
        work="O(1) fixed-shape acknowledgment and independently retained request commitment; O(N) over all N replies and retries",
        extent="Every acknowledgment identity, exact request commitment and original committed generation; no current-state substitution",
        limits=(),
        capacity=(),
        proofs=(
            "tests/test_workflow_acknowledgment_growth.py::test_complete_reply_sequence_and_retries_have_linear_work",
        ),
        linear_proofs=(
            "tests/test_workflow_acknowledgment_growth.py::test_complete_reply_sequence_and_retries_have_linear_work",
        ),
    )
)
def validate_workflow_mutation_acknowledgment(
    value: dict[str, Any],
    *,
    method: str,
    owner: dict[str, Any],
    workflow_id: str,
    mutation_id: str,
    request_digest: str,
    expected_generation: int,
) -> None:
    """Correlate an authenticated reply with independently retained request facts.

    The caller derives request_digest from the complete original decoded request,
    never the staged input locator or values selected from this acknowledgment.
    Current channel authentication and receiving-owner permission remain outside
    this pure checker. Acceptance does not prove any child operation completed.
    """
    validate("workflow.schema.json", value, "MutationAcknowledgment")
    _require(
        value["method"] == method
        and value["owner"] == owner
        and value["workflow_id"] == workflow_id
        and value["mutation_id"] == mutation_id
        and value["request_digest"] == request_digest
        and value["generation"] == expected_generation + 1,
        "workflow acknowledgment changed original request or outcome",
    )
