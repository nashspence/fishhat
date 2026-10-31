"""Complete shared workflow inspection models; no live owner admission.

These full-value helpers construct and validate an explicitly requested audit
projection from independently retained facts. They are not a journal writer or
a participant protocol: live admission uses workflow_journal and its partitioned
owner journals. Materialize complete views only for explicit inspection, never
after each accepted child or at every participating owner.

Owner-native workflow admission changes with immutable local custody.

These reference transitions do not stop children, release holds or coordinate
participants. Native owners authorize and durably serialize them with admission.
Transport callers cannot select native authority through request fields.
Each call validates and copies its complete decoded capsule; this is not a
bounded native admission implementation or a native persistence qualification.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any, NoReturn

from .bounds import Bounds, bounds
from .handoffs import PHASES
from .validation import ContractError, digest, validate


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def lifecycle_destination(decision: dict[str, Any], workflow: dict[str, Any]) -> str:
    """Decode one legal local admission change, without granting its authority."""
    state, action = decision["from_state"], decision["action"]
    allowed = {
        "pause": {"prepared", "active"},
        "resume": {"paused"},
        "require-recovery": {"prepared", "active", "paused"},
        "cancel": {"prepared", "active", "paused", "recovery-required"},
    }
    _require(state in allowed[action], "illegal workflow lifecycle transition")
    if action == "resume":
        return "prepared" if decision["phase"] == PHASES[workflow["type"]][0] else "active"
    return {"pause": "paused", "require-recovery": "recovery-required", "cancel": "cancelled"}[
        action
    ]


def validate_lifecycle_decision(decision: dict[str, Any], workflow: dict[str, Any]) -> str:
    validate("workflow.schema.json", decision, "NativeLifecycleDecision")
    _require(
        decision["owner"] == workflow["owner"]
        and decision["workflow_id"] == workflow["id"]
        and decision["proposal_digest"] == workflow["proposal_digest"]
        and decision["procedure"] == workflow["type"],
        "workflow lifecycle identity changed",
    )
    _require(decision["phase"] in PHASES[workflow["type"]], "workflow lifecycle phase changed")
    attribution = decision["request"]
    if attribution is not None:
        request = attribution["input"]
        _require(
            request["request_id"] == decision["advance_id"]
            and all(
                request[key] == decision[key]
                for key in (
                    "owner",
                    "workflow_id",
                    "proposal_digest",
                    "expected_generation",
                    "driver_term",
                    "action",
                )
            ),
            "workflow lifecycle request changed native decision",
        )
    destination = lifecycle_destination(decision, workflow)
    witness = decision["witness"]
    _require(
        witness["owner"] == decision["owner"]
        and witness["workflow_id"] == decision["workflow_id"]
        and witness["kind"] == "approval"
        and witness["state"] == destination
        and witness["generation"] == decision["expected_generation"] + 1
        and witness["subject_digest"]
        == digest({key: value for key, value in decision.items() if key != "witness"}),
        "workflow lifecycle witness changed",
    )
    return destination


def record_native_lifecycle_view(
    decision: dict[str, Any],
    workflow: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    native_authorized: bool,
    verified_decision: dict[str, Any] | None = None,
    verified_driver: dict[str, Any] | None = None,
    verified_reconciled: bool = False,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Retain one exact admission decision without changing procedure or custody.

    Verified context comes from protected current owner state, never request JSON.
    Resume requires the current driver and reconciliation of accepted child facts,
    unresolved holds and current permissions; it cannot revive recovery-required
    work. Cancellation closes only this owner's future child admission. Previously
    accepted children keep their independent execution, replay and custody rules.
    Every native decision is serialized atomically with local child admission.
    """
    from .handoffs import validate_workflow
    from .workflows import retained_transition_input

    validate("workflow.schema.json", decision, "NativeLifecycleDecision")
    validate_workflow(workflow, recovery_readers=recovery_readers)
    _require(native_authorized is True, "current owner-native lifecycle authority required")
    _require(decision["owner"] == workflow["owner"] == expected_owner, "lifecycle receiver changed")
    _require(decision["workflow_id"] == workflow["id"], "lifecycle workflow identity changed")
    for receipt in workflow["advances"]:
        original = retained_transition_input(receipt)
        if original["advance_id"] == decision["advance_id"]:
            _require(receipt["authority"] == "native-lifecycle", "transition changed authority")
            _require(original == decision, "accepted lifecycle decision changed")
            return copy.deepcopy(workflow)
    _require(
        decision["expected_generation"] == workflow["generation"] < 9007199254740991
        and decision["driver_term"] == workflow["driver_term"]
        and decision["from_state"] == workflow["state"]
        and decision["phase"] == workflow["phase"],
        "workflow lifecycle generation, term or predecessor changed",
    )
    _require(
        workflow.get("recovery", {}).get("phase", "committed") == "committed",
        "uncommitted recovery successor requires explicit abandonment",
    )
    destination = validate_lifecycle_decision(decision, workflow)
    _require(
        decision == verified_decision, "workflow lifecycle decision is not independently verified"
    )
    if decision["action"] == "resume":
        _require(
            verified_driver
            == {"principal": workflow["driver_principal"], "term": workflow["driver_term"]}
            and verified_reconciled is True,
            "workflow resume requires current driver and reconciliation",
        )
        _require(
            workflow["transfer"] is None or workflow["transfer"]["phase"] == "completed",
            "workflow resume cannot bypass incomplete driver transfer",
        )
    result = copy.deepcopy(workflow)
    result["generation"] += 1
    result["state"] = destination
    result["advances"].append(
        {
            "authority": "native-lifecycle",
            "decision": copy.deepcopy(decision),
            "decision_digest": digest(decision),
            **{key: result[key] for key in ("generation", "driver_term", "phase", "state")},
        }
    )
    validate_workflow(result, recovery_readers=recovery_readers)
    return result


class LifecycleRefusal(ContractError):
    """Typed refusal of a new lifecycle request; no accepted transition is implied."""

    def __init__(
        self,
        code: str,
        summary: str,
        *,
        owner: dict[str, Any],
        workflow_id: str,
    ) -> None:
        self.problem = {
            "code": code,
            "summary": summary,
            "retry": "safe-read",
            "owner": copy.deepcopy(owner),
            "resource": {"kind": "workflow", "id": workflow_id},
            "evidence": [],
        }
        validate("records.schema.json", self.problem, "Problem")
        super().__init__(summary)


def validate_lifecycle_result(value: dict[str, Any]) -> None:
    """Check the complete retained outcome without authenticating its native witness."""
    validate("workflow.schema.json", value, "LifecycleResult")
    receipt = value["receipt"]
    decision = receipt["decision"]
    attribution = decision["request"]
    _require(attribution is not None, "lifecycle result lacks its requested decision")
    assert attribution is not None
    request = attribution["input"]
    _require(
        value["owner"] == decision["owner"]
        and value["workflow_id"] == decision["workflow_id"]
        and value["procedure"] == decision["procedure"]
        and value["request_id"] == request["request_id"]
        and value["request_digest"] == digest(request)
        and receipt["decision_digest"] == digest(decision)
        and receipt["generation"] == decision["expected_generation"] + 1
        and receipt["driver_term"] == decision["driver_term"]
        and receipt["phase"] == decision["phase"],
        "lifecycle result changed its accepted request or outcome",
    )
    destination = validate_lifecycle_decision(
        decision,
        {
            "owner": value["owner"],
            "id": value["workflow_id"],
            "proposal_digest": decision["proposal_digest"],
            "type": value["procedure"],
        },
    )
    _require(receipt["state"] == destination, "lifecycle result changed destination state")


def _request_result(workflow: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    request = receipt["decision"]["request"]["input"]
    result = {
        "kind": "WorkflowLifecycleResult",
        "owner": copy.deepcopy(workflow["owner"]),
        "workflow_id": workflow["id"],
        "request_id": request["request_id"],
        "request_digest": digest(request),
        "procedure": workflow["type"],
        "receipt": copy.deepcopy(receipt),
    }
    validate_lifecycle_result(result)
    return result


def _request_decision(
    request: dict[str, Any],
    workflow: dict[str, Any],
    principal: str,
    verified_decision: dict[str, Any] | None,
) -> dict[str, Any]:
    """Join an independently produced decision to the actual authenticated request."""
    _require(verified_decision is not None, "independent native lifecycle decision required")
    assert verified_decision is not None
    validate_lifecycle_decision(verified_decision, workflow)
    _require(
        verified_decision["request"] == {"input": request, "authenticated_principal": principal},
        "lifecycle decision request attribution changed",
    )
    return verified_decision


@bounds(
    Bounds(
        id="workflow.lifecycle-request",
        work="O(B + H) complete capsule validation, exact history lookup and copying; B complete retained workflow/proposal/evidence bytes and H retained transition entries; the finite request never bounds retained result evidence",
        extent="Complete current workflow history, exact original request attribution and complete accepted receipt/evidence; no history prefix selection",
        limits=(),
        capacity=(
            "native owner capacity may refuse new requests without evicting accepted identities",
        ),
        proofs=(
            "tests/test_workflow_lifecycle_requests.py::test_accepted_lifecycle_request_replay_preserves_original_result_and_attribution",
        ),
        linear_proofs=(
            "tests/test_workflow_lifecycle_requests.py::test_lifecycle_request_linear_complete_history_work",
            "tests/test_workflow_lifecycle_requests.py::test_lifecycle_request_linear_child_and_binding_work",
        ),
    )
)
def request_workflow_lifecycle_view(
    request: dict[str, Any],
    workflow: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    principal: str,
    read_authorized: bool,
    request_authorized: bool,
    native_authorized: bool,
    verified_decision: dict[str, Any] | None = None,
    verified_driver: dict[str, Any] | None = None,
    verified_reconciled: bool = False,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Request a protected owner decision; the request supplies no native authority.

    The receiving boundary independently authenticates principal and supplies every
    authorization/verification argument. New requests require scoped administrator
    lifecycle permission and a separately produced native decision. An administrator
    may request resume on behalf of the retained driver only after that driver's
    current authority and all native reconciliation facts are independently verified.
    Exact replay first requires current read permission, then preserves the original
    attribution and complete receipt even after generation, driver or lifecycle change.
    Replay grants no mutation permission and does not require new native evidence.
    A native implementation atomically retains the decision and request reservation
    with local child admission before acknowledging success. This pure copy model
    neither authenticates a caller nor qualifies native durability or reconciliation.
    """
    from .handoffs import validate_workflow
    from .workflows import retained_transition_input

    validate("workflow.schema.json", request, "LifecycleRequest")
    validate("common.schema.json", principal, "Id")

    def refuse(code: str, summary: str) -> NoReturn:
        raise LifecycleRefusal(
            code, summary, owner=expected_owner, workflow_id=request["workflow_id"]
        )

    if read_authorized is not True:
        refuse("PERMISSION_DENIED", "current scoped workflow read permission required")
    if request["owner"] != expected_owner or workflow["owner"] != expected_owner:
        refuse("OWNER_EPOCH_CHANGED", "workflow lifecycle receiving owner changed")
    if request["workflow_id"] != workflow["id"]:
        refuse("NOT_FOUND", "workflow lifecycle identity is not present at this receiver")
    validate_workflow(workflow, recovery_readers=recovery_readers)
    for receipt in workflow["advances"]:
        original = retained_transition_input(receipt)
        if original["advance_id"] != request["request_id"]:
            continue
        if (
            receipt["authority"] != "native-lifecycle"
            or original["request"] is None
            or original["request"]["input"] != request
        ):
            refuse("CONFLICT", "lifecycle request identity already selects different work")
        return copy.deepcopy(workflow), _request_result(workflow, receipt)
    if request_authorized is not True or native_authorized is not True:
        refuse("PERMISSION_DENIED", "current scoped lifecycle and native authority required")
    if (
        request["proposal_digest"] != workflow["proposal_digest"]
        or request["expected_generation"] != workflow["generation"]
        or request["driver_term"] != workflow["driver_term"]
    ):
        refuse("PRECONDITION_FAILED", "workflow lifecycle proposal, generation or driver changed")
    try:
        decision = _request_decision(request, workflow, principal, verified_decision)
        result = record_native_lifecycle_view(
            decision,
            workflow,
            expected_owner=expected_owner,
            native_authorized=native_authorized,
            verified_decision=verified_decision,
            verified_driver=verified_driver,
            verified_reconciled=verified_reconciled,
            recovery_readers=recovery_readers,
        )
    except ContractError as exc:
        refuse("PRECONDITION_FAILED", str(exc))
    return result, _request_result(result, result["advances"][-1])


def require_workflow_child_admission(
    workflow: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Check the local workflow gate for a *new* child, never accepted replay.

    This is necessary but insufficient for admission: the receiving owner also
    authorizes the exact bound child Plan, installed phase, current generations,
    exclusions and input custody in the same durable admission transaction.
    """
    from .handoffs import validate_workflow
    from .workflow_preparation import validate_workflow_agreement

    validate_workflow(workflow, recovery_readers=recovery_readers)
    _require(workflow["state"] in {"prepared", "active"}, "workflow blocks new child admission")
    _require(
        workflow["transfer"] is None or workflow["transfer"]["phase"] == "completed",
        "workflow child admission requires completed driver transfer",
    )
    _require(
        workflow.get("recovery", {}).get("phase", "committed") == "committed",
        "workflow child admission requires committed recovery preparation",
    )
    validate_workflow_agreement(workflow, require_complete=True)
