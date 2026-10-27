"""Owner-native workflow admission changes with immutable local custody.

These reference transitions do not stop children, release holds or coordinate
participants. Native owners authorize and durably serialize them with admission.
Transport callers cannot select native authority through request fields.
Each call validates and copies its complete decoded capsule; this is not a
bounded native admission implementation or a native persistence qualification.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any

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
        and decision["proposal_digest"] == workflow["proposal_digest"],
        "workflow lifecycle identity changed",
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


def record_native_lifecycle(
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
