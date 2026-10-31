"""Complete shared workflow inspection models; no live owner admission.

These full-value helpers construct and validate an explicitly requested audit
projection from independently retained facts. They are not a journal writer or
a participant protocol: live admission uses workflow_journal and its partitioned
owner journals. Materialize complete views only for explicit inspection, never
after each accepted child or at every participating owner.

Owner-native final settlement of admitted work, separate from driver requests.

This complete-input reference models exact custody joins and immutable receipts.
Native authorization, observation, authentication and durable atomic retention
remain independent owner responsibilities. Transport bytes cannot select this path.
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


def _evidence_context(completion: dict[str, Any], workflow: dict[str, Any]) -> dict[str, Any]:
    """Adapt protected native evidence for common joins, never for transport admission."""
    return {
        **completion,
        "phase": PHASES[workflow["type"]][-1],
        "transfer_completion": None,
    }


def validate_native_completion(
    completion: dict[str, Any],
    workflow: dict[str, Any],
    *,
    before_generation: int | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Validate new or retained native evidence without granting native authority."""
    from .workflow_evidence import validate_phase_evidence

    validate("workflow.schema.json", completion, "NativeCompletion")
    validate_phase_evidence(
        _evidence_context(completion, workflow),
        workflow,
        authority="native-owner",
        before_generation=before_generation,
        recovery_readers=recovery_readers,
    )


def record_native_completion_view(
    completion: dict[str, Any],
    workflow: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    native_authorized: bool,
    verified_phase_evidence: dict[str, Any] | None = None,
    now: str | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Retain terminal facts without new work, transfer progress or hold release.

    expected_owner, native_authorized and verified_phase_evidence are selected by
    protected current owner state, never by a transport caller. The owner verifies
    complete successful child outcomes and all final native obligations first.
    Exact accepted replay skips fresh observation, but not current native authority.
    """
    from .handoffs import validate_workflow
    from .workflow_bindings import require_bound_phase
    from .workflow_evidence import require_verified_phase_evidence
    from .workflow_preparation import validate_workflow_agreement
    from .workflows import retained_transition_input

    validate("workflow.schema.json", completion, "NativeCompletion")
    validate_workflow(workflow, recovery_readers=recovery_readers)
    _require(native_authorized is True, "current owner-native completion authority required")
    _require(
        completion["owner"] == workflow["owner"] == expected_owner
        and completion["workflow_id"] == workflow["id"],
        "native workflow completion receiver changed",
    )
    for receipt in workflow["advances"]:
        original = retained_transition_input(receipt)
        if original["advance_id"] == completion["advance_id"]:
            _require(
                receipt["authority"] == "native-owner",
                "workflow transition identity changed authority",
            )
            _require(original == completion, "accepted native completion input changed")
            return copy.deepcopy(workflow)
    _require(
        workflow["state"] in {"active", "paused"}
        and workflow["phase"] == PHASES[workflow["type"]][-2],
        "native completion requires the active or paused final installed transition",
    )
    _require(
        workflow.get("recovery", {}).get("phase", "committed") == "committed",
        "workflow recovery preparation is not committed",
    )
    _require(
        completion["expected_generation"] == workflow["generation"] < 9007199254740991
        and completion["driver_term"] == workflow["driver_term"],
        "native completion generation or observed driver term changed",
    )
    validate_workflow_agreement(workflow, require_complete=True)
    require_bound_phase(workflow, workflow["phase"])
    validate_native_completion(completion, workflow, recovery_readers=recovery_readers)
    require_verified_phase_evidence(
        _evidence_context(completion, workflow), verified_phase_evidence, now=now
    )
    result = copy.deepcopy(workflow)
    result["generation"] += 1
    result["phase"] = PHASES[result["type"]][-1]
    result["state"] = "completed"
    result["advances"].append(
        {
            "authority": "native-owner",
            "completion": copy.deepcopy(completion),
            "completion_digest": digest(completion),
            **{key: result[key] for key in ("generation", "driver_term", "phase", "state")},
        }
    )
    validate_workflow(result, recovery_readers=recovery_readers)
    return result
