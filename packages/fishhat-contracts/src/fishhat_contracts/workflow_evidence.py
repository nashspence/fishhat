"""Exact workflow phase evidence joins, separate from native verification.

Installed obligations belong to workflow-evidence.schema.json and are included in
its immutable schema closure. This complete-input reference model does not
authenticate witnesses, inspect native state, revalidate freshness or retain
exclusion and material. Trusted evidence is supplied by that independent
receiving-owner boundary; request bytes never supply their own approval.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Literal

from .bounds import Bounds, bounds
from .handoffs import PHASES
from .operations import validate_operation_plan
from .validation import SCHEMAS, ContractError, digest, validate

REQUIREMENTS = SCHEMAS["workflow-evidence.schema.json"]["$defs"]["InstalledProcedureRequirements"][
    "const"
]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def phase_subject(transition: dict[str, Any], participant: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical signed preimage; it supplies no native authority."""
    return {
        "transition": transition,
        "participant": {key: value for key, value in participant.items() if key != "witness"},
    }


def _child_outcome(
    outcome: dict[str, Any],
    participant: dict[str, Any],
    binding: dict[str, Any],
    workflow: dict[str, Any],
    *,
    completion_required: bool,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
) -> None:
    from .workflows import bound_plan

    child, operation = outcome["child"], outcome["operation"]
    plan = bound_plan(binding)
    validate_operation_plan(operation, plan, recovery_readers=recovery_readers)
    _require(
        child == {"owner": participant["owner"], "request_id": binding["request_id"]}
        and plan["subject"]["resource"] == participant["resource"],
        "workflow phase child resource or identity changed",
    )
    if "completed" in binding:
        _require(
            operation == binding["completed"]["operation"],
            "workflow phase changed preserved completed child",
        )
    else:
        _require(
            operation["owner"] == child["owner"]
            and operation["request_id"] == child["request_id"]
            and operation["witness"]["workflow_id"] == workflow["id"],
            "workflow phase Operation changed child or workflow identity",
        )
    if completion_required or "completed" in binding:
        _require(
            operation["state"] == "succeeded" and operation["effect_certainty"] == "known",
            "workflow phase requires successful known child outcome",
        )
    else:
        _require(
            operation["state"] in {"accepted", "running", "waiting", "succeeded"}
            and operation["effect_certainty"] in {"none", "known"},
            "workflow phase cannot advance unresolved child work",
        )


@bounds(
    Bounds(
        id="workflow.phase-evidence",
        linear_proofs=("tests/test_linear_growth.py::test_phase_evidence_linear_work",),
        work="O(B + P + C + K) complete-input validation with hash-indexed structural uniqueness for fixed installed schema/phase closure; B serialized proposal/evidence/Plan bytes, P participants, C child slots and K retained bindings",
        extent="Every participant resource, every child started before the destination phase and every native evidence handle; no prefix selection or total-size cap",
        limits=(),
        capacity=("native owners may explicitly refuse capacity without truncating evidence",),
        proofs=(
            "tests/test_workflow_evidence.py::test_phase_evidence_checks_complete_child_extent",
        ),
    )
)
def validate_phase_evidence(
    request: dict[str, Any],
    workflow: dict[str, Any],
    *,
    authority: Literal["driver", "native-owner"] = "driver",
    before_generation: int | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Validate new or retained transition evidence without inventing observation.

    before_generation selects bindings already retained at a historical advance.
    Callers validate the enclosing capsule and its immutable advance receipts.
    Historical inspection does not reapply current native freshness or authority.
    Native settlement has a separately signed authority and can only finish the
    final adjacent phase; a driver request cannot claim that native path.
    """
    from .workflows import _pair, _request_key, proposal_children

    _require(
        request["owner"] == workflow["owner"] and request["workflow_id"] == workflow["id"],
        "workflow phase evidence receiver changed",
    )
    evidence = request["phase_evidence"]
    if request["transfer_completion"] is not None:
        _require(
            authority == "driver" and evidence is None,
            "transfer completion cannot supply procedure evidence or native authority",
        )
        return
    _require(evidence is not None, "workflow advance requires phase evidence")
    assert evidence is not None
    validate("workflow-evidence.schema.json", evidence, "PhaseEvidence")
    phases = PHASES[workflow["type"]]
    _require(request["phase"] in phases[1:], "workflow phase evidence destination changed")
    position = phases.index(request["phase"])
    _require(
        authority != "native-owner" or position == len(phases) - 1,
        "native workflow settlement requires terminal phase",
    )
    transition = evidence["transition"]
    _require(
        transition
        == {
            "authority": authority,
            **{
                key: request[key]
                for key in (
                    "owner",
                    "workflow_id",
                    "advance_id",
                    "expected_generation",
                    "driver_term",
                )
            },
            "proposal_digest": workflow["proposal_digest"],
            "procedure": workflow["type"],
            "requirements_digest": digest(REQUIREMENTS[workflow["type"]]),
            "from_phase": phases[position - 1],
            "to_phase": request["phase"],
        },
        "workflow phase evidence transition changed",
    )
    if before_generation is None:
        _require(
            transition["from_phase"] == workflow["phase"]
            and request["expected_generation"] == workflow["generation"]
            and request["driver_term"] == workflow["driver_term"],
            "workflow phase evidence does not follow current phase",
        )
    else:
        _require(
            request["expected_generation"] + 1 == before_generation,
            "workflow phase evidence historical generation changed",
        )
    selected = proposal_children(workflow["proposal"])
    ready = {
        key: binding
        for key, (_, binding) in selected.items()
        if "plan" in binding or "completed" in binding
    }
    for receipt in workflow["bindings"]:
        if before_generation is None or receipt["generation"] < before_generation:
            original = receipt["request"]
            child = original["child"]
            ready[_request_key(child["owner"], child["request_id"])] = original["binding"]
    participants = {
        _pair(p["owner"], p["resource"]): p for p in workflow["proposal"]["participants"]
    }
    found: set[bytes] = set()
    barriers = REQUIREMENTS[workflow["type"]]["child_completion"]
    for proof in evidence["participants"]:
        pair = _pair(proof["owner"], proof["resource"])
        _require(
            pair in participants and pair not in found, "workflow phase participant closure changed"
        )
        found.add(pair)
        participant = participants[pair]
        _require(
            proof["resource_generation"] >= participant["expected_generation"],
            "workflow phase resource generation regressed",
        )
        expected = {
            _request_key(participant["owner"], slot["request_id"]): slot
            for slot in participant["requests"]
            if phases.index(slot["phase"]) < position
        }
        outcomes: set[bytes] = set()
        for outcome in proof["operations"]:
            child = outcome["child"]
            key = _request_key(child["owner"], child["request_id"])
            _require(
                key in expected and key in ready and key not in outcomes,
                "workflow phase child outcome closure changed",
            )
            outcomes.add(key)
            _child_outcome(
                outcome,
                participant,
                ready[key],
                workflow,
                completion_required=position >= phases.index(barriers[expected[key]["phase"]]),
                recovery_readers=recovery_readers,
            )
        _require(outcomes == set(expected), "workflow phase missing required child outcome")
        identities: set[bytes] = set()
        for handle in proof["native_evidence"]:
            identity = _request_key(handle["owner"], handle["id"])
            _require(
                handle["owner"] == participant["owner"] and identity not in identities,
                "workflow phase native evidence custody changed",
            )
            identities.add(identity)
        witness = proof["witness"]
        _require(
            witness["owner"] == proof["owner"]
            and witness["generation"] == proof["resource_generation"]
            and witness["workflow_id"] == workflow["id"]
            and witness["kind"] == "approval"
            and witness["state"] == "workflow-phase-verified"
            and witness["evidence_digests"] == []
            and witness["subject_digest"] == digest(phase_subject(transition, proof)),
            "workflow phase witness preimage changed",
        )
    _require(found == set(participants), "workflow phase missing participant evidence")


def require_verified_phase_evidence(
    request: dict[str, Any], verified_phase_evidence: dict[str, Any] | None
) -> None:
    """Require independently authenticated, current native evidence for a new advance.

    Equality is only a context join. It does not perform the native verification
    that the receiving owner must complete before supplying this argument.
    Exact accepted replays bypass this new-admission check.
    """
    _require(
        request["phase_evidence"] == verified_phase_evidence
        and (request["transfer_completion"] is not None or verified_phase_evidence is not None),
        "workflow phase evidence is not independently verified",
    )
