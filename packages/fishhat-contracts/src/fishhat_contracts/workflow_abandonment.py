"""Complete shared workflow inspection models; no live owner admission.

These full-value helpers construct and validate an explicitly requested audit
projection from independently retained facts. They are not a journal writer or
a participant protocol: live admission uses workflow_journal and its partitioned
owner journals. Materialize complete views only for explicit inspection, never
after each accepted child or at every participating owner.

Explicitly abandon unused successor selection without reopening old authority.

The caller supplies independently authenticated current receiving context. The
reference model does not prove the native negative fact that no successor child
was accepted, nor atomic admission fencing or durable reservation replacement.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any

from .history import validate_owner_custody
from .validation import ContractError, canonical, digest, validate
from .workflow_unprepared import origin_workflow_id


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _logical(owner: dict[str, Any]) -> tuple[str, str]:
    return owner["tool"], owner["id"]


def recovery_selection(proposal: dict[str, Any]) -> dict[str, Any]:
    """Name retained complete proposal custody without recursively embedding it."""
    return {
        "workflow_id": proposal["workflow_id"],
        "recovery_id": proposal["recovery_id"],
        "proposal_digest": digest(proposal),
        "original_workflow_id": origin_workflow_id(proposal["origins"][0]),
        "participants": copy.deepcopy(proposal["participants"]),
    }


def _selection_join(value: dict[str, Any], selection: dict[str, Any], owners: set[bytes]) -> None:
    """Join one proof to an already validated selection and its complete owner set."""
    _require(
        canonical(value["origin"]) in owners
        and value["workflow_id"] == selection["workflow_id"]
        and value["recovery_id"] == selection["recovery_id"]
        and value["proposal_digest"] == selection["proposal_digest"],
        "abandonment selected a different successor proposal",
    )


def validate_abandonment(value: dict[str, Any], *, selection: dict[str, Any] | None = None) -> None:
    """Check bounded proof joins, without authenticating its signer or native facts."""
    validate("workflow-recovery.schema.json", value, "Abandonment")
    owner, origin, custody = value["owner"], value["origin"], value["custody"]
    _require(_logical(owner) == _logical(origin), "abandonment changed logical owner")
    if owner == origin:
        _require(custody is None, "current abandonment substituted historical custody")
    else:
        _require(custody is not None, "historical abandonment lacks current custody")
        assert custody is not None
        validate_owner_custody(custody, expected_custodian=owner)
        _require(custody["origin"] == origin, "abandonment origin custody changed")
    witness = value["witness"]
    _require(
        witness["owner"] == owner
        and witness["kind"] == "approval"
        and witness["state"] == "workflow-supersession-abandoned"
        and witness["workflow_id"] == value["workflow_id"]
        and witness["subject_digest"] == digest({k: v for k, v in value.items() if k != "witness"}),
        "abandonment witness changed",
    )
    if selection is None:
        return
    validate("workflow-recovery.schema.json", selection, "Selection")
    _selection_join(value, selection, {canonical(p["owner"]) for p in selection["participants"]})


def validate_abandonment_closure(
    proposal: dict[str, Any], *, verified_abandonments: list[dict[str, Any]] | None = None
) -> None:
    """Require every current participant to close each selected unused successor."""
    current = {_logical(p["owner"]): p["owner"] for p in proposal["participants"]}
    expected_owners = {canonical(owner) for owner in current.values()}
    original_ids = {origin_workflow_id(o) for o in proposal["origins"]}
    origins = {canonical(p["origin"]) for p in proposal["participants"]}
    verified = (
        None
        if verified_abandonments is None
        else {canonical(proof) for proof in verified_abandonments}
    )
    selected: set[str] = set()
    for closure in proposal["abandonments"]:
        previous = closure["selection"]
        validate("workflow-recovery.schema.json", previous, "Selection")
        previous_owners = {canonical(p["owner"]) for p in previous["participants"]}
        _require(
            previous["workflow_id"] not in selected
            and previous["workflow_id"] != proposal["workflow_id"]
            and {previous["original_workflow_id"]} == original_ids
            and {canonical(p["origin"]) for p in previous["participants"]} == origins,
            "abandoned successor changed original lineage or identity",
        )
        selected.add(previous["workflow_id"])
        found: set[bytes] = set()
        for proof in closure["proofs"]:
            validate_abandonment(proof)
            _selection_join(proof, previous, previous_owners)
            owner = canonical(proof["owner"])
            _require(
                _logical(proof["owner"]) in current
                and proof["owner"] == current[_logical(proof["owner"])]
                and owner not in found,
                "abandonment owner closure changed",
            )
            if verified is not None:
                _require(
                    canonical(proof) in verified,
                    "successor abandonment is not independently authenticated",
                )
            found.add(owner)
        _require(
            found == expected_owners,
            "successor selection requires complete participant abandonment",
        )


def abandon_workflow_recovery_view(
    request: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    recovery_authorized: bool,
    verified_proposal: dict[str, Any],
    verified_abandonment: dict[str, Any],
    verified_no_child_admission: bool,
    retained: dict[str, Any] | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Return a retained local proof after positive native abandonment checks.

    Before producing verified_abandonment, the owner atomically closes all future
    preparation, commit, driver and child admission for this successor, including
    when it never prepared a capsule. It also keeps or completes original admission
    retirement and retains every ancestor hold/input and accepted replay result.
    Any accepted successor child forbids abandonment: recover the fully materialized
    successor instead. Absence from a client or restored journal is not proof.
    """
    from .workflow_recovery import _structure

    validate("workflow-recovery.schema.json", request, "AbandonRequest")
    _require(recovery_authorized is True, "current workflow recovery authority required")
    _require(request["owner"] == expected_owner, "workflow abandonment receiver changed")
    proposal = request["proposal"]
    if retained is not None:
        validate_abandonment(retained, selection=recovery_selection(proposal))
        _require(
            retained["owner"] == expected_owner and retained["request_digest"] == digest(request),
            "accepted abandonment input changed",
        )
        return copy.deepcopy(retained)
    _require(proposal == verified_proposal, "abandoned proposal is not independently selected")
    _structure(proposal, recovery_readers=recovery_readers)
    _require(verified_no_child_admission is True, "accepted successor child requires recovery")
    validate_abandonment(verified_abandonment, selection=recovery_selection(proposal))
    _require(
        verified_abandonment["owner"] == expected_owner
        and verified_abandonment["request_digest"] == digest(request),
        "independently verified abandonment changed receiver or input",
    )
    return copy.deepcopy(verified_abandonment)


def record_workflow_abandonment_view(
    workflow: dict[str, Any],
    proof: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Expose same-epoch abandonment without erasing accepted preparation/commit.

    A current custodian preserves a historical capsule unchanged and keeps its
    authenticated abandonment in current protected state instead. This transition
    models only a capsule still owned by its actual current receiving epoch.
    """
    from .handoffs import validate_workflow

    validate_workflow(workflow, recovery_readers=recovery_readers)
    custody = workflow.get("recovery")
    _require(custody is not None, "abandoned workflow has no successor preparation")
    assert custody is not None
    proposal = custody["request"]["proposal"]
    validate_abandonment(proof, selection=recovery_selection(proposal))
    _require(
        proof["request_digest"]
        == digest(
            {
                "owner": proof["owner"],
                "phase": "abandon",
                "proposal": proposal,
                "custody": proof["custody"],
            }
        ),
        "abandonment retained input changed",
    )
    _require(proof["owner"] == workflow["owner"], "historical capsule cannot be retargeted")
    if custody["abandonment"] is not None:
        _require(custody["abandonment"]["proof"] == proof, "accepted abandonment proof changed")
        return copy.deepcopy(workflow)
    _require(workflow["generation"] < 9007199254740991, "workflow generation exhausted")
    result = copy.deepcopy(workflow)
    result["generation"] += 1
    result["state"] = "cancelled"
    result["recovery"].update(
        phase="abandoned",
        abandonment={"proof": copy.deepcopy(proof), "generation": result["generation"]},
    )
    validate_workflow(result, recovery_readers=recovery_readers)
    return result
