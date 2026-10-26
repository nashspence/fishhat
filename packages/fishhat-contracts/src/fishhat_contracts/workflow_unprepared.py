"""Positive retirement of an initial participant with no accepted preparation.

Native owners establish the negative facts from authoritative protected history
after fencing execution. They permanently close old admission and preserve all
input/hold custody before supplying verified arguments or issuing a witness.
An absent client, timed-out request or restored empty journal supplies no proof.
"""

from __future__ import annotations

import copy
from typing import Any

from .history import validate_owner_custody
from .validation import ContractError, digest, validate


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def origin_owner(origin: dict[str, Any]) -> dict[str, Any]:
    return dict(
        origin["reference"]["owner"]
        if "reference" in origin
        else origin["never_prepared"]["origin"]
    )


def origin_workflow_id(origin: dict[str, Any]) -> str:
    return str(
        origin["reference"]["record"]["id"]
        if "reference" in origin
        else origin["never_prepared"]["workflow_id"]
    )


def origin_digest(origin: dict[str, Any]) -> str:
    return str(
        origin["reference"]["digest"] if "reference" in origin else digest(origin["never_prepared"])
    )


def validate_never_prepared(
    proof: dict[str, Any],
    *,
    proposal: dict[str, Any] | None = None,
    expected_owner: dict[str, Any] | None = None,
) -> None:
    """Check exact immutable proof joins, independently of native authentication."""
    validate("workflow-recovery.schema.json", proof, "NeverPrepared")
    owner, origin, custody = proof["owner"], proof["origin"], proof["custody"]
    _require(
        all(owner[k] == origin[k] for k in ("tool", "id"))
        and (expected_owner is None or owner == expected_owner),
        "unprepared retirement changed owner identity",
    )
    if owner == origin:
        _require(custody is None, "same-epoch unprepared retirement changed custody")
    else:
        _require(custody is not None, "historical unprepared retirement lacks custody")
        assert custody is not None
        validate_owner_custody(custody, expected_custodian=owner)
        _require(custody["origin"] == origin, "unprepared retirement changed original epoch")
    witness = proof["witness"]
    _require(
        witness["owner"] == owner
        and witness["workflow_id"] == proof["workflow_id"]
        and witness["kind"] == "approval"
        and witness["state"] == "workflow-never-prepared"
        and witness["subject_digest"] == digest({k: v for k, v in proof.items() if k != "witness"}),
        "unprepared retirement witness changed",
    )
    if proposal is None:
        return
    local = [p for p in proposal["participants"] if p["owner"] == origin]
    _require(
        bool(local)
        and proof["workflow_id"] == proposal["workflow_id"]
        and proof["proposal_digest"] == digest(proposal)
        and proof["participants_digest"] == digest(local),
        "unprepared retirement changed original proposal or local child closure",
    )
    request = {
        "owner": owner,
        "phase": "retire-unprepared",
        "origin": origin,
        "proposal": proposal,
        "custody": custody,
    }
    _require(proof["request_digest"] == digest(request), "unprepared retirement input changed")


def retire_unprepared_workflow(
    request: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    recovery_authorized: bool,
    verified_proposal: dict[str, Any],
    verified_proof: dict[str, Any],
    verified_never_prepared: bool,
    verified_no_child_admission: bool,
    retained: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return independently issued retirement or replay its exact durable proof.

    The native transaction retains the complete request, proof, native evidence and
    pre-preparation material/hold closure with permanent old workflow/child admission
    tombstones. verified_proposal comes from authenticated original participant
    custody; it is an initial proposal, not a selected recovery successor. The two
    verified facts and verified_proof are independently loaded protected context,
    never copies or flags supplied by the transport caller. A prior accepted capsule
    or child requires the ordinary retained-origin recovery path instead.
    """
    from .workflows import validate_workflow_proposal

    validate("workflow-recovery.schema.json", request, "RetireUnpreparedRequest")
    _require(recovery_authorized is True, "current unprepared-retirement authority required")
    _require(request["owner"] == expected_owner, "unprepared retirement receiver changed")
    proposal = request["proposal"]
    if retained is not None:
        validate_never_prepared(retained, proposal=proposal, expected_owner=expected_owner)
        _require(retained["request_digest"] == digest(request), "accepted retirement input changed")
        return copy.deepcopy(retained)
    _require(proposal == verified_proposal, "unprepared proposal is not independently verified")
    validate_workflow_proposal(proposal)
    _require(verified_never_prepared is True, "positive never-prepared proof required")
    _require(
        verified_no_child_admission is True, "accepted child requires retained-origin recovery"
    )
    validate_never_prepared(verified_proof, proposal=proposal, expected_owner=expected_owner)
    _require(
        verified_proof["request_digest"] == digest(request),
        "independently verified retirement changed input",
    )
    return copy.deepcopy(verified_proof)
