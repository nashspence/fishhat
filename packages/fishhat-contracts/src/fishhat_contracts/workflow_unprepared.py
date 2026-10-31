"""Complete shared workflow inspection models; no live owner admission.

These full-value helpers construct and validate an explicitly requested audit
projection from independently retained facts. They are not a journal writer or
a participant protocol: live admission uses workflow_journal and its partitioned
owner journals. Materialize complete views only for explicit inspection, never
after each accepted child or at every participating owner.

Positive retirement of an initial participant with no accepted preparation.

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


def _request_commitment(
    owner: dict[str, Any],
    origin: dict[str, Any],
    custody: dict[str, Any] | None,
    proposal_digest: str,
) -> str:
    """Bind every closed request field through the complete canonical proposal digest."""
    return digest(
        {
            "owner": owner,
            "origin": origin,
            "phase": "retire-unprepared",
            "custody": custody,
            "proposal_digest": proposal_digest,
        }
    )


def _proposal_binding(
    proof: dict[str, Any],
    workflow_id: str,
    proposal_digest: str,
    local: list[dict[str, Any]],
) -> None:
    """Join an already validated proof to internally derived original proposal facts."""
    _require(
        bool(local)
        and proof["workflow_id"] == workflow_id
        and proof["proposal_digest"] == proposal_digest
        and proof["participants_digest"] == digest(local),
        "unprepared retirement changed original proposal or local child closure",
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
    _require(
        proof["request_commitment"]
        == _request_commitment(owner, origin, custody, proof["proposal_digest"]),
        "unprepared retirement input changed",
    )
    if proposal is None:
        return
    local = [p for p in proposal["participants"] if p["owner"] == origin]
    _proposal_binding(proof, proposal["workflow_id"], digest(proposal), local)


def retire_unprepared_workflow_view(
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
    commitment = _request_commitment(
        request["owner"], request["origin"], request["custody"], digest(proposal)
    )
    if retained is not None:
        validate_never_prepared(retained, proposal=proposal, expected_owner=expected_owner)
        _require(retained["request_commitment"] == commitment, "accepted retirement input changed")
        return copy.deepcopy(retained)
    _require(proposal == verified_proposal, "unprepared proposal is not independently verified")
    validate_workflow_proposal(proposal)
    _require(verified_never_prepared is True, "positive never-prepared proof required")
    _require(
        verified_no_child_admission is True, "accepted child requires retained-origin recovery"
    )
    validate_never_prepared(verified_proof, proposal=proposal, expected_owner=expected_owner)
    _require(
        verified_proof["request_commitment"] == commitment,
        "independently verified retirement changed input",
    )
    return copy.deepcopy(verified_proof)
