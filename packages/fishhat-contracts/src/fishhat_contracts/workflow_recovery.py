"""Explicit successor workflow custody; no native retirement or authorization.

Every verified argument is independently selected protected receiving context.
Preparing a successor requires positive old-admission retirement and native
cessation, not merely an absent request, an expired Plan or a restored epoch.
The original capsule and accepted outcomes remain immutable recovery evidence.
"""

from __future__ import annotations

import copy
from collections import ChainMap
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .bounds import Bounds, bounds
from .history import validate_owner_custody
from .record_delivery import validate_record_payload
from .validation import ContractError, canonical, digest, validate, validate_plan
from .workflow_unprepared import (
    _proposal_binding,
    origin_digest,
    origin_owner,
    origin_workflow_id,
    validate_never_prepared,
)
from .workflows import (
    _child_identity_matches,
    _pair,
    _request_key,
    bound_plan,
    child_action,
    prepared_capsule,
    proposal_children,
    retained_transition_input,
    validate_workflow_proposal,
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _key(reference: dict[str, Any]) -> bytes:
    return _request_key(reference["owner"], reference["request_id"])


def _record_schema(reference: dict[str, Any], kind: str) -> None:
    validate("common.schema.json", reference, "RecordReference")
    _require(
        reference["record"]["kind"] == kind
        and reference["schema"]["uri"]
        == f"https://fishhat.invalid/contracts/records.schema.json#/$defs/{kind}",
        "workflow recovery record kind or schema URI changed",
    )


def _recovery_record(
    reference: dict[str, Any],
    record: dict[str, Any],
    kind: str,
    *,
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
) -> dict[str, Any]:
    """Read exact original bytes under independently installed recovery semantics.

    Inspection support alone never qualifies historical evidence for recovery.
    The receiving owner installs each recovery reader for one exact URI and
    closure digest after establishing compatible v1 meanings and preserved
    guarantees. It may validate, but never translate or rewrite, original bytes.
    Current v1 semantic checks remain required after that independent reader.
    This context provides neither record authentication nor execution authority.
    """
    from .handoffs import schema_identity, validate_workflow
    from .operations import validate_operation

    _record_schema(reference, kind)
    schema = reference["schema"]
    current = schema == schema_identity(schema["uri"])
    reader = (
        None
        if recovery_readers is None
        else recovery_readers.get((schema["uri"], schema["digest"]))
    )
    _require(
        current or reader is not None,
        "unsupported workflow recovery schema: independently installed compatible v1 reader required",
    )
    original = canonical(record)
    result = validate_record_payload(
        reference,
        original,
        expected_owner=reference["owner"],
        retained_readers=retained_readers,
        recovery_readers=recovery_readers,
    )
    if not current:
        assert reader is not None
        reader(result)
        _require(canonical(result) == original, "workflow recovery reader changed original bytes")
        if kind == "Workflow":
            validate_workflow(result, recovery_readers=recovery_readers)
        else:
            validate_operation(result, recovery_readers=recovery_readers)
    return result


def _owners(proposal: dict[str, Any]) -> dict[bytes, dict[str, Any]]:
    participants = proposal["participants"]
    result = {canonical(p["origin"]): p["owner"] for p in participants}
    _require(len(result) == len(participants), "duplicate recovery origin participant")
    _require(
        len({canonical(p["owner"]) for p in participants}) == len(participants),
        "recovery current owner aliases another origin",
    )
    for participant in participants:
        _require(
            all(participant["origin"][k] == participant["owner"][k] for k in ("tool", "id")),
            "workflow recovery changed logical participant identity",
        )
    return result


def _structure(
    proposal: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    # Retained accepted lineage preserves its exact historical schema identities.
    # New recovery admission separately qualifies readers against protected state;
    # merely inspecting retained custody never reauthorizes its original inputs.
    for origin in proposal.get("origins", []):
        if isinstance(origin, dict) and isinstance(origin.get("reference"), dict):
            _record_schema(origin["reference"], "Workflow")
    for disposition in proposal.get("children", []):
        if not isinstance(disposition, dict):
            continue
        for name in ("operation", "recovery"):
            evidence = disposition.get(name)
            if isinstance(evidence, dict) and isinstance(evidence.get("reference"), dict):
                _record_schema(evidence["reference"], "Operation")
    validate("workflow-recovery.schema.json", proposal, "RecoveryProposal")
    validate_workflow_proposal(
        proposal["successor"], recovery=True, recovery_readers=recovery_readers
    )
    _require(
        proposal["workflow_id"] == proposal["successor"]["workflow_id"],
        "workflow recovery successor identity changed",
    )
    owners = _owners(proposal)
    origins = {canonical(origin_owner(o)): o for o in proposal["origins"]}
    _require(
        len(origins) == len(proposal["origins"]) and set(origins) == set(owners),
        "workflow recovery origin owner closure changed",
    )
    original_ids = {origin_workflow_id(o) for o in origins.values()}
    _require(
        len(original_ids) == 1 and proposal["workflow_id"] not in original_ids,
        "workflow recovery requires one distinct original workflow",
    )
    _require(any("reference" in o for o in origins.values()), "recovery lacks an original capsule")
    accepted_owners = {
        canonical(d["origin"]["owner"]) for d in proposal["children"] if d["kind"] != "unaccepted"
    }
    for key, origin in origins.items():
        if "never_prepared" in origin:
            validate_never_prepared(origin["never_prepared"], expected_owner=owners[key])
            _require(
                key not in accepted_owners,
                "unprepared origin cannot supply accepted child work",
            )
    children = proposal_children(proposal["successor"])
    old_identities = {
        (d["origin"]["owner"]["tool"], d["origin"]["owner"]["id"], d["origin"]["request_id"])
        for d in proposal["children"]
    }
    old_keys, new_keys = set(), set()
    for disposition in proposal["children"]:
        old, new = disposition["origin"], disposition["successor"]
        original_owner = canonical(old["owner"])
        _require(
            original_owner in owners and owners[original_owner] == new["owner"],
            "workflow recovery child custodian changed",
        )
        _require(
            _key(old) not in old_keys and _key(new) not in new_keys and _key(new) in children,
            "duplicate or absent workflow recovery child",
        )
        _require(
            (new["owner"]["tool"], new["owner"]["id"], new["request_id"]) not in old_identities,
            "recovery reused an old request identity",
        )
        old_keys.add(_key(old))
        new_keys.add(_key(new))
        replacement = children[_key(new)][1]
        completed = disposition["kind"] == "completed"
        _require(
            ("completed" in replacement) == completed,
            "workflow recovery changed completed-child disposition",
        )
        if completed:
            _require(
                replacement["completed"]["operation"] == disposition["operation"]["operation"],
                "workflow recovery substituted a completed outcome",
            )
    _require(new_keys == set(children), "workflow recovery omits a successor child")
    from .workflow_abandonment import validate_abandonment_closure

    validate_abandonment_closure(proposal)


def _origin_records(
    proposal: dict[str, Any],
    verified_origins: list[dict[str, Any]],
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
) -> dict[bytes, dict[str, Any]]:
    owners = _owners(proposal)
    trusted = {canonical(origin_owner(o)): o for o in verified_origins}
    _require(len(trusted) == len(verified_origins), "duplicate independently verified origin")
    result: dict[bytes, dict[str, Any]] = {}
    proposals: set[bytes] = set()
    for origin in proposal["origins"]:
        key = canonical(origin_owner(origin))
        if "never_prepared" in origin:
            _require(
                trusted.get(key) == origin,
                "unprepared retirement is not independently verified",
            )
            continue
        reference = origin["reference"]
        known = trusted.get(key)
        _require(
            known is not None and origin == {k: known[k] for k in ("reference", "custody")},
            "workflow recovery requires the independently selected latest origin",
        )
        assert known is not None
        current, custody = owners[key], origin["custody"]
        if current == reference["owner"]:
            _require(custody is None, "same-epoch recovery cannot substitute historical custody")
        else:
            _require(custody is not None, "historical workflow recovery lacks verified custody")
            assert custody is not None
            validate_owner_custody(custody, expected_custodian=current)
            _require(custody["origin"] == reference["owner"], "workflow recovery custody changed")
        record = _recovery_record(
            reference,
            known["record"],
            "Workflow",
            retained_readers=retained_readers,
            recovery_readers=recovery_readers,
        )
        _require(record["type"] == proposal["successor"]["type"], "recovery procedure changed")
        proposals.add(canonical(record["proposal"]))
        result[key] = record
    _require(len(proposals) == 1, "original participant proposals disagree")
    original = next(iter(result.values()))["proposal"]
    proposal_digest = digest(original)
    participants: dict[bytes, list[dict[str, Any]]] = {}
    for participant in original["participants"]:
        participants.setdefault(canonical(participant["owner"]), []).append(participant)
    for origin in proposal["origins"]:
        if "never_prepared" in origin:
            _proposal_binding(
                origin["never_prepared"],
                original["workflow_id"],
                proposal_digest,
                participants.get(canonical(origin_owner(origin)), []),
            )
    _require(
        {canonical(p["owner"]) for p in original["participants"]} == set(owners),
        "workflow recovery omits an original participant owner",
    )
    expected = {
        _pair(owners[canonical(p["owner"])], p["resource"]) for p in original["participants"]
    }
    actual = {_pair(p["owner"], p["resource"]) for p in proposal["successor"]["participants"]}
    _require(expected == actual, "workflow recovery changed participant resource closure")
    return result


def _ready(
    record: dict[str, Any], initial: dict[bytes, dict[str, Any]]
) -> Mapping[bytes, dict[str, Any]]:
    return ChainMap(
        {
            _key(receipt["request"]["child"]): receipt["request"]["binding"]
            for receipt in record["bindings"]
        },
        initial,
    )


def _same_child_operation(first: dict[str, Any], later: dict[str, Any]) -> None:
    _require(
        all(
            first[name] == later[name]
            for name in (
                "owner",
                "id",
                "request_id",
                "plan_digest",
                "subject",
                "authenticated_principal",
                "claimed_actor",
            )
        ),
        "retained workflow child Operation identity changed",
    )


def _retained_acceptance(
    records: Mapping[bytes, dict[str, Any]],
    children: Mapping[bytes, tuple[dict[str, Any], dict[str, Any]]],
) -> tuple[dict[bytes, dict[str, Any]], dict[bytes, dict[str, Any]]]:
    """Index facts in every verified origin, including another owner's capsule.

    Absence here is not evidence of nonacceptance. Native retirement still proves
    the latest disposition independently. Logical completed-slot references keep
    their original Operation epoch and request identity, without retargeting it.
    """
    from .workflow_bindings import _predecessor

    accepted: dict[bytes, dict[str, Any]] = {}
    succeeded: dict[bytes, dict[str, Any]] = {}

    def remember(key: bytes, operation: dict[str, Any]) -> None:
        _require(key in children, "retained Operation outside original workflow child closure")
        if key in accepted:
            _same_child_operation(accepted[key], operation)
        else:
            accepted[key] = operation
        if operation["state"] == "succeeded":
            _require(
                key not in succeeded or succeeded[key] == operation,
                "retained workflow child successful outcome changed",
            )
            succeeded[key] = operation

    for key, (_, binding) in children.items():
        if "completed" in binding:
            remember(key, binding["completed"]["operation"])
    for record in records.values():
        for receipt in record["bindings"]:
            request = receipt["request"]
            slot = children[_key(request["child"])][1]
            key = _key(_predecessor(slot["intent"]))
            remember(key, request["predecessors"][0])
        for receipt in record["advances"]:
            evidence = retained_transition_input(receipt).get("phase_evidence")
            if evidence is not None:
                for participant in evidence["participants"]:
                    for outcome in participant["operations"]:
                        remember(_key(outcome["child"]), outcome["operation"])
    return accepted, succeeded


def _evidence(
    evidence: dict[str, Any],
    *,
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
) -> dict[str, Any]:
    reference, record = evidence["reference"], evidence["operation"]
    return _recovery_record(
        reference,
        record,
        "Operation",
        retained_readers=retained_readers,
        recovery_readers=recovery_readers,
    )


def _recovered_child(
    disposition: dict[str, Any],
    original: dict[str, Any],
    current_owner: dict[str, Any],
    origin: dict[str, Any],
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
) -> None:
    recovered = disposition["recovery"]
    operation = _evidence(
        recovered, retained_readers=retained_readers, recovery_readers=recovery_readers
    )
    plan = recovered["plan"]
    validate_plan(plan)
    scoped_action = "app.recover" if current_owner["tool"] == "app-ops" else "host.recover"
    _require(
        original["state"] in {"failed", "cancelled", "quarantined"}
        and operation["owner"] == plan["owner"] == current_owner
        and operation["id"] != original["id"]
        and operation["request_id"] != original["request_id"]
        and operation["plan_digest"] == plan["digest"]
        and operation["subject"] == plan["subject"]
        and operation["state"] == "succeeded"
        and operation["effect_certainty"] == "known"
        and plan["subject"]["action"] in {"operation.recover", scoped_action}
        and plan["subject"]["resource"] == original["subject"]["resource"]
        and plan["subject"]["arguments"]["operation_id"] == original["id"],
        "workflow failed child lacks exact successful current-authority recovery",
    )
    selected = plan["subject"]["arguments"]["origin"]
    if original["owner"] == current_owner:
        _require(selected is None, "current workflow recovery changed operation provenance")
    else:
        _require(
            selected is not None
            and origin["custody"] is not None
            and selected["custody_id"] == origin["custody"]["id"]
            and selected["reference"] == disposition["operation"]["reference"],
            "historical workflow child recovery substituted its origin",
        )


def _dispositions(
    proposal: dict[str, Any],
    records: dict[bytes, dict[str, Any]],
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
) -> None:
    original = next(iter(records.values()))["proposal"]
    original_children = proposal_children(original)
    successor_children = proposal_children(proposal["successor"])
    initial = {
        key: binding
        for key, (_, binding) in original_children.items()
        if "plan" in binding or "completed" in binding
    }
    ready = {owner: _ready(record, initial) for owner, record in records.items()}
    accepted, succeeded = _retained_acceptance(records, original_children)
    seen = {_key(d["origin"]) for d in proposal["children"]}
    _require(seen == set(original_children), "workflow recovery omits original child disposition")
    mapped = {_key(d["origin"]): d["successor"] for d in proposal["children"]}
    target = {
        role: (
            [mapped[_key(item)] for item in reference]
            if isinstance(reference, list)
            else mapped[_key(reference)]
        )
        for role, reference in original["target"].items()
    }
    _require(proposal["successor"]["target"] == target, "workflow recovery changed target lineage")
    origins = {canonical(origin_owner(o)): o for o in proposal["origins"]}
    for disposition in proposal["children"]:
        old, new = disposition["origin"], disposition["successor"]
        participant, old_slot = original_children[_key(old)]
        new_participant, new_slot = successor_children[_key(new)]
        _require(
            participant["resource"] == new_participant["resource"]
            and old_slot["phase"] == new_slot["phase"]
            and child_action(old_slot) == child_action(new_slot),
            "workflow recovery changed child procedure role",
        )
        key = _key(old)
        if disposition["kind"] == "unaccepted":
            _require(
                key not in accepted, "retained accepted workflow child cannot become unaccepted"
            )
        if key in succeeded:
            _require(
                disposition["kind"] == "completed",
                "retained successful workflow child requires completed disposition",
            )
        owner = canonical(old["owner"])
        if owner not in ready:
            _require(disposition["kind"] == "unaccepted", "unprepared origin has accepted child")
            continue
        binding = ready[owner].get(key)
        if disposition["kind"] == "unaccepted":
            _require(
                binding is None or "completed" not in binding,
                "previously completed child cannot become unaccepted",
            )
            continue
        _require(binding is not None, "accepted child lacks its exact retained Plan")
        assert binding is not None
        plan = bound_plan(binding)
        operation = _evidence(
            disposition["operation"],
            retained_readers=retained_readers,
            recovery_readers=recovery_readers,
        )
        if key in accepted:
            _same_child_operation(accepted[key], operation)
        if key in succeeded:
            _require(
                operation == succeeded[key],
                "recovery changed retained successful workflow child outcome",
            )
        _require(
            _child_identity_matches(operation, old, binding, original["workflow_id"])
            and operation["plan_digest"] == plan["digest"]
            and operation["subject"] == plan["subject"],
            "workflow recovery substituted original child work",
        )
        if disposition["kind"] == "completed":
            _require(new_slot["completed"]["plan"] == plan, "completed child Plan changed")
        else:
            _recovered_child(
                disposition,
                operation,
                new["owner"],
                origins[canonical(old["owner"])],
                retained_readers,
                recovery_readers,
            )


@bounds(
    Bounds(
        id="workflow.recovery-proposal",
        work="O(B) complete proposal, independently verified origins and retained evidence bytes for fixed installed schema/phase closure; per-call child, owner, preparation and abandonment indexes preserve complete joins",
        extent="Every original/current owner, resource, child, retained acceptance/success, preparation and abandonment, including positive never-prepared proofs and recovered origin custody; no prefix selection or total-size cap",
        limits=(),
        capacity=(
            "native owners may refuse new recovery capacity without discarding accepted custody",
        ),
        proofs=(
            "tests/test_workflow_validation_growth.py::test_recovery_validation_linear_child_and_binding_work",
            "tests/test_workflow_validation_growth.py::test_recovery_validation_linear_unprepared_owner_work",
            "tests/test_workflow_validation_growth.py::test_retained_recovery_preparations_linear_owner_work",
            "tests/test_workflow_abandonment.py::test_recovery_abandonment_linear_owner_and_selection_work",
        ),
        linear_proofs=(
            "tests/test_workflow_validation_growth.py::test_recovery_validation_linear_child_and_binding_work",
            "tests/test_workflow_validation_growth.py::test_recovery_validation_linear_unprepared_owner_work",
            "tests/test_workflow_validation_growth.py::test_retained_recovery_preparations_linear_owner_work",
            "tests/test_workflow_abandonment.py::test_recovery_abandonment_linear_owner_and_selection_work",
        ),
    )
)
def validate_recovery_proposal(
    proposal: dict[str, Any],
    *,
    verified_origins: list[dict[str, Any]],
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Check exact latest protected origin joins, without proving native retirement."""
    _structure(proposal, recovery_readers=recovery_readers)
    records = _origin_records(proposal, verified_origins, retained_readers, recovery_readers)
    _dispositions(proposal, records, retained_readers, recovery_readers)


@dataclass(frozen=True)
class _PreparationIndex:
    proposal_digest: str
    owners: dict[bytes, tuple[dict[str, Any], str, str]]


def _preparation_index(proposal: dict[str, Any]) -> _PreparationIndex:
    origins = {canonical(origin_owner(o)): origin_digest(o) for o in proposal["origins"]}
    children: dict[bytes, list[dict[str, Any]]] = {}
    for disposition in proposal["children"]:
        children.setdefault(canonical(disposition["origin"]["owner"]), []).append(disposition)
    owners = {}
    for participant in proposal["participants"]:
        key = canonical(participant["origin"])
        owners[canonical(participant["owner"])] = (
            participant["origin"],
            origins[key],
            digest(children.get(key, [])),
        )
    return _PreparationIndex(digest(proposal), owners)


def _preparation(
    value: dict[str, Any],
    proposal: dict[str, Any],
    index: _PreparationIndex | None = None,
) -> None:
    validate("workflow-recovery.schema.json", value, "Preparation")
    if index is None:
        index = _preparation_index(proposal)
    owner, retirement, witness = value["owner"], value["retirement"], value["witness"]
    expected = index.owners.get(canonical(owner))
    _require(expected is not None, "supersession preparation owner outside closure")
    assert expected is not None
    origin, original_digest, children_digest = expected
    _require(
        value["recovery_id"] == proposal["recovery_id"]
        and value["proposal_digest"] == index.proposal_digest
        and retirement["owner"] == owner
        and retirement["origin"] == origin
        and retirement["recovery_id"] == value["recovery_id"]
        and retirement["proposal_digest"] == value["proposal_digest"]
        and retirement["origin_digest"] == original_digest
        and retirement["children_digest"] == children_digest,
        "supersession retirement preimage changed",
    )
    _require(
        witness["owner"] == owner
        and witness["kind"] == "approval"
        and witness["state"] == "workflow-supersession-prepared"
        and witness["workflow_id"] == proposal["workflow_id"]
        and witness["subject_digest"] == digest({k: v for k, v in value.items() if k != "witness"}),
        "supersession preparation witness changed",
    )


def _preparation_closure(values: list[dict[str, Any]], proposal: dict[str, Any]) -> set[bytes]:
    index = _preparation_index(proposal)
    found: set[bytes] = set()
    for value in values:
        _preparation(value, proposal, index)
        owner = canonical(value["owner"])
        _require(owner not in found, "duplicate supersession preparation owner")
        found.add(owner)
    return found


def validate_recovery_custody(
    workflow: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Validate discoverable immutable lineage without reauthorizing historical inputs."""
    custody = workflow.get("recovery")
    if custody is None:
        return
    validate("workflow-recovery.schema.json", custody, "RecoveryCustody")
    request = custody["request"]
    proposal = request["proposal"]
    _structure(proposal, recovery_readers=recovery_readers)
    _require(
        request["owner"] == workflow["owner"]
        and custody["request_digest"] == digest(request)
        and proposal["successor"] == workflow["proposal"]
        and proposal["workflow_id"] == workflow["id"],
        "retained workflow recovery input changed",
    )
    found = _preparation_closure(custody["preparations"], proposal)
    _require(canonical(workflow["owner"]) in found, "local supersession preparation missing")
    abandoned = custody["abandonment"]
    if custody["phase"] == "abandoned":
        from .workflow_abandonment import recovery_selection, validate_abandonment

        _require(abandoned is not None, "abandoned successor lacks its retained proof")
        assert abandoned is not None
        validate_abandonment(abandoned["proof"], selection=recovery_selection(proposal))
        _require(
            abandoned["proof"]["owner"] == workflow["owner"]
            and abandoned["generation"] <= workflow["generation"]
            and workflow["state"] == "cancelled",
            "abandoned successor revived or changed custody",
        )
    else:
        _require(abandoned is None, "successor discarded abandonment status")
    if custody["commit"] is None:
        _require(
            found == {canonical(workflow["owner"])}
            and (
                (
                    custody["phase"] == "prepared"
                    and workflow["generation"] == 0
                    and workflow["state"] == "prepared"
                )
                or (
                    custody["phase"] == "abandoned"
                    and abandoned is not None
                    and abandoned["generation"] == 1
                )
            )
            and workflow["phase"] == "prepared"
            and workflow["driver_term"] == 1
            and not workflow["bindings"]
            and not workflow["advances"]
            and workflow["transfer"] is None,
            "uncommitted supersession became executable or lost local custody",
        )
        return
    receipt = custody["commit"]
    _require(custody["phase"] in {"committed", "abandoned"}, "committed supersession phase changed")
    original = receipt["request"]
    _require(
        original["expected_generation"] == 0 and receipt["generation"] == 1,
        "retained recovery commit must be the first successor generation",
    )
    _require(
        found == {canonical(p["owner"]) for p in proposal["participants"]}
        and original["preparations"] == custody["preparations"]
        and original["owner"] == workflow["owner"]
        and original["workflow_id"] == workflow["id"]
        and original["recovery_id"] == proposal["recovery_id"]
        and original["proposal_digest"] == digest(proposal)
        and receipt["request_digest"] == digest(original)
        and original["expected_generation"] + 1 == receipt["generation"] <= workflow["generation"]
        and (abandoned is None or receipt["generation"] < abandoned["generation"]),
        "committed supersession closure or retained outcome changed",
    )


def prepare_workflow_recovery(
    request: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    recovery_authorized: bool,
    verified_proposal: dict[str, Any],
    verified_origins: list[dict[str, Any]],
    verified_preparation: dict[str, Any],
    verified_content: list[dict[str, Any]],
    retained_preparation: dict[str, Any] | None,
    reserved_successor: dict[str, Any] | None,
    verified_abandonments: list[dict[str, Any]],
    local_abandonments: list[dict[str, Any]],
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Model atomic successor preparation after independent local retirement.

    verified_proposal includes current scoped approval, driver agreement, selected
    adapters and every new Plan. verified_preparation comes from protected native
    retirement, positive disposition checks and durable input/hold custody. None
    may be populated by trusting request fields. The native transaction records
    old-identity admission tombstones, an exclusive reservation of the original
    lineage to this exact successor and this discoverable capsule together.
    retained_preparation is the exact historical preparation resolved by queried
    successor identity before considering current selection. reserved_successor
    is loaded by original lineage, never merely by the new ID. They remain
    separate after an abandoned predecessor is replaced by a new selection.
    local_abandonments contains protected tombstones even when this receiver
    never prepared a capsule for the abandoned successor.
    A different reserved successor requires complete authenticated abandonment.
    Preparation does not admit any Plan; stale Plans/preconditions remain stale
    and normal child admission rejects them. Materializing an agreed partial
    successor does not depend on keeping its original Plans fresh.
    Restored absence, expired input and a failed transfer never establish that an
    old request was unaccepted or that a dispatched native effect has ceased.
    Noncurrent record closures additionally require independently installed
    recovery_readers keyed by exact schema URI and digest; ordinary inspection
    readers alone cannot qualify recovery. No reader may rewrite original bytes.
    """
    from .handoffs import validate_workflow

    validate("workflow-recovery.schema.json", request, "PrepareRequest")
    _require(recovery_authorized is True, "current workflow recovery authority required")
    _require(request["owner"] == expected_owner, "workflow recovery receiver changed")
    if retained_preparation is not None:
        validate_workflow(retained_preparation, recovery_readers=recovery_readers)
        _require(
            retained_preparation["owner"] == expected_owner
            and retained_preparation.get("recovery", {}).get("request") == request,
            "accepted workflow recovery preparation input changed",
        )
        return copy.deepcopy(retained_preparation)
    if reserved_successor is not None:
        from .workflow_abandonment import recovery_selection

        validate_workflow(reserved_successor, recovery_readers=recovery_readers)
        _require(
            all(reserved_successor["owner"][k] == expected_owner[k] for k in ("tool", "id")),
            "reserved successor belongs to a different receiving owner",
        )
        previous = reserved_successor.get("recovery", {}).get("request")
        _require(previous is not None, "reserved successor lacks exact accepted preparation")
        assert previous is not None
        if previous == request:
            _require(reserved_successor["owner"] == expected_owner, "recovery replay owner changed")
            return copy.deepcopy(reserved_successor)
        selected = recovery_selection(previous["proposal"])
        _require(
            any(a["selection"] == selected for a in request["proposal"]["abandonments"]),
            "original lineage is reserved by another successor",
        )
    proposal = request["proposal"]
    from .workflow_abandonment import validate_abandonment, validate_abandonment_closure

    for abandoned in local_abandonments:
        validate_abandonment(abandoned)
        _require(abandoned["owner"] == expected_owner, "local abandonment custodian changed")
        _require(
            abandoned["workflow_id"] != proposal["workflow_id"]
            and abandoned["recovery_id"] != proposal["recovery_id"],
            "abandoned successor cannot prepare again",
        )
    _require(proposal == verified_proposal, "successor proposal is not independently reviewed")
    validate_recovery_proposal(
        proposal,
        verified_origins=verified_origins,
        retained_readers=retained_readers,
        recovery_readers=recovery_readers,
    )
    validate_abandonment_closure(proposal, verified_abandonments=verified_abandonments)
    _preparation(verified_preparation, proposal)
    _require(verified_preparation["owner"] == expected_owner, "local retirement owner changed")
    local = [h for h in proposal["successor"]["content"] if h["owner"] == expected_owner]
    content = {canonical(h) for h in verified_content}
    _require(
        all(canonical(h) in content for h in local), "successor local material custody incomplete"
    )
    result = prepared_capsule(proposal["successor"], expected_owner)
    result["recovery"] = {
        "phase": "prepared",
        "request": copy.deepcopy(request),
        "request_digest": digest(request),
        "preparations": [copy.deepcopy(verified_preparation)],
        "commit": None,
        "abandonment": None,
    }
    validate_workflow(result, recovery_readers=recovery_readers)
    return result


def commit_workflow_recovery(
    request: dict[str, Any],
    workflow: dict[str, Any],
    *,
    recovery_authorized: bool,
    verified_preparations: list[dict[str, Any]],
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Model one local commit after authentication of complete current-owner closure."""
    from .handoffs import validate_workflow

    validate("workflow-recovery.schema.json", request, "CommitRequest")
    _require(recovery_authorized is True, "current workflow recovery authority required")
    validate_workflow(workflow, recovery_readers=recovery_readers)
    custody = workflow.get("recovery")
    _require(custody is not None, "workflow has no supersession preparation")
    assert custody is not None
    proposal = custody["request"]["proposal"]
    _require(
        request["owner"] == workflow["owner"]
        and request["workflow_id"] == workflow["id"]
        and request["recovery_id"] == proposal["recovery_id"]
        and request["proposal_digest"] == digest(proposal),
        "workflow recovery commit identity changed",
    )
    if custody["commit"] is not None:
        _require(custody["commit"]["request"] == request, "accepted recovery commit input changed")
        return copy.deepcopy(workflow)
    _require(custody["phase"] == "prepared", "abandoned successor cannot commit")
    _require(
        request["expected_generation"] == workflow["generation"] < 9007199254740991,
        "workflow recovery commit generation changed",
    )
    values = request["preparations"]
    verified = {canonical(p) for p in verified_preparations}
    _require(
        all(canonical(p) in verified for p in values),
        "supersession preparation is not authenticated",
    )
    found = _preparation_closure(values, proposal)
    _require(
        found == {canonical(p["owner"]) for p in proposal["participants"]},
        "supersession commit lacks complete participant retirement",
    )
    local = next(p for p in values if p["owner"] == workflow["owner"])
    _require(local == custody["preparations"][0], "supersession local preparation changed")
    result = copy.deepcopy(workflow)
    result["generation"] += 1
    result["recovery"].update(
        phase="committed",
        preparations=copy.deepcopy(values),
        commit={
            "request": copy.deepcopy(request),
            "request_digest": digest(request),
            "generation": result["generation"],
        },
    )
    validate_workflow(result, recovery_readers=recovery_readers)
    return result
