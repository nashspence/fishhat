"""Complete valid workflow inputs; construction is outside measured validation work."""

from __future__ import annotations

import copy
from collections import Counter

from fishhat_contracts import workflow_bindings, workflow_recovery, workflow_unprepared, workflows
from fishhat_contracts.handoffs import validate_workflow
from fishhat_contracts.record_delivery import RecordSnapshot
from fishhat_contracts.validation import canonical, digest

from tests.test_contracts import uid
from tests.test_owner_handoffs import rebind_workflow_proposal, workflow
from tests.test_workflow_continuations import bind_request, move, prepare, successful


def chain(count, *, bound):
    """One initial Plan and a complete causal chain of reviewed successor slots."""
    proposal = workflow()["proposal"]
    participant = proposal["participants"][0]
    first = participant["requests"][0]
    for index in range(count):
        previous = participant["requests"][-1]
        participant["requests"].append(
            {
                "request_id": uid(f"growth-child-{index}"),
                "phase": "host-effect",
                "intent": {
                    "kind": "reviewed-successor",
                    "predecessor": {
                        "owner": participant["owner"],
                        "request_id": previous["request_id"],
                    },
                    "subject": copy.deepcopy(first["plan"]["subject"]),
                },
            }
        )
    value = move(prepare(proposal), "host-effect")
    if bound:
        previous = first
        for index, slot in enumerate(participant["requests"][1:]):
            operation = successful(
                {"owner": participant["owner"], "request_id": previous["request_id"]},
                previous,
                generation=10 + index,
                workflow_id=value["id"],
            )
            request = bind_request(
                value,
                {**participant, "requests": [slot]},
                first["plan"]["subject"],
                operation,
                generation=10 + index,
            )
            value["generation"] += 1
            value["bindings"].append(
                {
                    "request": request,
                    "request_digest": digest(request),
                    "generation": value["generation"],
                }
            )
            previous = request["binding"]
    validate_workflow(value)
    return value


def count_child_indexes(patch):
    """Observe actual complete indexes without replacing or truncating their results."""
    counts = Counter(index_builds=0, indexed_children=0)

    def observed(original):
        def counted(proposal):
            children = original(proposal)
            counts["index_builds"] += 1
            counts["indexed_children"] += len(children)
            return children

        return counted

    for module in (workflow_bindings, workflow_recovery, workflows):
        patch.setattr(module, "proposal_children", observed(module.proposal_children))
    return counts


def unprepared_owners(count):
    """One real local preparation and complete signed retirements from all other owners."""
    from tests.test_workflow_initial_custody import retirement
    from tests.test_workflow_recovery import scenario

    original = workflow()
    template = original["participants"][0]
    for index in range(count):
        participant = copy.deepcopy(template)
        participant["owner"]["id"] = uid(f"unprepared-owner-{index}")
        participant["resource"]["id"] = f"unprepared-host-{index}"
        participant["request_ids"] = [uid(f"unprepared-request-{index}")]
        original["participants"].append(participant)
    rebind_workflow_proposal(original)
    validate_workflow(original)
    proofs = {}
    for participant in original["proposal"]["participants"][1:]:
        _, proof = retirement(
            original["proposal"], participant["owner"], participant["owner"], None
        )
        proofs[canonical(participant["owner"])] = proof
    proposal, records = scenario(original=original, never_prepared=proofs)
    reference = RecordSnapshot(original, uid("only-prepared-origin")).reference
    records[0] = {"reference": reference, "custody": None, "record": original}
    proposal["origins"][0] = {"reference": reference, "custody": None}
    return proposal, records


def count_recovery_joins(patch):
    """Count full proposal hashes and the ordered local closures actually traversed."""
    counts = Counter(
        original_proposal_hashes=0,
        original_participants_hashed=0,
        recovery_proposal_hashes=0,
        recovery_participants_hashed=0,
        unprepared_local_participants=0,
        preparation_indexes=0,
        preparation_owners_indexed=0,
    )

    def observed_digest(original):
        def counted(value):
            if isinstance(value, dict):
                if value.get("format") == "deployment-ops/workflow-proposal/v1":
                    counts["original_proposal_hashes"] += 1
                    counts["original_participants_hashed"] += len(value["participants"])
                elif value.get("format") == "deployment-ops/workflow-recovery/v1":
                    counts["recovery_proposal_hashes"] += 1
                    counts["recovery_participants_hashed"] += len(value["participants"])
            return original(value)

        return counted

    for module in (workflow_recovery, workflow_unprepared):
        patch.setattr(module, "digest", observed_digest(module.digest))
    original_binding = workflow_recovery._proposal_binding

    def bind(proof, workflow_id, proposal_digest, local):
        counts["unprepared_local_participants"] += len(local)
        return original_binding(proof, workflow_id, proposal_digest, local)

    patch.setattr(workflow_recovery, "_proposal_binding", bind)
    original_index = workflow_recovery._preparation_index

    def index(proposal):
        result = original_index(proposal)
        counts["preparation_indexes"] += 1
        counts["preparation_owners_indexed"] += len(result.owners)
        return result

    patch.setattr(workflow_recovery, "_preparation_index", index)
    return counts
