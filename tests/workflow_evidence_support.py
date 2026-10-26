"""Explicit synthetic workflow evidence; no native observation or qualification."""

from __future__ import annotations

import copy
from typing import Any
from urllib.parse import urljoin

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_contracts.handoffs import ACTIONS, PHASES, schema_identity
from fishhat_contracts.validation import canonical, digest
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_evidence import REQUIREMENTS, phase_subject
from fishhat_contracts.workflows import advance_workflow, bound_plan

from tests.operation_support import seal_operation
from tests.test_contracts import uid
from tests.test_owner_handoffs import operation, preparation_witnesses

KEY = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)


def synthetic_operation(workflow, participant, binding, *, state="succeeded"):
    """Construct a signed test record, explicitly not an observed native outcome."""
    if "completed" in binding:
        return copy.deepcopy(binding["completed"]["operation"])
    plan = bound_plan(binding)
    result = operation()
    result.update(
        id=uid("phase-operation-" + binding["request_id"]),
        request_id=binding["request_id"],
        owner=copy.deepcopy(participant["owner"]),
        subject=copy.deepcopy(plan["subject"]),
        plan_digest=plan["digest"],
        state=state,
        effect_certainty="known",
        result_handle=None,
    )
    result["witness"]["workflow_id"] = workflow["id"]
    specification = ACTIONS[plan["subject"]["action"]]["result"]
    if state == "succeeded" and specification.get("required_on_success", False):
        identity = (
            schema_identity(
                urljoin("https://fishhat.invalid/contracts/", specification["schema"]["$ref"])
            )
            if specification["mode"] == "schema"
            else plan["subject"]["arguments"][specification["subject_field"]]
        )
        # This factory supplies synthetic custody identities for decoded-record
        # tests. It does not verify a result payload or claim native production.
        data = canonical({"synthetic_result_for": result["id"]})
        result["result_handle"] = {
            "handle": {
                "owner": copy.deepcopy(result["owner"]),
                "id": uid("phase-result-" + result["id"]),
                "purpose": "content",
                "binding": {"kind": "operation", "operation_id": result["id"]},
                "digest": digest({"synthetic_result_for": result["id"]}),
                "size": len(data),
            },
            "schema": identity,
        }
    return seal_operation(result)


def seal_phase_participant(evidence, participant):
    witness = {key: value for key, value in operation()["witness"].items() if key != "signature"}
    witness.update(
        id=uid("phase-witness-" + digest(phase_subject(evidence["transition"], participant))),
        owner=copy.deepcopy(participant["owner"]),
        generation=participant["resource_generation"],
        kind="approval",
        state="workflow-phase-verified",
        workflow_id=evidence["transition"]["workflow_id"],
        subject_digest=digest(phase_subject(evidence["transition"], participant)),
        evidence_digests=[],
    )
    participant["witness"] = sign(witness, KEY)
    return participant


def phase_evidence(workflow, request, *, operations=None, authority="driver"):
    """Build visibly synthetic, exact evidence for a test's chosen next phase."""
    phases = PHASES[workflow["type"]]
    position = phases.index(request["phase"])
    supplied = operations or {}
    retained = {
        canonical(receipt["request"]["child"]): receipt["request"]["binding"]
        for receipt in workflow["bindings"]
    }
    known = {
        canonical({"owner": op["owner"], "request_id": op["request_id"]}): op
        for receipt in workflow["bindings"]
        for op in receipt["request"]["predecessors"]
    }
    evidence = {
        "transition": {
            "authority": authority,
            **{
                key: copy.deepcopy(request[key])
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
        "participants": [],
    }
    for participant in workflow["proposal"]["participants"]:
        native = {
            "synthetic_native_observation": participant["resource"],
            "phase": request["phase"],
        }
        proof = {
            "owner": copy.deepcopy(participant["owner"]),
            "resource": copy.deepcopy(participant["resource"]),
            "resource_generation": participant["expected_generation"],
            "operations": [],
            "native_evidence": [
                {
                    "owner": copy.deepcopy(participant["owner"]),
                    "id": uid("phase-native-" + digest(native)),
                    "purpose": "content",
                    "binding": {
                        "kind": "staging",
                        "staging_id": uid("phase-native-staging-" + digest(native)),
                    },
                    "digest": digest(native),
                    "size": len(canonical(native)),
                }
            ],
        }
        for slot in participant["requests"]:
            if phases.index(slot["phase"]) >= position:
                continue
            child = {"owner": copy.deepcopy(participant["owner"]), "request_id": slot["request_id"]}
            key = canonical(child)
            binding = retained.get(key, slot)
            if "plan" not in binding and "completed" not in binding:
                # Leave the required outcome missing so production validation,
                # not a fixture KeyError, proves an unresolved slot is blocked.
                continue
            outcome = supplied.get(key) or known.get(key)
            if outcome is None:
                outcome = synthetic_operation(workflow, participant, binding)
            outcome = copy.deepcopy(outcome)
            if "completed" not in binding:
                outcome["witness"]["workflow_id"] = workflow["id"]
                seal_operation(outcome)
            proof["operations"].append({"child": child, "operation": outcome})
        evidence["participants"].append(seal_phase_participant(evidence, proof))
    return evidence


def advance_request(workflow, phase, *, operations=None, advance_id=None):
    request = {
        "owner": copy.deepcopy(workflow["owner"]),
        "workflow_id": workflow["id"],
        "advance_id": advance_id or uid(f"advance-{phase}-{workflow['generation']}"),
        "driver_term": workflow["driver_term"],
        "expected_generation": workflow["generation"],
        "phase": phase,
        "witnesses": (
            preparation_witnesses(workflow["proposal"])
            if workflow["phase"] == "prepared" and "recovery" not in workflow
            else []
        ),
        "transfer_completion": None,
    }
    request["phase_evidence"] = phase_evidence(workflow, request, operations=operations)
    return request


def advance_with_evidence(request, workflow, **context: Any):
    """Pass explicit synthetic trusted context without filling missing request evidence."""
    context.setdefault("verified_phase_evidence", copy.deepcopy(request.get("phase_evidence")))
    context.setdefault(
        "verified_preparations",
        copy.deepcopy([w for w in request["witnesses"] if w["state"] == "workflow-prepared"]),
    )
    return advance_workflow(request, workflow, **context)
