"""Later reviewed workflow Plans and retained output lineage; no native admission.

All verified arguments are independently obtained protected receiver context. The
reference model checks exact joins, not signatures, native derivation, current
authorization, durable transactions or material storage.
"""

from __future__ import annotations

import copy
from datetime import datetime
from typing import Any

from .handoffs import PHASES, validate_result_reference
from .validation import ContractError, canonical, digest, validate
from .workflows import _pair, _plan_binding, _request_key, child_action, proposal_children


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _key(reference: dict[str, Any]) -> bytes:
    return _request_key(reference["owner"], reference["request_id"])


def _ready(workflow: dict[str, Any]) -> dict[bytes, dict[str, Any]]:
    return {
        key: binding
        for key, (_, binding) in proposal_children(workflow["proposal"]).items()
        if "plan" in binding
    }


def _predecessor(intent: dict[str, Any]) -> dict[str, Any]:
    name = {
        "reviewed-successor": "predecessor",
        "secret-publication": "issuer",
        "secret-adoption": "publication",
    }[intent["kind"]]
    return dict(intent[name])


def _operation(record: dict[str, Any], reference: dict[str, Any], binding: dict[str, Any]) -> None:
    validate_result_reference(record)
    plan = binding["plan"]
    _require(
        record["owner"] == reference["owner"]
        and record["request_id"] == reference["request_id"]
        and record["subject"] == plan["subject"]
        and record["plan_digest"] == plan["digest"]
        and record["state"] == "succeeded"
        and record["effect_certainty"] == "known"
        and record["witness"]["owner"] == record["owner"],
        "workflow predecessor does not prove exact successful child",
    )


def _material(
    material: dict[str, Any],
    request: dict[str, Any],
    intent: dict[str, Any],
    predecessor: dict[str, Any],
    ready: dict[bytes, dict[str, Any]],
) -> None:
    reference = _predecessor(intent)
    handle, witness = material["material"], material["witness"]
    output, copied = predecessor["result_handle"], material["producer_output"]
    _require(output is not None, "workflow producer lacks its exact retained result")
    assert output is not None
    _require(
        copied["owner"] == request["child"]["owner"]
        and copied["digest"] == output["handle"]["digest"]
        and copied["size"] == output["handle"]["size"]
        and copied in request["content"]
        and copied["digest"] in request["binding"]["plan"]["input_digests"],
        "workflow producer result lacks exact retained custody",
    )
    _require(
        material["producer"] == reference
        and material["operation"] == predecessor
        and handle["owner"] == request["child"]["owner"],
        "workflow produced material changed producer or custodian",
    )
    _require(
        witness["owner"] == handle["owner"]
        and witness["kind"] == "binding"
        and witness["state"] == "verified"
        and witness["workflow_id"] == request["workflow_id"]
        and witness["subject_digest"]
        == digest({k: v for k, v in material.items() if k != "witness"}),
        "workflow produced material witness changed",
    )
    _require(handle in request["content"], "workflow produced material lacks retained custody")
    arguments = request["binding"]["plan"]["subject"]["arguments"]
    if intent["kind"] == "secret-publication":
        _require(
            material["publication_receipt"] is None
            and handle["purpose"] == "secret-candidate"
            and arguments
            == {"candidate": handle, "expected_previous": intent["expected_previous"]},
            "workflow publication candidate or predecessor changed",
        )
    else:
        receipt = material["publication_receipt"]
        _require(receipt is not None, "workflow adoption lacks completed publication receipt")
        assert receipt is not None
        candidate = ready[_key(reference)]["plan"]["subject"]["arguments"]["candidate"]
        _require(
            receipt["state"] == "completed"
            and receipt["custodian"] == reference["owner"]
            and receipt["current"]["ciphertext_digest"] == candidate["digest"]
            and receipt["current"]["bytes"] == candidate["size"]
            and handle["digest"] == digest(receipt)
            and handle["size"] == len(canonical(receipt))
            and copied == handle
            and arguments == {"bundle_receipt": digest(receipt)},
            "workflow adoption substituted publication receipt or candidate",
        )


def _binding_shape(
    request: dict[str, Any],
    workflow: dict[str, Any],
    ready: dict[bytes, dict[str, Any]],
) -> None:
    children = proposal_children(workflow["proposal"])
    key = _key(request["child"])
    _require(key in children and key not in ready, "workflow child is absent or already bound")
    participant, slot = children[key]
    _require("intent" in slot, "workflow child is not a continuation")
    intent, binding = slot["intent"], request["binding"]
    _require(
        binding["request_id"] == slot["request_id"]
        and binding["phase"] == slot["phase"]
        and binding["plan"]["subject"]["action"] == child_action(slot),
        "workflow bound Plan changed immutable child intent",
    )
    generations = {
        _pair(p["owner"], p["resource"]): p["expected_generation"]
        for p in workflow["proposal"]["participants"]
    }
    for condition in binding["plan"]["preconditions"]:
        pair = _pair(condition["owner"], condition["resource"])
        if pair in generations:
            _require(condition["generation"] >= generations[pair], "workflow generation regressed")
            generations[pair] = condition["generation"]
    content = {canonical(h) for h in request["content"]}
    _require(len(content) == len(request["content"]), "duplicate workflow binding content")
    identities = {_request_key(h["owner"], h["id"]) for h in request["content"]}
    _require(len(identities) == len(content), "workflow binding content identity changed")
    _plan_binding(binding, participant, generations, content)
    available = {canonical([h["owner"], h["digest"]]) for h in request["content"]}
    _require(
        all(
            canonical([binding["plan"]["owner"], d]) in available
            for d in binding["plan"]["input_digests"]
        ),
        "workflow binding Plan input lacks retained content",
    )
    reference = _predecessor(intent)
    _require(_key(reference) in ready, "workflow predecessor Plan is not retained")
    _require(len(request["predecessors"]) == 1, "workflow binding requires exact predecessor")
    predecessor = request["predecessors"][0]
    _operation(predecessor, reference, ready[_key(reference)])
    if intent["kind"] == "reviewed-successor":
        _require(
            binding["plan"]["subject"] == intent["subject"], "workflow successor subject changed"
        )
        _require(not request["materials"], "workflow successor has unrelated material lineage")
    else:
        _require(
            len(request["materials"]) == 1, "workflow rotation requires exact material lineage"
        )
        _material(request["materials"][0], request, intent, predecessor, ready)


def validate_workflow_bindings(workflow: dict[str, Any]) -> None:
    """Check retained exact bindings without reapplying current admission checks."""
    ready = _ready(workflow)
    ids: set[str] = set()
    generation = 0
    advances = {receipt["generation"] for receipt in workflow["advances"]}
    for receipt in workflow["bindings"]:
        original = receipt["request"]
        _require(original["bind_id"] not in ids, "duplicate workflow binding identity")
        ids.add(original["bind_id"])
        _require(
            original["owner"] == workflow["owner"]
            and original["workflow_id"] == workflow["id"]
            and receipt["request_digest"] == digest(original)
            and generation < receipt["generation"] <= workflow["generation"]
            and receipt["generation"] not in advances
            and original["expected_generation"] + 1 == receipt["generation"]
            and original["driver_term"] <= workflow["driver_term"],
            "retained workflow binding identity or generation changed",
        )
        _binding_shape(original, workflow, ready)
        ready[_key(original["child"])] = original["binding"]
        generation = receipt["generation"]


def require_bound_phase(
    workflow: dict[str, Any],
    phase: str,
    *,
    before_generation: int | None = None,
) -> None:
    ready = _ready(workflow)
    for receipt in workflow["bindings"]:
        if before_generation is None or receipt["generation"] < before_generation:
            ready[_key(receipt["request"]["child"])] = receipt["request"]["binding"]
    position = PHASES[workflow["type"]].index(phase)
    _require(
        all(
            key in ready
            for key, (_, slot) in proposal_children(workflow["proposal"]).items()
            if PHASES[workflow["type"]].index(slot["phase"]) <= position
        ),
        "workflow phase has unresolved required child Plans",
    )


def validate_bind_request(request: dict[str, Any], workflow: dict[str, Any]) -> str:
    from .handoffs import validate_workflow

    validate("workflow.schema.json", request, "BindRequest")
    validate_workflow(workflow)
    _require(
        request["owner"] == workflow["owner"] and request["workflow_id"] == workflow["id"],
        "workflow binding receiver changed",
    )
    for receipt in workflow["bindings"]:
        if receipt["request"]["bind_id"] == request["bind_id"]:
            _require(receipt["request"] == request, "accepted workflow binding input changed")
            return "replay"
    _require(
        request["expected_generation"] == workflow["generation"] < 9007199254740991
        and request["driver_term"] == workflow["driver_term"]
        and workflow["state"] in {"prepared", "active", "paused"},
        "workflow binding generation, driver or state changed",
    )
    phases = PHASES[workflow["type"]]
    phase = request["binding"]["phase"]
    _require(
        phase in phases
        and phases.index(workflow["phase"]) in {phases.index(phase) - 1, phases.index(phase)},
        "workflow binding outside installed phase",
    )
    ready = _ready(workflow)
    for receipt in workflow["bindings"]:
        ready[_key(receipt["request"]["child"])] = receipt["request"]["binding"]
    _binding_shape(request, workflow, ready)
    return "new"


def _verify_binding_custody(
    request: dict[str, Any],
    *,
    verified_binding: dict[str, Any],
    current_generations: list[dict[str, Any]],
    verified_operations: list[dict[str, Any]],
    verified_materials: list[dict[str, Any]],
    verified_content: list[dict[str, Any]],
    verified_adapters: list[dict[str, Any]],
    now: str,
) -> None:
    _require(request["binding"] == verified_binding, "workflow Plan is not independently reviewed")
    observed = {_pair(c["owner"], c["resource"]): c["generation"] for c in current_generations}
    _require(len(observed) == len(current_generations), "duplicate current generation authority")
    plan = request["binding"]["plan"]
    _require(
        all(
            observed.get(_pair(c["owner"], c["resource"])) == c["generation"]
            for c in plan["preconditions"]
        ),
        "workflow Plan current generation changed",
    )
    validate("common.schema.json", now, "Time")
    _require(
        datetime.fromisoformat(now) < datetime.fromisoformat(plan["expires_at"]),
        "workflow binding Plan expired",
    )
    _require(
        all(item in verified_operations for item in request["predecessors"]),
        "workflow predecessor is not independently verified",
    )
    _require(
        all(item in verified_materials for item in request["materials"]),
        "workflow produced material is not independently verified",
    )
    _require(
        all(h in verified_content for h in request["content"]),
        "workflow binding verified custody incomplete",
    )
    adapter = request["binding"].get("adapter")
    _require(
        adapter is None or adapter in verified_adapters,
        "workflow binding adapter is not independently verified",
    )


def bind_workflow(
    request: dict[str, Any],
    workflow: dict[str, Any],
    *,
    verified_binding: dict[str, Any],
    verified_driver: dict[str, Any],
    current_generations: list[dict[str, Any]],
    verified_operations: list[dict[str, Any]],
    verified_materials: list[dict[str, Any]],
    verified_content: list[dict[str, Any]],
    now: str,
    verified_adapters: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Retain one independently reviewed continuation; never submit a native child.

    Native receivers reauthorize current access before this model. Exact retained
    replay precedes new Plan expiry, generation, review and material checks. No
    verified argument may be populated merely by copying request fields.
    """
    from .handoffs import validate_workflow

    disposition = validate_bind_request(request, workflow)
    result = copy.deepcopy(workflow)
    if disposition == "replay":
        return result
    _require(
        verified_driver
        == {"principal": workflow["driver_principal"], "term": workflow["driver_term"]},
        "workflow binding driver is not independently authorized",
    )
    _verify_binding_custody(
        request,
        verified_binding=verified_binding,
        current_generations=current_generations,
        verified_operations=verified_operations,
        verified_materials=verified_materials,
        verified_content=verified_content,
        verified_adapters=verified_adapters or [],
        now=now,
    )
    result["generation"] += 1
    result["bindings"].append(
        {
            "request": copy.deepcopy(request),
            "request_digest": digest(request),
            "generation": result["generation"],
        }
    )
    validate_workflow(result)
    return result
