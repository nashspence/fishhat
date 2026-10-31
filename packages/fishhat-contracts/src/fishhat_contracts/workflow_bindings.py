"""Complete shared workflow inspection models; no live owner admission.

These full-value helpers construct and validate an explicitly requested audit
projection from independently retained facts. They are not a journal writer or
a participant protocol: live admission uses workflow_journal and its partitioned
owner journals. Materialize complete views only for explicit inspection, never
after each accepted child or at every participating owner.

Later reviewed workflow Plans and retained output lineage; no native admission.

All verified arguments are independently obtained protected receiver context. The
reference model checks exact joins, not signatures, native derivation, current
authorization, durable transactions or material storage.
"""

from __future__ import annotations

import copy
from collections import ChainMap
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from .bounds import Bounds, bounds
from .handoffs import PHASES
from .operations import validate_operation
from .validation import ContractError, canonical, digest, validate
from .workflows import (
    _child_identity_matches,
    _pair,
    _plan_binding,
    _request_key,
    bound_plan,
    child_action,
    proposal_children,
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _key(reference: dict[str, Any]) -> bytes:
    return _request_key(reference["owner"], reference["request_id"])


def _ready(
    children: Mapping[bytes, tuple[dict[str, Any], dict[str, Any]]],
) -> dict[bytes, dict[str, Any]]:
    return {
        key: binding
        for key, (_, binding) in children.items()
        if "plan" in binding or "completed" in binding
    }


def _predecessor(intent: dict[str, Any]) -> dict[str, Any]:
    name = {
        "reviewed-successor": "predecessor",
        "secret-publication": "issuer",
        "secret-adoption": "publication",
    }[intent["kind"]]
    return dict(intent[name])


def _phase_review_windows(workflow: dict[str, Any]) -> dict[str, tuple[int, int | None]]:
    """Index installed phase-entry barriers once for all retained initial bindings.

    Complete capsule validation independently verifies every entry's phase evidence
    and legal order. Transfers and lifecycle changes do not create a phase barrier.
    """
    windows: dict[str, tuple[int, int | None]] = {}
    previous = PHASES[workflow["type"]][0]
    for receipt in workflow["advances"]:
        authority = receipt["authority"]
        if authority == "native-lifecycle":
            continue
        if authority == "driver" and receipt["request"]["transfer_completion"] is not None:
            continue
        phase, generation = receipt["phase"], receipt["generation"]
        _require(phase not in windows, "workflow repeats an installed phase review barrier")
        if previous in windows:
            windows[previous] = (windows[previous][0], generation)
        windows[phase] = (generation, None)
        previous = phase
    return windows


def _initial_review(
    request: dict[str, Any],
    intent: dict[str, Any],
    phase_windows: Mapping[str, tuple[int, int | None]],
) -> None:
    window = phase_windows.get(request["binding"]["phase"])
    _require(
        window is not None
        and window[0] <= request["expected_generation"]
        and (window[1] is None or request["expected_generation"] + 1 < window[1]),
        "initial workflow review must follow its installed phase barrier",
    )
    _require(
        request["binding"]["plan"]["subject"] == intent["subject"]
        and not request["predecessors"]
        and not request["materials"],
        "initial workflow review changed its closed subject or installed dependencies",
    )


def _operation(
    record: dict[str, Any],
    reference: dict[str, Any],
    binding: dict[str, Any],
    workflow_id: str,
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
) -> None:
    validate_operation(record, recovery_readers=recovery_readers)
    plan = bound_plan(binding)
    _require(
        _child_identity_matches(record, reference, binding, workflow_id)
        and record["subject"] == plan["subject"]
        and record["plan_digest"] == plan["digest"]
        and record["state"] == "succeeded"
        and record["effect_certainty"] == "known",
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
        destination = {
            key: intent[key]
            for key in (
                "source",
                "entry",
                "consumer",
                "version",
                "catalogue_digest",
                "evidence_schema",
                "expected_previous",
            )
        }
        _require(
            material["publication_receipt"] is None
            and handle["purpose"] == "secret-candidate"
            and arguments == {**destination, "candidate": handle},
            "workflow publication candidate or predecessor changed",
        )
    else:
        receipt = material["publication_receipt"]
        _require(receipt is not None, "workflow adoption lacks completed publication receipt")
        assert receipt is not None
        from .publication import validate_publication_result

        publication_plan = bound_plan(ready[_key(reference)])
        candidate = publication_plan["subject"]["arguments"]["candidate"]
        validate_publication_result(
            receipt, publication_plan["subject"], expected_custodian=publication_plan["owner"]
        )
        _require(
            receipt["state"] == "completed"
            and receipt["current"]["artifact_digest"] == candidate["digest"]
            and receipt["current"]["bytes"] == candidate["size"]
            and handle["digest"] == digest(receipt)
            and handle["size"] == len(canonical(receipt))
            and copied == handle
            and arguments == {"publication_receipt": digest(receipt)},
            "workflow adoption substituted publication receipt or candidate",
        )


def _binding_shape(
    request: dict[str, Any],
    workflow: dict[str, Any],
    ready: dict[bytes, dict[str, Any]],
    *,
    children: Mapping[bytes, tuple[dict[str, Any], dict[str, Any]]],
    generations: dict[bytes, int],
    phase_windows: Mapping[str, tuple[int, int | None]],
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
) -> None:
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
    reviewed_generations = {}
    for condition in binding["plan"]["preconditions"]:
        pair = _pair(condition["owner"], condition["resource"])
        if pair in generations:
            _require(condition["generation"] >= generations[pair], "workflow generation regressed")
            reviewed_generations[pair] = condition["generation"]
    content = {canonical(h) for h in request["content"]}
    _require(len(content) == len(request["content"]), "duplicate workflow binding content")
    identities = {_request_key(h["owner"], h["id"]) for h in request["content"]}
    _require(len(identities) == len(content), "workflow binding content identity changed")
    _plan_binding(
        binding,
        participant,
        ChainMap(reviewed_generations, generations),
        content,
        recovery_readers=recovery_readers,
    )
    available = {canonical([h["owner"], h["digest"]]) for h in request["content"]}
    _require(
        all(
            canonical([binding["plan"]["owner"], d]) in available
            for d in binding["plan"]["input_digests"]
        ),
        "workflow binding Plan input lacks retained content",
    )
    if intent["kind"] == "reviewed-initial":
        _initial_review(request, intent, phase_windows)
        return
    reference = _predecessor(intent)
    _require(_key(reference) in ready, "workflow predecessor Plan is not retained")
    _require(len(request["predecessors"]) == 1, "workflow binding requires exact predecessor")
    predecessor = request["predecessors"][0]
    _operation(
        predecessor,
        reference,
        ready[_key(reference)],
        workflow["id"],
        recovery_readers=recovery_readers,
    )
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


@bounds(
    Bounds(
        id="workflow.bindings",
        work="O(B) complete proposal, binding and retained phase-history bytes with one child index and one installed phase-window index per validation",
        extent="Every immutable child slot, accepted binding, predecessor/material input and installed initial-review barrier; no prefix or total-count cap",
        limits=(),
        capacity=("native owners may refuse new capacity without dropping accepted bindings",),
        proofs=(
            "tests/test_workflow_initial_review.py::test_consumer_first_plan_is_reviewed_after_provider_success_without_supersession",
            "tests/test_workflow_continuations.py::test_successor_plan_uses_fresh_generation_after_exact_predecessor_and_replays",
        ),
        linear_proofs=(
            "tests/test_workflow_initial_review_growth.py::test_initial_binding_validation_linear_complete_history_work",
            "tests/test_workflow_validation_growth.py::test_recovery_validation_linear_child_and_binding_work",
        ),
    )
)
def validate_workflow_bindings(
    workflow: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Check retained exact bindings without reapplying current admission checks."""
    children = proposal_children(workflow["proposal"])
    ready = _ready(children)
    generations = {
        _pair(p["owner"], p["resource"]): p["expected_generation"]
        for p in workflow["proposal"]["participants"]
    }
    ids: set[str] = set()
    generation = 0
    advances = {receipt["generation"] for receipt in workflow["advances"]}
    phase_windows = _phase_review_windows(workflow)
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
        _binding_shape(
            original,
            workflow,
            ready,
            children=children,
            generations=generations,
            phase_windows=phase_windows,
            recovery_readers=recovery_readers,
        )
        ready[_key(original["child"])] = original["binding"]
        generation = receipt["generation"]


def require_bound_phase(
    workflow: dict[str, Any],
    phase: str,
    *,
    before_generation: int | None = None,
) -> None:
    children = proposal_children(workflow["proposal"])
    ready = _ready(children)
    for receipt in workflow["bindings"]:
        if before_generation is None or receipt["generation"] < before_generation:
            ready[_key(receipt["request"]["child"])] = receipt["request"]["binding"]
    position = PHASES[workflow["type"]].index(phase)
    _require(
        all(
            key in ready
            for key, (_, slot) in children.items()
            if PHASES[workflow["type"]].index(slot["phase"]) <= position
        ),
        "workflow phase has unresolved required child Plans",
    )


def validate_bind_request(
    request: dict[str, Any],
    workflow: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> str:
    from .handoffs import validate_workflow

    validate("workflow.schema.json", request, "BindRequest")
    validate_workflow(workflow, recovery_readers=recovery_readers)
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
        and workflow["state"] in {"prepared", "active"},
        "workflow binding generation, driver or state changed",
    )
    _require(
        workflow["transfer"] is None or workflow["transfer"]["phase"] == "completed",
        "workflow driver transfer is incomplete",
    )
    _require(
        workflow.get("recovery", {}).get("phase", "committed") == "committed",
        "workflow recovery preparation is not committed",
    )
    phases = PHASES[workflow["type"]]
    phase = request["binding"]["phase"]
    _require(
        phase in phases
        and phases.index(workflow["phase"]) in {phases.index(phase) - 1, phases.index(phase)},
        "workflow binding outside installed phase",
    )
    children = proposal_children(workflow["proposal"])
    ready = _ready(children)
    for receipt in workflow["bindings"]:
        ready[_key(receipt["request"]["child"])] = receipt["request"]["binding"]
    _binding_shape(
        request,
        workflow,
        ready,
        children=children,
        phase_windows=_phase_review_windows(workflow),
        generations={
            _pair(p["owner"], p["resource"]): p["expected_generation"]
            for p in workflow["proposal"]["participants"]
        },
        recovery_readers=recovery_readers,
    )
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
    content = {canonical(h) for h in verified_content}
    _require(
        all(canonical(h) in content for h in request["content"]),
        "workflow binding verified custody incomplete",
    )
    adapter = request["binding"].get("adapter")
    _require(
        adapter is None or adapter in verified_adapters,
        "workflow binding adapter is not independently verified",
    )


def bind_workflow_view(
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
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Retain one independently reviewed continuation; never submit a native child.

    Native receivers reauthorize current access before this model. Exact retained
    replay precedes new Plan expiry, generation, review and material checks. No
    verified argument may be populated merely by copying request fields.
    """
    from .handoffs import validate_workflow

    disposition = validate_bind_request(request, workflow, recovery_readers=recovery_readers)
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
    validate_workflow(result, recovery_readers=recovery_readers)
    return result
