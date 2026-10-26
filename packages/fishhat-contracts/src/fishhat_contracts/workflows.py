"""Decoded immutable workflow inputs and finite transition reference models.

These complete-input checks make no native authorization, persistence or bounded
streaming claim. Receivers independently authenticate Plans and witnesses, verify
local content custody and authorize the entire local participant closure before
acknowledging work. A Python argument never supplies that authority.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from .handoffs import PHASES, schema_identity, validate_staged_input, validate_staging
from .validation import (
    SCHEMAS,
    ContractError,
    canonical,
    digest,
    strict_json,
    validate,
    validate_plan,
)

INPUT_SCHEMAS = {
    "workflow.prepare": ("workflow.schema.json", "PrepareRequest"),
    "workflow.bind": ("workflow.schema.json", "BindRequest"),
    "workflow.advance": ("workflow.schema.json", "AdvanceRequest"),
    "workflow.transfer": ("records.schema.json", "WorkflowTransferRequest"),
    "workflow.recover": ("workflow-recovery.schema.json", "RecoveryRequest"),
}

# Semantic joins belong here because JSON Schema cannot follow a ChildReference
# into another member of the proposal and inspect its retained Plan's action.
TARGET_ACTIONS = {
    "host-drain": {
        "host_change": {"host.apply", "host.reboot", "host.sleep", "host.runtime-install"}
    },
    "interface-binding": {
        "provider": {"app.deploy", "app.upgrade", "app.repair"},
        "consumers": {"app.deploy", "app.upgrade", "app.repair", "app.secrets-adopt"},
    },
    "ingress-publication": {"publication": {"adapter.execute"}},
    "secret-rotation": {
        "issuer_change": {"adapter.execute"},
        "publication": {"publisher.publish"},
        "consumer_adoptions": {"app.secrets-adopt", "host.secrets-adopt"},
    },
    "checkpoint": {"capture": {"app.backup"}},
    "relocation": {"relocation": {"app.relocate"}},
    "source-publication": {"publication": {"source.publish"}},
    "dns-change": {"change": {"dns.reconcile"}},
    "secret-publication": {"publication": {"publisher.publish", "publisher.recover"}},
    "raw-maintenance": {"maintenance": {"app.maintenance-run", "adapter.execute"}},
    "runtime-upgrade": {"installation": {"host.runtime-install"}},
}

PHASE_ACTIONS = {
    "host-drain": {
        "draining": {"app.maintenance-run", "adapter.execute"},
        "host-effect": TARGET_ACTIONS["host-drain"]["host_change"],
        "reconciling": {"app.repair", "app.restart", "app.maintenance-run", "adapter.execute"},
    },
    "interface-binding": {
        "provider-verified": TARGET_ACTIONS["interface-binding"]["provider"],
        "consumer-adopting": TARGET_ACTIONS["interface-binding"]["consumers"],
    },
    "ingress-publication": {"published": {"adapter.execute"}, "reloaded": {"adapter.execute"}},
    "secret-rotation": {
        "issuer-changing": {"adapter.execute"},
        "publishing": {"publisher.publish"},
        "consumers-adopting": {"app.secrets-adopt", "host.secrets-adopt"},
    },
    "checkpoint": {"native-capturing": {"app.backup"}},
    "relocation": {"source-quiescing": {"app.relocate"}},
    "source-publication": {"ref-updating": {"source.publish"}},
    "dns-change": {"applying": {"dns.reconcile"}},
    "secret-publication": {"replacing": {"publisher.publish", "publisher.recover"}},
    "raw-maintenance": {"external-work": {"app.maintenance-run", "adapter.execute"}},
    "runtime-upgrade": {"migrating": {"host.runtime-install"}},
}

TARGET_PHASES = {
    "host-drain": {"host_change": "host-effect"},
    "interface-binding": {"provider": "provider-verified", "consumers": "consumer-adopting"},
    "ingress-publication": {"publication": "published"},
    "secret-rotation": {
        "issuer_change": "issuer-changing",
        "publication": "publishing",
        "consumer_adoptions": "consumers-adopting",
    },
    "checkpoint": {"capture": "native-capturing"},
    "relocation": {"relocation": "source-quiescing"},
    "source-publication": {"publication": "ref-updating"},
    "dns-change": {"change": "applying"},
    "secret-publication": {"publication": "replacing"},
    "raw-maintenance": {"maintenance": "external-work"},
    "runtime-upgrade": {"installation": "migrating"},
}


def child_action(binding: dict[str, Any]) -> str:
    if "completed" in binding:
        return str(binding["completed"]["plan"]["subject"]["action"])
    if "plan" in binding:
        return str(binding["plan"]["subject"]["action"])
    intent = binding["intent"]
    if intent["kind"] == "reviewed-successor":
        return str(intent["subject"]["action"])
    return "publisher.publish" if intent["kind"] == "secret-publication" else str(intent["action"])


def bound_plan(binding: dict[str, Any]) -> dict[str, Any]:
    """Return exact Plan identity without granting a completed slot execution."""
    return dict(binding["completed"]["plan"] if "completed" in binding else binding["plan"])


def validate_completed_binding(
    binding: dict[str, Any],
    participant: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    from .operations import validate_operation

    retained = binding["completed"]
    plan, operation = retained["plan"], retained["operation"]
    validate_plan(plan)
    validate_operation(operation, recovery_readers=recovery_readers)
    _require(
        all(plan["owner"][key] == participant["owner"][key] for key in ("tool", "id"))
        and plan["subject"]["resource"] == participant["resource"]
        and operation["owner"] == plan["owner"]
        and operation["plan_digest"] == plan["digest"]
        and operation["subject"] == plan["subject"]
        and operation["state"] == "succeeded"
        and operation["effect_certainty"] == "known",
        "completed workflow slot changed original successful work",
    )
    if "adapter" in retained:
        _adapter_binding(retained, recovery_readers=recovery_readers)


def proposal_children(
    proposal: dict[str, Any],
) -> dict[bytes, tuple[dict[str, Any], dict[str, Any]]]:
    return {
        _request_key(participant["owner"], binding["request_id"]): (participant, binding)
        for participant in proposal["participants"]
        for binding in participant["requests"]
    }


def _intent_binding(
    binding: dict[str, Any], participant: dict[str, Any], index: int, proposal: dict[str, Any]
) -> None:
    intent = binding["intent"]
    if intent["kind"] == "reviewed-successor":
        _require(index > 0, "workflow successor has no prior participant request")
        previous = participant["requests"][index - 1]
        _require(
            intent["predecessor"]
            == {"owner": participant["owner"], "request_id": previous["request_id"]}
            and intent["subject"]["resource"] == participant["resource"],
            "workflow successor changed predecessor or resource",
        )
        _require(
            PHASES[proposal["type"]].index(previous["phase"])
            <= PHASES[proposal["type"]].index(binding["phase"]),
            "workflow successor reverses installed phase order",
        )
        return
    _require(index == 0, "later participant output requires reviewed successor")
    _require(proposal["type"] == "secret-rotation", "secret continuation outside rotation")
    target = proposal["target"]
    _require(intent["issuer"] == target["issuer_change"], "rotation issuer child changed")
    if intent["kind"] == "secret-adoption":
        _require(intent["publication"] == target["publication"], "rotation publication changed")


def _validate_child(
    binding: dict[str, Any],
    participant: dict[str, Any],
    index: int,
    proposal: dict[str, Any],
    generations: dict[bytes, int],
    content: set[bytes],
    *,
    recovery: bool = False,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    _require(
        child_action(binding) in PHASE_ACTIONS[proposal["type"]].get(binding["phase"], set()),
        "workflow child action outside installed phase",
    )
    if "completed" in binding:
        _require(recovery, "completed workflow slots require explicit recovery")
        validate_completed_binding(binding, participant, recovery_readers=recovery_readers)
    elif "plan" in binding:
        _require(
            index == 0
            or (recovery and all("completed" in b for b in participant["requests"][:index])),
            "later participant child requires reviewed continuation",
        )
        _plan_binding(binding, participant, generations, content, recovery_readers=recovery_readers)
        available = {canonical([h["owner"], h["digest"]]) for h in proposal["content"]}
        _require(
            all(
                canonical([binding["plan"]["owner"], d]) in available
                for d in binding["plan"]["input_digests"]
            ),
            "workflow Plan input lacks retained content handle",
        )
    else:
        _intent_binding(binding, participant, index, proposal)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _pair(owner: dict[str, Any], resource: dict[str, Any]) -> bytes:
    return canonical([owner, resource])


def _request_key(owner: dict[str, Any], request_id: str) -> bytes:
    return canonical([owner, request_id])


def _handles(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        if set(value) == {"owner", "id", "purpose", "binding", "digest", "size"}:
            validate("common.schema.json", value, "Handle")
            yield value
        else:
            for item in value.values():
                yield from _handles(item)
    elif isinstance(value, list):
        for item in value:
            yield from _handles(item)


def _plan_binding(
    binding: dict[str, Any],
    participant: dict[str, Any],
    generations: dict[bytes, int],
    content: set[bytes],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    plan = binding["plan"]
    validate_plan(plan)
    _require(
        plan["owner"] == participant["owner"]
        and plan["subject"]["resource"] == participant["resource"],
        "workflow child Plan owner or resource changed",
    )
    for condition in plan["preconditions"]:
        pair = _pair(condition["owner"], condition["resource"])
        if pair in generations:
            _require(
                condition["generation"] == generations[pair],
                "workflow child Plan generation changed",
            )
    _require(
        all(_pair(item["executor"], item["resource"]) in generations for item in plan["effects"]),
        "workflow effect outside participant closure",
    )
    _require(
        all(canonical(handle) in content for handle in _handles(binding)),
        "workflow Plan handle missing from content closure",
    )
    if "adapter" in binding:
        _adapter_binding(binding, recovery_readers=recovery_readers)


def _adapter_binding(
    binding: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    adapter, plan = binding["adapter"], binding["plan"]
    executor, request = adapter["executor"], adapter["request"]
    arguments = plan["subject"]["arguments"]
    _require(
        request["contract"] == "fishhat." + executor["role"]
        and request["input"]["scope"] == executor["scope"]
        and arguments["adapter_id"] == executor["instance"]
        and arguments["adapter_release"] == executor["installation_digest"]
        and arguments["action"] == request["method"],
        "workflow adapter selected method changed",
    )
    data = canonical(request)
    _require(
        arguments["input"]["owner"] == plan["owner"]
        and arguments["input"]["digest"] == digest(request)
        and arguments["input"]["size"] == len(data),
        "workflow adapter input preimage changed",
    )
    role_schema = SCHEMAS[executor["role"] + "-adapter.schema.json"]["$id"]
    input_schema = schema_identity(role_schema + "#/$defs/MutationRequest")
    result_schema = schema_identity(role_schema + "#/$defs/Output")
    input_key = (input_schema["uri"], arguments["input_schema_digest"])
    result_key = (arguments["result_schema"]["uri"], arguments["result_schema"]["digest"])
    input_current = arguments["input_schema_digest"] == input_schema["digest"]
    _require(
        (input_current or (recovery_readers is not None and input_key in recovery_readers))
        and arguments["result_schema"]["uri"] == result_schema["uri"]
        and (
            arguments["result_schema"] == result_schema
            or (recovery_readers is not None and result_key in recovery_readers)
        ),
        "workflow adapter schema binding changed",
    )
    if not input_current:
        assert recovery_readers is not None
        checked = copy.deepcopy(request)
        recovery_readers[input_key](checked)
        _require(canonical(checked) == data, "workflow adapter reader changed original input")
    if executor["role"] == "credential-issuer" and request["method"] == "issue":
        _require(request["input"]["issuer"] == executor, "workflow issuer binding changed")


def validate_workflow_proposal(
    proposal: dict[str, Any],
    *,
    recovery: bool = False,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Check complete decoded intent and exact child/content joins, not authority."""
    validate("workflow.schema.json", proposal, "WorkflowProposal")
    participants = proposal["participants"]
    generations = {
        _pair(item["owner"], item["resource"]): item["expected_generation"] for item in participants
    }
    _require(len(generations) == len(participants), "duplicate workflow proposal participant")
    content = {canonical(handle) for handle in proposal["content"]}
    _require(len(content) == len(proposal["content"]), "duplicate workflow content handle")
    content_ids = {_request_key(h["owner"], h["id"]) for h in proposal["content"]}
    _require(len(content_ids) == len(content), "workflow content identity changed")
    requests: dict[bytes, dict[str, Any]] = {}
    for participant in participants:
        for index, binding in enumerate(participant["requests"]):
            key = _request_key(participant["owner"], binding["request_id"])
            _require(key not in requests, "duplicate workflow child request")
            _validate_child(
                binding,
                participant,
                index,
                proposal,
                generations,
                content,
                recovery=recovery,
                recovery_readers=recovery_readers,
            )
            requests[key] = binding
    seen: set[bytes] = set()
    for role, reference in proposal["target"].items():
        references = reference if isinstance(reference, list) else [reference]
        for item in references:
            key = _request_key(item["owner"], item["request_id"])
            _require(
                key in requests and key not in seen, "workflow target child missing or repeated"
            )
            seen.add(key)
            binding = requests[key]
            _require(
                child_action(binding) in TARGET_ACTIONS[proposal["type"]][role],
                "workflow target child action does not match procedure role",
            )
            _target_binding(proposal, role, binding)
            if (proposal["type"], role) in {
                ("ingress-publication", "publication"),
                ("secret-rotation", "issuer_change"),
            }:
                expected = (
                    ("fishhat.ingress", "publish")
                    if proposal["type"] == "ingress-publication"
                    else ("fishhat.credential-issuer", "issue")
                )
                selected = binding.get("completed", binding)
                _require(
                    "adapter" in selected,
                    "workflow adapter producer must retain its initial Plan",
                )
                request = selected["adapter"]["request"]
                _require(
                    (request["contract"], request["method"]) == expected,
                    "workflow adapter method does not match procedure role",
                )


def _target_binding(proposal: dict[str, Any], role: str, binding: dict[str, Any]) -> None:
    _require(
        binding["phase"] == TARGET_PHASES[proposal["type"]][role],
        "workflow target changed installed procedure phase",
    )
    if proposal["type"] != "secret-rotation":
        return
    if "completed" in binding:
        return
    if role == "issuer_change":
        _require("plan" in binding, "rotation issuer requires ready reviewed Plan")
        return
    kind = "secret-publication" if role == "publication" else "secret-adoption"
    _require(
        "intent" in binding and binding["intent"]["kind"] == kind,
        "rotation output requires a later reviewed continuation",
    )


def _participants(proposal: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            **{
                key: copy.deepcopy(item[key])
                for key in ("owner", "resource", "expected_generation")
            },
            "request_ids": [binding["request_id"] for binding in item["requests"]],
            "last_witness": None,
        }
        for item in proposal["participants"]
    ]


def validate_workflow_proposal_binding(
    workflow: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Require the discoverable capsule to preserve its entire immutable proposal."""
    proposal = workflow["proposal"]
    validate_workflow_proposal(
        proposal, recovery="recovery" in workflow, recovery_readers=recovery_readers
    )
    _require(
        proposal["workflow_id"] == workflow["id"]
        and proposal["type"] == workflow["type"]
        and workflow["proposal_digest"] == digest(proposal),
        "workflow proposal identity changed",
    )
    observed = [{**participant, "last_witness": None} for participant in workflow["participants"]]
    _require(observed == _participants(proposal), "workflow participant Plan closure changed")
    if workflow["driver_term"] == 1:
        _require(
            workflow["driver_principal"] == proposal["initial_driver"]["principal"],
            "workflow initial driver preimage agreement changed",
        )
    from .workflow_bindings import require_bound_phase, validate_workflow_bindings

    validate_workflow_bindings(workflow, recovery_readers=recovery_readers)
    _validate_advance_history(workflow)
    phases = PHASES[workflow["type"]]
    if workflow["phase"] in phases and phases.index(workflow["phase"]) > 0:
        require_bound_phase(workflow, phases[phases.index(workflow["phase"]) - 1])
    from .workflow_recovery import validate_recovery_custody

    validate_recovery_custody(workflow, recovery_readers=recovery_readers)


def prepare_workflow(
    request: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    principal: str,
    verified_driver: dict[str, Any],
    verified_content: list[dict[str, Any]],
    verified_adapters: list[dict[str, Any]] | None = None,
    retained: dict[str, Any] | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Build/replay a pure capsule after independent receiving checks.

    verified_driver, verified_content, verified_adapters and retained come from protected owner
    state, never from the request. Equality models custody and enrollment joins,
    not authentication, authorization, native method support or durable pinning.
    """
    from .handoffs import validate_workflow

    validate("workflow.schema.json", request, "PrepareRequest")
    validate("common.schema.json", principal, "Id")
    _require(request["owner"] == expected_owner, "workflow receiving owner changed")
    proposal = request["proposal"]
    validate_workflow_proposal(proposal, recovery_readers=recovery_readers)
    _require(
        any(item["owner"] == expected_owner for item in proposal["participants"]),
        "workflow receiver is not a participant",
    )
    if retained is not None:
        validate_workflow(retained, recovery_readers=recovery_readers)
        _require(
            retained["owner"] == expected_owner and retained["proposal"] == proposal,
            "workflow preparation identity conflict",
        )
        return copy.deepcopy(retained)
    _require(
        proposal["initial_driver"] == verified_driver,
        "workflow initial driver is not independently authorized",
    )
    local = {canonical(h) for h in proposal["content"] if h["owner"] == expected_owner}
    _require(
        local <= {canonical(h) for h in verified_content},
        "workflow local content custody incomplete",
    )
    local_adapters = {
        canonical(binding["adapter"])
        for participant in proposal["participants"]
        if participant["owner"] == expected_owner
        for binding in participant["requests"]
        if "adapter" in binding
    }
    _require(
        local_adapters <= {canonical(item) for item in verified_adapters or []},
        "workflow local adapter selection is not independently verified",
    )
    result = prepared_capsule(proposal, expected_owner)
    validate_workflow(result, recovery_readers=recovery_readers)
    return result


def prepared_capsule(proposal: dict[str, Any], expected_owner: dict[str, Any]) -> dict[str, Any]:
    """Construct decoded fields only; callers establish custody before validation."""
    return {
        "format": "deployment-ops/record/v1",
        "kind": "Workflow",
        "id": proposal["workflow_id"],
        "owner": copy.deepcopy(expected_owner),
        "generation": 0,
        "type": proposal["type"],
        "proposal": copy.deepcopy(proposal),
        "proposal_digest": digest(proposal),
        "driver_term": 1,
        "driver_principal": proposal["initial_driver"]["principal"],
        "state": "prepared",
        "phase": PHASES[proposal["type"]][0],
        "participants": _participants(proposal),
        "prerequisite_witnesses": [],
        "holds": [],
        "recovery_digests": [],
        "transfer": None,
        "advances": [],
        "bindings": [],
    }


def decode_workflow_input(
    method: str,
    reference: dict[str, Any],
    data: bytes,
    *,
    expected_owner: dict[str, Any],
    max_bytes: int | None = None,
) -> dict[str, Any]:
    """Verify a complete staged payload once, independently of the frame bound.

    This in-memory reference has O(complete input) work/storage. Native bounded
    spooling, current authorization, staging freshness and retention are separate.
    max_bytes, when supplied, is an independently approved receiving capacity.
    """
    _require(method in INPUT_SCHEMAS, "unknown workflow input method")
    validate("workflow.schema.json", reference, "InputReference")
    handle = reference["input"]
    _require(
        reference["owner"] == handle["owner"] == expected_owner,
        "workflow input owner changed",
    )
    _require(
        handle["size"] == len(data)
        and handle["digest"] == "sha256:" + hashlib.sha256(data).hexdigest(),
        "workflow input bytes changed",
    )
    if max_bytes is not None:
        _require(type(max_bytes) is int and max_bytes >= 0, "invalid workflow receiving capacity")
    value = strict_json(data, max_bytes=len(data) if max_bytes is None else max_bytes)
    schema, definition = INPUT_SCHEMAS[method]
    validate(schema, value, definition)
    _require(canonical(value) == data, "workflow input must be complete canonical JSON")
    _require(value["owner"] == expected_owner, "workflow payload receiver changed")
    return dict(value)


def validate_workflow_input_custody(
    reference: dict[str, Any],
    payload: dict[str, Any],
    staging: dict[str, Any],
    *,
    principal: str,
    now: str,
    retained_request: dict[str, Any] | None = None,
) -> None:
    """Check independently loaded custody after resolving semantic replay identity.

    A native receiver selects retained_request from protected exact replay state
    and reauthorizes current access before this check; it is never a caller flag.
    Accepted replay does not depend on a prior caller or new-admission deadlines.
    """
    validate("workflow.schema.json", reference, "InputReference")
    workflow_id = (
        payload["proposal"]["workflow_id"] if "proposal" in payload else payload["workflow_id"]
    )
    resource = {"kind": "workflow", "id": workflow_id}
    handle = reference["input"]
    _require(payload["owner"] == reference["owner"], "workflow custody receiver changed")
    if retained_request is not None:
        _require(payload == retained_request, "retained workflow input changed")
        validate_staging(staging, expected_owner=reference["owner"], resource=resource)
        if staging["accepted_references"] > 0:
            _require(
                staging["state"] == "committed"
                and staging["handle"] == handle
                and staging["purpose"] == "workflow-input",
                "accepted workflow input lacks pinned custody",
            )
            return
        # A replacement caller can stage the same immutable semantic input.
        # That transport copy needs fresh custody; it never reaccepts the work.
    validate_staged_input(
        staging,
        handle,
        expected_owner=reference["owner"],
        principal=principal,
        resource=resource,
        purpose="workflow-input",
        now=now,
    )


def _validate_advance_history(workflow: dict[str, Any]) -> None:
    from .workflow_bindings import require_bound_phase

    identities: set[str] = set()
    generation = 0
    for receipt in workflow["advances"]:
        original = receipt["request"]
        _require(original["advance_id"] not in identities, "duplicate retained workflow advance")
        identities.add(original["advance_id"])
        _require(
            original["owner"] == workflow["owner"]
            and original["workflow_id"] == workflow["id"]
            and receipt["request_digest"] == digest(original),
            "retained workflow advance identity changed",
        )
        _require(
            generation < receipt["generation"] <= workflow["generation"]
            and original["expected_generation"] + 1 == receipt["generation"]
            and original["driver_term"] == receipt["driver_term"] <= workflow["driver_term"],
            "retained workflow advance generation changed",
        )
        generation = receipt["generation"]
        _require(
            original["phase"] == receipt["phase"] in PHASES[workflow["type"]]
            and (receipt["state"] == "completed")
            == (receipt["phase"] == PHASES[workflow["type"]][-1]),
            "retained workflow advance outcome changed",
        )
        phases = PHASES[workflow["type"]]
        position = phases.index(receipt["phase"])
        if position > 0:
            require_bound_phase(
                workflow, phases[position - 1], before_generation=receipt["generation"]
            )


def _completion_witnesses(request: dict[str, Any], workflow: dict[str, Any]) -> None:
    from .transfers import _proofs

    completion, transfer = request["transfer_completion"], workflow["transfer"]
    if transfer is None or transfer["phase"] == "completed":
        _require(completion is None, "no pending workflow transfer to complete")
        return
    _require(
        completion is not None and transfer is not None and transfer["phase"] == "commit",
        "workflow transfer has not committed locally",
    )
    assert completion is not None and transfer is not None
    _require(
        request["phase"] == workflow["phase"],
        "driver transfer completion must preserve procedure phase",
    )
    _require(
        completion["transfer_id"] == transfer["proposal"]["transfer_id"]
        and completion["proposal_digest"] == transfer["proposal_digest"],
        "workflow transfer completion identity changed",
    )
    found = _proofs(completion["witnesses"], transfer["proposal"], "transferred")
    owners = {canonical(item["owner"]) for item in workflow["participants"]}
    _require(found == owners, "workflow transfer completion lacks participant commits")
    local = next(item for item in completion["witnesses"] if item["owner"] == workflow["owner"])
    _require(local in transfer["commit_witnesses"], "workflow transfer local commit changed")


def validate_advance_request(
    request: dict[str, Any],
    workflow: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> str:
    """Classify exact replay/new decoded input without changing owner state."""
    from .handoffs import validate_workflow

    validate("workflow.schema.json", request, "AdvanceRequest")
    validate_workflow(workflow, recovery_readers=recovery_readers)
    _require(
        request["owner"] == workflow["owner"] and request["workflow_id"] == workflow["id"],
        "workflow advance receiver changed",
    )
    for receipt in workflow["advances"]:
        if receipt["request"]["advance_id"] == request["advance_id"]:
            _require(receipt["request"] == request, "accepted workflow advance input changed")
            return "replay"
    _require(
        request["expected_generation"] == workflow["generation"] < 9007199254740991
        and request["driver_term"] == workflow["driver_term"],
        "workflow advance generation or driver term changed",
    )
    _require(
        workflow.get("recovery", {}).get("phase", "committed") == "committed",
        "workflow recovery preparation is not committed",
    )
    completion_only = (
        request["transfer_completion"] is not None and request["phase"] == workflow["phase"]
    )
    allowed = {"prepared", "active", "paused"}
    if completion_only:
        allowed.add("recovery-required")
    _require(workflow["state"] in allowed, "workflow cannot advance in this state")
    _completion_witnesses(request, workflow)
    phases = PHASES[workflow["type"]]
    position = phases.index(workflow["phase"])
    following = phases[position + 1] if position + 1 < len(phases) else None
    _require(
        request["phase"] == following
        or (request["transfer_completion"] is not None and request["phase"] == workflow["phase"]),
        "workflow advance skips installed phase",
    )
    from .workflow_bindings import require_bound_phase

    if request["phase"] != workflow["phase"]:
        require_bound_phase(workflow, workflow["phase"])
    owners = {canonical(item["owner"]) for item in workflow["participants"]}
    for witness in request["witnesses"]:
        _require(
            witness["workflow_id"] == workflow["id"] and canonical(witness["owner"]) in owners,
            "workflow advance prerequisite outside closure",
        )
    return "new"


def advance_workflow(
    request: dict[str, Any],
    workflow: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Model one atomic record transition; this does not execute or release anything."""
    from .handoffs import validate_workflow

    disposition = validate_advance_request(request, workflow, recovery_readers=recovery_readers)
    result = copy.deepcopy(workflow)
    if disposition == "replay":
        return result
    completion = request["transfer_completion"]
    if completion is not None:
        result["transfer"]["commit_witnesses"] = copy.deepcopy(completion["witnesses"])
        result["transfer"]["phase"] = "completed"
    result["generation"] += 1
    result["phase"] = request["phase"]
    if request["phase"] != workflow["phase"]:
        result["state"] = (
            "completed" if request["phase"] == PHASES[workflow["type"]][-1] else "active"
        )
    known = {canonical(witness) for witness in result["prerequisite_witnesses"]}
    for witness in request["witnesses"]:
        if canonical(witness) not in known:
            result["prerequisite_witnesses"].append(copy.deepcopy(witness))
            known.add(canonical(witness))
    result["advances"].append(
        {
            "request": copy.deepcopy(request),
            "request_digest": digest(request),
            **{key: result[key] for key in ("generation", "driver_term", "phase", "state")},
        }
    )
    validate_workflow(result, recovery_readers=recovery_readers)
    return result
