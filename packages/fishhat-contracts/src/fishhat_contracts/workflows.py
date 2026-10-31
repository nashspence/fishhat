"""Complete shared workflow inspection models; no live owner admission.

These full-value helpers construct and validate an explicitly requested audit
projection from independently retained facts. They are not a journal writer or
a participant protocol: live admission uses workflow_journal and its partitioned
owner journals. Materialize complete views only for explicit inspection, never
after each accepted child or at every participating owner.

Decoded immutable workflow inputs and finite transition reference models.

These complete-input checks make no native authorization, persistence or bounded
streaming claim. Receivers independently authenticate Plans and witnesses, verify
local content custody and authorize the entire local participant closure before
acknowledging work. A Python argument never supplies that authority.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable, Iterable, Iterator, Mapping
from heapq import merge
from typing import Any

from .adapter_semantics import check_request
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
    if intent["kind"] in {"reviewed-successor", "reviewed-initial"}:
        return str(intent["subject"]["action"])
    return "publisher.publish" if intent["kind"] == "secret-publication" else str(intent["action"])


def bound_plan(binding: dict[str, Any]) -> dict[str, Any]:
    """Return exact Plan identity without granting a completed slot execution."""
    return dict(binding["completed"]["plan"] if "completed" in binding else binding["plan"])


def _child_identity_matches(
    operation: dict[str, Any],
    reference: dict[str, Any],
    binding: dict[str, Any],
    workflow_id: str,
) -> bool:
    """Match ordinary membership or the exact preserved completed ancestor.

    Recovery gives a completed slot a new reference, never a rewritten Operation
    or witness. Its original workflow identity remains part of the exact record.
    """
    if "completed" in binding:
        return bool(operation == binding["completed"]["operation"])
    return bool(
        operation["owner"] == reference["owner"]
        and operation["request_id"] == reference["request_id"]
        and operation["witness"]["workflow_id"] == workflow_id
    )


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
    if intent["kind"] == "reviewed-initial":
        _require(
            index == 0
            and proposal["type"] != "secret-rotation"
            and PHASES[proposal["type"]].index(binding["phase"]) >= 2
            and intent["subject"]["resource"] == participant["resource"],
            "initial workflow review lacks its installed predecessor barrier",
        )
        return
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
    available: set[bytes],
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
        _require(
            all(
                canonical([binding["plan"]["owner"], d]) in available
                for d in binding["plan"]["input_digests"]
            ),
            "workflow Plan input lacks retained content handle",
        )
    else:
        _intent_binding(binding, participant, index, proposal)
        if binding["intent"]["kind"] == "reviewed-initial":
            _require(
                all(canonical(h) in content for h in _handles(binding["intent"]["subject"])),
                "initial workflow intent handle missing from content closure",
            )


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
    generations: Mapping[bytes, int],
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
    check_request(executor["role"], request)
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
    result_schema = schema_identity(role_schema + "#/$defs/RetainedResult")
    input_key = (arguments["input_schema"]["uri"], arguments["input_schema"]["digest"])
    result_key = (arguments["result_schema"]["uri"], arguments["result_schema"]["digest"])
    input_current = arguments["input_schema"] == input_schema
    _require(
        arguments["input_schema"]["uri"] == input_schema["uri"]
        and (input_current or (recovery_readers is not None and input_key in recovery_readers))
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
    available = {canonical([h["owner"], h["digest"]]) for h in proposal["content"]}
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
                available,
                recovery=recovery,
                recovery_readers=recovery_readers,
            )
            requests[key] = binding
    _validate_native_participants(proposal)
    seen: set[bytes] = set()
    for role, reference in proposal["target"].items():
        if proposal["type"] == "relocation" and role == "destination":
            continue
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


def _validate_native_participants(proposal: dict[str, Any]) -> None:
    """Keep the destination's native obligations in every ordinary owner closure.

    This is an identity/role join, not native authorization, fencing or dispatch.
    The installed relocation is the only procedure with a childless participant.
    """
    native = [p for p in proposal["participants"] if "native_role" in p]
    if proposal["type"] != "relocation":
        _require(not native, "native participant outside installed relocation")
        return
    destination = proposal["target"]["destination"]
    _require(
        len(native) == 1
        and all(native[0][key] == destination[key] for key in ("owner", "resource")),
        "relocation requires its exact native destination participant",
    )
    for participant in proposal["participants"]:
        for binding in participant["requests"]:
            subject = (
                binding["intent"]["subject"]
                if "intent" in binding
                else bound_plan(binding)["subject"]
            )
            _require(
                subject["arguments"]["destination_host"] == destination["resource"]["id"],
                "relocation child changed destination host",
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
            **({"native_role": item["native_role"]} if "native_role" in item else {}),
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
    from .workflow_preparation import validate_workflow_agreement

    validate_workflow_bindings(workflow, recovery_readers=recovery_readers)
    validate_workflow_agreement(
        workflow, require_complete=workflow["phase"] != PHASES[workflow["type"]][0]
    )
    _validate_advance_history(workflow, recovery_readers=recovery_readers)
    phases = PHASES[workflow["type"]]
    if workflow["phase"] in phases and phases.index(workflow["phase"]) > 0:
        require_bound_phase(workflow, phases[phases.index(workflow["phase"]) - 1])
    from .workflow_recovery import validate_recovery_custody

    validate_recovery_custody(workflow, recovery_readers=recovery_readers)


def prepare_workflow_view(
    request: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    principal: str,
    verified_driver: dict[str, Any],
    verified_content: list[dict[str, Any]],
    verified_preparation: dict[str, Any] | None,
    verified_adapters: list[dict[str, Any]] | None = None,
    retained: dict[str, Any] | None = None,
    retained_retirement: dict[str, Any] | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Build/replay a pure capsule after independent receiving checks.

    verified_driver, verified_content, verified_adapters and retained come from protected owner
    state, never from the request. Equality models custody and enrollment joins,
    not authentication, authorization, native method support or durable pinning.
    verified_preparation is issued only with durable custody; retained_retirement
    is independently resolved by workflow identity, including restored tombstones.
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
    if retained_retirement is not None:
        from .workflow_unprepared import validate_never_prepared

        validate_never_prepared(retained_retirement)
        _require(
            all(retained_retirement["owner"][k] == expected_owner[k] for k in ("tool", "id"))
            and retained_retirement["workflow_id"] == proposal["workflow_id"],
            "initial workflow retirement selection changed",
        )
        raise ContractError("retired initial workflow cannot prepare again")
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
    from .workflow_preparation import validate_preparation_witness

    _require(verified_preparation is not None, "workflow local preparation proof required")
    assert verified_preparation is not None
    validate_preparation_witness(verified_preparation, proposal, owner=expected_owner)
    result = prepared_workflow_view(proposal, expected_owner)
    result["prerequisite_witnesses"] = [copy.deepcopy(verified_preparation)]
    validate_workflow(result, recovery_readers=recovery_readers)
    return result


def prepared_workflow_view(
    proposal: dict[str, Any], expected_owner: dict[str, Any]
) -> dict[str, Any]:
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


def decode_workflow_audit_input(
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


def _driver_transfer_window(workflow: dict[str, Any]) -> tuple[int, int | None] | None:
    """Locate the retained transfer's closed driver-admission interval."""
    transfer = workflow["transfer"]
    if transfer is None:
        return None
    freezes = [item for item in transfer["accepted_phases"] if item["phase"] == "freeze"]
    _require(len(freezes) == 1, "retained transfer lacks its exact freeze input")
    completions = [
        receipt
        for receipt in workflow["advances"]
        if receipt["authority"] == "driver"
        and receipt["request"]["transfer_completion"] is not None
        and receipt["request"]["transfer_completion"]["transfer_id"]
        == transfer["proposal"]["transfer_id"]
    ]
    if transfer["phase"] == "completed":
        _require(len(completions) == 1, "completed transfer lacks exact advance receipt")
        end = int(completions[0]["generation"])
    else:
        _require(not completions, "pending transfer has a retained completion receipt")
        end = None
    return int(freezes[0]["expected_generation"]), end


def retained_transition_input(receipt: dict[str, Any]) -> dict[str, Any]:
    """Select the original input without confusing native and driver authority."""
    key = {"driver": "request", "native-owner": "completion", "native-lifecycle": "decision"}[
        receipt["authority"]
    ]
    return dict(receipt[key])


def _require_recovery_admission(workflow: dict[str, Any], expected_generation: int) -> None:
    recovery = workflow.get("recovery")
    if recovery is None:
        return
    commit = recovery["commit"]
    _require(
        commit is not None and expected_generation >= commit["generation"],
        "retained workflow admission precedes committed recovery preparation",
    )


def _custody_events(
    workflow: dict[str, Any], transfer_window: tuple[int, int | None] | None
) -> Iterator[tuple[int, str]]:
    """Merge ordered bindings with the finite transfer/abandonment phase facts."""
    events = []
    transfer = workflow["transfer"]
    if transfer is not None:
        for original in transfer["accepted_phases"]:
            _require_recovery_admission(workflow, original["expected_generation"])
            witnesses = transfer[original["phase"] + "_witnesses"]
            local = next((item for item in witnesses if item["owner"] == workflow["owner"]), None)
            _require(local is not None, "local transfer phase lacks retained witness")
            assert local is not None
            events.append((local["generation"], "transfer"))
    abandonment = workflow.get("recovery", {}).get("abandonment")
    if abandonment is not None:
        events.append((abandonment["generation"], "abandonment"))
    bindings = ((receipt["generation"], "binding") for receipt in workflow["bindings"])
    previous = 0
    # There are at most two installed transfer phases and one abandonment.
    # Bindings remain a complete, linearly merged collection without a size cap.
    for generation, kind in merge(bindings, sorted(events)):
        _require(generation > previous, "workflow custody changes share a generation")
        if kind == "binding":
            _require_recovery_admission(workflow, generation - 1)
            if transfer_window is not None and generation > transfer_window[0]:
                _require(
                    transfer_window[1] is not None and generation > transfer_window[1],
                    "retained workflow binding was recorded inside a pending transfer",
                )
        previous = generation
        yield generation, kind


def _custody_lifecycle(state: str, kind: str) -> str:
    if kind == "binding":
        _require(state in {"prepared", "active"}, "retained binding bypassed workflow lifecycle")
    elif kind == "transfer":
        _require(
            state not in {"completed", "cancelled"},
            "retained transfer follows terminal workflow lifecycle",
        )
    else:
        _require(state != "completed", "completed workflow cannot be abandoned")
        return "cancelled"
    return state


def _validate_advance_history(
    workflow: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    from .workflow_bindings import require_bound_phase
    from .workflow_evidence import validate_phase_evidence
    from .workflow_lifecycle import validate_lifecycle_decision
    from .workflow_settlement import validate_native_completion

    identities: set[str] = set()
    generation = 0
    phases = PHASES[workflow["type"]]
    _require(workflow["phase"] in phases, "workflow phase outside installed procedure")
    phase_position = 0
    bound_phases: set[str] = set()
    state = "prepared"
    transfer_window = _driver_transfer_window(workflow)
    custody_events = _custody_events(workflow, transfer_window)
    custody = next(custody_events, None)
    for receipt in workflow["advances"]:
        while custody is not None and custody[0] < receipt["generation"]:
            state = _custody_lifecycle(state, custody[1])
            custody = next(custody_events, None)
        _require(
            custody is None or custody[0] != receipt["generation"],
            "workflow transition shares a custody generation",
        )
        _require(
            state not in {"completed", "cancelled"},
            "workflow transition follows terminal settlement or cancellation",
        )
        native = receipt["authority"] == "native-owner"
        lifecycle = receipt["authority"] == "native-lifecycle"
        original = retained_transition_input(receipt)
        original_digest = receipt[
            "decision_digest" if lifecycle else "completion_digest" if native else "request_digest"
        ]
        _require(original["advance_id"] not in identities, "duplicate retained workflow advance")
        identities.add(original["advance_id"])
        _require(
            original["owner"] == workflow["owner"]
            and original["workflow_id"] == workflow["id"]
            and original_digest == digest(original),
            "retained workflow advance identity changed",
        )
        _require_recovery_admission(workflow, original["expected_generation"])
        _require(
            generation < receipt["generation"] <= workflow["generation"]
            and original["expected_generation"] + 1 == receipt["generation"]
            and original["driver_term"] == receipt["driver_term"] <= workflow["driver_term"],
            "retained workflow advance generation changed",
        )
        generation = receipt["generation"]
        if lifecycle:
            _require(
                original["from_state"] == state
                and original["phase"] == receipt["phase"] == phases[phase_position],
                "retained workflow lifecycle predecessor changed",
            )
            state = validate_lifecycle_decision(original, workflow)
            _require(receipt["state"] == state, "retained workflow lifecycle outcome changed")
            if original["action"] == "resume" and transfer_window is not None:
                _require(
                    receipt["generation"] <= transfer_window[0]
                    or (
                        transfer_window[1] is not None
                        and receipt["generation"] > transfer_window[1]
                    ),
                    "retained workflow resume bypassed incomplete transfer",
                )
            continue
        destination = phases[-1] if native else original["phase"]
        _require(
            destination == receipt["phase"] in phases
            and (receipt["state"] == "completed")
            == (receipt["phase"] == PHASES[workflow["type"]][-1]),
            "retained workflow advance outcome changed",
        )
        if native or original["transfer_completion"] is None:
            phase_position += 1
            _require(
                receipt["state"] == ("completed" if destination == phases[-1] else "active"),
                "ordinary workflow transition changed lifecycle outcome",
            )
        _require(
            phase_position < len(phases) and destination == phases[phase_position],
            "retained workflow phase history is incomplete or reordered",
        )
        if native:
            _require(state in {"active", "paused"}, "native settlement bypassed workflow lifecycle")
            validate_native_completion(
                original,
                workflow,
                before_generation=receipt["generation"],
                recovery_readers=recovery_readers,
            )
        else:
            if original["transfer_completion"] is None:
                _require(
                    state in {"prepared", "active"}, "driver advance bypassed workflow lifecycle"
                )
            else:
                _require(
                    receipt["state"] == state, "transfer completion changed workflow lifecycle"
                )
            if transfer_window is not None and receipt["generation"] > transfer_window[0]:
                _require(
                    transfer_window[1] is not None and receipt["generation"] >= transfer_window[1],
                    "driver advance was recorded inside a pending transfer",
                )
            validate_phase_evidence(
                original,
                workflow,
                before_generation=receipt["generation"],
                recovery_readers=recovery_readers,
            )
        state = receipt["state"]
        position = phases.index(receipt["phase"])
        if position > 0 and phases[position - 1] not in bound_phases:
            require_bound_phase(
                workflow, phases[position - 1], before_generation=receipt["generation"]
            )
            # Bindings are validated append-only above. Once the complete phase
            # closure held at its first transition, a same-phase transfer cannot
            # remove it or make a later binding authorize that earlier advance.
            bound_phases.add(phases[position - 1])
    while custody is not None:
        state = _custody_lifecycle(state, custody[1])
        custody = next(custody_events, None)
    _require(
        workflow["phase"] == phases[phase_position],
        "workflow phase lacks its complete retained transition history",
    )
    _require(workflow["state"] == state, "workflow lifecycle differs from retained history")


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
        original = retained_transition_input(receipt)
        if original["advance_id"] == request["advance_id"]:
            _require(
                receipt["authority"] == "driver", "workflow transition identity changed authority"
            )
            _require(original == request, "accepted workflow advance input changed")
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
    allowed = {"prepared", "active"}
    if completion_only:
        allowed.update({"paused", "recovery-required"})
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
        from .workflow_preparation import validate_workflow_agreement

        validate_workflow_agreement(workflow, witnesses=request["witnesses"], require_complete=True)
    owners = {canonical(item["owner"]) for item in workflow["participants"]}
    for witness in request["witnesses"]:
        _require(
            witness["workflow_id"] == workflow["id"] and canonical(witness["owner"]) in owners,
            "workflow advance prerequisite outside closure",
        )
    from .workflow_evidence import validate_phase_evidence

    validate_phase_evidence(request, workflow, recovery_readers=recovery_readers)
    return "new"


def advance_workflow_view(
    request: dict[str, Any],
    workflow: dict[str, Any],
    *,
    verified_phase_evidence: dict[str, Any] | None = None,
    now: str | None = None,
    verified_preparations: list[dict[str, Any]] | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Model one atomic record transition; this does not execute or release anything."""
    from .handoffs import validate_workflow

    disposition = validate_advance_request(request, workflow, recovery_readers=recovery_readers)
    result = copy.deepcopy(workflow)
    if disposition == "replay":
        return result
    from .workflow_evidence import require_verified_phase_evidence
    from .workflow_preparation import require_verified_preparations

    require_verified_phase_evidence(request, verified_phase_evidence, now=now)
    require_verified_preparations(request, workflow, verified_preparations)
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
            "authority": "driver",
            "request": copy.deepcopy(request),
            "request_digest": digest(request),
            **{key: result[key] for key in ("generation", "driver_term", "phase", "state")},
        }
    )
    validate_workflow(result, recovery_readers=recovery_readers)
    return result
