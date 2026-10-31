"""Typed retirement/pruning evidence and exact current-state joins.

The receiving owner supplies authenticated protected context, accepted policies,
complete dataset inventories and currently verified custody independently of the
request. These pure checks do not enroll keys, observe native state, authorize a
principal, persist preparation or execute retirement/deletion.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .bounds import Bounds, bounds
from .handoffs import schema_identity, validate_staged_input
from .resources import retained_runtime_handles
from .validation import ContractError, canonical, digest, strict_json, validate

Authenticate = Callable[[dict[str, Any], dict[str, Any], str], None]
Attest = Callable[[dict[str, Any]], dict[str, Any]]
_ACTIONS = {"app.retire", "host.retire", "backend.prune"}
_SCHEMA = "lifecycle-evidence.schema.json"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _bounds(name: str) -> Bounds:
    proof = "tests/test_lifecycle_evidence.py::test_lifecycle_complete_work_is_linear"
    return Bounds(
        id="lifecycle." + name,
        work="O(B) complete input/evidence, native selection, retention and custody bytes with indexed joins; independent authentication/native verifiers own their work bounds",
        extent="Every selected resource/object, policy, obligation and surviving recovery closure; no collection-count ceiling",
        limits=(),
        capacity=("receiving owner immutable evidence/content custody and metadata memory",),
        proofs=(proof,),
        linear_proofs=(proof,),
    )


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _definition(action: str) -> str:
    return "PruningEvidence" if action == "backend.prune" else "RetirementEvidence"


def _request(value: dict[str, Any]) -> dict[str, Any]:
    context = value["context"]
    return {
        "format": "deployment-ops/lifecycle-evidence/v1",
        "preparation_id": value["preparation_id"],
        "owner": context["owner"],
        "resource": context["resource"],
        "selection": context["selection"],
    }


def _witness(
    value: dict[str, Any],
    *,
    owner: dict[str, Any],
    kind: str,
    state: str,
    authenticate: Authenticate,
    generation: int | None = None,
) -> None:
    witness = value["witness"]
    commitment = digest({key: item for key, item in value.items() if key != "witness"})
    _require(
        witness["owner"] == owner
        and witness["kind"] == kind
        and witness["state"] == state
        and witness["subject_digest"] == commitment
        and (generation is None or witness["generation"] == generation),
        "lifecycle witness identity mismatch",
    )
    # Caller resolves the approved owner/resource-scoped key independently. A
    # wire key_id or matching digest is never a key enrollment or authorization.
    authenticate(witness, owner, commitment)


@bounds(_bounds("reference"))
def validate_lifecycle_reference(reference: dict[str, Any]) -> None:
    validate(_SCHEMA, reference, "EvidenceReference")
    action, handle = reference["action"], reference["handle"]
    definition = _definition(action)
    _require(
        reference["schema"]
        == schema_identity(f"https://fishhat.invalid/contracts/{_SCHEMA}#/$defs/{definition}"),
        "lifecycle evidence schema substitution",
    )
    _require(
        handle["owner"] == reference["owner"]
        and handle["binding"]
        == {"kind": "lifecycle-evidence", "preparation_id": reference["preparation_id"]},
        "lifecycle evidence content custody mismatch",
    )
    expected = {
        "app.retire": ("app-ops", "app"),
        "host.retire": ("host-ops", "host"),
        "backend.prune": ("host-ops", "backend"),
    }[action]
    _require(
        (reference["owner"]["tool"], reference["resource"]["kind"]) == expected,
        "lifecycle action owner or resource kind mismatch",
    )


@bounds(_bounds("input"))
def decode_lifecycle_input(
    reference: dict[str, Any], data: bytes, *, expected_owner: dict[str, Any]
) -> dict[str, Any]:
    validate(_SCHEMA, reference, "InputReference")
    handle = reference["input"]
    _require(
        reference["owner"] == handle["owner"] == expected_owner,
        "lifecycle input owner epoch mismatch",
    )
    _require(
        len(data) == handle["size"]
        and "sha256:" + hashlib.sha256(data).hexdigest() == handle["digest"],
        "lifecycle input content identity mismatch",
    )
    value = strict_json(data, max_bytes=len(data))
    validate(_SCHEMA, value, "PrepareRequest")
    _require(
        canonical(value) == data
        and value["owner"] == expected_owner
        and value["preparation_id"] == reference["preparation_id"],
        "lifecycle input canonical encoding or identity mismatch",
    )
    return dict(value)


@bounds(_bounds("read"))
def decode_lifecycle_evidence(
    reference: dict[str, Any],
    data: bytes,
    *,
    expected_owner: dict[str, Any],
    authenticate: Authenticate,
) -> dict[str, Any]:
    """Read original retained bytes; expiry restricts admission, not inspection."""
    validate_lifecycle_reference(reference)
    _require(reference["owner"] == expected_owner, "lifecycle evidence owner epoch mismatch")
    handle = reference["handle"]
    _require(
        len(data) == handle["size"]
        and "sha256:" + hashlib.sha256(data).hexdigest() == handle["digest"],
        "lifecycle evidence content identity mismatch",
    )
    value = strict_json(data, max_bytes=len(data))
    validate(_SCHEMA, value, _definition(reference["action"]))
    context = value["context"]
    _require(canonical(value) == data, "lifecycle evidence is not canonical")
    _require(
        all(
            reference[key] == context[key]
            for key in ("owner", "resource", "generation", "holds_digest")
        )
        and reference["action"] == context["selection"]["action"]
        and reference["preparation_id"] == value["preparation_id"]
        and reference["request_digest"] == value["request_digest"] == digest(_request(value)),
        "lifecycle evidence reference or original request changed",
    )
    _witness(
        value,
        owner=expected_owner,
        kind="approval",
        state="prepared",
        generation=context["generation"],
        authenticate=authenticate,
    )
    _require(
        value["witness"]["created_at"] == context["observed_at"]
        and value["witness"]["workflow_id"] is None,
        "lifecycle preparation witness observation mismatch",
    )
    return dict(value)


def _backup_target(target: dict[str, Any], executor: dict[str, Any], repository: str) -> bytes:
    _require(
        executor["role"] == "backup"
        and executor["scope"]["kind"] == "backup-repository"
        and executor["scope"]["handle"] == repository
        and target["object"]["repository"] == repository
        and target["native_identity"]["scope"] == executor["scope"],
        "lifecycle backup repository or native scope mismatch",
    )
    return canonical(target["native_identity"])


def _selection(context: dict[str, Any]) -> set[bytes]:
    selected = context["selection"]
    action = selected["action"]
    expected = {
        "app.retire": ("app-ops", "app"),
        "host.retire": ("host-ops", "host"),
        "backend.prune": ("host-ops", "backend"),
    }[action]
    _require(
        (context["owner"]["tool"], context["resource"]["kind"]) == expected,
        "lifecycle action owner or resource kind mismatch",
    )
    if action == "backend.prune":
        _require(context["resource"]["kind"] == "backend", "pruning resource changed")
        native: set[bytes] = set()
        handles: set[str] = set()
        for target in selected["objects"]:
            key = _backup_target(target, selected["executor"], selected["repository"])
            handle = target["object"]["handle"]
            _require(key not in native and handle not in handles, "duplicate pruning object")
            native.add(key)
            handles.add(handle)
        protected = {canonical(item) for item in context["protected_objects"]}
        _require(len(protected) == len(context["protected_objects"]), "duplicate protected object")
        _require(not native & protected, "pruning selects a currently protected object")
        return native
    targets = selected["targets"]
    names = {item["resource"]["id"] for item in targets}
    identities = {canonical(item["native_identity"]) for item in targets}
    _require(
        len(names) == len(targets) == len(identities), "duplicate retirement target or incarnation"
    )
    if action == "app.retire":
        _require(
            len(targets) == 1
            and targets[0]["resource"] == context["resource"]
            and targets[0]["generation"] == context["generation"]
            and len(selected["datasets"]) == 1
            and selected["datasets"][0]["owner"] == context["owner"]
            and selected["datasets"][0]["resource"] == context["resource"],
            "application retirement selection or complete dataset inventory changed",
        )
    else:
        _require(context["resource"]["kind"] == "host", "host retirement resource changed")
    return set()


def _retention_requirements(
    context: dict[str, Any],
    policies: list[dict[str, Any]],
    inventories: list[dict[str, Any]],
    now: str,
) -> set[tuple[bytes, str]]:
    indexed = {canonical([item["owner"], item["account"]]): item for item in inventories}
    _require(len(indexed) == len(inventories), "duplicate retention inventory")
    expected = {canonical([item["owner"], item["account"]]): item for item in context["retention"]}
    bindings: dict[bytes, dict[str, Any]] = {}
    local: set[tuple[bytes, str]] = set()
    for policy in policies:
        key = canonical([policy["owner"], policy["account"]])
        _require(
            key not in bindings and key in indexed and key in expected,
            "retention policy coverage mismatch",
        )
        inventory = indexed[key]
        decision = retained_runtime_handles(inventory, accepted_policy=policy, now=now)
        bindings[key] = {
            "owner": policy["owner"],
            "resource": expected[key]["resource"],
            "account": policy["account"],
            "policy_generation": policy["generation"],
            "policy_digest": digest(policy),
            "inventory_digest": digest(inventory),
            "protection_generation": inventory["protection_generation"],
        }
        owner = canonical([policy["owner"], expected[key]["resource"]])
        local.update((owner, material) for material in decision["protected_roots"])
    _require(
        len(expected) == len(context["retention"])
        and bindings == expected
        and indexed.keys() == bindings.keys(),
        "current lifecycle retention policy or protection binding changed",
    )
    return local


def _dataset_requirements(
    context: dict[str, Any], inventories: list[dict[str, Any]]
) -> tuple[set[tuple[bytes, str]], dict[tuple[bytes, str], dict[str, Any]]]:
    from .datasets import validate_dataset_inventory

    selection = context["selection"]
    bindings = [] if selection["action"] == "backend.prune" else selection["datasets"]
    indexed = {digest(item): item for item in inventories}
    _require(len(indexed) == len(inventories), "duplicate lifecycle dataset inventory")
    seen: set[str] = set()
    scopes: set[bytes] = set()
    required: set[tuple[bytes, str]] = set()
    obligations: dict[tuple[bytes, str], dict[str, Any]] = {}
    for binding in bindings:
        commitment = binding["inventory_digest"]
        _require(
            commitment in indexed and commitment not in seen, "dataset inventory absent or repeated"
        )
        inventory = indexed[commitment]
        validate_dataset_inventory(inventory)
        scope = canonical([inventory["owner"], inventory["resource"], inventory["app_instance"]])
        _require(scope not in scopes, "dataset inventory scope repeated")
        scopes.add(scope)
        seen.add(commitment)
        _require(
            all(binding[key] == inventory[key] for key in ("owner", "resource", "app_instance"))
            and set(binding["retained_obligations"])
            == {entry["obligation"]["id"] for entry in inventory["entries"]},
            "retirement dataset identity or complete obligation set changed",
        )
        owner = canonical([inventory["owner"], inventory["resource"]])
        for entry in inventory["entries"]:
            obligation = entry["obligation"]
            required.update((owner, material) for material in obligation["recovery_closure"])
            obligations[(owner, obligation["id"])] = {
                "inventory_digest": commitment,
                "obligation_id": obligation["id"],
                "obligation_digest": digest(obligation),
                "native_identity": obligation["native_identity"],
            }
    _require(seen == indexed.keys(), "retirement omits an affected dataset inventory")
    return required, obligations


def _custody_requirements(
    value: dict[str, Any],
    *,
    custody: list[dict[str, Any]],
    deleted: set[bytes],
    required: set[tuple[bytes, str]],
    local: set[tuple[bytes, str]],
    obligations: dict[tuple[bytes, str], dict[str, Any]],
    now: str,
    authenticate: Authenticate,
) -> None:
    indexed = {digest(item): item for item in custody}
    presented = {digest(item): item for item in value["custody"]}
    _require(
        len(indexed) == len(custody)
        and len(presented) == len(value["custody"])
        and indexed == presented,
        "lifecycle custody differs from independently verified current custody",
    )
    available: set[tuple[bytes, str]] = set()
    local_available: set[tuple[bytes, str]] = set()
    covered: set[tuple[bytes, str]] = set()
    declared = set(value["context"]["required_materials"])
    for item in value["custody"]:
        _require(
            _instant(item["verified_at"]) <= _instant(now) < _instant(item["valid_until"])
            and _instant(value["context"]["valid_until"]) <= _instant(item["valid_until"]),
            "lifecycle custody is stale or expires before evidence",
        )
        previous = item["previous_custodian"]
        _require(
            (item["state"] == "retained" and previous is None and item["previous_resource"] is None)
            or (
                item["state"] == "handoff-complete"
                and previous is not None
                and item["previous_resource"] is not None
                and (previous != item["owner"] or item["previous_resource"] != item["resource"])
            ),
            "lifecycle custody lacks completed handoff identity",
        )
        location = item["location"]
        if location["kind"] == "content":
            _require(
                location["handle"]["owner"] == item["owner"]
                and location["handle"]["digest"] == item["material_digest"],
                "lifecycle content custody changed",
            )
        elif location["kind"] == "native":
            _require(
                canonical(location["identity"]) not in deleted,
                "selected deletion is surviving custody",
            )
        else:
            target, executor = location["target"], location["executor"]
            key = _backup_target(target, executor, target["object"]["repository"])
            _require(
                key not in deleted
                and target["object"]["completeness"] == "sealed"
                and target["object"]["retrieval"] == "available"
                and item["material_digest"] in {a["digest"] for a in target["object"]["artifacts"]},
                "backup custody is deleted, incomplete or unavailable",
            )
        _witness(
            item, owner=item["owner"], kind="effect", state=item["state"], authenticate=authenticate
        )
        origin = item["owner"] if previous is None else previous
        resource = item["resource"] if previous is None else item["previous_resource"]
        authority = canonical([origin, resource])
        available.add((authority, item["material_digest"]))
        binding = item["obligation"]
        if binding is not None:
            obligation_key = (authority, binding["obligation_id"])
            _require(
                obligations.get(obligation_key) == binding
                and location["kind"] != "content"
                and item["material_digest"] in declared,
                "dataset custody lacks exact obligation or surviving native data",
            )
            _require(
                previous is not None
                or location["kind"] != "native"
                or location["identity"] == binding["native_identity"],
                "retained dataset native incarnation changed",
            )
            covered.add(obligation_key)
        if item["local"] and previous is None:
            local_available.add(
                (canonical([item["owner"], item["resource"]]), item["material_digest"])
            )
    _require(required <= available, "lifecycle evidence omits surviving recovery custody")
    _require(local <= local_available, "lifecycle evidence weakens required local retention")
    _require(
        covered == obligations.keys(), "lifecycle evidence omits positive native dataset custody"
    )


def _validate_current(
    value: dict[str, Any],
    *,
    current: dict[str, Any],
    accepted_policies: list[dict[str, Any]],
    retention_inventories: list[dict[str, Any]],
    dataset_inventories: list[dict[str, Any]],
    custody: list[dict[str, Any]],
    now: str,
    authenticate: Authenticate,
) -> None:
    """Check all authority/custody inputs before an owner issues its signature."""
    validate(_SCHEMA, value["context"], "Context")
    for item in value["custody"]:
        validate(_SCHEMA, item, "Custody")
    validate(_SCHEMA, current, "Context")
    validate("common.schema.json", now, "Time")
    context = value["context"]
    _require(context == current, "lifecycle owner, resource or current protection context changed")
    _require(
        _instant(context["observed_at"]) <= _instant(now) < _instant(context["valid_until"]),
        "lifecycle evidence observation is stale",
    )
    _require(value["request_digest"] == digest(_request(value)), "lifecycle request changed")
    _require(
        value["kind"] == _definition(context["selection"]["action"]),
        "lifecycle evidence kind changed",
    )
    deleted = _selection(context)
    local = _retention_requirements(context, accepted_policies, retention_inventories, now)
    required, obligations = _dataset_requirements(context, dataset_inventories)
    required |= local
    owner = canonical([context["owner"], context["resource"]])
    declared = set(context["required_materials"])
    _require(
        {material for _, material in required} <= declared, "lifecycle recovery closure omitted"
    )
    # Materials with an application/retention authority keep that exact authority;
    # additional subject-owned closure roots remain with the issuing owner.
    attributed = {material for _, material in required}
    required.update((owner, material) for material in declared - attributed)
    _custody_requirements(
        value,
        custody=custody,
        deleted=deleted,
        required=required,
        local=local,
        obligations=obligations,
        now=now,
        authenticate=authenticate,
    )


@bounds(_bounds("evidence"))
def validate_lifecycle_evidence(
    value: dict[str, Any],
    *,
    current: dict[str, Any],
    accepted_policies: list[dict[str, Any]],
    retention_inventories: list[dict[str, Any]],
    dataset_inventories: list[dict[str, Any]],
    custody: list[dict[str, Any]],
    now: str,
    authenticate: Authenticate,
) -> None:
    """Check current independent authority and complete custody under owner exclusion.

    Native owners separately authenticate complete context/custody and the actual
    principal's scoped permission. authenticate verifies independently approved
    scoped witness keys and raises on failure; it cannot come from request data.
    """
    validate(_SCHEMA, value, "Evidence")
    context = value["context"]
    _witness(
        value,
        owner=context["owner"],
        kind="approval",
        state="prepared",
        generation=context["generation"],
        authenticate=authenticate,
    )
    _require(
        value["witness"]["created_at"] == context["observed_at"]
        and value["witness"]["workflow_id"] is None,
        "lifecycle preparation witness observation mismatch",
    )
    _validate_current(
        value,
        current=current,
        accepted_policies=accepted_policies,
        retention_inventories=retention_inventories,
        dataset_inventories=dataset_inventories,
        custody=custody,
        now=now,
        authenticate=authenticate,
    )


@dataclass(frozen=True)
class PreparedEvidence:
    """Reference snapshot; native storage must commit all fields before reply."""

    input_reference: dict[str, Any]
    principal: str
    reference: dict[str, Any]
    data: bytes


@bounds(_bounds("prepare"))
def prepare_lifecycle_evidence(
    reference: dict[str, Any],
    data: bytes,
    staging: dict[str, Any],
    *,
    principal: str,
    current: dict[str, Any],
    accepted_policies: list[dict[str, Any]],
    retention_inventories: list[dict[str, Any]],
    dataset_inventories: list[dict[str, Any]],
    custody: list[dict[str, Any]],
    content_id: str,
    now: str,
    attest: Attest,
    authenticate: Authenticate,
    previous: PreparedEvidence | None = None,
) -> PreparedEvidence:
    """Prepare observational evidence or replay the exact retained preparation.

    Current scoped read/prepare authorization is checked by the native caller on
    every invocation. Replay precedes new-input expiry/current generation checks;
    it never makes stale evidence admissible or invokes a native effect.
    """
    request = decode_lifecycle_input(reference, data, expected_owner=current["owner"])
    if previous is not None:
        _require(
            previous.input_reference == reference and previous.principal == principal,
            "lifecycle preparation replay input or principal conflict",
        )
        old = decode_lifecycle_evidence(
            previous.reference,
            previous.data,
            expected_owner=current["owner"],
            authenticate=authenticate,
        )
        _require(
            old["request_digest"] == digest(request),
            "lifecycle preparation replay request conflict",
        )
        return deepcopy(previous)
    validate_staged_input(
        staging,
        reference["input"],
        expected_owner=current["owner"],
        principal=principal,
        resource=current["resource"],
        purpose="lifecycle-input",
        now=now,
    )
    _require(
        request["resource"] == current["resource"] and request["selection"] == current["selection"],
        "lifecycle selection differs from independent current authority",
    )
    validate("common.schema.json", content_id, "UUID")
    body = {
        "format": "deployment-ops/lifecycle-evidence/v1",
        "kind": _definition(request["selection"]["action"]),
        "preparation_id": request["preparation_id"],
        "request_digest": digest(request),
        "context": deepcopy(current),
        "custody": deepcopy(custody),
    }
    _validate_current(
        body,
        current=current,
        accepted_policies=accepted_policies,
        retention_inventories=retention_inventories,
        dataset_inventories=dataset_inventories,
        custody=custody,
        now=now,
        authenticate=authenticate,
    )
    value = {**body, "witness": attest(deepcopy(body))}
    validate(_SCHEMA, value, "Evidence")
    payload = canonical(value)
    result = {
        "kind": "LifecycleEvidenceReference",
        **{key: current[key] for key in ("owner", "resource", "generation", "holds_digest")},
        "action": request["selection"]["action"],
        "preparation_id": request["preparation_id"],
        "request_digest": value["request_digest"],
        "handle": {
            "owner": current["owner"],
            "id": content_id,
            "purpose": "content",
            "binding": {"kind": "lifecycle-evidence", "preparation_id": request["preparation_id"]},
            "digest": digest(value),
            "size": len(payload),
        },
        "schema": schema_identity(
            f"https://fishhat.invalid/contracts/{_SCHEMA}#/$defs/{value['kind']}"
        ),
    }
    decode_lifecycle_evidence(
        result, payload, expected_owner=current["owner"], authenticate=authenticate
    )
    return PreparedEvidence(deepcopy(reference), principal, deepcopy(result), payload)


@bounds(_bounds("material"))
def lifecycle_evidence_material(value: dict[str, Any]) -> set[str]:
    """Direct roots for complete Plan/Operation custody, including hidden full inputs."""
    validate(_SCHEMA, value, "Evidence")
    context = value["context"]
    roots = {
        digest(value),
        value["request_digest"],
        *context["required_materials"],
        *context["protected_references"],
    }
    for binding in context["retention"]:
        roots.update((binding["policy_digest"], binding["inventory_digest"]))
    if context["selection"]["action"] != "backend.prune":
        roots.update(item["inventory_digest"] for item in context["selection"]["datasets"])
    roots.update(item["material_digest"] for item in value["custody"])
    return roots


@bounds(_bounds("plan"))
def validate_lifecycle_plan(plan: dict[str, Any]) -> None:
    """Join the finite reference; admission also requires its complete typed bytes."""
    subject = plan["subject"]
    if subject["action"] not in _ACTIONS:
        return
    reference = subject["arguments"]["evidence"]
    validate_lifecycle_reference(reference)
    _require(
        reference["owner"] == plan["owner"]
        and reference["resource"] == subject["resource"]
        and reference["action"] == subject["action"],
        "lifecycle Plan owner, resource or action changed",
    )
    preconditions = {
        canonical([item["owner"], item["resource"]]): item for item in plan["preconditions"]
    }
    current = preconditions.get(canonical([plan["owner"], subject["resource"]]))
    _require(
        current is not None
        and current["generation"] == reference["generation"]
        and current["holds_digest"] == reference["holds_digest"],
        "lifecycle Plan resource generation or holds changed",
    )


@bounds(_bounds("admission"))
def validate_lifecycle_admission(
    plan: dict[str, Any],
    data: bytes,
    *,
    current: dict[str, Any],
    accepted_policies: list[dict[str, Any]],
    retention_inventories: list[dict[str, Any]],
    dataset_inventories: list[dict[str, Any]],
    custody: list[dict[str, Any]],
    now: str,
    authenticate: Authenticate,
) -> dict[str, Any]:
    """Join complete evidence at new Plan admission; return evidence, never permission.

    Accepted replay does not re-admit an expired Plan. Before each later effect,
    validate_lifecycle_evidence separately rechecks current protection/custody;
    accepted outcomes and uncertainty remain owned by the Operation contract.
    """
    from .validation import validate_plan

    validate_plan(plan)
    _require(plan["subject"]["action"] in _ACTIONS, "not a lifecycle Plan")
    _require(_instant(now) < _instant(plan["expires_at"]), "lifecycle Plan expired")
    value = decode_lifecycle_evidence(
        plan["subject"]["arguments"]["evidence"],
        data,
        expected_owner=current["owner"],
        authenticate=authenticate,
    )
    validate_lifecycle_evidence(
        value,
        current=current,
        accepted_policies=accepted_policies,
        retention_inventories=retention_inventories,
        dataset_inventories=dataset_inventories,
        custody=custody,
        now=now,
        authenticate=authenticate,
    )
    _require(
        lifecycle_evidence_material(value) <= set(plan["input_digests"]),
        "lifecycle Plan lacks complete evidence or recovery material custody",
    )
    selection = value["context"]["selection"]
    if selection["action"] != "backend.prune":
        preconditions = {
            canonical([item["owner"], item["resource"]]): item for item in plan["preconditions"]
        }
        for target in selection["targets"]:
            precondition = preconditions.get(canonical([current["owner"], target["resource"]]))
            _require(
                precondition is not None and precondition["generation"] == target["generation"],
                "lifecycle target lacks exact reviewed resource generation",
            )
        if selection["action"] == "host.retire":
            _require(
                set(plan["subject"]["arguments"]["resources"])
                == {item["resource"]["id"] for item in selection["targets"]},
                "host retirement selected resource set changed",
            )
    return value
