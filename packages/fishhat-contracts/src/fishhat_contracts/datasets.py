"""Reviewed dataset obligations across source releases, without native authority.

Receiving owners independently supply complete protected inventories, approved
native admissions and current authorization/evidence verifiers. These pure joins
do not create storage, authenticate a receipt, commit state or delete data.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from typing import Any

from .bounds import Bounds, bounds
from .validation import ContractError, canonical, digest, validate

_SAFETY_FIELDS = ("custody", "recovery", "owner", "native_format", "grant")
DischargeVerifier = Callable[[dict[str, Any], Mapping[str, dict[str, Any]]], None]
TransitionAuthorizer = Callable[[dict[str, Any], str], None]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _bounds(name: str) -> Bounds:
    proof = "tests/test_dataset_transitions.py::test_dataset_transition_linear_work"
    return Bounds(
        id="datasets." + name,
        work="O(B) complete inventory, transition, source and admission bytes with indexed identity joins; independent native verifiers retain their own complete-work bounds",
        extent="Every active and discharged obligation, proposed binding, admission and discharge; no collection-count ceiling",
        limits=(),
        capacity=("receiving owner admits complete retained dataset/recovery custody",),
        proofs=(proof,),
        linear_proofs=(proof,),
    )


@bounds(_bounds("inventory"))
def validate_dataset_inventory(value: dict[str, Any]) -> None:
    """Validate complete retained metadata; callers authenticate completeness separately."""
    validate("dataset-obligations.schema.json", value, "DatasetInventory")
    identities: set[str] = set()
    native: set[bytes] = set()
    names: set[str] = set()
    for entry in value["entries"]:
        obligation = entry["obligation"]
        identity = obligation["id"]
        _require(identity not in identities, "duplicate dataset obligation identity")
        identities.add(identity)
        key = canonical(obligation["native_identity"])
        _require(key not in native, "dataset native incarnation reused")
        native.add(key)
        _require(
            obligation["native_identity"]["scope"]["authority"] == value["owner"]["id"],
            "dataset native authority differs from receiving owner",
        )
        _require(
            obligation["origin_release_digest"] in obligation["recovery_closure"],
            "dataset original release missing from recovery closure",
        )
        discharge = entry["discharge"]
        if discharge is None:
            _require(entry["dataset"] not in names, "duplicate active dataset name")
            names.add(entry["dataset"])
        else:
            _require(
                discharge["obligation_id"] == identity
                and discharge["obligation_digest"] == digest(obligation),
                "dataset discharge differs from original obligation",
            )
    if value["accepted_release_digest"] is None:
        _require(
            value["generation"] == 0 and not value["entries"],
            "initial dataset inventory must be empty",
        )


def _same_responsibility(original: dict[str, Any], proposed: dict[str, Any]) -> bool:
    return all(original[key] == proposed[key] for key in _SAFETY_FIELDS)


def require_dataset_source(
    inventory: dict[str, Any], *, accepted_app: dict[str, Any], accepted_release_digest: str
) -> None:
    """Join an independently accepted source to its complete protected obligation set.

    The receiving owner separately validates the complete source and secret
    catalogue and authenticates its release binding before supplying this context.
    """
    validate_dataset_inventory(inventory)
    validate("source.schema.json", accepted_app, "App")
    _require(
        inventory["accepted_release_digest"] == accepted_release_digest,
        "dataset inventory differs from accepted release",
    )
    _require(
        inventory["resource"] == {"kind": "app", "id": accepted_app["id"]},
        "dataset inventory differs from source application identity",
    )
    active = {
        entry["dataset"]: entry["obligation"]
        for entry in inventory["entries"]
        if entry["discharge"] is None
    }
    _require(
        set(active) == set(accepted_app["datasets"]), "accepted source omits dataset obligations"
    )
    for name, obligation in active.items():
        _require(
            _same_responsibility(obligation["declaration"], accepted_app["datasets"][name]),
            "accepted source reclassifies dataset responsibility",
        )


def _transition_indexes(
    value: dict[str, Any],
) -> tuple[dict[str, str], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    validate("dataset-obligations.schema.json", value, "DatasetTransition")
    bindings = {item["obligation_id"]: item["dataset"] for item in value["bindings"]}
    admissions = {item["id"]: item for item in value["admissions"]}
    discharges = {item["obligation_id"]: item for item in value["discharges"]}
    _require(
        len(bindings) == len(value["bindings"]) and len(set(bindings.values())) == len(bindings),
        "duplicate dataset transition binding",
    )
    _require(len(admissions) == len(value["admissions"]), "duplicate dataset admission")
    _require(len(discharges) == len(value["discharges"]), "duplicate dataset discharge")
    _require(not bindings.keys() & discharges.keys(), "continued dataset is also discharged")
    return bindings, admissions, discharges


def dataset_transition_material(value: dict[str, Any]) -> set[str]:
    """Direct material roots; the owner retains the complete referenced input closures."""
    _transition_indexes(value)
    roots = {digest(value), value["before_inventory_digest"], value["release_digest"]}
    if value["previous_release_digest"] is not None:
        roots.add(value["previous_release_digest"])
    for obligation in value["admissions"]:
        roots.update(obligation["recovery_closure"])
    roots.update(item["evidence_digest"] for item in value["discharges"])
    return roots


def validate_dataset_plan(plan: dict[str, Any]) -> None:
    """Join the reviewed capsule after ordinary Plan shape/digest validation."""
    if plan["subject"]["action"] not in {"app.deploy", "app.upgrade"}:
        return
    transition = plan["dataset_transition"]
    _require(
        transition["owner"] == plan["owner"]
        and transition["resource"] == plan["subject"]["resource"]
        and transition["release_digest"] == plan["subject"]["arguments"]["release_digest"],
        "dataset transition differs from reviewed application release",
    )
    _require(
        dataset_transition_material(transition) <= set(plan["input_digests"]),
        "dataset transition material outside reviewed Plan",
    )


@bounds(_bounds("transition"))
def require_dataset_transition(
    value: dict[str, Any],
    *,
    current_inventory: dict[str, Any],
    proposed_app: dict[str, Any],
    proposed_release_digest: str,
    approved_admissions: Mapping[str, dict[str, Any]],
    approved_bindings: Mapping[str, dict[str, Any]],
    authorize_transition: TransitionAuthorizer,
    verify_discharges: DischargeVerifier,
) -> dict[str, Any]:
    """Propose the exact successor inventory using independent current owner facts.

    current_inventory is complete protected accepted state, not the transition's
    cached copy. approved_admissions and approved_bindings come from independently
    authorized native selection and positive incarnation/custody checks; neither
    source names nor request-supplied fields may populate them. Authorize the
    exact transition under current receiving permission, at least the required
    role passed to authorize_transition (administrator for any discharge,
    operator otherwise). verify_discharges independently authenticates typed retirement
    evidence, joins the complete inventory/native obligations and proves retained
    or successor custody under current authority. It receives the complete batch
    once so shared inventory/evidence is indexed once, not rescanned per dataset.
    A callback failure blocks. The supplied proposed source has independently
    passed complete source/catalogue validation and release binding checks.

    Reclassification uses an explicitly discharged original obligation plus an
    independently admitted successor native incarnation. Reusing a handle after
    verified replacement is allowed; merely relabeling the same native object is
    not. Original bytes and recovery custody remain protected by the discharge.

    Call these checks before review and again under native exclusion at admission
    and settlement. The returned value is a proposal, never committed acceptance.
    Only a verified successful owner transaction can install it; failures retain
    original obligations plus newly created native work in Operation custody.
    Exact accepted replay returns its original outcome before these freshness
    checks and cannot resurrect a discharged identity or lose original evidence.
    """
    bindings, admissions, discharges = _transition_indexes(value)
    validate_dataset_inventory(current_inventory)
    validate("source.schema.json", proposed_app, "App")
    _require(
        all(value[key] == current_inventory[key] for key in ("owner", "resource", "app_instance"))
        and value["resource"] == {"kind": "app", "id": proposed_app["id"]}
        and value["expected_generation"] == current_inventory["generation"]
        and value["before_inventory_digest"] == digest(current_inventory)
        and value["previous_release_digest"] == current_inventory["accepted_release_digest"]
        and value["release_digest"] == proposed_release_digest,
        "dataset transition predecessor or application identity changed",
    )
    entries = {entry["obligation"]["id"]: entry for entry in current_inventory["entries"]}
    active = {identity for identity, entry in entries.items() if entry["discharge"] is None}
    _require(not admissions.keys() & entries.keys(), "dataset obligation identity reused")
    _require(
        set(bindings) | set(discharges) == active | set(admissions)
        and set(discharges) <= active
        and set(admissions) <= set(bindings),
        "dataset transition omits or resurrects an obligation",
    )
    _require(
        set(bindings.values()) == set(proposed_app["datasets"]) == set(approved_bindings),
        "dataset transition differs from complete proposed dataset selection",
    )
    _require(
        dict(approved_admissions) == admissions, "dataset admissions lack independent approval"
    )
    for identity, name in bindings.items():
        obligation = (
            admissions[identity] if identity in admissions else entries[identity]["obligation"]
        )
        _require(
            obligation["native_identity"] == approved_bindings[name],
            "dataset binding differs from approved native incarnation",
        )
        _require(
            _same_responsibility(obligation["declaration"], proposed_app["datasets"][name]),
            "dataset continuation changes custody or recovery responsibility",
        )
        if identity in admissions:
            _require(
                obligation["origin_dataset"] == name
                and obligation["origin_release_digest"] == proposed_release_digest
                and obligation["declaration"] == proposed_app["datasets"][name],
                "dataset admission differs from proposed source",
            )
    for identity, discharge in discharges.items():
        _require(
            discharge["obligation_digest"] == digest(entries[identity]["obligation"]),
            "dataset discharge substitutes original obligation",
        )
    authorize_transition(deepcopy(value), "administrator" if discharges else "operator")
    if discharges:
        verify_discharges(current_inventory, discharges)
    projected = []
    for identity, entry in entries.items():
        new_entry = deepcopy(entry)
        if identity in bindings:
            new_entry["dataset"] = bindings[identity]
        elif identity in discharges:
            discharge = discharges[identity]
            new_entry.update(dataset=None, discharge=deepcopy(discharge))
        projected.append(new_entry)
    projected.extend(
        {"obligation": deepcopy(obligation), "dataset": bindings[identity], "discharge": None}
        for identity, obligation in admissions.items()
    )
    result = {
        **deepcopy(current_inventory),
        "generation": current_inventory["generation"] + 1,
        "accepted_release_digest": proposed_release_digest,
        "entries": projected,
    }
    require_dataset_source(
        result, accepted_app=proposed_app, accepted_release_digest=proposed_release_digest
    )
    return result
