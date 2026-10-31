"""Typed lifecycle evidence, complete retained custody and independent current authority."""

from __future__ import annotations

import copy
import hashlib
import io

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_client.wire import frame, read_frame
from fishhat_contracts import lifecycle
from fishhat_contracts.handoffs import validate_cli_result
from fishhat_contracts.lifecycle import (
    decode_lifecycle_evidence,
    decode_lifecycle_input,
    lifecycle_evidence_material,
    prepare_lifecycle_evidence,
    validate_lifecycle_admission,
    validate_lifecycle_evidence,
)
from fishhat_contracts.validation import (
    MAX_BYTES,
    ContractError,
    canonical,
    digest,
    validate,
    validate_plan,
)
from fishhat_contracts.witness import sign, verify
from fishhat_owner.commands import parse_command

from tests.linear_support import assert_linear, measure
from tests.test_contracts import OWNER, plan, uid
from tests.test_dataset_contracts import application
from tests.test_owner_handoffs import committed, request, wire
from tests.test_plan_review import reseal

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/lifecycle-evidence.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-records.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/dataset-obligations.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/HandleBinding",
    ],
    "scope": "owner-issued typed evidence, current policy/protection, exact resource/native selection, complete obligations and surviving custody",
    "relationship": "candidate",
    "reason": "Resealed substitutions and independently supplied current state challenge every lifecycle join; complete synthetic content survives client loss and retries. No native observation, permission, durable commit or deletion is qualified.",
    "claims": [],
}
CHECK_OVERRIDES = {
    "test_lifecycle_complete_work_is_linear": {
        "purpose": "implementation",
        "authority": [
            "release.toml#/engineering",
            *[
                "packages/fishhat-contracts/src/fishhat_contracts/lifecycle.py#" + name
                for name in (
                    "validate_lifecycle_reference",
                    "decode_lifecycle_input",
                    "decode_lifecycle_evidence",
                    "validate_lifecycle_evidence",
                    "prepare_lifecycle_evidence",
                    "lifecycle_evidence_material",
                    "validate_lifecycle_plan",
                    "validate_lifecycle_admission",
                )
            ],
        ],
        "scope": "complete preparation, retained replay, byte reads, policy/obligation/custody validation and Plan admission over sixteenfold extent",
        "relationship": "scoped-witness",
        "reason": "Measured Python/container/serialization work includes complete evidence and indexed joins; synthetic signatures/bytes establish no native custody or timing guarantee.",
        "claims": [
            f"engineering:lifecycle.{name}"
            for name in (
                "reference",
                "input",
                "read",
                "evidence",
                "prepare",
                "material",
                "plan",
                "admission",
            )
        ],
    }
}

NOW = "2026-10-23T00:30:00Z"
LATER = "2026-10-23T00:30:20Z"
UNTIL = "2026-10-23T00:31:00Z"
KEY = Ed25519PrivateKey.from_private_bytes(b"\x17" * 32)


def authenticate(witness, owner, commitment):
    assert witness["key_id"] == "test-owner"
    verify(witness, KEY.public_key(), owner, commitment)


def attest(body):
    context = body.get("context", body)
    return sign(
        {
            "format": "deployment-ops/witness/v1",
            "id": uid("witness-" + digest(body)),
            "owner": copy.deepcopy(context["owner"]),
            "kind": "approval" if "context" in body else "effect",
            "subject_digest": digest(body),
            "workflow_id": None,
            "generation": context.get("generation", 1),
            "state": "prepared" if "context" in body else body["state"],
            "boot_id": None,
            "evidence_digests": [],
            "created_at": context.get("observed_at", NOW),
            "key_id": "test-owner",
        },
        KEY,
    )


def seal(value):
    value["witness"] = attest({key: item for key, item in value.items() if key != "witness"})
    return value


def native(owner, handle, *, kind="dataset", incarnation=None):
    return {
        "scope": {"authority": owner["id"], "kind": kind, "handle": handle},
        "incarnation": incarnation or digest({"native": handle}),
    }


def inventory(count, owner, resource):
    declaration = application()["datasets"]["state"]
    release = digest({"accepted": "release"})
    entries = []
    for index in range(count):
        name = f"dataset-{index:06d}"
        entries.append(
            {
                "obligation": {
                    "id": uid(name),
                    "origin_release_digest": release,
                    "origin_dataset": name,
                    "declaration": copy.deepcopy(declaration),
                    "native_identity": native(owner, name),
                    "recovery_closure": [release, digest({"data": index})],
                },
                "dataset": name,
                "discharge": None,
            }
        )
    return {
        "format": "deployment-ops/dataset-obligations/v1",
        "kind": "DatasetInventory",
        "owner": copy.deepcopy(owner),
        "resource": copy.deepcopy(resource),
        "app_instance": "prod:" + "a" * 64,
        "generation": 4,
        "accepted_release_digest": release,
        "entries": entries,
    }


def retained(owner, resource, material):
    item = {
        "owner": copy.deepcopy(owner),
        "resource": copy.deepcopy(resource),
        "material_digest": material,
        "location": {
            "kind": "content",
            "handle": {
                "owner": copy.deepcopy(owner),
                "id": uid("material-" + material),
                "purpose": "content",
                "binding": {"kind": "operation", "operation_id": uid("source")},
                "digest": material,
                "size": 10,
            },
        },
        "local": True,
        "state": "retained",
        "previous_custodian": None,
        "previous_resource": None,
        "obligation": None,
        "verified_at": NOW,
        "valid_until": UNTIL,
    }
    return seal(item)


def prepared_inputs(action="app.retire", count=2):
    owner = copy.deepcopy(OWNER)
    if action != "app.retire":
        owner["tool"] = "host-ops"
    resource = {
        "kind": {"app.retire": "app", "host.retire": "host", "backend.prune": "backend"}[action],
        "id": "demo-app" if action == "app.retire" else "node-a",
    }
    datasets = []
    materials = []
    if action == "backend.prune":
        scope = native(owner, "backup:repository", kind="backup-repository")["scope"]
        executor = {
            "instance": "backup-local",
            "role": "backup",
            "installation_digest": digest("installation"),
            "configuration_digest": digest("configuration"),
            "instance_generation": 1,
            "instance_digest": digest("enrollment"),
            "scope": scope,
        }
        objects = [
            {
                "native_identity": {
                    "scope": copy.deepcopy(scope),
                    "incarnation": digest({"object": index}),
                },
                "object": {
                    "handle": f"backup:object-{index}",
                    "repository": scope["handle"],
                    "artifacts": [
                        {
                            "digest": digest({"artifact": index}),
                            "media_type": "application/octet-stream",
                            "size_bytes": 12,
                        }
                    ],
                    "completeness": "sealed",
                    "retrieval": "available",
                },
            }
            for index in range(count)
        ]
        selection = {
            "action": action,
            "executor": executor,
            "repository": scope["handle"],
            "objects": objects,
        }
        materials = [digest({"recovery": index}) for index in range(count)]
    else:
        if action == "app.retire":
            targets = [
                {
                    "resource": resource,
                    "generation": 7,
                    "native_identity": native(owner, "app:demo", kind="application"),
                }
            ]
            datasets = [inventory(count, owner, resource)]
            materials = list(
                dict.fromkeys(
                    material
                    for entry in datasets[0]["entries"]
                    for material in entry["obligation"]["recovery_closure"]
                )
            )
        else:
            targets = [
                {
                    "resource": {"kind": "dataset", "id": f"storage-{index:06d}"},
                    "generation": 7,
                    "native_identity": native(owner, f"storage:{index}"),
                }
                for index in range(count)
            ]
            materials = [digest({"data": index}) for index in range(count)]
        selection = {
            "action": action,
            "targets": targets,
            "datasets": [
                {
                    "owner": item["owner"],
                    "resource": item["resource"],
                    "app_instance": item["app_instance"],
                    "inventory_digest": digest(item),
                    "retained_obligations": [
                        entry["obligation"]["id"] for entry in item["entries"]
                    ],
                }
                for item in datasets
            ],
        }
    current = {
        "owner": owner,
        "resource": resource,
        "generation": 7,
        "holds_digest": digest([]),
        "selection": selection,
        "retention": [],
        "protection_generation": 5,
        "protected_objects": [],
        "required_materials": materials,
        "protected_references": [],
        "observed_at": NOW,
        "valid_until": UNTIL,
    }
    custody = [retained(owner, resource, material) for material in materials]
    for dataset_inventory in datasets:
        commitment = digest(dataset_inventory)
        for entry in dataset_inventory["entries"]:
            obligation = entry["obligation"]
            material = digest({"native-data-closure": obligation["id"]})
            current["required_materials"].append(material)
            item = retained(owner, resource, material)
            item["location"] = {
                "kind": "native",
                "identity": copy.deepcopy(obligation["native_identity"]),
            }
            item["obligation"] = {
                "inventory_digest": commitment,
                "obligation_id": obligation["id"],
                "obligation_digest": digest(obligation),
                "native_identity": copy.deepcopy(obligation["native_identity"]),
            }
            custody.append(seal(item))
    return {
        "current": current,
        "accepted_policies": [],
        "retention_inventories": [],
        "dataset_inventories": datasets,
        "custody": custody,
        "now": NOW,
        "authenticate": authenticate,
    }


def staged(context):
    current = context["current"]
    payload = {
        "format": "deployment-ops/lifecycle-evidence/v1",
        "preparation_id": uid("preparation"),
        "owner": current["owner"],
        "resource": current["resource"],
        "selection": current["selection"],
    }
    data = canonical(payload)
    staging = committed()
    staging.update(
        owner=copy.deepcopy(current["owner"]),
        resource=copy.deepcopy(current["resource"]),
        purpose="lifecycle-input",
        digest=digest(payload),
        size=len(data),
        offset=len(data),
    )
    staging["handle"].update(
        owner=copy.deepcopy(current["owner"]),
        purpose="lifecycle-input",
        digest=digest(payload),
        size=len(data),
    )
    reference = {
        "owner": current["owner"],
        "preparation_id": payload["preparation_id"],
        "input": staging["handle"],
    }
    return reference, data, staging


def prepare(context, **extra):
    return prepare_lifecycle_evidence(
        *staged(context),
        principal="ops-app-operate",
        content_id=uid("evidence-content"),
        attest=attest,
        **context,
        **extra,
    )


def decode(snapshot):
    return decode_lifecycle_evidence(
        snapshot.reference,
        snapshot.data,
        expected_owner=snapshot.reference["owner"],
        authenticate=authenticate,
    )


def review(snapshot):
    value = decode(snapshot)
    context = value["context"]
    result = copy.deepcopy(plan())
    result["owner"] = copy.deepcopy(context["owner"])
    arguments = {"evidence": copy.deepcopy(snapshot.reference)}
    if context["selection"]["action"] == "host.retire":
        arguments["resources"] = [
            item["resource"]["id"] for item in context["selection"]["targets"]
        ]
    result["subject"] = {
        "action": context["selection"]["action"],
        "resource": context["resource"],
        "arguments": arguments,
    }
    result["created_at"] = NOW
    result["expires_at"] = UNTIL
    result["input_digests"] = list(lifecycle_evidence_material(value))
    result["effects"] = [
        {
            "step": "lifecycle",
            "executor": context["owner"],
            "resource": context["resource"],
            "summary": "Apply the exact reviewed lifecycle selection.",
            "action": "admitted-lifecycle",
            "input_digest": digest(value),
            "reconciliation": "inspect-native-lifecycle",
        }
    ]
    result["preconditions"] = [
        {
            "owner": context["owner"],
            "resource": context["resource"],
            "generation": context["generation"],
            "holds_digest": context["holds_digest"],
            "source_digests": [],
        }
    ]
    if context["selection"]["action"] == "host.retire":
        result["preconditions"].extend(
            {
                "owner": context["owner"],
                "resource": item["resource"],
                "generation": item["generation"],
                "holds_digest": digest([]),
                "source_digests": [],
            }
            for item in context["selection"]["targets"]
        )
    result["witness"]["owner"] = copy.deepcopy(context["owner"])
    return reseal(result)


def policy_context(context):
    owner = copy.deepcopy(OWNER)
    root = digest("protected-local-runtime")
    policy = {
        "format": "deployment-ops/resources/v1",
        "kind": "AcceptedRetentionPolicy",
        "owner": owner,
        "account": "app-demo-app",
        "generation": 3,
        "release_digest": digest("accepted-release"),
        "policy": {
            "prior_releases": 1,
            "minimum_prior_age_seconds": 86400,
            "unused_candidate_grace_seconds": 3600,
            "cold_archive": "keep-local",
        },
        "max_observation_age_seconds": 60,
    }
    inventory = {
        "format": "deployment-ops/resources/v1",
        "kind": "RetentionInventory",
        "owner": owner,
        "account": policy["account"],
        "protection_generation": 8,
        "observed_at": NOW,
        "complete": True,
        "releases": [
            {
                "release_digest": policy["release_digest"],
                "verified_at": NOW,
                "accepted": True,
                "recovery_required": True,
                "runtime_handles": [root],
                "blocking_refs": [],
                "archive": None,
                "cold_demotion_receipt": None,
            }
        ],
        "policy_digest": digest(policy),
    }
    context["accepted_policies"] = [policy]
    context["retention_inventories"] = [inventory]
    context["current"]["retention"] = [
        {
            "owner": owner,
            "account": policy["account"],
            "resource": {"kind": "app", "id": "demo-app"},
            "policy_generation": policy["generation"],
            "policy_digest": digest(policy),
            "inventory_digest": digest(inventory),
            "protection_generation": inventory["protection_generation"],
        }
    ]
    context["current"]["required_materials"].append(root)
    context["custody"].append(retained(owner, {"kind": "app", "id": "demo-app"}, root))


@pytest.mark.parametrize("action", ["app.retire", "host.retire", "backend.prune"])
def test_typed_owner_evidence_is_the_only_retirement_or_pruning_input(action):
    context = prepared_inputs(action)
    snapshot = prepare(context)
    value = validate_lifecycle_admission(review(snapshot), snapshot.data, **context)
    assert value["kind"] == (
        "PruningEvidence" if action == "backend.prune" else "RetirementEvidence"
    )
    envelope = request("lifecycle.evidence.prepare", staged(context)[0])
    validate("ssh-request.schema.json", envelope)
    response = wire("lifecycle.evidence.prepare", snapshot.reference)
    validate("ssh-response.schema.json", response)
    assert read_frame(io.BytesIO(frame(response))) == response
    validate_cli_result(snapshot.reference)
    assert (
        parse_command("app-ops lifecycle evidence --request-stdin --json", "app-ops")["use_case"]
        == "lifecycle.evidence.prepare"
    )
    old = copy.deepcopy(review(snapshot)["subject"])
    old["arguments"].pop("evidence")
    old["arguments"]["retention_receipt"] = digest("untyped")
    with pytest.raises(ContractError):
        validate("actions.schema.json", old)


@pytest.mark.parametrize(
    "field",
    ["owner", "epoch", "resource", "generation", "holds", "protection", "selection", "expired"],
)
def test_new_admission_rejects_changed_independent_current_authority(field):
    context = prepared_inputs("backend.prune")
    snapshot = prepare(context)
    reviewed = review(snapshot)
    current = context["current"]
    if field == "owner":
        current["owner"]["id"] = uid("other-owner")
    elif field == "epoch":
        current["owner"]["epoch"] = uid("new-epoch")
    elif field == "resource":
        current["resource"]["id"] = "another-backend"
    elif field == "generation":
        current["generation"] += 1
    elif field == "holds":
        current["holds_digest"] = digest(["new hold"])
    elif field == "protection":
        current["protection_generation"] += 1
    elif field == "selection":
        current["selection"]["objects"][0]["native_identity"]["incarnation"] = digest("replacement")
    else:
        context["now"] = UNTIL
    with pytest.raises(ContractError):
        validate_lifecycle_admission(reviewed, snapshot.data, **context)
    # Immutable old bytes remain available as evidence, with their original owner.
    assert decode(snapshot)["request_digest"] == snapshot.reference["request_digest"]


@pytest.mark.parametrize(
    "field",
    ["repository", "executor", "incarnation", "artifact", "duplicate", "protected", "scope"],
)
def test_pruning_rejects_substituted_or_protected_exact_native_objects(field):
    context = prepared_inputs("backend.prune")
    snapshot = prepare(context)
    value = decode(snapshot)
    selection = value["context"]["selection"]
    if field == "repository":
        selection["repository"] = "backup:other"
    elif field == "executor":
        selection["executor"]["configuration_digest"] = digest("other")
    elif field == "incarnation":
        selection["objects"][0]["native_identity"]["incarnation"] = digest("other")
    elif field == "artifact":
        selection["objects"][0]["object"]["artifacts"][0]["digest"] = digest("other")
    elif field == "duplicate":
        selection["objects"].append(copy.deepcopy(selection["objects"][0]))
    elif field == "scope":
        selection["objects"][0]["native_identity"]["scope"]["authority"] = uid("other")
    else:
        context["current"]["protected_objects"] = [
            copy.deepcopy(selection["objects"][0]["native_identity"])
        ]
        value["context"] = copy.deepcopy(context["current"])
    seal(value)
    with pytest.raises(ContractError):
        validate_lifecycle_evidence(value, **context)


@pytest.mark.parametrize(
    "field",
    [
        "policy-generation",
        "policy-digest",
        "protection-generation",
        "incomplete",
        "missing",
        "local",
    ],
)
def test_pruning_cannot_replace_accepted_policy_or_required_local_custody(field):
    context = prepared_inputs("backend.prune")
    policy_context(context)
    snapshot = prepare(context)
    value = decode(snapshot)
    if field == "policy-generation":
        context["accepted_policies"][0]["generation"] += 1
    elif field == "policy-digest":
        context["accepted_policies"][0]["policy"]["cold_archive"] = "verified-independent-archive"
    elif field == "protection-generation":
        context["retention_inventories"][0]["protection_generation"] += 1
    elif field == "incomplete":
        context["retention_inventories"][0]["complete"] = False
    elif field == "missing":
        context["accepted_policies"] = []
    else:
        context["custody"][-1]["local"] = False
        seal(context["custody"][-1])
        value["custody"] = copy.deepcopy(context["custody"])
        seal(value)
    with pytest.raises(ContractError):
        validate_lifecycle_evidence(value, **context)


@pytest.mark.parametrize(
    "field", ["obligation", "inventory", "instance", "owner", "resource", "material"]
)
def test_retirement_preserves_every_original_dataset_obligation(field):
    context = prepared_inputs()
    value = decode(prepare(context))
    selection = value["context"]["selection"]
    if field == "obligation":
        selection["datasets"][0]["retained_obligations"].pop()
    elif field == "inventory":
        selection["datasets"][0]["inventory_digest"] = digest("other")
    elif field == "instance":
        selection["datasets"][0]["app_instance"] = "prod:" + "b" * 64
    elif field == "owner":
        selection["datasets"][0]["owner"]["id"] = uid("other-owner")
    elif field == "resource":
        selection["datasets"][0]["resource"]["id"] = "other-app"
    else:
        value["context"]["required_materials"].pop()
    # Even a newly prepared/resealed observation must join independent full inventory.
    context["current"] = copy.deepcopy(value["context"])
    value["request_digest"] = digest(lifecycle._request(value))
    seal(value)
    with pytest.raises(ContractError):
        validate_lifecycle_evidence(value, **context)


def test_completed_successor_handoff_is_required_and_retirement_never_deletes_data():
    context = prepared_inputs()
    successor = {**OWNER, "id": uid("successor")}
    for item in context["custody"]:
        item.update(
            owner=copy.deepcopy(successor),
            previous_custodian=copy.deepcopy(OWNER),
            previous_resource=copy.deepcopy(context["current"]["resource"]),
            state="handoff-complete",
            local=False,
        )
        if item["location"]["kind"] == "content":
            item["location"]["handle"]["owner"] = copy.deepcopy(successor)
        else:
            item["location"]["identity"] = native(successor, item["obligation"]["obligation_id"])
        seal(item)
    snapshot = prepare(context)
    assert (
        validate_lifecycle_admission(review(snapshot), snapshot.data, **context)["kind"]
        == "RetirementEvidence"
    )
    value = decode(snapshot)
    value["custody"][0]["state"] = "offered"
    seal(value)
    with pytest.raises(ContractError):
        validate_lifecycle_evidence(value, **context)
    value = decode(snapshot)
    value["custody"][0]["previous_custodian"] = None
    context["custody"] = copy.deepcopy(value["custody"])
    seal(value)
    with pytest.raises(ContractError):
        validate_lifecycle_evidence(value, **context)
    value = decode(snapshot)
    value["context"]["selection"]["delete_data"] = True
    with pytest.raises(ContractError):
        validate("lifecycle-evidence.schema.json", value, "Evidence")


def test_selected_prune_object_cannot_be_its_own_sole_recovery_copy():
    context = prepared_inputs("backend.prune", 1)
    selected = context["current"]["selection"]
    item = context["custody"][0]
    item["material_digest"] = selected["objects"][0]["object"]["artifacts"][0]["digest"]
    context["current"]["required_materials"] = [item["material_digest"]]
    item["location"] = {
        "kind": "backup",
        "executor": copy.deepcopy(selected["executor"]),
        "target": copy.deepcopy(selected["objects"][0]),
    }
    seal(item)
    with pytest.raises(ContractError, match="deleted"):
        prepare(context)


def test_same_owner_and_digest_cannot_borrow_another_resources_custody():
    context = prepared_inputs()
    context["custody"][0]["resource"]["id"] = "another-app"
    seal(context["custody"][0])
    with pytest.raises(ContractError, match="surviving recovery custody"):
        prepare(context)


@pytest.mark.parametrize("failure", ["missing-custody", "protected-object"])
def test_producer_refuses_unsafe_selection_before_issuing_owner_approval(failure):
    context = prepared_inputs("backend.prune")
    if failure == "missing-custody":
        context["custody"].pop()
    else:
        context["current"]["protected_objects"] = [
            copy.deepcopy(context["current"]["selection"]["objects"][0]["native_identity"])
        ]
    with pytest.raises(ContractError):
        prepare_lifecycle_evidence(
            *staged(context),
            principal="ops-app-operate",
            content_id=uid("content"),
            attest=lambda _: pytest.fail("unsafe evidence must never be signed"),
            **context,
        )


def test_retirement_keeps_discharged_obligation_tombstones_and_original_closure():
    context = prepared_inputs()
    inventory = context["dataset_inventories"][0]
    entry = inventory["entries"][0]
    entry["dataset"] = None
    entry["discharge"] = {
        "obligation_id": entry["obligation"]["id"],
        "obligation_digest": digest(entry["obligation"]),
        "evidence_digest": digest("earlier verified discharge"),
    }
    context["current"]["selection"]["datasets"][0]["inventory_digest"] = digest(inventory)
    for item in context["custody"]:
        if item["obligation"] is not None:
            item["obligation"]["inventory_digest"] = digest(inventory)
            seal(item)
    snapshot = prepare(context)
    value = validate_lifecycle_admission(review(snapshot), snapshot.data, **context)
    assert (
        entry["obligation"]["id"]
        in value["context"]["selection"]["datasets"][0]["retained_obligations"]
    )
    context["custody"] = []
    with pytest.raises(ContractError, match="custody"):
        validate_lifecycle_evidence(value, **context)


@pytest.mark.parametrize("failure", ["missing", "content-only", "incarnation", "binding"])
def test_dataset_metadata_never_substitutes_for_positive_current_native_custody(failure):
    context = prepared_inputs()
    item = context["custody"][-1]
    if failure == "missing":
        item["obligation"] = None
    elif failure == "content-only":
        item["location"] = retained(item["owner"], item["resource"], item["material_digest"])[
            "location"
        ]
    elif failure == "incarnation":
        item["location"]["identity"]["incarnation"] = digest("unrelated-replacement")
    else:
        item["obligation"]["native_identity"]["incarnation"] = digest("wrong-original")
    seal(item)
    with pytest.raises(ContractError):
        prepare(context)


@pytest.mark.parametrize(
    "failure", ["issuer-signature", "custodian-signature", "schema-uri", "schema-digest", "binding"]
)
def test_evidence_and_custody_require_exact_approved_issuer_and_type(failure):
    context = prepared_inputs()
    snapshot = prepare(context)
    reference = copy.deepcopy(snapshot.reference)
    value = decode(snapshot)
    if failure == "issuer-signature":
        value["witness"]["signature"] = "A" * 86 + "=="
    elif failure == "custodian-signature":
        value["custody"][0]["witness"]["signature"] = "A" * 86 + "=="
        context["custody"] = copy.deepcopy(value["custody"])
        seal(value)
    elif failure == "schema-uri":
        reference["schema"]["uri"] = reference["schema"]["uri"].replace(
            "RetirementEvidence", "PruningEvidence"
        )
    elif failure == "schema-digest":
        reference["schema"]["digest"] = digest("unapproved-schema")
    else:
        reference["handle"]["binding"]["preparation_id"] = uid("other-preparation")
    data = canonical(value)
    reference["handle"].update(digest=digest(value), size=len(data))
    with pytest.raises(ContractError):
        decoded = decode_lifecycle_evidence(
            reference, data, expected_owner=context["current"]["owner"], authenticate=authenticate
        )
        validate_lifecycle_evidence(decoded, **context)


@pytest.mark.parametrize(
    "field", ["principal", "resource", "purpose", "epoch", "expiry", "digest", "noncanonical"]
)
def test_preparation_requires_exact_authenticated_staging_custody(field):
    context = prepared_inputs()
    reference, data, staging = staged(context)
    if field == "principal":
        staging["authenticated_principal"] = "another-principal"
    elif field == "resource":
        staging["resource"]["id"] = "other-app"
    elif field == "purpose":
        staging["purpose"] = staging["handle"]["purpose"] = "plan-input"
    elif field == "epoch":
        staging["owner"]["epoch"] = uid("old-epoch")
    elif field == "expiry":
        staging["expires_at"] = NOW
    elif field == "digest":
        reference["input"]["digest"] = digest("wrong")
    else:
        data += b"\n"
        reference["input"].update(
            size=len(data), digest="sha256:" + hashlib.sha256(data).hexdigest()
        )
    with pytest.raises(ContractError):
        prepare_lifecycle_evidence(
            reference,
            data,
            staging,
            principal="ops-app-operate",
            content_id=uid("content"),
            attest=attest,
            **context,
        )


def test_exact_preparation_retry_retains_original_bytes_before_freshness_and_client_loss():
    context = prepared_inputs("backend.prune")
    reference, data, staging = staged(context)
    snapshot = prepare(context)
    context["current"]["generation"] += 1
    context["now"] = "2026-10-24T00:00:00Z"
    replay = prepare_lifecycle_evidence(
        reference,
        data,
        staging,
        principal="ops-app-operate",
        content_id=uid("unused-content"),
        attest=lambda _: pytest.fail("replay must not reissue"),
        previous=snapshot,
        **context,
    )
    assert replay.reference == snapshot.reference and replay.data == snapshot.data
    value = decode_lifecycle_evidence(
        replay.reference,
        replay.data,
        expected_owner=context["current"]["owner"],
        authenticate=authenticate,
    )
    assert value["context"]["generation"] == 7
    with pytest.raises(ContractError):
        prepare_lifecycle_evidence(
            reference,
            data,
            staging,
            principal="other-principal",
            content_id=uid("unused"),
            attest=attest,
            previous=snapshot,
            **context,
        )


@pytest.mark.parametrize("field", ["owner", "generation", "holds", "resources", "material"])
def test_reviewed_plan_must_pin_exact_context_selection_and_all_material(field):
    context = prepared_inputs("host.retire")
    snapshot = prepare(context)
    reviewed = review(snapshot)
    if field == "owner":
        reviewed["subject"]["arguments"]["evidence"]["owner"]["epoch"] = uid("old")
    elif field == "generation":
        reviewed["preconditions"][0]["generation"] += 1
    elif field == "holds":
        reviewed["preconditions"][0]["holds_digest"] = digest("hold")
    elif field == "resources":
        reviewed["subject"]["arguments"]["resources"].pop()
    else:
        reviewed["input_digests"].remove(context["current"]["required_materials"][0])
    reseal(reviewed)
    with pytest.raises(ContractError):
        validate_lifecycle_admission(reviewed, snapshot.data, **context)


def test_large_evidence_and_selection_keep_complete_content_across_frames():
    context = prepared_inputs("host.retire", 1800)
    # Full evidence is much larger than its bounded wire result. Only content
    # transfer chunks carry it; the Plan never silently trims selected targets.
    snapshot = prepare(context)
    assert len(snapshot.data) > MAX_BYTES
    reference, data, _ = staged(context)
    assert (
        decode_lifecycle_input(reference, data, expected_owner=context["current"]["owner"])[
            "selection"
        ]
        == context["current"]["selection"]
    )
    retained_by_owner = {snapshot.reference["handle"]["id"]: snapshot.data}
    reviewed = review(snapshot)
    handle = reviewed["subject"]["arguments"]["evidence"]["handle"]
    parts = []
    for offset in range(0, handle["size"], 196608):
        get = request("content.get", {"handle": handle, "offset": offset, "length": 196608})
        validate("ssh-request.schema.json", get)
        assert read_frame(io.BytesIO(frame(get))) == get
        parts.append(retained_by_owner[handle["id"]][offset : offset + 196608])
    complete = b"".join(parts)
    value = validate_lifecycle_admission(reviewed, complete, **context)
    assert len(value["context"]["selection"]["targets"]) == 1800
    with pytest.raises(ContractError, match="content identity"):
        decode_lifecycle_evidence(
            snapshot.reference,
            b"".join(parts[:-1]),
            expected_owner=context["current"]["owner"],
            authenticate=authenticate,
        )


def test_lifecycle_complete_work_is_linear():
    samples = []
    for count in (2, 8, 32):
        context = prepared_inputs("app.retire", count)
        # Existing accepted-policy decisions participate in the same complete run.
        policy_context(context)
        reference, data, staging = staged(context)

        def run(reference=reference, data=data, staging=staging, context=context):
            first = prepare_lifecycle_evidence(
                reference,
                data,
                staging,
                principal="ops-app-operate",
                content_id=uid("content"),
                attest=attest,
                **context,
            )
            replay = prepare_lifecycle_evidence(
                reference,
                data,
                staging,
                principal="ops-app-operate",
                content_id=uid("unused"),
                attest=attest,
                previous=first,
                **context,
            )
            value = decode(replay)
            reviewed = review(replay)
            validate_plan(reviewed)
            return validate_lifecycle_admission(reviewed, replay.data, **context), value

        (accepted, original), work = measure(run, modules=(lifecycle,))
        assert accepted == original
        assert len(accepted["context"]["selection"]["datasets"][0]["retained_obligations"]) == count
        samples.append((count, work))
    assert_linear(samples)
