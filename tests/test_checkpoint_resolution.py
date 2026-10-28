"""Independent signed receipt joins for complete historical checkpoint recovery inputs."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from functools import cache

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_contracts import checkpoints
from fishhat_contracts.checkpoints import resolve_checkpoint, validate_checkpoint
from fishhat_contracts.handoffs import schema_identity, validate_cli_result, validate_result_payload
from fishhat_contracts.operations import validate_operation
from fishhat_contracts.validation import ContractError, canonical, digest, strict_json
from fishhat_contracts.witness import sign

from tests.adapter_support import OWNER, identifier
from tests.linear_support import assert_linear, measure
from tests.operation_support import seal_operation
from tests.test_adapter_handoffs import installed, invocation_for, response_for
from tests.test_contracts import wb
from tests.test_owner_handoffs import operation
from tests.test_workflow_continuations import attach_result
from tests.test_workflow_inputs import material_handle

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Checkpoint",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json#/$defs/Snapshot",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/ResultHandle",
    ],
    "scope": "exact signed capture/store/verification receipt mapping and historical recovery inputs",
    "relationship": "candidate",
    "reason": "Independently signed metadata, replaced aliases and adverse closure joins exercise exact reconstruction; native byte custody, current permission and restore execution remain separate.",
    "claims": [],
}

KEY = Ed25519PrivateKey.from_private_bytes(b"\x17" * 32)


@cache
def schemas(role):
    base = f"https://fishhat.invalid/contracts/{role}-adapter.schema.json#/$defs/"
    return schema_identity(base + "MutationRequest"), schema_identity(base + "RetainedResult")


def receipt(role, method, inputs, executor, output, number):
    query = {"contract": "fishhat." + role, "method": method, "input": deepcopy(inputs)}
    invocation = invocation_for(query)
    invocation["attempt"].update(
        operation_id=identifier(number),
        effect_id=identifier(number + 100000),
        attempt_id=identifier(number + 200000),
        executor=deepcopy(executor),
    )
    retained = {
        "invocation": invocation,
        "response": response_for(query, invocation["attempt"], deepcopy(output)),
    }
    record = operation()
    input_schema, result_schema = schemas(role)
    record.update(
        id=invocation["attempt"]["operation_id"],
        owner=deepcopy(OWNER),
        state="succeeded",
        effect_certainty="known",
        subject={
            "action": "adapter.execute",
            "resource": {"kind": "adapter", "id": executor["instance"]},
            "arguments": {
                "adapter_id": executor["instance"],
                "adapter_release": executor["installation_digest"],
                "action": method,
                "input": material_handle(OWNER, digest(query), size=len(canonical(query))),
                "input_schema": deepcopy(input_schema),
                "result_schema": deepcopy(result_schema),
            },
        },
    )
    attach_result(record, retained, OWNER)
    return record, retained


def seal(checkpoint):
    body = {key: value for key, value in checkpoint.items() if key != "witness"}
    checkpoint["witness"] = sign(
        {**wb(digest(body)), "owner": OWNER, "kind": "checkpoint", "state": "verified"}, KEY
    )


def fixture(count=2, *, shared=True):
    _, capture = installed("capture")
    _, backup = installed("backup", endpoint="original-repository")
    records = {}
    closure = set()
    for executor in (capture, backup):
        closure.update(executor[key] for key in checkpoints.ENROLLMENT_IDENTITIES)
    keys = {}
    selected = {}
    snapshots = {}

    def put(record, retained):
        for value in (record, retained):
            records[digest(value)] = canonical(value)
            closure.add(digest(value))
        owner, witness = record["owner"], record["witness"]
        keys[(owner["tool"], owner["id"], owner["epoch"], witness["key_id"])] = KEY.public_key()
        return digest(record)

    for index in range(count):
        dataset = f"dataset-{index:04d}"
        artifact = {
            "digest": digest({"captured": dataset}),
            "media_type": "application/octet-stream",
            "size_bytes": 64,
        }
        closure.add(artifact["digest"])
        snapshot = {
            "handle": "snapshot:" + dataset,
            "dataset": dataset,
            "format": "independent.snapshot",
            "consistency": "quiesced",
            "artifacts": [artifact],
            "restore_requirements": ["independent.reader"],
            "producer": deepcopy(capture),
        }
        snapshots[dataset] = snapshot
        inputs = {
            "scope": deepcopy(capture["scope"]),
            "dataset": dataset,
            "destination": "protected:" + dataset,
            "procedure_digest": digest({"capture": dataset}),
            "binding": deepcopy(capture),
        }
        selected[dataset] = {
            "capture_digest": put(
                *receipt(
                    "capture",
                    "capture",
                    inputs,
                    capture,
                    {"snapshots": [snapshot], "verification": "consistent"},
                    1000 + index,
                )
            )
        }
    groups = [list(snapshots)] if shared else [[dataset] for dataset in snapshots]
    for index, group in enumerate(groups):
        artifacts = [a for dataset in group for a in snapshots[dataset]["artifacts"]]
        inputs = {
            "scope": deepcopy(backup["scope"]),
            "repository": "repository:original",
            "object": f"backup:object-{index:04d}",
            "artifacts": artifacts,
        }
        output = {
            "objects": [
                {
                    "handle": inputs["object"],
                    "repository": inputs["repository"],
                    "artifacts": deepcopy(artifacts),
                    "completeness": "sealed",
                    "retrieval": "available",
                }
            ]
        }
        store = put(*receipt("backup", "store", inputs, backup, output, 10000 + index))
        verified = put(*receipt("backup", "verify", inputs, backup, output, 20000 + index))
        for dataset in group:
            selected[dataset].update(backup_digest=store, verification_digest=verified)
    release = digest({"accepted": "release"})
    secrets = [digest({"secret-generation": "accepted"})]
    closure.update([release, *secrets])
    checkpoint = {
        "format": "deployment-ops/record/v1",
        "kind": "Checkpoint",
        "id": identifier(900000),
        "app_instance": "prod:" + "a" * 64,
        "owner": deepcopy(OWNER),
        "release_digest": release,
        "datasets": selected,
        "secret_generations": secrets,
        "backup_executor": backup,
        "recovery_closure": sorted(closure),
        "verified_at": "2026-10-24T00:00:00Z",
        "restore_tested_at": None,
        "consistency_scope": "independent-datasets",
        "quiescence_evidence": None,
    }
    seal(checkpoint)
    keys[(OWNER["tool"], OWNER["id"], OWNER["epoch"], checkpoint["witness"]["key_id"])] = (
        KEY.public_key()
    )
    context = {
        "expected_owner": deepcopy(OWNER),
        "expected_checkpoint_digest": digest(checkpoint),
        "expected_app_instance": checkpoint["app_instance"],
        "expected_release_digest": release,
        "expected_datasets": tuple(snapshots),
        "expected_secret_generations": tuple(secrets),
        "records": records,
        "trusted_keys": keys,
    }
    return checkpoint, context, snapshots


def test_fresh_owner_resolves_exact_historical_inputs():
    checkpoint, context, snapshots = fixture()
    original = deepcopy(checkpoint)
    _, current_backup = installed("backup", endpoint="replacement-repository", generation=4)
    assert current_backup["instance"] == checkpoint["backup_executor"]["instance"]
    assert current_backup != checkpoint["backup_executor"]
    validate_checkpoint(checkpoint)
    recovered = resolve_checkpoint(checkpoint, **context)
    assert recovered.snapshots == snapshots
    assert len(recovered.backup_objects) == 1
    assert set(recovered.dataset_backups) == set(snapshots)
    assert set(recovered.dataset_backups.values()) == set(recovered.backup_objects)
    assert next(iter(recovered.backup_objects.values()))["repository"] == "repository:original"
    assert checkpoint == original
    # A second reader receives independently decoded records, without client state or alias lookup.
    restored = strict_json(canonical(checkpoint))
    assert (
        resolve_checkpoint(restored, **{**context, "records": dict(context["records"])})
        == recovered
    )


@pytest.mark.parametrize("field", ["capture_digest", "backup_digest", "verification_digest"])
@pytest.mark.parametrize("missing", ["receipt", "payload", "membership"])
def test_missing_selected_receipt_or_payload_blocks_reconstruction(field, missing):
    checkpoint, context, _ = fixture()
    selected = checkpoint["datasets"]["dataset-0000"][field]
    if missing == "payload":
        selected = strict_json(context["records"][selected])["result_handle"]["handle"]["digest"]
    if missing == "membership":
        checkpoint["recovery_closure"].remove(selected)
        seal(checkpoint)
        context["expected_checkpoint_digest"] = digest(checkpoint)
    else:
        del context["records"][selected]
    with pytest.raises(ContractError, match=r"closure|unavailable"):
        resolve_checkpoint(checkpoint, **context)


@pytest.mark.parametrize(
    "change",
    [
        "dataset",
        "release",
        "secrets",
        "owner",
        "instance",
        "selected-checkpoint",
        "executor",
        "capture",
        "method",
        "material",
        "capture-enrollment",
        "backup-enrollment",
        "signature",
        "key",
        "bytes",
    ],
)
def test_checkpoint_substitution_cannot_change_selected_recovery_input(change):
    checkpoint, context, _ = fixture()
    first, second = checkpoint["datasets"].values()
    if change == "dataset":
        del checkpoint["datasets"]["dataset-0001"]
    elif change == "release":
        context["expected_release_digest"] = digest("another release")
    elif change == "secrets":
        context["expected_secret_generations"] = ()
    elif change == "owner":
        context["expected_owner"]["epoch"] = identifier(999)
    elif change == "instance":
        context["expected_app_instance"] = "prod:" + "b" * 64
    elif change == "executor":
        checkpoint["backup_executor"]["configuration_digest"] = digest("replacement configuration")
    elif change == "capture":
        first["capture_digest"], second["capture_digest"] = (
            second["capture_digest"],
            first["capture_digest"],
        )
    elif change == "method":
        first["verification_digest"] = first["backup_digest"]
    elif change == "material":
        record = strict_json(context["records"][first["capture_digest"]])
        retained = strict_json(context["records"][record["result_handle"]["handle"]["digest"]])
        checkpoint["recovery_closure"].remove(
            retained["response"]["output"]["snapshots"][0]["artifacts"][0]["digest"]
        )
    elif change == "key":
        context["trusted_keys"] = {}
    elif change == "bytes":
        context["records"][first["capture_digest"]] += b" "
    elif change.endswith("-enrollment"):
        if change == "backup-enrollment":
            executor = checkpoint["backup_executor"]
        else:
            record = strict_json(context["records"][first["capture_digest"]])
            retained = strict_json(context["records"][record["result_handle"]["handle"]["digest"]])
            executor = retained["invocation"]["attempt"]["executor"]
        checkpoint["recovery_closure"].remove(executor["configuration_digest"])
    seal(checkpoint)
    if change == "signature":
        checkpoint["witness"]["signature"] = "A" * 86 + "=="
    context["expected_checkpoint_digest"] = (
        digest(checkpoint) if change != "selected-checkpoint" else digest("another checkpoint")
    )
    with pytest.raises(ContractError):
        resolve_checkpoint(checkpoint, **context)


def test_opaque_backend_and_snapshot_aliases_are_not_checkpoint_mapping():
    checkpoint, context, _ = fixture()
    checkpoint["backup_backend"] = checkpoint.pop("backup_executor")["instance"]
    seal(checkpoint)
    with pytest.raises(ContractError):
        resolve_checkpoint(checkpoint, **context)


def replace_receipt(checkpoint, context, field, change):
    previous = checkpoint["datasets"]["dataset-0000"][field]
    record = strict_json(context["records"][previous])
    retained = strict_json(context["records"][record["result_handle"]["handle"]["digest"]])
    change(record, retained)
    invocation, response = retained["invocation"], retained["response"]
    query = invocation["request"]
    invocation["attempt"]["input_digest"] = digest(query)
    response["effect"]["input_digest"] = digest(query)
    response_query = (
        query
        if response["method"] != "reconcile"
        else {
            "contract": query["contract"],
            "method": "reconcile",
            "input": {"scope": query["input"]["scope"], "invocation": invocation},
        }
    )
    response["request_digest"] = digest(response_query)
    record["subject"]["arguments"]["input"].update(digest=digest(query), size=len(canonical(query)))
    attach_result(record, retained, OWNER)
    for value in (record, retained):
        context["records"][digest(value)] = canonical(value)
        checkpoint["recovery_closure"].append(digest(value))
    for selection in checkpoint["datasets"].values():
        if selection[field] == previous:
            selection[field] = digest(record)
    checkpoint["recovery_closure"] = sorted(set(checkpoint["recovery_closure"]))
    seal(checkpoint)
    context["expected_checkpoint_digest"] = digest(checkpoint)


def test_backup_receipt_artifact_order_does_not_change_identity():
    checkpoint, context, snapshots = fixture()

    def reverse_order(record, retained):
        retained["invocation"]["request"]["input"]["artifacts"].reverse()
        retained["response"]["output"]["objects"][0]["artifacts"].reverse()

    replace_receipt(checkpoint, context, "verification_digest", reverse_order)
    assert resolve_checkpoint(checkpoint, **context).snapshots == snapshots


@pytest.mark.parametrize("field", ["capture_digest", "backup_digest", "verification_digest"])
def test_reconciled_original_receipts_reconstruct_without_new_mutation(field):
    checkpoint, context, snapshots = fixture()
    replace_receipt(
        checkpoint,
        context,
        field,
        lambda record, retained: retained["response"].update(method="reconcile"),
    )
    original = dict(context["records"])
    assert resolve_checkpoint(checkpoint, **context).snapshots == snapshots
    assert context["records"] == original


def test_checkpoint_result_requires_exact_declared_payload_size():
    checkpoint, context, _ = fixture(1)
    selected = checkpoint["datasets"]["dataset-0000"]
    record = strict_json(context["records"][selected["capture_digest"]])
    record["result_handle"]["handle"]["size"] += 1
    seal_operation(record)
    changed = digest(record)
    context["records"][changed] = canonical(record)
    checkpoint["recovery_closure"].append(changed)
    selected["capture_digest"] = changed
    seal(checkpoint)
    context["expected_checkpoint_digest"] = digest(checkpoint)
    with pytest.raises(ContractError, match="result content size changed"):
        resolve_checkpoint(checkpoint, **context)


@pytest.mark.parametrize("selected_schema", ["input", "result"])
@pytest.mark.parametrize("reader_state", ["missing", "installed", "mutating"])
def test_historical_schema_pins_require_exact_unchanged_reader(selected_schema, reader_state):
    checkpoint, context, snapshots = fixture(1)

    def historical_pin(record, retained):
        record["subject"]["arguments"][selected_schema + "_schema"]["digest"] = digest(
            "independently qualified historical " + selected_schema + " schema"
        )

    replace_receipt(checkpoint, context, "capture_digest", historical_pin)
    record = strict_json(
        context["records"][checkpoint["datasets"]["dataset-0000"]["capture_digest"]]
    )
    retained = strict_json(context["records"][record["result_handle"]["handle"]["digest"]])
    identity = record["subject"]["arguments"][selected_schema + "_schema"]
    expected = retained["invocation"]["request"] if selected_schema == "input" else retained
    inspected = []

    def reader(value):
        inspected.append(deepcopy(value))
        if reader_state == "mutating":
            value["unapproved_translation"] = True

    if reader_state != "missing":
        context["recovery_readers"] = {(identity["uri"], identity["digest"]): reader}
    original = dict(context["records"])
    if reader_state == "installed":
        assert resolve_checkpoint(checkpoint, **context).snapshots == snapshots
    else:
        message = (
            "reader changed original bytes" if reader_state == "mutating" else "schema.*changed"
        )
        with pytest.raises(ContractError, match=message):
            resolve_checkpoint(checkpoint, **context)
    assert inspected == ([] if reader_state == "missing" else [expected])
    assert context["records"] == original


@pytest.mark.parametrize(
    "change",
    [
        "failed-operation",
        "unknown-capture",
        "unavailable-backup",
        "substituted-artifact",
        "unknown-retained-field",
        "unknown-output-field",
    ],
)
def test_signed_but_incomplete_receipts_cannot_complete_checkpoint(change):
    checkpoint, context, _ = fixture()

    def mutate(record, retained):
        if change == "failed-operation":
            record["state"] = "failed"
        elif change == "unknown-capture":
            retained["response"]["output"]["verification"] = "unknown"
        elif change == "unavailable-backup":
            retained["response"]["output"]["objects"][0]["retrieval"] = "deferred"
        elif change == "unknown-retained-field":
            retained["unreviewed"] = True
        elif change == "unknown-output-field":
            retained["response"]["output"]["unreviewed"] = True
        else:
            artifact = retained["response"]["output"]["snapshots"][0]["artifacts"][0]
            artifact["digest"] = digest("another complete artifact")
            checkpoint["recovery_closure"].append(artifact["digest"])

    field = "verification_digest" if change == "unavailable-backup" else "capture_digest"
    replace_receipt(checkpoint, context, field, mutate)
    with pytest.raises(ContractError):
        resolve_checkpoint(checkpoint, **context)


def test_application_quiescence_claim_requires_every_snapshot_to_be_quiesced():
    checkpoint, context, snapshots = fixture()
    checkpoint["consistency_scope"] = "application-quiesced"
    checkpoint["quiescence_evidence"] = digest("independent native common-fence evidence")
    checkpoint["recovery_closure"].append(checkpoint["quiescence_evidence"])
    seal(checkpoint)
    context["expected_checkpoint_digest"] = digest(checkpoint)
    assert resolve_checkpoint(checkpoint, **context).snapshots == snapshots
    replace_receipt(
        checkpoint,
        context,
        "capture_digest",
        lambda record, retained: retained["response"]["output"]["snapshots"][0].update(
            consistency="native-transaction"
        ),
    )
    with pytest.raises(ContractError, match="requires quiesced snapshots"):
        resolve_checkpoint(checkpoint, **context)


def test_decoded_checkpoint_and_app_backup_payload_reapply_snapshot_integrity():
    checkpoint, _, _ = fixture()
    validate_cli_result(checkpoint)
    record = operation()
    record.update(
        owner=deepcopy(OWNER),
        state="succeeded",
        effect_certainty="known",
        subject={
            "action": "app.backup",
            "resource": {"kind": "app", "id": "example"},
            "arguments": {},
        },
    )

    def read(value):
        handle = material_handle(OWNER, digest(value), size=len(canonical(value)))
        handle["binding"] = {"kind": "operation", "operation_id": record["id"]}
        record["result_handle"] = {
            "handle": handle,
            "schema": schema_identity(
                "https://fishhat.invalid/contracts/records.schema.json#/$defs/Checkpoint"
            ),
        }
        seal_operation(record)
        return validate_result_payload(record, canonical(value))

    assert read(checkpoint) == checkpoint
    checkpoint["witness"]["subject_digest"] = digest("another checkpoint body")
    with pytest.raises(ContractError, match="checkpoint witness snapshot mismatch"):
        validate_cli_result(checkpoint)
    with pytest.raises(ContractError, match="checkpoint witness snapshot mismatch"):
        read(checkpoint)


@pytest.mark.parametrize("encoding", ["whitespace", "member-order", "string-escape"])
def test_signed_capture_results_reject_noncanonical_bytes_at_intake(encoding):
    checkpoint, context, snapshots = fixture(count=1)
    assert resolve_checkpoint(checkpoint, **context).snapshots == snapshots
    capture_id = checkpoint["datasets"]["dataset-0000"]["capture_digest"]
    record = strict_json(context["records"][capture_id])
    handle = record["result_handle"]["handle"]
    original = context["records"][handle["digest"]]
    value = validate_result_payload(record, original)
    variants = {
        "whitespace": original + b"\n",
        "member-order": json.dumps(
            dict(reversed(list(value.items()))), ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8"),
        "string-escape": original.replace(b"fishhat.capture", b"fishhat.\\u0063apture"),
    }
    data = variants[encoding]
    assert data != original and strict_json(data) == value
    handle.update(size=len(data), digest="sha256:" + hashlib.sha256(data).hexdigest())
    seal_operation(record)
    validate_operation(record)
    retained = canonical(record)
    with pytest.raises(ContractError, match="result payload encoding is not canonical"):
        validate_result_payload(record, data)
    assert canonical(record) == retained


@pytest.mark.parametrize("shared", [False, True], ids=["separate-objects", "shared-object"])
def test_checkpoint_resolution_linear_work(shared):
    samples = []
    validation_samples = []
    for count in (1, 4, 16):
        checkpoint, context, snapshots = fixture(count, shared=shared)
        recovered, work = measure(
            lambda checkpoint=checkpoint, context=context: resolve_checkpoint(
                checkpoint, **context
            ),
            modules=(checkpoints,),
        )
        assert recovered.snapshots == snapshots
        assert len(recovered.backup_objects) == (1 if shared else count)
        _, validation_work = measure(lambda checkpoint=checkpoint: validate_checkpoint(checkpoint))
        samples.append((count, work))
        validation_samples.append((count, validation_work))
    assert_linear(samples)
    assert_linear(validation_samples)


CHECK_OVERRIDES = {
    name: {
        **CHECK_PURPOSE,
        "purpose": "implementation",
        "authority": [
            *CHECK_PURPOSE["authority"],
            "packages/fishhat-contracts/src/fishhat_contracts/checkpoints.py#validate_checkpoint",
            "packages/fishhat-contracts/src/fishhat_contracts/checkpoints.py#resolve_checkpoint",
            "release.toml#/engineering",
        ],
        "relationship": "scoped-witness",
        "reason": "Complete receipt reconstruction and deterministic work cover every dataset and shared backup object across sixteenfold input extents, without claiming native availability or restore execution.",
        "claims": ["engineering:checkpoints.validate", "engineering:checkpoints.resolve"],
    }
    for name in (
        "test_fresh_owner_resolves_exact_historical_inputs",
        "test_checkpoint_resolution_linear_work",
    )
}
