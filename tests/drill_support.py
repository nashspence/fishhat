"""Explicit synthetic isolated drill evidence, without native qualification."""

from copy import deepcopy

from fishhat_contracts.handoffs import schema_identity
from fishhat_contracts.validation import canonical, digest

from tests.adapter_support import binding
from tests.operation_support import seal_operation
from tests.test_contracts import uid
from tests.test_hook_results import records as hook_records


def refresh_evidence(value):
    required = {
        digest(value["checkpoint"]),
        *value["checkpoint"]["recovery_closure"],
        value["isolation_evidence"],
        value["cleanup"]["evidence_digest"],
    }
    for name in ("production_binding", "target_binding"):
        required.add(
            digest(
                {key: item for key, item in value[name].items() if key != "admission_generation"}
            )
        )
    for entry in [*value["restorations"], *value["verifications"]]:
        request, result, procedure = entry["request"], entry["result"], entry["procedure"]
        request["procedure_digest"] = digest(procedure)
        result.update(
            request_digest=digest(request),
            request_id=request["id"],
            operation_id=request["operation_id"],
            release_digest=request["release_digest"],
            procedure_digest=request["procedure_digest"],
            runtime_binding_digest=request["runtime_binding_digest"],
        )
        required.update((digest(request), digest(result), digest(procedure)))
        required.update(artifact["digest"] for artifact in result["artifacts"])
        for item in request["restore_input"]["datasets"].values():
            required.update(artifact["digest"] for artifact in item["snapshot"]["artifacts"])
    value["evidence_closure"] = sorted(required)


def drill_result(checkpoint, record, snapshots):
    value = {
        "format": "deployment-ops/drill-result/v1",
        "kind": "DrillResult",
        "owner": deepcopy(record["owner"]),
        "operation_id": record["id"],
        "request_id": record["request_id"],
        "plan_digest": record["plan_digest"],
        "resource": deepcopy(record["subject"]["resource"]),
        "checkpoint": deepcopy(checkpoint),
        "production_binding": binding(),
        "target_binding": binding(),
        "isolation_evidence": digest("independent synthetic native isolation"),
        "restorations": [],
        "verifications": [],
        "completed_at": "2026-10-25T00:00:00Z",
        "cleanup": {"state": "retained", "evidence_digest": digest("retained drill resources")},
        "evidence_closure": [],
    }
    value["target_binding"].update(
        subject="isolated-drill", native_incarnation=uid("isolated-drill")
    )
    value["target_binding"]["scope"]["handle"] = "isolated-drill"
    for dataset, snapshot in snapshots.items():
        for role, destination in (("restore", "restorations"), ("verify-restore", "verifications")):
            request, result, procedure = hook_records(role=role)
            request.update(
                id=uid(role + dataset),
                operation_id=record["id"],
                release_digest=checkpoint["release_digest"],
                runtime_binding_digest=digest(
                    {
                        key: item
                        for key, item in value["target_binding"].items()
                        if key != "admission_generation"
                    }
                ),
                subject={"kind": "dataset", "id": dataset},
                dataset_handles={
                    dataset: {
                        "path": "/synthetic/target/" + dataset,
                        "mode": "write" if role == "restore" else "read",
                    }
                },
                output_directory="/synthetic/output/" + role + "/" + dataset,
                restore_input={
                    "checkpoint_digest": digest(checkpoint),
                    "datasets": {
                        dataset: {
                            "snapshot": deepcopy(snapshot),
                            "materializations": [
                                {
                                    "artifact": deepcopy(artifact),
                                    "path": f"/synthetic/input/{dataset}/{index}",
                                    "mode": "read",
                                }
                                for index, artifact in enumerate(snapshot["artifacts"])
                            ],
                        }
                    },
                },
            )
            procedure["datasets"] = [dataset]
            value[destination].append(
                {"procedure": procedure, "request": request, "result": result}
            )
    refresh_evidence(value)
    return value


def attach_drill(record, value):
    data = canonical(value)
    record["result_handle"] = {
        "handle": {
            "owner": deepcopy(record["owner"]),
            "id": uid("drill-result"),
            "purpose": "content",
            "binding": {"kind": "operation", "operation_id": record["id"]},
            "digest": digest(value),
            "size": len(data),
        },
        "schema": schema_identity(
            "https://fishhat.invalid/contracts/drill-result.schema.json#/$defs/DrillResult"
        ),
    }
    seal_operation(record)
    return data
