"""Immutable drill evidence tied to one unchanged checkpoint and reviewed producer."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .bounds import Bounds, bounds
from .checkpoints import CheckpointInputs, validate_checkpoint
from .hooks import validate_hook_result
from .validation import ContractError, digest, validate


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _binding_digest(binding: dict[str, Any]) -> str:
    return digest({key: value for key, value in binding.items() if key != "admission_generation"})


def _hook_evidence(
    value: dict[str, Any],
    role: str,
    entries: list[dict[str, Any]],
    required: set[str],
    request_ids: set[str],
    accepted_procedures: Mapping[str, dict[str, Any]] | None,
    checkpoint_digest: str,
) -> dict[str, tuple[str, str]]:
    snapshots: dict[str, tuple[str, str]] = {}
    for entry in entries:
        procedure, request, result = entry["procedure"], entry["request"], entry["result"]
        validate_hook_result(request, result)
        procedure_digest = digest(procedure)
        _require(
            request["role"] == role
            and request["operation_id"] == value["operation_id"]
            and request["release_digest"] == value["checkpoint"]["release_digest"]
            and request["runtime_binding_digest"] == _binding_digest(value["target_binding"])
            and request["procedure_digest"] == procedure_digest
            and request["executor_component"] == procedure["component"]
            and request["role"] == procedure["role"]
            and request["timeout_seconds"] == procedure["timeout_seconds"]
            and request["required_checks"] == procedure["required_checks"]
            and set(request["dataset_handles"]) == set(procedure["datasets"])
            and set(request["secret_paths"]) == set(procedure["secrets"])
            and (procedure["network"] != "none" or not request["endpoint_bindings"])
            and result["outcome"] == "succeeded",
            "drill hook differs from producer or accepted verification procedure",
        )
        if accepted_procedures is not None:
            _require(
                accepted_procedures.get(procedure_digest) == procedure,
                "drill procedure is not independently accepted",
            )
        _require(request["id"] not in request_ids, "drill reuses a hook invocation")
        request_ids.add(request["id"])
        selected = request["restore_input"]
        _require(
            selected is not None and selected["checkpoint_digest"] == checkpoint_digest,
            "drill hook selects another checkpoint",
        )
        _require(
            request["subject"] == value["resource"]
            or (
                request["subject"]["kind"] == "dataset"
                and set(selected["datasets"]) == {request["subject"]["id"]}
            ),
            "drill hook selects another application or dataset",
        )
        for dataset, item in selected["datasets"].items():
            _require(dataset not in snapshots, "drill stage repeats a selected dataset")
            snapshots[dataset] = (
                digest(item["snapshot"]),
                request["dataset_handles"][dataset]["path"],
            )
            required.update(artifact["digest"] for artifact in item["snapshot"]["artifacts"])
        required.update((procedure_digest, digest(request), digest(result)))
        required.update(artifact["digest"] for artifact in result["artifacts"])
    return snapshots


@bounds(
    Bounds(
        id="drill.result",
        work="O(B + D + E) complete result bytes with indexed dataset, hook and evidence joins",
        extent="The original checkpoint, every restored/verified dataset and complete retained hook evidence",
        limits=(),
        capacity=("The receiving owner admits complete evidence without dropping accepted work",),
        proofs=(
            "tests/test_drill_results.py::test_drill_retains_original_checkpoint_and_exact_evidence",
        ),
        linear_proofs=("tests/test_drill_results.py::test_complete_drill_result_linear_work",),
    )
)
def validate_drill_result(
    value: dict[str, Any],
    *,
    operation: dict[str, Any] | None = None,
    plan: dict[str, Any] | None = None,
    checkpoint_inputs: CheckpointInputs | None = None,
    accepted_procedures: Mapping[str, dict[str, Any]] | None = None,
    expected_production_binding: dict[str, Any] | None = None,
    expected_target_binding: dict[str, Any] | None = None,
) -> None:
    """Check exact retained joins, with optional independently accepted owner context.

    Before admitting drill success the receiving owner supplies its original Plan,
    bindings and accepted procedures plus authenticated ``resolve_checkpoint``
    inputs. It also independently verifies native isolation, complete result and
    artifact custody and any cleanup assertion. The context-free CLI/result
    boundary checks immutable structure and correlation only; it never converts
    copied evidence or embedded procedure bytes into native authority.
    """
    validate("drill-result.schema.json", value, "DrillResult")
    checkpoint = value["checkpoint"]
    validate_checkpoint(checkpoint)
    checkpoint_digest = digest(checkpoint)
    production, target = value["production_binding"], value["target_binding"]
    _require(
        production["native_incarnation"] != target["native_incarnation"]
        and _binding_digest(production) != _binding_digest(target),
        "drill target is the production runtime",
    )
    for actual, expected in (
        (production, expected_production_binding),
        (target, expected_target_binding),
    ):
        if expected is not None:
            _require(actual == expected, "drill runtime differs from accepted binding")
    required = {
        checkpoint_digest,
        *checkpoint["recovery_closure"],
        _binding_digest(production),
        _binding_digest(target),
        value["isolation_evidence"],
        value["cleanup"]["evidence_digest"],
    }
    request_ids: set[str] = set()
    restored = _hook_evidence(
        value,
        "restore",
        value["restorations"],
        required,
        request_ids,
        accepted_procedures,
        checkpoint_digest,
    )
    verified = _hook_evidence(
        value,
        "verify-restore",
        value["verifications"],
        required,
        request_ids,
        accepted_procedures,
        checkpoint_digest,
    )
    _require(
        set(restored) == set(checkpoint["datasets"]) and restored == verified,
        "drill evidence omits or substitutes a selected dataset snapshot",
    )
    if checkpoint_inputs is not None:
        _require(
            checkpoint_inputs.checkpoint_digest == checkpoint_digest
            and {name: item[0] for name, item in restored.items()}
            == {name: digest(item) for name, item in checkpoint_inputs.snapshots.items()},
            "drill snapshots differ from authenticated checkpoint inputs",
        )
    _require(required <= set(value["evidence_closure"]), "drill evidence closure is incomplete")
    if operation is not None:
        subject = operation["subject"]
        _require(
            subject["action"] == "app.drill"
            and value["owner"] == operation["owner"]
            and value["operation_id"] == operation["id"]
            and value["request_id"] == operation["request_id"]
            and value["plan_digest"] == operation["plan_digest"]
            and value["resource"] == subject["resource"]
            and checkpoint_digest == subject["arguments"]["checkpoint"],
            "drill differs from producing operation or reviewed checkpoint",
        )
    if plan is not None:
        from .operations import validate_operation_plan

        _require(operation is not None, "drill Plan requires producing Operation")
        assert operation is not None
        validate_operation_plan(operation, plan)
        planned = {
            checkpoint_digest,
            _binding_digest(production),
            _binding_digest(target),
            *(digest(entry["procedure"]) for entry in value["restorations"]),
            *(digest(entry["procedure"]) for entry in value["verifications"]),
        }
        _require(
            planned <= set(plan["input_digests"]),
            "drill evidence differs from reviewed Plan inputs",
        )
