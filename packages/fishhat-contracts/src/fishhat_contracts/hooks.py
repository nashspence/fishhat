"""Pure application-hook handoff checks; no materialization, grants or native execution."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any, BinaryIO

from .artifact_custody import verify_artifact_stream
from .bounds import Bounds, bounds
from .validation import ContractError, canonical, digest, validate

READ_ROLES = frozenset(
    {
        "health",
        "verify-config",
        "dependency-check",
        "busy",
        "transition-assess",
        "transition-verify",
        "capture",
        "verify-restore",
        "verify-rebuild",
    }
)


def _hook_bounds(name: str) -> Bounds:
    return Bounds(
        id="hooks." + name,
        work="O(B) complete request, procedure, result, path components and selected artifact bytes",
        extent="Every required check, dataset, materialization and artifact; no collection truncation",
        limits=(),
        capacity=("receiving owner memory and independently opened stable artifact custody",),
        proofs=("tests/test_hook_results.py::test_hook_result_linear_work",),
        linear_proofs=("tests/test_hook_results.py::test_hook_result_linear_work",),
    )


class _PathIndex:
    def __init__(self) -> None:
        self.root: dict[str, Any] = {}

    def overlaps(self, path: PurePosixPath) -> bool:
        node = self.root
        for part in path.parts:
            if "" in node:
                return True
            if part not in node:
                return False
            node = node[part]
        return bool(node)

    def add(self, path: PurePosixPath) -> None:
        node = self.root
        for part in path.parts:
            node = node.setdefault(part, {})
        node[""] = True


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _path(value: str) -> PurePosixPath:
    _require(
        value.startswith("/") and all(part not in ("", ".", "..") for part in value[1:].split("/")),
        "noncanonical hook path",
    )
    return PurePosixPath(value)


def _output_targets(value: dict[str, Any]) -> _PathIndex:
    output = _path(value["output_directory"])
    datasets = [_path(target["path"]) for target in value["dataset_handles"].values()]
    inputs = datasets + [_path(path) for path in value["secret_paths"].values()]
    output_index = _PathIndex()
    output_index.add(output)
    _require(
        all(not output_index.overlaps(path) for path in inputs),
        "hook output overlaps dataset target or secret",
    )
    index = _PathIndex()
    for target in [output, *inputs]:
        index.add(target)
    return index


@bounds(_hook_bounds("validate_hook_request"))
def validate_hook_request(value: dict[str, Any]) -> None:
    """Validate the closed request and exact snapshot/materialization joins.

    These lexical checks do not establish filesystem identity or authority. The
    receiving owner independently verifies accepted procedure grants, selected
    input custody, actual artifact bytes, native aliases and read-only isolation.
    """
    validate("hook-request.schema.json", value)
    targets = _output_targets(value)
    selected = value["restore_input"]
    if selected is None:
        return
    _require(
        set(selected["datasets"]) == set(value["dataset_handles"]),
        "restore input must cover every dataset target exactly",
    )
    paths: dict[PurePosixPath, bytes] = {}
    materializations = _PathIndex()
    for dataset, item in selected["datasets"].items():
        from .recovery_points import validate_recovery_point

        snapshot = item["snapshot"]
        validate_recovery_point(snapshot["recovery_point"])
        _require(
            snapshot["dataset"] == dataset and snapshot["producer"]["role"] == "capture",
            "restore snapshot dataset or producer mismatch",
        )
        expected = {canonical(artifact) for artifact in snapshot["artifacts"]}
        supplied = [canonical(entry["artifact"]) for entry in item["materializations"]]
        _require(
            len(supplied) == len(expected) and set(supplied) == expected,
            "restore materialization differs from complete snapshot artifacts",
        )
        for materialization in item["materializations"]:
            path = _path(materialization["path"])
            identity = canonical(materialization["artifact"])
            _require(
                path not in paths or paths[path] == identity,
                "restore materialization path selects different artifacts",
            )
            if path not in paths:
                _require(
                    not materializations.overlaps(path),
                    "restore materialization paths overlap",
                )
                materializations.add(path)
            _require(
                not targets.overlaps(path),
                "restore materialization overlaps dataset target or output",
            )
            paths[path] = identity


@bounds(_hook_bounds("require_selected_restore_input"))
def require_selected_restore_input(
    value: dict[str, Any],
    *,
    checkpoint_digest: str,
    snapshots: Mapping[str, dict[str, Any]],
) -> None:
    """Compare with independently retained owner inputs, never request-derived pins.

    The owner supplies the checkpoint and snapshot closure selected by accepted
    work, after authenticating their custody. A matching result supplies neither
    continuing dispatch permission nor evidence of native materialization.
    """
    validate_hook_request(value)
    validate("common.schema.json", checkpoint_digest, "Digest")
    for snapshot in snapshots.values():
        validate("adapter.schema.json", snapshot, "Snapshot")
    selected = value["restore_input"]
    _require(selected is not None, "selected restore input requires a restore hook")
    _require(selected["checkpoint_digest"] == checkpoint_digest, "selected checkpoint changed")
    _require(
        {dataset: item["snapshot"] for dataset, item in selected["datasets"].items()}
        == dict(snapshots),
        "selected snapshot closure changed",
    )


@bounds(_hook_bounds("validate_hook_result"))
def validate_hook_result(request: dict[str, Any], result: dict[str, Any]) -> None:
    """Validate correlation and outcome semantics, without authenticating native facts."""
    validate_hook_request(request)
    validate("hook-result.schema.json", result)
    _require(
        result["request_id"] == request["id"]
        and result["request_digest"] == digest(request)
        and all(
            result[key] == request[key]
            for key in (
                "operation_id",
                "release_digest",
                "executor_component",
                "role",
                "procedure_digest",
                "runtime_binding_digest",
            )
        ),
        "hook result identity mismatch",
    )
    checks = {check["code"]: check for check in result["checks"]}
    _require(len(checks) == len(result["checks"]), "duplicate hook check code")
    mandatory = set(request["required_checks"])
    _require(
        all(
            (check["requirement"] == "mandatory") == (code in mandatory)
            for code, check in checks.items()
        ),
        "hook check requirement changed",
    )
    if result["outcome"] == "succeeded":
        _require(
            mandatory <= checks.keys() and all(checks[code]["passed"] for code in mandatory),
            "mandatory hook verification failed or missing",
        )
        _require(result["effects"] != "unknown", "unknown hook effects cannot succeed")
        if request["role"] in READ_ROLES:
            _require(result["effects"] == "none", "observational hook mutated managed state")
    if result["outcome"] == "unsupported":
        _require(result["effects"] == "none", "unsupported hook cannot assert native effects")
    paths = _PathIndex()
    for artifact in result["artifacts"]:
        path = PurePosixPath(artifact["path"])
        _require(str(path) == artifact["path"], "noncanonical hook artifact path")
        _require(not paths.overlaps(path), "duplicate or overlapping hook artifact path")
        paths.add(path)


@bounds(_hook_bounds("require_hook_success"))
def require_hook_success(
    request: dict[str, Any],
    result: dict[str, Any],
    *,
    accepted_procedure: dict[str, Any],
    expected_runtime_binding_digest: str,
    artifact_streams: Mapping[str, BinaryIO],
    retained_result_digest: str | None = None,
) -> None:
    """Check success against independent procedure and byte custody before phase advance.

    The receiving owner loads accepted_procedure from the accepted release and
    opens immutable/confined regular-file streams independently. It supplies the
    stable runtime binding digest from that accepted execution context, never
    from the hook reply. These arguments are trusted context, never
    request-selected authority. Native isolation,
    authentication, and atomic retention with the owning operation remain owner
    duties. A caller must not advance on a failed check or before that retention.
    An exact replay may supply its independently retained result digest; it never
    upgrades an old observation to evidence for a fresh request or changed state.
    """
    validate("source.schema.json", accepted_procedure, "Hook")
    validate("common.schema.json", expected_runtime_binding_digest, "Digest")
    validate_hook_result(request, result)
    _require(
        request["runtime_binding_digest"] == expected_runtime_binding_digest,
        "hook execution runtime differs from accepted binding",
    )
    _require(
        request["procedure_digest"] == digest(accepted_procedure)
        and request["executor_component"] == accepted_procedure["component"]
        and request["role"] == accepted_procedure["role"]
        and request["timeout_seconds"] == accepted_procedure["timeout_seconds"]
        and request["required_checks"] == accepted_procedure["required_checks"]
        and set(request["dataset_handles"]) == set(accepted_procedure["datasets"])
        and set(request["secret_paths"]) == set(accepted_procedure["secrets"])
        and (accepted_procedure["network"] != "none" or not request["endpoint_bindings"]),
        "hook accepted procedure or requirements changed",
    )
    _require(result["outcome"] == "succeeded", "hook did not establish required success")
    if retained_result_digest is not None:
        validate("common.schema.json", retained_result_digest, "Digest")
        _require(digest(result) == retained_result_digest, "retained hook result changed")
    _require(
        set(artifact_streams) == {item["path"] for item in result["artifacts"]},
        "hook artifact custody is incomplete or substituted",
    )
    for artifact in result["artifacts"]:
        verify_artifact_stream(
            {
                "digest": artifact["digest"],
                "size_bytes": artifact["bytes"],
                "media_type": "application/octet-stream",
            },
            artifact_streams[artifact["path"]],
        )
