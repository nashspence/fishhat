"""Exact checkpoint receipt resolution with independently trusted owner keys.

This reference checks retained metadata and signatures. Native byte custody,
quiescence, current retrieval permission and restore execution remain with their
receiving owners; historical producer identity never supplies current authority.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .adapter_semantics import check_retained_result
from .bounds import Bounds, bounds
from .handoffs import schema_identity, validate_result_payload
from .operations import validate_operation
from .validation import ContractError, canonical, digest, strict_json, validate
from .witness import verify

KeyIdentity = tuple[str, str, str, str]
ENROLLMENT_IDENTITIES = ("installation_digest", "configuration_digest", "instance_digest")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _checkpoint_bounds(name: str) -> Bounds:
    return Bounds(
        id="checkpoints." + name,
        work=(
            "Current-core O(S + B + E): per-resolution installed schema closure setup, complete checkpoint and distinct receipt/result bytes, and dataset-artifact incidences; each shared receipt and object indexed once. Historical pins use complete result validation under its fixed admitted schema profile and qualified reader bounds"
            if name == "resolve"
            else "O(B + E) complete checkpoint bytes and dataset/closure identities"
        ),
        extent="All selected preserved datasets and every referenced capture, store, verification and artifact identity",
        limits=(),
        capacity=("Caller admits complete retained metadata under its explicit memory capacity",),
        proofs=(
            "tests/test_checkpoint_resolution.py::test_fresh_owner_resolves_exact_historical_inputs",
        ),
        linear_proofs=(
            "tests/test_checkpoint_resolution.py::test_checkpoint_resolution_linear_work",
        ),
    )


@bounds(_checkpoint_bounds("validate"))
def validate_checkpoint(value: dict[str, Any]) -> None:
    """Check snapshot integrity and explicit closure membership, without authentication."""
    validate("records.schema.json", value, "Checkpoint")
    witness = value["witness"]
    _require(
        witness["owner"] == value["owner"]
        and witness["kind"] == "checkpoint"
        and witness["state"] == "verified"
        and witness["subject_digest"]
        == digest({key: item for key, item in value.items() if key != "witness"}),
        "checkpoint witness snapshot mismatch",
    )
    closure = set(value["recovery_closure"])
    required = {
        value["release_digest"],
        *value["secret_generations"],
        *(value["backup_executor"][key] for key in ENROLLMENT_IDENTITIES),
    }
    if value["quiescence_evidence"] is not None:
        required.add(value["quiescence_evidence"])
    for selection in value["datasets"].values():
        required.update(selection.values())
    _require(required <= closure, "checkpoint recovery closure omits a selected identity")


@dataclass(frozen=True)
class CheckpointInputs:
    """Complete sparse joins; shared backup objects appear once, without alias resolution."""

    snapshots: dict[str, dict[str, Any]]
    backup_objects: dict[str, dict[str, Any]]
    dataset_backups: dict[str, str]
    checkpoint_digest: str


class _ReceiptReader:
    def __init__(
        self,
        closure: set[str],
        records: Mapping[str, bytes],
        trusted_keys: Mapping[KeyIdentity, Ed25519PublicKey],
        recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
    ) -> None:
        self.closure = closure
        self.records = records
        self.trusted_keys = trusted_keys
        self.recovery_readers = recovery_readers
        self.values: dict[str, tuple[bytes, dict[str, Any]]] = {}
        self.results: dict[str, tuple[str, str, dict[str, Any]]] = {}
        self.current_schemas: dict[str, tuple[dict[str, str], dict[str, str]]] = {}

    def authenticate(self, value: dict[str, Any]) -> None:
        owner, witness = value["owner"], value["witness"]
        identity = owner["tool"], owner["id"], owner["epoch"], witness["key_id"]
        key = self.trusted_keys.get(identity)
        _require(key is not None, "checkpoint receipt owner key is not independently trusted")
        assert key is not None
        verify(
            witness,
            key,
            owner,
            digest({name: item for name, item in value.items() if name != "witness"}),
        )

    def load(self, identity: str) -> tuple[bytes, dict[str, Any]]:
        if identity not in self.values:
            _require(identity in self.closure, "checkpoint receipt or payload is outside closure")
            data = self.records.get(identity)
            _require(data is not None, "checkpoint retained receipt or payload is unavailable")
            assert data is not None
            _require(
                "sha256:" + hashlib.sha256(data).hexdigest() == identity,
                "checkpoint retained bytes changed",
            )
            value = strict_json(data, max_bytes=len(data))
            _require(
                isinstance(value, dict) and canonical(value) == data,
                "checkpoint metadata requires canonical JSON objects",
            )
            self.values[identity] = data, value
        return self.values[identity]

    def result(self, identity: str, role: str, method: str) -> dict[str, Any]:
        if identity not in self.results:
            _, operation = self.load(identity)
            validate_operation(operation, recovery_readers=self.recovery_readers)
            self.authenticate(operation)
            _require(
                operation["state"] == "succeeded"
                and operation["effect_certainty"] == "known"
                and operation["subject"]["action"] == "adapter.execute",
                "checkpoint requires a successful known adapter Operation",
            )
            arguments = operation["subject"]["arguments"]
            base = "https://fishhat.invalid/contracts/" + role + "-adapter.schema.json#/$defs/"
            _require(
                arguments["action"] == method
                and arguments["input_schema"]["uri"] == base + "MutationRequest"
                and arguments["result_schema"]["uri"] == base + "RetainedResult",
                "checkpoint receipt selects another role or method",
            )
            handle = operation["result_handle"]["handle"]
            data, value = self.load(handle["digest"])
            _require(len(data) == handle["size"], "checkpoint result content size changed")
            if role not in self.current_schemas:
                self.current_schemas[role] = (
                    schema_identity(base + "MutationRequest"),
                    schema_identity(base + "RetainedResult"),
                )
            input_schema, result_schema = self.current_schemas[role]
            if (
                arguments["input_schema"] == input_schema
                and arguments["result_schema"] == result_schema
            ):
                # Operation and exact bytes are already checked. This applies the
                # complete current retained schema and all original-method joins;
                # neither a URI match alone nor a historical pin takes this path.
                check_retained_result(role, value, operation=operation)
            else:
                validate_result_payload(
                    operation, data, max_bytes=len(data), recovery_readers=self.recovery_readers
                )
            self.results[identity] = role, method, value
        cached_role, cached_method, result = self.results[identity]
        _require(
            (cached_role, cached_method) == (role, method),
            "checkpoint receipt reused for another role or method",
        )
        return result


def _artifact_index(artifacts: list[dict[str, Any]], closure: set[str]) -> set[bytes]:
    result = set()
    for artifact in artifacts:
        _require(artifact["digest"] in closure, "checkpoint closure omits captured material")
        result.add(canonical(artifact))
    return result


@bounds(_checkpoint_bounds("resolve"))
def resolve_checkpoint(
    value: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    expected_checkpoint_digest: str,
    expected_app_instance: str,
    expected_release_digest: str,
    expected_datasets: Iterable[str],
    expected_secret_generations: Iterable[str],
    records: Mapping[str, bytes],
    trusted_keys: Mapping[KeyIdentity, Ed25519PublicKey],
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> CheckpointInputs:
    """Reconstruct selected historical snapshots and objects from exact signed receipts.

    Expected pins, keys and compatible readers come from independently accepted
    recovery context, never from this checkpoint. ``records`` supplies immutable
    canonical receipt/result bytes, addressed by their digest. The returned
    metadata is the input to subsequent owner-authorized retrieval, exact artifact
    stream verification and restore. It does not establish the native common
    quiescence fence/cohort named by an application-quiesced checkpoint, prove that
    material bytes are still available, or authorize historical configurations.
    """
    validate_checkpoint(value)
    _require(
        value["owner"] == expected_owner
        and digest(value) == expected_checkpoint_digest
        and value["app_instance"] == expected_app_instance
        and value["release_digest"] == expected_release_digest
        and set(value["datasets"]) == set(expected_datasets)
        and set(value["secret_generations"]) == set(expected_secret_generations),
        "checkpoint differs from accepted recovery selection",
    )
    closure = set(value["recovery_closure"])
    reader = _ReceiptReader(closure, records, trusted_keys, recovery_readers)
    reader.authenticate(value)
    snapshots: dict[str, dict[str, Any]] = {}
    objects: dict[str, dict[str, Any]] = {}
    dataset_backups: dict[str, str] = {}
    object_artifacts: dict[str, set[bytes]] = {}
    verified_pairs: set[tuple[str, str]] = set()
    executor = value["backup_executor"]
    for dataset, selected in value["datasets"].items():
        captured = reader.result(selected["capture_digest"], "capture", "capture")
        output = captured["response"]["output"]
        snapshot = output["snapshots"][0]
        from .recovery_points import validate_recovery_point

        validate_recovery_point(snapshot["recovery_point"])
        if snapshot["recovery_point"] is not None:
            _require(
                snapshot["recovery_point"]["evidence_digest"] in closure,
                "checkpoint closure omits recovery-point evidence",
            )
        _require(
            all(snapshot["producer"][key] in closure for key in ENROLLMENT_IDENTITIES),
            "checkpoint closure omits historical capture enrollment",
        )
        _require(
            snapshot["dataset"] == dataset and output["verification"] == "consistent",
            "checkpoint capture does not establish the selected consistent dataset",
        )
        _require(
            value["consistency_scope"] != "application-quiesced"
            or snapshot["consistency"] == "quiesced",
            "application-quiesced checkpoint requires quiesced snapshots",
        )
        stored_id, verified_id = selected["backup_digest"], selected["verification_digest"]
        stored = reader.result(stored_id, "backup", "store")
        verified = reader.result(verified_id, "backup", "verify")
        pair = stored_id, verified_id
        if pair not in verified_pairs:
            _require(
                stored["invocation"]["attempt"]["executor"] == executor
                and verified["invocation"]["attempt"]["executor"] == executor,
                "checkpoint historical backup executor changed",
            )
            stored_input = stored["invocation"]["request"]["input"]
            verified_input = verified["invocation"]["request"]["input"]
            _require(
                all(
                    stored_input[key] == verified_input[key]
                    for key in ("scope", "repository", "object")
                )
                and _artifact_index(stored_input["artifacts"], closure)
                == _artifact_index(verified_input["artifacts"], closure),
                "checkpoint backup verification selects another immutable object",
            )
            stored_object = stored["response"]["output"]["objects"][0]
            verified_object = verified["response"]["output"]["objects"][0]
            _require(
                all(
                    stored_object[key] == verified_object[key]
                    for key in ("handle", "repository", "completeness")
                )
                and _artifact_index(stored_object["artifacts"], closure)
                == _artifact_index(verified_object["artifacts"], closure)
                and verified_object["retrieval"] == "available",
                "checkpoint backup verification differs from sealed stored object",
            )
            verified_pairs.add(pair)
            if stored_id not in objects:
                objects[stored_id] = deepcopy(verified_object)
                object_artifacts[stored_id] = _artifact_index(verified_object["artifacts"], closure)
        _require(
            _artifact_index(snapshot["artifacts"], closure) <= object_artifacts[stored_id],
            "checkpoint backup omits or substitutes snapshot artifacts",
        )
        snapshots[dataset] = deepcopy(snapshot)
        dataset_backups[dataset] = stored_id
    return CheckpointInputs(snapshots, objects, dataset_backups, digest(value))
