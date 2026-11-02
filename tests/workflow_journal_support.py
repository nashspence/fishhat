"""Complete journal workloads with independently owned synthetic native facts.

Only logical input construction is outside measurement. Every workflow model,
signature, frame, durable write, replay and cold restoration is exercised inside
the measured run. This is reference evidence, not native implementation qualification.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sys
import threading
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_client.wire import frame, read_frame
from fishhat_contracts import validation
from fishhat_contracts.handoffs import PHASES, schema_identity
from fishhat_contracts.record_delivery import (
    InstalledRecordSchema,
    RecordSnapshot,
    validate_content_chunk,
    validate_record_chunk,
)
from fishhat_contracts.validation import ContractError, canonical, digest, strict_json, validate
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_evidence import REQUIREMENTS
from fishhat_contracts.workflow_journal import (
    GateEnrollment,
    dispatch_journal_command,
    initialize_workflow_journal,
)
from fishhat_contracts.workflow_journal_delivery import (
    WorkflowRecordDelivery,
    decode_journal_command,
    validate_journal_input_custody,
)
from fishhat_contracts.workflow_journal_recovery import JournalRecovery
from fishhat_owner.workflow_journal import WorkflowJournal

from tests.test_contracts import uid
from tests.test_owner_handoffs import operation

NOW = "2026-11-01T00:00:00Z"
LATER = "2026-11-01T01:00:00Z"
DRIVER = "ops-app-operate"
NEXT_DRIVER = "ops-app-recovery"
KEY_ID = "journal-owner"
CHUNK_BYTES = 65536


@dataclass(frozen=True)
class LogicalWorkload:
    owners: int = 2
    children: int = 2
    evidence_bytes: int = 256

    def owner(self, index):
        return {
            "tool": "host-ops",
            "id": uid(f"journal-owner-{index:08d}"),
            "epoch": uid(f"journal-epoch-{index:08d}"),
        }

    def resource(self, index):
        return {"kind": "host", "id": f"journal-host-{index:08d}"}

    def child(self, owner_index, child_index):
        return {
            "owner": self.owner(owner_index),
            "request_id": uid(f"journal-child-{owner_index:08d}-{child_index:08d}"),
        }

    def inputs(self):
        """Logical inputs and required consumer-byte incidences, before protocol replication."""
        return {
            "procedure": "host-drain",
            "participants": [
                {
                    "owner": self.owner(index),
                    "resource": self.resource(index),
                    "children": [self.child(index, child) for child in range(self.children)],
                    "source": self.material(index).decode(),
                    "native_observations": [
                        {"phase": phase, "material": self.material(index).decode()}
                        for phase in PHASES["host-drain"][1:]
                    ],
                }
                for index in range(self.owners)
            ],
        }

    def material(self, index):
        return (f"owner-{index:08d}:" + "x" * self.evidence_bytes).encode()

    def extent(self):
        inputs = self.inputs()
        required_edges = self.owners * (
            self.children + max(0, self.children - 1) + len(PHASES["host-drain"]) + 6
        )
        return {
            "logical_bytes": len(canonical(inputs)),
            "owners": self.owners,
            "semantic_edges": required_edges,
            "continuation_edges": self.owners * max(0, self.children - 1),
        }


class MeteredPublicKey:
    def __init__(self, key, metrics):
        self._key, self._metrics = key, metrics

    def verify(self, signature, data):
        self._metrics["signature_verifications"] += 1
        self._metrics["signature_verified_bytes"] += len(data)
        return self._key.verify(signature, data)

    def public_bytes(self, *args, **kwargs):
        return self._key.public_bytes(*args, **kwargs)


class MeteredPrivateKey:
    def __init__(self, identity, metrics):
        # Distinct keys belong to owner actors; no driver method receives them.
        self._key = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(canonical(identity)).digest()
        )
        self._metrics = metrics

    def sign(self, data):
        self._metrics["signatures_created"] += 1
        self._metrics["signature_created_bytes"] += len(data)
        return self._key.sign(data)

    def public_key(self):
        return MeteredPublicKey(self._key.public_key(), self._metrics)


class WorkMeter:
    def __init__(self):
        self.values = Counter()
        self.messages = []

    @contextmanager
    def account(self):
        original_jcs = validation.jcs_bytes
        original_sha256 = hashlib.sha256
        original_loads = json.loads
        original_validate = validation.validate
        metrics = self.values
        previous_trace = sys.gettrace()

        def trace(frame, event, arg):
            module = frame.f_globals.get("__name__", "")
            if module not in {
                "fishhat_contracts.workflow_journal",
                "fishhat_contracts.workflow_journal_recovery",
                "fishhat_contracts.workflow_gate_recovery",
                "fishhat_contracts.workflow_journal_delivery",
                "fishhat_contracts.workflow_bindings",
                "fishhat_contracts.workflows",
                "fishhat_owner.workflow_journal",
                "tests.workflow_journal_support",
            }:
                return None
            if event == "line":
                metrics["reference_python_steps"] += 1
            elif event == "call" and frame.f_code.co_name in {
                "_key",
                "_pair",
                "lookup",
                "append",
                "record",
                "replay_reference",
                "_gate_record",
                "__getitem__",
            }:
                metrics["protected_index_visits"] += 1
            return trace

        def encoded(value):
            data = original_jcs(value)
            metrics["canonical_calls"] += 1
            metrics["canonical_bytes"] += len(data)
            return data

        def parsed(data, *args, **kwargs):
            metrics["json_parse_calls"] += 1
            metrics["json_parsed_bytes"] += len(data.encode() if isinstance(data, str) else data)
            return original_loads(data, *args, **kwargs)

        def checked(schema, value, definition=None):
            metrics["validation_calls"] += 1
            # Measure the complete input to every installed schema validation,
            # including aliases imported before instrumentation. Generic schema
            # evaluation composes with its separately maintained linear proof;
            # its full validation input cannot disappear from this aggregate.
            metrics["validation_input_bytes"] += len(original_jcs(value))
            return original_validate(schema, value, definition)

        def validation_aliases(original, replacement):
            for module in tuple(sys.modules.values()):
                namespace = getattr(module, "__dict__", {})
                if not namespace.get("__name__", "").startswith(
                    ("fishhat_", "tests.workflow_journal_support")
                ):
                    continue
                for name, value in tuple(namespace.items()):
                    if value is original:
                        namespace[name] = replacement

        class Hash:
            def __init__(self, *args, **kwargs):
                self._hash = original_sha256(*args, **kwargs)
                metrics["hash_calls"] += 1
                metrics["hash_bytes"] += len(args[0] if args else kwargs.get("string", b""))

            def update(self, data):
                metrics["hash_bytes"] += len(data)
                return self._hash.update(data)

            def digest(self):
                return self._hash.digest()

            def hexdigest(self):
                return self._hash.hexdigest()

            def copy(self):
                clone = object.__new__(Hash)
                clone._hash = self._hash.copy()
                return clone

            def __getattr__(self, name):
                return getattr(self._hash, name)

        with (
            patch.object(validation, "jcs_bytes", encoded),
            patch.object(hashlib, "sha256", Hash),
            patch.object(json, "loads", parsed),
        ):
            try:
                validation_aliases(original_validate, checked)
                sys.settrace(trace)
                yield
            finally:
                sys.settrace(previous_trace)
                validation_aliases(checked, original_validate)

    def message(self, source, destination, value, *, category="protocol"):
        """Encode/decode real bounded frames; metadata copies are charged on every link."""
        data = frame(value)
        self.values["wire_messages"] += 1
        self.values["wire_bytes"] += len(data)
        self.values[category + "_wire_bytes"] += len(data)
        self.messages.append((source, destination, category, len(data)))
        return read_frame(io.BytesIO(data))

    def write_material(self, path, data):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if self.read_material(path) != data:
                raise ContractError("changed immutable native material")
            return
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            remaining = memoryview(data)
            while remaining:
                written = os.write(fd, remaining[:CHUNK_BYTES])
                assert written > 0
                self.values["artifact_bytes_written"] += written
                remaining = remaining[written:]
            os.fsync(fd)
            self.values["artifact_fsync_calls"] += 1
        finally:
            os.close(fd)

    def read_material(self, path):
        data = bytearray()
        with Path(path).open("rb") as stream:
            while part := stream.read(CHUNK_BYTES):
                self.values["artifact_bytes_read"] += len(part)
                data.extend(part)
        return bytes(data)

    def retained(self, root):
        self.values["retained_bytes"] = sum(
            path.stat().st_size for path in Path(root).rglob("*") if path.is_file()
        )

    def rpc(self, source, destination, method, params, *, category="protocol"):
        request = {
            "format": "deployment-ops/owner/v1",
            "message_id": uid(f"frame-{self.values['wire_messages']}"),
            "method": method,
            "params": params,
        }
        incoming = self.message(source, destination, request, category=category)
        validate("ssh-request.schema.json", incoming)
        return incoming["params"]

    def stage(
        self,
        source,
        owner,
        workflow_id,
        identifier,
        data,
        path,
        *,
        purpose="workflow-input",
        category="protocol",
    ):
        """Transfer all actual bytes in bounded frames into independently owned custody."""
        identity = "sha256:" + hashlib.sha256(data).hexdigest()
        staging_id = uid("staging-" + identifier)
        begin = self.rpc(
            source,
            owner["id"],
            "content.begin",
            {
                "expected_owner": owner,
                "staging_id": staging_id,
                "resource": {"kind": "workflow", "id": workflow_id},
                "purpose": purpose,
                "digest": identity,
                "size": len(data),
            },
            category=category,
        )
        received = bytearray()
        for offset in range(0, len(data), CHUNK_BYTES):
            chunk = self.rpc(
                source,
                owner["id"],
                "content.chunk",
                {
                    "owner": owner,
                    "staging_id": staging_id,
                    "offset": offset,
                    "base64": base64.b64encode(data[offset : offset + CHUNK_BYTES]).decode(),
                },
                category=category,
            )
            assert chunk["offset"] == len(received)
            received.extend(base64.b64decode(chunk["base64"], validate=True))
            self.message(
                owner["id"],
                source,
                {"staging_id": staging_id, "offset": len(received)},
                category=category,
            )
        assert len(received) == begin["size"]
        assert "sha256:" + hashlib.sha256(received).hexdigest() == begin["digest"]
        self.write_material(path, bytes(received))
        handle = {
            "owner": deepcopy(owner),
            "id": uid("handle-" + identifier),
            "purpose": purpose,
            "binding": {"kind": "staging", "staging_id": staging_id},
            "digest": identity,
            "size": len(received),
        }
        staging = {
            "format": "deployment-ops/record/v1",
            "kind": "ContentStaging",
            "id": staging_id,
            "owner": deepcopy(owner),
            "resource": {"kind": "workflow", "id": workflow_id},
            "authenticated_principal": source,
            "purpose": purpose,
            "digest": identity,
            "size": len(received),
            "state": "committed",
            "offset": len(received),
            "created_at": NOW,
            "expires_at": LATER,
            "accepted_references": 0,
            "handle": handle,
        }
        self.message(owner["id"], source, staging, category=category)
        try:
            command_id = str(UUID(identifier))
        except ValueError:
            command_id = uid("reference-" + identifier)
        return {
            "owner": deepcopy(owner),
            "workflow_id": workflow_id,
            "command_id": command_id,
            "input": handle,
        }, staging


def signed_plan(owner, resource, child, material_digest, private_key, *, generation=9):
    value = {
        "format": "deployment-ops/record/v1",
        "kind": "Plan",
        "id": uid("journal-plan-" + child["request_id"]),
        "owner": deepcopy(owner),
        "subject": {"action": "host.reboot", "resource": deepcopy(resource), "arguments": {}},
        "summary": "Reboot the exact independently selected synthetic host.",
        "data_consequences": "Retain all selected data and recovery obligations.",
        "recovery_limits": "Reconcile accepted work before any replacement request.",
        "created_at": NOW,
        "expires_at": LATER,
        "input_digests": [material_digest],
        "preconditions": [
            {
                "owner": deepcopy(owner),
                "resource": deepcopy(resource),
                "generation": generation,
                "source_digests": [material_digest],
                "holds_digest": digest([]),
            }
        ],
        "effects": [
            {
                "step": "reboot",
                "executor": deepcopy(owner),
                "resource": deepcopy(resource),
                "summary": "Reboot the selected host after complete native fencing.",
                "action": "admitted-reboot",
                "input_digest": material_digest,
                "reconciliation": "inspect-runtime",
            }
        ],
        "checkpoint_required": False,
        "interruption": "Selected host reboot",
        "recovery": ["native-reconcile"],
        "blockers": [],
    }
    value["digest"] = digest(value)
    witness = {key: item for key, item in operation()["witness"].items() if key != "signature"}
    witness.update(
        id=uid("journal-plan-witness-" + child["request_id"]),
        owner=deepcopy(owner),
        kind="plan",
        state="prepared",
        workflow_id=None,
        generation=generation,
        subject_digest=value["digest"],
        key_id=KEY_ID,
        created_at=NOW,
    )
    value["witness"] = sign(witness, private_key)
    return value


def proposal(workload, keys):
    """Construct the real installed-procedure proposal within measured setup."""
    participants, content = [], []
    for index in range(workload.owners):
        owner, resource = workload.owner(index), workload.resource(index)
        material_digest = "sha256:" + hashlib.sha256(workload.material(index)).hexdigest()
        requests = []
        for child_index in range(workload.children):
            child = workload.child(index, child_index)
            if child_index == 0:
                slot = {
                    "request_id": child["request_id"],
                    "phase": "host-effect",
                    "plan": signed_plan(owner, resource, child, material_digest, keys[index]),
                }
            else:
                slot = {
                    "request_id": child["request_id"],
                    "phase": "host-effect",
                    "intent": {
                        "kind": "reviewed-successor",
                        "predecessor": workload.child(index, child_index - 1),
                        "subject": {
                            "action": "host.reboot",
                            "resource": deepcopy(resource),
                            "arguments": {},
                        },
                    },
                }
            requests.append(slot)
        participants.append(
            {"owner": owner, "resource": resource, "expected_generation": 9, "requests": requests}
        )
        content.append(
            {
                "owner": deepcopy(owner),
                "id": uid(f"handle-source-{index:08d}"),
                "purpose": "content",
                "binding": {"kind": "staging", "staging_id": uid(f"staging-source-{index:08d}")},
                "digest": material_digest,
                "size": len(workload.material(index)),
            }
        )
    return {
        "format": "deployment-ops/workflow-proposal/v1",
        "workflow_id": uid("aggregate-journal-workflow"),
        "initial_driver": {"principal": DRIVER, "term": 1},
        "type": "host-drain",
        "target": {"host_change": workload.child(0, 0)},
        "participants": participants,
        "content": content,
    }


def require(condition, message):
    if not condition:
        raise ContractError(message)


def child_key(child):
    return canonical([child["owner"], child["request_id"]])


class NativeOwner:
    """Independent synthetic receiver with append-only native facts on real disk.

    Logical owner scope is installed separately from wire requests. Native
    protection, resource generations, reviewed Plans and accepted Operations are
    reconstructed exclusively from this actor's own protected journal at restart.
    These checks exercise reference joins; they do not qualify a host implementation.
    """

    def __init__(self, root, workload, index, key, meter, *, restore=False):
        self.root, self.workload, self.index = Path(root), workload, index
        self._native_lock = threading.RLock()
        self.owner, self.resource = workload.owner(index), workload.resource(index)
        self.key, self.meter = key, meter
        self.operation_schema = InstalledRecordSchema("Operation")
        self.root.mkdir(parents=True, exist_ok=True)
        self.schema = {
            "uri": "https://synthetic.invalid/native-facts/v1",
            "digest": digest("independently-installed-synthetic-native-facts/v1"),
        }
        self.path = self.root / "native.journal"
        self.store = (
            WorkflowJournal.open(
                self.path,
                expected_owner=self.owner,
                expected_schema=self.schema,
                metrics=meter.values,
            )
            if restore
            else WorkflowJournal.create(
                self.path, owner=self.owner, schema=self.schema, metrics=meter.values
            )
        )
        self.resource_generation = 9
        self.prepared = None
        self.bindings = {}
        self.admissions = {}
        self.operations = {}
        self.reservations = {}
        self.fence_generations = {}
        self.protection_holds = set()
        self.retired = False
        self.successor = None
        self.dispositions = {}
        self.abandonments = {}
        self.abandoned = set()
        self.denied_principals = set()
        self.paused = False
        self.retired_permits = {}
        self.gate_recovery_enrollments = {}
        self.gate_reapprovals = {}
        self._allowed_children = {
            child_key(workload.child(index, slot)): slot for slot in range(workload.children)
        }
        for event in self.store.iter_events(read_authorized=True):
            meter.values["native_restore_visits"] += 1
            self._apply(event["request"]["action"], event["outcome"])
        if restore:
            meter.values["cold_restores"] += 1

    def _append(self, identifier, action, outcome):
        with self._native_lock:
            self.store.append(
                identifier,
                {"action": action, "owner": self.owner},
                outcome,
                expected_head=self.store.head,
            )
            self._apply(action, outcome)

    def _apply(self, action, outcome):
        if action == "prepare":
            self.prepared = outcome
        elif action == "review":
            self.bindings[child_key(outcome["child"])] = outcome["binding"]
        elif action == "reserve":
            self.reservations[outcome["id"]] = outcome
            self.fence_generations[outcome["id"]] = outcome["generation"]
            self.protection_holds.add(outcome["id"])
        elif action == "lose-fence":
            self.fence_generations[outcome["id"]] = outcome["generation"]
        elif action == "admit":
            key = child_key(outcome["child"])
            self.admissions[key] = outcome
            self.operations[key] = outcome["operation"]
        elif action == "operation":
            self.operations[child_key(outcome["child"])] = outcome["operation"]
            self.resource_generation = outcome["resource_generation"]
        elif action == "recover":
            self.retired = True
            self.successor = outcome["successor_workflow_id"]
            self.dispositions[outcome["successor_workflow_id"]] = outcome
        elif action == "lifecycle":
            self.paused = outcome["admission_closed"]
        elif action == "renew-admission":
            self.retired_permits[outcome["previous_permit_id"]] = outcome
        elif action == "gate-reapproval":
            self.retired = True
            self.gate_reapprovals[outcome["authority_digest"]] = outcome
        elif action == "abandon":
            self.abandonments[outcome["successor_workflow_id"]] = outcome
        elif action == "observe-abandon":
            self.abandoned.add(outcome["successor_workflow_id"])
            self.successor = None
        else:
            raise ContractError("unknown protected synthetic native event")

    def authorize(self, principal, action, context):
        self.meter.values["native_authorization_visits"] += 1
        require(
            principal in {DRIVER, NEXT_DRIVER} and principal not in self.denied_principals,
            "native current permission denied",
        )
        require(context["owner"] == self.owner, "native authorization owner changed")
        if action in {"admit", "bind", "vote", "prepare"}:
            require(
                not self.retired or context["workflow_id"] == self.successor,
                "native original admission retired",
            )

    def prepare(self, projection, enrollment):
        self.meter.values["native_prepare_visits"] += 1
        require(
            projection["owner"] == enrollment.member_owner == self.owner,
            "native local scope changed",
        )
        participants = projection["participants"]
        require(
            len(participants) == 1 and participants[0]["resource"] == self.resource,
            "native resource scope changed",
        )
        slots = participants[0]["requests"]
        require(
            [slot["request_id"] for slot in slots]
            == [
                self.workload.child(self.index, n)["request_id"]
                for n in range(self.workload.children)
            ],
            "native local child closure changed",
        )
        require(len(projection["content"]) == 1, "native source closure changed")
        handle = projection["content"][0]
        data = self.meter.read_material(self.root / "source.material")
        require(
            handle["owner"] == self.owner
            and handle["digest"] == "sha256:" + hashlib.sha256(data).hexdigest()
            and handle["size"] == len(data)
            and data == self.workload.material(self.index),
            "native complete material custody changed",
        )
        if self.prepared is None:
            self._append(
                "native-prepare",
                "prepare",
                {
                    "workflow_id": enrollment.workflow_id,
                    "proposal_digest": enrollment.proposal_digest,
                    "projection_digest": enrollment.projection_digest,
                    "participants": participants,
                    "content": projection["content"],
                    "grant_id": enrollment.grant_id,
                },
            )
        first = self.review(self.workload.child(self.index, 0))
        require(first == slots[0], "native independently reviewed initial Plan changed")

    def review(self, child):
        key = child_key(child)
        self.meter.values["native_index_visits"] += 1
        require(
            key in self._allowed_children and not self.retired,
            "native child outside approved scope",
        )
        if key in self.bindings:
            return deepcopy(self.bindings[key])
        require(self.prepared is not None, "native local preparation missing")
        slot = self._allowed_children[key]
        if slot:
            predecessor = self.operations.get(child_key(self.workload.child(self.index, slot - 1)))
            require(
                predecessor is not None
                and predecessor["state"] == "succeeded"
                and predecessor["effect_certainty"] == "known",
                "native predecessor has no exact success",
            )
        binding = {
            "request_id": child["request_id"],
            "phase": "host-effect",
            "plan": signed_plan(
                self.owner,
                self.resource,
                child,
                self.prepared["content"][0]["digest"],
                self.key,
                generation=self.resource_generation,
            ),
        }
        self._append(
            "native-review-" + child["request_id"], "review", {"child": child, "binding": binding}
        )
        return deepcopy(binding)

    def _review_context(self, request, child):
        key = child_key(child)
        self.meter.values["native_index_visits"] += 1
        require(key in self.bindings, "native independent review absent")
        independently_reviewed = self.bindings[key]
        require(request["binding"] == independently_reviewed, "native reviewed Plan substituted")
        require(
            independently_reviewed["plan"]["preconditions"][0]["generation"]
            == self.resource_generation,
            "native current resource generation changed",
        )
        verified = []
        for predecessor in request["predecessors"]:
            self.meter.values["native_index_visits"] += 1
            retained = self.operations.get(
                child_key({"owner": predecessor["owner"], "request_id": predecessor["request_id"]})
            )
            require(retained == predecessor, "native predecessor differs from retained result")
            verified.append(retained)
        require(not request["materials"], "native material lineage outside installed reboot scope")
        return {
            "verified_binding": independently_reviewed,
            "current_generations": [
                {
                    "owner": self.owner,
                    "resource": self.resource,
                    "generation": self.resource_generation,
                }
            ],
            "verified_operations": verified,
            "verified_materials": [],
            "verified_content": self.prepared["content"],
            "verified_adapters": [],
            "now": NOW,
        }

    def bind(self, request):
        self.meter.values["native_bind_visits"] += 1
        require(not self.retired, "native original admission retired")
        return self._review_context(request, request["child"])

    def admit(self, context):
        self.meter.values["native_admission_visits"] += 1
        require(
            not self.retired and self.prepared is not None, "native original admission unavailable"
        )
        require(
            context["workflow_id"] == self.prepared["workflow_id"]
            and context["phase"] == "host-effect",
            "native admission workflow or phase changed",
        )
        reservation = context["reservation"]
        self.check(reservation, {"round_id": reservation["round_id"]})
        review = self._review_context(context["request"], context["child"])
        return review

    def renew_admission(self, context):
        with self._native_lock:
            child = context["child"]
            key = child_key(child)
            require(
                context["owner"] == self.owner
                and key in self._allowed_children
                and key not in self.admissions,
                "native positive unaccepted proof unavailable",
            )
            self.meter.values["native_renewal_index_visits"] += 1
            previous = context["previous_permit"]
            result = {
                "owner": self.owner,
                "workflow_id": context["workflow_id"],
                "child": child,
                "previous_permit_id": previous["id"],
                "previous_permit_digest": digest(previous),
                "native_generation": self.resource_generation,
                "unaccepted": True,
                "previous_permit_closed": True,
            }
            self._append("native-renew-" + previous["id"], "renew-admission", result)
            return deepcopy(result)

    def approve_gate_recovery(self, context):
        authority = context["authority"]
        identity = digest(authority)
        require(
            self.gate_recovery_enrollments.get(identity) == context
            and self.prepared is not None
            and self.prepared["workflow_id"] == context["workflow_id"],
            "native gate recovery was not independently approved",
        )
        self.meter.values["native_gate_reapproval_visits"] += 1
        result = {
            "owner": self.owner,
            "workflow_id": context["workflow_id"],
            "authority_digest": identity,
            "grant_id": context["grant_id"],
            "previous_authority_digest": context["previous_authority_digest"],
            "native_generation": self.resource_generation,
            "original_admission_closed": True,
            "custody_preserved": True,
        }
        self._append("native-gate-reapproval-" + identity, "gate-reapproval", result)
        return deepcopy(result)

    def submit_native(self, submission, member, *, principal):
        child = {"owner": submission["owner"], "request_id": submission["request_id"]}
        key = child_key(child)
        member._authorize(principal, "read")
        accepted = self.admissions.get(key)
        self.meter.values["native_index_visits"] += 1
        if accepted is not None:
            require(accepted["submission"] == submission, "native request changed accepted input")
            self.meter.values["native_exact_replays"] += 1
            return deepcopy(accepted["operation"])
        with member.operation_admission_guard(submission, principal=principal) as permit:
            with self._native_lock:
                return self._accept_native(submission, member, principal, child, key, permit)

    def _accept_native(self, submission, member, principal, child, key, permit):
        accepted = self.admissions.get(key)
        if accepted is not None:
            require(accepted["submission"] == submission, "native request changed accepted input")
            self.meter.values["native_exact_replays"] += 1
            return deepcopy(accepted["operation"])
        require(
            permit["id"] not in self.retired_permits, "native admission permit permanently closed"
        )
        require(
            not self.retired and not self.paused and key in self.bindings,
            "native original admission unavailable",
        )
        plan = self.bindings[key]["plan"]
        require(
            plan["preconditions"][0]["generation"] == self.resource_generation,
            "native generation changed before acceptance",
        )
        self.check(member._reservation, member._round["body"])
        require(
            submission["plan_id"] == plan["id"]
            and submission["plan_digest"] == plan["digest"]
            and submission["subject_digest"] == digest(plan["subject"]),
            "native exact Plan commitment changed",
        )
        result = operation()
        result.update(
            id=uid("native-operation-" + child["request_id"]),
            request_id=child["request_id"],
            owner=deepcopy(self.owner),
            subject=deepcopy(plan["subject"]),
            plan_digest=plan["digest"],
            generation=0,
            state="accepted",
            effect_certainty="none",
            authenticated_principal=principal,
            created_at=NOW,
            updated_at=NOW,
            last_event=0,
            result_handle=None,
        )
        witness = {key: value for key, value in result["witness"].items() if key != "signature"}
        witness.update(
            id=uid("native-acceptance-witness-" + child["request_id"]),
            owner=deepcopy(self.owner),
            kind="acceptance",
            workflow_id=member.workflow_id,
            state="accepted",
            generation=0,
            key_id=KEY_ID,
            created_at=NOW,
            subject_digest=digest(
                {key: value for key, value in result.items() if key != "witness"}
            ),
        )
        result["witness"] = sign(witness, self.key)
        self._append(
            "native-admit-" + child["request_id"],
            "admit",
            {
                "child": child,
                "plan_digest": plan["digest"],
                "submission": submission,
                "operation": result,
            },
        )
        return deepcopy(result)

    def finish(self, child, *, unknown=False):
        self.meter.values["native_index_visits"] += 1
        key = child_key(child)
        require(key in self.admissions, "native child was never admitted")
        require(self.operations[key]["state"] == "accepted", "native accepted result is immutable")
        plan = self.bindings[key]["plan"]
        result = deepcopy(self.admissions[key]["operation"])
        result.update(
            id=uid("native-operation-" + child["request_id"]),
            request_id=child["request_id"],
            owner=deepcopy(self.owner),
            subject=deepcopy(plan["subject"]),
            plan_digest=plan["digest"],
            generation=1,
            state="quarantined" if unknown else "succeeded",
            effect_certainty="unknown" if unknown else "known",
            created_at=NOW,
            updated_at=NOW,
            last_event=1,
            result_handle=None,
        )
        witness = {key: value for key, value in result["witness"].items() if key != "signature"}
        witness.update(
            id=uid("native-operation-witness-" + child["request_id"]),
            owner=deepcopy(self.owner),
            kind="effect",
            workflow_id=self.prepared["workflow_id"],
            state=result["state"],
            generation=1,
            key_id=KEY_ID,
            created_at=NOW,
            subject_digest=digest(
                {key: value for key, value in result.items() if key != "witness"}
            ),
        )
        result["witness"] = sign(witness, self.key)
        self._append(
            "native-operation-" + child["request_id"],
            "operation",
            {
                "child": child,
                "operation": result,
                "resource_generation": self.resource_generation + 1,
            },
        )
        return deepcopy(result)

    def reserve(self, round, participants, outcomes):
        self.meter.values["native_reserve_visits"] += 1
        require(not self.retired and self.prepared is not None, "native protection unavailable")
        require(participants == self.prepared["participants"], "native phase scope changed")
        identifier = uid("native-reservation-" + self.owner["id"] + round["round_id"])
        if identifier in self.reservations:
            return deepcopy(self.reservations[identifier])
        phase = round["to_phase"]
        destination = PHASES["host-drain"].index(phase)
        required = []
        for slot in participants[0]["requests"]:
            self.meter.values["native_scope_visits"] += 1
            if PHASES["host-drain"].index(slot["phase"]) < destination:
                child = {"owner": self.owner, "request_id": slot["request_id"]}
                self.meter.values["native_index_visits"] += 1
                known = self.operations.get(child_key(child))
                require(
                    known is not None and known == outcomes.get(child_key(child)),
                    "native phase omitted retained child outcome",
                )
                required.append({"child": child, "operation": known})
        # Acquire all observation bytes here and retain them before signing any vote.
        evidence = canonical(
            {
                "owner": self.owner,
                "resource": self.resource,
                "phase": phase,
                "generation": self.resource_generation,
                "observations": self.workload.material(self.index).decode(),
            }
        )
        path = self.root / ("evidence-" + round["round_id"])
        self.meter.write_material(path, evidence)
        require(
            self.meter.read_material(path) == evidence, "native evidence lost before reservation"
        )
        handle = {
            "owner": deepcopy(self.owner),
            "id": uid("native-evidence-" + identifier),
            "purpose": "content",
            "binding": {
                "kind": "staging",
                "staging_id": uid("native-evidence-custody-" + identifier),
            },
            "digest": "sha256:" + hashlib.sha256(evidence).hexdigest(),
            "size": len(evidence),
        }
        result = {
            "id": identifier,
            "generation": len(self.reservations) + 1,
            "protection": "durable-until-verified-release",
            "round_id": round["round_id"],
            "owner": deepcopy(self.owner),
            "participants": [
                {
                    "owner": deepcopy(self.owner),
                    "resource": deepcopy(self.resource),
                    "resource_generation": self.resource_generation,
                    "operations": required,
                    "native_evidence": [handle],
                    "expires_at": LATER,
                }
            ],
            "issued_at": NOW,
            "expires_at": LATER,
        }
        self._append("native-reserve-" + round["round_id"], "reserve", result)
        return deepcopy(result)

    def check(self, reservation, round):
        self.meter.values["native_fence_checks"] += 1
        identifier = reservation["id"]
        require(
            self.reservations.get(identifier) == reservation
            and self.fence_generations.get(identifier) == reservation["generation"]
            and reservation["round_id"] == round["round_id"],
            "native fence missing, stale or replaced",
        )

    def lose_fence(self, reservation):
        # A lost local admission guard closes new effects. The independently
        # durable shared exclusion remains held; failure does not revoke it.
        self._append(
            "lose-" + reservation["id"],
            "lose-fence",
            {"id": reservation["id"], "generation": reservation["generation"] + 1},
        )

    def revoke_protection(self, reservation):
        require(reservation["id"] in self.protection_holds, "native protection is not retained")
        raise ContractError(
            "nonrevocable native protection requires independently settled dependent closure"
        )

    def lifecycle(self, action, snapshot):
        require(snapshot["owner"] == self.owner, "native lifecycle owner changed")
        result = {
            "action": action,
            "owner": self.owner,
            "workflow_id": snapshot["workflow_id"],
            "admission_closed": action != "resume",
            "holds_digest": digest(self.fence_generations),
            "accepted_digest": self.store.head,
            "generation": snapshot["generation"],
        }
        self._append(
            "native-lifecycle-" + action + str(snapshot["generation"]), "lifecycle", result
        )
        return result

    def result_payload(self, result):
        require(result["result_handle"] is None, "unexpected synthetic result payload")
        return None

    def recovery_disposition(self, projection):
        recovery = projection["recovery"]
        successor_id = recovery["successor_workflow_id"]
        require(
            successor_id not in self.abandoned and self.successor in {None, successor_id},
            "native successor abandoned or different successor already reserved",
        )
        if successor_id in self.dispositions:
            return deepcopy(self.dispositions[successor_id])
        require(self.prepared is not None, "native recovery preparation fact unavailable")
        require(
            projection["owner"] == self.owner
            and projection["origin_projection_digest"] == self.prepared["projection_digest"],
            "native recovery origin scope changed",
        )
        dispositions = []
        for pair in projection["mapping"]:
            origin = pair["origin"]
            key = child_key(origin)
            self.meter.values["native_index_visits"] += 1
            require(key in self._allowed_children, "native recovery unknown original child")
            retained = self.operations.get(key)
            if (
                retained is not None
                and retained["state"] == "succeeded"
                and retained["effect_certainty"] == "known"
            ):
                kind, stopped = "completed", True
            elif key not in self.admissions:
                # The protected original admission index and exclusive retirement
                # establish positive nonadmission; missing external custody does not.
                kind, stopped = "unaccepted", True
            else:
                kind, stopped = "unknown", False
            dispositions.append(
                {
                    "origin": origin,
                    "kind": kind,
                    "operation": retained,
                    "operation_reference": None
                    if retained is None
                    else RecordSnapshot(
                        retained,
                        uid("native-retained-operation-" + retained["id"]),
                        installed_schema=self.operation_schema,
                    ).reference,
                    "recovery": None,
                    "native_stopped": stopped,
                }
            )
        data = self.meter.read_material(self.root / "source.material")
        require(data == self.workload.material(self.index), "native recovery material custody lost")
        result = {
            "origin_workflow_id": self.prepared["workflow_id"],
            "origin_proposal_digest": self.prepared["proposal_digest"],
            "origin_projection_digest": self.prepared["projection_digest"],
            "successor_workflow_id": successor_id,
            "successor_proposal_digest": recovery["successor_proposal_digest"],
            "preparation": "prepared",
            "admission_retired": True,
            "successor_reserved": True,
            "custody_digest": self.store.head,
            "children": dispositions,
        }
        self._append("native-recover-" + successor_id, "recover", result)
        return deepcopy(result)

    def check_recovery(self, projection, facts, certificate):
        self.meter.values["native_recovery_checks"] += 1
        successor = projection["recovery"]["successor_workflow_id"]
        require(
            self.retired
            and self.successor == successor
            and self.dispositions.get(successor) == facts
            and certificate["body"]["recovery"] == projection["recovery"],
            "native retirement or exact successor reservation lost",
        )
        require(
            self.meter.read_material(self.root / "source.material")
            == self.workload.material(self.index),
            "native retained recovery material lost",
        )

    def abandon_recovery(self, projection, proposal):
        recovery = projection["recovery"]
        successor = recovery["successor_workflow_id"]
        require(
            self.successor == successor
            and proposal["recovery"] == recovery
            and all(
                item["operation"]["witness"]["workflow_id"] != successor
                for item in self.admissions.values()
            ),
            "native successor used or exact reservation unavailable",
        )
        facts = {
            **{
                name: recovery[name]
                for name in (
                    "origin_workflow_id",
                    "successor_workflow_id",
                    "successor_proposal_digest",
                )
            },
            "unused": True,
            "successor_admission_closed": True,
            "native_stopped": True,
            "custody_digest": self.store.head,
        }
        self._append("native-abandon-" + successor, "abandon", facts)
        return deepcopy(facts)

    def observe_abandonment(self, projection, facts, certificate):
        successor = projection["recovery"]["successor_workflow_id"]
        require(
            self.abandonments.get(successor) == facts
            and certificate["body"]["recovery"] == projection["recovery"],
            "native abandonment closure changed",
        )
        self._append(
            "native-observe-abandon-" + successor,
            "observe-abandon",
            {
                "successor_workflow_id": successor,
            },
        )

    def close(self):
        self.store.close()


class Endpoint:
    """Public staged submit and typed chunk replies backed by one durable owner store."""

    def __init__(self, target, root, meter):
        self.target, self.root, self.meter = target, Path(root), meter
        self.root.mkdir(parents=True, exist_ok=True)
        self.delivery = WorkflowRecordDelivery(
            target.owner,
            authorize_read=lambda principal, workflow_id: self.authorize_read(
                principal, workflow_id
            ),
        )
        self.registered = set()
        for event in target.journal.iter_events(read_authorized=True):
            self._register(event["event_id"])
        self.inputs = {}

    def authorize_read(self, principal, workflow_id):
        self.target._authorize(principal, "read")
        return workflow_id == self.target.workflow_id

    def _register(self, identifier):
        if identifier not in self.registered:
            self.delivery.retain(
                self.target.journal.outcome_bytes(identifier, read_authorized=True),
                command_bytes=self.target.journal.command_bytes(identifier, read_authorized=True),
            )
            self.registered.add(identifier)
            self.meter.values["delivery_index_visits"] += 1

    def command(self, action, payload=None, *, fresh=False, label=None):
        selected = {} if payload is None else deepcopy(payload)
        if fresh:
            selected = {
                "expected_generation": self.target.generation,
                "driver_term": self.target.driver_term,
                **selected,
            }
        return {
            "id": uid(
                label
                or f"{self.target.owner['id']}-{self.target.workflow_id}-{action}-{self.target.generation}-{self.meter.values['commands_constructed']}"
            ),
            "workflow_id": self.target.workflow_id,
            "action": action,
            "payload": selected,
        }

    def submit(self, command, *, principal=DRIVER, lost_reply=False):
        self.meter.values["commands_constructed"] += 1
        identifier = command["id"]
        data = canonical(command)
        path = self.root / (identifier + ".input")
        if identifier not in self.inputs:
            reference, staging = self.meter.stage(
                principal,
                self.target.owner,
                self.target.workflow_id,
                identifier,
                data,
                path,
                category="phase-evidence" if command["action"] == "vote" else "protocol",
            )
            self.inputs[identifier] = (reference, staging)
        else:
            reference, staging = self.inputs[identifier]
            require(self.meter.read_material(path) == data, "staged retry changed accepted bytes")
        incoming = self.meter.rpc(
            principal, self.target.owner["id"], "workflow.journal.submit", reference
        )
        decoded = decode_journal_command(
            incoming, self.meter.read_material(path), expected_owner=self.target.owner
        )
        self.target._authorize(principal, "read")
        retained = self.target.journal.lookup(identifier, read_authorized=True)
        validate_journal_input_custody(
            incoming,
            decoded,
            staging,
            principal=principal,
            now=NOW,
            retained_command=None if retained is None else retained["request"],
        )
        outcome = dispatch_journal_command(self.target, decoded, principal=principal)
        staging["accepted_references"] = 1
        self._register(identifier)
        result = self.read(identifier, principal=principal)
        require(result == outcome, "typed journal delivery substituted outcome")
        if lost_reply:
            before = self.meter.values["signatures_created"]
            # The first accepted reply is deliberately unavailable to the caller.
            # Retry uses the original staged identity and exact immutable command.
            repeated = self.retry(reference, principal=principal)
            require(repeated == result, "lost reply changed original accepted outcome")
            require(
                self.meter.values["signatures_created"] == before,
                "exact retry created a new signature",
            )
            self.meter.values["lost_reply_replays"] += 1
            return repeated
        return result

    def retry(self, reference, *, principal=DRIVER):
        before = self.meter.values["artifact_bytes_read"]
        incoming = self.meter.rpc(
            principal, self.target.owner["id"], "workflow.journal.submit", reference
        )
        identifier = self.target.replay_reference(incoming, principal=principal)
        require(identifier is not None, "accepted reference retry lost custody")
        require(
            self.meter.values["artifact_bytes_read"] == before,
            "bounded retry reread complete staged command",
        )
        self.meter.values["bounded_reference_replays"] += 1
        return self.read(identifier, principal=principal)

    def call(
        self, action, payload=None, *, fresh=False, principal=DRIVER, lost_reply=False, label=None
    ):
        return self.submit(
            self.command(action, payload, fresh=fresh, label=label),
            principal=principal,
            lost_reply=lost_reply,
        )

    def read(self, identifier, *, principal=DRIVER):
        kind = self.target._records[identifier]["body"]["type"]
        category = (
            "phase-evidence"
            if kind == "vote"
            else ("manifest" if kind == "projection" else "protocol")
        )
        query = self.meter.rpc(
            principal,
            self.target.owner["id"],
            "workflow.journal.get",
            {
                "owner": self.target.owner,
                "workflow_id": self.target.workflow_id,
                "record_id": identifier,
            },
        )
        reference = self.delivery.get(query, principal=principal)
        reference = self.meter.message(
            self.target.owner["id"], principal, reference, category=category
        )
        pieces, offset = [], 0
        while offset < reference["size"]:
            request = self.meter.rpc(
                principal,
                self.target.owner["id"],
                "record.read",
                {"reference": reference, "offset": offset, "length": CHUNK_BYTES},
            )
            chunk = self.delivery.read(
                request["reference"],
                principal=principal,
                offset=request["offset"],
                length=request["length"],
            )
            chunk = self.meter.message(self.target.owner["id"], principal, chunk, category=category)
            part = validate_record_chunk(chunk, reference, offset=offset, length=CHUNK_BYTES)
            require(bool(part), "record read failed to progress")
            pieces.append(part)
            offset += len(part)
        data = b"".join(pieces)
        require(
            len(data) == reference["size"]
            and "sha256:" + hashlib.sha256(data).hexdigest() == reference["digest"],
            "typed reply did not preserve complete bytes",
        )
        return strict_json(data, max_bytes=len(data))

    def close(self):
        self.target.journal.close()


class WorkflowRun:
    """Complete roles whose only shared state is explicit input and measured transport."""

    def __init__(self, root, workload, meter, *, restore=False):
        self.root, self.workload, self.meter = Path(root), workload, meter
        self.root.mkdir(parents=True, exist_ok=True)
        self.principal = DRIVER
        self.gate_owner = workload.owner(workload.owners)
        self.gate_key = MeteredPrivateKey(self.gate_owner, meter.values)
        self.keys = [
            MeteredPrivateKey(workload.owner(index), meter.values)
            for index in range(workload.owners)
        ]
        self.native = [
            NativeOwner(
                self.root / f"member-{index:08d}",
                workload,
                index,
                self.keys[index],
                meter,
                restore=restore,
            )
            for index in range(workload.owners)
        ]
        self.native_by_owner = {canonical(actor.owner): actor for actor in self.native}
        self.schema = schema_identity(
            "https://fishhat.invalid/contracts/workflow-journal.schema.json#/$defs/JournalRecord"
        )
        if restore:
            self.manifest = strict_json(
                meter.read_material(self.root / "proposal.input"),
                max_bytes=(self.root / "proposal.input").stat().st_size,
            )
        else:
            logical_proposal = proposal(workload, self.keys)
            meter.stage(
                DRIVER,
                self.gate_owner,
                logical_proposal["workflow_id"],
                "gate-proposal",
                canonical(logical_proposal),
                self.root / "proposal.input",
            )
            data = meter.read_material(self.root / "proposal.input")
            self.manifest = strict_json(data, max_bytes=len(data))
        gate_store = self.store(self.root / "gate.journal", self.gate_owner, restore=restore)
        member_keys = {
            (canonical(workload.owner(index)), KEY_ID): self.keys[index].public_key()
            for index in range(workload.owners)
        }
        self.gate = Endpoint(
            self.initialize(
                {
                    "id": uid("initial-gate-command"),
                    "workflow_id": self.manifest["workflow_id"],
                    "action": "gate.create",
                    "payload": {"proposal": self.manifest},
                },
                {
                    "owner": self.gate_owner,
                    "key_id": KEY_ID,
                    "private_key": self.gate_key,
                    "member_keys": member_keys,
                    "authorize": self.authorize_gate,
                    "check_reservation": self.check_reservation,
                    "journal": gate_store,
                    "clock": lambda: NOW,
                    "extension": JournalRecovery(),
                },
                self.root / "gate-initialize.input",
                restore=restore,
            ),
            self.root / "gate-inputs",
            meter,
        )
        self.gate.read(uid("initial-gate-command"))
        self.members = []
        header = {
            "workflow_id": self.manifest["workflow_id"],
            "proposal_digest": digest(self.manifest),
            "procedure": "host-drain",
            "requirements_digest": digest(REQUIREMENTS["host-drain"]),
            "gate_owner": self.gate_owner,
            "gate_key_id": KEY_ID,
            "driver_principal": DRIVER,
            "driver_term": 1,
            "owner_count": workload.owners,
        }
        for index, actor in enumerate(self.native):
            local_root = self.root / f"member-{index:08d}"
            owner = workload.owner(index)
            projection_path = local_root / "projection.input"
            grant_path = local_root / "enrollment.input"
            if restore:
                data = meter.read_material(projection_path)
                signed_projection = strict_json(data, max_bytes=len(data))
                data = meter.read_material(grant_path)
                grant = strict_json(data, max_bytes=len(data))
            else:
                signed_projection = self.gate.call("projection", {"owner": owner})
                independent_local = {
                    "type": "projection",
                    "header": header,
                    "owner": owner,
                    "participants": [self.manifest["participants"][index]],
                    "content": [self.manifest["content"][index]],
                    "dependencies": [],
                }
                # The manifest is indexed centrally. A receiving native owner
                # sees only the separately approved local scope, never all peers.
                require(
                    {
                        key: value
                        for key, value in signed_projection["body"].items()
                        if key != "command_digest"
                    }
                    == independent_local,
                    "gate projection differed from independently approved local intent",
                )
                grant = {
                    "workflow_id": header["workflow_id"],
                    "proposal_digest": header["proposal_digest"],
                    "gate_owner": self.gate_owner,
                    "gate_key_id": KEY_ID,
                    "member_owner": owner,
                    "projection_digest": digest(independent_local),
                    "grant_id": uid("approved-grant-" + owner["id"]),
                }
                meter.write_material(grant_path, canonical(grant))
                meter.stage(
                    DRIVER,
                    owner,
                    header["workflow_id"],
                    "projection-" + owner["id"],
                    canonical(signed_projection),
                    projection_path,
                )
                source, _ = meter.stage(
                    DRIVER,
                    owner,
                    header["workflow_id"],
                    f"source-{index:08d}",
                    workload.material(index),
                    local_root / "source.material",
                    purpose="content",
                )
                require(
                    source["input"] == self.manifest["content"][index],
                    "source transfer changed logical source handle",
                )
            enrollment = GateEnrollment(**grant, gate_public_key=self.gate_key.public_key())
            local_keys = {(canonical(owner), KEY_ID): self.keys[index].public_key()}
            member_command = {
                "id": uid("initial-member-command-" + owner["id"]),
                "workflow_id": self.manifest["workflow_id"],
                "action": "member.join",
                "payload": {"projection": signed_projection},
            }
            member = self.initialize(
                member_command,
                {
                    "owner": owner,
                    "key_id": KEY_ID,
                    "private_key": self.keys[index],
                    "enrollment": enrollment,
                    "operation_keys": local_keys,
                    "native": actor,
                    "journal": self.store(local_root / "member.journal", owner, restore=restore),
                    "clock": lambda: NOW,
                    "extension": JournalRecovery(),
                },
                local_root / "member-initialize.input",
                restore=restore,
            )
            endpoint = Endpoint(member, local_root / "inputs", meter)
            endpoint.read(member_command["id"])
            self.members.append(endpoint)
        if restore:
            self.principal = self.gate.target.driver_principal

    def initialize(self, command, context, path, *, restore=False):
        if restore:
            data = self.meter.read_material(path)
            decoded = strict_json(data, max_bytes=len(data))
            require(decoded == command, "restored initialization changed")
        else:
            reference, staging = self.meter.stage(
                self.principal,
                context["owner"],
                command["workflow_id"],
                command["id"],
                canonical(command),
                path,
                category="manifest",
            )
            incoming = self.meter.rpc(
                self.principal, context["owner"]["id"], "workflow.journal.submit", reference
            )
            decoded = decode_journal_command(
                incoming, self.meter.read_material(path), expected_owner=context["owner"]
            )
            validate_journal_input_custody(
                incoming, decoded, staging, principal=self.principal, now=NOW
            )
        return initialize_workflow_journal(decoded, principal=self.principal, context=context)

    def store(self, path, owner, *, restore):
        if restore:
            self.meter.values["cold_restores"] += 1
            return WorkflowJournal.open(
                path, expected_owner=owner, expected_schema=self.schema, metrics=self.meter.values
            )
        return WorkflowJournal.create(
            path, owner=owner, schema=self.schema, metrics=self.meter.values
        )

    def authorize_gate(self, principal, action, context):
        self.meter.values["gate_authorization_visits"] += 1
        require(principal in {DRIVER, NEXT_DRIVER}, "gate current permission denied")
        require(context["owner"] == self.gate_owner, "gate owner changed")

    def check_reservation(self, owner, reservation, round):
        self.meter.values["gate_native_index_visits"] += 1
        actor = self.native_by_owner.get(canonical(owner))
        require(actor is not None, "gate native reservation owner is not independently installed")
        query = self.meter.message(
            self.gate_owner["id"],
            owner["id"],
            {"reservation": reservation, "round": round},
            category="native-check",
        )
        actor.check(query["reservation"], query["round"])
        self.meter.message(
            owner["id"],
            self.gate_owner["id"],
            {
                "owner": owner,
                "reservation_id": reservation["id"],
                "generation": actor.fence_generations[reservation["id"]],
                "custody": actor.store.head,
            },
            category="native-check",
        )

    def prepare(self):
        for member in self.members:
            proof = member.call("prepare", fresh=True, principal=self.principal, lost_reply=True)
            self.gate.call("preparation", {"preparation": proof}, principal=self.principal)
        agreement = self.gate.call("agreement", principal=self.principal)
        for member in self.members:
            member.call("agreement", {"agreement": agreement}, principal=self.principal)

    def round(self, phase, *, apply=True):
        round_record = self.gate.call(
            "round", {"to_phase": phase}, fresh=True, principal=self.principal
        )
        votes = []
        for member in self.members:
            vote = member.call(
                "vote", {"round": round_record}, fresh=True, principal=self.principal
            )
            self.gate.call("vote", {"vote": vote}, principal=self.principal)
            votes.append(vote)
        decision = self.gate.call("decision", principal=self.principal)
        certificates = [
            self.gate.call(
                "certificate",
                {"owner": member.target.owner, "round_id": round_record["id"]},
                principal=self.principal,
            )
            for member in self.members
        ]
        if apply:
            for member, certificate in zip(self.members, certificates, strict=True):
                member.call(
                    "apply", {"certificate": certificate}, fresh=True, principal=self.principal
                )
        return round_record, votes, decision, certificates

    def children(self, *, unknown_at=None):
        for index, (member, actor) in enumerate(zip(self.members, self.native, strict=True)):
            for slot in range(self.workload.children):
                child = self.workload.child(index, slot)
                if slot:
                    binding = actor.review(child)
                    request = {
                        "owner": self.gate_owner,
                        "workflow_id": self.manifest["workflow_id"],
                        "bind_id": uid("binding-" + child["request_id"]),
                        "expected_generation": self.gate.target.generation,
                        "driver_term": self.gate.target.driver_term,
                        "child": child,
                        "binding": binding,
                        "content": actor.prepared["content"],
                        "predecessors": [
                            actor.operations[child_key(self.workload.child(index, slot - 1))]
                        ],
                        "materials": [],
                    }
                    signed_binding = self.gate.call(
                        "bind",
                        {"request": request},
                        fresh=True,
                        principal=self.principal,
                        label="binding-" + child["request_id"],
                    )
                    member.call(
                        "bind", {"binding": signed_binding}, fresh=True, principal=self.principal
                    )
                member.call(
                    "admit",
                    {"child": child},
                    fresh=True,
                    principal=self.principal,
                    lost_reply=slot == 0,
                )
                submission = self.native_submission(index, slot)
                accepted = self.submit_native(index, submission)
                member.call("complete", {"operation": accepted}, principal=self.principal)
                if slot == 0:
                    require(
                        self.submit_native(index, submission) == accepted,
                        "native accepted retry changed attribution",
                    )
                result = actor.finish(child, unknown=unknown_at == (index, slot))
                member.call(
                    "complete",
                    {"operation": result},
                    principal=self.principal,
                    lost_reply=slot == 0,
                )
                if unknown_at == (index, slot):
                    return

    def native_submission(self, index, slot):
        actor, member = self.native[index], self.members[index]
        child = self.workload.child(index, slot)
        plan = actor.bindings[child_key(child)]["plan"]
        return {
            "owner": actor.owner,
            "request_id": child["request_id"],
            "plan_id": plan["id"],
            "plan_digest": plan["digest"],
            "subject_digest": digest(plan["subject"]),
            "confirmed": True,
            "claimed_actor": None,
            "workflow_id": self.manifest["workflow_id"],
            "driver_term": member.target.driver_term,
        }

    def submit_native(self, index, submission):
        actor = self.native[index]
        incoming = self.meter.rpc(self.principal, actor.owner["id"], "operation.submit", submission)
        accepted = actor.submit_native(
            incoming, self.members[index].target, principal=self.principal
        )
        # Actual accepted Operation bytes are part of the native receiver's
        # durable admission before this response is made observable.
        return self.meter.message(
            actor.owner["id"], self.principal, accepted, category="native-operation"
        )

    def clone_member(self, index):
        """A second in-process target must share the durable admission guard."""
        endpoint, actor = self.members[index], self.native[index]
        data = endpoint.target.journal.command_bytes(
            uid("initial-member-command-" + actor.owner["id"]), read_authorized=True
        )
        return initialize_workflow_journal(
            strict_json(data, max_bytes=len(data)),
            principal=self.principal,
            context={
                "owner": actor.owner,
                "key_id": KEY_ID,
                "private_key": actor.key,
                "enrollment": endpoint.target.enrollment,
                "operation_keys": {(canonical(actor.owner), KEY_ID): actor.key.public_key()},
                "native": actor,
                "journal": endpoint.target.journal,
                "clock": lambda: NOW,
                "extension": JournalRecovery(),
            },
        )

    def transfer(self):
        proposal_record = self.gate.call(
            "transfer.propose", {"new_driver": NEXT_DRIVER}, principal=self.principal
        )
        for member in self.members:
            freeze = member.call(
                "transfer.freeze",
                {"proposal": proposal_record},
                principal=self.principal,
                lost_reply=True,
            )
            self.gate.call("transfer.collect_freeze", {"freeze": freeze}, principal=self.principal)
        certificate = self.gate.call("transfer.commit", principal=self.principal)
        for member in self.members:
            installation = member.call(
                "transfer.install", {"certificate": certificate}, principal=self.principal
            )
            self.gate.call(
                "transfer.collect_install", {"installation": installation}, principal=self.principal
            )
        activation = self.gate.call("transfer.activate", principal=NEXT_DRIVER)
        for member in self.members:
            member.call("transfer.observe", {"activation": activation}, principal=NEXT_DRIVER)
        self.principal = NEXT_DRIVER
        require(
            all(
                member.target.driver_principal == NEXT_DRIVER and member.target.driver_term == 2
                for member in self.members
            ),
            "transfer omitted a member",
        )
        self.meter.values["completed_transfers"] += 1

    def successor(self):
        successor = deepcopy(self.manifest)
        successor["workflow_id"] = uid("aggregate-successor-workflow")
        successor["initial_driver"] = {"principal": NEXT_DRIVER, "term": 1}
        mapping = []
        for index, participant in enumerate(successor["participants"]):
            actor = self.native[index]
            participant["expected_generation"] = actor.resource_generation
            replacements = []
            for slot in range(self.workload.children):
                original = self.workload.child(index, slot)
                replacement = {
                    "owner": original["owner"],
                    "request_id": uid("successor-" + original["request_id"]),
                }
                mapping.append({"origin": original, "successor": replacement})
                key = child_key(original)
                result = actor.operations.get(key)
                if (
                    result is not None
                    and result["state"] == "succeeded"
                    and result["effect_certainty"] == "known"
                ):
                    binding = {
                        "request_id": replacement["request_id"],
                        "phase": "host-effect",
                        "completed": {"plan": actor.bindings[key]["plan"], "operation": result},
                    }
                elif slot == 0:
                    binding = {
                        "request_id": replacement["request_id"],
                        "phase": "host-effect",
                        "plan": signed_plan(
                            actor.owner,
                            actor.resource,
                            replacement,
                            actor.prepared["content"][0]["digest"],
                            actor.key,
                            generation=actor.resource_generation,
                        ),
                    }
                else:
                    binding = {
                        "request_id": replacement["request_id"],
                        "phase": "host-effect",
                        "intent": {
                            "kind": "reviewed-successor",
                            "predecessor": {
                                "owner": actor.owner,
                                "request_id": replacements[-1]["request_id"],
                            },
                            "subject": {
                                "action": "host.reboot",
                                "resource": actor.resource,
                                "arguments": {},
                            },
                        },
                    }
                replacements.append(binding)
            participant["requests"] = replacements
        successor["target"] = {"host_change": mapping[0]["successor"]}
        return successor, mapping

    def recover(self, *, commit=True):
        successor, mapping = self.successor()
        self.gate.call(
            "recover.propose",
            {"successor": successor, "mapping": mapping},
            principal=self.principal,
        )
        self.meter.write_material(self.root / "successor.proposal", canonical(successor))
        for member in self.members:
            projection_record = self.gate.call(
                "recover.projection", {"owner": member.target.owner}, principal=self.principal
            )
            disposition = member.call(
                "recover.inspect",
                {"projection": projection_record},
                principal=self.principal,
                lost_reply=True,
            )
            self.gate.call(
                "recover.collect", {"disposition": disposition}, principal=self.principal
            )
        if not commit:
            return successor
        certificate = self.gate.call("recover.commit", principal=self.principal)
        for member in self.members:
            member.call("recover.install", {"certificate": certificate}, principal=self.principal)
        self.meter.values["completed_recoveries"] += 1
        return successor

    def initialize_successor(self):
        data = self.meter.read_material(self.root / "successor.proposal")
        successor = strict_json(data, max_bytes=len(data))
        old_gate = self.gate.target
        extension = JournalRecovery()
        context = extension.context(old_gate, principal=self.principal)
        next_gate = Endpoint(
            self.initialize(
                {
                    "id": uid("successor-gate-initialize"),
                    "workflow_id": successor["workflow_id"],
                    "action": "gate.create",
                    "payload": {"proposal": successor},
                },
                {
                    "owner": self.gate_owner,
                    "key_id": KEY_ID,
                    "private_key": self.gate_key,
                    "member_keys": {
                        (canonical(actor.owner), KEY_ID): actor.key.public_key()
                        for actor in self.native
                    },
                    "authorize": self.authorize_gate,
                    "check_reservation": self.check_reservation,
                    "journal": self.store(
                        self.root / "successor-gate.journal", self.gate_owner, restore=False
                    ),
                    "clock": lambda: NOW,
                    "extension": extension,
                    "recovery_context": context,
                },
                self.root / "successor-gate.input",
            ),
            self.root / "successor-gate-inputs",
            self.meter,
        )
        next_gate.read(uid("successor-gate-initialize"), principal=self.principal)
        next_members = []
        for index, (member, actor) in enumerate(zip(self.members, self.native, strict=True)):
            signed = next_gate.call("projection", {"owner": actor.owner}, principal=self.principal)
            approved = {
                "type": "projection",
                "header": next_gate.target.header,
                "owner": actor.owner,
                "participants": [successor["participants"][index]],
                "content": [successor["content"][index]],
                "dependencies": [],
            }
            require(
                {key: value for key, value in signed["body"].items() if key != "command_digest"}
                == approved,
                "successor changed independently reserved local scope",
            )
            enrollment = GateEnrollment(
                workflow_id=successor["workflow_id"],
                proposal_digest=digest(successor)
                if index == 0
                else next_gate.target.header["proposal_digest"],
                gate_owner=self.gate_owner,
                gate_key_id=KEY_ID,
                gate_public_key=self.gate_key.public_key(),
                member_owner=actor.owner,
                projection_digest=digest(approved),
                grant_id=uid("successor-grant-" + actor.owner["id"]),
            )
            member_context = extension.context(member.target, principal=self.principal)
            command = {
                "id": uid("successor-member-" + actor.owner["id"]),
                "workflow_id": successor["workflow_id"],
                "action": "member.join",
                "payload": {"projection": signed},
            }
            target = self.initialize(
                command,
                {
                    "owner": actor.owner,
                    "key_id": KEY_ID,
                    "private_key": actor.key,
                    "enrollment": enrollment,
                    "operation_keys": {(canonical(actor.owner), KEY_ID): actor.key.public_key()},
                    "native": actor,
                    "journal": self.store(
                        actor.root / "successor.journal", actor.owner, restore=False
                    ),
                    "clock": lambda: NOW,
                    "extension": JournalRecovery(),
                    "recovery_context": member_context,
                },
                actor.root / "successor.input",
            )
            endpoint = Endpoint(target, actor.root / "successor-inputs", self.meter)
            endpoint.read(command["id"], principal=self.principal)
            for slot in successor["participants"][index]["requests"]:
                child = {"owner": actor.owner, "request_id": slot["request_id"]}
                require(
                    target.outcomes[child_key(child)] == slot["completed"]["operation"],
                    "successor changed completed ancestor bytes",
                )
                try:
                    endpoint.call("admit", {"child": child}, fresh=True, principal=self.principal)
                except ContractError as exc:
                    require(
                        "completed" in str(exc), "completed replay refused for an unrelated reason"
                    )
                    self.meter.values["completed_nonexecutions"] += 1
                else:
                    raise AssertionError("completed successor slot admitted native work")
            next_members.append(endpoint)
        self.successor_endpoints = [next_gate, *next_members]

    def assert_complete(self):
        for index, (member, actor) in enumerate(zip(self.members, self.native, strict=True)):
            require(member.target.phase == "completed", "owner omitted installed phases")
            require(
                len(member.target.outcomes) == self.workload.children, "owner omitted child outcome"
            )
            for slot in range(self.workload.children):
                key = child_key(self.workload.child(index, slot))
                require(
                    member.target.outcomes[key] == actor.operations[key]
                    and actor.operations[key]["state"] == "succeeded",
                    "retained owner outcome mismatch",
                )
            require(
                len(member.target.projection["participants"]) == 1
                and member.target.projection["participants"][0]["owner"] == actor.owner
                and len(member.target.projection["content"]) == 1,
                "member replicated peer manifest",
            )
        return self.workload.owners * self.workload.children

    def discover(self):
        """A fresh caller discovers all workflows and events without original IDs."""
        by_owner = {}
        endpoints = [self.gate, *self.members, *getattr(self, "successor_endpoints", [])]
        for endpoint in endpoints:
            by_owner.setdefault(canonical(endpoint.target.owner), []).append(endpoint)
        discovered = 0
        for owned in by_owner.values():
            owner = owned[0].target.owner
            routes = {endpoint.target.workflow_id: endpoint for endpoint in owned}

            def authorize(principal, workflow_id, routes=routes):
                endpoint = routes.get(workflow_id)
                return endpoint is not None and endpoint.authorize_read(principal, workflow_id)

            delivery = WorkflowRecordDelivery(owner, authorize_read=authorize)
            expected = set()
            for endpoint in owned:
                for event in endpoint.target.journal.iter_events(read_authorized=True):
                    delivery.retain(
                        endpoint.target.journal.outcome_bytes(
                            event["event_id"], read_authorized=True
                        ),
                        command_bytes=endpoint.target.journal.command_bytes(
                            event["event_id"], read_authorized=True
                        ),
                    )
                    expected.add(event["event_id"])
            head_cursor = None
            found = set()
            while True:
                query = self.meter.rpc(
                    self.principal,
                    owner["id"],
                    "workflow.journal.list",
                    {"owner": owner, "cursor": head_cursor},
                )
                page = delivery.heads(query, principal=self.principal)
                page = self.meter.message(owner["id"], self.principal, page, category="discovery")
                validate("workflow-journal.schema.json", page, "Page")
                repeated_query = self.meter.rpc(
                    self.principal, owner["id"], "workflow.journal.list", query
                )
                repeated = self.meter.message(
                    owner["id"],
                    self.principal,
                    delivery.heads(repeated_query, principal=self.principal),
                    category="discovery",
                )
                require(repeated == page, "head page retry changed its stable extent")
                self.meter.values["discovery_pages"] += 1
                for head in page["items"]:
                    workflow_id = head["record"]["resource"]["id"]
                    cursor = None
                    while True:
                        request = self.meter.rpc(
                            self.principal,
                            owner["id"],
                            "workflow.journal.events",
                            {"owner": owner, "workflow_id": workflow_id, "cursor": cursor},
                        )
                        events = self.meter.message(
                            owner["id"],
                            self.principal,
                            delivery.events(request, principal=self.principal),
                            category="discovery",
                        )
                        validate("workflow-journal.schema.json", events, "Page")
                        retry_request = self.meter.rpc(
                            self.principal, owner["id"], "workflow.journal.events", request
                        )
                        retry = self.meter.message(
                            owner["id"],
                            self.principal,
                            delivery.events(retry_request, principal=self.principal),
                            category="discovery",
                        )
                        require(retry == events, "event page retry changed its stable extent")
                        self.meter.values["discovery_pages"] += 1
                        for reference in events["items"]:
                            identifier = reference["record"]["id"]
                            require(
                                identifier not in found,
                                "discovery duplicated a retained journal event",
                            )
                            record = routes[workflow_id].read(identifier, principal=self.principal)
                            require(
                                record["id"] == identifier and record["workflow_id"] == workflow_id,
                                "discovery changed typed record scope",
                            )
                            lookup = self.meter.rpc(
                                self.principal,
                                owner["id"],
                                "workflow.journal.input",
                                {
                                    "owner": owner,
                                    "workflow_id": workflow_id,
                                    "record_id": identifier,
                                },
                            )
                            retained_input = self.meter.message(
                                owner["id"],
                                self.principal,
                                delivery.input(lookup, principal=self.principal),
                                category="discovery",
                            )
                            require(
                                retained_input["acceptance"] == reference
                                and retained_input["command_id"] == identifier,
                                "input discovery changed signed acceptance",
                            )
                            handle = retained_input["input"]
                            parts, offset = [], 0
                            while offset < handle["size"]:
                                request = self.meter.rpc(
                                    self.principal,
                                    owner["id"],
                                    "content.get",
                                    {"handle": handle, "offset": offset, "length": CHUNK_BYTES},
                                )
                                chunk = delivery.read_input(
                                    request["handle"],
                                    principal=self.principal,
                                    offset=request["offset"],
                                    length=request["length"],
                                )
                                chunk = self.meter.message(
                                    owner["id"], self.principal, chunk, category="discovery"
                                )
                                part = validate_content_chunk(
                                    chunk, handle, offset=offset, length=CHUNK_BYTES
                                )
                                require(bool(part), "retained input discovery made no progress")
                                parts.append(part)
                                offset += len(part)
                            encoded = b"".join(parts)
                            command = strict_json(encoded, max_bytes=len(encoded))
                            require(
                                len(encoded) == handle["size"]
                                and "sha256:" + hashlib.sha256(encoded).hexdigest()
                                == handle["digest"]
                                == record["body"]["command_digest"]
                                and command["id"] == identifier
                                and command["workflow_id"] == workflow_id,
                                "discovery changed accepted original command bytes",
                            )
                            self.meter.values["discovered_input_bytes"] += len(encoded)
                            found.add(identifier)
                        cursor = events["next_cursor"]
                        if cursor is None:
                            break
                head_cursor = page["next_cursor"]
                if head_cursor is None:
                    break
            require(found == expected, "fresh discovery omitted retained workflow history")
            discovered += len(found)
        self.meter.values["discovered_journal_records"] += discovered
        return discovered

    def close(self):
        for endpoint in getattr(self, "successor_endpoints", []):
            endpoint.close()
        self.gate.close()
        for member in self.members:
            member.close()
        for native in self.native:
            native.close()


def execute_workflow(root, workload, *, regression=None, meter=None):
    """Measure the complete run from empty disk through protected successor custody."""
    selected = meter or WorkMeter()
    extent = workload.extent()
    with selected.account():
        run = WorkflowRun(root, workload, selected)
        try:
            run.prepare()
            if regression == "replicated-proposal":
                data = canonical(run.manifest)
                for actor in run.native:
                    selected.stage(
                        DRIVER,
                        actor.owner,
                        run.manifest["workflow_id"],
                        "regression-proposal-" + actor.owner["id"],
                        data,
                        actor.root / "duplicated-full-proposal",
                        purpose="content",
                        category="manifest",
                    )
            for phase in PHASES["host-drain"][1:]:
                _, votes, _, _ = run.round(phase)
                if regression == "all-owner-votes":
                    for actor in run.native:
                        for vote in votes:
                            selected.message(
                                run.gate_owner["id"],
                                actor.owner["id"],
                                vote,
                                category="phase-evidence",
                            )
                if phase == "host-effect":
                    run.children()
            completed = run.assert_complete()
            run.transfer()
            run.recover()
        finally:
            run.close()
        # No target, native actor, reservation, journal index or delivery cache
        # crosses this boundary. Static keys and approvals are recreated inside
        # WorkflowRun; accepted facts come exclusively from protected disk files.
        del run
        restored = WorkflowRun(root, workload, selected, restore=True)
        try:
            require(restored.assert_complete() == completed, "cold restore lost completed extent")
            restored.initialize_successor()
            require(restored.discover() > 0, "cold recovery discovery returned no retained work")
            for member in restored.members:
                record = member.target.snapshot(principal=NEXT_DRIVER)
                require(
                    member.read(record["head"], principal=NEXT_DRIVER)
                    == member.target.record(record["head"], principal=NEXT_DRIVER),
                    "cold indexed reply changed",
                )
        finally:
            restored.close()
        selected.retained(root)
    return {
        "extent": extent,
        "completed_owners": workload.owners,
        "completed_children": completed,
        "cold_restores": selected.values["cold_restores"],
        "lost_reply_replays": selected.values["lost_reply_replays"],
        "metrics": dict(selected.values),
    }
