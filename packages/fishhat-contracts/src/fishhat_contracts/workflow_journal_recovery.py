"""Owner-local transfer and positive successor recovery for partitioned journals.

The gate retains each global closure once. Members receive only a common signed
decision and their own retained projection. Protected native callbacks establish
retirement, cessation, material custody and exclusive successor reservations;
neither a missing event nor a caller-supplied Boolean establishes those facts.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .bounds import Bounds, bounds
from .handoffs import schema_identity, validate_result_payload
from .history import validate_owner_custody
from .operations import validate_operation_plan
from .validation import ContractError, canonical, digest, validate
from .witness import verify as verify_witness
from .workflow_bindings import _key
from .workflow_journal import (
    GateEnrollment,
    JournalStore,
    KeyRing,
    _identity,
    _JournalTarget,
    _KeyOverlay,
    _now,
    _verify_plan,
    verify_journal_record,
    verify_journal_signature,
)
from .workflow_recovery import _evidence, _recovered_child
from .workflows import (
    bound_plan,
    child_action,
    proposal_children,
    validate_completed_binding,
    validate_workflow_proposal,
)

JSON = dict[str, Any]

if TYPE_CHECKING:
    from .workflow_gate_recovery import GateRecoveryEnrollment


def _bounds(name: str) -> Bounds:
    return Bounds(
        id="workflow.journal-recovery." + name,
        work="O(B + N + E + H + R) complete transfer/recovery with one gate closure and exact local projections; indexed replay and append-only state",
        extent="Every original owner, child disposition, retained outcome and successor slot; no collection limit",
        limits=(),
        capacity=(
            "Unavailable authoritative custody refuses new work without erasing local outcomes",
        ),
        proofs=(
            "tests/test_workflow_journal.py::test_complete_workflow_survives_disk_restart_and_lost_replies",
        ),
        linear_proofs=(
            "tests/test_workflow_journal_growth.py::test_complete_multi_owner_workflow_is_linear",
        ),
    )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _fields(value: JSON, names: set[str]) -> None:
    _require(isinstance(value, dict) and value.keys() == names, "journal recovery fields changed")


def _is_gate(target: Any) -> bool:
    return hasattr(target, "_members")


def _body(target: Any, record: JSON, kind: str, owner: JSON | None = None) -> JSON:
    authority = getattr(target, "_recovery_gate_authority", None)
    gate = owner == target.header["gate_owner"]
    if gate and authority is not None:
        owner = authority["owner"]
    target._verify(record, owner)
    body = record["body"]
    _require(
        body.get("type") == kind and body.get("header_digest") == target.header_digest,
        "journal recovery signed subject changed",
    )
    if gate:
        expected_key = target.header["gate_key_id"] if authority is None else authority["key_id"]
        _require(record["key_id"] == expected_key, "journal gate key changed")
    return {key: value for key, value in body.items() if key != "command_digest"}


def _transfer(target: Any) -> JSON:
    state = target._recovery_state.get("transfer")
    _require(isinstance(state, dict), "workflow transfer is not retained")
    assert isinstance(state, dict)
    return state


def _recovery(target: Any) -> JSON:
    state = target._recovery_state.get("recovery")
    _require(isinstance(state, dict), "workflow recovery is not retained")
    assert isinstance(state, dict)
    return state


def _same_transfer(body: JSON, state: JSON) -> None:
    _require(
        body.get("transfer") == state["proposal"]["body"]["transfer"], "workflow transfer changed"
    )


def _same_recovery(body: JSON, state: JSON) -> None:
    _require(body.get("recovery") == state["recovery"], "workflow successor reservation changed")


def _partition(
    target: Any,
    successor: JSON,
    mapping: list[JSON],
    recovery: JSON,
    owners: Mapping[bytes, JSON],
    custody: Mapping[bytes, JSON],
) -> dict[bytes, JSON]:
    """Build all local projections in one pass; no receiver scans the manifest."""
    result: dict[bytes, JSON] = {}
    current: dict[bytes, bytes] = {}
    logical: dict[tuple[str, str], bytes] = {}
    original_content: dict[bytes, set[bytes]] = {}
    for member, original in target._projections.items():
        owner = owners.get(member, original["owner"])
        current[canonical(owner)] = member
        logical_identity = (owner["tool"], owner["id"])
        _require(logical_identity not in logical, "recovery aliases a logical native owner")
        logical[logical_identity] = member
        original_content[member] = {canonical(handle) for handle in original["content"]}
        result[member] = {
            "type": "recovery-projection",
            "header_digest": target.header_digest,
            "recovery": recovery,
            "owner": owner,
            "origin_owner": original["owner"],
            "custody": custody.get(member),
            "origin_projection_digest": target._projection_digests[member],
            "origin_participants": original["participants"],
            "origin_content": original["content"],
            "participants": [],
            "content": [],
            "dependencies": [],
            "mapping": [],
        }
    for participant in successor["participants"]:
        selected = canonical(participant["owner"])
        _require(selected in current, "successor changed an independently enrolled owner epoch")
        member = current[selected]
        result[member]["participants"].append(participant)
        for binding in participant["requests"]:
            intent = binding.get("intent", {})
            for name in ("predecessor", "issuer", "publication"):
                dependency = intent.get(name)
                if dependency is not None and dependency["owner"] != participant["owner"]:
                    result[member]["dependencies"].append(dependency)
    for content in successor["content"]:
        member = canonical(content["owner"])
        if member not in result:
            if member in current:
                member = current[member]
            else:
                logical_identity = (content["owner"]["tool"], content["owner"]["id"])
                _require(logical_identity in logical, "successor material has no native owner")
                member = logical[logical_identity]
                _require(
                    canonical(content) in original_content[member],
                    "successor selected unrelated historical material",
                )
        result[member]["content"].append(content)
    for item in mapping:
        result[canonical(item["origin"]["owner"])]["mapping"].append(item)
    _require(
        all(value["participants"] for value in result.values()), "successor omitted a native owner"
    )
    return result


def _local_items(projection: JSON) -> dict[bytes, JSON]:
    successors = proposal_children({"participants": projection["participants"]})
    projection_digest = digest(projection)
    return {
        _key(item["origin"]): {
            "projection": projection,
            "projection_digest": projection_digest,
            "participant": successors[_key(item["successor"])][0],
            "replacement": successors[_key(item["successor"])][1],
            "successor": item["successor"],
            "fact": None,
            "record_id": None,
        }
        for item in projection["mapping"]
    }


def _custody_digest(projections: Mapping[bytes, JSON]) -> str:
    return digest(
        [
            {name: value[name] for name in ("origin_owner", "owner", "custody")}
            for value in projections.values()
        ]
    )


@dataclass(frozen=True)
class RecoveryContext:
    """Independently supplied old-gate trust and retained positive retirement.

    This is protected constructor context, never a decoded command field. The
    signature's own owner/key spelling cannot select these independently enrolled
    values. Members additionally require their native exact reservation to remain
    retained when initializing or restoring the successor.
    """

    origin_gate_owner: JSON
    origin_gate_key_id: str
    origin_gate_public_key: Ed25519PublicKey
    certificate: JSON
    projection: JSON | None = None
    disposition: JSON | None = None
    historical_gate_keys: KeyRing | None = None


@dataclass(frozen=True)
class OriginRecoveryContext:
    """Qualified protected custody of one original member, including exact schema.

    The source is opened through its original owner/epoch and accepted schema.
    It is not an exported Python state tuple. The current native owner verifies
    restoration membership, permanent old-epoch fencing and material retention
    independently before supplying this context or allowing any recovery fact.
    """

    source: JournalStore
    source_schema: JSON
    signed_projection: JSON
    enrollment: GateEnrollment
    custody: JSON
    source_keys: KeyRing


class WorkflowRecoveryMember(_JournalTarget):
    """Current-epoch recovery authority over exact old local journal custody.

    Original Plans, Operations and signatures retain their original owner and
    epoch. This target signs only new recovery facts under current authority and
    can never admit a child, bind a Plan or revive old workflow execution.
    """

    @bounds(
        Bounds(
            id="workflow.journal-recovery.member-restore",
            work="O(L + H) one original owner-local projection and one verified replay of each original and current retained event",
            extent="All original local accepted Plans, outcomes and recovery tombstones; no history count limit",
            limits=(),
            capacity=(
                "Missing qualified original custody blocks recovery and never becomes empty state",
            ),
            proofs=(
                "tests/test_workflow_journal_epoch.py::test_restored_epoch_requires_exact_custody_and_preserves_original_bytes",
            ),
            linear_proofs=(
                "tests/test_workflow_journal_epoch.py::test_restored_epoch_recovery_is_linear",
            ),
        )
    )
    def __init__(
        self,
        origin: OriginRecoveryContext,
        *,
        owner: JSON,
        key_id: str,
        private_key: Ed25519PrivateKey,
        native: Any,
        operation_keys: KeyRing,
        journal: JournalStore,
        principal: str,
        extension: JournalRecovery,
        clock: Callable[[], str] = _now,
        command: JSON | None = None,
    ) -> None:
        self.native, self.enrollment = native, origin.enrollment
        keys: KeyRing = _KeyOverlay(
            {
                (
                    canonical(origin.enrollment.gate_owner),
                    origin.enrollment.gate_key_id,
                ): origin.enrollment.gate_public_key,
                (canonical(owner), key_id): private_key.public_key(),
            },
            _KeyOverlay(operation_keys, origin.source_keys),
        )
        self._setup(
            owner=owner,
            key_id=key_id,
            private_key=private_key,
            keys=keys,
            journal=journal,
            clock=clock,
            extension=extension,
        )
        self.workflow_id = origin.enrollment.workflow_id
        projection_selection = {"projection_digest": digest(origin.signed_projection)}
        command = command or self._command(
            "member.recover",
            _identity("recovery-member-init", self.workflow_id, owner),
            projection_selection,
        )
        _require(
            command["action"] == "member.recover"
            and command["workflow_id"] == self.workflow_id
            and command["payload"] == projection_selection,
            "restored member initialization changed exact caller command",
        )
        identity = origin.source_schema
        _require(
            identity["uri"]
            == "https://fishhat.invalid/contracts/workflow-journal.schema.json#/$defs/JournalRecord",
            "restored workflow source schema root changed",
        )
        historical = identity != schema_identity(identity["uri"])
        selected = (identity["uri"], identity["digest"])
        if historical:
            _require(
                extension.retained_readers is not None
                and selected in extension.retained_readers
                and extension.recovery_readers is not None
                and selected in extension.recovery_readers,
                "restored workflow schema lacks independently qualified recovery reader",
            )
        self._source_record(
            origin.signed_projection, origin.enrollment.gate_owner, extension, historical, selected
        )
        self.projection = {
            key: value
            for key, value in origin.signed_projection["body"].items()
            if key != "command_digest"
        }
        self.signed_projection = copy.deepcopy(origin.signed_projection)
        self.projection_digest = digest(self.projection)
        self.header = copy.deepcopy(self.projection["header"])
        self.header_digest = digest(self.header)
        self.driver_principal, self.driver_term = (
            self.header["driver_principal"],
            self.header["driver_term"],
        )
        self.phase = "recovery"
        self._authorize(principal, "read")
        original_owner = origin.enrollment.member_owner
        _require(
            self.projection.get("type") == "projection"
            and self.projection["owner"] == original_owner
            and origin.source.owner == original_owner
            and self.projection_digest == origin.enrollment.projection_digest
            and self.header["proposal_digest"] == origin.enrollment.proposal_digest
            and self.header["workflow_id"] == self.workflow_id
            and self.header["gate_owner"] == origin.enrollment.gate_owner
            and self.header["gate_key_id"] == origin.enrollment.gate_key_id,
            "restored workflow original enrolled projection changed",
        )
        _require(
            extension._current_owner(original_owner) == owner
            and extension.verified_custody.get(canonical(original_owner)) == origin.custody,
            "restored workflow custody was not independently approved",
        )
        validate_owner_custody(origin.custody, expected_custodian=owner)
        _require(
            origin.custody["origin"] == original_owner
            and getattr(origin.source, "schema", None) == origin.source_schema,
            "restored workflow source identity changed",
        )
        context: JSON = {
            "owner": owner,
            "origin": original_owner,
            "custody": origin.custody,
            "source_head": origin.source.head,
            "source_schema": identity,
            "projection_digest": self.projection_digest,
            "workflow_id": self.workflow_id,
        }
        native.restore_recovery(context)
        self.children = proposal_children({"participants": self.projection["participants"]})
        self.ready = {
            key: binding
            for key, (_, binding) in self.children.items()
            if "plan" in binding or "completed" in binding
        }
        self.outcomes: dict[bytes, JSON] = {
            key: binding["completed"]["operation"]
            for key, binding in self.ready.items()
            if "completed" in binding
        }
        self._admissions: dict[bytes, JSON] = {}
        self._preparation: JSON | None = None
        found = False
        with origin.source.guard(context["source_head"]):
            for event in origin.source.iter_events(read_authorized=True):
                request, record = event["request"], event["outcome"]
                self._source_record(record, original_owner, extension, historical, selected)
                _require(
                    request["workflow_id"] == self.workflow_id
                    and record["id"] == request["id"]
                    and record["body"].get("command_digest") == digest(request),
                    "restored source event commitment changed",
                )
                if not found:
                    _require(
                        request["action"] == "member.join"
                        and request["payload"].get("projection") == origin.signed_projection,
                        "restored source lacks its exact original initialization",
                    )
                    found = True
                self._source_event(request, record, extension)
        _require(found, "restored original journal is empty")
        self._known_outcomes = dict(self.outcomes)
        self._initialize(
            command,
            self._outcome(
                command,
                {
                    "type": "recovery-initialized",
                    "header_digest": self.header_digest,
                    "projection_digest": self.projection_digest,
                    "custody_digest": digest(context),
                },
            ),
            principal,
        )

    def _source_record(
        self,
        record: JSON,
        owner: JSON,
        extension: JournalRecovery,
        historical: bool,
        selected: tuple[str, str],
    ) -> None:
        if not historical:
            verify_journal_record(
                record, self.keys, expected_owner=owner, expected_workflow_id=self.workflow_id
            )
            return
        assert extension.retained_readers is not None and extension.recovery_readers is not None
        original = canonical(record)
        extension.retained_readers[selected](record)
        extension.recovery_readers[selected](record)
        _require(canonical(record) == original, "historical recovery reader rewrote original bytes")
        verify_journal_signature(
            record, self.keys, expected_owner=owner, expected_workflow_id=self.workflow_id
        )

    def _source_event(self, command: JSON, record: JSON, extension: JournalRecovery) -> None:
        action, payload = command["action"], command["payload"]
        if action == "prepare":
            self._preparation = record
        elif action == "bind":
            request = payload["binding"]["body"]["request"]
            key = _key(request["child"])
            _require(key in self.children, "restored binding changed original local slot")
            self.ready[key] = request["binding"]
        elif action in {"admit", "admit.renew"}:
            key = _key(payload["child"])
            _require(key in self.ready, "restored admission omitted original Plan")
            self._admissions[key] = record
        elif action == "complete":
            operation = payload["operation"]
            key = _key({"owner": operation["owner"], "request_id": operation["request_id"]})
            _require(
                key in self._admissions and key in self.ready,
                "restored outcome lacks original admission",
            )
            extension._operation(self, operation, bound_plan(self.ready[key]), self.workflow_id)
            self.outcomes[key] = operation
        elif action == "recover.gate_approve":
            self._recovery_gate_authority = copy.deepcopy(record["body"]["authority"])
            self._recovery_gate_approval = copy.deepcopy(record)
        elif action in {
            "member.join",
            "agreement",
            "vote",
            "apply",
            "pause",
            "resume",
            "cancel",
        } or action.startswith(("transfer.", "recover.")):
            return
        else:
            raise ContractError("restored original event has no qualified recovery semantics")

    def _authorize(self, principal: str, action: str) -> None:
        self.native.authorize(
            principal,
            action,
            {
                "owner": self.owner,
                "workflow_id": self.workflow_id,
                "header_digest": self.header_digest,
                "projection_digest": self.projection_digest,
                "grant_id": self.enrollment.grant_id,
                "driver_principal": self.driver_principal,
                "driver_term": self.driver_term,
            },
        )

    def _accept(self, command: JSON, principal: str) -> JSON:
        _require(
            command["action"].startswith("recover."),
            "restored epoch permits recovery only, never original admission",
        )
        assert self.extension is not None
        return self.extension.outcome(self, command, principal)

    def _apply_event(self, command: JSON, outcome: JSON) -> None:
        if command["action"] == "member.recover":
            return
        _require(
            command["action"].startswith("recover."),
            "restored epoch retained forbidden original admission",
        )
        assert self.extension is not None
        self.extension.apply(self, command, outcome)


class JournalRecovery:
    """Pure event reducer plus protected native retirement/verification callbacks."""

    def __init__(
        self,
        *,
        current_owners: Mapping[bytes, JSON] | None = None,
        verified_custody: Mapping[bytes, JSON] | None = None,
        retained_readers: Mapping[tuple[str, str], Callable[[JSON], None]] | None = None,
        recovery_readers: Mapping[tuple[str, str], Callable[[JSON], None]] | None = None,
        gate_recovery_enrollments: Mapping[str, GateRecoveryEnrollment] | None = None,
    ) -> None:
        # Independently installed indexes may cover many unrelated workflows.
        # Select exact entries; neither local preparation nor restoration copies
        # or traverses the owner's entire trust/custody configuration.
        self.current_owners = current_owners if current_owners is not None else {}
        self.verified_custody = verified_custody if verified_custody is not None else {}
        self.retained_readers, self.recovery_readers = retained_readers, recovery_readers
        self.gate_recovery_enrollments = (
            gate_recovery_enrollments if gate_recovery_enrollments is not None else {}
        )

    def _current_owner(self, origin: JSON) -> JSON:
        owner = self.current_owners.get(canonical(origin), origin)
        _require(
            all(owner[key] == origin[key] for key in ("tool", "id")),
            "recovery changed logical owner identity",
        )
        if owner != origin:
            custody = self.verified_custody.get(canonical(origin))
            _require(
                custody is not None,
                "changed epoch lacks independently verified restoration custody",
            )
            assert custody is not None
            validate_owner_custody(custody, expected_custodian=owner)
            _require(custody["origin"] == origin, "recovery changed historical owner custody")
        return dict(owner)

    @bounds(_bounds("outcome"))
    def outcome(self, target: Any, command: JSON, principal: str) -> JSON:
        action = command["action"]
        if action == "recover.gate_approve":
            from .workflow_gate_recovery import approve_recovery_gate

            _require(not _is_gate(target), "gate reapproval belongs to each native member")
            authority = command["payload"]["initialization"]["body"]["authority"]
            selected = self.gate_recovery_enrollments.get(digest(authority))
            _require(selected is not None, "recovery gate is not independently enrolled")
            assert selected is not None
            body = approve_recovery_gate(target, command, selected)
        elif action.startswith("transfer."):
            body = self._transfer_outcome(target, command, principal)
        elif action.startswith("recover."):
            body = self._recovery_outcome(target, command, principal)
        else:
            raise ContractError("unsupported workflow journal extension command")
        return dict(target._outcome(command, body))

    def _transfer_outcome(self, target: Any, command: JSON, principal: str) -> JSON:
        action, payload = command["action"], command["payload"]
        common = {"header_digest": target.header_digest}
        gate = _is_gate(target)
        if action == "transfer.propose":
            _require(gate, "driver transfer proposal belongs to the gate")
            _fields(payload, {"new_driver"})
            validate("common.schema.json", payload["new_driver"], "Id")
            old = target._recovery_state.get("transfer")
            _require(
                old is None or old.get("active") is True, "another driver transfer is retained"
            )
            _require(not target._recovery_state.get("retired"), "retired workflow cannot transfer")
            _require(
                payload["new_driver"] != target.driver_principal,
                "driver transfer must change principal",
            )
            target._authorize(payload["new_driver"], "drive")
            transfer = {
                "id": command["id"],
                "from_term": target.driver_term,
                "to_term": target.driver_term + 1,
                "from_driver": target.driver_principal,
                "to_driver": payload["new_driver"],
            }
            return {**common, "type": "transfer-proposal", "transfer": transfer}
        if action == "transfer.freeze":
            _require(not gate, "driver freeze belongs to a native member")
            _fields(payload, {"proposal"})
            proposal = _body(
                target, payload["proposal"], "transfer-proposal", target.header["gate_owner"]
            )
            transfer = proposal["transfer"]
            old = target._recovery_state.get("transfer")
            _require(old is None or old.get("active") is True, "another local transfer is retained")
            _require(not target._recovery_state.get("retired"), "retired member cannot transfer")
            _require(
                transfer["from_term"] == target.driver_term
                and transfer["to_term"] == target.driver_term + 1
                and transfer["from_driver"] == target.driver_principal,
                "driver freeze predecessor changed",
            )
            return {
                **common,
                "type": "transfer-freeze",
                "transfer": transfer,
                "projection_digest": target.projection_digest,
                "member_generation": target.generation + 1,
                "phase": target.phase,
            }
        state = _transfer(target)
        transfer = state["proposal"]["body"]["transfer"]
        if action == "transfer.collect_freeze":
            _require(gate and state.get("certificate") is None, "transfer freeze closure is closed")
            _fields(payload, {"freeze"})
            record = payload["freeze"]
            body = _body(target, record, "transfer-freeze")
            member = canonical(record["owner"])
            _same_transfer(body, state)
            _require(
                member in target._members and member not in state["freezes"],
                "transfer freeze issuer missing or duplicated",
            )
            _require(
                body.get("projection_digest") == target._projection_digests[member],
                "transfer freeze changed local projection",
            )
            return {
                **common,
                "type": "transfer-freeze-accepted",
                "transfer": transfer,
                "member": record["owner"],
                "freeze_digest": digest(record),
            }
        if action == "transfer.commit":
            _require(gate, "transfer term certificate belongs to the gate")
            _fields(payload, set())
            _require(
                state.get("certificate") is None and len(state["freezes"]) == len(target._members),
                "transfer freeze closure incomplete or committed",
            )
            return {
                **common,
                "type": "transfer-certificate",
                "transfer": transfer,
                "freeze_closure_digest": state["freeze_closure_digest"],
                "owner_count": len(target._members),
            }
        if action == "transfer.install":
            _require(
                not gate and state.get("installation") is None,
                "local transfer is already installed",
            )
            _fields(payload, {"certificate"})
            body = _body(
                target, payload["certificate"], "transfer-certificate", target.header["gate_owner"]
            )
            _same_transfer(body, state)
            _require(
                state.get("freeze") is not None
                and body["owner_count"] == target.header["owner_count"],
                "transfer lacks exact local freeze or full owner closure",
            )
            target._authorize(transfer["to_driver"], "drive")
            return {
                **common,
                "type": "transfer-installation",
                "transfer": transfer,
                "projection_digest": target.projection_digest,
                "freeze_digest": digest(state["freeze"]),
                "certificate_digest": digest(payload["certificate"]),
            }
        if action == "transfer.collect_install":
            _require(
                gate and state.get("certificate") is not None and not state.get("active"),
                "transfer installation closure is unavailable",
            )
            _fields(payload, {"installation"})
            record = payload["installation"]
            body = _body(target, record, "transfer-installation")
            _same_transfer(body, state)
            member = canonical(record["owner"])
            _require(
                member in state["freezes"] and member not in state["installations"],
                "transfer installation issuer missing or duplicated",
            )
            _require(
                body.get("projection_digest") == target._projection_digests[member]
                and body.get("freeze_digest") == digest(state["freezes"][member])
                and body.get("certificate_digest") == digest(state["certificate"]),
                "transfer installation changed frozen term",
            )
            return {
                **common,
                "type": "transfer-installation-accepted",
                "transfer": transfer,
                "member": record["owner"],
                "installation_digest": digest(record),
            }
        if action == "transfer.activate":
            _require(gate, "transfer activation belongs to the gate")
            _fields(payload, set())
            _require(
                not state.get("active") and len(state["installations"]) == len(target._members),
                "transfer installation closure incomplete or active",
            )
            return {
                **common,
                "type": "transfer-activation",
                "transfer": transfer,
                "certificate_digest": digest(state["certificate"]),
                "installation_closure_digest": state["installation_closure_digest"],
                "owner_count": len(target._members),
            }
        if action == "transfer.observe":
            _require(
                not gate and not state.get("active"), "member transfer activation already retained"
            )
            _fields(payload, {"activation"})
            body = _body(
                target, payload["activation"], "transfer-activation", target.header["gate_owner"]
            )
            _same_transfer(body, state)
            _require(
                state.get("installation") is not None
                and body.get("certificate_digest") == digest(state["certificate"])
                and body.get("owner_count") == target.header["owner_count"],
                "transfer activation lacks local installation or complete closure",
            )
            target._authorize(transfer["to_driver"], "drive")
            return {
                **common,
                "type": "transfer-activated",
                "transfer": transfer,
                "activation_digest": digest(payload["activation"]),
                "installation_digest": digest(state["installation"]),
            }
        raise ContractError("unsupported workflow transfer command")

    def _recovery_outcome(self, target: Any, command: JSON, principal: str) -> JSON:
        action, payload = command["action"], command["payload"]
        common = {"header_digest": target.header_digest}
        gate = _is_gate(target)
        if action == "recover.abandon_recertify":
            _require(
                gate and getattr(target, "_gate_recovery_certificate", None) is not None,
                "terminal abandonment recertification requires an approved recovery gate",
            )
            _fields(payload, {"successor_workflow_id"})
            previous = target._recovery_state.get("abandonment_certificates", {}).get(
                payload["successor_workflow_id"]
            )
            _require(
                previous is not None and previous["owner"] != target.owner,
                "terminal abandonment certificate missing or already current",
            )
            assert previous is not None
            body = previous["body"]
            return {
                **common,
                "type": "recovery-abandon-certificate",
                "recovery": body["recovery"],
                "abandon_id": body["abandon_id"],
                "owner_count": body["owner_count"],
                "closure_digest": body["closure_digest"],
                "supersedes": {"id": previous["id"], "digest": digest(previous)},
            }
        if action == "recover.propose":
            _require(gate, "successor manifest belongs to the gate")
            _fields(payload, {"successor", "mapping"})
            _require(
                target._recovery_state.get("recovery") is None,
                "origin already reserved to a successor",
            )
            successor = payload["successor"]
            validate_workflow_proposal(
                successor, recovery=True, recovery_readers=self.recovery_readers
            )
            _require(
                successor["workflow_id"] != target.workflow_id
                and successor["workflow_id"] not in target._recovery_state.get("abandoned", {})
                and successor["type"] == target.header["procedure"],
                "successor workflow or installed procedure changed",
            )
            target._authorize(successor["initial_driver"]["principal"], "drive")
            self._mapping(target, successor, payload["mapping"])
            recovery = {
                "id": command["id"],
                "origin_workflow_id": target.workflow_id,
                "origin_proposal_digest": target.header["proposal_digest"],
                "successor_workflow_id": successor["workflow_id"],
                "successor_proposal_digest": digest(successor),
                "successor_driver": successor["initial_driver"]["principal"],
                "mapping_digest": digest(payload["mapping"]),
            }
            projections = _partition(
                target,
                successor,
                payload["mapping"],
                recovery,
                self.current_owners,
                self.verified_custody,
            )
            return {
                **common,
                "type": "recovery-proposal",
                "recovery": recovery,
                "custody_digest": _custody_digest(projections),
            }
        if action == "recover.inspect":
            _require(not gate, "recovery retirement belongs to the native member")
            _fields(payload, {"projection"})
            body = _body(
                target, payload["projection"], "recovery-projection", target.header["gate_owner"]
            )
            _require(
                target._recovery_state.get("recovery") is None, "local origin is already reserved"
            )
            _require(
                body.get("owner") == target.owner
                and body.get("origin_owner") == target.projection["owner"]
                and body.get("custody")
                == self.verified_custody.get(canonical(target.projection["owner"]))
                and self._current_owner(target.projection["owner"]) == target.owner
                and body.get("origin_projection_digest") == target.projection_digest
                and body.get("origin_participants") == target.projection["participants"]
                and body.get("origin_content") == target.projection["content"],
                "recovery changed local original projection",
            )
            target._authorize(body["recovery"]["successor_driver"], "drive")
            # This protected callback durably fences/reserves before returning.
            # Journal failure cannot reopen admission in the native authority.
            facts = target.native.recovery_disposition(body)
            self._facts(target, body, facts, native=True)
            return {
                **common,
                "type": "recovery-disposition",
                "recovery": body["recovery"],
                "projection_digest": digest(body),
                "facts": facts,
            }
        state = _recovery(target)
        recovery = state["recovery"]
        if action.startswith("recover.abandon") or action in {
            "recover.collect_abandon",
            "recover.observe_abandon",
        }:
            return self._abandonment_outcome(target, command, state)
        if action == "recover.projection":
            _require(gate, "recovery projection belongs to the gate")
            _fields(payload, {"owner"})
            issuer = canonical(payload["owner"])
            _require(issuer in state["issuer_origins"], "recovery projection owner changed")
            member = state["issuer_origins"][issuer]
            return dict(state["projections"][member])
        if action == "recover.collect":
            _require(
                gate and state.get("certificate") is None, "recovery disposition closure is closed"
            )
            _fields(payload, {"disposition"})
            record = payload["disposition"]
            body = _body(target, record, "recovery-disposition")
            _same_recovery(body, state)
            issuer = canonical(record["owner"])
            _require(
                issuer in state["issuer_origins"], "recovery disposition current custodian changed"
            )
            member = state["issuer_origins"][issuer]
            _require(
                member in state["projections"] and member not in state["dispositions"],
                "recovery disposition issuer missing or duplicated",
            )
            projection = state["projections"][member]
            _require(
                body.get("projection_digest") == digest(projection),
                "recovery disposition projection changed",
            )
            self._facts(target, projection, body["facts"], native=False)
            blocked = sum(
                item["kind"] == "unknown" or not item["native_stopped"]
                for item in body["facts"]["children"]
            )
            return {
                **common,
                "type": "recovery-disposition-accepted",
                "recovery": recovery,
                "member": record["owner"],
                "disposition_digest": digest(record),
                "blocked": blocked,
            }
        if action == "recover.commit":
            _require(gate, "recovery closure belongs to the gate")
            _fields(payload, set())
            previous = state.get("certificate")
            recertify = (
                previous is not None
                and previous["owner"] != target.owner
                and getattr(target, "_gate_recovery_certificate", None) is not None
            )
            _require(
                (previous is None or recertify)
                and state.get("abandonment") is None
                and len(state["dispositions"]) == len(target._members),
                "recovery disposition closure incomplete or committed",
            )
            _require(
                state["blocked"] == 0, "unknown or active original work blocks successor admission"
            )
            return {
                **common,
                "type": "recovery-certificate",
                "recovery": recovery,
                "owner_count": len(target._members),
                "disposition_closure_digest": state["disposition_closure_digest"],
                "supersedes": (
                    None if previous is None else {"id": previous["id"], "digest": digest(previous)}
                ),
            }
        if action == "recover.reconcile":
            _require(
                not gate and state.get("certificate") is None, "local recovery is already committed"
            )
            _fields(payload, {"origin", "previous_disposition_id"})
            key = _key(payload["origin"])
            _require(key in state["items"], "recovery update changed original child")
            item = state["items"][key]
            previous = item["fact"]
            _require(
                previous["kind"] == "unknown"
                and payload["previous_disposition_id"] == item["record_id"],
                "only exact unresolved disposition can advance",
            )
            fact = target.native.reconcile_recovery(
                {
                    "recovery": recovery,
                    "owner": target.owner,
                    "origin": payload["origin"],
                    "successor": item["successor"],
                    "original_binding": target.ready[key],
                    "successor_binding": item["replacement"],
                    "previous": previous,
                    "previous_disposition_id": item["record_id"],
                }
            )
            self._update_fact(previous, fact)
            self._fact(
                target,
                item["projection"],
                fact,
                item["participant"],
                item["replacement"],
                native=True,
            )
            return {
                **common,
                "type": "recovery-update",
                "recovery": recovery,
                "origin": payload["origin"],
                "previous_disposition_id": item["record_id"],
                "previous_fact_digest": digest(previous),
                "projection_digest": item["projection_digest"],
                "fact": fact,
            }
        if action == "recover.collect_update":
            _require(gate and state.get("certificate") is None, "recovery update closure is closed")
            _fields(payload, {"update"})
            record = payload["update"]
            update = _body(target, record, "recovery-update")
            _same_recovery(update, state)
            key = _key(update["origin"])
            _require(key in state["items"], "recovery update changed original child")
            item = state["items"][key]
            _require(
                record["owner"] == item["projection"]["owner"]
                and item["fact"] is not None
                and update["previous_disposition_id"] == item["record_id"]
                and update["previous_fact_digest"] == digest(item["fact"])
                and update["projection_digest"] == item["projection_digest"],
                "recovery update changed issuer or exact predecessor",
            )
            self._update_fact(item["fact"], update["fact"])
            self._fact(
                target,
                item["projection"],
                update["fact"],
                item["participant"],
                item["replacement"],
                native=False,
            )
            return {
                **common,
                "type": "recovery-update-accepted",
                "recovery": recovery,
                "origin": update["origin"],
                "update_digest": digest(record),
            }
        if action == "recover.install":
            _require(not gate, "local recovery installation belongs to the member")
            _fields(payload, {"certificate"})
            body = _body(
                target, payload["certificate"], "recovery-certificate", target.header["gate_owner"]
            )
            _same_recovery(body, state)
            previous = state.get("certificate")
            if previous is not None:
                _require(
                    previous["owner"] != payload["certificate"]["owner"]
                    and body["supersedes"] is not None
                    and getattr(target, "_recovery_gate_authority", None) is not None
                    and body["owner_count"] == previous["body"]["owner_count"]
                    and body["disposition_closure_digest"]
                    == previous["body"]["disposition_closure_digest"],
                    "local successor certificate changed its committed reservation or closure",
                )
                # The current gate reconstructs the complete authoritative lineage
                # and signs its exact predecessor. A member may have missed an
                # intermediate delivery; its already committed reservation and
                # complete disposition closure must still be exactly unchanged.
            _require(
                body.get("owner_count") == target.header["owner_count"],
                "recovery owner closure changed",
            )
            selected = {
                key: value
                for key, value in state["projection"]["body"].items()
                if key != "command_digest"
            }
            facts = {
                **state["disposition"]["body"]["facts"],
                "children": [item["fact"] for item in state["items"].values()],
            }
            _require(
                all(
                    item["kind"] != "unknown" and item["native_stopped"]
                    for item in facts["children"]
                ),
                "unknown or active original work blocks local successor installation",
            )
            target.native.check_recovery(selected, facts, payload["certificate"])
            return {
                **common,
                "type": "recovery-installed",
                "recovery": recovery,
                "certificate_digest": digest(payload["certificate"]),
                "disposition_digest": digest(state["disposition"]),
                "projection_digest": digest(selected),
                "facts": facts,
            }
        raise ContractError("unsupported workflow recovery command")

    def _abandonment_outcome(self, target: Any, command: JSON, state: JSON) -> JSON:
        action, payload = command["action"], command["payload"]
        common = {"header_digest": target.header_digest, "recovery": state["recovery"]}
        _require(
            state.get("certificate") is None,
            "committed successor cannot use unused-reservation abandonment",
        )
        gate = _is_gate(target)
        if action == "recover.abandon_start":
            _require(
                gate and state.get("abandonment") is None,
                "successor abandonment is already started",
            )
            _fields(payload, set())
            return {**common, "type": "recovery-abandon-proposal", "abandon_id": command["id"]}
        if action == "recover.abandon":
            _require(
                not gate and state.get("abandonment") is None,
                "local successor abandonment already retained",
            )
            _fields(payload, {"proposal"})
            proposal = _body(
                target,
                payload["proposal"],
                "recovery-abandon-proposal",
                target.header["gate_owner"],
            )
            _same_recovery(proposal, state)
            projection = {
                key: value
                for key, value in state["projection"]["body"].items()
                if key != "command_digest"
            }
            facts = target.native.abandon_recovery(projection, proposal)
            self._abandonment_facts(facts, state["recovery"])
            return {
                **common,
                "type": "recovery-abandonment",
                "abandon_id": proposal["abandon_id"],
                "projection_digest": digest(projection),
                "facts": facts,
            }
        abandonment = state.get("abandonment")
        _require(isinstance(abandonment, dict), "successor abandonment was not durably started")
        assert isinstance(abandonment, dict)
        common["abandon_id"] = abandonment["proposal"]["body"]["abandon_id"]
        if action == "recover.collect_abandon":
            _require(gate, "abandonment closure belongs to the gate")
            _fields(payload, {"abandonment"})
            record = payload["abandonment"]
            body = _body(target, record, "recovery-abandonment")
            _same_recovery(body, state)
            issuer = canonical(record["owner"])
            _require(
                issuer in state["issuer_origins"], "abandonment issuer is not the current custodian"
            )
            origin = state["issuer_origins"][issuer]
            _require(
                origin not in abandonment["members"]
                and body["abandon_id"] == common["abandon_id"]
                and body["projection_digest"] == digest(state["projections"][origin]),
                "abandonment duplicated or changed native successor reservation",
            )
            self._abandonment_facts(body["facts"], state["recovery"])
            return {
                **common,
                "type": "recovery-abandonment-accepted",
                "member": record["owner"],
                "abandonment_digest": digest(record),
            }
        if action == "recover.abandon_commit":
            _require(gate, "abandonment certificate belongs to the gate")
            _fields(payload, set())
            _require(
                len(abandonment["members"]) == len(target._members),
                "complete positive successor abandonment closure required",
            )
            return {
                **common,
                "type": "recovery-abandon-certificate",
                "owner_count": len(target._members),
                "closure_digest": abandonment["closure_digest"],
                "supersedes": None,
            }
        if action == "recover.observe_abandon":
            _require(not gate, "local abandonment installation belongs to a member")
            _fields(payload, {"certificate"})
            body = _body(
                target,
                payload["certificate"],
                "recovery-abandon-certificate",
                target.header["gate_owner"],
            )
            _same_recovery(body, state)
            _require(
                body["abandon_id"] == common["abandon_id"]
                and body["owner_count"] == target.header["owner_count"],
                "local abandonment changed all-owner closure",
            )
            projection = {
                key: value
                for key, value in state["projection"]["body"].items()
                if key != "command_digest"
            }
            target.native.observe_abandonment(
                projection, abandonment["local"]["body"]["facts"], payload["certificate"]
            )
            return {
                **common,
                "type": "recovery-abandoned",
                "certificate_digest": digest(payload["certificate"]),
                "abandonment_digest": digest(abandonment["local"]),
            }
        raise ContractError("unsupported successor abandonment command")

    def _abandonment_facts(self, facts: JSON, recovery: JSON) -> None:
        _fields(
            facts,
            {
                "origin_workflow_id",
                "successor_workflow_id",
                "successor_proposal_digest",
                "unused",
                "successor_admission_closed",
                "native_stopped",
                "custody_digest",
            },
        )
        _require(
            all(
                facts[name] == recovery[name]
                for name in (
                    "origin_workflow_id",
                    "successor_workflow_id",
                    "successor_proposal_digest",
                )
            )
            and facts["unused"] is True
            and facts["successor_admission_closed"] is True
            and facts["native_stopped"] is True,
            "abandonment needs positive unused successor closure and native cessation",
        )
        validate("common.schema.json", facts["custody_digest"], "MaterialDigest")

    def _update_fact(self, previous: JSON, fact: JSON) -> None:
        _require(
            previous["kind"] == "unknown"
            and fact["kind"] == "recovered"
            and fact["origin"] == previous["origin"]
            and fact["operation"] == previous["operation"]
            and fact["operation_reference"] == previous["operation_reference"],
            "recovery update must preserve exact original uncertainty and add positive recovery",
        )

    def _mapping(self, target: Any, successor: JSON, mapping: list[JSON]) -> None:
        new = proposal_children(successor)
        owners = {key: self._current_owner(owner) for key, owner in target._members.items()}
        _require(
            len({canonical(owner) for owner in owners.values()}) == len(owners),
            "recovery current custodian aliases another origin",
        )
        old_seen: set[bytes] = set()
        new_seen: set[bytes] = set()
        mapped: dict[bytes, JSON] = {}
        _require(isinstance(mapping, list), "successor child mapping must be complete")
        for item in mapping:
            _fields(item, {"origin", "successor"})
            for reference in item.values():
                validate("workflow.schema.json", reference, "ChildReference")
            old_key, new_key = _key(item["origin"]), _key(item["successor"])
            _require(
                old_key in target.children
                and old_key not in old_seen
                and new_key in new
                and new_key not in new_seen
                and owners.get(canonical(item["origin"]["owner"])) == item["successor"]["owner"]
                and old_key != new_key
                and new_key not in target.children,
                "successor mapping changed original owner or request closure",
            )
            old_seen.add(old_key)
            new_seen.add(new_key)
            mapped[old_key] = item["successor"]
            old_participant, old_binding = target.children[old_key]
            new_participant, new_binding = new[new_key]
            _require(
                old_participant["resource"] == new_participant["resource"]
                and old_binding["phase"] == new_binding["phase"]
                and child_action(old_binding) == child_action(new_binding),
                "successor changed original native resource or installed phase",
            )
        _require(
            old_seen == target.children.keys() and new_seen == new.keys(),
            "successor mapping omitted a child",
        )
        expected_target = {
            role: (
                [mapped[_key(item)] for item in reference]
                if isinstance(reference, list)
                else mapped[_key(reference)]
            )
            for role, reference in target.proposal["target"].items()
            if target.header["procedure"] != "relocation" or role != "destination"
        }
        if target.header["procedure"] == "relocation":
            original = target.proposal["target"]["destination"]
            expected_target["destination"] = {
                "owner": owners[canonical(original["owner"])],
                "resource": original["resource"],
            }
        _require(
            successor["target"] == expected_target, "successor changed installed target lineage"
        )

    def _operation(self, target: Any, operation: JSON, plan: JSON, workflow_id: str | None) -> None:
        validate_operation_plan(operation, plan, recovery_readers=self.recovery_readers)
        witness = operation["witness"]
        key = target.keys.get((canonical(operation["owner"]), witness["key_id"]))
        _require(key is not None, "recovery Operation key is not independently enrolled")
        assert key is not None
        verify_witness(
            witness,
            key,
            operation["owner"],
            digest({name: value for name, value in operation.items() if name != "witness"}),
        )
        _require(
            witness["workflow_id"] == workflow_id, "recovery Operation changed original workflow"
        )

    def _fact(
        self,
        target: Any,
        projection: JSON,
        fact: JSON,
        participant: JSON,
        replacement: JSON,
        *,
        native: bool,
    ) -> None:
        _fields(
            fact,
            {"origin", "kind", "operation", "operation_reference", "recovery", "native_stopped"},
        )
        key = _key(fact["origin"])
        _require(
            key in target.children and fact["origin"]["owner"] == projection["origin_owner"],
            "native recovery changed original child identity",
        )
        _require(
            type(fact["native_stopped"]) is bool
            and fact["kind"] in {"completed", "unaccepted", "unknown", "recovered"},
            "native recovery disposition changed",
        )
        original = target.ready.get(key, target.children[key][1])
        operation = fact["operation"]
        known = getattr(target, "_known_outcomes", {}).get(key)
        if known is not None:
            _require(
                fact["kind"] != "unaccepted" and isinstance(operation, dict),
                "native disposition contradicts retained accepted work",
            )
            _require(
                all(
                    operation[name] == known[name]
                    for name in (
                        "id",
                        "owner",
                        "request_id",
                        "plan_digest",
                        "subject",
                        "authenticated_principal",
                        "claimed_actor",
                    )
                ),
                "native disposition changed retained original Operation",
            )
            if known["state"] in {"succeeded", "failed", "cancelled"}:
                _require(
                    operation == known, "native disposition replaced a terminal retained Operation"
                )
            if known["state"] == "succeeded":
                _require(
                    fact["kind"] == "completed", "native disposition changed known successful work"
                )
        if fact["kind"] == "unaccepted":
            _require(
                operation is None
                and fact["operation_reference"] is None
                and fact["recovery"] is None
                and fact["native_stopped"]
                and "completed" not in replacement
                and "completed" not in original,
                "unaccepted child cannot carry accepted or completed work",
            )
            if native:
                _require(
                    key not in target.outcomes,
                    "native unaccepted proof contradicts retained admission",
                )
            return
        _require(
            isinstance(operation, dict)
            and isinstance(fact["operation_reference"], dict)
            and ("plan" in original or "completed" in original),
            "accepted recovery work lacks its exact original Plan and schema identity",
        )
        original_evidence = {"reference": fact["operation_reference"], "operation": operation}
        _evidence(
            original_evidence,
            retained_readers=self.retained_readers,
            recovery_readers=self.recovery_readers,
        )
        self._operation(
            target,
            operation,
            bound_plan(original),
            target.workflow_id
            if "completed" not in original
            else operation["witness"]["workflow_id"],
        )
        _require(
            operation["owner"] == bound_plan(original)["owner"]
            and (
                "completed" in original
                or (
                    operation["owner"] == fact["origin"]["owner"]
                    and operation["request_id"] == fact["origin"]["request_id"]
                )
            ),
            "native recovery Operation changed original child",
        )
        if "completed" in original:
            _require(
                operation == original["completed"]["operation"],
                "native recovery changed preserved completed ancestor",
            )
        if native and key in target.outcomes:
            _require(
                operation == target.outcomes[key], "native recovery replaced retained child outcome"
            )
        if fact["kind"] == "completed":
            _require(
                fact["native_stopped"] and fact["recovery"] is None and "completed" in replacement,
                "completed work must remain a stopped nonexecutable slot",
            )
            validate_completed_binding(
                replacement, participant, recovery_readers=self.recovery_readers
            )
            _require(
                replacement["completed"]["operation"] == operation
                and replacement["completed"]["plan"] == bound_plan(original),
                "successor changed exact completed Operation or Plan",
            )
            if native and operation["result_handle"] is not None:
                data = target.native.result_payload(operation)
                _require(
                    isinstance(data, bytes),
                    "completed recovery result lacks retained local custody",
                )
                validate_result_payload(operation, data, max_bytes=len(data))
        elif fact["kind"] == "recovered":
            _require(
                fact["native_stopped"]
                and "completed" not in replacement
                and isinstance(fact["recovery"], dict),
                "recovered work lacks positive native cessation",
            )
            validate("workflow-recovery.schema.json", fact["recovery"], "RecoveryEvidence")
            _recovered_child(
                {"operation": original_evidence, "recovery": fact["recovery"]},
                operation,
                projection["owner"],
                {"custody": projection["custody"]},
                self.retained_readers,
                self.recovery_readers,
            )
            recovered = fact["recovery"]
            _verify_plan(recovered["plan"], target.keys)
            self._operation(
                target,
                recovered["operation"],
                recovered["plan"],
                recovered["operation"]["witness"]["workflow_id"],
            )
            if native and recovered["operation"]["result_handle"] is not None:
                data = target.native.result_payload(recovered["operation"])
                _require(isinstance(data, bytes), "native recovery result lacks retained custody")
                validate_result_payload(recovered["operation"], data, max_bytes=len(data))
        else:
            _require(
                "completed" not in replacement and fact["recovery"] is None,
                "unknown original work cannot become successful recovery",
            )

    def _facts(self, target: Any, projection: JSON, facts: JSON, *, native: bool) -> None:
        _fields(
            facts,
            {
                "origin_workflow_id",
                "origin_proposal_digest",
                "origin_projection_digest",
                "successor_workflow_id",
                "successor_proposal_digest",
                "preparation",
                "admission_retired",
                "successor_reserved",
                "custody_digest",
                "children",
            },
        )
        recovery = projection["recovery"]
        _require(
            all(
                facts[name] == recovery[name]
                for name in (
                    "origin_workflow_id",
                    "origin_proposal_digest",
                    "successor_workflow_id",
                    "successor_proposal_digest",
                )
            )
            and facts["origin_projection_digest"] == projection["origin_projection_digest"],
            "native retirement changed original or successor commitment",
        )
        _require(
            facts["preparation"] in {"prepared", "never-prepared"}
            and facts["admission_retired"] is True
            and facts["successor_reserved"] is True,
            "positive native admission retirement and exclusive successor reservation required",
        )
        validate("common.schema.json", facts["custody_digest"], "MaterialDigest")
        mapping = {_key(item["origin"]): item["successor"] for item in projection["mapping"]}
        successors = proposal_children({"participants": projection["participants"]})
        seen: set[bytes] = set()
        for fact in facts["children"]:
            key = _key(fact["origin"])
            _require(
                key in mapping and key not in seen,
                "native recovery omitted or duplicated an original child",
            )
            seen.add(key)
            participant, replacement = successors[_key(mapping[key])]
            self._fact(target, projection, fact, participant, replacement, native=native)
        _require(seen == mapping.keys(), "native recovery child closure incomplete")
        if facts["preparation"] == "never-prepared":
            _require(
                all(item["kind"] == "unaccepted" for item in facts["children"]),
                "never-prepared retirement contradicts accepted work",
            )
            if native:
                _require(
                    target._preparation is None,
                    "never-prepared proof contradicts retained preparation",
                )

    def _apply_transfer(self, target: Any, command: JSON, outcome: JSON) -> None:
        action, payload, body = command["action"], command["payload"], outcome["body"]
        if action in {"transfer.propose", "transfer.freeze"}:
            target._recovery_state["transfer"] = {
                "proposal": outcome if action == "transfer.propose" else payload["proposal"],
                "freeze": outcome if action == "transfer.freeze" else None,
                "freezes": {},
                "installations": {},
                "certificate": None,
                "installation": None,
                "active": False,
                "freeze_closure_digest": digest([]),
                "installation_closure_digest": digest([]),
            }
        elif action.startswith("transfer."):
            state = _transfer(target)
            if action == "transfer.collect_freeze":
                record = payload["freeze"]
                state["freezes"][canonical(record["owner"])] = record
                state["freeze_closure_digest"] = digest(
                    {"previous": state["freeze_closure_digest"], "freeze": body["freeze_digest"]}
                )
            elif action == "transfer.commit":
                state["certificate"] = outcome
            elif action == "transfer.install":
                state["certificate"], state["installation"] = payload["certificate"], outcome
                target.driver_term, target.driver_principal = (
                    body["transfer"]["to_term"],
                    body["transfer"]["to_driver"],
                )
            elif action == "transfer.collect_install":
                record = payload["installation"]
                state["installations"][canonical(record["owner"])] = record
                state["installation_closure_digest"] = digest(
                    {
                        "previous": state["installation_closure_digest"],
                        "installation": body["installation_digest"],
                    }
                )
            elif action in {"transfer.activate", "transfer.observe"}:
                state["active"] = True
                state["activation"] = (
                    outcome if action == "transfer.activate" else payload["activation"]
                )
                target.driver_term, target.driver_principal = (
                    body["transfer"]["to_term"],
                    body["transfer"]["to_driver"],
                )
                # A fresh current-phase round reestablishes native reservations;
                # historical outcomes and accepted admissions remain untouched.
                target._round = None
                if _is_gate(target):
                    target._decision, target._votes = None, {}
                else:
                    target._vote, target._certificate, target._reservation = None, None, None
            else:
                raise ContractError("unsupported retained transfer event")

    @bounds(_bounds("apply"))
    def apply(self, target: Any, command: JSON, outcome: JSON) -> None:
        """Apply only an already durable event, including one cold restore pass."""
        action, payload, body = command["action"], command["payload"], outcome["body"]
        if action == "recover.gate_approve":
            from .workflow_gate_recovery import retain_recovery_gate

            selected = self.gate_recovery_enrollments.get(digest(body["authority"]))
            _require(selected is not None, "retained recovery gate enrollment missing")
            assert selected is not None
            retain_recovery_gate(target, outcome, selected)
            target.generation += 1
            return
        if action.startswith("transfer."):
            self._apply_transfer(target, command, outcome)
            target.generation += 1
            return
        if action == "recover.propose":
            target._recovery_state["retired"] = True
            projections = _partition(
                target,
                payload["successor"],
                payload["mapping"],
                body["recovery"],
                self.current_owners,
                self.verified_custody,
            )
            _require(
                _custody_digest(projections) == body["custody_digest"],
                "retained recovery owner or qualified custody configuration changed",
            )
            target._recovery_state["recovery"] = {
                "recovery": body["recovery"],
                "proposal": outcome,
                "successor": payload["successor"],
                "projections": projections,
                "issuer_origins": {
                    canonical(projection["owner"]): origin
                    for origin, projection in projections.items()
                },
                "items": {
                    key: item
                    for projection in projections.values()
                    for key, item in _local_items(projection).items()
                },
                "dispositions": {},
                "blocked": 0,
                "certificate": None,
                "disposition_closure_digest": digest([]),
            }
        elif action == "recover.projection":
            return
        elif action == "recover.abandon_start":
            _recovery(target)["abandonment"] = {
                "proposal": outcome,
                "members": {},
                "closure_digest": digest([]),
            }
        elif action == "recover.abandon":
            _recovery(target)["abandonment"] = {"proposal": payload["proposal"], "local": outcome}
        elif action == "recover.collect_abandon":
            state = _recovery(target)
            record = payload["abandonment"]
            origin = state["issuer_origins"][canonical(record["owner"])]
            abandonment = state["abandonment"]
            abandonment["members"][origin] = record
            abandonment["closure_digest"] = digest(
                {
                    "previous": abandonment["closure_digest"],
                    "abandonment": body["abandonment_digest"],
                }
            )
        elif action in {"recover.abandon_commit", "recover.observe_abandon"}:
            state = _recovery(target)
            certificate = outcome if action == "recover.abandon_commit" else payload["certificate"]
            target._recovery_state.setdefault("abandonment_certificates", {})[
                state["recovery"]["successor_workflow_id"]
            ] = certificate
            abandoned = target._recovery_state.setdefault("abandoned", {})
            abandoned[state["recovery"]["successor_workflow_id"]] = outcome["id"]
            target._recovery_state["recovery"] = None
            target._recovery_state["retired"] = True
        elif action == "recover.abandon_recertify":
            target._recovery_state["abandonment_certificates"][
                body["recovery"]["successor_workflow_id"]
            ] = outcome
        elif action == "recover.inspect":
            target._recovery_state["retired"] = True
            projection = {
                key: value
                for key, value in payload["projection"]["body"].items()
                if key != "command_digest"
            }
            items = _local_items(projection)
            for fact in body["facts"]["children"]:
                items[_key(fact["origin"])].update(fact=fact, record_id=outcome["id"])
            target._recovery_state["recovery"] = {
                "recovery": body["recovery"],
                "projection": payload["projection"],
                "disposition": outcome,
                "certificate": None,
                "items": items,
            }
        elif action == "recover.collect":
            state = _recovery(target)
            record = payload["disposition"]
            member = state["issuer_origins"][canonical(record["owner"])]
            state["dispositions"][member] = record
            for fact in record["body"]["facts"]["children"]:
                state["items"][_key(fact["origin"])].update(fact=fact, record_id=record["id"])
            state["blocked"] += int(body["blocked"])
            state["disposition_closure_digest"] = digest(
                {
                    "previous": state["disposition_closure_digest"],
                    "disposition": body["disposition_digest"],
                }
            )
        elif action == "recover.commit":
            _recovery(target)["certificate"] = outcome
        elif action in {"recover.reconcile", "recover.collect_update"}:
            state = _recovery(target)
            record = outcome if action == "recover.reconcile" else payload["update"]
            selected = record["body"]
            state["items"][_key(selected["origin"])].update(
                fact=selected["fact"], record_id=record["id"]
            )
            if action == "recover.collect_update":
                state["blocked"] -= 1
                state["disposition_closure_digest"] = digest(
                    {
                        "previous": state["disposition_closure_digest"],
                        "update": body["update_digest"],
                    }
                )
        elif action == "recover.install":
            state = _recovery(target)
            state["certificate"] = payload["certificate"]
            state["installed"] = outcome
        else:
            raise ContractError("unsupported retained recovery event")
        target.generation += 1

    @bounds(_bounds("blocks_work"))
    def blocks_work(self, target: Any) -> bool:
        state = target._recovery_state
        transfer = state.get("transfer")
        return bool(
            state.get("retired")
            or getattr(target, "_recovery_gate_authority", None) is not None
            or (transfer is not None and not transfer["active"])
        )

    @bounds(_bounds("context"))
    def context(self, target: Any, *, principal: str) -> RecoveryContext:
        """Select protected accepted retirement for a new successor constructor."""
        target._authorize(principal, "read")
        state = _recovery(target)
        _require(
            state.get("certificate") is not None, "successor retirement closure is not committed"
        )
        gate_owner, key_id = state["certificate"]["owner"], state["certificate"]["key_id"]
        key = target.keys.get((canonical(gate_owner), key_id))
        _require(key is not None, "original recovery gate is not independently enrolled")
        return RecoveryContext(
            copy.deepcopy(gate_owner),
            key_id,
            key,
            copy.deepcopy(state["certificate"]),
            copy.deepcopy(state.get("projection")),
            copy.deepcopy(state.get("installed", state.get("disposition"))),
            target.keys,
        )

    def _certificate(self, context: RecoveryContext) -> JSON:
        certificate = context.certificate
        verify_journal_record(
            certificate,
            {
                (
                    canonical(context.origin_gate_owner),
                    context.origin_gate_key_id,
                ): context.origin_gate_public_key
            },
            expected_owner=context.origin_gate_owner,
        )
        body = certificate["body"]
        _require(
            certificate["key_id"] == context.origin_gate_key_id
            and body.get("type") == "recovery-certificate"
            and body["recovery"]["origin_workflow_id"] == certificate["workflow_id"],
            "successor original recovery authority changed",
        )
        return dict(body)

    @bounds(_bounds("initialize_gate"))
    def initialize_gate(self, target: Any, proposal: JSON, context: RecoveryContext) -> None:
        body = self._certificate(context)
        recovery = body["recovery"]
        _require(
            target.owner == context.origin_gate_owner
            and proposal["workflow_id"] == recovery["successor_workflow_id"]
            and digest(proposal) == recovery["successor_proposal_digest"]
            and target.header["owner_count"] == body["owner_count"],
            "successor gate changed complete reserved manifest or owner",
        )

    @bounds(_bounds("initialize_member"))
    def initialize_member(self, target: Any, projection: JSON, context: RecoveryContext) -> None:
        body = self._certificate(context)
        _require(
            context.projection is not None and context.disposition is not None,
            "successor lacks exact local retirement custody",
        )
        assert context.projection is not None and context.disposition is not None
        verify_journal_record(
            context.projection,
            _KeyOverlay(
                {
                    (
                        canonical(context.origin_gate_owner),
                        context.origin_gate_key_id,
                    ): context.origin_gate_public_key
                },
                context.historical_gate_keys if context.historical_gate_keys is not None else {},
            ),
            expected_workflow_id=body["recovery"]["origin_workflow_id"],
        )
        selected = {
            key: value
            for key, value in context.projection["body"].items()
            if key != "command_digest"
        }
        _require(
            selected.get("type") == "recovery-projection"
            and all(
                context.projection["owner"][name] == context.origin_gate_owner[name]
                for name in ("tool", "id")
            )
            and selected["header_digest"] == body["header_digest"]
            and selected["recovery"] == body["recovery"]
            and selected["owner"] == target.owner
            and target.header["proposal_digest"] == body["recovery"]["successor_proposal_digest"]
            and target.workflow_id == body["recovery"]["successor_workflow_id"],
            "successor local projection changed reserved workflow",
        )
        _require(
            self._current_owner(selected["origin_owner"]) == target.owner
            and self.verified_custody.get(canonical(selected["origin_owner"]))
            == selected["custody"],
            "successor historical custody is not independently approved",
        )
        _require(
            all(
                projection[name] == selected[name]
                for name in ("participants", "content", "dependencies")
            ),
            "successor changed exact local material or intent",
        )
        verify_journal_record(
            context.disposition,
            target.keys,
            expected_owner=target.owner,
            expected_workflow_id=body["recovery"]["origin_workflow_id"],
        )
        disposition = context.disposition["body"]
        _require(
            disposition.get("type") == "recovery-installed"
            and disposition["recovery"] == body["recovery"]
            and disposition["projection_digest"] == digest(selected),
            "successor changed local disposition commitment",
        )
        _require(
            all(
                item["kind"] != "unknown" and item["native_stopped"]
                for item in disposition["facts"]["children"]
            ),
            "unknown or active original work blocks successor initialization",
        )
        target.native.check_recovery(selected, disposition["facts"], context.certificate)
        for key, (participant, binding) in target.children.items():
            if "completed" in binding:
                validate_completed_binding(
                    binding, participant, recovery_readers=self.recovery_readers
                )
                target.outcomes[key] = copy.deepcopy(binding["completed"]["operation"])
