"""Current-epoch, recovery-only gate authority over complete original custody.

Restoration never relabels old signatures or reopens old execution. A protected
native callback verifies the entire retained gate lineage and fences the former
authority. Each local owner independently enrolls and durably approves the exact
replacement before its gate can certify any new shared recovery decision.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .bounds import Bounds, bounds
from .handoffs import schema_identity
from .history import validate_owner_custody
from .validation import canonical, digest, validate
from .workflow_journal import (
    JournalStore,
    KeyRing,
    WorkflowGate,
    _fields,
    _identity,
    _KeyOverlay,
    _now,
    _require,
    verify_journal_record,
    verify_journal_signature,
)
from .workflow_journal_recovery import JournalRecovery

JSON = dict[str, Any]
_ROOT = "https://fishhat.invalid/contracts/workflow-journal.schema.json#/$defs/JournalRecord"
_APPROVAL_ACTIONS = {"recover.gate_approve", "recover.gate_collect", "recover.gate_commit"}


@dataclass(frozen=True)
class GateJournalSource:
    """One independently opened immutable epoch segment and its original reducer.

    recovery retains the independently approved owner/custody mapping used by
    that segment. Replaying it under today's mapping could silently change an
    already reserved successor. Every segment and expected head is covered by
    the current custodian's verified complete restoration manifest.
    """

    journal: JournalStore
    schema: JSON
    head: str
    recovery: JournalRecovery


@dataclass(frozen=True)
class OriginGateRecoveryContext:
    """Protected complete original gate custody, never supplied by a command.

    sources begins with the original gate journal and includes every later
    recovery-only epoch segment in order. No missing segment or restored empty
    index is accepted. Native restore verifies completeness and anti-rollback
    against the custody manifest before authorizing a replacement. source_keys is
    the exact finite signing-key closure of these sources, not an owner-wide
    unrelated trust registry. It is materialized once during cold reconstruction.
    """

    proposal: JSON
    sources: tuple[GateJournalSource, ...]
    custody: JSON
    source_keys: KeyRing


@dataclass(frozen=True)
class GateRecoveryEnrollment:
    """Independent exact authority and receiver-local predecessor approval.

    previous_authority_digest is null before the receiver's first recovery-gate
    approval, otherwise the digest of that receiver's exact retained authority.
    It is independent native configuration, never a caller-selected history.
    """

    authority: JSON
    public_key: Ed25519PublicKey
    grant_id: str
    previous_authority_digest: str | None


def _authority(value: JSON) -> None:
    validate("workflow-journal.schema.json", value, "GateRecoveryAuthority")
    _require(
        value["owner"]["epoch"] != value["predecessor"]["epoch"]
        and all(
            value["owner"][name] == value["predecessor"][name] == value["origin"][name]
            for name in ("tool", "id")
        ),
        "gate recovery must replace the exact logical owner's epoch",
    )


def approve_recovery_gate(target: Any, command: JSON, enrollment: GateRecoveryEnrollment) -> JSON:
    """Authorize locally from installed trust, retaining native closure before signing."""
    _fields(command["payload"], {"initialization"})
    authority = copy.deepcopy(enrollment.authority)
    _authority(authority)
    validate("common.schema.json", enrollment.grant_id, "UUID")
    record = command["payload"]["initialization"]
    verify_journal_record(
        record,
        {(canonical(authority["owner"]), authority["key_id"]): enrollment.public_key},
        expected_owner=authority["owner"],
        expected_workflow_id=target.workflow_id,
    )
    _require(
        record["key_id"] == authority["key_id"]
        and record["body"].get("type") == "gate-recovery-initialized"
        and record["body"].get("authority") == authority
        and authority["workflow_id"] == target.workflow_id
        and authority["header_digest"] == target.header_digest
        and authority["proposal_digest"] == target.header["proposal_digest"]
        and authority["origin"] == target.header["gate_owner"],
        "gate recovery differs from independently approved exact authority",
    )
    old = getattr(target, "_recovery_gate_authority", None)
    old_approval = getattr(target, "_recovery_gate_approval", None)
    renewed_member = (
        old == authority and old_approval is not None and old_approval["owner"] != target.owner
    )
    _require(old != authority or renewed_member, "gate recovery authority already approved")
    _require(
        enrollment.previous_authority_digest == (None if old is None else digest(old)),
        "gate recovery changed the receiver's exact retained authority predecessor",
    )
    native = target.native.approve_gate_recovery(
        {
            "owner": target.owner,
            "workflow_id": target.workflow_id,
            "authority": copy.deepcopy(authority),
            "grant_id": enrollment.grant_id,
            "previous_authority_digest": enrollment.previous_authority_digest,
        }
    )
    validate("workflow-journal.schema.json", native, "GateRecoveryApprovalEvidence")
    _require(
        native["owner"] == target.owner
        and native["workflow_id"] == target.workflow_id
        and native["authority_digest"] == digest(authority)
        and native["grant_id"] == enrollment.grant_id
        and native["previous_authority_digest"] == enrollment.previous_authority_digest,
        "native gate reapproval changed exact receiver or delegation",
    )
    return {
        "type": "gate-recovery-approved",
        "header_digest": target.header_digest,
        "authority": authority,
        "native": native,
    }


def retain_recovery_gate(target: Any, outcome: JSON, enrollment: GateRecoveryEnrollment) -> None:
    """Install only independently approved current recovery trust after durable append."""
    authority = outcome["body"]["authority"]
    previous = getattr(target, "_recovery_gate_authority", None)
    native = outcome["body"]["native"]
    _require(
        authority == enrollment.authority
        and native["grant_id"] == enrollment.grant_id
        and native["previous_authority_digest"] == enrollment.previous_authority_digest
        and enrollment.previous_authority_digest
        == (None if previous is None else digest(previous)),
        "retained gate recovery enrollment or local predecessor changed",
    )
    target._recovery_gate_authority = copy.deepcopy(authority)
    target._recovery_gate_approval = copy.deepcopy(outcome)
    index = getattr(target, "_recovery_gate_key_index", None)
    if index is None:
        index = {}
        target._recovery_gate_key_index = index
        target.keys = _KeyOverlay(index, target.keys)
    index[(canonical(authority["owner"]), authority["key_id"])] = enrollment.public_key


class WorkflowRecoveryGate(WorkflowGate):
    """Reconstruct shared custody once; permit recovery only after all local approvals."""

    @bounds(
        Bounds(
            id="workflow.journal.gate-recover",
            work="O(B + N + H) one manifest partition, one pass over each qualified epoch segment and one current journal replay; each local reapproval is indexed once",
            extent="Complete original gate custody, every original participant and every retained transfer/recovery reservation; no history or owner-count cap",
            limits=(),
            capacity=("Missing complete authoritative custody blocks gate replacement",),
            proofs=(
                "tests/test_workflow_gate_recovery.py::test_gate_epoch_recovery_requires_every_local_approval_and_preserves_custody",
            ),
            linear_proofs=(
                "tests/test_workflow_gate_recovery.py::test_gate_recovery_growth_counts_complete_owner_closure",
            ),
        )
    )
    def __init__(
        self,
        origin: OriginGateRecoveryContext,
        *,
        owner: JSON,
        key_id: str,
        private_key: Ed25519PrivateKey,
        member_keys: KeyRing,
        authorize: Callable[[str, str, JSON], None],
        restore_gate: Callable[[JSON], None],
        journal: JournalStore,
        principal: str,
        extension: JournalRecovery,
        clock: Callable[[], str] = _now,
        command: JSON | None = None,
    ) -> None:
        _require(bool(origin.sources), "gate recovery lacks complete original custody")
        validate_owner_custody(origin.custody, expected_custodian=owner)
        predecessor = origin.sources[-1]
        _require(
            origin.custody["origin"] == predecessor.journal.owner,
            "gate recovery custody changed predecessor epoch",
        )
        self.authorize = authorize
        self.lifecycle = None
        source_keys = dict(origin.source_keys)
        self._installed_journal_schema = schema_identity(_ROOT)
        self._setup(
            owner=owner,
            key_id=key_id,
            private_key=private_key,
            keys=_KeyOverlay(
                {(canonical(owner), key_id): private_key.public_key()},
                _KeyOverlay(source_keys, member_keys),
            ),
            journal=journal,
            clock=clock,
            extension=extension,
        )
        self._gate_recovery_approvals: dict[bytes, JSON] = {}
        self._gate_recovery_certificate: JSON | None = None
        self._gate_recovery_closure = digest([])
        self._gate_recovery_initialized: JSON | None = None
        with ExitStack() as guards:
            for source in origin.sources:
                guards.enter_context(source.journal.guard(source.head))
            self._restore_sources(origin, source_keys)
            # Freeze only this finite workflow's selected native mapping once.
            # Owner-wide indexes may be mutable and contain unrelated entries;
            # neither later mutation nor a whole-registry copy belongs here.
            selected_owners, selected_custody = {}, {}
            for original, member in self._members.items():
                selected_owners[original] = copy.deepcopy(extension._current_owner(member))
                custody = extension.verified_custody.get(original)
                if custody is not None:
                    selected_custody[original] = copy.deepcopy(custody)
            extension = JournalRecovery(
                current_owners=selected_owners,
                verified_custody=selected_custody,
                retained_readers=extension.retained_readers,
                recovery_readers=extension.recovery_readers,
            )
            self.extension = extension
            self._recovery_gate_members = {
                canonical(current): original for original, current in selected_owners.items()
            }
            _require(
                len(self._recovery_gate_members) == len(self._members),
                "gate recovery collapsed independent member identities",
            )
            self.authority = {
                "workflow_id": self.workflow_id,
                "proposal_digest": self.header["proposal_digest"],
                "header_digest": self.header_digest,
                "origin": copy.deepcopy(self.header["gate_owner"]),
                "predecessor": predecessor.journal.owner,
                "owner": copy.deepcopy(owner),
                "key_id": key_id,
                "source_head": predecessor.head,
                "source_schema": copy.deepcopy(predecessor.schema),
                "custody_digest": origin.custody["digest"],
                "member_custody_digest": digest(
                    [
                        {
                            "origin": member,
                            "owner": selected_owners[original],
                            "custody": selected_custody.get(original),
                        }
                        for original, member in self._members.items()
                    ]
                ),
            }
            _authority(self.authority)
            payload = {"source_head": predecessor.head, "custody_digest": origin.custody["digest"]}
            command = command or self._command(
                "gate.recover", _identity("gate-recover", self.workflow_id, owner), payload
            )
            _require(
                command["action"] == "gate.recover"
                and command["workflow_id"] == self.workflow_id
                and command["payload"] == payload,
                "gate recovery changed exact protected custody commitment",
            )
            self._authorize(principal, "read")
            if self.journal.lookup(command["id"], read_authorized=True) is None:
                self._authorize(principal, "initialize")
            restore_gate(
                {
                    "authority": copy.deepcopy(self.authority),
                    "custody": copy.deepcopy(origin.custody),
                    "sources": [
                        {
                            "owner": source.journal.owner,
                            "head": source.head,
                            "schema": source.schema,
                        }
                        for source in origin.sources
                    ],
                }
            )
        self._recovery_state["retired"] = True
        self._initialize(
            command,
            self._outcome(
                command,
                {
                    "type": "gate-recovery-initialized",
                    "header_digest": self.header_digest,
                    "authority": self.authority,
                },
            ),
            principal,
        )

    def _restore_sources(self, origin: OriginGateRecoveryContext, keys: KeyRing) -> None:
        seen: set[bytes] = set()
        previous: GateJournalSource | None = None
        for source in origin.sources:
            owner = source.journal.owner
            _require(canonical(owner) not in seen, "gate recovery repeats an epoch segment")
            seen.add(canonical(owner))
            _require(
                source.schema["uri"] == _ROOT
                and getattr(source.journal, "schema", None) == source.schema,
                "gate recovery source schema or custody changed",
            )
            found = False
            self.extension = source.recovery
            for event in source.journal.iter_events(read_authorized=True):
                request, record = event["request"], event["outcome"]
                self._source_record(source, record, keys)
                _require(
                    request["workflow_id"] == origin.proposal["workflow_id"]
                    and record["workflow_id"] == origin.proposal["workflow_id"]
                    and record["id"] == request["id"]
                    and record["body"].get("command_digest") == digest(request),
                    "gate recovery source event commitment changed",
                )
                if not found:
                    if previous is None:
                        _require(
                            request["action"] == "gate.create"
                            and request["payload"] == {"proposal": origin.proposal},
                            "gate recovery lacks exact original proposal initialization",
                        )
                        self._index_manifest(
                            origin.proposal,
                            recovery=True,
                            gate_owner=owner,
                            gate_key_id=record["key_id"],
                        )
                    else:
                        authority = record["body"].get("authority", {})
                        _require(
                            request["action"] == "gate.recover"
                            and record["body"].get("type") == "gate-recovery-initialized"
                            and authority.get("source_head") == previous.head
                            and authority.get("predecessor") == previous.journal.owner
                            and authority.get("owner") == owner
                            and authority.get("proposal_digest") == self.header["proposal_digest"]
                            and authority.get("header_digest") == self.header_digest,
                            "gate recovery lineage omitted or substituted an epoch segment",
                        )
                    _require(
                        record["body"].get("header_digest") == self.header_digest,
                        "gate recovery changed original common header",
                    )
                    found = True
                if request["action"] not in _APPROVAL_ACTIONS | {"gate.recover"}:
                    WorkflowGate._apply_event(self, request, record)
                else:
                    self.generation += 1
            _require(found, "gate recovery original journal is empty")
            previous = source
        _require(
            canonical(self.owner) not in seen,
            "gate recovery cannot reuse an earlier owner epoch",
        )

    def _source_record(self, source: GateJournalSource, record: JSON, keys: KeyRing) -> None:
        if source.schema == self._installed_journal_schema:
            verify_journal_record(
                record,
                keys,
                expected_owner=source.journal.owner,
                expected_workflow_id=record["workflow_id"],
            )
            return
        selected = (source.schema["uri"], source.schema["digest"])
        readers, recovery = source.recovery.retained_readers, source.recovery.recovery_readers
        _require(
            readers is not None
            and selected in readers
            and recovery is not None
            and selected in recovery,
            "gate recovery source lacks independently qualified historical readers",
        )
        assert readers is not None and recovery is not None
        original = canonical(record)
        readers[selected](record)
        recovery[selected](record)
        _require(canonical(record) == original, "gate recovery reader rewrote original bytes")
        verify_journal_signature(record, keys, expected_owner=source.journal.owner)

    def _accept(self, command: JSON, principal: str) -> JSON:
        action, payload = command["action"], command["payload"]
        if action == "recover.gate_collect":
            _fields(payload, {"approval"})
            record = payload["approval"]
            self._verify(record)
            member = canonical(record["owner"])
            _require(
                self._gate_recovery_certificate is None
                and member in self._recovery_gate_members
                and member not in self._gate_recovery_approvals,
                "gate recovery approval is foreign, duplicated or already committed",
            )
            _require(
                record["body"].get("type") == "gate-recovery-approved"
                and record["body"].get("header_digest") == self.header_digest
                and record["body"].get("authority") == self.authority
                and record["body"]["native"]["owner"] == record["owner"]
                and record["body"]["native"]["workflow_id"] == self.workflow_id
                and record["body"]["native"]["authority_digest"] == digest(self.authority),
                "gate recovery local approval changed exact authority",
            )
            return self._outcome(
                command,
                {
                    "type": "gate-recovery-approval-accepted",
                    "header_digest": self.header_digest,
                    "authority_digest": digest(self.authority),
                    "member": record["owner"],
                    "approval_digest": digest(record),
                },
            )
        if action == "recover.gate_commit":
            _fields(payload, set())
            _require(
                self._gate_recovery_certificate is None
                and len(self._gate_recovery_approvals) == len(self._members),
                "gate recovery requires complete independent local reapproval",
            )
            return self._outcome(
                command,
                {
                    "type": "gate-recovery-certificate",
                    "header_digest": self.header_digest,
                    "authority": self.authority,
                    "owner_count": len(self._members),
                    "approval_closure_digest": self._gate_recovery_closure,
                },
            )
        _require(
            action.startswith("recover.") and action not in _APPROVAL_ACTIONS,
            "restored gate permits recovery only, never original admission or transfer",
        )
        _require(
            self._gate_recovery_certificate is not None,
            "gate recovery requires complete independent local reapproval",
        )
        assert self.extension is not None
        return self.extension.outcome(self, command, principal)

    def _apply_event(self, command: JSON, outcome: JSON) -> None:
        action = command["action"]
        if action == "gate.recover":
            self._gate_recovery_initialized = outcome
        elif action == "recover.gate_collect":
            record = command["payload"]["approval"]
            self._gate_recovery_approvals[canonical(record["owner"])] = record
            self._gate_recovery_closure = digest(
                {"previous": self._gate_recovery_closure, "approval": digest(record)}
            )
        elif action == "recover.gate_commit":
            self._gate_recovery_certificate = outcome
        else:
            _require(action.startswith("recover."), "restored gate retained new ordinary work")
            assert self.extension is not None
            self.extension.apply(self, command, outcome)
            return
        self.generation += 1
