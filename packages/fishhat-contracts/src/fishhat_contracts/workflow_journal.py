"""Partitioned owner workflow journals with independently approved finite gates.

The complete manifest is validated and indexed once at its gate. Members retain
only their local projection and exact incoming dependencies. No event serializes
the accumulated history. Native contexts are protected receiver services: wire
commands never provide authorization, reservations, current facts or trust keys.
"""

from __future__ import annotations

import base64
import copy
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .bounds import Bounds, bounds
from .handoffs import PHASES, validate_result_payload
from .operations import validate_operation_plan
from .validation import ContractError, canonical, digest, validate, validate_plan
from .witness import verify as verify_witness
from .workflow_bindings import _binding_shape, _key, _predecessor, _verify_binding_custody
from .workflow_evidence import REQUIREMENTS, _child_outcome
from .workflows import (
    _child_identity_matches,
    _handles,
    _pair,
    bound_plan,
    child_action,
    proposal_children,
    validate_workflow_proposal,
)

JSON = dict[str, Any]
KeyRing = Mapping[tuple[bytes, str], Ed25519PublicKey]
PREFIX = b"fishhat/workflow-journal/v1\x00"

if TYPE_CHECKING:
    from .workflow_journal_recovery import RecoveryContext


class _KeyOverlay(Mapping[tuple[bytes, str], Ed25519PublicKey]):
    """Constant-size local configuration over an independently installed reader."""

    def __init__(self, local: KeyRing, installed: KeyRing) -> None:
        self.local, self.installed = local, installed

    def __getitem__(self, key: tuple[bytes, str]) -> Ed25519PublicKey:
        return self.local[key] if key in self.local else self.installed[key]

    def __iter__(self) -> Iterator[tuple[bytes, str]]:
        yield from self.local
        for key in self.installed:
            if key not in self.local:
                yield key

    def __len__(self) -> int:
        return sum(1 for _ in self)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _fields(value: JSON, required: set[str], optional: set[str] | None = None) -> None:
    _require(
        isinstance(value, dict)
        and required <= value.keys()
        and value.keys() <= required | (optional or set()),
        "workflow journal fields changed",
    )


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _time(value: str) -> datetime:
    validate("common.schema.json", value, "Time")
    return datetime.fromisoformat(value)


def _identity(*parts: Any) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, canonical(list(parts)).decode()))


def _recovery_digest(context: RecoveryContext | None) -> str | None:
    if context is None:
        return None
    return digest(
        {
            "certificate": context.certificate,
            "projection": context.projection,
            "disposition": context.disposition,
        }
    )


def _declaration(name: str, work: str) -> Bounds:
    return Bounds(
        id="workflow.journal." + name,
        work=work,
        extent="Complete owner-local inputs, dependency edges and fixed installed phases; no owner, child, material or history count ceiling",
        limits=(),
        capacity=(
            "Protected native owners may refuse new capacity without discarding accepted work",
        ),
        proofs=(
            "tests/test_workflow_journal.py::test_complete_workflow_survives_disk_restart_and_lost_replies",
        ),
        linear_proofs=(
            "tests/test_workflow_journal_growth.py::test_complete_multi_owner_workflow_is_linear",
        ),
    )


class JournalStore(Protocol):
    """Owner-supplied durable custody; append commits before returning."""

    @property
    def owner(self) -> JSON: ...

    @property
    def head(self) -> str: ...

    def lookup(self, event_id: str, *, read_authorized: bool) -> JSON | None: ...

    def append(self, event_id: str, request: Any, outcome: Any, *, expected_head: str) -> JSON: ...

    def iter_events(self, *, read_authorized: bool) -> Iterator[JSON]: ...

    def guard(self, expected_head: str) -> AbstractContextManager[None]: ...


@dataclass(frozen=True)
class GateEnrollment:
    """Independent owner configuration for one exact workflow and local projection.

    The grant is checked by the current native authorization service on every new
    use. Possession of this value or an earlier signed record grants no permission.
    """

    workflow_id: str
    proposal_digest: str
    gate_owner: JSON
    gate_key_id: str
    gate_public_key: Ed25519PublicKey
    member_owner: JSON
    projection_digest: str
    grant_id: str


class NativeWorkflowContext(Protocol):
    """Protected native implementation, never deserialized from a command.

    reserve durably and idempotently holds the installed phase conditions for the
    exact common round before returning a complete local reservation. These are
    durable nonrevocable protections through dependent effects, not observations
    or expiring leases. Exclusion/fencing survives owner failure or fails closed
    at every dependent effect boundary. It cannot disappear, expire or be revoked
    unilaterally. A native implementation unable to implement that primitive must
    refuse reserve. Release requires positive verification that dependent
    admissions are fenced and accepted work is settled. Loss must fence the actual
    dependent effects; simply noticing it at a later poll is insufficient.
    check independently rejects lost, replaced or unprotected conditions. Expiry
    never releases protection.
    bind/admit return independently obtained, non-effectful review context. They
    must not accept or start the native Operation. Actual operation.submit resolves
    its own exact native replay first, then requires the durable journal permit
    and atomically rechecks current permission, generation and the same fence
    before retaining native acceptance. Journal lifecycle/transfer protection and
    native admission must serialize at that native boundary. Copying caller claims
    into protected review context is not an implementation.
    Review contexts contain exactly the selected request facts and Plan scopes,
    fetched through native indexes; neither a full local catalog nor peer history
    is rescanned or returned for an individual child.
    """

    def authorize(self, principal: str, action: str, context: JSON) -> None: ...

    def prepare(self, projection: JSON, enrollment: GateEnrollment) -> None: ...

    def reserve(
        self, round: JSON, participants: list[JSON], outcomes: Mapping[bytes, JSON]
    ) -> JSON: ...

    def check(self, reservation: JSON, round: JSON) -> None: ...

    def bind(self, request: JSON) -> JSON: ...

    def admit(self, context: JSON) -> JSON: ...

    def result_payload(self, operation: JSON) -> bytes | None: ...

    def lifecycle(self, action: str, context: JSON) -> JSON: ...

    def recovery_disposition(self, projection: JSON) -> JSON: ...

    def check_recovery(self, projection: JSON, disposition: JSON, certificate: JSON) -> None: ...

    def restore_recovery(self, context: JSON) -> None: ...


class JournalExtension(Protocol):
    def outcome(self, target: Any, command: JSON, principal: str) -> JSON: ...

    def apply(self, target: Any, command: JSON, outcome: JSON) -> None: ...

    def blocks_work(self, target: Any) -> bool: ...

    def initialize_gate(self, target: Any, proposal: JSON, recovery: RecoveryContext) -> None: ...

    def initialize_member(
        self, target: Any, projection: JSON, recovery: RecoveryContext
    ) -> None: ...


def verify_journal_record(
    record: JSON,
    keys: KeyRing,
    *,
    expected_owner: JSON | None = None,
    expected_workflow_id: str | None = None,
) -> None:
    """Authenticate a record against independently installed owner/epoch keys."""
    validate("workflow-journal.schema.json", record, "JournalRecord")
    verify_journal_signature(
        record, keys, expected_owner=expected_owner, expected_workflow_id=expected_workflow_id
    )


def verify_journal_signature(
    record: JSON,
    keys: KeyRing,
    *,
    expected_owner: JSON | None = None,
    expected_workflow_id: str | None = None,
) -> None:
    """Authenticate the fixed signed envelope without selecting body semantics.

    Historical inspection calls this only after independently installed readers
    for the exact retained source schema validate unchanged bytes. This function
    grants no body interpretation, recovery approval or new admission authority.
    Current admission uses verify_journal_record and its installed closed schema.
    """
    _fields(record, {"format", "kind", "id", "owner", "workflow_id", "key_id", "body", "signature"})
    _require(
        record["format"] == "fishhat.workflow-journal/v1"
        and record["kind"] == "WorkflowJournalRecord"
        and isinstance(record["body"], dict)
        and isinstance(record["body"].get("type"), str),
        "workflow journal record format changed",
    )
    validate("common.schema.json", record["id"], "UUID")
    validate("common.schema.json", record["workflow_id"], "UUID")
    validate("common.schema.json", record["owner"], "Owner")
    validate("common.schema.json", record["key_id"], "Id")
    _require(
        expected_owner is None or record["owner"] == expected_owner,
        "workflow journal issuer changed",
    )
    _require(
        expected_workflow_id is None or record["workflow_id"] == expected_workflow_id,
        "workflow journal identity changed",
    )
    key = keys.get((canonical(record["owner"]), record["key_id"]))
    _require(key is not None, "workflow journal key is not independently enrolled")
    assert key is not None
    try:
        key.verify(
            base64.b64decode(record["signature"], validate=True),
            PREFIX
            + canonical({name: value for name, value in record.items() if name != "signature"}),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ContractError("workflow journal signature is not trusted") from exc


def _verify_operation(operation: JSON, plan: JSON, keys: KeyRing, workflow_id: str) -> None:
    validate_operation_plan(operation, plan)
    witness = operation["witness"]
    key = keys.get((canonical(operation["owner"]), witness["key_id"]))
    _require(key is not None, "workflow child signing key is not independently enrolled")
    assert key is not None
    verify_witness(
        witness,
        key,
        operation["owner"],
        digest({k: v for k, v in operation.items() if k != "witness"}),
    )
    _require(witness["workflow_id"] == workflow_id, "workflow child belongs to another workflow")


def _verify_plan(plan: JSON, keys: KeyRing) -> None:
    validate_plan(plan)
    key = keys.get((canonical(plan["owner"]), plan["witness"]["key_id"]))
    _require(key is not None, "workflow Plan signing key is not independently enrolled")
    assert key is not None
    verify_witness(plan["witness"], key, plan["owner"], plan["digest"])


def _known_outcome(previous: JSON | None, operation: JSON) -> None:
    if previous is None or previous == operation:
        return
    _require(
        operation["id"] == previous["id"] and operation["generation"] > previous["generation"],
        "workflow evidence replaced or regressed a retained native Operation",
    )
    _require(
        previous["state"] not in {"succeeded", "failed", "cancelled"},
        "workflow evidence replaced a retained terminal outcome",
    )


def _selected_review(request: JSON, review: JSON) -> None:
    """Consume only exact indexed native facts required by this one local review."""
    _fields(
        review,
        {
            "verified_binding",
            "current_generations",
            "verified_operations",
            "verified_materials",
            "verified_content",
            "verified_adapters",
            "now",
        },
    )
    for name in ("operations", "materials", "content"):
        requested = request["predecessors" if name == "operations" else name]
        verified = review["verified_" + name]
        wanted = {canonical(value) for value in requested}
        actual = {canonical(value) for value in verified}
        _require(
            len(wanted) == len(requested) and len(actual) == len(verified) and actual == wanted,
            "workflow native review must contain exactly its selected duplicate-free facts",
        )
    expected_adapters = (
        [] if "adapter" not in request["binding"] else [request["binding"]["adapter"]]
    )
    _require(
        review["verified_adapters"] == expected_adapters,
        "workflow native review changed selected adapter",
    )
    expected = {
        _pair(condition["owner"], condition["resource"])
        for condition in request["binding"]["plan"]["preconditions"]
    }
    actual = {
        _pair(condition["owner"], condition["resource"])
        for condition in review["current_generations"]
    }
    _require(
        actual == expected and len(actual) == len(review["current_generations"]),
        "workflow native review must select exact current Plan scopes",
    )
    _require(
        all(type(item["generation"]) is int for item in review["current_generations"]),
        "workflow native current generation is invalid",
    )
    _verify_binding_custody(request, **review)


class _JournalTarget:
    workflow_id: str
    header: JSON
    header_digest: str
    driver_principal: str
    driver_term: int
    phase: str

    def _setup(
        self,
        *,
        owner: JSON,
        key_id: str,
        private_key: Ed25519PrivateKey,
        keys: KeyRing,
        journal: JournalStore,
        clock: Callable[[], str],
        extension: JournalExtension | None,
    ) -> None:
        validate("common.schema.json", owner, "Owner")
        _require(journal.owner == owner, "workflow journal custody owner changed")
        self.owner, self.key_id = copy.deepcopy(owner), key_id
        self.private_key, self.keys, self.journal = private_key, keys, journal
        self.clock, self.extension = clock, extension
        self.generation = 0
        self._recovery_state: JSON = {}
        self._lock = threading.RLock()
        self._records: dict[str, JSON] = {}
        self._command_sizes: dict[str, int] = {}
        self._head_record: JSON | None = None
        self._journal_head = journal.head
        self._failed = False
        self.state = "prepared"
        self._cancelled = False

    def _authorize(self, principal: str, action: str) -> None:
        raise NotImplementedError

    def _sign(self, body: JSON, record_id: str) -> JSON:
        record = {
            "format": "fishhat.workflow-journal/v1",
            "kind": "WorkflowJournalRecord",
            "id": record_id,
            "owner": copy.deepcopy(self.owner),
            "workflow_id": self.workflow_id,
            "key_id": self.key_id,
            "body": copy.deepcopy(body),
        }
        signature = self.private_key.sign(PREFIX + canonical(record))
        return {**record, "signature": base64.b64encode(signature).decode("ascii")}

    def _outcome(self, command: JSON, body: JSON) -> JSON:
        return self._sign({**body, "command_digest": digest(command)}, command["id"])

    def _verify(self, record: JSON, expected_owner: JSON | None = None) -> None:
        verify_journal_record(
            record, self.keys, expected_owner=expected_owner, expected_workflow_id=self.workflow_id
        )

    def _command(self, action: str, event_id: str, payload: JSON) -> JSON:
        return {
            "id": event_id,
            "workflow_id": self.workflow_id,
            "action": action,
            "payload": payload,
        }

    def _replay(self, command: JSON) -> JSON | None:
        old = self.journal.lookup(command["id"], read_authorized=True)
        if old is None:
            return None
        _require(old["request"] == command, "workflow journal request ID changed accepted input")
        return cast(JSON, copy.deepcopy(old["outcome"]))

    def _commit(self, command: JSON, outcome: JSON) -> JSON:
        validate("workflow-journal.schema.json", outcome, "JournalRecord")
        _require(
            outcome["owner"] == self.owner
            and outcome["workflow_id"] == self.workflow_id
            and outcome["id"] == command["id"],
            "workflow journal outcome receiver or identity changed",
        )
        _require(
            outcome["body"].get("command_digest") == digest(command),
            "workflow journal outcome does not commit exact input",
        )
        try:
            self.journal.append(command["id"], command, outcome, expected_head=self._journal_head)
            self._journal_head = self.journal.head
            self._apply_event(command, outcome)
            self._records[outcome["id"]] = copy.deepcopy(outcome)
            self._command_sizes[outcome["id"]] = len(canonical(command))
            self._head_record = self._records[outcome["id"]]
        except BaseException:
            self._failed = True
            raise
        return copy.deepcopy(outcome)

    def _initialize(self, command: JSON, outcome: JSON, principal: str) -> None:
        self._authorize(principal, "read")
        with self._lock, self.journal.guard(self._journal_head):
            self._initialize_locked(command, outcome, principal)

    def _initialize_locked(self, command: JSON, outcome: JSON, principal: str) -> None:
        found = False
        for event in self.journal.iter_events(read_authorized=True):
            request, result = event["request"], event["outcome"]
            self._verify(result, self.owner)
            _require(
                result["id"] == request["id"]
                and result["body"].get("command_digest") == digest(request),
                "workflow journal retained event commitment changed",
            )
            if not found:
                _require(request == command, "workflow journal immutable initialization changed")
                _require(
                    result["body"] == outcome["body"],
                    "workflow journal independently approved initialization changed",
                )
                found = True
            self._apply_event(request, result)
            self._records[result["id"]] = result
            self._command_sizes[result["id"]] = len(canonical(request))
            self._head_record = result
        self._journal_head = self.journal.head
        if not found:
            self._authorize(principal, "initialize")
            self._commit(command, outcome)

    def _apply_event(self, command: JSON, outcome: JSON) -> None:
        raise NotImplementedError

    def _fresh(
        self, payload: JSON, principal: str, *, driver: bool = True, settlement: bool = False
    ) -> None:
        _require(
            payload.get("expected_generation") == self.generation,
            "workflow journal generation changed",
        )
        _require(payload.get("driver_term") == self.driver_term, "workflow driver term changed")
        if not settlement:
            self._new_work_allowed()
        if driver:
            _require(principal == self.driver_principal, "workflow driver principal changed")

    def _new_work_allowed(self) -> None:
        _require(
            self.state in {"prepared", "active"} and not self._cancelled,
            "workflow local admission is paused or cancelled",
        )
        _require(
            not self.extension or not self.extension.blocks_work(self),
            "workflow admission is frozen by transfer or recovery",
        )

    def _run(self, command: JSON, principal: str) -> JSON:
        _fields(command, {"id", "workflow_id", "action", "payload"})
        validate("common.schema.json", command["id"], "UUID")
        _require(command["workflow_id"] == self.workflow_id, "workflow command identity changed")
        _require(isinstance(command["payload"], dict), "workflow command payload must be an object")
        with self._lock:
            _require(
                not self._failed,
                "workflow journal requires cold restoration after failed persistence",
            )
            self._authorize(principal, "read")
            command = copy.deepcopy(command)
            retained = self._replay(command)
            if retained is not None:
                return retained
            with self.journal.guard(self._journal_head):
                validate("workflow-journal.schema.json", command, "Command")
                self._authorize(principal, command["action"])
                outcome = self._accept(command, principal)
                return self._commit(command, outcome)

    def _accept(self, command: JSON, principal: str) -> JSON:
        raise NotImplementedError

    def _lifecycle_outcome(
        self,
        command: JSON,
        principal: str,
        observe: Callable[[str, JSON], JSON] | None,
    ) -> JSON:
        action, payload = command["action"], command["payload"]
        _fields(payload, {"expected_generation", "driver_term"})
        self._fresh(payload, principal, settlement=True)
        _require(observe is not None, "workflow lifecycle native authority is unavailable")
        _require(
            self.phase != PHASES[self.header["procedure"]][-1],
            "terminal workflow cannot change lifecycle",
        )
        _require(not self._cancelled, "workflow cancellation is a retained admission tombstone")
        if action == "resume":
            _require(self.state == "paused", "only a paused workflow can resume")
            _require(
                not self.extension or not self.extension.blocks_work(self),
                "frozen workflow cannot resume admission",
            )
        assert observe is not None
        evidence = observe(action, self.snapshot(principal=principal))
        _fields(
            evidence,
            {
                "action",
                "owner",
                "workflow_id",
                "admission_closed",
                "holds_digest",
                "accepted_digest",
                "generation",
            },
        )
        _require(
            evidence["action"] == action
            and evidence["owner"] == self.owner
            and evidence["workflow_id"] == self.workflow_id
            and evidence["admission_closed"] is (action != "resume"),
            "workflow lifecycle native disposition changed",
        )
        _require(
            type(evidence["generation"]) is int and evidence["generation"] >= 0,
            "workflow lifecycle native generation invalid",
        )
        validate("common.schema.json", evidence["holds_digest"], "MaterialDigest")
        validate("common.schema.json", evidence["accepted_digest"], "MaterialDigest")
        return self._outcome(
            command,
            {
                "type": "lifecycle",
                "header_digest": self.header_digest,
                "action": action,
                "state": {"pause": "paused", "resume": "active", "cancel": "cancelled"}[action],
                "evidence": evidence,
                "generation": self.generation + 1,
            },
        )

    def _apply_lifecycle(self, outcome: JSON) -> None:
        self.state = outcome["body"]["state"]
        self._cancelled = self._cancelled or self.state == "cancelled"
        self.generation += 1

    @bounds(
        _declaration(
            "get", "O(B) exact indexed selected record bytes, independent of retained history"
        )
    )
    def record(self, record_id: str, *, principal: str) -> JSON:
        self._authorize(principal, "read")
        record = self._records.get(record_id)
        _require(record is not None, "workflow journal record is not retained")
        assert record is not None
        return copy.deepcopy(record)

    @bounds(
        _declaration(
            "replay-reference",
            "O(1) bounded command identity and digest lookup; retained proposal, command and outcome bytes are not materialized",
        )
    )
    def replay_reference(self, reference: JSON, *, principal: str) -> str | None:
        """Resolve an accepted staged command without requiring its old staging."""
        validate("workflow-journal.schema.json", reference, "InputReference")
        _require(
            reference["owner"] == reference["input"]["owner"] == self.owner
            and reference["workflow_id"] == self.workflow_id,
            "workflow replay reference receiver changed",
        )
        self._authorize(principal, "read")
        record = self._records.get(reference["command_id"])
        if record is None:
            return None
        _require(
            record["body"]["command_digest"] == reference["input"]["digest"]
            and self._command_sizes[record["id"]] == reference["input"]["size"],
            "workflow journal request ID changed accepted input",
        )
        return str(record["id"])

    def snapshot(self, *, principal: str) -> JSON:
        self._authorize(principal, "read")
        return {
            "owner": copy.deepcopy(self.owner),
            "workflow_id": self.workflow_id,
            "header_digest": self.header_digest,
            "generation": self.generation,
            "driver_principal": self.driver_principal,
            "driver_term": self.driver_term,
            "phase": self.phase,
            "state": self.state,
            "head": None if self._head_record is None else self._head_record["id"],
        }


def _reservation(
    reservation: JSON,
    *,
    owner: JSON,
    round: JSON,
    participants: list[JSON],
    children: Mapping[bytes, tuple[JSON, JSON]],
    ready: Mapping[bytes, JSON],
    outcomes: Mapping[bytes, JSON] | None,
    header: JSON,
    keys: KeyRing,
    now: str,
) -> None:
    """Validate one issuer's complete phase proof; never inspect peer history."""
    _fields(
        reservation,
        {
            "id",
            "generation",
            "round_id",
            "owner",
            "participants",
            "issued_at",
            "expires_at",
            "protection",
        },
    )
    _require(
        reservation["protection"] == "durable-until-verified-release",
        "workflow reservation is not durable dependent-effect protection",
    )
    validate("common.schema.json", reservation["id"], "UUID")
    _require(
        reservation["owner"] == owner and reservation["round_id"] == round["round_id"],
        "workflow reservation owner or round changed",
    )
    _require(
        type(reservation["generation"]) is int and reservation["generation"] >= 0,
        "workflow reservation generation invalid",
    )
    _require(
        _time(reservation["issued_at"]) <= _time(now) < _time(reservation["expires_at"]),
        "workflow reservation is not current",
    )
    phases = PHASES[header["procedure"]]
    destination = phases.index(round["to_phase"])
    requirements = REQUIREMENTS[header["procedure"]]
    expected = {_pair(item["owner"], item["resource"]): item for item in participants}
    seen: set[bytes] = set()
    for proof in reservation["participants"]:
        _fields(
            proof,
            {
                "owner",
                "resource",
                "resource_generation",
                "operations",
                "native_evidence",
                "expires_at",
            },
        )
        key = _pair(proof["owner"], proof["resource"])
        _require(
            key in expected and key not in seen, "workflow reservation participant closure changed"
        )
        seen.add(key)
        participant = expected[key]
        _require(
            type(proof["resource_generation"]) is int
            and proof["resource_generation"] >= participant["expected_generation"],
            "workflow participant generation regressed",
        )
        _require(
            _time(reservation["expires_at"]) <= _time(proof["expires_at"]),
            "workflow reservation exceeds native evidence validity",
        )
        required = {
            _key({"owner": owner, "request_id": binding["request_id"]}): binding
            for binding in participant["requests"]
            if phases.index(binding["phase"]) < destination
        }
        observed: set[bytes] = set()
        for result in proof["operations"]:
            _fields(result, {"child", "operation"})
            child = _key(result["child"])
            _require(
                child in required and child not in observed and child in ready,
                "workflow reservation child closure changed",
            )
            observed.add(child)
            binding = ready[child]
            _require(child in children, "workflow child is not installed")
            completion = destination >= phases.index(
                requirements["child_completion"][binding["phase"]]
            )
            _child_outcome(
                result,
                participant,
                binding,
                {"id": header["workflow_id"], "type": header["procedure"]},
                completion_required=completion,
                recovery_readers=None,
            )
            _verify_operation(
                result["operation"],
                bound_plan(binding),
                keys,
                header["workflow_id"]
                if "completed" not in binding
                else result["operation"]["witness"]["workflow_id"],
            )
            if outcomes is not None:
                _require(
                    outcomes.get(child) == result["operation"],
                    "workflow native proof changed retained child outcome",
                )
        _require(observed == required.keys(), "workflow reservation omitted required child outcome")
        evidence_ids: set[str] = set()
        _require(
            bool(proof["native_evidence"]),
            "workflow installed native obligation has no retained evidence",
        )
        for handle in proof["native_evidence"]:
            validate("common.schema.json", handle, "Handle")
            _require(
                handle["owner"] == owner and handle["id"] not in evidence_ids,
                "workflow native evidence custody changed",
            )
            evidence_ids.add(handle["id"])
    _require(seen == expected.keys(), "workflow reservation omitted native participant")


class WorkflowGate(_JournalTarget):
    """One finite owner validates the manifest and aggregates each issuer once."""

    @bounds(
        _declaration(
            "gate-initialize",
            "O(B + N + E + H) full manifest partition and one cold journal replay",
        )
    )
    def __init__(
        self,
        proposal: JSON,
        *,
        owner: JSON,
        key_id: str,
        private_key: Ed25519PrivateKey,
        member_keys: KeyRing,
        authorize: Callable[[str, str, JSON], None],
        check_reservation: Callable[[JSON, JSON, JSON], None],
        journal: JournalStore,
        principal: str,
        clock: Callable[[], str] = _now,
        extension: JournalExtension | None = None,
        lifecycle: Callable[[str, JSON], JSON] | None = None,
        recovery_context: RecoveryContext | None = None,
        command: JSON | None = None,
    ) -> None:
        self.authorize, self.check_reservation = authorize, check_reservation
        self.lifecycle = lifecycle
        keys: KeyRing = _KeyOverlay(
            {(canonical(owner), key_id): private_key.public_key()}, member_keys
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
        _require(
            recovery_context is None or extension is not None,
            "workflow successor requires independently installed recovery validation",
        )
        validate_workflow_proposal(proposal, recovery=recovery_context is not None)
        self.proposal = copy.deepcopy(proposal)
        self.workflow_id = proposal["workflow_id"]
        self.header = {
            "workflow_id": self.workflow_id,
            "proposal_digest": digest(proposal),
            "procedure": proposal["type"],
            "requirements_digest": digest(REQUIREMENTS[proposal["type"]]),
            "gate_owner": copy.deepcopy(owner),
            "gate_key_id": key_id,
            "driver_principal": proposal["initial_driver"]["principal"],
            "driver_term": 1,
            "owner_count": len({canonical(p["owner"]) for p in proposal["participants"]}),
        }
        self.header_digest = digest(self.header)
        self.driver_principal, self.driver_term = self.header["driver_principal"], 1
        self.phase = PHASES[proposal["type"]][0]
        self._members: dict[bytes, JSON] = {}
        self._projections: dict[bytes, JSON] = {}
        logical_members: dict[bytes, list[bytes]] = {}
        self.generations = {
            _pair(p["owner"], p["resource"]): p["expected_generation"]
            for p in proposal["participants"]
        }
        self.children = proposal_children(proposal)
        self.ready = {
            key: binding
            for key, (_, binding) in self.children.items()
            if "plan" in binding or "completed" in binding
        }
        self._known_outcomes: dict[bytes, JSON] = {
            key: binding["completed"]["operation"]
            for key, binding in self.ready.items()
            if "completed" in binding
        }
        self.phase_windows: dict[str, tuple[int, int | None]] = {}
        for participant in proposal["participants"]:
            member = canonical(participant["owner"])
            if member not in self._members:
                self._members[member] = participant["owner"]
                logical = canonical([participant["owner"]["tool"], participant["owner"]["id"]])
                logical_members.setdefault(logical, []).append(member)
                self._projections[member] = {
                    "type": "projection",
                    "header": self.header,
                    "owner": participant["owner"],
                    "participants": [],
                    "content": [],
                    "dependencies": [],
                }
            self._projections[member]["participants"].append(participant)
            for binding in participant["requests"]:
                intent = binding.get("intent", {})
                for name in ("predecessor", "issuer", "publication"):
                    dependency = intent.get(name)
                    if dependency is not None and dependency["owner"] != participant["owner"]:
                        self._projections[member]["dependencies"].append(dependency)
        for handle in proposal["content"]:
            member = canonical(handle["owner"])
            if member not in self._members and recovery_context is not None:
                logical = canonical([handle["owner"]["tool"], handle["owner"]["id"]])
                candidates = logical_members.get(logical, [])
                _require(
                    len(candidates) == 1,
                    "historical workflow material has no unique approved successor custodian",
                )
                member = candidates[0]
            _require(member in self._members, "workflow material owner is not a participant")
            self._projections[member]["content"].append(handle)
        self._projection_digests = {
            member: digest(value) for member, value in self._projections.items()
        }
        self._prepared: dict[bytes, JSON] = {}
        self._agreement: JSON | None = None
        self._round: JSON | None = None
        self._votes: dict[bytes, JSON] = {}
        self._certificates: dict[bytes, JSON] = {}
        self._round_sources: dict[str, JSON] = {}
        self._decision: JSON | None = None
        self._remaining = len(self._members)
        self._evidence_digest = digest([])
        self._earliest_expiry: str | None = None
        if recovery_context is not None:
            assert extension is not None
            extension.initialize_gate(self, proposal, recovery_context)
        command = command or self._command(
            "gate.create", _identity("gate-init", self.workflow_id, owner), {"proposal": proposal}
        )
        _require(
            command["action"] == "gate.create"
            and command["workflow_id"] == self.workflow_id
            and command["payload"] == {"proposal": proposal},
            "workflow gate initialization changed exact caller command",
        )
        self._initialize(
            command,
            self._outcome(
                command,
                {
                    "type": "initialized",
                    "header_digest": self.header_digest,
                    "recovery_digest": _recovery_digest(recovery_context),
                },
            ),
            principal,
        )

    def _authorize(self, principal: str, action: str) -> None:
        self.authorize(
            principal,
            action,
            {
                "owner": self.owner,
                "workflow_id": self.workflow_id,
                "header_digest": self.header_digest,
                "driver_principal": self.driver_principal,
                "driver_term": self.driver_term,
            },
        )

    def _accept(self, command: JSON, principal: str) -> JSON:
        action, payload = command["action"], command["payload"]
        if action in {"pause", "resume", "cancel"}:
            return self._lifecycle_outcome(command, principal, self.lifecycle)
        if action == "projection":
            _fields(payload, {"owner"})
            member = canonical(payload["owner"])
            _require(member in self._projections, "workflow member is not in manifest")
            return self._outcome(command, self._projections[member])
        if action == "preparation":
            _fields(payload, {"preparation"})
            record = payload["preparation"]
            self._verify(record)
            member, body = canonical(record["owner"]), record["body"]
            _require(
                member in self._members and member not in self._prepared,
                "workflow preparation issuer absent or already accepted",
            )
            _require(
                body.get("type") == "preparation"
                and body.get("header_digest") == self.header_digest
                and body.get("projection_digest") == self._projection_digests[member]
                and body.get("driver_term") == self.driver_term,
                "workflow preparation agreement changed",
            )
            return self._outcome(
                command,
                {
                    "type": "preparation-accepted",
                    "member": record["owner"],
                    "preparation_digest": digest(record),
                },
            )
        if action == "agreement":
            _fields(payload, set())
            _require(
                len(self._prepared) == len(self._members), "workflow preparation closure incomplete"
            )
            _require(self._agreement is None, "workflow agreement already retained")
            return self._outcome(
                command,
                {
                    "type": "agreement",
                    "header_digest": self.header_digest,
                    "owner_count": len(self._members),
                    "driver_term": self.driver_term,
                },
            )
        if action in {"round", "settle"}:
            _fields(payload, {"expected_generation", "driver_term", "to_phase"}, {"supersedes"})
            self._fresh(
                payload, principal, driver=action != "settle", settlement=action == "settle"
            )
            _require(self._agreement is not None, "workflow has no complete preparation agreement")
            phases = PHASES[self.header["procedure"]]
            _require(payload["to_phase"] in phases, "workflow phase is not installed for procedure")
            current, destination = phases.index(self.phase), phases.index(payload["to_phase"])
            refresh = destination == current and current > 0
            _require(
                destination == current + 1 or refresh,
                "workflow phase is not adjacent or a current barrier refresh",
            )
            if action == "settle":
                _require(
                    destination == len(phases) - 1 and current >= len(phases) - 2,
                    "native workflow settlement is terminal only",
                )
            if self._round is not None and self._decision is None:
                _require(
                    payload.get("supersedes") == self._round["body"]["round_id"],
                    "workflow open round requires exact supersession",
                )
            if action != "settle" and self._decision is not None:
                _require(
                    len(self._certificates) == len(self._members),
                    "workflow decision lacks durably minted member certificates",
                )
            return self._outcome(
                command,
                {
                    "type": "round",
                    "header_digest": self.header_digest,
                    "round_id": command["id"],
                    "sequence": destination,
                    "from_phase": phases[destination - 1],
                    "to_phase": phases[destination],
                    "authority": "native-owner" if action == "settle" else "driver",
                    "driver_term": None if action == "settle" else self.driver_term,
                    "requirements_digest": self.header["requirements_digest"],
                },
            )
        if action == "vote":
            _fields(payload, {"vote"})
            record = payload["vote"]
            self._verify(record)
            body, member = record["body"], canonical(record["owner"])
            _require(
                self._round is not None and self._decision is None,
                "workflow round is not accepting votes",
            )
            assert self._round is not None
            round = self._round["body"]
            if round["authority"] == "driver":
                self._new_work_allowed()
            _require(
                member in self._members and member not in self._votes,
                "workflow vote issuer absent or duplicated",
            )
            _require(
                body.get("type") == "vote"
                and body.get("header_digest") == self.header_digest
                and body.get("projection_digest") == self._projection_digests[member]
                and body.get("round_digest") == digest(self._round),
                "workflow vote common subject changed",
            )
            _reservation(
                body["reservation"],
                owner=record["owner"],
                round=round,
                participants=self._projections[member]["participants"],
                children=self.children,
                ready=self.ready,
                outcomes=None,
                header=self.header,
                keys=self.keys,
                now=self.clock(),
            )
            self.check_reservation(record["owner"], body["reservation"], round)
            for proof in body["reservation"]["participants"]:
                for result in proof["operations"]:
                    _known_outcome(
                        self._known_outcomes.get(_key(result["child"])), result["operation"]
                    )
            return self._outcome(
                command,
                {
                    "type": "vote-accepted",
                    "round_id": round["round_id"],
                    "member": record["owner"],
                    "vote_digest": digest(record),
                },
            )
        if action == "decision":
            _fields(payload, set())
            _require(
                self._round is not None and self._remaining == 0 and self._decision is None,
                "workflow complete vote closure is unavailable",
            )
            assert self._round is not None and self._earliest_expiry is not None
            _require(
                _time(self.clock()) < _time(self._earliest_expiry),
                "workflow complete proof closure expired",
            )
            round = self._round["body"]
            if round["authority"] == "driver":
                self._new_work_allowed()
            return self._outcome(
                command,
                {
                    "type": "decision",
                    "header_digest": self.header_digest,
                    "round_id": round["round_id"],
                    "round_digest": digest(self._round),
                    "sequence": round["sequence"],
                    "from_phase": round["from_phase"],
                    "to_phase": round["to_phase"],
                    "authority": round["authority"],
                    "driver_term": round["driver_term"],
                    "evidence_digest": self._evidence_digest,
                    "owner_count": len(self._members),
                    "expires_at": self._earliest_expiry,
                },
            )
        if action == "certificate":
            _fields(payload, {"owner", "round_id"})
            member = canonical(payload["owner"])
            source = self._round_sources.get(payload["round_id"])
            _require(
                source is not None and source["decision"] is not None and member in source["votes"],
                "workflow complete decision is unavailable",
            )
            assert source is not None
            _require(
                member not in source["certificates"],
                "workflow certificate round changed or member certificate already retained",
            )
            vote = source["votes"][member]
            reservation = vote["body"]["reservation"]
            return self._outcome(
                command,
                {
                    "type": "certificate",
                    "header_digest": self.header_digest,
                    "member": payload["owner"],
                    "projection_digest": self._projection_digests[member],
                    "decision": source["decision"],
                    "vote_digest": digest(vote),
                    "member_generation": vote["body"]["member_generation"],
                    "reservation_id": reservation["id"],
                    "reservation_generation": reservation["generation"],
                },
            )
        if action == "bind":
            _fields(payload, {"expected_generation", "driver_term", "request"})
            self._fresh(payload, principal)
            request = payload["request"]
            validate("workflow.schema.json", request, "BindRequest")
            _require(
                request["workflow_id"] == self.workflow_id
                and request["driver_term"] == self.driver_term
                and request["expected_generation"] == self.generation,
                "workflow binding generation or identity changed",
            )
            _require(
                request["owner"] == self.owner and request["bind_id"] == command["id"],
                "workflow binding receiver or request identity changed",
            )
            phases = PHASES[self.header["procedure"]]
            _require(
                phases.index(self.phase)
                in {
                    phases.index(request["binding"]["phase"]) - 1,
                    phases.index(request["binding"]["phase"]),
                },
                "workflow binding outside installed phase",
            )
            _binding_shape(
                request,
                {"id": self.workflow_id, "type": self.header["procedure"]},
                self.ready,
                children=self.children,
                generations=self.generations,
                phase_windows=self.phase_windows,
                recovery_readers=None,
            )
            _verify_plan(request["binding"]["plan"], self.keys)
            for operation in request["predecessors"]:
                slot = self.children[_key(request["child"])][1]
                key = _key(_predecessor(slot["intent"]))
                _require(key in self.ready, "workflow predecessor Plan is absent")
                _verify_operation(
                    operation,
                    bound_plan(self.ready[key]),
                    self.keys,
                    self.workflow_id
                    if "completed" not in self.ready[key]
                    else operation["witness"]["workflow_id"],
                )
                _known_outcome(self._known_outcomes.get(key), operation)
            return self._outcome(
                command,
                {
                    "type": "binding",
                    "header_digest": self.header_digest,
                    "member": request["child"]["owner"],
                    "driver_term": self.driver_term,
                    "request": request,
                },
            )
        if self.extension is not None:
            return self.extension.outcome(self, command, principal)
        raise ContractError("unsupported workflow gate command")

    def _apply_event(self, command: JSON, outcome: JSON) -> None:
        action, payload, body = command["action"], command["payload"], outcome["body"]
        if action in {"gate.create", "projection"}:
            return
        if action == "certificate":
            self._round_sources[payload["round_id"]]["certificates"][
                canonical(payload["owner"])
            ] = outcome
            return
        if action in {"pause", "resume", "cancel"}:
            self._apply_lifecycle(outcome)
            return
        if action == "preparation":
            record = payload["preparation"]
            self._prepared[canonical(record["owner"])] = record
        elif action == "agreement":
            self._agreement = outcome
            if self.state == "prepared":
                self.state = "active"
        elif action in {"round", "settle"}:
            self._round, self._decision = outcome, None
            self._votes = {}
            self._certificates = {}
            self._round_sources[outcome["id"]] = {
                "round": outcome,
                "votes": self._votes,
                "decision": None,
                "certificates": self._certificates,
            }
            self._remaining = len(self._members)
            self._evidence_digest = digest([])
            self._earliest_expiry = None
        elif action == "vote":
            vote = payload["vote"]
            self._votes[canonical(vote["owner"])] = vote
            self._remaining -= 1
            self._evidence_digest = digest(
                {"previous": self._evidence_digest, "vote": digest(vote)}
            )
            expiry = vote["body"]["reservation"]["expires_at"]
            if self._earliest_expiry is None or _time(expiry) < _time(self._earliest_expiry):
                self._earliest_expiry = expiry
            for proof in vote["body"]["reservation"]["participants"]:
                for result in proof["operations"]:
                    self._known_outcomes[_key(result["child"])] = result["operation"]
        elif action == "decision":
            self._decision = outcome
            self._round_sources[body["round_id"]]["decision"] = outcome
            previous = self.phase
            self.phase = body["to_phase"]
            if self.phase == PHASES[self.header["procedure"]][-1] and not self._cancelled:
                self.state = "completed"
            if self.phase != previous:
                if previous in self.phase_windows:
                    self.phase_windows[previous] = (
                        self.phase_windows[previous][0],
                        self.generation + 1,
                    )
                self.phase_windows[self.phase] = (self.generation + 1, None)
        elif action == "bind":
            request = payload["request"]
            self.ready[_key(request["child"])] = request["binding"]
            for operation in request["predecessors"]:
                slot = self.children[_key(request["child"])][1]
                key = _key(_predecessor(slot["intent"]))
                self._known_outcomes[key] = operation
        elif self.extension is not None:
            self.extension.apply(self, command, outcome)
            return
        else:
            raise ContractError("unknown retained workflow gate event")
        self.generation += 1

    def projection(self, owner: JSON, *, principal: str, event_id: str | None = None) -> JSON:
        return self._run(
            self._command(
                "projection",
                event_id or _identity("projection", self.workflow_id, owner),
                {"owner": owner},
            ),
            principal,
        )

    def accept_preparation(self, event_id: str, preparation: JSON, *, principal: str) -> JSON:
        return self._run(
            self._command("preparation", event_id, {"preparation": preparation}), principal
        )

    def agreement(self, *, principal: str, event_id: str | None = None) -> JSON:
        return self._run(
            self._command("agreement", event_id or _identity("agreement", self.workflow_id), {}),
            principal,
        )

    def begin_round(
        self, event_id: str, to_phase: str, *, principal: str, supersedes: str | None = None
    ) -> JSON:
        payload: JSON = {
            "expected_generation": self.generation,
            "driver_term": self.driver_term,
            "to_phase": to_phase,
        }
        if supersedes is not None:
            payload["supersedes"] = supersedes
        return self._run(self._command("round", event_id, payload), principal)

    def accept_vote(self, event_id: str, vote: JSON, *, principal: str) -> JSON:
        return self._run(self._command("vote", event_id, {"vote": vote}), principal)

    def decision(self, *, principal: str, event_id: str | None = None) -> JSON:
        _require(self._round is not None, "workflow round is absent")
        assert self._round is not None
        return self._run(
            self._command(
                "decision",
                event_id or _identity("decision", self.workflow_id, self._round["id"]),
                {},
            ),
            principal,
        )

    def certificate(self, owner: JSON, *, principal: str, event_id: str | None = None) -> JSON:
        _require(self._round is not None, "workflow round is absent")
        assert self._round is not None
        return self._run(
            self._command(
                "certificate",
                event_id or _identity("certificate", self.workflow_id, self._round["id"], owner),
                {"owner": owner, "round_id": self._round["id"]},
            ),
            principal,
        )


class WorkflowMember(_JournalTarget):
    """One independently authorized local projection and native admission journal."""

    @bounds(
        _declaration(
            "member-initialize",
            "O(L + E + H) exact local projection, incoming dependency bytes and one cold replay",
        )
    )
    def __init__(
        self,
        signed_projection: JSON,
        *,
        owner: JSON,
        key_id: str,
        private_key: Ed25519PrivateKey,
        enrollment: GateEnrollment,
        operation_keys: KeyRing,
        native: NativeWorkflowContext,
        journal: JournalStore,
        principal: str,
        clock: Callable[[], str] = _now,
        extension: JournalExtension | None = None,
        recovery_context: RecoveryContext | None = None,
        command: JSON | None = None,
    ) -> None:
        self.native, self.enrollment = native, enrollment
        keys: KeyRing = _KeyOverlay(
            {
                (
                    canonical(enrollment.gate_owner),
                    enrollment.gate_key_id,
                ): enrollment.gate_public_key,
                (canonical(owner), key_id): private_key.public_key(),
            },
            operation_keys,
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
        self.workflow_id = enrollment.workflow_id
        validate("common.schema.json", enrollment.grant_id, "UUID")
        self._verify(signed_projection, enrollment.gate_owner)
        body = signed_projection["body"]
        projection = {key: value for key, value in body.items() if key != "command_digest"}
        _fields(projection, {"type", "header", "owner", "participants", "content", "dependencies"})
        self.header = copy.deepcopy(projection["header"])
        self.header_digest = digest(self.header)
        _require(
            projection["type"] == "projection"
            and projection["owner"] == owner == enrollment.member_owner
            and digest(projection) == enrollment.projection_digest,
            "workflow local projection is not independently approved",
        )
        _require(
            self.header["workflow_id"] == self.workflow_id
            and self.header["proposal_digest"] == enrollment.proposal_digest
            and self.header["gate_owner"] == enrollment.gate_owner
            and self.header["gate_key_id"] == enrollment.gate_key_id,
            "workflow gate enrollment changed",
        )
        _require(
            bool(enrollment.grant_id)
            and self.header["requirements_digest"]
            == digest(REQUIREMENTS[self.header["procedure"]]),
            "workflow requirements or independent gate grant changed",
        )
        self.signed_projection, self.projection = (
            copy.deepcopy(signed_projection),
            copy.deepcopy(projection),
        )
        self.projection_digest = enrollment.projection_digest
        self.driver_principal, self.driver_term = (
            self.header["driver_principal"],
            self.header["driver_term"],
        )
        self.phase = PHASES[self.header["procedure"]][0]
        self.children: dict[bytes, tuple[JSON, JSON]] = {}
        self.ready: dict[bytes, JSON] = {}
        self._binding_content: dict[bytes, list[JSON]] = {}
        self._content_by_digest: dict[tuple[bytes, str], JSON] = {}
        self._content_by_identity: dict[bytes, JSON] = {}
        historical_content = (
            {canonical(handle) for handle in recovery_context.projection["body"]["origin_content"]}
            if recovery_context is not None and recovery_context.projection is not None
            else set()
        )
        for handle in self.projection["content"]:
            _require(
                handle["owner"] == self.owner or canonical(handle) in historical_content,
                "workflow projection contains foreign custody",
            )
            self._content_by_digest[(canonical(handle["owner"]), handle["digest"])] = handle
            self._content_by_identity[canonical([handle["owner"], handle["id"]])] = handle
        for participant in self.projection["participants"]:
            _require(
                participant["owner"] == owner, "workflow projection contains foreign participant"
            )
            for binding in participant["requests"]:
                key = _key({"owner": owner, "request_id": binding["request_id"]})
                _require(key not in self.children, "workflow projection duplicates a child")
                self.children[key] = (participant, binding)
                if "plan" in binding or "completed" in binding:
                    plan = bound_plan(binding)
                    _verify_plan(plan, self.keys)
                    self.ready[key] = binding
                    selected: dict[bytes, JSON] = {}
                    for content_digest in plan["input_digests"]:
                        content_key = (canonical(plan["owner"]), content_digest)
                        _require(
                            content_key in self._content_by_digest,
                            "workflow local Plan input custody absent",
                        )
                        handle = self._content_by_digest[content_key]
                        selected[canonical([handle["owner"], handle["id"]])] = handle
                    for handle in _handles(binding):
                        handle_key = canonical([handle["owner"], handle["id"]])
                        _require(
                            self._content_by_identity.get(handle_key) == handle,
                            "workflow local handle custody changed",
                        )
                        selected[handle_key] = handle
                    self._binding_content[key] = list(selected.values())
        self._preparation: JSON | None = None
        self._agreement: JSON | None = None
        self._vote: JSON | None = None
        self._round: JSON | None = None
        self._certificate: JSON | None = None
        self._reservation: JSON | None = None
        self._admissions: dict[bytes, JSON] = {}
        self.outcomes: dict[bytes, JSON] = {}
        _require(
            recovery_context is None or extension is not None,
            "workflow successor requires independently installed recovery validation",
        )
        if recovery_context is not None:
            assert extension is not None
            extension.initialize_member(self, self.projection, recovery_context)
        command = command or self._command(
            "member.join",
            _identity("member-init", self.workflow_id, owner),
            {"projection": signed_projection},
        )
        _require(
            command["action"] == "member.join"
            and command["workflow_id"] == self.workflow_id
            and command["payload"] == {"projection": signed_projection},
            "workflow member initialization changed exact caller command",
        )
        self._initialize(
            command,
            self._outcome(
                command,
                {
                    "type": "initialized",
                    "header_digest": self.header_digest,
                    "projection_digest": self.projection_digest,
                    "grant_id": enrollment.grant_id,
                    "recovery_digest": _recovery_digest(recovery_context),
                },
            ),
            principal,
        )

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

    def _gate_record(self, record: JSON, kind: str) -> JSON:
        self._verify(record, self.enrollment.gate_owner)
        body = record["body"]
        _require(
            record["key_id"] == self.enrollment.gate_key_id
            and body.get("type") == kind
            and body.get("header_digest") == self.header_digest,
            "workflow approved gate subject changed",
        )
        return cast(JSON, body)

    def _accept(self, command: JSON, principal: str) -> JSON:
        action, payload = command["action"], command["payload"]
        if action in {"pause", "resume", "cancel"}:
            return self._lifecycle_outcome(command, principal, self.native.lifecycle)
        if action == "prepare":
            _fields(payload, {"expected_generation", "driver_term"})
            self._fresh(payload, principal)
            _require(self._preparation is None, "workflow local preparation already retained")
            self.native.prepare(self.projection, self.enrollment)
            return self._outcome(
                command,
                {
                    "type": "preparation",
                    "header_digest": self.header_digest,
                    "projection_digest": self.projection_digest,
                    "driver_term": self.driver_term,
                    "grant_id": self.enrollment.grant_id,
                },
            )
        if action == "agreement":
            _fields(payload, {"agreement"})
            body = self._gate_record(payload["agreement"], "agreement")
            _require(
                self._preparation is not None
                and self._agreement is None
                and body["driver_term"] == self.driver_term
                and body["owner_count"] == self.header["owner_count"],
                "workflow preparation agreement is unavailable",
            )
            return self._outcome(
                command,
                {
                    "type": "agreement-accepted",
                    "header_digest": self.header_digest,
                    "agreement_digest": digest(payload["agreement"]),
                },
            )
        if action == "vote":
            _fields(payload, {"expected_generation", "driver_term", "round"})
            round = self._gate_record(payload["round"], "round")
            self._fresh(
                payload,
                principal,
                driver=round["authority"] != "native-owner",
                settlement=round["authority"] == "native-owner",
            )
            _require(self._agreement is not None, "workflow complete preparation agreement absent")
            phases = PHASES[self.header["procedure"]]
            _require(
                round["to_phase"] in phases and round["from_phase"] in phases,
                "workflow round phase is not installed",
            )
            destination, current = phases.index(round["to_phase"]), phases.index(self.phase)
            _require(
                round["driver_term"]
                == (None if round["authority"] == "native-owner" else self.driver_term)
                and round["requirements_digest"] == self.header["requirements_digest"]
                and round["sequence"] == destination
                and round["from_phase"] == phases[destination - 1]
                and destination in {current, current + 1}
                and destination > 0,
                "workflow round phase or term changed",
            )
            _require(
                round["authority"] in {"driver", "native-owner"}
                and (round["authority"] != "native-owner" or destination == len(phases) - 1),
                "workflow native authority cannot start intermediate work",
            )
            reservation = self.native.reserve(round, self.projection["participants"], self.outcomes)
            _reservation(
                reservation,
                owner=self.owner,
                round=round,
                participants=self.projection["participants"],
                children=self.children,
                ready=self.ready,
                outcomes=self.outcomes,
                header=self.header,
                keys=self.keys,
                now=self.clock(),
            )
            self.native.check(reservation, round)
            return self._outcome(
                command,
                {
                    "type": "vote",
                    "header_digest": self.header_digest,
                    "projection_digest": self.projection_digest,
                    "round_digest": digest(payload["round"]),
                    "member_generation": self.generation + 1,
                    "reservation": reservation,
                },
            )
        if action == "apply":
            _fields(payload, {"expected_generation", "driver_term", "certificate"})
            certificate = self._gate_record(payload["certificate"], "certificate")
            decision = self._gate_record(certificate["decision"], "decision")
            self._fresh(
                payload,
                principal,
                driver=decision["authority"] != "native-owner",
                settlement=decision["authority"] == "native-owner",
            )
            _require(
                self._vote is not None
                and self._round is not None
                and self._reservation is not None,
                "workflow local vote custody absent",
            )
            assert (
                self._vote is not None and self._round is not None and self._reservation is not None
            )
            _require(
                certificate["member"] == self.owner
                and certificate["projection_digest"] == self.projection_digest
                and certificate["vote_digest"] == digest(self._vote)
                and certificate["member_generation"] == self.generation
                and certificate["reservation_id"] == self._reservation["id"]
                and certificate["reservation_generation"] == self._reservation["generation"],
                "workflow certificate changed local reservation or generation",
            )
            round = self._round["body"]
            _require(
                decision["round_digest"] == digest(self._round)
                and decision["round_id"] == round["round_id"]
                and decision["from_phase"] == round["from_phase"]
                and decision["to_phase"] == round["to_phase"]
                and decision["authority"] == round["authority"]
                and decision["sequence"] == round["sequence"]
                and decision["driver_term"]
                == (None if decision["authority"] == "native-owner" else self.driver_term)
                and decision["owner_count"] == self.header["owner_count"],
                "workflow certificate common barrier changed",
            )
            _require(
                _time(self.clock()) < _time(decision["expires_at"]),
                "workflow phase certificate expired",
            )
            self.native.check(self._reservation, round)
            return self._outcome(
                command,
                {
                    "type": "applied",
                    "header_digest": self.header_digest,
                    "round_id": round["round_id"],
                    "phase": decision["to_phase"],
                    "generation": self.generation + 1,
                    "certificate_digest": digest(payload["certificate"]),
                },
            )
        if action == "bind":
            _fields(payload, {"expected_generation", "driver_term", "binding"})
            self._fresh(payload, principal)
            body = self._gate_record(payload["binding"], "binding")
            request = body["request"]
            key = _key(request["child"])
            _require(
                body["member"] == self.owner
                and body["driver_term"] == self.driver_term
                and request["child"]["owner"] == self.owner
                and key in self.children
                and key not in self.ready,
                "workflow binding is foreign or already retained",
            )
            slot = self.children[key][1]
            binding = request["binding"]
            _require(
                request["workflow_id"] == self.workflow_id
                and request["owner"] == self.enrollment.gate_owner
                and request["driver_term"] == self.driver_term
                and binding["request_id"] == slot["request_id"]
                and binding["phase"] == slot["phase"]
                and binding["plan"]["subject"]["action"] == child_action(slot),
                "workflow local binding changed immutable intent",
            )
            intent = slot["intent"]
            if intent["kind"] in {"reviewed-initial", "reviewed-successor"}:
                _require(
                    binding["plan"]["subject"] == intent["subject"],
                    "workflow local binding changed independently approved subject",
                )
            phases = PHASES[self.header["procedure"]]
            _require(
                phases.index(self.phase)
                in {phases.index(binding["phase"]) - 1, phases.index(binding["phase"])},
                "workflow local binding outside installed phase",
            )
            _verify_plan(request["binding"]["plan"], self.keys)
            review = self.native.bind(request)
            _selected_review(request, review)
            _require(
                _time(review["now"])
                <= _time(self.clock())
                < _time(request["binding"]["plan"]["expires_at"]),
                "workflow binding Plan is not currently valid",
            )
            return self._outcome(
                command,
                {
                    "type": "bound",
                    "header_digest": self.header_digest,
                    "child": request["child"],
                    "plan_digest": request["binding"]["plan"]["digest"],
                    "binding_digest": digest(payload["binding"]),
                    "generation": self.generation + 1,
                },
            )
        if action == "admit":
            _fields(payload, {"expected_generation", "driver_term", "child"})
            self._fresh(payload, principal)
            child, key = payload["child"], _key(payload["child"])
            _require(
                key in self.ready and key not in self._admissions,
                "workflow child is absent, unbound or already admitted",
            )
            binding = self.ready[key]
            _require(
                "completed" not in binding and binding["phase"] == self.phase,
                "workflow child is completed or outside its installed phase",
            )
            _require(
                self._certificate is not None
                and self._round is not None
                and self._reservation is not None,
                "workflow child has no applied protected barrier",
            )
            assert (
                self._certificate is not None
                and self._round is not None
                and self._reservation is not None
            )
            decision = self._certificate["body"]["decision"]["body"]
            _require(
                decision["round_id"] == self._round["id"]
                and _time(self.clock()) < _time(decision["expires_at"])
                and _time(self.clock()) < _time(self._reservation["expires_at"]),
                "workflow child applied barrier is stale or replaced",
            )
            self.native.check(self._reservation, self._round["body"])
            plan = bound_plan(binding)
            _require(not plan["blockers"], "workflow child Plan retains admission blockers")
            request = {
                "binding": binding,
                "content": self._binding_content[key],
                "predecessors": [],
                "materials": [],
            }
            review = self.native.admit(
                {
                    "workflow_id": self.workflow_id,
                    "child": child,
                    "request": request,
                    "reservation": self._reservation,
                    "phase": self.phase,
                    "driver_term": self.driver_term,
                }
            )
            _selected_review(request, review)
            _require(
                _time(review["now"]) <= _time(self.clock()) < _time(plan["expires_at"]),
                "workflow child Plan is not currently valid",
            )
            return self._outcome(
                command,
                {
                    "type": "admission",
                    "header_digest": self.header_digest,
                    "member": self.owner,
                    "child": child,
                    "plan_digest": plan["digest"],
                    "phase": self.phase,
                    "member_generation": self.generation + 1,
                    "driver_term": self.driver_term,
                    "authenticated_principal": principal,
                    "round_id": self._round["id"],
                    "certificate_id": self._certificate["id"],
                    "reservation_id": self._reservation["id"],
                    "reservation_generation": self._reservation["generation"],
                },
            )
        if action == "complete":
            _fields(payload, {"operation"})
            operation = payload["operation"]
            child = {"owner": operation["owner"], "request_id": operation["request_id"]}
            key = _key(child)
            _require(
                key in self._admissions and key in self.ready,
                "workflow child was not locally admitted",
            )
            binding, admission = self.ready[key], self._admissions[key]
            _verify_operation(operation, bound_plan(binding), self.keys, self.workflow_id)
            _require(
                _child_identity_matches(operation, child, binding, self.workflow_id)
                and operation["plan_digest"] == admission["body"]["plan_digest"]
                and operation["authenticated_principal"]
                == admission["body"]["authenticated_principal"],
                "workflow child admission identity changed",
            )
            previous = self.outcomes.get(key)
            if previous is not None:
                _require(
                    operation["id"] == previous["id"]
                    and operation["generation"] > previous["generation"],
                    "workflow child observation did not advance exact operation",
                )
                _require(
                    previous["state"] not in {"succeeded", "failed", "cancelled"},
                    "workflow terminal child outcome cannot be replaced",
                )
            if operation["result_handle"] is not None:
                data = self.native.result_payload(operation)
                _require(
                    isinstance(data, bytes),
                    "workflow result payload lacks independently retained custody",
                )
                assert isinstance(data, bytes)
                validate_result_payload(operation, data, max_bytes=len(data))
            return self._outcome(
                command,
                {
                    "type": "outcome",
                    "header_digest": self.header_digest,
                    "child": child,
                    "operation_id": operation["id"],
                    "operation_digest": digest(operation),
                    "generation": self.generation + 1,
                },
            )
        if self.extension is not None:
            return self.extension.outcome(self, command, principal)
        raise ContractError("unsupported workflow member command")

    def _apply_event(self, command: JSON, outcome: JSON) -> None:
        action, payload = command["action"], command["payload"]
        if action == "member.join":
            return
        if action in {"pause", "resume", "cancel"}:
            self._apply_lifecycle(outcome)
            return
        if action == "prepare":
            self._preparation = outcome
        elif action == "agreement":
            self._agreement = payload["agreement"]
            if self.state == "prepared":
                self.state = "active"
        elif action == "vote":
            self._vote, self._round = outcome, payload["round"]
            self._reservation = outcome["body"]["reservation"]
        elif action == "apply":
            self._certificate = payload["certificate"]
            self.phase = outcome["body"]["phase"]
            if self.phase == PHASES[self.header["procedure"]][-1] and not self._cancelled:
                self.state = "completed"
        elif action == "bind":
            request = payload["binding"]["body"]["request"]
            key = _key(request["child"])
            self.ready[key] = request["binding"]
            self._binding_content[key] = request["content"]
        elif action == "admit":
            self._admissions[_key(payload["child"])] = outcome
        elif action == "complete":
            operation = payload["operation"]
            self.outcomes[
                _key({"owner": operation["owner"], "request_id": operation["request_id"]})
            ] = operation
        elif self.extension is not None:
            self.extension.apply(self, command, outcome)
            return
        else:
            raise ContractError("unknown retained workflow member event")
        self.generation += 1

    def prepare(self, event_id: str, *, principal: str) -> JSON:
        return self._run(
            self._command(
                "prepare",
                event_id,
                {"expected_generation": self.generation, "driver_term": self.driver_term},
            ),
            principal,
        )

    @bounds(
        _declaration(
            "operation-admission",
            "O(B + E) exact retained local Plan, selected child permit and independently acquired native admission context; no peer or history traversal",
        )
    )
    def require_operation_admission(self, submission: JSON, *, principal: str) -> JSON:
        """Require the retained local permit at the normal operation.submit boundary.

        This performs no native acceptance. The owner resolves its accepted native
        request retry before calling it, and serializes this check with the actual
        native acceptance/fence transaction. Native review callbacks are
        non-effectful and cannot manufacture an accepted Operation.
        """
        validate(
            "ssh-request.schema.json",
            {
                "format": "deployment-ops/owner/v1",
                "message_id": submission["request_id"],
                "method": "operation.submit",
                "params": submission,
            },
        )
        with self._lock, self.journal.guard(self._journal_head):
            _require(not self._failed, "workflow admission requires verified journal custody")
            self._authorize(principal, "read")
            self._authorize(principal, "operation.submit")
            self._fresh(
                {"expected_generation": self.generation, "driver_term": submission["driver_term"]},
                principal,
            )
            _require(
                submission["owner"] == self.owner and submission["workflow_id"] == self.workflow_id,
                "native operation changed local workflow identity",
            )
            child = {"owner": submission["owner"], "request_id": submission["request_id"]}
            key = _key(child)
            _require(
                key in self.ready and key in self._admissions,
                "native operation lacks a durable local journal permit",
            )
            binding, permit = self.ready[key], self._admissions[key]
            body = permit["body"]
            plan = bound_plan(binding)
            _require(
                "completed" not in binding
                and binding["phase"] == self.phase
                and body["phase"] == self.phase
                and body["driver_term"] == self.driver_term
                and body["authenticated_principal"] == principal
                and body["child"] == child,
                "native operation journal permit is stale or nonexecutable",
            )
            _require(
                submission["plan_id"] == plan["id"]
                and submission["plan_digest"] == plan["digest"] == body["plan_digest"]
                and submission["subject_digest"] == digest(plan["subject"])
                and submission["confirmed"] is True,
                "native operation changed its exact reviewed Plan or subject",
            )
            _require(
                self._round is not None
                and self._certificate is not None
                and self._reservation is not None,
                "native operation protected barrier is absent",
            )
            assert (
                self._round is not None
                and self._certificate is not None
                and self._reservation is not None
            )
            decision = self._certificate["body"]["decision"]["body"]
            _require(
                body["round_id"] == self._round["id"] == decision["round_id"]
                and body["certificate_id"] == self._certificate["id"]
                and body["reservation_id"] == self._reservation["id"]
                and body["reservation_generation"] == self._reservation["generation"],
                "native operation changed the exact retained reservation",
            )
            now = self.clock()
            _require(
                _time(now) < _time(decision["expires_at"])
                and _time(now) < _time(self._reservation["expires_at"])
                and _time(now) < _time(plan["expires_at"])
                and not plan["blockers"],
                "native operation admission expired or retains blockers",
            )
            self.native.check(self._reservation, self._round["body"])
            request = {
                "binding": binding,
                "content": self._binding_content[key],
                "predecessors": [],
                "materials": [],
            }
            review = self.native.admit(
                {
                    "workflow_id": self.workflow_id,
                    "child": child,
                    "request": request,
                    "reservation": self._reservation,
                    "phase": self.phase,
                    "driver_term": self.driver_term,
                }
            )
            _selected_review(request, review)
            _require(
                _time(review["now"]) <= _time(self.clock()) < _time(plan["expires_at"]),
                "native operation Plan is not currently valid",
            )
            return copy.deepcopy(permit)

    @contextmanager
    def operation_admission_guard(self, submission: JSON, *, principal: str) -> Iterator[JSON]:
        """Serialize the reference native acceptance with journal admission closure.

        The owner retains native acceptance inside this scope, rechecking its own
        resource generation and actual durable fence atomically. An independently
        implemented owner may use its own equivalent shared transaction boundary;
        a stand-alone earlier permit check is insufficient.
        """
        with self._lock, self.journal.guard(self._journal_head):
            yield self.require_operation_admission(submission, principal=principal)

    def accept_agreement(self, event_id: str, agreement: JSON, *, principal: str) -> JSON:
        return self._run(self._command("agreement", event_id, {"agreement": agreement}), principal)

    def vote(self, event_id: str, round: JSON, *, principal: str) -> JSON:
        return self._run(
            self._command(
                "vote",
                event_id,
                {
                    "expected_generation": self.generation,
                    "driver_term": self.driver_term,
                    "round": round,
                },
            ),
            principal,
        )

    def apply(self, event_id: str, certificate: JSON, *, principal: str) -> JSON:
        return self._run(
            self._command(
                "apply",
                event_id,
                {
                    "expected_generation": self.generation,
                    "driver_term": self.driver_term,
                    "certificate": certificate,
                },
            ),
            principal,
        )

    def bind(self, event_id: str, binding: JSON, *, principal: str) -> JSON:
        return self._run(
            self._command(
                "bind",
                event_id,
                {
                    "expected_generation": self.generation,
                    "driver_term": self.driver_term,
                    "binding": binding,
                },
            ),
            principal,
        )

    def admit(self, event_id: str, child: JSON, *, principal: str) -> JSON:
        return self._run(
            self._command(
                "admit",
                event_id,
                {
                    "expected_generation": self.generation,
                    "driver_term": self.driver_term,
                    "child": child,
                },
            ),
            principal,
        )

    def complete(self, event_id: str, operation: JSON, *, principal: str) -> JSON:
        return self._run(self._command("complete", event_id, {"operation": operation}), principal)


@bounds(
    _declaration(
        "submit",
        "O(B + E) new command and its exact affected local dependencies; preparation and each fixed phase visit each owner once; replay reads only the indexed original command/outcome",
    )
)
def dispatch_journal_command(target: _JournalTarget, command: JSON, *, principal: str) -> JSON:
    """Canonical live submit path after staged bytes and receiver scope validation."""
    return target._run(command, principal)


@bounds(
    _declaration(
        "initialize",
        "O(B + N + E + H) one exact create/join/recovery command, one manifest partition or local projection, and one cold replay",
    )
)
def initialize_workflow_journal(
    command: JSON,
    *,
    principal: str,
    context: Mapping[str, Any],
) -> _JournalTarget:
    """Create or restore a target from a staged command and protected configuration.

    context is independently installed receiver configuration: owner, key custody,
    key ring, journal, native callbacks and (for members) exact GateEnrollment.
    It is never read from the staged command. The returned target retains the
    original command ID as its signed initialized outcome for normal record.read.
    Recovery commands commit the exact signed projection already held in trusted
    OriginRecoveryContext; they do not carry or reinterpret historical payloads.
    """
    _fields(command, {"id", "workflow_id", "action", "payload"})
    validate("workflow-journal.schema.json", command, "Command")
    validate("common.schema.json", command["id"], "UUID")
    validate("common.schema.json", command["workflow_id"], "UUID")
    _require(
        "command" not in context and "principal" not in context,
        "workflow installed context cannot replace caller attribution",
    )
    if command["action"] == "gate.create":
        _fields(command["payload"], {"proposal"})
        return WorkflowGate(
            command["payload"]["proposal"], principal=principal, command=command, **context
        )
    if command["action"] == "member.join":
        _fields(command["payload"], {"projection"})
        return WorkflowMember(
            command["payload"]["projection"], principal=principal, command=command, **context
        )
    if command["action"] == "member.recover":
        from .workflow_journal_recovery import WorkflowRecoveryMember

        _fields(command["payload"], {"projection_digest"})
        _require(
            "origin" in context
            and command["payload"]["projection_digest"]
            == digest(context["origin"].signed_projection),
            "workflow recovery source differs from independently restored custody",
        )
        return WorkflowRecoveryMember(principal=principal, command=command, **context)
    raise ContractError(
        "workflow initialization requires gate.create, member.join or member.recover"
    )
