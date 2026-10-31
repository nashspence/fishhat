"""Owner-private phase attestation reference journal and complete proof assembly.

Native owners independently authenticate callers/peers, verify live obligations
and preserve exclusions and material before using this model. The in-memory
journal proves no native persistence, fencing, authorization or distributed
transaction. Only the issuer receives its signing key; drivers request proofs
through the public attestation and immutable record-read contracts.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Any, Literal, NoReturn

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .bounds import Bounds, bounds
from .handoffs import PHASES, validate_workflow
from .record_delivery import RecordSnapshot
from .validation import ContractError, canonical, digest, validate
from .witness import sign, verify
from .workflow_evidence import (
    phase_subject,
    validate_issuer_phase_context,
    validate_phase_evidence,
)
from .workflow_preparation import validate_workflow_agreement


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _bounds(name: str) -> Bounds:
    native = name.startswith("native-")
    return Bounds(
        id="workflow.attestation-" + name,
        work=(
            "O(B + P) complete supplied capsule/proof bytes and participant closure for issuance "
            "or assembly; indexed replay/lookup returns one bounded reference; restore visits "
            "each complete retained record once; record.read accounts for each requested chunk"
        ),
        extent="Complete issuer-local participant closure, original requests/results and native material; no prefix selection or collection cap",
        limits=(),
        capacity=("native issuer may refuse new capacity without evicting accepted identities",),
        proofs=(
            "tests/test_workflow_native_attestations.py::test_two_owner_native_proof_acquisition_settlement_and_replay"
            if native
            else "tests/test_workflow_attestations.py::test_two_owner_public_attestation_path_and_lost_reply_replay",
        ),
        linear_proofs=(
            "tests/test_workflow_native_attestations.py::test_native_attestation_complete_acquisition_check_and_assembly_are_linear"
            if native
            else "tests/test_workflow_attestations.py::test_attestation_complete_issuance_assembly_restore_and_replay_are_linear",
        ),
    )


def validate_attestation(value: dict[str, Any]) -> None:
    """Validate immutable joins; native truth, key trust and current expiry are external."""
    validate("workflow-evidence.schema.json", value, "WorkflowPhaseAttestation")
    request = value["request"]
    _require(
        value["owner"] == request["owner"]
        and value["id"] == request["attestation_id"]
        and value["resource"] == {"kind": "workflow", "id": request["workflow_id"]}
        and request["workflow_id"] == request["transition"]["workflow_id"]
        and value["generation"] == request["expected_generation"]
        and value["request_digest"] == digest(request),
        "workflow attestation identity changed",
    )
    _require(
        datetime.fromisoformat(value["issued_at"]) < datetime.fromisoformat(value["expires_at"]),
        "workflow attestation expiry does not follow issuance",
    )
    resources: set[bytes] = set()
    for participant in value["participants"]:
        resource = canonical(participant["resource"])
        _require(resource not in resources, "duplicate workflow attestation resource")
        resources.add(resource)
        witness = participant["witness"]
        _require(
            participant["owner"] == witness["owner"] == value["owner"]
            and participant["attestation_id"] == value["id"]
            and witness["workflow_id"] == request["workflow_id"]
            and witness["generation"] == participant["resource_generation"]
            and witness["kind"] == "approval"
            and witness["state"] == "workflow-phase-verified"
            and witness["created_at"] == value["issued_at"]
            and participant["expires_at"] == value["expires_at"]
            and witness["evidence_digests"] == []
            and witness["subject_digest"]
            == digest(phase_subject(request["transition"], participant)),
            "workflow attestation proof changed",
        )


class AttestationRefusal(ContractError):
    """Typed refusal; no native fact, accepted proof or renewed exclusion is implied."""

    def __init__(self, code: str, summary: str, owner: dict[str, Any], workflow_id: str) -> None:
        self.problem = {
            "code": code,
            "summary": summary,
            "retry": "safe-read",
            "owner": copy.deepcopy(owner),
            "resource": {"kind": "workflow", "id": workflow_id},
            "evidence": [],
        }
        validate("records.schema.json", self.problem, "Problem")
        super().__init__(summary)


class PhaseAttestationJournal:
    """Indexed immutable reference custody, supplied only with protected issuer context.

    A native owner serializes issuance with its workflow admission/fence state and
    durably commits the request reservation, signed result and required material
    before returning a reference. It never increments a workflow capsule merely
    to attest it. Native restart restores the complete journal and separately
    reconciles live exclusion; restoring these bytes alone never restores a fence.
    """

    @bounds(_bounds("restore"))
    def __init__(
        self,
        owner: dict[str, Any],
        *,
        key_id: str,
        private_key: Ed25519PrivateKey,
        boot_id: str | None = None,
        retained: Iterable[tuple[dict[str, Any], bytes]] = (),
        retained_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
    ) -> None:
        validate("common.schema.json", owner, "Owner")
        validate("common.schema.json", key_id, "Id")
        if boot_id is not None:
            validate("common.schema.json", boot_id, "UUID")
        self._owner = copy.deepcopy(owner)
        self._key_id, self._private_key, self._boot_id = key_id, private_key, boot_id
        self._records: dict[str, dict[str, Any]] = {}
        self._snapshots: dict[str, RecordSnapshot] = {}
        for reference, data in retained:
            _require(
                reference.get("record", {}).get("kind") == "WorkflowPhaseAttestation",
                "retained attestation record kind changed",
            )
            snapshot = RecordSnapshot.restore(
                reference,
                data,
                expected_owner=self._owner,
                retained_readers=retained_readers,
            )
            value = snapshot.record
            _require(value["owner"] == self._owner, "attestation restoration owner changed")
            _require(value["id"] not in self._records, "duplicate retained attestation identity")
            self._records[value["id"]] = value
            self._snapshots[value["id"]] = snapshot

    def _retain(self, value: dict[str, Any]) -> dict[str, Any]:
        snapshot = RecordSnapshot(value, value["id"])
        self._records[value["id"]] = copy.deepcopy(value)
        self._snapshots[value["id"]] = snapshot
        return snapshot.reference

    def _refuse(self, code: str, summary: str, workflow_id: str) -> NoReturn:
        raise AttestationRefusal(code, summary, self._owner, workflow_id)

    def _authorize_read(
        self,
        owner: dict[str, Any],
        workflow_id: str,
        *,
        expected_owner: dict[str, Any],
        principal: str,
        read_authorized: bool,
    ) -> None:
        validate("common.schema.json", principal, "Id")
        if read_authorized is not True:
            self._refuse(
                "PERMISSION_DENIED", "current complete attestation read scope required", workflow_id
            )
        if owner != self._owner or expected_owner != self._owner:
            self._refuse("OWNER_EPOCH_CHANGED", "workflow attestation issuer changed", workflow_id)

    @bounds(_bounds("issue"))
    def issue(
        self,
        request: dict[str, Any],
        workflow: dict[str, Any],
        *,
        expected_owner: dict[str, Any],
        principal: str,
        read_authorized: bool,
        attest_authorized: bool,
        native_authorized: bool,
        verified_receiver: dict[str, Any] | None = None,
        verified_driver: dict[str, Any] | None = None,
        verified_participants: list[dict[str, Any]] | None = None,
        verified_preparations: list[dict[str, Any]] | None = None,
        issued_at: str,
        expires_at: str,
        recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
    ) -> dict[str, Any]:
        """Issue a driver proof; request data cannot select owner-native authority."""
        return self._issue(
            request,
            workflow,
            expected_owner=expected_owner,
            principal=principal,
            read_authorized=read_authorized,
            attest_authorized=attest_authorized,
            native_authorized=native_authorized,
            authority="driver",
            authenticated_peer=None,
            verified_receiver=verified_receiver,
            verified_driver=verified_driver,
            verified_participants=verified_participants,
            verified_preparations=verified_preparations,
            issued_at=issued_at,
            expires_at=expires_at,
            recovery_readers=recovery_readers,
        )

    @bounds(_bounds("native-issue"))
    def issue_native(
        self,
        request: dict[str, Any],
        workflow: dict[str, Any],
        *,
        expected_owner: dict[str, Any],
        principal: str,
        authenticated_peer: dict[str, Any] | None,
        read_authorized: bool,
        attest_authorized: bool,
        native_authorized: bool,
        verified_receiver: dict[str, Any] | None = None,
        verified_participants: list[dict[str, Any]] | None = None,
        verified_preparations: list[dict[str, Any]] | None = None,
        issued_at: str,
        expires_at: str,
        recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
    ) -> dict[str, Any]:
        """Protected peer issuance for the receiver's final native settlement only.

        authenticated_peer comes from independently enrolled owner transport or
        protected same-owner dispatch, never principal spelling or request data.
        A driver or administrator without that identity cannot use this path.
        """
        return self._issue(
            request,
            workflow,
            expected_owner=expected_owner,
            principal=principal,
            authenticated_peer=authenticated_peer,
            read_authorized=read_authorized,
            attest_authorized=attest_authorized,
            native_authorized=native_authorized,
            authority="native-owner",
            verified_receiver=verified_receiver,
            verified_participants=verified_participants,
            verified_preparations=verified_preparations,
            issued_at=issued_at,
            expires_at=expires_at,
            recovery_readers=recovery_readers,
        )

    def _authorize_peer(
        self, request: dict[str, Any], authenticated_peer: dict[str, Any] | None
    ) -> None:
        if authenticated_peer != request["transition"]["owner"]:
            self._refuse(
                "PERMISSION_DENIED",
                "independently authenticated receiving owner epoch required",
                request["workflow_id"],
            )

    def _issue(
        self,
        request: dict[str, Any],
        workflow: dict[str, Any],
        *,
        expected_owner: dict[str, Any],
        principal: str,
        read_authorized: bool,
        attest_authorized: bool,
        native_authorized: bool,
        authority: Literal["driver", "native-owner"],
        authenticated_peer: dict[str, Any] | None,
        verified_receiver: dict[str, Any] | None = None,
        verified_driver: dict[str, Any] | None = None,
        verified_participants: list[dict[str, Any]] | None = None,
        verified_preparations: list[dict[str, Any]] | None = None,
        issued_at: str,
        expires_at: str,
        recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
    ) -> dict[str, Any]:
        """Issue only after independent live verification, or rediscover exact old custody.

        Every verified argument and permission is protected receiving context,
        never copied from untrusted request fields. Native verification includes
        complete real result bytes and continuing exclusion for every local
        participant. Missing protection refuses issuance. Current read scope covers
        the entire original result, not merely possession of a workflow identity.
        """
        validate(
            "workflow-evidence.schema.json",
            request,
            "AttestationRequest" if authority == "driver" else "NativeAttestationRequest",
        )
        workflow_id = request["workflow_id"]
        self._authorize_read(
            request["owner"],
            workflow_id,
            expected_owner=expected_owner,
            principal=principal,
            read_authorized=read_authorized,
        )
        if authority == "native-owner":
            self._authorize_peer(request, authenticated_peer)
        retained = self._records.get(request["attestation_id"])
        if retained is not None:
            if retained["request"] != request:
                self._refuse(
                    "CONFLICT", "attestation identity selects different input", workflow_id
                )
            return self._snapshots[retained["id"]].reference
        if attest_authorized is not True or native_authorized is not True:
            self._refuse(
                "PERMISSION_DENIED",
                "current attestation and native authority required",
                workflow_id,
            )
        try:
            self._checked_context(
                request,
                workflow,
                authority=authority,
                principal=principal,
                verified_receiver=verified_receiver,
                verified_driver=verified_driver,
                verified_preparations=verified_preparations,
                recovery_readers=recovery_readers,
            )
            validate("common.schema.json", issued_at, "Time")
            validate("common.schema.json", expires_at, "Time")
            _require(
                datetime.fromisoformat(issued_at) < datetime.fromisoformat(expires_at),
                "attestation policy deadline must follow issuance",
            )
            _require(
                verified_participants is not None, "current native phase verification required"
            )
            assert verified_participants is not None and verified_receiver is not None
            participants = copy.deepcopy(verified_participants)
            for proof in participants:
                proof["attestation_id"] = request["attestation_id"]
                _require(
                    proof["expires_at"] == expires_at, "attestation native policy deadline changed"
                )
            # Check both the target's retained bindings and the issuer's own
            # current bindings before allowing its protected signer to run.
            validate_issuer_phase_context(
                request["transition"],
                participants,
                verified_receiver,
                owner=self._owner,
                authority=authority,
                recovery_readers=recovery_readers,
            )
            local_view = {
                **workflow,
                **{
                    "owner": request["transition"]["owner"],
                    "generation": request["transition"]["expected_generation"],
                    "phase": request["transition"]["from_phase"],
                    "driver_term": request["transition"]["driver_term"],
                },
            }
            validate_issuer_phase_context(
                request["transition"],
                participants,
                local_view,
                owner=self._owner,
                authority=authority,
                recovery_readers=recovery_readers,
            )
        except ContractError as exc:
            self._refuse("PRECONDITION_FAILED", str(exc), workflow_id)
        result = {
            "format": "deployment-ops/workflow-attestation/v1",
            "kind": "WorkflowPhaseAttestation",
            "id": request["attestation_id"],
            "owner": copy.deepcopy(self._owner),
            "resource": {"kind": "workflow", "id": workflow_id},
            "generation": request["expected_generation"],
            "request": copy.deepcopy(request),
            "request_digest": digest(request),
            "authenticated_principal": principal,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "participants": participants,
        }
        for proof in participants:
            proof["witness"] = sign(
                {
                    "format": "deployment-ops/witness/v1",
                    "id": str(uuid.uuid4()),
                    "owner": copy.deepcopy(self._owner),
                    "kind": "approval",
                    "subject_digest": digest(phase_subject(request["transition"], proof)),
                    "workflow_id": workflow_id,
                    "generation": proof["resource_generation"],
                    "state": "workflow-phase-verified",
                    "boot_id": self._boot_id,
                    "evidence_digests": [],
                    "created_at": issued_at,
                    "key_id": self._key_id,
                },
                self._private_key,
            )
        validate_attestation(result)
        return self._retain(result)

    def _checked_context(
        self,
        request: dict[str, Any],
        workflow: dict[str, Any],
        *,
        authority: Literal["driver", "native-owner"],
        principal: str,
        verified_receiver: dict[str, Any] | None,
        verified_driver: dict[str, Any] | None,
        verified_preparations: list[dict[str, Any]] | None,
        recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
    ) -> None:
        if authority == "driver":
            self._current_context(
                request,
                workflow,
                principal=principal,
                verified_receiver=verified_receiver,
                verified_driver=verified_driver,
                verified_preparations=verified_preparations,
                recovery_readers=recovery_readers,
            )
            return
        validate_workflow(workflow, recovery_readers=recovery_readers)
        _require(verified_receiver is not None, "current authenticated receiver capsule required")
        assert verified_receiver is not None
        validate_workflow(verified_receiver, recovery_readers=recovery_readers)
        transition = request["transition"]
        _require(
            workflow["owner"] == self._owner
            and workflow["id"] == verified_receiver["id"] == request["workflow_id"]
            and request["expected_generation"] == workflow["generation"]
            and workflow["proposal"] == verified_receiver["proposal"]
            and transition["owner"] == verified_receiver["owner"]
            and transition["expected_generation"] == verified_receiver["generation"]
            and transition["driver_term"] == verified_receiver["driver_term"],
            "native attestation issuer, receiver, proposal or generation changed",
        )
        phases = PHASES[workflow["type"]]
        _require(
            transition["authority"] == "native-owner"
            and transition["from_phase"] == verified_receiver["phase"] == phases[-2]
            and transition["to_phase"] == phases[-1]
            and verified_receiver["state"] in {"active", "paused"}
            and (
                (workflow["state"] in {"active", "paused"} and workflow["phase"] == phases[-2])
                or (workflow["state"] == "completed" and workflow["phase"] == phases[-1])
            ),
            "native attestation requires the final installed transition",
        )
        # A partially committed driver transfer may leave peers at different
        # driver terms. This path observes already accepted child outcomes; it
        # cannot finish that transfer, admit work or release retained protection.
        for capsule in (workflow, verified_receiver):
            _require(
                capsule.get("recovery", {}).get("phase", "committed") == "committed",
                "uncommitted workflow recovery forbids native attestation",
            )
            validate_workflow_agreement(
                capsule, witnesses=verified_preparations or [], require_complete=True
            )

    def _current_context(
        self,
        request: dict[str, Any],
        workflow: dict[str, Any],
        *,
        principal: str,
        verified_receiver: dict[str, Any] | None,
        verified_driver: dict[str, Any] | None,
        verified_preparations: list[dict[str, Any]] | None,
        recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
    ) -> None:
        validate_workflow(workflow, recovery_readers=recovery_readers)
        _require(verified_receiver is not None, "current authenticated receiver capsule required")
        assert verified_receiver is not None
        validate_workflow(verified_receiver, recovery_readers=recovery_readers)
        transition = request["transition"]
        _require(
            workflow["owner"] == self._owner
            and workflow["id"] == verified_receiver["id"] == request["workflow_id"]
            and request["expected_generation"] == workflow["generation"]
            and workflow["proposal"] == verified_receiver["proposal"]
            and transition["owner"] == verified_receiver["owner"]
            and transition["expected_generation"] == verified_receiver["generation"]
            and transition["from_phase"] == verified_receiver["phase"],
            "attestation issuer, receiver, proposal or generation changed",
        )
        _require(
            verified_driver == {"principal": principal, "term": transition["driver_term"]}
            and principal == workflow["driver_principal"] == verified_receiver["driver_principal"]
            and transition["driver_term"]
            == workflow["driver_term"]
            == verified_receiver["driver_term"],
            "current authenticated workflow driver required",
        )
        terminal_peer = (
            workflow["state"] == "completed"
            and workflow["phase"] == transition["to_phase"] == PHASES[workflow["type"]][-1]
        )
        _require(
            (workflow["state"] in {"prepared", "active"} or terminal_peer)
            and workflow["phase"] in {transition["from_phase"], transition["to_phase"]}
            and verified_receiver["state"] in {"prepared", "active"},
            "workflow lifecycle or phase forbids new attestation",
        )
        for capsule in (workflow, verified_receiver):
            _require(
                (capsule["transfer"] is None or capsule["transfer"]["phase"] == "completed")
                and capsule.get("recovery", {}).get("phase", "committed") == "committed",
                "uncommitted workflow custody forbids new attestation",
            )
            validate_workflow_agreement(
                capsule, witnesses=verified_preparations or [], require_complete=True
            )

    @bounds(_bounds("lookup"))
    def get(
        self,
        request: dict[str, Any],
        *,
        expected_owner: dict[str, Any],
        principal: str,
        read_authorized: bool,
    ) -> dict[str, Any]:
        validate("workflow-evidence.schema.json", request, "AttestationLookup")
        self._authorize_read(
            request["owner"],
            request["workflow_id"],
            expected_owner=expected_owner,
            principal=principal,
            read_authorized=read_authorized,
        )
        value = self._records.get(request["attestation_id"])
        if value is None or value["resource"]["id"] != request["workflow_id"]:
            self._refuse("NOT_FOUND", "workflow attestation not found", request["workflow_id"])
        return self._snapshots[request["attestation_id"]].reference

    def read(
        self,
        reference: dict[str, Any],
        *,
        offset: int,
        length: int,
        expected_owner: dict[str, Any],
        principal: str,
        read_authorized: bool,
    ) -> dict[str, Any]:
        """Model record.read only after current complete protected disclosure permission."""
        validate("workflow-evidence.schema.json", reference, "AttestationReference")
        resource = reference["record"]["resource"]
        query = {
            "owner": reference["owner"],
            "workflow_id": resource["id"],
            "attestation_id": reference["record"]["id"],
        }
        current = self.get(
            query,
            expected_owner=expected_owner,
            principal=principal,
            read_authorized=read_authorized,
        )
        _require(current == reference, "attestation snapshot substitution")
        return self._snapshots[query["attestation_id"]].chunk(
            reference, offset=offset, length=length
        )

    @bounds(_bounds("check"))
    def check(
        self,
        request: dict[str, Any],
        workflow: dict[str, Any],
        *,
        expected_owner: dict[str, Any],
        principal: str,
        read_authorized: bool,
        check_authorized: bool,
        native_current: bool,
        verified_receiver: dict[str, Any] | None,
        verified_driver: dict[str, Any] | None,
        verified_preparations: list[dict[str, Any]] | None,
        now: str,
        recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
    ) -> dict[str, Any]:
        """Check a driver proof under independently verified current driver context."""
        return self._check(
            request,
            workflow,
            expected_owner=expected_owner,
            principal=principal,
            read_authorized=read_authorized,
            check_authorized=check_authorized,
            native_current=native_current,
            verified_receiver=verified_receiver,
            verified_driver=verified_driver,
            verified_preparations=verified_preparations,
            now=now,
            authority="driver",
            authenticated_peer=None,
            recovery_readers=recovery_readers,
        )

    @bounds(_bounds("native-check"))
    def check_native(
        self,
        request: dict[str, Any],
        workflow: dict[str, Any],
        *,
        expected_owner: dict[str, Any],
        principal: str,
        authenticated_peer: dict[str, Any] | None,
        read_authorized: bool,
        check_authorized: bool,
        native_current: bool,
        verified_receiver: dict[str, Any] | None,
        verified_preparations: list[dict[str, Any]] | None,
        now: str,
        recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
    ) -> dict[str, Any]:
        """Recheck native proof only for its independently authenticated receiver."""
        return self._check(
            request,
            workflow,
            expected_owner=expected_owner,
            principal=principal,
            authenticated_peer=authenticated_peer,
            read_authorized=read_authorized,
            check_authorized=check_authorized,
            native_current=native_current,
            verified_receiver=verified_receiver,
            verified_driver=None,
            verified_preparations=verified_preparations,
            now=now,
            authority="native-owner",
            recovery_readers=recovery_readers,
        )

    def _check(
        self,
        request: dict[str, Any],
        workflow: dict[str, Any],
        *,
        expected_owner: dict[str, Any],
        principal: str,
        read_authorized: bool,
        check_authorized: bool,
        native_current: bool,
        verified_receiver: dict[str, Any] | None,
        verified_driver: dict[str, Any] | None,
        verified_preparations: list[dict[str, Any]] | None,
        now: str,
        authority: Literal["driver", "native-owner"],
        authenticated_peer: dict[str, Any] | None,
        recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
    ) -> dict[str, Any]:
        """Observe current proof validity without renewal, release or admission.

        native_current is independently selected after checking the exact retained
        native material, resource generations and continuing exclusions. It cannot
        be populated from request JSON or a prior signed attestation. A native
        receiver still serializes its own admission against the required ongoing
        protections; this response is not a lease that closes a later race.
        """
        validate("workflow-evidence.schema.json", request, "AttestationCheckRequest")
        reference = request["reference"]
        workflow_id = reference["record"]["resource"]["id"]
        selected = self.get(
            {
                "owner": reference["owner"],
                "workflow_id": workflow_id,
                "attestation_id": reference["record"]["id"],
            },
            expected_owner=expected_owner,
            principal=principal,
            read_authorized=read_authorized,
        )
        if selected != reference:
            self._refuse("CONFLICT", "attestation check snapshot changed", workflow_id)
        if check_authorized is not True:
            self._refuse(
                "PERMISSION_DENIED", "current attestation check authority required", workflow_id
            )
        value = self._records[reference["record"]["id"]]
        if authority == "native-owner":
            self._authorize_peer(value["request"], authenticated_peer)
        try:
            validate(
                "workflow-evidence.schema.json",
                value["request"],
                "AttestationRequest" if authority == "driver" else "NativeAttestationRequest",
            )
            _require(native_current is True, "attested native protection is not currently verified")
            self._checked_context(
                value["request"],
                workflow,
                authority=authority,
                principal=workflow["driver_principal"],
                verified_receiver=verified_receiver,
                verified_driver=verified_driver,
                verified_preparations=verified_preparations,
                recovery_readers=recovery_readers,
            )
            validate("common.schema.json", now, "Time")
            _require(
                datetime.fromisoformat(value["issued_at"])
                <= datetime.fromisoformat(now)
                < datetime.fromisoformat(value["expires_at"]),
                "workflow attestation is not currently valid",
            )
        except ContractError as exc:
            self._refuse("PRECONDITION_FAILED", str(exc), workflow_id)
        result = {
            "kind": "CurrentWorkflowAttestation",
            "reference": copy.deepcopy(reference),
            "transition": copy.deepcopy(value["request"]["transition"]),
            "checked_at": now,
        }
        validate("workflow-evidence.schema.json", result, "CurrentAttestation")
        return result


@bounds(_bounds("assemble"))
def assemble_phase_evidence(
    attestations: Iterable[dict[str, Any]],
    transition: dict[str, Any],
    workflow: dict[str, Any],
    *,
    public_keys: Mapping[tuple[bytes, str], Ed25519PublicKey],
    now: str,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Assemble complete authentic proof bytes; this does not grant native authority.

    Trusted keys are selected independently for exact owner epochs and key IDs.
    A driver cannot substitute caller-provided enrollment or revive expired proof.
    Native admission still independently rechecks current exclusions and facts.
    """
    return _assemble_phase_evidence(
        attestations,
        transition,
        workflow,
        public_keys=public_keys,
        now=now,
        authority="driver",
        recovery_readers=recovery_readers,
    )


@bounds(_bounds("native-assemble"))
def assemble_native_phase_evidence(
    attestations: Iterable[dict[str, Any]],
    transition: dict[str, Any],
    workflow: dict[str, Any],
    *,
    public_keys: Mapping[tuple[bytes, str], Ed25519PublicKey],
    now: str,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Join complete peer-issued native final proofs using independently trusted keys.

    Authentic bytes do not supply current native authority. The receiving owner
    separately checks each exact record through protected peer routing and keeps
    the required exclusions through its serialized final settlement.
    """
    return _assemble_phase_evidence(
        attestations,
        transition,
        workflow,
        public_keys=public_keys,
        now=now,
        authority="native-owner",
        recovery_readers=recovery_readers,
    )


def _assemble_phase_evidence(
    attestations: Iterable[dict[str, Any]],
    transition: dict[str, Any],
    workflow: dict[str, Any],
    *,
    public_keys: Mapping[tuple[bytes, str], Ed25519PublicKey],
    now: str,
    authority: Literal["driver", "native-owner"],
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
) -> dict[str, Any]:
    validate("common.schema.json", now, "Time")
    validate_workflow(workflow, recovery_readers=recovery_readers)
    participants = []
    owners: set[bytes] = set()
    for value in attestations:
        validate_attestation(value)
        validate(
            "workflow-evidence.schema.json",
            value["request"],
            "AttestationRequest" if authority == "driver" else "NativeAttestationRequest",
        )
        owner = canonical(value["owner"])
        _require(owner not in owners, "duplicate workflow attestation issuer")
        owners.add(owner)
        _require(
            value["request"]["transition"] == transition, "attestation transition substitution"
        )
        _require(
            datetime.fromisoformat(value["issued_at"])
            <= datetime.fromisoformat(now)
            < datetime.fromisoformat(value["expires_at"]),
            "workflow attestation is not currently valid",
        )
        for proof in value["participants"]:
            witness = proof["witness"]
            key = public_keys.get((owner, witness["key_id"]))
            _require(key is not None, "workflow attestation issuer key is not trusted")
            assert key is not None
            verify(witness, key, value["owner"], digest(phase_subject(transition, proof)))
            participants.append(copy.deepcopy(proof))
    evidence = {"transition": copy.deepcopy(transition), "participants": participants}
    validate_phase_evidence(
        {
            **{
                key: transition[key]
                for key in (
                    "owner",
                    "workflow_id",
                    "advance_id",
                    "expected_generation",
                    "driver_term",
                )
            },
            "phase": transition["to_phase"],
            "transfer_completion": None,
            "phase_evidence": evidence,
        },
        workflow,
        authority=authority,
        recovery_readers=recovery_readers,
    )
    return evidence
