"""Protected final-proof acquisition between independently keyed synthetic owners.

Peer enrollment, accepted child outcomes and exclusions are explicit fake native
state. The driver never receives signing keys or supplies authenticated peer identity.
"""

from __future__ import annotations

import copy
from functools import lru_cache

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_contracts import workflow_attestations
from fishhat_contracts.handoffs import PHASES
from fishhat_contracts.record_delivery import RecordSnapshot
from fishhat_contracts.validation import ContractError, canonical, digest, validate
from fishhat_contracts.workflow_attestations import (
    PhaseAttestationJournal,
    assemble_native_phase_evidence,
    assemble_phase_evidence,
)
from fishhat_contracts.workflow_evidence import REQUIREMENTS
from fishhat_contracts.workflow_settlement import record_native_completion
from fishhat_owner.commands import parse_command

from tests.linear_support import assert_linear, measure
from tests.test_contracts import uid
from tests.test_owner_handoffs import rebind_workflow_proposal, workflow
from tests.test_workflow_attestations import DRIVER, EXPIRES, NOW, call, current, read_record
from tests.test_workflow_continuations import move, prepare
from tests.test_workflow_transfer import committed, frozen
from tests.workflow_evidence_support import phase_evidence
from tests.workflow_lifecycle_support import lifecycle

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-evidence.schema.json#/$defs/NativeAttestationRequest",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-evidence.schema.json#/$defs/NativeAttestationCheckRequest",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/NativeCompletion",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
    ],
    "scope": "authenticated receiving-owner proof issuance, current checking and final settlement with paused and partially transferred peers",
    "relationship": "candidate",
    "reason": "Independent fake owner processes retain their private keys and answer framed requests through separately enrolled peer context. Tests challenge authority selection, exact receiver and issuer joins, expiry, changed context and replay; no native authentication, fencing or persistence is qualified.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_two_owner_native_proof_acquisition_settlement_and_replay": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_attestations.py#PhaseAttestationJournal.issue_native",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_attestations.py#PhaseAttestationJournal.check_native",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_attestations.py#assemble_native_phase_evidence",
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-evidence.schema.json",
        ],
        "scope": "complete peer-signed native proof acquisition and exact final settlement replay",
        "relationship": "scoped-witness",
        "reason": "Two separately keyed synthetic owners acquire all final proofs under protected peer context despite paused lifecycle and different partially transferred driver terms; no native qualification is inferred.",
        "claims": [
            "engineering:workflow.attestation-native-issue",
            "engineering:workflow.attestation-native-check",
            "engineering:workflow.attestation-native-assemble",
        ],
    },
    "test_native_attestation_complete_acquisition_check_and_assembly_are_linear": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_attestations.py#PhaseAttestationJournal.issue_native",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_attestations.py#PhaseAttestationJournal.check_native",
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_attestations.py#assemble_native_phase_evidence",
            "release.toml#/engineering",
        ],
        "scope": "complete native proof issuance, current checking, assembly and exact replay over sixteenfold native material extent",
        "relationship": "scoped-witness",
        "reason": "Executed work counters include complete native records, signed proofs and retries; fixture preparation and independently supplied fake native observations are outside the measured reference boundary.",
        "claims": [
            "engineering:workflow.attestation-native-issue",
            "engineering:workflow.attestation-native-check",
            "engineering:workflow.attestation-native-assemble",
        ],
    },
}


@lru_cache
def ready_capsules():
    draft = workflow()
    peer = copy.deepcopy(draft["participants"][0])
    peer["owner"]["id"] = uid("native-peer-owner")
    peer["resource"]["id"] = "native-peer-host"
    peer["request_ids"] = [uid("native-peer-child")]
    draft["participants"].append(peer)
    rebind_workflow_proposal(draft)
    values = []
    for participant in draft["participants"]:
        value = prepare(draft["proposal"], participant["owner"])
        value = lifecycle(move(value, PHASES[value["type"]][-2]), "pause")
        values.append(value)
    first, _ = frozen(values[0])
    second, _ = committed(values[1])
    return first, second


def target(value):
    return {
        "authority": "native-owner",
        "owner": copy.deepcopy(value["owner"]),
        "workflow_id": value["id"],
        "advance_id": uid("native-final-" + value["owner"]["id"] + str(value["generation"])),
        "proposal_digest": value["proposal_digest"],
        "procedure": value["type"],
        "requirements_digest": digest(REQUIREMENTS[value["type"]]),
        "expected_generation": value["generation"],
        "driver_term": value["driver_term"],
        "from_phase": PHASES[value["type"]][-2],
        "to_phase": PHASES[value["type"]][-1],
    }


class NativeOwner:
    """Protected native state belongs to this process, separately from request JSON."""

    def __init__(self, capsule, seed):
        self.__workflow = copy.deepcopy(capsule)
        self.identity, self.workflow_id = capsule["owner"], capsule["id"]
        self.principal = "peer-" + str(seed)
        self.__key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        self.public_key = self.__key.public_key()
        self.__journal = PhaseAttestationJournal(
            self.identity, key_id="native-peer-key", private_key=self.__key
        )
        self.__accepted = {}
        self.__workflow_records = {}
        self.peers, self.enrollment = {}, {}
        self.retained_readers = None
        self.read_allowed = self.native_protected = True
        self.now, self.expires_at = NOW, EXPIRES
        self.evidence_count = 1

    def read_context(self, principal):
        return {
            "expected_owner": self.identity,
            "principal": principal,
            "read_authorized": self.read_allowed,
        }

    def context(self, transition):
        receiver = current(self.peers[canonical(transition["owner"])])
        return {
            "verified_receiver": receiver,
            "verified_preparations": [
                witness
                for peer in self.peers.values()
                for witness in current(peer)["prerequisite_witnesses"]
                if witness["owner"] == peer.identity and witness["state"] == "workflow-prepared"
            ],
        }

    def participants(self, transition):
        query = {
            **transition,
            "phase": transition["to_phase"],
        }
        evidence = phase_evidence(self.__workflow, query, authority="native-owner")
        proofs = []
        for proof in evidence["participants"]:
            if proof["owner"] != self.identity:
                continue
            proof.pop("witness")
            proof.pop("attestation_id")
            proof["expires_at"] = self.expires_at
            base = proof["native_evidence"][0]
            proof["native_evidence"] = [
                {**base, "id": uid("native-evidence-" + str(index))}
                for index in range(self.evidence_count)
            ]
            proofs.append(proof)
        return proofs

    def dispatch(self, method, params, principal):
        read = self.read_context(principal)
        if method == "workflow.get":
            snapshot = RecordSnapshot(
                self.__workflow, uid("native-capsule-" + digest(self.__workflow))
            )
            self.__workflow_records[snapshot.reference["snapshot_id"]] = snapshot
            return snapshot.reference
        if method == "record.read":
            reference = params["reference"]
            if reference["record"]["kind"] == "Workflow":
                return self.__workflow_records[reference["snapshot_id"]].chunk(
                    reference, offset=params["offset"], length=params["length"]
                )
            return self.__journal.read(
                reference, offset=params["offset"], length=params["length"], **read
            )
        if method == "workflow.attestation.get":
            return self.__journal.get(params, **read)
        if method in {"workflow.native-attest", "workflow.attest"}:
            context = {}
            if params["attestation_id"] not in self.__accepted:
                context = {
                    **self.context(params["transition"]),
                    "verified_participants": self.participants(params["transition"]),
                }
            if method == "workflow.native-attest":
                result = self.__journal.issue_native(
                    params,
                    self.__workflow,
                    **read,
                    authenticated_peer=self.enrollment.get(principal),
                    attest_authorized=True,
                    native_authorized=self.native_protected,
                    issued_at=self.now,
                    expires_at=self.expires_at,
                    **context,
                )
            else:
                result = self.__journal.issue(
                    params,
                    self.__workflow,
                    **read,
                    attest_authorized=True,
                    native_authorized=self.native_protected,
                    issued_at=self.now,
                    expires_at=self.expires_at,
                    **context,
                )
            self.__accepted[params["attestation_id"]] = copy.deepcopy(params)
            return result
        if method in {"workflow.native-attestation.check", "workflow.attestation.check"}:
            original = self.__accepted[params["reference"]["record"]["id"]]
            context = self.context(original["transition"])
            if method == "workflow.native-attestation.check":
                return self.__journal.check_native(
                    params,
                    self.__workflow,
                    **read,
                    authenticated_peer=self.enrollment.get(principal),
                    check_authorized=True,
                    native_current=self.native_protected,
                    now=self.now,
                    **context,
                )
            return self.__journal.check(
                params,
                self.__workflow,
                **read,
                check_authorized=True,
                native_current=self.native_protected,
                verified_driver=None,
                now=self.now,
                **context,
            )
        raise AssertionError(method)

    def settle(self, transition, evidence):
        query = {
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
            "phase_evidence": copy.deepcopy(evidence),
        }
        self.__workflow = record_native_completion(
            query,
            self.__workflow,
            expected_owner=self.identity,
            native_authorized=self.native_protected,
            verified_phase_evidence=evidence,
            now=self.now,
        )

    def change_generation(self):
        self.__workflow["generation"] += 1

    def restore(self):
        retained = []
        for identity in self.__accepted:
            reference = self.__journal.get(
                {
                    "owner": self.identity,
                    "workflow_id": self.workflow_id,
                    "attestation_id": identity,
                },
                **self.read_context(self.principal),
            )
            retained.append((reference, canonical(read_record(self, reference))))
        self.__journal = PhaseAttestationJournal(
            self.identity, key_id="native-peer-key", private_key=self.__key, retained=retained
        )

    def measure_models(self, query, receiver, context, participants):
        """Exercise reference work after independent fixture observation setup."""
        arguments = {
            **self.read_context(receiver.principal),
            "authenticated_peer": receiver.identity,
            "attest_authorized": True,
            "native_authorized": True,
            "issued_at": NOW,
            "expires_at": EXPIRES,
            **context,
            "verified_participants": participants,
        }
        reference = self.__journal.issue_native(query, self.__workflow, **arguments)
        for _ in range(3):
            assert self.__journal.issue_native(query, self.__workflow, **arguments) == reference
        self.__accepted[query["attestation_id"]] = copy.deepcopy(query)
        self.__journal.check_native(
            {"reference": reference},
            self.__workflow,
            **self.read_context(receiver.principal),
            authenticated_peer=receiver.identity,
            check_authorized=True,
            native_current=True,
            now=NOW,
            **context,
        )
        return reference


def cluster():
    owners = [NativeOwner(value, 70 + index) for index, value in enumerate(ready_capsules())]
    for owner in owners:
        owner.peers = {canonical(peer.identity): peer for peer in owners}
        owner.enrollment = {peer.principal: copy.deepcopy(peer.identity) for peer in owners}
    return owners


def query(issuer, transition):
    return {
        "owner": copy.deepcopy(issuer.identity),
        "workflow_id": issuer.workflow_id,
        "attestation_id": uid("native-proof-" + issuer.identity["id"] + digest(transition)),
        "expected_generation": current(issuer)["generation"],
        "transition": copy.deepcopy(transition),
    }


def acquire(owners, receiver):
    transition = target(current(receiver))
    references, records, requests = [], [], []
    for issuer in owners:
        request = query(issuer, transition)
        reference = call(issuer, "workflow.native-attest", request, principal=receiver.principal)
        result = call(
            issuer,
            "workflow.native-attestation.check",
            {"reference": reference},
            principal=receiver.principal,
        )
        assert result["transition"] == transition
        records.append(read_record(issuer, reference))
        references.append(reference)
        requests.append(request)
    keys = {(canonical(owner.identity), "native-peer-key"): owner.public_key for owner in owners}
    evidence = assemble_native_phase_evidence(
        records, transition, current(receiver), public_keys=keys, now=NOW
    )
    return transition, evidence, references, requests, records


def test_two_owner_native_proof_acquisition_settlement_and_replay():
    owners = cluster()
    assert current(owners[0])["driver_term"] != current(owners[1])["driver_term"]
    for receiver in owners:
        before = current(receiver)
        transition, evidence, references, requests, records = acquire(owners, receiver)
        assert all(record["authenticated_principal"] == receiver.principal for record in records)
        receiver.settle(transition, evidence)
        after = current(receiver)
        assert after["state"] == "completed"
        assert after["phase"] == PHASES[after["type"]][-1]
        assert after["advances"][-1]["authority"] == "native-owner"
        for field in before.keys() - {"state", "phase", "generation", "advances"}:
            assert after[field] == before[field]
        receiver.settle(transition, evidence)
        assert current(receiver) == after
        for issuer, request, reference in zip(owners, requests, references, strict=True):
            issuer.restore()
            assert (
                call(issuer, "workflow.native-attest", request, principal=receiver.principal)
                == reference
            )
            assert read_record(issuer, reference)["request"] == request


@pytest.mark.parametrize("principal", [DRIVER, "administrator", "peer-pretender"])
def test_native_route_does_not_grant_peer_authority_to_a_driver_or_admin(principal):
    issuer, receiver = cluster()
    request = query(issuer, target(current(receiver)))
    with pytest.raises(ContractError, match="PERMISSION_DENIED"):
        call(issuer, "workflow.native-attest", request, principal=principal)
    reference = call(issuer, "workflow.native-attest", request, principal=receiver.principal)
    with pytest.raises(ContractError, match="PERMISSION_DENIED"):
        call(
            issuer,
            "workflow.native-attestation.check",
            {"reference": reference},
            principal=principal,
        )
    with pytest.raises(ContractError, match="PERMISSION_DENIED"):
        call(issuer, "workflow.native-attest", request, principal=principal)


@pytest.mark.parametrize(
    "field", ["authenticated_peer", "native_authorized", "participants", "expires_at"]
)
def test_native_request_cannot_supply_protected_context(field):
    issuer, receiver = cluster()
    request = query(issuer, target(current(receiver)))
    request[field] = receiver.identity if field == "authenticated_peer" else True
    with pytest.raises(ContractError):
        call(issuer, "workflow.native-attest", request, principal=DRIVER)


@pytest.mark.parametrize(
    "change", ["peer-epoch", "issuer-generation", "receiver-generation", "protection", "expiry"]
)
def test_native_current_check_refuses_stale_or_foreign_context(change):
    issuer, receiver = cluster()
    request = query(issuer, target(current(receiver)))
    reference = call(issuer, "workflow.native-attest", request, principal=receiver.principal)
    if change == "peer-epoch":
        issuer.enrollment[receiver.principal]["epoch"] = uid("changed-peer-epoch")
    elif change == "issuer-generation":
        issuer.change_generation()
    elif change == "receiver-generation":
        receiver.change_generation()
    elif change == "protection":
        issuer.native_protected = False
    else:
        issuer.now = EXPIRES
    with pytest.raises(ContractError):
        call(
            issuer,
            "workflow.native-attestation.check",
            {"reference": reference},
            principal=receiver.principal,
        )
    if change != "peer-epoch":
        assert (
            call(issuer, "workflow.native-attest", request, principal=receiver.principal)
            == reference
        )
    assert read_record(issuer, reference)["request"] == request


def test_driver_and_native_proof_routes_and_assembly_cannot_be_substituted():
    owners = cluster()
    transition, _, references, requests, records = acquire(owners, owners[0])
    with pytest.raises(ContractError):
        call(owners[0], "workflow.attest", requests[0])
    with pytest.raises(ContractError):
        call(owners[0], "workflow.attestation.check", {"reference": references[0]})
    with pytest.raises(ContractError):
        assemble_phase_evidence(records, transition, current(owners[0]), public_keys={}, now=NOW)
    changed = copy.deepcopy(requests[0])
    changed["transition"]["advance_id"] = uid("different-native-final")
    with pytest.raises(ContractError, match="CONFLICT"):
        call(owners[0], "workflow.native-attest", changed, principal=owners[0].principal)


def test_native_routes_are_explicit_cli_forms_and_reject_intermediate_phases():
    for tool in ("app-ops", "host-ops"):
        assert (
            parse_command(tool + " workflow native-attest --request-stdin --json", tool)["use_case"]
            == "workflow.native-attest"
        )
        assert (
            parse_command(tool + " workflow native-attestation check --request-stdin --json", tool)[
                "use_case"
            ]
            == "workflow.native-attestation.check"
        )
    issuer, receiver = cluster()
    request = query(issuer, target(current(receiver)))
    request["transition"].update(from_phase="prepared", to_phase="draining")
    validate("workflow-evidence.schema.json", request, "NativeAttestationRequest")
    with pytest.raises(ContractError, match="final installed transition"):
        call(issuer, "workflow.native-attest", request, principal=receiver.principal)


def test_native_attestation_complete_acquisition_check_and_assembly_are_linear():
    samples = []
    for count in (4, 16, 64):
        owners = cluster()
        receiver = owners[0]
        transition = target(current(receiver))
        setup = []
        for issuer in owners:
            issuer.evidence_count = count
            setup.append(
                (
                    issuer,
                    query(issuer, transition),
                    issuer.context(transition),
                    issuer.participants(transition),
                )
            )

        def exercise(setup=setup, owners=owners, receiver=receiver, transition=transition):
            records = []
            for issuer, request, context, participants in setup:
                reference = issuer.measure_models(request, receiver, context, participants)
                records.append(read_record(issuer, reference))
            keys = {
                (canonical(owner.identity), "native-peer-key"): owner.public_key for owner in owners
            }
            return assemble_native_phase_evidence(
                records, transition, current(receiver), public_keys=keys, now=NOW
            )

        evidence, work = measure(exercise, modules=(workflow_attestations,))
        assert sum(len(proof["native_evidence"]) for proof in evidence["participants"]) == 2 * count
        samples.append((count, work))
    assert_linear(samples)
