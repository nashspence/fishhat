"""Public phase-proof acquisition between independently keyed synthetic owners.

Fake native observations below are explicit test state. These checks exercise
wire ownership, exact custody and proof joins, not real native fencing or storage.
"""

from __future__ import annotations

import base64
import copy
import io

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_client.wire import frame, read_frame
from fishhat_contracts.handoffs import validate_cli_result
from fishhat_contracts.record_delivery import (
    RecordSnapshot,
    validate_record_chunk,
    validate_record_payload,
)
from fishhat_contracts.validation import (
    MAX_BYTES,
    SCHEMAS,
    ContractError,
    canonical,
    digest,
    validate,
)
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_acknowledgments import workflow_mutation_acknowledgment
from fishhat_contracts.workflow_attestations import (
    AttestationRefusal,
    PhaseAttestationJournal,
    assemble_phase_evidence,
    validate_attestation,
)
from fishhat_contracts.workflow_evidence import REQUIREMENTS, phase_subject
from fishhat_contracts.workflows import (
    advance_workflow,
    decode_workflow_input,
    prepare_workflow,
    validate_advance_request,
    validate_workflow_input_custody,
)
from fishhat_owner.commands import parse_command

from scripts.project_policy import ROOT, read_toml
from tests.linear_support import assert_linear, measure
from tests.test_contracts import uid
from tests.test_owner_handoffs import (
    preparation_witness,
    rebind_workflow_proposal,
    request,
    staging,
    wire,
    workflow,
)
from tests.workflow_lifecycle_support import lifecycle

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-evidence.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
    ],
    "scope": "owner-issued complete phase proofs, current checks, exact replay and bounded wire delivery",
    "relationship": "candidate",
    "reason": "Two independently keyed synthetic owners answer framed public requests; the driver only sees public keys and immutable proof bytes. Wrong authority, stale state, lost protection, expiry, substitution and interrupted delivery challenge the contract without claiming native qualification.",
    "claims": [],
}

_CLAIMS = [
    "engineering:workflow.attestation-" + name
    for name in ("restore", "issue", "lookup", "check", "assemble")
]
CHECK_OVERRIDES = {
    name: {
        "purpose": "implementation",
        "authority": [
            *[
                "packages/fishhat-contracts/src/fishhat_contracts/workflow_attestations.py#"
                + symbol
                for symbol in (
                    "PhaseAttestationJournal.__init__",
                    "PhaseAttestationJournal.issue",
                    "PhaseAttestationJournal.get",
                    "PhaseAttestationJournal.check",
                    "assemble_phase_evidence",
                )
            ],
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-evidence.schema.json",
            "release.toml#/engineering",
        ],
        "scope": scope,
        "relationship": "scoped-witness",
        "reason": reason,
        "claims": _CLAIMS,
    }
    for name, scope, reason in [
        (
            "test_two_owner_public_attestation_path_and_lost_reply_replay",
            "complete issuer-local proofs, immutable replay and independently verified public advancement",
            "The driver obtains every signature through owner RPCs, reads complete records and resumes after a lost reply; native observations and authentication are explicit fake-owner context.",
        ),
        (
            "test_attestation_complete_issuance_assembly_restore_and_replay_are_linear",
            "complete issuance, assembly, journal restoration, current checking and exact lookup/replay over growing native evidence",
            "Executed Python, serialization and container counters cover at least sixteenfold evidence growth with full results and retries; no native or elapsed-time qualification is inferred.",
        ),
    ]
}
CHECK_OVERRIDES["test_receiver_bound_phase_closure_cannot_qualify_as_aggregate_linear"] = {
    "purpose": "validation-tooling",
    "authority": [
        "release.toml#/engineering",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-evidence.schema.json#/$defs/PhaseEvidence",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/WorkflowProposal",
        "tests/linear_support.py#assert_linear",
    ],
    "scope": "aggregate lower bounds over distinct participant owners, complete retained proposals and receiver-bound signed phase subjects",
    "relationship": "no-product-claim",
    "reason": "Increasing owner counts expose replication and distinct proof subjects outside issuer-local growth witnesses. The maintained linear proof guard rejects these aggregate costs; correctness and local linear evidence cannot qualify this composition. This is a structural lower bound, not an aggregate CPU, native or elapsed-time proof.",
    "claims": [],
}

NOW = "2026-11-01T00:00:00Z"
EXPIRES = "2026-11-01T01:00:00Z"
DRIVER = "ops-app-operate"


def call(owner, method, params, *, principal=DRIVER):
    incoming = read_frame(io.BytesIO(frame(request(method, params))))
    validate("ssh-request.schema.json", incoming)
    try:
        reply = wire(method, owner.dispatch(method, incoming["params"], principal))
    except AttestationRefusal as exc:
        reply = {**wire(method, None), "ok": False, "problem": exc.problem}
        del reply["result"]
    validate("ssh-response.schema.json", reply)
    reply = read_frame(io.BytesIO(frame(reply)))
    if not reply["ok"]:
        raise ContractError(reply["problem"]["code"] + ": " + reply["problem"]["summary"])
    validate_cli_result(reply["result"], retained_readers=owner.retained_readers)
    return reply["result"]


def read_record(owner, reference, *, principal=DRIVER):
    chunks, offset = [], 0
    while offset < reference["size"]:
        chunk = call(
            owner,
            "record.read",
            {
                "reference": reference,
                "offset": offset,
                "length": 196608,
            },
            principal=principal,
        )
        chunks.append(validate_record_chunk(chunk, reference, offset=offset, length=196608))
        offset = chunk["next_offset"]
    return validate_record_payload(
        reference,
        b"".join(chunks),
        expected_owner=owner.identity,
        retained_readers=owner.retained_readers,
    )


def current(owner):
    return read_record(
        owner,
        call(
            owner,
            "workflow.get",
            {
                "owner": owner.identity,
                "workflow_id": owner.workflow_id,
            },
        ),
    )


def transition(value):
    return {
        "authority": "driver",
        "owner": value["owner"],
        "workflow_id": value["id"],
        "advance_id": uid("public-advance-" + value["owner"]["id"] + str(value["generation"])),
        "proposal_digest": value["proposal_digest"],
        "procedure": value["type"],
        "requirements_digest": digest(REQUIREMENTS[value["type"]]),
        "expected_generation": value["generation"],
        "driver_term": value["driver_term"],
        "from_phase": value["phase"],
        "to_phase": "draining",
    }


def attestation_request(issuer, target):
    local = current(issuer)
    return {
        "owner": issuer.identity,
        "workflow_id": local["id"],
        "attestation_id": uid("attest-" + issuer.identity["id"] + digest(target)),
        "expected_generation": local["generation"],
        "transition": copy.deepcopy(target),
    }


class FakeNativeOwner:
    """Keys and native state belong to this fake receiving process, never its driver."""

    def __init__(self, identity, proposal, seed):
        self.identity, self.workflow_id = copy.deepcopy(identity), proposal["workflow_id"]
        self.retained_readers = None
        self.__key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        self.public_key = self.__key.public_key()
        self.__journal = PhaseAttestationJournal(
            identity, key_id="test-owner", private_key=self.__key
        )
        unsigned = {
            k: v for k, v in preparation_witness(proposal, identity).items() if k != "signature"
        }
        unsigned["key_id"] = "test-owner"
        self.__workflow = prepare_workflow(
            {"owner": identity, "proposal": proposal},
            expected_owner=identity,
            principal=DRIVER,
            verified_driver=proposal["initial_driver"],
            verified_content=proposal["content"],
            verified_preparation=sign(unsigned, self.__key),
        )
        self.peers = {}
        self.read_allowed = self.attest_allowed = self.native_protected = True
        self.now, self.expires_at = NOW, EXPIRES
        self.native_visits = 0
        self.evidence_count = 1
        self.__records, self.__staging, self.__bytes, self.__accepted = {}, {}, {}, set()

    def read_context(self, principal):
        return {
            "expected_owner": self.identity,
            "principal": principal,
            "read_authorized": self.read_allowed,
        }

    def native_context(self, target):
        receiver = current(self.peers[canonical(target["owner"])])
        preparations = [
            proof
            for peer in self.peers.values()
            for proof in current(peer)["prerequisite_witnesses"]
            if proof["owner"] == peer.identity and proof["state"] == "workflow-prepared"
        ]
        return {
            "verified_receiver": receiver,
            "verified_driver": {"principal": DRIVER, "term": receiver["driver_term"]},
            "verified_preparations": preparations,
        }

    def native_participants(self):
        self.native_visits += 1
        result = []
        for participant in self.__workflow["proposal"]["participants"]:
            if participant["owner"] != self.identity:
                continue
            evidence = [
                {
                    "owner": self.identity,
                    "id": uid("native-" + participant["resource"]["id"] + str(index)),
                    "purpose": "content",
                    "binding": {"kind": "staging", "staging_id": uid("native-stage-" + str(index))},
                    "digest": digest({"fake-native-obligation": index, "protected": True}),
                    "size": 1,
                }
                for index in range(self.evidence_count)
            ]
            result.append(
                {
                    "owner": self.identity,
                    "resource": participant["resource"],
                    "resource_generation": participant["expected_generation"],
                    "operations": [],
                    "native_evidence": evidence,
                    "expires_at": self.expires_at,
                }
            )
        return result

    def restart(self, *, retained=None, retained_readers=None):
        if retained is None:
            retained = []
            for identity in self.__accepted:
                reference = self.__journal.get(
                    {
                        "owner": self.identity,
                        "workflow_id": self.workflow_id,
                        "attestation_id": identity,
                    },
                    **self.read_context(DRIVER),
                )
                retained.append((reference, canonical(read_record(self, reference))))
        self.__journal = PhaseAttestationJournal(
            self.identity,
            key_id="test-owner",
            private_key=self.__key,
            retained=retained,
            retained_readers=retained_readers,
        )
        self.retained_readers = retained_readers

    def pause(self):
        self.__workflow = lifecycle(self.__workflow, "pause")

    def exercise_attestation_models(self, query, workflow, native_context, participants):
        """Measure owner models; synthetic RPC discovery/observation is fixture setup."""
        common = self.read_context(DRIVER)
        reference = self.__journal.issue(
            query,
            workflow,
            **common,
            attest_authorized=True,
            native_authorized=True,
            issued_at=NOW,
            expires_at=EXPIRES,
            verified_participants=participants,
            **native_context,
        )
        chunks, offset = [], 0
        while offset < reference["size"]:
            chunk = self.__journal.read(reference, offset=offset, length=196608, **common)
            chunks.append(validate_record_chunk(chunk, reference, offset=offset, length=196608))
            offset = chunk["next_offset"]
        data = b"".join(chunks)
        record = validate_record_payload(reference, data, expected_owner=self.identity)
        evidence = assemble_phase_evidence(
            [record], query["transition"], workflow, public_keys=trust([self]), now=NOW
        )
        self.__journal = PhaseAttestationJournal(
            self.identity,
            key_id="test-owner",
            private_key=self.__key,
            retained=[(reference, data)],
        )
        for _ in range(3):
            assert (
                self.__journal.get(
                    {key: query[key] for key in ("owner", "workflow_id", "attestation_id")},
                    **common,
                )
                == reference
            )
            assert (
                self.__journal.issue(
                    query,
                    workflow,
                    **common,
                    attest_authorized=False,
                    native_authorized=False,
                    issued_at="2027-01-01T00:00:00Z",
                    expires_at="2027-01-01T00:00:00Z",
                )
                == reference
            )
        checked = self.__journal.check(
            {"reference": reference},
            workflow,
            **common,
            check_authorized=True,
            native_current=True,
            now=NOW,
            **native_context,
        )
        assert checked["reference"] == reference
        return evidence

    def dispatch(self, method, params, principal):
        if method == "workflow.get":
            assert params == {"owner": self.identity, "workflow_id": self.workflow_id}
            assert self.read_allowed
            snapshot = RecordSnapshot(self.__workflow, uid("capsule-" + digest(self.__workflow)))
            self.__records[snapshot.reference["snapshot_id"]] = snapshot
            return snapshot.reference
        if method == "record.read":
            if params["reference"]["record"]["kind"] == "WorkflowPhaseAttestation":
                return self.__journal.read(**params, **self.read_context(principal))
            assert self.read_allowed
            return self.__records[params["reference"]["snapshot_id"]].chunk(**params)
        if method == "workflow.attestation.get":
            return self.__journal.get(params, **self.read_context(principal))
        if method == "workflow.attest":
            context = {}
            if params["attestation_id"] not in self.__accepted and self.read_allowed:
                context = self.native_context(params["transition"])
                context["verified_participants"] = self.native_participants()
            result = self.__journal.issue(
                params,
                self.__workflow,
                **self.read_context(principal),
                attest_authorized=self.attest_allowed,
                native_authorized=self.native_protected,
                issued_at=self.now,
                expires_at=self.expires_at,
                **context,
            )
            self.__accepted.add(params["attestation_id"])
            return result
        if method == "workflow.attestation.check":
            value = read_record(self, params["reference"])
            return self.__journal.check(
                params,
                self.__workflow,
                **self.read_context(principal),
                check_authorized=self.attest_allowed,
                native_current=self.native_protected,
                now=self.now,
                **self.native_context(value["request"]["transition"]),
            )
        if method.startswith("content."):
            return self.stage(method, params, principal)
        if method == "workflow.advance":
            return self.advance(params, principal)
        raise AssertionError(method)

    def stage(self, method, params, principal):
        identity = params["staging_id"]
        if method == "content.begin":
            value = staging()
            value.update(
                id=identity,
                owner=self.identity,
                resource=params["resource"],
                authenticated_principal=principal,
                purpose=params["purpose"],
                digest=params["digest"],
                size=params["size"],
                created_at=self.now,
                expires_at=EXPIRES,
            )
            self.__staging[identity], self.__bytes[identity] = value, bytearray()
        value, data = self.__staging[identity], self.__bytes[identity]
        assert value["authenticated_principal"] == principal
        if method == "content.chunk":
            chunk = base64.b64decode(params["base64"], validate=True)
            assert params["offset"] == len(data) and len(chunk) <= 196608
            data.extend(chunk)
            value["offset"] = len(data)
        if method == "content.commit":
            assert len(data) == value["size"]
            value["state"] = "committed"
            value["handle"] = {
                "owner": self.identity,
                "id": uid("handle-" + identity),
                "purpose": value["purpose"],
                "binding": {"kind": "staging", "staging_id": identity},
                "digest": value["digest"],
                "size": len(data),
            }
        return copy.deepcopy(value)

    def advance(self, reference, principal):
        if not self.read_allowed:
            raise AttestationRefusal(
                "PERMISSION_DENIED",
                "current workflow read scope required",
                self.identity,
                self.workflow_id,
            )
        stage_id = reference["input"]["binding"]["staging_id"]
        proposed = decode_workflow_input(
            "workflow.advance",
            reference,
            bytes(self.__bytes[stage_id]),
            expected_owner=self.identity,
        )
        mode = validate_advance_request(proposed, self.__workflow)
        context = {}
        if mode == "new":
            validate_workflow_input_custody(
                reference,
                proposed,
                self.__staging[stage_id],
                principal=principal,
                now=self.now,
            )
            selected = {}
            for proof in proposed["phase_evidence"]["participants"]:
                selected[canonical(proof["owner"])] = (proof["owner"], proof["attestation_id"])
            values = []
            for owner, identity in selected.values():
                peer = self.peers[canonical(owner)]
                ref = call(
                    peer,
                    "workflow.attestation.get",
                    {
                        "owner": owner,
                        "workflow_id": self.workflow_id,
                        "attestation_id": identity,
                    },
                )
                values.append(read_record(peer, ref))
                checked = call(peer, "workflow.attestation.check", {"reference": ref})
                assert checked["transition"] == proposed["phase_evidence"]["transition"]
            evidence = assemble_phase_evidence(
                values,
                proposed["phase_evidence"]["transition"],
                self.__workflow,
                public_keys=trust(self.peers.values()),
                now=self.now,
            )
            assert evidence == proposed["phase_evidence"]
            context = {
                "verified_phase_evidence": evidence,
                "now": self.now,
                "verified_preparations": proposed["witnesses"],
            }
        self.__workflow = advance_workflow(proposed, self.__workflow, **context)
        return workflow_mutation_acknowledgment(
            "workflow.advance",
            next(
                receipt
                for receipt in self.__workflow["advances"]
                if receipt["request"]["advance_id"] == proposed["advance_id"]
            ),
        )


def cluster(count=2, *, local_resources=1):
    value = workflow()
    template = value["participants"][0]
    for index in range(1, count):
        participant = copy.deepcopy(template)
        participant["owner"]["id"] = uid("public-owner-" + str(index))
        participant["resource"]["id"] = "node-" + str(index)
        participant["request_ids"] = [uid("public-child-" + str(index))]
        value["participants"].append(participant)
    for original in list(value["participants"]):
        for index in range(1, local_resources):
            participant = copy.deepcopy(original)
            participant["resource"]["id"] += "-resource-" + str(index)
            participant["request_ids"] = [uid("public-child-" + participant["resource"]["id"])]
            value["participants"].append(participant)
    rebind_workflow_proposal(value)
    identities = {canonical(p["owner"]): p["owner"] for p in value["proposal"]["participants"]}
    owners = [
        FakeNativeOwner(identity, value["proposal"], 40 + i)
        for i, identity in enumerate(identities.values())
    ]
    peers = {canonical(owner.identity): owner for owner in owners}
    for owner in owners:
        owner.peers = peers
    return owners


def trust(owners):
    return {(canonical(owner.identity), "test-owner"): owner.public_key for owner in owners}


def acquire(owners, target):
    records, references, requests = [], [], []
    for owner in owners:
        query = attestation_request(owner, target)
        reference = call(owner, "workflow.attest", query)
        records.append(read_record(owner, reference))
        references.append(reference)
        requests.append(query)
    return records, references, requests


def submit_advance(owner, target, evidence, owners):
    proposed = {
        **{
            k: target[k]
            for k in ("owner", "workflow_id", "advance_id", "expected_generation", "driver_term")
        },
        "phase": target["to_phase"],
        "phase_evidence": evidence,
        "transfer_completion": None,
        "witnesses": [
            p
            for peer in owners
            for p in current(peer)["prerequisite_witnesses"]
            if p["owner"] == peer.identity and p["state"] == "workflow-prepared"
        ],
    }
    data = canonical(proposed)
    stage_id = uid("public-stage-" + digest(proposed))
    call(
        owner,
        "content.begin",
        {
            "expected_owner": owner.identity,
            "staging_id": stage_id,
            "resource": {"kind": "workflow", "id": owner.workflow_id},
            "purpose": "workflow-input",
            "digest": digest(proposed),
            "size": len(data),
        },
    )
    for offset in range(0, len(data), 196608):
        call(
            owner,
            "content.chunk",
            {
                "owner": owner.identity,
                "staging_id": stage_id,
                "offset": offset,
                "base64": base64.b64encode(data[offset : offset + 196608]).decode(),
            },
        )
    staged = call(owner, "content.commit", {"owner": owner.identity, "staging_id": stage_id})
    reference = {"owner": owner.identity, "input": staged["handle"]}
    return call(owner, "workflow.advance", reference), reference


def test_two_owner_public_attestation_path_and_lost_reply_replay(monkeypatch):
    owners = cluster(local_resources=2)
    receiver = owners[0]
    value = current(receiver)
    target = transition(value)
    values, references, queries = acquire(owners, target)
    assert owners[0].public_key != owners[1].public_key
    assert [len(record["participants"]) for record in values] == [2, 2]
    # Model the first response being lost. The identity/redelivery is unchanged.
    visits = receiver.native_visits
    assert call(receiver, "workflow.attest", queries[0]) == references[0]
    assert receiver.native_visits == visits
    receiver.restart()
    assert (
        read_record(
            receiver,
            call(
                receiver,
                "workflow.attestation.get",
                {
                    "owner": receiver.identity,
                    "workflow_id": receiver.workflow_id,
                    "attestation_id": queries[0]["attestation_id"],
                },
            ),
        )
        == values[0]
    )
    evidence = assemble_phase_evidence(values, target, value, public_keys=trust(owners), now=NOW)
    acknowledgment, submitted = submit_advance(receiver, target, evidence, owners)
    assert acknowledgment["generation"] == 1
    assert current(receiver)["phase"] == "draining"
    # A peer at the adjacent destination can attest the other receiver's still
    # pending exact transition, allowing independently owned capsules to progress.
    second = owners[1]
    second_value = current(second)
    second_target = transition(second_value)
    second_values, second_references, _ = acquire(owners, second_target)
    second_evidence = assemble_phase_evidence(
        second_values, second_target, second_value, public_keys=trust(owners), now=NOW
    )
    submit_advance(second, second_target, second_evidence, owners)
    assert current(second)["phase"] == "draining"
    receiver.now = "2027-01-01T00:00:00Z"
    receiver.native_protected = False
    assert call(receiver, "workflow.advance", submitted) == acknowledgment
    assert call(receiver, "workflow.attest", queries[0]) == references[0]
    assert read_record(receiver, references[0]) == values[0]
    receiver.read_allowed = False
    with pytest.raises(ContractError, match="PERMISSION_DENIED"):
        call(receiver, "workflow.advance", submitted)
    receiver.read_allowed = True
    # Retention includes the original schema closure and bytes. A schema upgrade
    # cannot silently manufacture a different reference for an accepted identity.
    retained = [
        (references[0], canonical(values[0])),
        (second_references[0], canonical(second_values[0])),
    ]
    with monkeypatch.context() as changed_schema:
        changed_schema.setitem(
            SCHEMAS["common.schema.json"]["$defs"]["Owner"], "description", "updated owner closure"
        )
        with pytest.raises(ContractError, match="schema substitution"):
            receiver.restart(retained=retained)
        readers = {
            (
                references[0]["schema"]["uri"],
                references[0]["schema"]["digest"],
            ): validate_attestation
        }
        receiver.restart(retained=retained, retained_readers=readers)
        assert call(receiver, "workflow.attest", queries[0]) == references[0]
        assert read_record(receiver, references[0]) == values[0]
        checked = {
            "kind": "CurrentWorkflowAttestation",
            "reference": references[0],
            "transition": target,
            "checked_at": NOW,
        }
        with pytest.raises(ContractError, match="schema substitution"):
            validate_cli_result(checked)
        validate_cli_result(checked, retained_readers=readers)


@pytest.mark.parametrize(
    "failure",
    [
        "read",
        "authority",
        "native",
        "driver",
        "issuer-generation",
        "receiver-generation",
        "phase",
        "proposal",
        "policy-expiry",
    ],
)
def test_new_attestation_refuses_untrusted_or_stale_context(failure):
    owners = cluster()
    owner = owners[0]
    query = attestation_request(owner, transition(current(owner)))
    principal = DRIVER
    if failure == "read":
        owner.read_allowed = False
    elif failure == "authority":
        owner.attest_allowed = False
    elif failure == "native":
        owner.native_protected = False
    elif failure == "driver":
        principal = "another-reader"
    elif failure == "issuer-generation":
        query["expected_generation"] += 1
    elif failure == "receiver-generation":
        query["transition"]["expected_generation"] += 1
    elif failure == "phase":
        query["transition"]["to_phase"] = "quiescent"
    elif failure == "proposal":
        query["transition"]["proposal_digest"] = "sha256:" + "f" * 64
    else:
        owner.expires_at = NOW
    with pytest.raises(ContractError):
        call(owner, "workflow.attest", query, principal=principal)
    owner.read_allowed = True
    with pytest.raises(ContractError, match="NOT_FOUND"):
        call(
            owner,
            "workflow.attestation.get",
            {k: query[k] for k in ("owner", "workflow_id", "attestation_id")},
        )


def test_replay_keeps_original_expiry_attribution_and_checks_current_read_scope():
    owner = cluster(1)[0]
    values, refs, queries = acquire([owner], transition(current(owner)))
    owner.pause()
    owner.attest_allowed = owner.native_protected = False
    owner.now = "2027-01-01T00:00:00Z"
    assert call(owner, "workflow.attest", queries[0], principal="replacement-reader") == refs[0]
    assert read_record(owner, refs[0], principal="replacement-reader") == values[0]
    changed = copy.deepcopy(queries[0])
    changed["expected_generation"] += 1
    with pytest.raises(ContractError, match="CONFLICT"):
        call(owner, "workflow.attest", changed)
    owner.read_allowed = False
    with pytest.raises(ContractError, match="PERMISSION_DENIED"):
        call(owner, "workflow.attest", queries[0])


@pytest.mark.parametrize(
    "change",
    [
        "expiry",
        "key",
        "signature",
        "missing-owner",
        "mixed-transition",
        "signed-deadline",
        "duplicate-owner",
    ],
)
def test_assembly_refuses_expired_substituted_or_incomplete_proofs(change):
    owners = cluster()
    value = current(owners[0])
    target = transition(value)
    records, _, _ = acquire(owners, target)
    keys, now = trust(owners), NOW
    if change == "expiry":
        cached = assemble_phase_evidence(records, target, value, public_keys=keys, now=NOW)
        preparations = [
            proof
            for owner in owners
            for proof in current(owner)["prerequisite_witnesses"]
            if proof["owner"] == owner.identity and proof["state"] == "workflow-prepared"
        ]
        proposed = {
            **{
                key: target[key]
                for key in (
                    "owner",
                    "workflow_id",
                    "advance_id",
                    "expected_generation",
                    "driver_term",
                )
            },
            "phase": target["to_phase"],
            "transfer_completion": None,
            "phase_evidence": cached,
            "witnesses": preparations,
        }
        with pytest.raises(ContractError, match="proof is not currently valid"):
            advance_workflow(
                proposed,
                value,
                verified_phase_evidence=cached,
                verified_preparations=preparations,
                now=EXPIRES,
            )
        now = EXPIRES
    elif change == "key":
        keys = {}
    elif change == "signature":
        records[0]["participants"][0]["witness"]["signature"] = "A" * 86 + "=="
    elif change == "missing-owner":
        records.pop()
    elif change == "mixed-transition":
        target["advance_id"] = uid("other-transition")
    elif change == "signed-deadline":
        records[0]["participants"][0]["expires_at"] = "2027-01-01T00:00:00Z"
    else:
        records.append(copy.deepcopy(records[0]))
    with pytest.raises(ContractError):
        assemble_phase_evidence(records, target, value, public_keys=keys, now=now)


@pytest.mark.parametrize(
    "change", ["expired", "lost-protection", "generation", "reference", "read"]
)
def test_current_check_refuses_stale_or_lost_protection_without_renewal(change):
    owner = cluster(1)[0]
    records, refs, _ = acquire([owner], transition(current(owner)))
    reference = copy.deepcopy(refs[0])
    if change == "expired":
        owner.now = EXPIRES
    elif change == "lost-protection":
        owner.native_protected = False
    elif change == "generation":
        owner.pause()
    elif change == "reference":
        reference["digest"] = "sha256:" + "f" * 64
    else:
        owner.read_allowed = False
    with pytest.raises((ContractError, AssertionError)):
        call(owner, "workflow.attestation.check", {"reference": reference})
    owner.read_allowed = True
    assert read_record(owner, refs[0]) == records[0]


def test_complete_large_attestation_uses_record_chunks_and_current_check_is_finite():
    owner = cluster(1)[0]
    owner.evidence_count = 3500
    values, references, _ = acquire([owner], transition(current(owner)))
    reference = references[0]
    assert reference["size"] > MAX_BYTES
    assert len(values[0]["participants"][0]["native_evidence"]) == 3500
    checked = call(owner, "workflow.attestation.check", {"reference": reference})
    assert len(canonical(checked)) < MAX_BYTES
    assert checked["reference"] == reference
    assert read_record(owner, reference) == values[0]
    for verb, method in [
        ("attest", "workflow.attest"),
        ("attestation show", "workflow.attestation.get"),
        ("attestation check", "workflow.attestation.check"),
    ]:
        assert (
            parse_command("host-ops workflow " + verb + " --request-stdin --json", "host-ops")[
                "use_case"
            ]
            == method
        )


def test_driver_cannot_submit_native_context_or_inline_proofs_as_attestation_input(monkeypatch):
    owner = cluster(1, local_resources=2)[0]
    query = attestation_request(owner, transition(current(owner)))
    for field, value in [
        ("native_authorized", True),
        ("participants", []),
        ("key_id", "test-owner"),
        ("expires_at", EXPIRES),
    ]:
        with pytest.raises(ContractError):
            validate("ssh-request.schema.json", request("workflow.attest", {**query, field: value}))
    complete = owner.native_participants()
    for incomplete in (complete[:1], [*complete, copy.deepcopy(complete[0])]):
        with monkeypatch.context() as native:
            native.setattr(owner, "native_participants", lambda incomplete=incomplete: incomplete)
            with pytest.raises(ContractError, match=r"participant closure|missing participant"):
                call(owner, "workflow.attest", query)
    result = read_record(owner, call(owner, "workflow.attest", query))
    assert len(result["participants"]) == 2


def test_attestation_complete_issuance_assembly_restore_and_replay_are_linear():
    samples = []
    for count in (4, 16, 64):
        owner = cluster(1)[0]
        owner.evidence_count = count
        value = current(owner)
        target = transition(value)
        query = attestation_request(owner, target)
        native_context = owner.native_context(target)
        participants = owner.native_participants()

        def exercise(
            owner=owner, query=query, value=value, context=native_context, participants=participants
        ):
            return owner.exercise_attestation_models(query, value, context, participants)

        result, work = measure(exercise)
        assert len(result["participants"][0]["native_evidence"]) == count
        samples.append((count, work))
    assert_linear(samples)


def test_receiver_bound_phase_closure_cannot_qualify_as_aggregate_linear():
    samples = []
    for count in (1, 4, 16):
        owners = cluster(count)
        capsules = [current(owner) for owner in owners]
        assert len({canonical(value["owner"]) for value in capsules}) == count
        proposals = [canonical(value["proposal"]) for value in capsules]
        assert all(proposal == proposals[0] for proposal in proposals)
        subjects = set()
        for receiver in capsules:
            target = transition(receiver)
            for issuer in owners:
                for participant in issuer.native_participants():
                    participant["attestation_id"] = uid(
                        "attest-" + issuer.identity["id"] + digest(target)
                    )
                    subject = canonical(phase_subject(target, participant))
                    assert subject not in subjects
                    subjects.add(subject)
        # These are actual complete proposal copies and the exact canonical
        # preimages required by the signing boundary, before signature envelopes,
        # current native checks, framing, additional phases or retry delivery.
        samples.append(
            (
                count,
                {
                    "proposal_replica_bytes": sum(map(len, proposals)),
                    "distinct_signed_subjects": len(subjects),
                    "signed_subject_bytes": sum(map(len, subjects)),
                },
            )
        )
        assert len(subjects) == count * count
    for metric in samples[0][1]:
        with pytest.raises(AssertionError, match=metric):
            assert_linear([(count, {metric: costs[metric]}) for count, costs in samples])
    policy = read_toml(ROOT / "release.toml")
    assert policy["engineering"] == {"growth": "linear", "implementations": "all"}
    assert policy["production_qualified"] is False
    assert policy["publication"]["qualified_native_release_allowed"] is False
