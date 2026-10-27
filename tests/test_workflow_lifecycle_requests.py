"""Untrusted lifecycle requests and protected decisions; no native qualification."""

from __future__ import annotations

import base64
import copy
import io

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_client.wire import frame, read_frame
from fishhat_contracts.handoffs import validate_cli_result, validate_workflow
from fishhat_contracts.record_delivery import RecordSnapshot, validate_record_payload
from fishhat_contracts.validation import MAX_BYTES, ContractError, canonical, digest, validate
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_lifecycle import (
    LifecycleRefusal,
    request_workflow_lifecycle,
    validate_lifecycle_result,
)
from fishhat_owner.commands import parse_command

from tests.linear_support import assert_linear, measure
from tests.test_contracts import uid
from tests.test_owner_handoffs import request, wire, workflow
from tests.test_workflow_continuations import move
from tests.test_workflow_recovery import finish_transfer
from tests.test_workflow_transfer import committed, frozen
from tests.workflow_lifecycle_support import lifecycle, lifecycle_decision, seal_lifecycle

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/LifecycleRequest",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/LifecycleResult",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/NativeLifecycleDecision",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/states.json#/workflow_meanings",
    ],
    "scope": "request/native authority separation, immutable replay, current permission and complete lifecycle result delivery",
    "relationship": "candidate",
    "reason": "Independent synthetic receiver context challenges request attribution, identity conflicts, lifecycle barriers, changed current permissions and complete transferred evidence. No test authenticates a native caller, persists an admission transaction or establishes actual reconciliation or child cessation.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_accepted_lifecycle_request_replay_preserves_original_result_and_attribution": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_lifecycle.py#request_workflow_lifecycle",
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/LifecycleRequest",
            "release.toml#/engineering",
        ],
        "scope": "complete original lifecycle request attribution and result after later transfer and lifecycle transitions",
        "relationship": "scoped-witness",
        "reason": "The reference request helper preserves complete original accepted attribution and outcome through newer driver and lifecycle history, while independently supplied current read permission controls replay disclosure. This does not establish native authentication or persistence.",
        "claims": ["engineering:workflow.lifecycle-request"],
    },
    "test_lifecycle_request_linear_complete_history_work": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_lifecycle.py#request_workflow_lifecycle",
            "release.toml#/engineering",
        ],
        "scope": "complete lifecycle request processing and replay over increasing retained histories",
        "relationship": "scoped-witness",
        "reason": "Deterministic Python, byte and container counters measure the actual complete-input request helper at sixteenfold history extent; this proves reference work growth, not native bounded persistence or timing.",
        "claims": ["engineering:workflow.lifecycle-request"],
    },
}


def query(value, action, *, request_id=None):
    return {
        "owner": copy.deepcopy(value["owner"]),
        "workflow_id": value["id"],
        "request_id": request_id or uid(f"requested-{value['id']}-{value['generation']}-{action}"),
        "proposal_digest": value["proposal_digest"],
        "expected_generation": value["generation"],
        "driver_term": value["driver_term"],
        "action": action,
    }


def requested_decision(value, proposed, principal="scoped-admin"):
    decision = lifecycle_decision(value, proposed["action"])
    decision["advance_id"] = proposed["request_id"]
    decision["request"] = {
        "input": copy.deepcopy(proposed),
        "authenticated_principal": principal,
    }
    return seal_lifecycle(decision, value)


def receive(value, proposed, **changes):
    context = {
        "expected_owner": value["owner"],
        "principal": "scoped-admin",
        "read_authorized": True,
        "request_authorized": True,
        "native_authorized": True,
        "verified_driver": {"principal": value["driver_principal"], "term": value["driver_term"]},
        "verified_reconciled": True,
    }
    context.update(changes)
    if "verified_decision" not in context:
        context["verified_decision"] = requested_decision(value, proposed, context["principal"])
    return request_workflow_lifecycle(proposed, value, **context)


@pytest.mark.parametrize("action", ["pause", "resume", "require-recovery", "cancel"])
def test_requested_lifecycle_keeps_protected_decision_and_custody_distinct(action):
    value = lifecycle(workflow(), "pause") if action == "resume" else workflow()
    value["holds"] = [uid("retained-request-hold")]
    before = canonical(value)
    proposed = query(value, action)
    result, accepted = receive(value, proposed)
    assert canonical(value) == before
    assert result["generation"] == value["generation"] + 1
    expected = {
        "pause": "paused",
        "resume": "prepared",
        "require-recovery": "recovery-required",
        "cancel": "cancelled",
    }
    assert result["state"] == expected[action]
    assert accepted["receipt"] == result["advances"][-1]
    assert accepted["receipt"]["authority"] == "native-lifecycle"
    decision = accepted["receipt"]["decision"]
    assert decision["request"] == {"input": proposed, "authenticated_principal": "scoped-admin"}
    assert decision["witness"]["subject_digest"] == digest(
        {key: item for key, item in decision.items() if key != "witness"}
    )
    for key in value.keys() - {"state", "generation", "advances"}:
        assert result[key] == value[key]
    validate_lifecycle_result(accepted)
    validate_cli_result(accepted)


def test_accepted_lifecycle_request_replay_preserves_original_result_and_attribution():
    value = workflow()
    proposed = query(value, "pause")
    paused, original = receive(value, proposed)
    moved, _ = finish_transfer(paused)
    later = lifecycle(lifecycle(moved, "resume"), "cancel")
    replayed, result = receive(
        later,
        proposed,
        principal="replacement-reader",
        request_authorized=False,
        native_authorized=False,
        verified_decision=None,
        verified_driver=None,
        verified_reconciled=False,
    )
    assert result == original
    assert result["receipt"]["decision"]["request"]["authenticated_principal"] == "scoped-admin"
    assert replayed == later and replayed["state"] == "cancelled"
    assert replayed["driver_term"] > proposed["driver_term"]
    with pytest.raises(LifecycleRefusal) as caught:
        receive(later, proposed, read_authorized=False, verified_decision=None)
    assert caught.value.problem["code"] == "PERMISSION_DENIED"


@pytest.mark.parametrize("change", ["action", "generation", "term", "proposal"])
def test_accepted_request_identity_rejects_changed_input_before_stale_checks(change):
    value = workflow()
    proposed = query(value, "pause")
    paused, _ = receive(value, proposed)
    changed = copy.deepcopy(proposed)
    if change == "action":
        changed["action"] = "cancel"
    elif change == "proposal":
        changed["proposal_digest"] = "sha256:" + "f" * 64
    else:
        changed["expected_generation" if change == "generation" else "driver_term"] += 1
    with pytest.raises(LifecycleRefusal) as caught:
        receive(paused, changed, verified_decision=None)
    assert caught.value.problem["code"] == "CONFLICT"
    validate("records.schema.json", caught.value.problem, "Problem")


@pytest.mark.parametrize("origin", ["native", "driver"])
def test_request_cannot_reuse_an_unrelated_native_or_driver_transition_identity(origin):
    value = lifecycle(workflow(), "pause") if origin == "native" else move(workflow(), "draining")
    receipt = value["advances"][0]
    original = receipt["decision" if origin == "native" else "request"]
    proposed = query(value, "cancel", request_id=original["advance_id"])
    with pytest.raises(LifecycleRefusal) as caught:
        receive(value, proposed, verified_decision=None)
    assert caught.value.problem["code"] == "CONFLICT"


@pytest.mark.parametrize("field", ["native_authorized", "request_authorized", "read_authorized"])
def test_new_request_requires_independent_current_receiving_permissions(field):
    value = workflow()
    before = canonical(value)
    with pytest.raises(LifecycleRefusal) as caught:
        receive(value, query(value, "pause"), **{field: False})
    assert caught.value.problem["code"] == "PERMISSION_DENIED"
    assert canonical(value) == before


@pytest.mark.parametrize("change", ["principal", "input", "procedure", "native-decision"])
def test_request_cannot_supply_or_substitute_protected_native_decision_context(change):
    value = workflow()
    proposed = query(value, "pause")
    decision = requested_decision(value, proposed)
    if change == "principal":
        decision["request"]["authenticated_principal"] = "different-admin"
        seal_lifecycle(decision, value)
    elif change == "input":
        decision["request"]["input"]["action"] = "cancel"
        seal_lifecycle(decision, value)
    elif change == "procedure":
        decision["procedure"] = "runtime-upgrade"
        seal_lifecycle(decision, value)
    else:
        decision = None
    with pytest.raises(LifecycleRefusal) as caught:
        receive(value, proposed, verified_decision=decision)
    assert caught.value.problem["code"] == "PRECONDITION_FAILED"


@pytest.mark.parametrize(
    "field",
    [
        "authority",
        "witness",
        "native_authorized",
        "reconciled",
        "authenticated_principal",
        "from_state",
        "phase",
    ],
)
def test_closed_request_rejects_all_caller_claimed_native_authority(field):
    value = workflow()
    proposed = query(value, "pause")
    proposed[field] = True
    with pytest.raises(ContractError):
        receive(value, proposed, verified_decision=None)


@pytest.mark.parametrize("change", ["generation", "term", "proposal", "owner", "workflow"])
def test_new_request_binds_exact_workflow_receiver_and_current_preconditions(change):
    value = workflow()
    proposed = query(value, "pause")
    if change == "owner":
        proposed["owner"]["epoch"] = uid("different-epoch")
    elif change == "workflow":
        proposed["workflow_id"] = uid("different-workflow")
    elif change == "proposal":
        proposed["proposal_digest"] = "sha256:" + "c" * 64
    else:
        proposed["expected_generation" if change == "generation" else "driver_term"] += 1
    with pytest.raises(LifecycleRefusal) as caught:
        receive(value, proposed, verified_decision=None)
    expected = {"owner": "OWNER_EPOCH_CHANGED", "workflow": "NOT_FOUND"}
    assert caught.value.problem["code"] == expected.get(change, "PRECONDITION_FAILED")


@pytest.mark.parametrize("change", ["driver", "reconciliation", "freeze", "commit"])
def test_requested_resume_cannot_bypass_driver_reconciliation_or_transfer(change):
    value = lifecycle(workflow(), "pause")
    context = {}
    if change == "driver":
        context["verified_driver"] = {
            "principal": "unapproved-driver",
            "term": value["driver_term"],
        }
    elif change == "reconciliation":
        context["verified_reconciled"] = False
    elif change == "freeze":
        value, _ = frozen(value)
    else:
        value, _ = committed(value)
    before = canonical(value)
    with pytest.raises(LifecycleRefusal) as caught:
        receive(value, query(value, "resume"), **context)
    assert caught.value.problem["code"] == "PRECONDITION_FAILED"
    assert canonical(value) == before


@pytest.mark.parametrize("state", ["cancelled", "recovery-required"])
def test_request_cannot_relabel_terminal_or_recovery_required_work_for_resume(state):
    value = lifecycle(workflow(), "cancel" if state == "cancelled" else "require-recovery")
    proposed = query(value, "resume")
    imagined = {**value, "state": "paused"}
    decision = requested_decision(imagined, proposed)
    with pytest.raises(LifecycleRefusal) as caught:
        receive(value, proposed, verified_decision=decision)
    assert caught.value.problem["code"] == "PRECONDITION_FAILED"


@pytest.mark.parametrize(
    "change", ["request", "digest", "principal", "generation", "state", "procedure"]
)
def test_typed_result_rejects_relabelled_request_attribution_or_outcome(change):
    value = workflow()
    _, accepted = receive(value, query(value, "pause"))
    changed = copy.deepcopy(accepted)
    if change == "request":
        changed["request_id"] = uid("other-request")
    elif change == "digest":
        changed["request_digest"] = "sha256:" + "f" * 64
    elif change == "principal":
        changed["receipt"]["decision"]["request"]["authenticated_principal"] = "other-admin"
        changed["receipt"]["decision_digest"] = digest(changed["receipt"]["decision"])
    elif change == "procedure":
        changed["procedure"] = "runtime-upgrade"
    elif change == "generation":
        changed["receipt"]["generation"] += 1
    else:
        changed["receipt"]["state"] = "active"
    with pytest.raises(ContractError):
        validate_lifecycle_result(changed)


def test_lifecycle_request_wire_and_direct_owner_parity():
    value = workflow()
    proposed = query(value, "pause")
    _, accepted = receive(value, proposed)
    envelope = request("workflow.lifecycle", proposed)
    validate("ssh-request.schema.json", envelope)
    assert read_frame(io.BytesIO(frame(envelope))) == envelope
    reply = wire("workflow.lifecycle", accepted)
    validate("ssh-response.schema.json", reply)
    assert read_frame(io.BytesIO(frame(reply))) == reply
    assert (
        parse_command("host-ops workflow lifecycle --request-stdin --json", "host-ops")["use_case"]
        == "workflow.lifecycle"
    )
    with pytest.raises(LifecycleRefusal) as caught:
        receive(value, proposed, request_authorized=False)
    refused = {key: item for key, item in reply.items() if key != "result"}
    refused.update(ok=False, problem=caught.value.problem)
    validate("ssh-response.schema.json", refused)


def test_large_lifecycle_evidence_is_read_completely_from_retained_workflow():
    value = workflow()
    proposed = query(value, "pause")
    decision = requested_decision(value, proposed)
    body = {key: item for key, item in decision["witness"].items() if key != "signature"}
    body["evidence_digests"] = ["sha256:" + f"{index:064x}" for index in range(15000)]
    decision["witness"] = sign(body, Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))
    retained, accepted = receive(value, proposed, verified_decision=decision)
    assert len(canonical(accepted)) > MAX_BYTES
    with pytest.raises(ContractError, match="frame size"):
        frame(wire("workflow.lifecycle", accepted))
    snapshot = RecordSnapshot(retained, uid("large-lifecycle-result"))
    reference = snapshot.reference
    response = wire("workflow.lifecycle", reference)
    validate("ssh-response.schema.json", response)
    assert read_frame(io.BytesIO(frame(response))) == response
    parts = []
    offset = 0
    while offset < reference["size"]:
        chunk = snapshot.chunk(reference, offset=offset, length=196608)
        parts.append(base64.b64decode(chunk["base64"], validate=True))
        offset += len(parts[-1])
    recovered = validate_record_payload(
        reference, b"".join(parts), expected_owner=retained["owner"]
    )
    assert recovered == retained
    _, replay = receive(recovered, proposed, verified_decision=None)
    assert replay == accepted
    assert len(replay["receipt"]["decision"]["witness"]["evidence_digests"]) == 15000


def _history(count):
    value = workflow()
    for index in range(count):
        action = "pause" if index % 2 == 0 else "resume"
        decision = lifecycle_decision(value, action)
        value["generation"] += 1
        value["state"] = "paused" if action == "pause" else "prepared"
        value["advances"].append(
            {
                "authority": "native-lifecycle",
                "decision": decision,
                "decision_digest": digest(decision),
                **{key: value[key] for key in ("generation", "driver_term", "phase", "state")},
            }
        )
    validate_workflow(value)
    return value


def test_lifecycle_request_linear_complete_history_work():
    samples, replays = [], []
    for count in (16, 64, 256):
        value = _history(count)
        proposed = query(value, "pause")
        decision = requested_decision(value, proposed)
        (retained, accepted), work = measure(
            lambda value=value, proposed=proposed, decision=decision: receive(
                value, proposed, verified_decision=decision
            )
        )
        assert len(retained["advances"]) == count + 1
        assert retained["advances"][:-1] == value["advances"]
        samples.append((count, work))
        (_, repeated), replay_work = measure(
            lambda retained=retained, proposed=proposed: receive(
                retained, proposed, verified_decision=None
            )
        )
        assert repeated == accepted
        replays.append((count, replay_work))
    assert_linear(samples)
    assert_linear(replays)
