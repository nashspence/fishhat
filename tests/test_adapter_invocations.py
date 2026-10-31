from __future__ import annotations

import copy

import pytest
from fishhat_adapters import check_invocation, check_request, check_response
from fishhat_contracts.validation import ContractError, digest

from tests.adapter_support import OWNER, identifier
from tests.test_adapter_dns import change, generation, rrset
from tests.test_adapter_effects import coordinator, prepare, result
from tests.test_adapter_handoffs import (
    artifact,
    handoff,
    installed,
    invocation_for,
    response_for,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/capture-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/credential-issuer-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/secret-source-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/backup-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/dns-adapter.schema.json",
    ],
    "scope": "owner-authored invocation closure and original-method recovery result custody",
    "relationship": "candidate",
    "reason": "Lost replies, executor replacement and missing outputs use synthetic retained state; no native dispatch or qualification.",
    "claims": [],
}


def recovered(invocation):
    request = invocation["request"]
    return {
        "contract": request["contract"],
        "method": "reconcile",
        "input": {
            "scope": copy.deepcopy(request["input"]["scope"]),
            "invocation": copy.deepcopy(invocation),
        },
    }


def handoff_output(role, request):
    inputs = request["input"]
    if role == "capture":
        return {"snapshots": [copy.deepcopy(inputs["snapshot"])], "verification": "consistent"}
    if role == "credential-issuer":
        return {
            "leases": [
                {
                    **copy.deepcopy(inputs["lease"]),
                    "value_handle": "protected:old",
                    "validity": "revoked",
                    "expires_at": None,
                    "valid_from": None,
                    "renewable": False,
                }
            ]
        }
    return {
        "versions": [
            {
                "source": inputs["binding"]["instance"],
                "entry": inputs["entry"],
                "version": inputs["version"],
                "value_handle": "protected:new",
                "validity": "valid",
                "expires_at": None,
            }
        ]
    }


def test_bare_mutation_payload_is_not_an_executable_invocation():
    registry, request = handoff("capture", "restore")
    invocation = invocation_for(request)
    check_invocation("capture", invocation)
    registry.authorize_invocation("capture", invocation, owner_approved=True)
    with pytest.raises(ContractError, match="EFFECT_INVOCATION_REQUIRED"):
        registry.authorize_request("selected", "capture", request, owner_approved=True)
    response = response_for(request, invocation["attempt"], handoff_output("capture", request))
    with pytest.raises(ContractError, match="EFFECT_INVOCATION_REQUIRED"):
        check_response("capture", request, response)
    legacy = recovered(invocation)
    legacy["input"].pop("invocation")
    legacy["input"]["attempt"] = invocation["attempt"]
    with pytest.raises(ContractError):
        check_request("capture", legacy)


def test_identical_payloads_have_independent_owner_attempt_identity():
    _, request = handoff("credential-issuer", "revoke")
    original = invocation_for(request)
    another = copy.deepcopy(original)
    another["attempt"]["attempt_id"] = identifier(99)
    check_invocation("credential-issuer", original)
    check_invocation("credential-issuer", another)
    assert original["attempt"]["input_digest"] == another["attempt"]["input_digest"]
    response = response_for(
        request, original["attempt"], handoff_output("credential-issuer", request)
    )
    with pytest.raises(ContractError, match="RESULT_IDENTITY"):
        check_response("credential-issuer", request, response, invocation=another)


@pytest.mark.parametrize("field", ["input", "executor", "method", "scope"])
def test_invocation_cannot_substitute_its_retained_identity(field):
    _, request = handoff("capture", "restore")
    invocation = invocation_for(request)
    if field == "input":
        invocation["request"]["input"]["snapshot"]["artifacts"] = [artifact("e")]
    elif field == "executor":
        invocation["attempt"]["executor"]["configuration_digest"] = artifact("e")["digest"]
    elif field == "method":
        invocation["attempt"]["method"] = "verify"
    else:
        invocation["attempt"]["scope"]["handle"] = "other"
    with pytest.raises(ContractError):
        check_invocation("capture", invocation)


@pytest.mark.parametrize("state", ["prepared", "resolved", "reconciling"])
def test_retained_non_dispatchable_attempt_is_not_new_execution_authority(state):
    registry, request = handoff("capture", "restore")
    invocation = invocation_for(request)
    invocation["attempt"]["state"] = state
    with pytest.raises(ContractError, match="INVOCATION_NOT_DISPATCHABLE"):
        registry.authorize_invocation("capture", invocation, owner_approved=True)


@pytest.mark.parametrize(
    "role,method",
    [("capture", "restore"), ("credential-issuer", "revoke"), ("secret-source", "publish")],
)
def test_lost_reply_preserves_original_typed_output_identity(role, method):
    registry, request = handoff(role, method)
    invocation = invocation_for(request)
    query = recovered(invocation)
    registry.authorize_request("selected", role, query, invocation=invocation, owner_approved=True)
    output = handoff_output(role, request)
    reply = response_for(query, invocation["attempt"], output)
    check_response(role, query, reply, invocation=invocation)
    if role == "capture":
        output["snapshots"][0]["artifacts"] = [artifact("e")]
    elif role == "credential-issuer":
        output["leases"][0]["lease"] = "lease:replacement"
    else:
        output["versions"][0]["version"] = "version:replacement"
    with pytest.raises(ContractError):
        check_response(role, query, reply, invocation=invocation)


@pytest.mark.parametrize("change", ["configuration", "generation"])
def test_reconciliation_cannot_retarget_to_current_enrollment(change):
    _, request = handoff("capture", "restore")
    invocation = invocation_for(request)
    replacements = (
        {"endpoint": "replacement-target"} if change == "configuration" else {"generation": 4}
    )
    registry, _ = installed("capture", **replacements)
    with pytest.raises(ContractError, match="HANDOFF_INSTANCE_IDENTITY"):
        registry.authorize_invocation("capture", invocation, owner_approved=True)
    with pytest.raises(ContractError, match="RECONCILIATION_INSTANCE_IDENTITY"):
        registry.authorize_request(
            "selected", "capture", recovered(invocation), invocation=invocation, owner_approved=True
        )


def test_reconciliation_request_cannot_authorize_its_own_original_context():
    registry, request = handoff("capture", "restore")
    invocation = invocation_for(request)
    with pytest.raises(ContractError, match="EFFECT_INVOCATION_REQUIRED"):
        registry.authorize_request(
            "selected", "capture", recovered(invocation), owner_approved=True
        )
    query = recovered(invocation)
    original = query["input"]["invocation"]
    original["request"]["input"]["snapshot"]["artifacts"] = [artifact("e")]
    original["attempt"]["input_digest"] = digest(original["request"])
    with pytest.raises(ContractError, match="RECONCILIATION_IDENTITY"):
        registry.authorize_request(
            "selected", "capture", query, invocation=invocation, owner_approved=True
        )


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
@pytest.mark.parametrize(
    "role,method",
    [("capture", "restore"), ("credential-issuer", "revoke"), ("secret-source", "publish")],
)
def test_terminal_success_cannot_omit_or_expand_exact_result_custody(role, method, reconcile):
    _, request = handoff(role, method)
    invocation = invocation_for(request)
    query = recovered(invocation) if reconcile else request
    output = handoff_output(role, request)
    collection = next(key for key in output if isinstance(output[key], list))
    output[collection] = []
    reply = response_for(query, invocation["attempt"], output)
    with pytest.raises(ContractError):
        check_response(role, query, reply, invocation=invocation)
    output[collection] = handoff_output(role, request)[collection] * 2
    with pytest.raises(ContractError):
        check_response(role, query, reply, invocation=invocation)


@pytest.mark.parametrize("outcome", ["pending", "rejected", "failed"])
def test_no_result_is_representable_without_claiming_success(outcome):
    _, request = handoff("capture", "restore")
    invocation = invocation_for(request)
    reply = response_for(
        request, invocation["attempt"], {"snapshots": [], "verification": "unknown"}
    )
    effect = reply["effect"]
    if outcome == "pending":
        effect.update(task_state="unknown", effect_certainty="unknown", postcondition="unknown")
        reply["coverage"] = "unknown"
    elif outcome == "rejected":
        effect.update(
            acknowledgment="rejected", effect_certainty="none", postcondition="not-satisfied"
        )
    else:
        effect["postcondition"] = "not-satisfied"
    check_response("capture", request, reply, invocation=invocation)


@pytest.mark.parametrize("role", ["capture", "credential-issuer", "backup", "build"])
def test_creation_success_requires_recoverable_produced_identity(role):
    _, executor = installed(role)
    inputs = {"scope": executor["scope"]}
    if role == "capture":
        method = "capture"
        inputs.update(
            binding=executor,
            dataset="data",
            destination="target:data",
            procedure_digest=artifact("b")["digest"],
        )
        output = {"snapshots": [], "verification": "unknown"}
    elif role == "credential-issuer":
        method = "issue"
        inputs.update(
            issuer=executor,
            identity="database-user",
            consumer="demo",
            lifetime_seconds=3600,
            value_destination={
                "id": identifier(77),
                "owner": copy.deepcopy(OWNER),
                "consumer": "demo",
            },
        )
        output = {"leases": []}
    elif role == "backup":
        method = "store"
        inputs.update(repository="repository:demo", object="object:data", artifacts=[artifact("c")])
        output = {"objects": []}
    else:
        method = "build"
        inputs.update(source=artifact("b"), recipe=artifact("c"), destination="output:demo")
        output = {"artifacts": []}
    request = {"contract": "fishhat." + role, "method": method, "input": inputs}
    invocation = invocation_for(request)
    check_invocation(role, invocation)
    reply = response_for(request, invocation["attempt"], output)
    with pytest.raises(ContractError):
        check_response(role, request, reply, invocation=invocation)


def test_dispatch_releases_exact_committed_request_and_executor():
    owner, commits = coordinator()
    attempt = prepare(owner)
    invocation = owner.dispatch("demo", attempt["attempt_id"])
    check_invocation("runtime", invocation)
    assert invocation["attempt"] == commits[-1]["attempts"][attempt["attempt_id"]]
    assert invocation["request"] == commits[-1]["requests"][attempt["attempt_id"]]
    assert invocation["attempt"]["input_digest"] == digest(invocation["request"])
    lost = owner.snapshot()
    lost["requests"][attempt["attempt_id"]]["input"]["deployment"]["handle"] = "other"
    with pytest.raises(ContractError, match="INVOCATION_IDENTITY"):
        owner.restore(lost)
    query, reply = result(owner, attempt)
    missing = copy.deepcopy(reply)
    missing["output"]["deployment"] = None
    before = owner.snapshot()
    with pytest.raises(ContractError):
        owner.settle(attempt["attempt_id"], query, missing)
    assert owner.snapshot() == before
    pending = copy.deepcopy(reply)
    pending["effect"].update(task_state="running", postcondition="unknown", native_task="task:one")
    owner.settle(attempt["attempt_id"], query, pending)
    later = copy.deepcopy(pending)
    later["output"]["deployment"] = None
    owner.settle(attempt["attempt_id"], query, later)
    earlier = owner.snapshot()["results"][attempt["attempt_id"]]["records"]
    assert any(value["response"]["output"]["deployment"] is not None for value in earlier.values())
    reply["effect"]["native_task"] = "task:one"
    owner.settle(attempt["attempt_id"], query, reply)
    saved = owner.snapshot()
    assert saved["attempts"][attempt["attempt_id"]]["outcome"] == "succeeded"
    evidence = saved["results"][attempt["attempt_id"]]
    assert evidence["records"][evidence["latest"]]["response"] == reply
    assert len(evidence["records"]) == 3
    owner.restore(saved)
    saved["results"].clear()
    with pytest.raises(ContractError, match="RESTORE_RESULT_CUSTODY"):
        owner.restore(saved)


@pytest.mark.parametrize("method", ["store", "retrieve", "verify", "delete"])
def test_backup_success_has_method_specific_custody_and_noop_deletion_identity(method):
    _, executor = installed("backup")
    inputs = {
        "scope": executor["scope"],
        "repository": "repository:demo",
        "object": "object:data",
        "artifacts": [artifact("c")],
    }
    query = {"contract": "fishhat.backup", "method": method, "input": inputs}
    invocation = invocation_for(query)
    obj = {
        "handle": inputs["object"],
        "repository": inputs["repository"],
        "artifacts": copy.deepcopy(inputs["artifacts"]),
        "completeness": "sealed",
        "retrieval": "missing" if method == "delete" else "available",
    }
    reply = response_for(query, invocation["attempt"], {"objects": [obj]})
    check_response("backup", query, reply, invocation=invocation)
    if method == "store":
        obj["retrieval"] = "deferred"
        check_response("backup", query, reply, invocation=invocation)
    if method == "delete":
        obj["retrieval"] = "available"
    else:
        obj.update(completeness="incomplete", retrieval="missing")
    with pytest.raises(ContractError):
        check_response("backup", query, reply, invocation=invocation)


def test_dns_change_scope_and_success_result_cover_exact_affected_rrsets():
    registry, executor = installed("dns")
    changes = change(after=rrset())
    changes["scope"] = copy.deepcopy(executor["scope"])
    query = {
        "contract": "fishhat.dns",
        "method": "publish",
        "input": {"scope": executor["scope"], "change": changes},
    }
    invocation = invocation_for(query)
    registry.authorize_invocation("dns", invocation, owner_approved=True)
    changed = copy.deepcopy(query)
    changed["input"]["change"]["scope"]["handle"] = "ungranted"
    with pytest.raises(ContractError, match="DNS_SCOPE_IDENTITY"):
        check_request("dns", changed)
    output = {"rrsets": [rrset()], "served_generation": generation(executor, 2)}
    reply = response_for(query, invocation["attempt"], output)
    check_response("dns", query, reply, invocation=invocation)
    output["rrsets"] = []
    with pytest.raises(ContractError, match="SUCCESS_OUTPUT_IDENTITY"):
        check_response("dns", query, reply, invocation=invocation)
    changes["changes"] = [{"before": rrset(), "after": None}]
    invocation = invocation_for(query)
    reply = response_for(query, invocation["attempt"], output)
    check_response("dns", query, reply, invocation=invocation)
