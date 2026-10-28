from __future__ import annotations

import copy

import pytest
from fishhat_adapters import (
    ROLES,
    Registry,
    check_request,
    check_response,
    instance_reference,
)
from fishhat_contracts.validation import ContractError, digest
from fishhat_owner.adapter_state import AdapterCoordinator

from tests.adapter_support import (
    OWNER,
    binding,
    fresh_observation,
    identifier,
    native_exclusion,
    request,
    runtime_registry,
    runtime_sources,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/capture-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/secret-source-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/credential-issuer-adapter.schema.json",
    ],
    "scope": "exact adapter input custody, receiver enrollment joins and reconciliation identities",
    "relationship": "candidate",
    "reason": "Independent old/new input and lost-reply cases; no native execution or qualification.",
    "claims": [],
}


def artifact(letter):
    return {
        "digest": "sha256:" + letter * 64,
        "media_type": "application/octet-stream",
        "size_bytes": 64,
    }


def installed(role, *, observe_only=False, endpoint="protected-target", generation=3):
    """An independent authority-model double, not a supplied native adapter."""
    scope = {"authority": OWNER["id"], "kind": "dataset", "handle": "data"}
    if role in {"secret-source", "credential-issuer"}:
        scope["kind"] = role
    elif role == "runtime":
        scope["kind"] = "application"
    elif role in {"compute", "storage"}:
        scope["kind"] = "allocation"
    elif role == "backup":
        scope["kind"] = "backup-repository"
    elif role == "repository":
        scope["kind"] = "repository"
    elif role == "build":
        scope["kind"] = "builder"
    elif role == "dns":
        scope["kind"] = "dns-service"
    configuration_schema = {
        "type": "object",
        "properties": {"endpoint": {"type": "string"}},
        "required": ["endpoint"],
        "additionalProperties": False,
    }
    empty = {"type": "object", "properties": {}, "additionalProperties": False}
    descriptor = {
        "format": "deployment-ops/adapter/v1",
        "id": "independent.example-" + role,
        "roles": [role],
        "entrypoint": "bin/adapter",
        "process_protocol": "fishhat.adapter-process/v1",
        "configuration_schema": configuration_schema,
        "component_schema": empty,
        "source_schema": empty,
        "implemented": [role + "." + method for method in ROLES[role]],
        "native_qualified": False,
    }
    instance = {
        "id": "selected",
        "implementation": descriptor["id"],
        "installation_digest": artifact("a")["digest"],
        "role": role,
        "schema_digest": digest(configuration_schema),
        "configuration": {"endpoint": endpoint},
        "grants": [
            {
                "scope": scope,
                "access": ["observe"] if observe_only else ["observe", "change"],
                "mutation": None
                if observe_only
                else {
                    "controller": "selected",
                    "namespaces": [
                        {"authority": OWNER["id"], "resource": "data", "facet": "content"}
                    ],
                },
            }
        ],
        "generation": generation,
    }
    registry = Registry()
    registry.install(
        {
            "implementation": descriptor["id"],
            "artifact": artifact("a"),
            "descriptor_digest": digest(descriptor),
            "enabled": True,
        },
        descriptor,
        owner_approved=True,
    )
    registry.enroll(instance, owner_approved=True)
    reference = {
        "instance": instance["id"],
        "role": role,
        "installation_digest": instance["installation_digest"],
        "configuration_digest": digest(instance["configuration"]),
        "instance_generation": instance["generation"],
        "instance_digest": digest(instance),
        "scope": scope,
    }
    return registry, reference


def handoff(role, method):
    registry, reference = installed(role)
    inputs = {"scope": copy.deepcopy(reference["scope"])}
    if role == "capture":
        inputs.update(
            {
                "binding": reference,
                "dataset": "data",
                "destination": "target:data",
                "procedure_digest": artifact("b")["digest"],
                "snapshot": {
                    "handle": "snapshot:old",
                    "dataset": "data",
                    "format": "independent.snapshot",
                    "consistency": "quiesced",
                    "artifacts": [artifact("c")],
                    "restore_requirements": ["independent.reader"],
                    "producer": copy.deepcopy(reference),
                },
            }
        )
    elif role == "secret-source":
        inputs.update(
            {
                "binding": reference,
                "entry": "database",
                "version": "version:new",
                "consumer": "demo",
                "candidate": artifact("c"),
                "expected_previous": {
                    "source": copy.deepcopy(reference),
                    "entry": "database",
                    "version": "version:old",
                    "artifact_digest": artifact("b")["digest"],
                },
            }
        )
    else:
        inputs["lease"] = {
            "issuer": reference,
            "identity": "database-user",
            "consumer": "demo",
            "lease": "lease:old",
        }
        if method == "renew":
            inputs["lifetime_seconds"] = 3600
    if method in {"retrieve", "renew"}:
        if role == "secret-source":
            inputs.pop("candidate", None)
            inputs.pop("expected_previous", None)
        consumer = inputs["lease"]["consumer"] if "lease" in inputs else inputs["consumer"]
        inputs["value_destination"] = {
            "id": identifier(77),
            "owner": copy.deepcopy(OWNER),
            "consumer": consumer,
        }
    return registry, {"contract": "fishhat." + role, "method": method, "input": inputs}


def attempt_for(query):
    inputs = query["input"]
    executor = (
        inputs.get("binding") or inputs.get("issuer") or inputs.get("target", {}).get("executor")
    )
    if executor is None and "lease" in inputs:
        executor = inputs["lease"]["issuer"]
    if executor is None:
        role = query["contract"].removeprefix("fishhat.")
        executor = (
            instance_reference(runtime_registry()[2], inputs["scope"])
            if role == "runtime"
            else installed(role)[1]
        )
    return {
        "owner": OWNER,
        "operation_id": identifier(8),
        "effect_id": identifier(9),
        "attempt_id": identifier(10),
        "executor": copy.deepcopy(executor),
        "binding_generation": 3,
        "native_incarnation": identifier(11),
        "contract": query["contract"],
        "method": query["method"],
        "scope": query["input"]["scope"],
        "input_digest": digest(query),
        "state": "dispatched",
        "certainty": "unknown",
        "outcome": "pending",
        "native_task": None,
    }


def invocation_for(query):
    return {"attempt": attempt_for(query), "request": copy.deepcopy(query)}


def response_for(query, attempt, output):
    original = query["input"]["invocation"]["request"] if query["method"] == "reconcile" else query
    if "value_destination" in original["input"]:
        output = copy.deepcopy(output)
        records = output.get("leases", output.get("versions", []))
        output["handoff"] = {
            "destination": copy.deepcopy(original["input"]["value_destination"]),
            "value_handle": records[0]["value_handle"] if records else None,
            "state": "available" if records else "unknown",
            "size_bytes": 16 if records else None,
        }
    return {
        "contract": query["contract"],
        "method": query["method"],
        "request_digest": digest(query),
        "scope": query["input"]["scope"],
        "coverage": "complete",
        "continuation": None,
        "proposal": None,
        "output": output,
        "effect": {
            "attempt_id": attempt["attempt_id"],
            "input_digest": attempt["input_digest"],
            "acknowledgment": "accepted",
            "task_state": "terminal",
            "effect_certainty": "known",
            "postcondition": "satisfied",
            "native_task": None,
        },
    }


def reconciliation():
    original = request()
    invocation = invocation_for(original)
    query = {
        "contract": original["contract"],
        "method": "reconcile",
        "input": {"scope": original["input"]["scope"], "invocation": copy.deepcopy(invocation)},
    }
    response = response_for(
        query,
        invocation["attempt"],
        {"deployment": original["input"]["deployment"], "observation": None, "objects": []},
    )
    return query, invocation, response


def test_lost_activation_reply_is_settled_without_a_second_dispatch():
    registry, _, _ = runtime_registry()
    commits = []
    owner = AdapterCoordinator(
        OWNER,
        registry,
        lambda value: commits.append(copy.deepcopy(value)),
        native_exclusion=native_exclusion,
    )
    owner.bind(binding(), **runtime_sources(registry), owner_approved=True)
    owner.prove_quiescent("demo", fresh_observation(owner), owner_approved=True)
    owner.open_admission("demo", owner_approved=True)
    prepared = owner.prepare(
        "demo",
        request(),
        **runtime_sources(registry),
        operation_id=identifier(8),
        effect_id=identifier(9),
        attempt_id=identifier(10),
        owner_approved=True,
    )
    invocation = owner.dispatch("demo", prepared["attempt_id"])
    original = invocation["attempt"]
    query = {
        "contract": original["contract"],
        "method": "reconcile",
        "input": {"scope": original["scope"], "invocation": invocation},
    }
    response = response_for(
        query,
        original,
        {
            "deployment": invocation["request"]["input"]["deployment"],
            "observation": None,
            "objects": [],
        },
    )
    assert response["request_digest"] != response["effect"]["input_digest"]
    check_response("runtime", query, response, invocation=invocation)
    owner.settle(original["attempt_id"], query, response)
    assert owner.snapshot()["attempts"][original["attempt_id"]]["outcome"] == "succeeded"
    count = len(commits)
    with pytest.raises(ContractError, match="RECONCILE_REQUIRED"):
        owner.dispatch("demo", original["attempt_id"])
    assert len(commits) == count


@pytest.mark.parametrize(
    "substitution",
    [
        "rpc-digest",
        "effect-digest",
        "attempt-id",
        "scope",
        "role",
        "read-method",
        "trusted-attempt",
    ],
)
def test_reconciliation_refuses_identity_substitution(substitution):
    query, original, response = reconciliation()
    if substitution == "rpc-digest":
        response["request_digest"] = original["attempt"]["input_digest"]
    elif substitution == "effect-digest":
        response["effect"]["input_digest"] = digest(query)
    elif substitution == "attempt-id":
        response["effect"]["attempt_id"] = identifier(99)
    elif substitution == "trusted-attempt":
        original["attempt"]["executor"]["installation_digest"] = artifact("f")["digest"]
    else:
        changed = query["input"]["invocation"]["attempt"]
        if substitution == "scope":
            changed["scope"] = {**changed["scope"], "handle": "other"}
        elif substitution == "role":
            changed["contract"] = "fishhat.service"
        else:
            changed["method"] = "observe"
        response["request_digest"] = digest(query)
    with pytest.raises(ContractError):
        check_response("runtime", query, response, invocation=original)


def test_observational_reconciliation_does_not_require_mutation_authority():
    registry, reference = installed("runtime", observe_only=True)
    assert registry.authorize(
        "selected", "runtime", "reconcile", reference["scope"], owner_approved=True
    )
    with pytest.raises(ContractError, match="SCOPE_NOT_GRANTED"):
        registry.authorize(
            "selected", "runtime", "activate", reference["scope"], owner_approved=True
        )


@pytest.mark.parametrize("method", ["restore", "verify"])
def test_capture_handoff_distinguishes_old_and_new_snapshot(method):
    registry, query = handoff("capture", method)
    registry.authorize_invocation("capture", invocation_for(query), owner_approved=True)
    original = attempt_for(query)
    selected = query["input"]["snapshot"]
    response = response_for(
        query, original, {"snapshots": [copy.deepcopy(selected)], "verification": "consistent"}
    )
    check_response("capture", query, response, invocation={"attempt": original, "request": query})
    response["output"]["snapshots"][0]["artifacts"] = [artifact("d")]
    with pytest.raises(ContractError, match="SNAPSHOT_OUTPUT_IDENTITY"):
        check_response(
            "capture", query, response, invocation={"attempt": original, "request": query}
        )
    changed = copy.deepcopy(query)
    changed["input"]["snapshot"]["handle"] = "snapshot:new"
    changed["input"]["snapshot"]["artifacts"] = [artifact("d")]
    check_request("capture", changed)
    assert digest(changed) != digest(query)


def test_cross_owner_restore_keeps_source_identity_separate_from_target_authority():
    registry, query = handoff("capture", "restore")
    query["input"]["snapshot"]["producer"]["scope"]["authority"] = identifier(55)
    registry.authorize_invocation("capture", invocation_for(query), owner_approved=True)
    query["input"]["snapshot"]["dataset"] = "different-data"
    with pytest.raises(ContractError, match="SNAPSHOT_INPUT_IDENTITY"):
        check_request("capture", query)


@pytest.mark.parametrize("method", ["renew", "revoke"])
def test_overlapping_credential_lease_is_never_an_implicit_target(method):
    registry, query = handoff("credential-issuer", method)
    registry.authorize_invocation("credential-issuer", invocation_for(query), owner_approved=True)
    original = attempt_for(query)
    lease = {
        **copy.deepcopy(query["input"]["lease"]),
        "value_handle": "protected:old",
        "validity": "revoked" if method == "revoke" else "valid",
        "expires_at": "2026-10-19T13:00:00Z" if method == "renew" else None,
        "valid_from": "2026-10-19T12:00:00Z" if method == "renew" else None,
        "renewable": method == "renew",
    }
    response = response_for(query, original, {"leases": [lease]})
    check_response(
        "credential-issuer", query, response, invocation={"attempt": original, "request": query}
    )
    response["output"]["leases"][0]["lease"] = "lease:new"
    with pytest.raises(ContractError, match="LEASE_RESULT_IDENTITY"):
        check_response(
            "credential-issuer", query, response, invocation={"attempt": original, "request": query}
        )
    changed = copy.deepcopy(query)
    changed["input"]["lease"]["lease"] = "lease:new"
    check_request("credential-issuer", changed)
    assert digest(changed) != digest(query)


@pytest.mark.parametrize("method", ["issue", "renew"])
@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
def test_issuance_must_prove_effective_bounded_lease_lifetime(method, reconcile):
    _, query = handoff("credential-issuer", "renew")
    selected_lease = copy.deepcopy(query["input"]["lease"])
    if method == "issue":
        query["method"] = method
        query["input"].update(
            issuer=selected_lease["issuer"],
            identity=selected_lease["identity"],
            consumer=selected_lease["consumer"],
        )
        del query["input"]["lease"]
    invocation = invocation_for(query)
    original = query
    if reconcile:
        query = {
            "contract": query["contract"],
            "method": "reconcile",
            "input": {"scope": query["input"]["scope"], "invocation": invocation},
        }
    lease = {
        **selected_lease,
        "value_handle": "protected:old",
        "validity": "valid",
        "valid_from": "2026-10-19T12:00:00Z",
        "expires_at": "2026-10-19T13:00:00Z",
        "renewable": True,
    }
    response = response_for(query, invocation["attempt"], {"leases": [lease]})
    check_response("credential-issuer", query, response, invocation=invocation)
    for begin, end in (
        ("2026-10-19T12:00:00Z", "2026-10-19T12:30:00Z"),
        ("9999-12-31T23:59:58Z", "9999-12-31T23:59:59Z"),
    ):
        short = copy.deepcopy(response)
        short["output"]["leases"][0].update(valid_from=begin, expires_at=end)
        check_response("credential-issuer", query, short, invocation=invocation)
    assert original["input"]["lifetime_seconds"] == 3600
    for end in (None, "2026-10-19T13:00:01Z", "2026-10-19T12:00:00Z"):
        changed = copy.deepcopy(response)
        changed["output"]["leases"][0]["expires_at"] = end
        with pytest.raises(ContractError, match="LEASE_LIFETIME"):
            check_response("credential-issuer", query, changed, invocation=invocation)
    changed = copy.deepcopy(response)
    changed["output"]["leases"][0]["valid_from"] = None
    with pytest.raises(ContractError, match="LEASE_LIFETIME_UNVERIFIED"):
        check_response("credential-issuer", query, changed, invocation=invocation)


def test_publication_requires_same_source_and_exact_predecessor():
    registry, query = handoff("secret-source", "publish")
    registry.authorize_invocation("secret-source", invocation_for(query), owner_approved=True)
    changed = copy.deepcopy(query)
    changed["input"]["expected_previous"]["artifact_digest"] = artifact("d")["digest"]
    check_request("secret-source", changed)
    assert digest(changed) != digest(query)
    changed["input"]["expected_previous"]["source"]["configuration_digest"] = artifact("e")[
        "digest"
    ]
    with pytest.raises(ContractError, match="publication predecessor destination mismatch"):
        check_request("secret-source", changed)


@pytest.mark.parametrize("change", ["source", "entry", "version"])
def test_publication_rejects_contradictory_intent_before_invocation_authorization(change):
    registry, query = handoff("secret-source", "publish")
    previous = query["input"]["expected_previous"]
    if change == "source":
        previous["source"]["configuration_digest"] = artifact("e")["digest"]
    elif change == "entry":
        previous["entry"] = "another-entry"
    else:
        query["input"]["version"] = previous["version"]
        assert query["input"]["candidate"]["digest"] != previous["artifact_digest"]
    with pytest.raises(ContractError, match="publication"):
        check_request("secret-source", query)
    with pytest.raises(ContractError, match="publication"):
        registry.authorize_invocation("secret-source", invocation_for(query), owner_approved=True)


@pytest.mark.parametrize(
    "predecessor", [False, True], ids=["verified-absence", "exact-predecessor"]
)
def test_publication_allows_distinct_new_version_without_inventing_predecessor_authority(
    predecessor,
):
    registry, query = handoff("secret-source", "publish")
    if not predecessor:
        query["input"]["expected_previous"] = None
    registry.authorize_invocation("secret-source", invocation_for(query), owner_approved=True)


@pytest.mark.parametrize(
    "role,method",
    [("capture", "restore"), ("secret-source", "publish"), ("credential-issuer", "revoke")],
)
def test_handoff_cannot_substitute_current_instance_configuration(role, method):
    registry, query = handoff(role, method)
    reference = (
        query["input"]["lease"]["issuer"]
        if role == "credential-issuer"
        else query["input"]["binding"]
    )
    reference["configuration_digest"] = artifact("e")["digest"]
    if role == "secret-source":
        query["input"]["expected_previous"]["source"] = copy.deepcopy(reference)
    check_request(role, query)
    with pytest.raises(ContractError, match="HANDOFF_INSTANCE_IDENTITY"):
        registry.authorize_invocation(role, invocation_for(query), owner_approved=True)


@pytest.mark.parametrize(
    "role,method",
    [("capture", "restore"), ("secret-source", "publish"), ("credential-issuer", "revoke")],
)
def test_changed_exact_handoff_input_cannot_reuse_an_accepted_attempt(role, method):
    _, query = handoff(role, method)
    original = attempt_for(query)
    invocation = {"attempt": original, "request": copy.deepcopy(query)}
    if role == "capture":
        query["input"]["snapshot"]["artifacts"] = [artifact("d")]
        output = {"snapshots": [], "verification": "unknown"}
    elif role == "secret-source":
        query["input"]["candidate"] = artifact("d")
        output = {"versions": []}
    else:
        query["input"]["lease"]["lease"] = "lease:new"
        output = {"leases": []}
    response = response_for(query, original, output)
    response["effect"].update(
        task_state="unknown", effect_certainty="unknown", postcondition="unknown"
    )
    with pytest.raises(ContractError, match="RESPONSE_EFFECT_IDENTITY"):
        check_response(role, query, response, invocation=invocation)
