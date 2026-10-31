"""Complete staged workflow intent and replayable transitions, without native effects."""

from __future__ import annotations

import copy
import json

import pytest
from fishhat_client.wire import frame
from fishhat_contracts.handoffs import schema_identity, validate_workflow
from fishhat_contracts.transfers import validate_transfer_proposal
from fishhat_contracts.validation import MAX_BYTES, ContractError, canonical, digest, validate
from fishhat_contracts.workflows import (
    decode_workflow_input,
    prepare_workflow,
    validate_advance_request,
    validate_workflow_input_custody,
    validate_workflow_proposal,
)

from tests.support import FIXTURES
from tests.test_contracts import uid
from tests.test_owner_handoffs import (
    NOW,
    U,
    V,
    operation,
    preparation_witness,
    rebind_workflow_proposal,
    request,
    staged_workflow_input,
    workflow,
)
from tests.test_plan_review import reseal
from tests.test_workflow_transfer import committed, completion_request, frozen, proposal
from tests.workflow_evidence_support import advance_request
from tests.workflow_evidence_support import advance_with_evidence as advance_workflow

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-evidence.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Workflow",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/WorkflowTransfer",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/Handle",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/MaterialDigest",
    ],
    "scope": "complete immutable proposal custody, staged input extents and exact advance replay",
    "relationship": "candidate",
    "reason": "Lost-client reconstruction, omitted or substituted closure inputs, oversized complete payloads and interrupted transfer completion exercise decoded contracts. They do not prove native authorization, staging durability, atomic store transactions or bounded native spooling.",
    "claims": [],
}


def preparation(value):
    return {"owner": value["owner"], "proposal": value["proposal"]}


def stage(reference, workflow_id, *, pinned=0):
    handle = reference["input"]
    return {
        "format": "deployment-ops/record/v1",
        "kind": "ContentStaging",
        "id": handle["binding"]["staging_id"],
        "owner": copy.deepcopy(handle["owner"]),
        "resource": {"kind": "workflow", "id": workflow_id},
        "authenticated_principal": "ops-app-operate",
        "purpose": "workflow-input",
        "digest": handle["digest"],
        "size": handle["size"],
        "state": "committed",
        "offset": handle["size"],
        "created_at": "2026-10-23T00:00:00Z",
        "expires_at": "2026-10-23T01:00:00Z",
        "accepted_references": pinned,
        "handle": copy.deepcopy(handle),
    }


def normal_advance(value):
    return advance_request(value, "draining", advance_id=uid("ordinary-advance"))


def material_handle(owner, identity, *, size=1):
    return {
        "owner": copy.deepcopy(owner),
        "id": uid("material-" + identity),
        "purpose": "content",
        "binding": {"kind": "staging", "staging_id": uid("material-stage-" + identity)},
        "digest": identity,
        "size": size,
    }


def adapter_proposal(role="ingress"):
    intent = workflow()["proposal"]
    participant = intent["participants"][0]
    participant["resource"] = {"kind": "adapter", "id": "selected-adapter"}
    binding = participant["requests"][0]
    plan = binding["plan"]
    executor = {
        "instance": "selected-adapter",
        "role": role,
        "installation_digest": "sha256:" + "a" * 64,
        "configuration_digest": "sha256:" + "c" * 64,
        "instance_generation": 4,
        "instance_digest": "sha256:" + "e" * 64,
        "scope": {"authority": participant["owner"]["id"], "kind": role, "handle": "demo"},
    }
    if role == "ingress":
        selected = {
            "contract": "fishhat.ingress",
            "method": "publish",
            "input": {
                "scope": copy.deepcopy(executor["scope"]),
                "generation_digest": "sha256:" + "d" * 64,
                "routes": [],
                "target": {
                    "binding": copy.deepcopy(executor),
                    "namespace": {
                        "authority": participant["owner"]["id"],
                        "resource": "demo",
                        "facet": "routes",
                    },
                },
                "expected_previous": None,
            },
        }
        selected["input"]["generation_digest"] = digest(
            {
                "format": "fishhat.routing-generation/v1",
                "role": "ingress",
                "target": selected["input"]["target"],
                "routes": selected["input"]["routes"],
            }
        )
    else:
        selected = {
            "contract": "fishhat.credential-issuer",
            "method": "issue",
            "input": {
                "scope": copy.deepcopy(executor["scope"]),
                "identity": "demo-user",
                "consumer": "demo-app",
                "lifetime_seconds": 3600,
                "issuer": copy.deepcopy(executor),
                "value_destination": {
                    "id": uid("issued-value-slot"),
                    "owner": copy.deepcopy(participant["owner"]),
                    "consumer": "demo-app",
                },
            },
        }
    handle = material_handle(plan["owner"], digest(selected), size=len(canonical(selected)))
    uri = f"https://fishhat.invalid/contracts/{role}-adapter.schema.json"
    plan["subject"] = {
        "action": "adapter.execute",
        "resource": copy.deepcopy(participant["resource"]),
        "arguments": {
            "adapter_id": executor["instance"],
            "adapter_release": executor["installation_digest"],
            "action": selected["method"],
            "input": copy.deepcopy(handle),
            "input_schema": schema_identity(uri + "#/$defs/MutationRequest"),
            "result_schema": schema_identity(uri + "#/$defs/RetainedResult"),
        },
    }
    for condition in plan["preconditions"]:
        condition["resource"] = copy.deepcopy(participant["resource"])
    for effect in plan["effects"]:
        effect["resource"] = copy.deepcopy(participant["resource"])
    for item in (handle, material_handle(plan["owner"], executor["installation_digest"])):
        intent["content"].append(item)
        plan["input_digests"].append(item["digest"])
    reseal(plan)
    binding["adapter"] = {"executor": executor, "request": selected}
    binding["phase"] = "published" if role == "ingress" else "issuer-changing"
    reference = {"owner": copy.deepcopy(participant["owner"]), "request_id": binding["request_id"]}
    intent.update(type="ingress-publication", target={"publication": reference})
    return intent


def test_preparation_retains_typed_plans_and_content_after_client_loss():
    expected = workflow()
    original = preparation(expected)
    reference, data = staged_workflow_input("workflow.prepare", original)
    decoded = decode_workflow_input(
        "workflow.prepare", reference, data, expected_owner=expected["owner"]
    )
    validate_workflow_input_custody(
        reference,
        decoded,
        stage(reference, expected["id"]),
        principal=expected["driver_principal"],
        now=NOW,
    )
    retained = prepare_workflow(
        decoded,
        expected_owner=expected["owner"],
        principal=expected["driver_principal"],
        verified_driver=expected["proposal"]["initial_driver"],
        verified_preparation=preparation_witness(expected["proposal"], expected["owner"]),
        verified_content=expected["proposal"]["content"],
    )
    assert retained == expected
    del original, decoded, data
    recovered = preparation(retained)
    selected = retained["proposal"]["participants"][0]["requests"][0]
    assert selected["plan"]["subject"]["action"] == "host.reboot"
    assert selected["request_id"] == retained["proposal"]["target"]["host_change"]["request_id"]
    assert retained["proposal_digest"] == digest(recovered["proposal"])
    retained["generation"] = 7
    assert (
        prepare_workflow(
            recovered,
            expected_owner=retained["owner"],
            principal="replacement-operator",
            verified_driver=expected["proposal"]["initial_driver"],
            verified_preparation=None,
            verified_content=[],
            retained=retained,
        )
        == retained
    )


@pytest.mark.parametrize(
    "change", ["digest-only", "missing-plan", "request-id", "generation", "content"]
)
def test_workflow_proposal_rejects_incomplete_or_changed_target_closure(change):
    value = workflow()["proposal"]
    if change == "digest-only":
        value["target"] = {"target_digest": "sha256:" + "a" * 64}
    elif change == "missing-plan":
        del value["participants"][0]["requests"][0]["plan"]
    elif change == "request-id":
        value["target"]["host_change"]["request_id"] = U
    elif change == "generation":
        value["participants"][0]["expected_generation"] += 1
    else:
        value["content"] = []
    with pytest.raises(ContractError):
        validate_workflow_proposal(value)


def test_capsule_cannot_substitute_a_different_proposal_or_unverified_local_content():
    value = workflow()
    with pytest.raises(ContractError, match="local content custody"):
        prepare_workflow(
            preparation(value),
            expected_owner=value["owner"],
            principal=value["driver_principal"],
            verified_driver=value["proposal"]["initial_driver"],
            verified_preparation=preparation_witness(value["proposal"], value["owner"]),
            verified_content=[],
        )
    value["proposal"]["participants"][0]["requests"][0]["request_id"] = U
    with pytest.raises(ContractError):
        validate_workflow(value)
    value = workflow()
    value["proposal"]["type"] = "secret-rotation"
    with pytest.raises(ContractError):
        validate_workflow_proposal(value["proposal"])


def test_relocation_target_recovers_the_exact_planned_recovery_basis():
    intent = json.loads((FIXTURES / "workflow/relocation-proposal.json").read_text())
    validate_workflow_proposal(intent)
    restored = copy.deepcopy(intent)
    assert restored["participants"][0]["requests"][0]["plan"]["subject"]["arguments"][
        "recovery_basis"
    ] == {"kind": "checkpoint", "checkpoint_digest": "sha256:" + "b" * 64}
    restored["target"]["relocation"]["request_id"] = U
    with pytest.raises(ContractError, match="target child"):
        validate_workflow_proposal(restored)


def test_every_participant_precondition_joins_its_generation_without_expanding_read_scope():
    value, _ = committed()
    intent = value["proposal"]
    first, second = intent["participants"]
    plan = first["requests"][0]["plan"]
    condition = {
        **copy.deepcopy(plan["preconditions"][0]),
        "owner": copy.deepcopy(second["owner"]),
        "resource": copy.deepcopy(second["resource"]),
        "generation": second["expected_generation"],
    }
    plan["preconditions"].append(condition)
    plan["effects"].append(
        {
            **copy.deepcopy(plan["effects"][0]),
            "step": "second-host",
            "executor": copy.deepcopy(second["owner"]),
            "resource": copy.deepcopy(second["resource"]),
        }
    )
    # An observed dependency does not authorize a mutation or require a participant.
    plan["preconditions"].append(
        {
            **copy.deepcopy(condition),
            "resource": {"kind": "host", "id": "read-only-dependency"},
            "generation": 42,
        }
    )
    reseal(plan)
    validate_workflow_proposal(intent)
    condition["generation"] += 1
    reseal(plan)
    with pytest.raises(ContractError, match="Plan generation"):
        validate_workflow_proposal(intent)


def test_runtime_release_must_be_reviewed_and_retained_material():
    intent = workflow()["proposal"]
    plan = intent["participants"][0]["requests"][0]["plan"]
    release = "sha256:" + "b" * 64
    plan["subject"].update(
        action="host.runtime-install", arguments={"tool_release": release, "tools": ["host-ops"]}
    )
    intent.update(type="runtime-upgrade", target={"installation": intent["target"]["host_change"]})
    intent["participants"][0]["requests"][0]["phase"] = "migrating"
    reseal(plan)
    with pytest.raises(ContractError, match="material input"):
        validate_workflow_proposal(intent)
    plan["input_digests"].append(release)
    reseal(plan)
    with pytest.raises(ContractError, match="retained content handle"):
        validate_workflow_proposal(intent)
    intent["content"].append(material_handle(plan["owner"], release))
    validate_workflow_proposal(intent)


def test_generic_adapter_role_retains_typed_input_and_requires_independent_selection():
    intent = adapter_proposal()
    validate_workflow_proposal(intent)
    participant = intent["participants"][0]
    selected = participant["requests"][0]["adapter"]
    payload = {"owner": participant["owner"], "proposal": intent}
    with pytest.raises(ContractError, match="independently verified"):
        prepare_workflow(
            payload,
            expected_owner=payload["owner"],
            principal="operator",
            verified_driver=intent["initial_driver"],
            verified_preparation=preparation_witness(intent, payload["owner"]),
            verified_content=intent["content"],
        )
    prepared = prepare_workflow(
        payload,
        expected_owner=payload["owner"],
        principal="operator",
        verified_driver=intent["initial_driver"],
        verified_preparation=preparation_witness(intent, payload["owner"]),
        verified_content=intent["content"],
        verified_adapters=[copy.deepcopy(selected)],
    )
    assert prepared["proposal"]["participants"][0]["requests"][0]["adapter"] == selected
    # Comparison hashes and schema identities are not fabricated content inputs.
    inputs = participant["requests"][0]["plan"]["input_digests"]
    assert selected["request"]["input"]["generation_digest"] not in inputs


@pytest.mark.parametrize("change", ["missing", "method", "instance", "input", "schema", "role"])
def test_generic_adapter_target_cannot_substitute_an_unrelated_selected_method(change):
    intent = adapter_proposal()
    binding = intent["participants"][0]["requests"][0]
    arguments = binding["plan"]["subject"]["arguments"]
    if change == "missing":
        del binding["adapter"]
    elif change == "method":
        arguments["action"] = "prune"
    elif change == "instance":
        arguments["adapter_id"] = "other-adapter"
    elif change == "input":
        binding["adapter"]["request"]["input"]["routes"] = [
            {
                "name": "different",
                "listener": "http",
                "upstream": "demo",
                "policy_digest": "sha256:" + "f" * 64,
            }
        ]
    elif change == "schema":
        arguments["input_schema"]["digest"] = "sha256:" + "f" * 64
    else:
        intent = adapter_proposal("credential-issuer")
        binding = intent["participants"][0]["requests"][0]
    reseal(binding["plan"])
    with pytest.raises(ContractError):
        validate_workflow_proposal(intent)


def publication_evidence(provider):
    if provider == "forgejo-age":
        payload = {"release_id": 17, "asset_id": 23, "repository_id": 1}
    else:
        payload = {"mount": "kv", "path": "demo/database", "version": 7}
    uri = f"https://providers.example/{provider}/publication.schema.json"
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": uri,
        "type": "object",
        "properties": {
            key: {"type": "integer" if isinstance(item, int) else "string"}
            for key, item in payload.items()
        },
        "required": list(payload),
        "additionalProperties": False,
    }
    return payload, schema


def rotation_intent(provider="forgejo-age"):
    intent = adapter_proposal("credential-issuer")
    issuer_reference = intent["target"]["publication"]
    publisher_owner = {**issuer_reference["owner"], "id": uid("publisher-owner")}
    publication = {"owner": publisher_owner, "request_id": uid("rotation-publication")}
    consumer_owner = {**publisher_owner, "tool": "app-ops", "id": uid("consumer-owner")}
    adoption = {"owner": consumer_owner, "request_id": uid("consumer-adoption")}
    source = copy.deepcopy(intent["participants"][0]["requests"][0]["adapter"]["executor"])
    source.update(instance=provider, role="secret-source")
    source["scope"] = {
        "authority": publisher_owner["id"],
        "kind": "secret-source",
        "handle": "selected-secrets",
    }
    _, evidence_schema = publication_evidence(provider)
    intent["participants"].extend(
        [
            {
                "owner": publisher_owner,
                "resource": {"kind": "publisher", "id": "selected-publisher"},
                "expected_generation": 0,
                "requests": [
                    {
                        "request_id": publication["request_id"],
                        "phase": "publishing",
                        "intent": {
                            "kind": "secret-publication",
                            "issuer": issuer_reference,
                            "source": source,
                            "entry": "database",
                            "consumer": "demo-app",
                            "version": "opaque:" + provider + ":new-version",
                            "catalogue_digest": digest({"catalogue": 1}),
                            "evidence_schema": schema_identity(
                                evidence_schema["$id"], {evidence_schema["$id"]: evidence_schema}
                            ),
                            "expected_previous": None,
                        },
                    }
                ],
            },
            {
                "owner": consumer_owner,
                "resource": {"kind": "app", "id": "demo-app"},
                "expected_generation": 0,
                "requests": [
                    {
                        "request_id": adoption["request_id"],
                        "phase": "consumers-adopting",
                        "intent": {
                            "kind": "secret-adoption",
                            "action": "app.secrets-adopt",
                            "issuer": issuer_reference,
                            "publication": publication,
                        },
                    }
                ],
            },
        ]
    )
    intent.update(
        type="secret-rotation",
        target={
            "issuer_change": issuer_reference,
            "publication": publication,
            "consumer_adoptions": [adoption],
        },
    )
    return intent


def test_secret_rotation_requires_issuer_mutation_and_separate_consumer_adoption():
    intent = rotation_intent()
    validate_workflow_proposal(intent)
    issuer = intent["participants"][0]
    publication = issuer["requests"][0]
    selected = publication["plan"]
    candidate = selected["subject"]["arguments"]["input"]
    issuer["resource"] = {"kind": "publisher", "id": "selected-publisher"}
    selected["subject"] = {
        "action": "publisher.publish",
        "resource": copy.deepcopy(issuer["resource"]),
        "arguments": {
            **{
                key: value
                for key, value in intent["participants"][1]["requests"][0]["intent"].items()
                if key not in {"kind", "issuer"}
            },
            "candidate": {**candidate, "purpose": "secret-candidate"},
        },
    }
    for condition in selected["preconditions"]:
        condition["resource"] = copy.deepcopy(issuer["resource"])
    for effect in selected["effects"]:
        effect["resource"] = copy.deepcopy(issuer["resource"])
    del publication["adapter"]
    reseal(selected)
    with pytest.raises(ContractError, match=r"installed phase|procedure role"):
        validate_workflow_proposal(intent)


@pytest.mark.parametrize("method", ["workflow.prepare", "workflow.advance", "workflow.transfer"])
def test_complete_workflow_inputs_larger_than_a_frame_use_bounded_references(method):
    value = workflow()
    if method == "workflow.prepare":
        first = value["participants"][0]
        value["participants"] = []
        for index in range(450):
            item = copy.deepcopy(first)
            item["resource"]["id"] = f"host-{index}"
            item["request_ids"] = [uid(f"large-prepare-request-{index}")]
            value["participants"].append(item)
        rebind_workflow_proposal(value)
        payload = preparation(value)
        validate_workflow_proposal(payload["proposal"])
    elif method == "workflow.advance":
        payload = normal_advance(value)
        witness = copy.deepcopy(operation()["witness"])
        witness.update(owner=value["owner"], workflow_id=value["id"])
        witness["evidence_digests"] = ["sha256:" + f"{index:064x}" for index in range(15000)]
        payload["witnesses"] = [witness]
    else:
        intent = proposal(value)
        intent["participants"] = []
        witnesses = []
        for index in range(1500):
            owner = {**value["owner"], "id": uid(f"large-transfer-owner-{index}")}
            intent["participants"].append(
                {"owner": owner, "resource": {"kind": "host", "id": f"host-{index}"}}
            )
        identity = digest(intent)
        for participant in intent["participants"]:
            witness = copy.deepcopy(operation()["witness"])
            witness.update(
                owner=participant["owner"],
                kind="transfer",
                state="frozen",
                workflow_id=value["id"],
                subject_digest=identity,
            )
            witnesses.append(witness)
        payload = {
            "owner": value["owner"],
            "proposal": intent,
            "expected_generation": 1,
            "phase": "commit",
            "witnesses": witnesses,
        }
        validate_transfer_proposal(intent)
    reference, data = staged_workflow_input(method, payload)
    assert len(data) > MAX_BYTES
    assert len(frame(request(method, reference))) < 4096
    assert decode_workflow_input(method, reference, data, expected_owner=value["owner"]) == payload
    with pytest.raises(ContractError, match="bytes changed"):
        decode_workflow_input(method, reference, data[:-1], expected_owner=value["owner"])
    with pytest.raises(ContractError, match="size limit"):
        decode_workflow_input(
            method, reference, data, expected_owner=value["owner"], max_bytes=len(data) - 1
        )


def test_staging_size_is_capacity_bound_without_a_ten_gibibyte_contract_cutoff():
    value = workflow()
    reference, _ = staged_workflow_input("workflow.prepare", preparation(value))
    large = 11 * 1024**3
    reference["input"]["size"] = large
    validate("workflow.schema.json", reference, "InputReference")
    staging = stage(reference, value["id"])
    validate("records.schema.json", staging, "ContentStaging")
    begin = {
        "expected_owner": value["owner"],
        "staging_id": staging["id"],
        "resource": staging["resource"],
        "purpose": "workflow-input",
        "digest": staging["digest"],
        "size": large,
    }
    validate("ssh-request.schema.json", request("content.begin", begin))
    validate(
        "ssh-request.schema.json",
        request(
            "content.chunk",
            {
                "staging_id": staging["id"],
                "owner": value["owner"],
                "offset": large,
                "base64": "YQ==",
            },
        ),
    )


@pytest.mark.parametrize("change", ["owner", "workflow", "principal", "purpose", "expiry"])
def test_new_workflow_staging_cannot_change_receiving_scope(change):
    value = workflow()
    payload = preparation(value)
    reference, _ = staged_workflow_input("workflow.prepare", payload)
    custody = stage(reference, value["id"])
    if change == "owner":
        custody["owner"]["epoch"] = U
    elif change == "workflow":
        custody["resource"]["id"] = V
    elif change == "principal":
        custody["authenticated_principal"] = "other-principal"
    elif change == "purpose":
        custody["purpose"] = "content"
    else:
        custody["expires_at"] = "2026-10-23T00:01:00Z"
    with pytest.raises(ContractError):
        validate_workflow_input_custody(
            reference, payload, custody, principal=value["driver_principal"], now=NOW
        )


def test_exact_retained_input_replays_after_deadline_and_original_client_loss():
    value = workflow()
    payload = preparation(value)
    reference, _ = staged_workflow_input("workflow.prepare", payload)
    custody = stage(reference, value["id"], pinned=1)
    validate_workflow_input_custody(
        reference,
        payload,
        custody,
        principal="replacement-operator",
        now="2026-10-24T00:00:00Z",
        retained_request=copy.deepcopy(payload),
    )
    with pytest.raises(ContractError):
        validate_workflow_input_custody(
            reference,
            payload,
            custody,
            principal="replacement-operator",
            now="2026-10-24T00:00:00Z",
        )
    custody["accepted_references"] = 0
    with pytest.raises(ContractError, match="principal mismatch"):
        validate_workflow_input_custody(
            reference,
            payload,
            custody,
            principal="replacement-operator",
            now=NOW,
            retained_request=payload,
        )
    restaged = copy.deepcopy(reference)
    restaged["input"]["id"] = uid("replacement-input-handle")
    restaged["input"]["binding"]["staging_id"] = uid("replacement-input-staging")
    fresh = stage(restaged, value["id"])
    fresh["authenticated_principal"] = "replacement-operator"
    validate_workflow_input_custody(
        restaged,
        payload,
        fresh,
        principal="replacement-operator",
        now=NOW,
        retained_request=copy.deepcopy(payload),
    )
    assert fresh["accepted_references"] == 0


@pytest.mark.parametrize("change", ["missing", "generation", "proposal", "witnesses"])
def test_completed_capsule_cannot_omit_its_atomic_advance_receipt(change):
    value, _ = committed()
    complete = advance_workflow(completion_request(value), value)
    receipt = complete["advances"][0]
    if change == "missing":
        complete["advances"] = []
    elif change == "generation":
        complete["generation"] = value["generation"]
    else:
        completion = receipt["request"]["transfer_completion"]
        if change == "proposal":
            completion["proposal_digest"] = "sha256:" + "a" * 64
        else:
            completion["witnesses"].pop()
        receipt["request_digest"] = digest(receipt["request"])
    with pytest.raises(ContractError):
        validate_workflow(complete)


@pytest.mark.parametrize(
    "change",
    ["missing", "duplicate", "epoch", "local-commit", "proposal", "generation", "driver-term"],
)
def test_transfer_completion_rejects_incomplete_or_substituted_current_evidence(change):
    value, _ = committed()
    query = completion_request(value)
    completion = query["transfer_completion"]
    if change == "missing":
        completion["witnesses"].pop()
    elif change == "duplicate":
        completion["witnesses"].append(copy.deepcopy(completion["witnesses"][0]))
    elif change == "epoch":
        completion["witnesses"][-1]["owner"]["epoch"] = U
    elif change == "local-commit":
        completion["witnesses"][0]["generation"] += 1
    elif change == "proposal":
        completion["proposal_digest"] = "sha256:" + "c" * 64
    elif change == "generation":
        query["expected_generation"] += 1
    else:
        query["driver_term"] -= 1
    with pytest.raises(ContractError):
        advance_workflow(query, value)


def test_transfer_completion_requires_local_commit_and_replay_is_immutable():
    value, _ = committed()
    query = completion_request(value)
    pending, _ = frozen()
    query["expected_generation"] = pending["generation"]
    query["driver_term"] = pending["driver_term"]
    with pytest.raises(ContractError, match="not committed locally"):
        advance_workflow(query, pending)
    query = completion_request(value)
    query["phase"] = value["phase"]
    complete = advance_workflow(query, value)
    assert complete["phase"] == "prepared"
    assert complete["state"] == "prepared"
    assert complete["holds"] == value["holds"]
    original_receipt = copy.deepcopy(complete["advances"][0])
    following = normal_advance(complete)
    advanced = advance_workflow(following, complete)
    assert validate_advance_request(query, advanced) == "replay"
    assert advance_workflow(query, advanced)["advances"][0] == original_receipt
    changed = copy.deepcopy(query)
    changed["phase"] = "draining"
    with pytest.raises(ContractError, match="accepted workflow advance input changed"):
        advance_workflow(changed, advanced)


def test_ordinary_advance_rejects_phase_skips_and_retains_original_receipt():
    value = workflow()
    query = normal_advance(value)
    changed = copy.deepcopy(query)
    changed["phase"] = "host-effect"
    with pytest.raises(ContractError, match="skips installed phase"):
        advance_workflow(changed, value)
    result = advance_workflow(query, value)
    assert result["generation"] == 1
    assert result["advances"][0]["request_digest"] == digest(query)
    result["generation"] = 7
    result["driver_term"] = 2
    assert advance_workflow(query, result) == result
    changed = copy.deepcopy(query)
    changed["expected_generation"] = 7
    with pytest.raises(ContractError, match="accepted workflow advance input changed"):
        advance_workflow(changed, result)
