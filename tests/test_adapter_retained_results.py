"""Durable adapter results retain the same identity and success obligations as live replies."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import check_response
from fishhat_contracts.handoffs import schema_identity, validate_result_payload
from fishhat_contracts.operations import validate_operation_plan
from fishhat_contracts.validation import ContractError, canonical, digest
from fishhat_contracts.workflows import validate_workflow_proposal

from tests.adapter_support import identifier
from tests.operation_support import seal_operation
from tests.test_adapter_handoffs import handoff, invocation_for, response_for
from tests.test_adapter_invocations import handoff_output, recovered
from tests.test_owner_handoffs import adapter_result, operation
from tests.test_plan_review import reseal
from tests.test_workflow_continuations import attach_result, successful
from tests.test_workflow_inputs import material_handle, rotation_intent

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/credential-issuer-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/capture-adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json",
    ],
    "scope": "input-schema-selected core semantics, exact retained invocation and owning Operation, retained effect/native-task knowledge, and original-method success evidence in direct and recovered adapter results",
    "relationship": "candidate",
    "reason": "Synthetic sealed Operations with valid content commitments exercise semantic substitution and incomplete-success rejection; no native effect, authentication or custody is established.",
    "claims": [],
}


def result_fixture(role="credential-issuer", method="issue", *, reconcile=False):
    if role == "credential-issuer":
        _, query = handoff(role, "renew")
        lease = copy.deepcopy(query["input"]["lease"])
        if method == "issue":
            query["method"] = method
            query["input"].update(
                issuer=lease["issuer"], identity=lease["identity"], consumer=lease["consumer"]
            )
            del query["input"]["lease"]
        output = {
            "leases": [
                {
                    **lease,
                    "value_handle": "protected:issued",
                    "validity": "valid",
                    "valid_from": "2026-10-19T12:00:00Z",
                    "expires_at": "2026-10-19T13:00:00Z",
                    "renewable": True,
                }
            ]
        }
    else:
        _, query = handoff(role, method)
        output = handoff_output(role, query)
    invocation = copy.deepcopy(invocation_for(query))
    response_query = recovered(invocation) if reconcile else query
    retained = {
        "invocation": invocation,
        "response": response_for(response_query, invocation["attempt"], output),
    }
    record = operation()
    executor = invocation["attempt"]["executor"]
    uri = f"https://fishhat.invalid/contracts/{role}-adapter.schema.json"
    record.update(
        id=invocation["attempt"]["operation_id"],
        owner=copy.deepcopy(invocation["attempt"]["owner"]),
        state="succeeded",
        effect_certainty="known",
        subject={
            "action": "adapter.execute",
            "resource": {"kind": "adapter", "id": executor["instance"]},
            "arguments": {
                "adapter_id": executor["instance"],
                "adapter_release": executor["installation_digest"],
                "action": query["method"],
                "input": material_handle(
                    invocation["attempt"]["owner"], digest(query), size=len(canonical(query))
                ),
                "input_schema": schema_identity(uri + "#/$defs/MutationRequest"),
                "result_schema": schema_identity(uri + "#/$defs/RetainedResult"),
            },
        },
    )
    attach_result(record, retained, record["owner"])
    return record, retained


def read_result(record, retained):
    # Recommit exact changed bytes so a rejection must reach semantic validation.
    attach_result(record, retained, record["owner"])
    return validate_result_payload(record, canonical(retained))


@pytest.mark.parametrize(
    "role,method",
    [
        ("credential-issuer", "issue"),
        ("credential-issuer", "renew"),
        ("capture", "restore"),
        ("capture", "verify"),
    ],
)
@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
def test_complete_retained_results_reapply_original_method_semantics(role, method, reconcile):
    record, retained = result_fixture(role, method, reconcile=reconcile)
    original = copy.deepcopy(retained)
    assert read_result(record, retained) == original
    assert retained == original


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
@pytest.mark.parametrize(
    "change", ["missing-lease", "issuer", "identity", "lifetime", "missing-start"]
)
def test_durable_issuance_cannot_bypass_live_success_obligations(change, reconcile):
    record, retained = result_fixture(reconcile=reconcile)
    leases = retained["response"]["output"]["leases"]
    if change == "missing-lease":
        leases.clear()
    elif change == "issuer":
        leases[0]["issuer"]["configuration_digest"] = "sha256:" + "f" * 64
    elif change == "identity":
        leases[0]["identity"] = "another-user"
    elif change == "lifetime":
        leases[0]["expires_at"] = "2026-10-19T13:00:01Z"
    else:
        leases[0]["valid_from"] = None
    invocation = retained["invocation"]
    query = recovered(invocation) if reconcile else invocation["request"]
    with pytest.raises(ContractError):
        check_response("credential-issuer", query, retained["response"], invocation=invocation)
    with pytest.raises(ContractError):
        read_result(record, retained)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
@pytest.mark.parametrize(
    "method,change",
    [
        ("restore", "missing-snapshot"),
        ("restore", "different-snapshot"),
        ("verify", "missing-snapshot"),
        ("verify", "different-snapshot"),
        ("verify", "unknown-verification"),
    ],
)
def test_durable_capture_cannot_lose_snapshot_identity_or_verified_output(
    method, reconcile, change
):
    record, retained = result_fixture("capture", method, reconcile=reconcile)
    output = retained["response"]["output"]
    if change == "missing-snapshot":
        output["snapshots"].clear()
    elif change == "different-snapshot":
        output["snapshots"][0]["handle"] = "snapshot:substituted"
    else:
        output["verification"] = "unknown"
    with pytest.raises(ContractError):
        read_result(record, retained)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
@pytest.mark.parametrize(
    "change", ["operation", "owner", "executor", "artifact", "method", "input-size"]
)
def test_retained_invocation_must_belong_to_the_exact_accepted_operation(reconcile, change):
    record, retained = result_fixture(reconcile=reconcile)
    arguments = record["subject"]["arguments"]
    if change == "operation":
        record["id"] = identifier(99)
    elif change == "owner":
        retained["invocation"]["attempt"]["owner"]["epoch"] = identifier(99)
        if reconcile:
            retained["response"]["request_digest"] = digest(recovered(retained["invocation"]))
    elif change == "executor":
        arguments["adapter_id"] = "another-adapter"
    elif change == "artifact":
        arguments["adapter_release"] = "sha256:" + "f" * 64
    elif change == "method":
        arguments["action"] = "renew"
    else:
        arguments["input"]["size"] += 1
    with pytest.raises(ContractError, match="RETAINED_RESULT_OPERATION_IDENTITY"):
        read_result(record, retained)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
def test_self_consistent_replacement_request_cannot_change_original_operation_input(reconcile):
    record, retained = result_fixture(reconcile=reconcile)
    invocation = retained["invocation"]
    invocation["request"]["input"]["lifetime_seconds"] += 1
    identity = digest(invocation["request"])
    invocation["attempt"]["input_digest"] = identity
    retained["response"]["effect"]["input_digest"] = identity
    retained["response"]["request_digest"] = digest(
        recovered(invocation) if reconcile else invocation["request"]
    )
    with pytest.raises(ContractError, match="RETAINED_RESULT_OPERATION_IDENTITY"):
        read_result(record, retained)


def test_pending_adapter_evidence_cannot_support_a_successful_operation():
    record, retained = result_fixture()
    retained["response"]["effect"].update(
        task_state="running", native_task="task:pending", postcondition="unknown"
    )
    retained["response"]["output"]["leases"] = []
    with pytest.raises(ContractError, match="SUCCESSFUL_OPERATION_REQUIRES_ADAPTER_SUCCESS"):
        read_result(record, retained)


def test_succeeded_workflow_child_rejects_output_only_durable_shape():
    intent = rotation_intent()
    validate_workflow_proposal(intent)
    participant = intent["participants"][0]
    binding = participant["requests"][0]
    record = successful(intent["target"]["issuer_change"], binding)
    attach_result(record, {"leases": []}, participant["owner"])
    validate_operation_plan(record, binding["plan"])
    with pytest.raises(ContractError, match="result payload violates action schema"):
        validate_result_payload(record, canonical({"leases": []}))


def test_core_output_schema_cannot_be_selected_as_an_adapter_execution_result():
    record, retained = result_fixture()
    uri = "https://fishhat.invalid/contracts/credential-issuer-adapter.schema.json#/$defs/Output"
    record["subject"]["arguments"]["result_schema"] = schema_identity(uri)
    output = retained["response"]["output"]
    with pytest.raises(ContractError, match="complete retained invocation and response"):
        read_result(record, output)
    intent = rotation_intent()
    plan = intent["participants"][0]["requests"][0]["plan"]
    plan["subject"]["arguments"]["result_schema"] = schema_identity(uri)
    reseal(plan)
    with pytest.raises(ContractError, match="workflow adapter schema binding changed"):
        validate_workflow_proposal(intent)


def test_retained_effect_certainty_must_match_its_operation_summary():
    record, retained = result_fixture()
    record.update(state="running", effect_certainty="unknown")
    seal_operation(record)
    with pytest.raises(ContractError, match="RETAINED_RESULT_EFFECT_CERTAINTY"):
        read_result(record, retained)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
@pytest.mark.parametrize(
    "native_task,code",
    [
        ("task:replacement", "RESULT_NATIVE_TASK_CONFLICT"),
        (None, "RESULT_TASK_CESSATION_IDENTITY"),
    ],
    ids=["replacement", "missing"],
)
def test_retained_terminal_result_cannot_replace_or_forget_known_native_task(
    reconcile, native_task, code
):
    record, retained = result_fixture(reconcile=reconcile)
    invocation = retained["invocation"]
    invocation["attempt"].update(
        state="reconciling", certainty="known", native_task="task:original"
    )
    query = recovered(invocation) if reconcile else invocation["request"]
    response = retained["response"]
    response["request_digest"] = digest(query)
    response["effect"]["native_task"] = "task:original"
    assert read_result(record, retained) == retained

    response["effect"]["native_task"] = native_task
    with pytest.raises(ContractError, match=code):
        check_response("credential-issuer", query, response, invocation=invocation)
    with pytest.raises(ContractError, match=code):
        read_result(record, retained)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "recovered"])
def test_retained_adapter_result_cannot_erase_known_effect_certainty(reconcile):
    record, retained = result_fixture(reconcile=reconcile)
    invocation = retained["invocation"]
    invocation["attempt"].update(state="reconciling", certainty="known")
    query = recovered(invocation) if reconcile else invocation["request"]
    response = retained["response"]
    response["request_digest"] = digest(query)
    response["effect"].update(effect_certainty="none", postcondition="not-satisfied")
    response["output"]["leases"] = []
    # A weaker observation remains admissible for cumulative reconciliation. It
    # cannot become a committed summary that erases previously known effects.
    check_response("credential-issuer", query, response, invocation=invocation)
    record.update(state="failed", effect_certainty="none")
    with pytest.raises(ContractError, match="RETAINED_RESULT_EFFECT_CERTAINTY"):
        read_result(record, retained)


def test_retained_request_needs_its_exact_installed_input_schema_reader():
    record, retained = result_fixture()
    record["subject"]["arguments"]["input_schema"]["digest"] = "sha256:" + "f" * 64
    with pytest.raises(ContractError, match="retained adapter input schema binding changed"):
        read_result(record, retained)
    identity = (
        "https://fishhat.invalid/contracts/credential-issuer-adapter.schema.json#/$defs/MutationRequest",
        "sha256:" + "f" * 64,
    )
    inspected = []
    assert (
        validate_result_payload(
            record,
            canonical(retained),
            recovery_readers={identity: lambda value: inspected.append(value)},
        )
        == retained
    )
    assert inspected == [retained["invocation"]["request"]]

    def translating_reader(value):
        value["input"]["lifetime_seconds"] += 1

    with pytest.raises(ContractError, match="adapter input reader changed original bytes"):
        validate_result_payload(
            record, canonical(retained), recovery_readers={identity: translating_reader}
        )


@pytest.mark.parametrize("wrapped", ["Output", "RetainedResult"])
def test_custom_schema_wrapper_cannot_change_a_core_input_result_contract(wrapped):
    record, retained = result_fixture()
    uri = "https://synthetic.invalid/wrapped-issuer-result.schema.json"
    installed = {
        uri: {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": uri,
            "$ref": "https://fishhat.invalid/contracts/credential-issuer-adapter.schema.json#/$defs/"
            + wrapped,
        }
    }
    record["subject"]["arguments"]["result_schema"] = schema_identity(uri, installed)
    payload = {"leases": []} if wrapped == "Output" else retained
    attach_result(record, payload, record["owner"])
    with pytest.raises(ContractError, match="complete retained invocation and response"):
        validate_result_payload(record, canonical(payload), installed=installed)


def test_custom_input_extension_requires_an_independently_installed_schema_identity():
    record, data, installed = adapter_result()
    assert validate_result_payload(record, data, installed=installed) == {"revision": 3}
    record["subject"]["arguments"]["input_schema"]["digest"] = "sha256:" + "f" * 64
    seal_operation(record)
    with pytest.raises(
        ContractError, match="custom adapter input schema is not independently installed"
    ):
        validate_result_payload(record, data, installed=installed)


@pytest.mark.parametrize(
    "form", ["reference", "composition", "indirect", "encoded-direct", "encoded-indirect"]
)
def test_custom_input_alias_cannot_hide_a_core_method_behind_custom_result_schema(form):
    record, _ = result_fixture()
    input_uri = "https://synthetic.invalid/wrapped-issuer-input.schema.json"
    result_uri = "https://synthetic.invalid/wrapped-issuer-result.schema.json"
    core_uri = "https://fishhat.invalid/contracts/credential-issuer-adapter.schema.json#/$defs/"
    reference = {
        "$ref": core_uri + "MutationRequest"
        if form != "encoded-direct"
        else core_uri.replace("/$defs/", "/$defs%2F") + "MutationRequest"
    }
    installed = {
        input_uri: {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": input_uri,
            **(reference if form == "reference" else {"allOf": [reference]}),
        },
        result_uri: {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": result_uri,
            "$ref": core_uri + "Output",
        },
    }
    if form in {"indirect", "encoded-indirect"}:
        alias = "https://synthetic.invalid/input-alias.schema.json"
        installed[alias] = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": alias,
            "$defs": {"Input": {"allOf": [reference]}},
        }
        fragment = "#/$defs/Input" if form == "indirect" else "#/$defs%2FInput"
        installed[input_uri]["allOf"] = [{"$ref": alias + fragment}]
    record["subject"]["arguments"].update(
        input_schema=schema_identity(input_uri, installed),
        result_schema=schema_identity(result_uri, installed),
    )
    payload = {"leases": []}
    attach_result(record, payload, record["owner"])
    with pytest.raises(ContractError, match="custom input cannot wrap a core adapter mutation"):
        validate_result_payload(record, canonical(payload), installed=installed)


def test_adapter_execution_requires_complete_input_schema_identity():
    record, retained = result_fixture()
    arguments = record["subject"]["arguments"]
    arguments["input_schema_digest"] = arguments.pop("input_schema")["digest"]
    with pytest.raises(ContractError):
        read_result(record, retained)
