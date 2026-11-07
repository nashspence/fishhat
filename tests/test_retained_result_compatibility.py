"""Compatible original results survive recovery and composite retained-work joins."""

from copy import deepcopy
from io import BytesIO

import pytest
from fishhat_contracts.drill_results import validate_drill_result
from fishhat_contracts.handoffs import schema_identity, validate_result_payload
from fishhat_contracts.history import validate_historical_recovery
from fishhat_contracts.maintenance import (
    require_maintenance_result_custody,
    retained_maintenance_execution,
    validate_maintenance_result,
)
from fishhat_contracts.operations import validate_operation
from fishhat_contracts.record_delivery import RecordSnapshot
from fishhat_contracts.validation import SCHEMAS, ContractError, canonical, digest, validate

from tests.drill_support import attach_drill
from tests.operation_support import seal_operation
from tests.test_contracts import plan as ordinary_plan
from tests.test_contracts import uid
from tests.test_drill_results import pair as drill_pair
from tests.test_maintenance_handoffs import attach as attach_maintenance
from tests.test_maintenance_handoffs import backup_records
from tests.test_owner_history import custody_for, recovery_plan
from tests.test_plan_review import reseal
from tests.test_workflow_continuations import adoption_stage

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-history.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/maintenance.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/drill-result.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/operations.py#validate_operation",
    ],
    "scope": "qualified original result identities across historical recovery, maintenance custody and drill Plan validation",
    "relationship": "candidate",
    "reason": "Editorial schema changes distinguish retained result compatibility from record inspection. Exact-key, mutation, rejection and semantic-substitution probes preserve original bytes and authority checks. Synthetic readers and streams do not qualify native installation, recovery or custody.",
    "claims": [],
}


def editorial_change(monkeypatch, name):
    changed = deepcopy(SCHEMAS[name])
    changed["description"] = changed.get("description", "") + " Retained result clarification."
    monkeypatch.setitem(SCHEMAS, name, changed)


def result_readers(*operations):
    readers, observed = {}, []
    for operation in operations:
        identity = operation["result_handle"]["schema"]
        name = identity["uri"].split("/contracts/")[1]
        schema, _, definition = name.partition("#/$defs/")
        key = identity["uri"], identity["digest"]

        def read(value, schema=schema, definition=definition, key=key):
            observed.append((key, canonical(value)))
            validate(schema, value, definition or None)

        readers[key] = read
    return readers, observed


def historical_case():
    _, adoption = adoption_stage()
    original = adoption["predecessors"][0]
    payload = adoption["materials"][0]["publication_receipt"]
    custody = custody_for(original)
    reference = RecordSnapshot(original, uid("compatible-result-history")).reference
    _, _, plan = recovery_plan()
    plan["owner"] = deepcopy(custody["custodian"])
    plan["subject"] = {
        "action": "operation.recover",
        "resource": deepcopy(original["subject"]["resource"]),
        "arguments": {
            "operation_id": original["id"],
            "disposition": "native-reconcile",
            "origin": {"custody_id": custody["id"], "reference": reference},
        },
    }
    plan["input_digests"] = [reference["digest"]]
    plan["preconditions"][0].update(
        owner=plan["owner"], resource=plan["subject"]["resource"], generation=12
    )
    plan["effects"][0].update(
        executor=plan["owner"],
        resource=plan["subject"]["resource"],
        input_digest=reference["digest"],
    )
    plan["witness"]["owner"] = deepcopy(plan["owner"])
    reseal(plan)
    context = {
        "current_owner": custody["custodian"],
        "current_generation": 12,
        "verified_custody": custody,
        "verified_reference": reference,
        "recovery_authorized": True,
    }
    return original, payload, plan, context


@pytest.mark.parametrize("historical_record", [False, True])
def test_historical_recovery_keeps_qualified_original_result(monkeypatch, historical_record):
    original, payload, plan, context = historical_case()
    raw = canonical(original)
    reference = context["verified_reference"]
    readers, observed = result_readers(original)
    inspected = []

    def inspect(value):
        inspected.append(canonical(value))
        validate_operation(value, recovery_readers=readers)

    retained = {(reference["schema"]["uri"], reference["schema"]["digest"]): inspect}
    assert validate_historical_recovery(plan, raw, **context) == original
    editorial_change(monkeypatch, "publisher-receipt.schema.json")
    if historical_record:
        editorial_change(monkeypatch, "records.schema.json")
    assert (reference["schema"] != schema_identity(reference["schema"]["uri"])) == historical_record
    recovered = validate_historical_recovery(
        plan, raw, retained_readers=retained, recovery_readers=readers, **context
    )
    assert recovered == original and canonical(recovered) == raw
    assert inspected == ([raw] if historical_record else [])
    assert not observed  # Operation validation does not consume the separate result bytes.
    assert (
        validate_result_payload(recovered, canonical(payload), recovery_readers=readers) == payload
    )
    identity = original["result_handle"]["schema"]
    assert observed == [((identity["uri"], identity["digest"]), canonical(payload))]


@pytest.mark.parametrize("qualification", ["missing", "wrong-uri", "wrong-digest"])
def test_historical_recovery_requires_exact_result_qualification(monkeypatch, qualification):
    original, _, plan, context = historical_case()
    readers, _ = result_readers(original)
    (uri, closure), reader = next(iter(readers.items()))
    readers = {}
    if qualification == "wrong-uri":
        readers[(uri + "/other", closure)] = reader
    elif qualification == "wrong-digest":
        readers[(uri, digest("other schema"))] = reader
    editorial_change(monkeypatch, "publisher-receipt.schema.json")
    with pytest.raises(ContractError, match="action result schema substitution"):
        validate_historical_recovery(plan, canonical(original), recovery_readers=readers, **context)


@pytest.mark.parametrize("change", ["permission", "generation", "latest-reference"])
def test_compatible_result_does_not_supply_historical_recovery_authority(monkeypatch, change):
    original, _, plan, context = historical_case()
    readers, _ = result_readers(original)
    editorial_change(monkeypatch, "publisher-receipt.schema.json")
    if change == "permission":
        context["recovery_authorized"] = False
    elif change == "generation":
        context["current_generation"] += 1
    else:
        context["verified_reference"] = deepcopy(context["verified_reference"])
        context["verified_reference"]["digest"] = digest("later authoritative work")
    with pytest.raises(ContractError):
        validate_historical_recovery(plan, canonical(original), recovery_readers=readers, **context)


@pytest.mark.parametrize("schema", ["maintenance.schema.json", "backup-result.schema.json"])
def test_maintenance_preserves_qualified_parent_child_and_result_custody(monkeypatch, schema):
    parent, value, child_bytes = backup_records(1)
    raw = canonical(value)
    original_parent = canonical(parent)
    readers, observed = result_readers(parent, value["child"])
    assert validate_result_payload(parent, raw) == value
    editorial_change(monkeypatch, schema)
    with pytest.raises(ContractError, match="action result schema substitution"):
        validate_result_payload(parent, raw)
    assert (
        retained_maintenance_execution(parent, value["plan"], recovery_readers=readers)
        == value["plan"]["maintenance"]
    )
    validate_maintenance_result(value, parent, recovery_readers=readers)
    assert validate_result_payload(parent, raw, recovery_readers=readers) == value
    opened = []

    def open_content(handle):
        opened.append(deepcopy(handle))
        return BytesIO(child_bytes)

    require_maintenance_result_custody(
        value, parent, open_content=open_content, recovery_readers=readers
    )
    assert opened == [value["child"]["result_handle"]["handle"]]
    expected = [raw, child_bytes] if schema == "backup-result.schema.json" else [raw]
    assert [data for _, data in observed] == expected
    assert canonical(value) == raw and canonical(parent) == original_parent


@pytest.mark.parametrize(
    "qualification", ["missing", "wrong-uri", "wrong-digest", "reject", "mutate"]
)
def test_maintenance_requires_qualified_unchanged_child_bytes(monkeypatch, qualification):
    parent, value, child_bytes = backup_records(1)
    original = canonical(value)
    readers, observed = result_readers(parent, value["child"])
    identity = value["child"]["result_handle"]["schema"]
    key = identity["uri"], identity["digest"]
    reader = readers.pop(key)
    attempted = []

    def refusing(payload):
        attempted.append(canonical(payload))
        if qualification == "reject":
            raise ContractError("unqualified child semantics")
        payload["request_id"] = uid("translated-child-result")

    if qualification == "wrong-uri":
        readers[(key[0] + "/other", key[1])] = reader
    elif qualification == "wrong-digest":
        readers[(key[0], digest("other closure"))] = reader
    elif qualification in {"reject", "mutate"}:
        readers[key] = refusing
    editorial_change(monkeypatch, "backup-result.schema.json")
    with pytest.raises(ContractError):
        require_maintenance_result_custody(
            value, parent, open_content=lambda _: BytesIO(child_bytes), recovery_readers=readers
        )
    assert attempted == ([child_bytes] if qualification in {"reject", "mutate"} else [])
    assert not observed
    assert canonical(value) == original


def test_compatible_maintenance_reader_cannot_bypass_child_identity(monkeypatch):
    parent, value, _ = backup_records(1)
    value["child"]["request_id"] = uid("unrelated-child-request")
    seal_operation(value["child"])
    raw = attach_maintenance(parent, value)
    readers, observed = result_readers(parent, value["child"])
    editorial_change(monkeypatch, "maintenance.schema.json")
    with pytest.raises(ContractError, match="maintenance child identity"):
        validate_result_payload(parent, raw, recovery_readers=readers)
    assert [data for _, data in observed] == [raw]
    assert canonical(value) == raw


def reviewed_drill():
    record, value, inputs, procedures = drill_pair(1)
    plan = ordinary_plan()
    plan.update(owner=deepcopy(record["owner"]), subject=deepcopy(record["subject"]))
    plan["witness"]["owner"] = deepcopy(record["owner"])
    plan["preconditions"][0].update(owner=record["owner"], resource=record["subject"]["resource"])
    plan["effects"][0].update(
        executor=record["owner"],
        resource=record["subject"]["resource"],
        action="isolated-drill",
        input_digest=digest(value["checkpoint"]),
    )
    plan["input_digests"] = [
        digest(value["checkpoint"]),
        *(
            digest({k: v for k, v in value[name].items() if k != "admission_generation"})
            for name in ("production_binding", "target_binding")
        ),
        *procedures,
    ]
    reseal(plan)
    record["plan_id"] = plan["id"]
    record["plan_digest"] = value["plan_digest"] = plan["digest"]
    data = attach_drill(record, value)
    context = {
        "operation": record,
        "plan": plan,
        "checkpoint_inputs": inputs,
        "accepted_procedures": procedures,
    }
    return record, value, data, context


def test_drill_preserves_qualified_result_with_original_reviewed_plan(monkeypatch):
    record, value, data, context = reviewed_drill()
    original = canonical(record)
    readers, observed = result_readers(record)
    validate_drill_result(value, **context)
    editorial_change(monkeypatch, "drill-result.schema.json")
    with pytest.raises(ContractError, match="action result schema substitution"):
        validate_drill_result(value, **context)
    validate_drill_result(value, recovery_readers=readers, **context)
    assert validate_result_payload(record, data, recovery_readers=readers) == value
    assert [raw for _, raw in observed] == [data]
    assert canonical(value) == data and canonical(record) == original


def test_compatible_drill_reader_cannot_bypass_reviewed_input_closure(monkeypatch):
    record, value, _, context = reviewed_drill()
    target_digest = digest(
        {k: v for k, v in value["target_binding"].items() if k != "admission_generation"}
    )
    context["plan"]["input_digests"].remove(target_digest)
    reseal(context["plan"])
    record["plan_digest"] = value["plan_digest"] = context["plan"]["digest"]
    attach_drill(record, value)
    readers, _ = result_readers(record)
    editorial_change(monkeypatch, "drill-result.schema.json")
    with pytest.raises(ContractError, match="reviewed Plan inputs"):
        validate_drill_result(value, recovery_readers=readers, **context)
