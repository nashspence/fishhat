"""Historical inspection and current recovery require distinct installed semantics."""

from copy import deepcopy

import pytest
from fishhat_contracts.handoffs import schema_identity, validate_result_payload
from fishhat_contracts.history import validate_historical_recovery
from fishhat_contracts.record_delivery import validate_record_payload
from fishhat_contracts.validation import ContractError, canonical, digest, validate

from tests.operation_support import seal_operation
from tests.test_contracts import uid
from tests.test_plan_review import reseal
from tests.test_retained_result_compatibility import (
    editorial_change,
    historical_case,
    result_readers,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/history.py#validate_historical_recovery",
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_recovery.py",
        "packages/fishhat-contracts/src/fishhat_contracts/operations.py#validate_operation",
    ],
    "scope": "independent historical Operation recovery qualification and current-v1 semantic floor",
    "relationship": "candidate",
    "reason": "Separate inspection and recovery callbacks expose missing, miskeyed, rejecting or mutating qualification and semantic substitutions while preserving original bytes and current authority. Synthetic receiving context supplies no native authentication, reader commissioning or recovery proof.",
    "claims": [],
}


def installed_context(original, reference):
    readers, payloads = result_readers(original)
    inspected, qualified = [], []
    key = reference["schema"]["uri"], reference["schema"]["digest"]

    def inspect(value):
        inspected.append(canonical(value))
        validate("records.schema.json", value, "Operation")

    def qualify(value):
        qualified.append(canonical(value))
        # Independent current-v1 checks must still run after this installed reader.

    readers[key] = qualify
    return {key: inspect}, readers, inspected, qualified, payloads


def select_prior_record_schema(monkeypatch, plan, reference):
    # Pin an editorial prior record closure without changing the installed result schema.
    with monkeypatch.context() as prior:
        editorial_change(prior, "records.schema.json")
        reference["schema"] = schema_identity(reference["schema"]["uri"])
    reseal(plan)


@pytest.mark.parametrize("historical_record", [False, True])
@pytest.mark.parametrize("historical_result", [False, True])
def test_recovery_consumes_exact_independent_qualification(
    monkeypatch, historical_record, historical_result
):
    original, payload, plan, context = historical_case()
    reference = context["verified_reference"]
    if historical_record:
        select_prior_record_schema(monkeypatch, plan, reference)
    raw, reviewed = canonical(original), canonical(plan)
    retained, readers, inspected, qualified, payloads = installed_context(original, reference)
    if historical_result:
        editorial_change(monkeypatch, "publisher-receipt.schema.json")
    assert (reference["schema"] != schema_identity(reference["schema"]["uri"])) == historical_record
    identity = original["result_handle"]["schema"]
    assert (identity != schema_identity(identity["uri"])) == historical_result
    assert (
        validate_historical_recovery(
            plan, raw, retained_readers=retained, recovery_readers=readers, **context
        )
        == original
    )
    assert inspected == qualified == ([raw] if historical_record else [])
    assert not payloads  # Metadata qualification does not consume separate result bytes.
    assert (
        validate_result_payload(original, canonical(payload), recovery_readers=readers) == payload
    )
    assert len(payloads) == int(historical_result)
    assert canonical(original) == raw and canonical(plan) == reviewed


@pytest.mark.parametrize("historical_result", [False, True])
@pytest.mark.parametrize(
    "qualification", ["missing", "wrong-uri", "wrong-digest", "reject", "mutate"]
)
def test_inspection_never_substitutes_for_recovery_qualification(
    monkeypatch, qualification, historical_result
):
    original, _, plan, context = historical_case()
    reference = context["verified_reference"]
    select_prior_record_schema(monkeypatch, plan, reference)
    raw, reviewed = canonical(original), canonical(plan)
    retained, readers, _, qualified, _ = installed_context(original, reference)
    key = reference["schema"]["uri"], reference["schema"]["digest"]
    reader = readers.pop(key)
    if qualification == "wrong-uri":
        readers[(key[0] + "/other", key[1])] = reader
    elif qualification == "wrong-digest":
        readers[(key[0], digest("another closure"))] = reader
    elif qualification in {"reject", "mutate"}:

        def refuse_or_rewrite(value):
            qualified.append(canonical(value))
            if qualification == "reject":
                raise ContractError("independently refused recovery semantics")
            value["generation"] += 1

        readers[key] = refuse_or_rewrite
    if historical_result:
        editorial_change(monkeypatch, "publisher-receipt.schema.json")
    assert (
        validate_record_payload(
            reference, raw, expected_owner=original["owner"], retained_readers=retained
        )
        == original
    )
    message = {
        "reject": "independently refused recovery semantics",
        "mutate": "recovery reader changed original bytes",
    }.get(qualification, "independently installed compatible v1 reader required")
    with pytest.raises(ContractError, match=message):
        validate_historical_recovery(
            plan, raw, retained_readers=retained, recovery_readers=readers, **context
        )
    assert qualified == ([raw] if qualification in {"reject", "mutate"} else [])
    assert canonical(original) == raw and canonical(plan) == reviewed


@pytest.mark.parametrize("qualification", ["missing", "wrong-uri", "wrong-digest"])
def test_record_qualification_does_not_supply_result_compatibility(monkeypatch, qualification):
    original, _, plan, context = historical_case()
    reference = context["verified_reference"]
    select_prior_record_schema(monkeypatch, plan, reference)
    retained, readers, _, qualified, _ = installed_context(original, reference)
    identity = original["result_handle"]["schema"]
    key = identity["uri"], identity["digest"]
    reader = readers.pop(key)
    if qualification == "wrong-uri":
        readers[(key[0] + "/other", key[1])] = reader
    elif qualification == "wrong-digest":
        readers[(key[0], digest("another result closure"))] = reader
    editorial_change(monkeypatch, "publisher-receipt.schema.json")
    raw = canonical(original)
    assert (
        validate_record_payload(
            reference, raw, expected_owner=original["owner"], retained_readers=retained
        )
        == original
    )
    with pytest.raises(ContractError, match="action result schema substitution"):
        validate_historical_recovery(
            plan, raw, retained_readers=retained, recovery_readers=readers, **context
        )
    assert qualified == [raw] and canonical(original) == raw


def test_recovery_qualification_does_not_replace_inspection_support(monkeypatch):
    original, _, plan, context = historical_case()
    reference = context["verified_reference"]
    select_prior_record_schema(monkeypatch, plan, reference)
    _, readers, _, _, _ = installed_context(original, reference)
    with pytest.raises(ContractError, match="record schema substitution"):
        validate_historical_recovery(plan, canonical(original), recovery_readers=readers, **context)


@pytest.mark.parametrize("change", ["result-binding", "witness-snapshot"])
def test_qualified_historical_reader_cannot_skip_current_operation_semantics(monkeypatch, change):
    original, _, plan, context = historical_case()
    reference = context["verified_reference"]
    select_prior_record_schema(monkeypatch, plan, reference)
    retained, readers, _, qualified, _ = installed_context(original, reference)
    if change == "result-binding":
        original["result_handle"]["handle"]["binding"]["operation_id"] = uid("substituted-producer")
        seal_operation(original)
    else:
        original["witness"]["subject_digest"] = digest("another operation snapshot")
    raw = canonical(original)
    reference.update(digest=digest(original), size=len(raw))
    plan["input_digests"] = [reference["digest"]]
    plan["effects"][0]["input_digest"] = reference["digest"]
    reseal(plan)
    assert (
        validate_record_payload(
            reference, raw, expected_owner=original["owner"], retained_readers=retained
        )
        == original
    )
    message = (
        "result handle operation binding mismatch"
        if change == "result-binding"
        else "operation witness snapshot mismatch"
    )
    with pytest.raises(ContractError, match=message):
        validate_historical_recovery(
            plan, raw, retained_readers=retained, recovery_readers=readers, **context
        )
    assert qualified == [raw] and canonical(original) == raw


@pytest.mark.parametrize("change", ["permission", "generation", "latest-reference"])
def test_historical_record_qualification_does_not_supply_current_authority(monkeypatch, change):
    original, _, plan, context = historical_case()
    raw = canonical(original)
    reference = context["verified_reference"]
    select_prior_record_schema(monkeypatch, plan, reference)
    retained, readers, _, _, _ = installed_context(original, reference)
    if change == "permission":
        context["recovery_authorized"] = False
    elif change == "generation":
        context["current_generation"] += 1
    else:
        context["verified_reference"] = deepcopy(context["verified_reference"])
        context["verified_reference"]["digest"] = digest("later authoritative snapshot")
    with pytest.raises(ContractError):
        validate_historical_recovery(
            plan, raw, retained_readers=retained, recovery_readers=readers, **context
        )
    assert canonical(original) == raw
