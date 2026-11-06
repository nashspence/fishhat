"""Owner discovery pins the exact boundaries selected by independent caller policy."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.discovery import owner_contract_schemas, require_owner_contracts
from fishhat_contracts.validation import ContractError, validate

from tests.test_owner_handoffs import V, operation

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Info",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/SchemaIdentity",
    ],
    "scope": "exact advertised owner contract identities before new boundary use",
    "relationship": "candidate",
    "reason": "Independent expected identities reject same-label incompatible schemas and owner-epoch substitutions while incompatible discovery remains inspectable. No native transport, permission or qualification is asserted.",
    "claims": [],
}


def info():
    return {
        "owner": operation()["owner"],
        "wire": "deployment-ops/owner/v1",
        "contract_schemas": owner_contract_schemas(),
        "source_formats": ["deployment-ops/source/v2"],
        "actions": ["app.restart"],
        "adapters": [],
    }


def test_installed_owner_contracts_match_independently_selected_boundaries():
    advertised = info()
    expected = copy.deepcopy(advertised["contract_schemas"])
    require_owner_contracts(
        advertised, expected_owner=operation()["owner"], expected_contracts=expected
    )


@pytest.mark.parametrize("boundary", ["request", "response", "cli", "source"])
def test_same_v1_label_does_not_approve_a_changed_contract(boundary):
    advertised = info()
    expected = copy.deepcopy(advertised["contract_schemas"])
    advertised["contract_schemas"][boundary]["digest"] = "sha256:" + "f" * 64
    # Discovery is an observation. Reading an incompatible advertisement is safe;
    # accepting it as the independently approved contract is not.
    validate("records.schema.json", advertised, "Info")
    with pytest.raises(ContractError, match="contract identity"):
        require_owner_contracts(
            advertised, expected_owner=operation()["owner"], expected_contracts=expected
        )


def test_discovery_requires_explicit_boundaries_and_current_owner():
    advertised = info()
    with pytest.raises(ContractError, match="explicit"):
        require_owner_contracts(
            advertised, expected_owner=operation()["owner"], expected_contracts={}
        )
    with pytest.raises(ContractError, match="epoch"):
        require_owner_contracts(
            advertised,
            expected_owner={**operation()["owner"], "epoch": V},
            expected_contracts=advertised["contract_schemas"],
        )


def test_legacy_discovery_without_exact_identities_is_rejected():
    advertised = info()
    del advertised["contract_schemas"]
    with pytest.raises(ContractError):
        validate("records.schema.json", advertised, "Info")


@pytest.mark.parametrize("definition", ["CancellationReceipt", "SubmissionRefusal", "Problem"])
def test_incompatible_candidate_cannot_open_v1_decision_custody(monkeypatch, definition):
    from fishhat_contracts.cancellation import CancellationJournal
    from fishhat_contracts.validation import SCHEMAS, canonical

    from tests.test_cancellation import OWNER, context, request

    accepted = CancellationJournal(OWNER).cancel(request(), **context())
    original = canonical(accepted)
    name = "owner-decision-v1.schema.json"
    changed = copy.deepcopy(SCHEMAS[name])
    changed["$defs"][definition]["properties"]["new_required_field"] = {"type": "string"}
    changed["$defs"][definition]["required"].append("new_required_field")
    with monkeypatch.context() as candidate:
        candidate.setitem(SCHEMAS, name, changed)
        with pytest.raises(ContractError, match="incompatible v1 decision reader"):
            CancellationJournal(OWNER, retained=[accepted])
    reopened = CancellationJournal(OWNER, retained=[accepted])
    assert canonical(reopened.cancel(request(), **context(target=None))) == original


def test_upgrade_between_discovery_and_stop_intent_preserves_only_original_replay(monkeypatch):
    import io

    from fishhat_client.wire import frame, read_frame
    from fishhat_contracts.cancellation import CancellationJournal
    from fishhat_contracts.discovery import FRESH_ADMISSION_METHODS, admission_contract
    from fishhat_contracts.validation import SCHEMAS
    from fishhat_owner.commands import direct_admission_contract, parse_command

    from tests.test_cancellation import OWNER, context, request, wire

    guarded = {
        b["properties"]["method"]["const"]
        for b in SCHEMAS["ssh-request.schema.json"]["oneOf"]
        if "admission_contract" in b["properties"]
    }
    assert (
        guarded
        == FRESH_ADMISSION_METHODS
        == {
            "operation.submit",
            "operation.close",
            "operation.cancel",
            "plan.prepare",
            "content.begin",
            "content.chunk",
            "content.commit",
            "workflow.journal.submit",
            "lifecycle.evidence.prepare",
        }
    )
    approved = owner_contract_schemas()
    old_pin = admission_contract(approved)
    before = CancellationJournal(OWNER)
    old = request(0)
    retained = before.cancel(old, **context(admission_pin=old_pin))

    # Upgrade an installed normative description without changing owner epoch or wire shape.
    changed = copy.deepcopy(SCHEMAS["cancellation.schema.json"])
    changed["$defs"]["Request"]["description"] += " Require additional protected approval."
    monkeypatch.setitem(SCHEMAS, "cancellation.schema.json", changed)
    current_pin = admission_contract(owner_contract_schemas())
    assert old_pin != current_pin
    after = CancellationJournal(OWNER, retained=[retained])
    assert after.cancel(old, **context(admission_pin=old_pin, target=None)) == retained
    fresh = request(1)
    message = wire("operation.cancel", fresh)
    received = read_frame(io.BytesIO(frame(message, admission_contract=old_pin)))
    native_argv = (
        f"app-ops --admission-contract {old_pin} op cancel {fresh['request_id']}"
        f" --request-id {fresh['cancellation_id']} --confirm --owner-epoch {OWNER['epoch']} --json"
    )
    parsed = parse_command(native_argv, "app-ops")
    assert direct_admission_contract(parsed, message) == received["admission_contract"] == old_pin
    with pytest.raises(ContractError, match="conflicting"):
        direct_admission_contract(parsed, {**message, "admission_contract": current_pin})
    for supplied in (None, received["admission_contract"]):
        with pytest.raises(ContractError, match="CONFLICT"):
            after.cancel(received["params"], **context(admission_pin=supplied))
    assert after.snapshot() == [retained]
    assert after.cancel(fresh, **context(admission_pin=current_pin))["decision"] == "stop-requested"
