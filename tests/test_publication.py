"""Publication identities survive provider choice, lost replies and consumer handoff."""

from __future__ import annotations

import copy
from functools import cache

import pytest
from fishhat_contracts.handoffs import schema_identity, validate_result_payload
from fishhat_contracts.publication import validate_publication, validate_publication_result
from fishhat_contracts.validation import ContractError, canonical, digest, validate
from jsonschema import Draft202012Validator

from tests.test_contracts import uid
from tests.test_workflow_continuations import (
    adoption_stage,
    publication_evidence,
    seal_publication,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/publisher-receipt.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/publisher.publish",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/publisher.recover",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json",
    ],
    "scope": "provider-neutral publication, exact retained target/custody, recovery and adoption joins",
    "relationship": "candidate",
    "reason": "Distinct bundle and key-value evidence shapes complete synthetic issuer/publication/adoption handoffs; freshly signed substitutions and uncertain origins exercise receiving checks. Provider execution, schema installation authority and native publication durability remain unqualified.",
    "claims": [],
}


@cache
def _prepared_material(provider):
    _, query = adoption_stage(provider)
    return query["materials"][0]


def outcome(provider="openbao-kv"):
    # Every adversarial case gets independent copies of the reviewed fixture.
    material = _prepared_material(provider)
    return copy.deepcopy(material["publication_receipt"]), copy.deepcopy(material["operation"])


@pytest.mark.parametrize("provider", ["forgejo-age", "openbao-kv"])
def test_publication_result_retains_exact_provider_evidence_without_backend_translation(provider):
    receipt, operation = outcome(provider)
    evidence, schema = publication_evidence(provider)
    Draft202012Validator(schema).validate(evidence)
    handle = receipt["provider_evidence"]["handle"]
    assert (handle["digest"], handle["size"]) == (digest(evidence), len(canonical(evidence)))
    assert receipt["provider_evidence"]["schema"] == schema_identity(
        schema["$id"], {schema["$id"]: schema}
    )
    assert validate_result_payload(operation, canonical(receipt)) == receipt
    assert receipt["source"] == operation["subject"]["arguments"]["source"]
    assert receipt["version"] == operation["subject"]["arguments"]["version"]
    if provider == "openbao-kv":
        assert set(evidence) == {"mount", "path", "version"}
    assert not {"repository", "asset", "tag", "release_id", "asset_id"}.intersection(receipt)


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "entry",
        "consumer",
        "version",
        "catalogue",
        "candidate-handle",
        "predecessor",
        "artifact",
        "bytes",
        "custodian",
        "evidence-owner",
        "evidence-schema",
        "missing-evidence",
        "missing-current",
    ],
)
def test_completed_publication_rejects_freshly_signed_substitution(change):
    receipt, operation = outcome()
    if change == "source":
        receipt["source"]["instance_generation"] += 1
    elif change in {"entry", "consumer"}:
        receipt[change] = "different"
    elif change == "version":
        receipt["version"] = receipt["current"]["version"] = "opaque:another-version"
    elif change == "catalogue":
        receipt["catalogue_digest"] = digest({"catalogue": "different"})
    elif change == "candidate-handle":
        receipt["recovery_handle"]["id"] = uid("other-candidate")
    elif change == "predecessor":
        receipt["previous"] = {
            "source": copy.deepcopy(receipt["source"]),
            "entry": "another-entry",
            "version": "opaque:old-version",
            "artifact_digest": digest({"old": "protected-artifact"}),
        }
    elif change == "artifact":
        receipt["current"]["artifact_digest"] = digest({"different": "protected-material"})
    elif change == "bytes":
        receipt["current"]["bytes"] += 1
    elif change == "custodian":
        receipt["custodian"] = {**receipt["custodian"], "epoch": uid("another-epoch")}
    elif change == "evidence-owner":
        receipt["provider_evidence"]["handle"]["owner"] = {
            **receipt["custodian"],
            "epoch": uid("another-evidence-epoch"),
        }
    elif change == "evidence-schema":
        receipt["provider_evidence"]["schema"]["digest"] = digest({"other": "provider-schema"})
    elif change == "missing-evidence":
        receipt["provider_evidence"] = None
    else:
        receipt["current"] = None
    seal_publication(receipt)
    with pytest.raises(ContractError):
        validate_publication_result(
            receipt, operation["subject"], expected_custodian=operation["owner"]
        )


@pytest.mark.parametrize("field", ["owner", "kind", "state", "subject_digest"])
def test_publication_witness_must_bind_receipt_owner_kind_state_and_complete_body(field):
    receipt, _ = outcome()
    if field == "owner":
        receipt["witness"][field] = {**receipt["custodian"], "epoch": uid("other-witness-epoch")}
    else:
        receipt["witness"][field] = {
            "kind": "binding",
            "state": "uncertain",
            "subject_digest": digest({"other": "receipt"}),
        }[field]
    with pytest.raises(ContractError, match="witness identity"):
        validate_publication(receipt)


def test_unknown_publication_can_reconcile_only_its_retained_exact_destination_and_candidate():
    completed, operation = outcome()
    original = copy.deepcopy(completed)
    original.update(state="uncertain", current=None, verified_at=None)
    original["provider_evidence"]["handle"] = None
    seal_publication(original)
    validate_publication_result(
        original, operation["subject"], expected_custodian=operation["owner"]
    )
    recovery = {
        "action": "publisher.recover",
        "resource": operation["subject"]["resource"],
        "arguments": {
            "publication_id": completed["id"],
            "candidate_digest": completed["recovery_handle"]["digest"],
        },
    }
    validate_publication_result(
        completed,
        recovery,
        expected_custodian=operation["owner"],
        original_receipt=original,
    )
    with pytest.raises(ContractError, match="retained origin"):
        validate_publication_result(completed, recovery, expected_custodian=operation["owner"])
    changed = copy.deepcopy(completed)
    changed["version"] = changed["current"]["version"] = "opaque:substituted-after-timeout"
    seal_publication(changed)
    with pytest.raises(ContractError, match="changed retained intent"):
        validate_publication_result(
            changed,
            recovery,
            expected_custodian=operation["owner"],
            original_receipt=original,
        )


def test_unknown_outcome_does_not_authorize_overwriting_the_predecessor_version():
    receipt, _ = outcome()
    receipt.update(state="uncertain", current=None, verified_at=None)
    receipt["provider_evidence"]["handle"] = None
    receipt["previous"] = {
        "source": copy.deepcopy(receipt["source"]),
        "entry": receipt["entry"],
        "version": receipt["version"],
        "artifact_digest": digest({"old": "protected-artifact"}),
    }
    seal_publication(receipt)
    with pytest.raises(ContractError, match="immutable version"):
        validate_publication(receipt)


def test_recovery_replays_completed_publication_without_losing_confirmed_evidence():
    original, operation = outcome()
    request = {
        "action": "publisher.recover",
        "resource": operation["subject"]["resource"],
        "arguments": {
            "publication_id": original["id"],
            "candidate_digest": original["recovery_handle"]["digest"],
        },
    }
    validate_publication_result(
        original,
        request,
        expected_custodian=operation["owner"],
        original_receipt=original,
    )
    uncertain = copy.deepcopy(original)
    uncertain.update(state="uncertain", verified_at=None)
    uncertain["provider_evidence"]["handle"] = None
    seal_publication(uncertain)
    with pytest.raises(ContractError, match="completed publication outcome is immutable"):
        validate_publication_result(
            uncertain,
            request,
            expected_custodian=operation["owner"],
            original_receipt=original,
        )


def test_core_publication_and_adoption_reject_bundle_specific_fields():
    receipt, operation = outcome()
    receipt["asset"] = "secrets.tar.age"
    with pytest.raises(ContractError):
        validate("publisher-receipt.schema.json", receipt)
    adoption = {
        "action": "app.secrets-adopt",
        "resource": {"kind": "app", "id": "demo-app"},
        "arguments": {"bundle_receipt": digest(operation)},
    }
    with pytest.raises(ContractError):
        validate("actions.schema.json", adoption)
