"""Offline custody and recovery-policy checks; no native restore qualification."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.validation import ContractError, strict_yaml, validate, validate_app

from tests.support import FIXTURES

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json#/$defs/App",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/hook-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Checkpoint",
    ],
    "scope": "declared dataset custody, recovery procedures and source semantic joins",
    "relationship": "candidate",
    "reason": "Explicit positive and negative source cases check local declarations; they neither execute recovery nor authorize native data deletion.",
    "claims": [],
}


def application(recovery="preserve"):
    value = strict_yaml((FIXTURES / "demo-app/app.yaml").read_text())
    dataset = value["datasets"]["state"]
    if recovery == "preserve":
        return value
    capture = value["hooks"].pop("capture")
    restore = value["hooks"].pop("restore")
    value["hooks"].pop("verify-restore")
    dataset.update(capture=None, restore=None, verify_restore=None, recovery=recovery)
    value["lifecycle"]["checkpoint_policy"] = "stateless"
    if recovery == "external":
        dataset.update(custody="reference", owner={"kind": "app", "id": "shared-database"})
    else:
        dataset.update(rebuild="rebuild", verify_rebuild="verify-rebuild")
        restore.update(role="rebuild", argv=["/app/rebuild"])
        capture.update(role="verify-rebuild", argv=["/app/verify-rebuild"])
        value["hooks"].update({"rebuild": restore, "verify-rebuild": capture})
    return value


def check(value):
    catalogue = strict_yaml((FIXTURES / "demo-app/secrets.yaml").read_text())
    validate_app(value, catalogue)


@pytest.mark.parametrize("recovery", ["preserve", "rebuild", "external"])
def test_explicit_custody_and_recovery_pairs_are_valid(recovery):
    check(application(recovery))


@pytest.mark.parametrize(
    "custody,recovery",
    [("app", "external"), ("reference", "preserve"), ("reference", "rebuild")],
)
def test_custody_cannot_borrow_another_owners_recovery_policy(custody, recovery):
    value = application()
    value["datasets"]["state"].update(custody=custody, recovery=recovery)
    with pytest.raises(ContractError):
        check(value)


@pytest.mark.parametrize("field,value", [("kind", "owned"), ("verify", "verify-restore")])
def test_ambiguous_dataset_fields_are_rejected(field, value):
    app = application()
    app["datasets"]["state"][field] = value
    with pytest.raises(ContractError):
        check(app)


@pytest.mark.parametrize("recovery", ["preserve", "rebuild"])
def test_app_custody_cannot_also_claim_an_external_owner(recovery):
    value = application(recovery)
    value["datasets"]["state"]["owner"] = {"kind": "app", "id": "shared-database"}
    with pytest.raises(ContractError):
        check(value)


def test_reference_requires_a_named_custodian():
    value = application("external")
    value["datasets"]["state"]["owner"] = None
    with pytest.raises(ContractError):
        check(value)


def test_reference_cannot_delegate_recovery_back_to_itself():
    value = application("external")
    value["datasets"]["state"]["owner"] = {"kind": "app", "id": "demo-app"}
    with pytest.raises(ContractError, match="cannot name this app"):
        check(value)


@pytest.mark.parametrize(
    "procedure", ["capture", "restore", "verify_restore", "rebuild", "verify_rebuild"]
)
def test_reference_cannot_install_a_local_recovery_procedure(procedure):
    value = application("external")
    value["datasets"]["state"][procedure] = "local-procedure"
    with pytest.raises(ContractError):
        check(value)


@pytest.mark.parametrize(
    "recovery,procedure",
    [
        ("preserve", "capture"),
        ("preserve", "restore"),
        ("preserve", "verify_restore"),
        ("rebuild", "rebuild"),
        ("rebuild", "verify_rebuild"),
    ],
)
def test_recovery_requires_each_named_procedure(recovery, procedure):
    value = application(recovery)
    value["datasets"]["state"][procedure] = "missing"
    with pytest.raises(ContractError, match="dataset recovery procedure"):
        check(value)


@pytest.mark.parametrize("recovery,hook", [("preserve", "capture"), ("rebuild", "rebuild")])
def test_recovery_hook_must_name_the_dataset_it_recovers(recovery, hook):
    value = application(recovery)
    value["hooks"][hook]["datasets"] = []
    with pytest.raises(ContractError, match="omits its dataset"):
        check(value)


@pytest.mark.parametrize("recovery,hook", [("preserve", "restore"), ("rebuild", "rebuild")])
def test_recovery_mutation_cannot_claim_read_only_mode(recovery, hook):
    value = application(recovery)
    value["hooks"][hook]["mode"] = "read"
    with pytest.raises(ContractError, match=r"schema source\.schema\.json"):
        check(value)


@pytest.mark.parametrize(
    "recovery,hook", [("preserve", "verify-restore"), ("rebuild", "verify-rebuild")]
)
def test_recovery_verification_cannot_request_write_mode(recovery, hook):
    value = application(recovery)
    value["hooks"][hook]["mode"] = "write"
    with pytest.raises(ContractError, match=r"schema source\.schema\.json"):
        check(value)


def test_rebuild_verification_cannot_be_substituted_for_restore_verification():
    value = application()
    value["hooks"]["verify-restore"]["role"] = "verify-rebuild"
    with pytest.raises(ContractError, match="dataset recovery procedure"):
        check(value)


@pytest.mark.parametrize("recovery", ["external", "rebuild"])
def test_unselected_recovery_hook_cannot_bypass_dataset_policy(recovery):
    value = application(recovery)
    value["hooks"]["foreign-restore"] = copy.deepcopy(application()["hooks"]["restore"])
    with pytest.raises(ContractError, match="crosses dataset custody or recovery policy"):
        check(value)


def test_preserved_local_data_cannot_claim_stateless_checkpoints():
    value = application()
    value["lifecycle"]["checkpoint_policy"] = "stateless"
    with pytest.raises(ContractError, match="preserved app data"):
        check(value)


@pytest.mark.parametrize("role,mode", [("rebuild", "write"), ("verify-rebuild", "read")])
def test_rebuild_procedures_have_explicit_hook_wire_roles(role, mode):
    validate(
        "hook-request.schema.json",
        {
            "format": "deployment-ops/hook/v1",
            "procedure_digest": "sha256:" + "a" * 64,
            "required_checks": ["VERIFICATION_OK"],
            "id": "00000000-0000-4000-8000-000000000001",
            "operation_id": "00000000-0000-4000-8000-000000000002",
            "release_digest": "sha256:" + "a" * 64,
            "executor_component": "maintenance",
            "subject": {"kind": "dataset", "id": "state"},
            "role": role,
            "dataset_handles": {"state": {"path": "/synthetic/state", "mode": mode}},
            "secret_paths": {},
            "endpoint_bindings": {},
            "output_directory": "/synthetic/output",
            "timeout_seconds": 60,
            "restore_input": None,
        },
    )


@pytest.mark.parametrize(
    "scope,evidence,valid",
    [
        ("independent-datasets", None, True),
        ("independent-datasets", "sha256:" + "a" * 64, False),
        ("application-quiesced", None, False),
        ("application-quiesced", "sha256:" + "a" * 64, True),
    ],
    ids=["independent", "independent-extra-evidence", "quiesced-missing-evidence", "quiesced"],
)
def test_multi_dataset_checkpoint_declares_its_consistency_claim(scope, evidence, valid):
    from tests.test_contracts import OWNER, uid, wb

    d = "sha256:" + "a" * 64
    dataset = {
        "capture_digest": d,
        "backup_digest": d,
        "verification_digest": d,
    }
    value = {
        "format": "deployment-ops/record/v1",
        "kind": "Checkpoint",
        "id": uid("checkpoint"),
        "app_instance": "prod:" + "a" * 64,
        "owner": OWNER,
        "release_digest": d,
        "datasets": {"database": dataset, "files": copy.deepcopy(dataset)},
        "secret_generations": [],
        "backup_executor": {
            "instance": "backup",
            "role": "backup",
            "installation_digest": d,
            "configuration_digest": d,
            "instance_generation": 1,
            "instance_digest": d,
            "scope": {"authority": OWNER["id"], "kind": "backup-repository", "handle": "backup"},
        },
        "recovery_closure": [d],
        "verified_at": "2026-10-24T00:00:00Z",
        "restore_tested_at": None,
        "consistency_scope": scope,
        "quiescence_evidence": evidence,
    }
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from fishhat_contracts.validation import digest
    from fishhat_contracts.witness import sign

    value["witness"] = sign(
        {**wb(digest(value)), "kind": "checkpoint"}, Ed25519PrivateKey.generate()
    )
    if valid:
        validate("records.schema.json", value, "Checkpoint")
    else:
        with pytest.raises(ContractError):
            validate("records.schema.json", value, "Checkpoint")
