"""Declared relocation recovery bases, without executing a production handoff."""

from __future__ import annotations

import pytest
from fishhat_contracts.relocation import validate_relocation
from fishhat_contracts.validation import ContractError, digest, strict_yaml, validate_app

from tests.dataset_support import dataset_inventory
from tests.support import FIXTURES
from tests.test_contracts import OWNER
from tests.test_dataset_contracts import application

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/app.relocate",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json#/$defs/App",
    ],
    "scope": "exact relocation recovery basis and accepted dataset custody",
    "relationship": "candidate",
    "reason": "Positive stateless, rebuild and checkpoint proposals plus substituted releases and preservation bypasses exercise reference checks, not native transfer, restoration or fencing.",
    "claims": [],
}

D = "sha256:" + "a" * 64


def accepted_app(kind):
    if kind == "stateless":
        value = strict_yaml((FIXTURES / "stateless/app.yaml").read_text())
        validate_app(value)
    else:
        value = application(kind)
        validate_app(value, strict_yaml((FIXTURES / "demo-app/secrets.yaml").read_text()))
    return value


def proposal(kind="release"):
    return {
        "destination_host": "node-b",
        "placement_generation": 2,
        "recovery_basis": {
            "kind": kind,
            "release_digest" if kind == "release" else "checkpoint_digest": D,
        },
    }


def check(value, *, accepted_app, accepted_release_digest):
    inventory = dataset_inventory(accepted_app, OWNER, accepted_release_digest)
    value.setdefault("dataset_inventory_digest", digest(inventory))
    validate_relocation(
        value,
        accepted_app=accepted_app,
        accepted_release_digest=accepted_release_digest,
        accepted_inventory=inventory,
        expected_owner=OWNER,
        expected_resource=inventory["resource"],
        expected_app_instance=inventory["app_instance"],
    )


@pytest.mark.parametrize("kind", ["stateless", "rebuild", "external"])
def test_release_relocation_represents_apps_without_preserved_local_data(kind):
    check(proposal(), accepted_app=accepted_app(kind), accepted_release_digest=D)


def test_preserved_app_relocation_uses_an_explicit_checkpoint():
    check(proposal("checkpoint"), accepted_app=accepted_app("preserve"), accepted_release_digest=D)


def test_release_basis_cannot_skip_preserved_application_data():
    with pytest.raises(ContractError, match="requires a checkpoint"):
        check(proposal(), accepted_app=accepted_app("preserve"), accepted_release_digest=D)


def test_release_basis_cannot_substitute_a_different_accepted_release():
    value = proposal()
    value["recovery_basis"]["release_digest"] = "sha256:" + "b" * 64
    with pytest.raises(ContractError, match="differs from accepted release"):
        check(value, accepted_app=accepted_app("stateless"), accepted_release_digest=D)


@pytest.mark.parametrize("change", ["missing", "legacy", "mixed"])
def test_relocation_rejects_ambiguous_or_implicit_recovery_bases(change):
    value = proposal()
    if change == "missing":
        del value["recovery_basis"]
    elif change == "legacy":
        value.pop("recovery_basis")
        value["checkpoint"] = D
    else:
        value["recovery_basis"]["checkpoint_digest"] = D
    with pytest.raises(ContractError):
        check(value, accepted_app=accepted_app("stateless"), accepted_release_digest=D)
