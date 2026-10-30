"""Declared maintenance permission floors, without scheduler or native authorization."""

import copy

import pytest
from fishhat_contracts.authorization import minimum_action_role
from fishhat_contracts.validation import ContractError, strict_yaml, validate_app

from tests.support import FIXTURES

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/app.maintenance-run",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json#/$defs/App",
    ],
    "scope": "maintenance action expansion, hook selection and permission floors",
    "relationship": "candidate",
    "reason": "Synthetic accepted-task examples check role resolution and reject source-granted authority; no scheduler, enrollment or native admission is executed.",
    "claims": [],
}


@pytest.mark.parametrize(
    "task_action,expected",
    [
        ("backup", "operator"),
        ("backup-check", "operator"),
        ("drill", "administrator"),
        ("native-maintenance", "administrator"),
    ],
)
def test_maintenance_cannot_lower_the_expanded_action_role(task_action, expected):
    assert minimum_action_role("app.maintenance-run", task_action=task_action) == expected
    if task_action != "native-maintenance":
        assert minimum_action_role("app." + task_action) == expected


@pytest.mark.parametrize(
    "task_action",
    [None, "", "unknown", "app.drill", "restore"],
    ids=["missing", "empty", "unknown", "expanded-action", "restore"],
)
def test_unresolved_or_unrecognized_maintenance_never_defaults_to_operator(task_action):
    with pytest.raises(ContractError, match="accepted maintenance task action required"):
        minimum_action_role("app.maintenance-run", task_action=task_action)


def test_other_actions_cannot_accept_a_lower_privilege_task_substitution():
    with pytest.raises(ContractError, match="only belongs to maintenance-run"):
        minimum_action_role("app.drill", task_action="backup")
    with pytest.raises(ContractError, match="unknown action"):
        minimum_action_role("app.arbitrary")


@pytest.mark.parametrize("field", ["minimum_role", "delegated_role", "administrator_approved"])
def test_source_task_cannot_grant_itself_execution_authority(field):
    app = strict_yaml((FIXTURES / "demo-app/app.yaml").read_text())
    secrets = strict_yaml((FIXTURES / "demo-app/secrets.yaml").read_text())
    task = copy.deepcopy(next(iter(app["maintenance"].values())))
    task.update(action="drill", hook=None, checkpoint={"mode": "latest-verified"})
    app["maintenance"]["recovery-drill"] = task
    validate_app(app, secrets)
    assert minimum_action_role("app.maintenance-run", task_action=task["action"]) == "administrator"
    task[field] = "operator"
    with pytest.raises(ContractError):
        validate_app(app, secrets)


@pytest.mark.parametrize("action", ["backup", "backup-check", "drill"])
def test_builtin_maintenance_cannot_inject_a_hook(action):
    app = strict_yaml((FIXTURES / "demo-app/app.yaml").read_text())
    secrets = strict_yaml((FIXTURES / "demo-app/secrets.yaml").read_text())
    task = next(iter(app["maintenance"].values()))
    task.update(
        action=action,
        hook=None,
        checkpoint={"mode": "latest-verified"} if action == "drill" else None,
    )
    validate_app(app, secrets)
    task["hook"] = "restore"
    with pytest.raises(ContractError):
        validate_app(app, secrets)


@pytest.mark.parametrize("hook", ["health", "capture", "restore", "verify-restore"])
def test_native_maintenance_hook_selection_never_lowers_administrator_floor(hook):
    app = strict_yaml((FIXTURES / "demo-app/app.yaml").read_text())
    secrets = strict_yaml((FIXTURES / "demo-app/secrets.yaml").read_text())
    task = next(iter(app["maintenance"].values()))
    task.update(
        action="native-maintenance",
        hook=hook,
        checkpoint={"mode": "latest-verified"} if hook in {"restore", "verify-restore"} else None,
    )
    validate_app(app, secrets)
    assert minimum_action_role("app.maintenance-run", task_action=task["action"]) == "administrator"


@pytest.mark.parametrize("hook", [None, "absent"])
def test_native_maintenance_requires_a_declared_hook(hook):
    app = strict_yaml((FIXTURES / "demo-app/app.yaml").read_text())
    secrets = strict_yaml((FIXTURES / "demo-app/secrets.yaml").read_text())
    task = next(iter(app["maintenance"].values()))
    task.update(action="native-maintenance", hook=hook)
    with pytest.raises(ContractError):
        validate_app(app, secrets)
