"""Permission floors for declared actions; no principal enrollment or authorization.

The receiver resolves maintenance tasks from its exact accepted release. Calling
this helper with an untrusted proposed task does not approve that task, bind a
principal, or authorize a native effect. Current grants and resource scope remain
the receiving owner's responsibility, including for scheduled work.
"""

from __future__ import annotations

import json

from fishhat_contracts.validation import ROOT, SCHEMAS, ContractError

_ACTIONS = {
    item["name"]: item
    for item in json.loads((ROOT / "contracts/actions.json").read_text())["actions"]
}
_ROLE_ORDER = ("observer", "operator", "administrator")


def minimum_action_role(action: str, *, task_action: str | None = None) -> str:
    """Resolve the permission floor after the receiver selects the accepted task.

    A task cannot lower the expanded action's requirement. There is no implicit
    administrator delegation through source or a schedule. The unrestricted native
    hook branch requires administrator, and missing or unknown task resolution
    fails closed. This result alone is never an authorization.
    """
    if action not in _ACTIONS:
        raise ContractError("unknown action")
    required = [_ACTIONS[action]["minimum_role"]]
    if action == "app.maintenance-run":
        allowed = SCHEMAS["maintenance.schema.json"]["$defs"]["Task"]["properties"]["action"][
            "enum"
        ]
        if task_action not in allowed:
            raise ContractError("accepted maintenance task action required")
        if task_action == "native-maintenance":
            required.append("administrator")
        else:
            required.append(_ACTIONS["app." + str(task_action)]["minimum_role"])
    elif task_action is not None:
        raise ContractError("task action only belongs to maintenance-run")
    return _ROLE_ORDER[max(_ROLE_ORDER.index(role) for role in required)]
