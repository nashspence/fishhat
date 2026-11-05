"""Closed direct-owner command parser model. Never evaluates or executes a command."""

import json
import re
import shlex
from typing import Any

from fishhat_contracts.validation import ROOT, ContractError, strict_json, validate

FORMS = json.loads((ROOT / "contracts/owner-cli.json").read_text())["forms"]
PATTERNS = {
    "{cursor}": r"[A-Za-z0-9_-]{1,256}",
    "{kind}": r"(?:domain|host|app|source|dns|recovery|publisher|backend|adapter|interface|dataset|component|workflow)",
    "{resource}": r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,159}",
    "{tool}": r"(?:host-ops|app-ops)",
    "{id}": r"[a-z](?:[a-z0-9-]{0,22}[a-z0-9])?",
    "{uuid}": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "{digest}": r"sha256:[0-9a-f]{64}",
}


def parse_command(command: str, receiver: str) -> dict[str, Any]:
    if (
        receiver not in ("host-ops", "app-ops")
        or type(command) is not str
        or len(command.encode()) > 4096
        or any(ord(c) < 32 for c in command)
        or any(c in command for c in ";|&`$<>\\")
    ):
        raise ContractError("invalid owner CLI command")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as e:
        raise ContractError("invalid command quoting") from e
    if not tokens or tokens[0] != receiver:
        raise ContractError("wrong receiver")
    for form in FORMS:
        if len(tokens) != len(form["tokens"]):
            continue
        if all(
            re.fullmatch(PATTERNS[t], a) if t in PATTERNS else a == t
            for a, t in zip(tokens, form["tokens"], strict=True)
        ):
            return {"form": form["name"], "use_case": form["use_case"], "tokens": tokens}
    raise ContractError("unsupported owner CLI form")


def workflow_apply_params(data: bytes, expected_owner: dict[str, Any]) -> dict[str, Any]:
    """Decode workflow-apply stdin for the ordinary receiving admission guard."""
    params = strict_json(data)
    if not isinstance(params, dict) or params.get("owner") != expected_owner:
        raise ContractError("workflow submission requires the exact local owner epoch")
    validate(
        "ssh-request.schema.json",
        {
            "format": "deployment-ops/owner/v1",
            "message_id": params.get("request_id"),
            "method": "operation.submit",
            "params": params,
        },
    )
    if params["workflow_id"] is None:
        raise ContractError("workflow submission requires explicit membership and driver term")
    return params


def work_list_params(data: bytes, method: str, expected_owner: dict[str, Any]) -> dict[str, Any]:
    """Decode a direct list request using the same closed selector as the SSH method."""
    if method not in ("operation.list", "workflow.list"):
        raise ContractError("expected an operation or workflow list request")
    params = _read_envelope(data, method)
    if params["owner"] != expected_owner:
        raise ContractError("list request requires the exact local owner epoch")
    return params


def resource_observation_params(data: bytes) -> dict[str, Any]:
    """Preserve the same exact selection as the resources.observe SSH request."""
    return _read_envelope(data, "resources.observe")


def _read_envelope(data: bytes, method: str) -> dict[str, Any]:
    request = strict_json(data)
    if not isinstance(request, dict):
        raise ContractError("expected request envelope")
    if request.get("method") != method:
        raise ContractError("request method mismatch")
    validate("ssh-request.schema.json", request)
    params: dict[str, Any] = request["params"]
    return params
