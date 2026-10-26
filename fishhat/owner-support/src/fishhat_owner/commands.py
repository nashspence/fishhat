"""Closed direct-owner command parser model. Never evaluates or executes a command."""

import json
import re
import shlex
from typing import Any

from fishhat_contracts.validation import ROOT, ContractError

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
