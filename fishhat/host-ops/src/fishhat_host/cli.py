"""Host-owned administrative identity commands and read-only source validation."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from fishhat_cli.validation import build_parser, execute


def _state_commands(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    state = commands.add_parser(
        "state", help="Explicit Linux administrator owner identity (no operation admission)"
    )
    actions = state.add_subparsers(dest="state_command", required=True)
    for name, help_text in (
        ("initialize", "Initialize fresh protected owner storage explicitly"),
        ("inspect", "Verify an existing protected owner identity and installed schema"),
    ):
        action = actions.add_parser(name, help=help_text)
        action.add_argument("path", type=Path)
        action.add_argument("--owner-id", required=True)
        action.add_argument("--owner-epoch", required=True)
        action.add_argument("--json", action="store_true")


def main(argv: list[str] | None = None) -> int:
    args = build_parser("host-ops", configure_commands=_state_commands).parse_args(argv)
    if args.command != "state":
        return execute("host-ops", args, capabilities=("owner-state-identity",))

    # Dependency configuration must use the selected runtime rather than a
    # caller-selected user base or an NSS lookup for a missing home directory.
    os.environ["PYTHONUSERBASE"] = sys.prefix
    from fishhat_owner import identity_store

    owner = {"tool": "host-ops", "id": args.owner_id, "epoch": args.owner_epoch}
    try:
        action = (
            identity_store.initialize
            if args.state_command == "initialize"
            else identity_store.inspect
        )
        identity = action(args.path, owner)
    except (ValueError, OSError):
        initializing = args.state_command == "initialize"
        error = {
            "tool": "host-ops",
            "status": "unconfirmed" if initializing else "invalid",
            "error": "OWNER_INITIALIZATION_UNCONFIRMED" if initializing else "OWNER_STATE_REJECTED",
        }
        message = (
            "Owner initialization unconfirmed; inspect retained state before retry"
            if initializing
            else "Owner state rejected"
        )
        print(json.dumps(error) if args.json else message, file=sys.stderr)
        return 2
    result = {
        "tool": "host-ops",
        "status": "initialized" if args.state_command == "initialize" else "verified",
        **identity,
        "native_mutations": False,
        "production_qualified": False,
    }
    print(
        json.dumps(result, sort_keys=True)
        if args.json
        else "\n".join(f"{key}: {value}" for key, value in result.items())
    )
    return 0
