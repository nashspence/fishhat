"""Read-only scaffold entry points. No native execution is wired up yet."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from fishhat_contracts.readiness import validate_readiness
from fishhat_contracts.validation import (
    SCHEMAS,
    ContractError,
    strict_json,
    strict_yaml,
    validate,
    validate_app,
    validate_domain,
    validate_host,
)

from . import __version__


def build_parser(tool: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=tool, description="Fishhat scaffold (no native mutations)"
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    info = commands.add_parser("info", help="Report implemented capabilities, not host readiness")
    info.add_argument("--json", action="store_true")
    check = commands.add_parser("validate", help="Validate local source data without side effects")
    check.add_argument("path", type=Path)
    check.add_argument("--schema", choices=sorted(SCHEMAS), default="source.schema.json")
    check.add_argument("--definition", help="Required for collections of named record types")
    check.add_argument(
        "--capacity-bytes",
        type=int,
        help="Reject a complete input larger than this local byte capacity",
    )
    check.add_argument("--catalogue", type=Path)
    check.add_argument("--json", action="store_true")
    return parser


def main(tool: str, argv: list[str] | None = None) -> int:
    args = build_parser(tool).parse_args(argv)
    if args.command == "info":
        result = {
            "tool": tool,
            "version": __version__,
            "implementation": "scaffold",
            "capabilities": ["local-contract-validation"],
            "native_mutations": False,
            "production_qualified": False,
        }
    else:
        try:

            def load(path: Path) -> Any:
                capacity = args.capacity_bytes
                if capacity is not None and capacity < 1:
                    raise ContractError("invalid input capacity")
                with path.open("rb") as stream:
                    if capacity is None:
                        data = stream.read()
                    else:
                        buffer = bytearray()
                        while chunk := stream.read(min(65536, capacity + 1 - len(buffer))):
                            buffer.extend(chunk)
                            if len(buffer) > capacity:
                                raise ContractError("input capacity exceeded")
                        data = bytes(buffer)
                return (
                    strict_yaml(data.decode("utf-8"))
                    if path.suffix in (".yaml", ".yml")
                    else strict_json(data, max_bytes=len(data))
                )

            data = load(args.path)
            if args.schema == "readiness.schema.json" and args.definition is None:
                validate_readiness(data)
            else:
                validate(args.schema, data, args.definition)
            if args.schema == "source.schema.json" and (
                args.definition is None or args.definition in {"Domain", "Host", "App"}
            ):
                cat = load(args.catalogue) if args.catalogue else None
                if data.get("kind") == "Domain":
                    validate_domain(data)
                elif data.get("kind") == "Host":
                    validate_host(data, cat)
                elif data.get("kind") == "App":
                    validate_app(data, cat)
            result = {
                "tool": tool,
                "status": "valid",
                "scope": "local-contracts-only",
                "production_qualified": False,
            }
        except (OSError, UnicodeError, ContractError, KeyError, ValueError):
            # Do not echo input, paths, or malformed private source in errors.
            result = {"tool": tool, "status": "invalid", "error": "INPUT_REJECTED"}
            print(json.dumps(result) if args.json else "Input rejected", file=sys.stderr)
            return 2
    print(
        json.dumps(result, sort_keys=True)
        if args.json
        else "\n".join(f"{k}: {v}" for k, v in result.items())
    )
    return 0
