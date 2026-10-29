from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from fishhat_adapters import check_configuration, check_descriptor
from fishhat_contracts.validation import ContractError, canonical, digest, strict_json


def main(package_file: str, argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Installed adapter scaffold; no native dispatch")
    parser.add_argument("command", choices=("info", "validate", "validate-source", "qualify"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result: dict[str, Any]
    try:
        descriptor = strict_json(Path(package_file).with_name("descriptor.json").read_bytes())
        check_descriptor(descriptor)
        if args.command in {"validate", "validate-source"}:
            data = strict_json(sys.stdin.buffer.read(1048577))
            key = "source_schema" if args.command == "validate-source" else "configuration_schema"
            check_configuration(descriptor[key], data, digest(descriptor[key]))
            scope = (
                "local-source-description-only"
                if args.command == "validate-source"
                else "local-configuration-only"
            )
            result = {"status": "valid", "scope": scope}
        elif args.command == "qualify":
            print(
                canonical(
                    {
                        "status": "unqualified",
                        "error": "NATIVE_EXECUTOR_UNIMPLEMENTED",
                        "native_qualified": False,
                    }
                ).decode("utf-8")
            )
            return 2
        else:
            result = {
                "implementation": descriptor["id"],
                "roles": descriptor["roles"],
                "descriptor_digest": digest(descriptor),
                "implemented_operations": descriptor["implemented"],
                "capabilities": [
                    "local-configuration-validation",
                    "local-source-description-validation",
                ],
                "native_mutations": False,
                "native_qualified": False,
            }
        print(canonical(result).decode("utf-8"))
        return 0
    except (OSError, ValueError, ContractError, KeyError, TypeError):
        print(canonical({"error": "INPUT_REJECTED"}).decode("utf-8"), file=sys.stderr)
        return 2
