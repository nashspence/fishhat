from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from scripts.check_evidence import current_run, proof, summary
from scripts.project_policy import ROOT, components, read_toml
from scripts.validation import source_identity

MAP_PATH = "policy/operations.json"
REGISTRY = "policy/operation-coverage.toml"
CONTRACTS = "packages/fishhat-contracts/src/fishhat_contracts/contracts/"


def runtime_commands(tool: str) -> list[str]:
    from fishhat_cli.validation import build_parser

    result: list[str] = []
    for action in build_parser(tool)._actions:
        if isinstance(action, argparse._SubParsersAction):
            result.extend(action.choices)
    return sorted(result)


def inventory(root: Path = ROOT) -> tuple[dict[str, dict[str, Any]], set[str]]:
    rows: dict[str, dict[str, Any]] = {}
    sources: set[str] = set()

    def load(name: str) -> Any:
        path = CONTRACTS + name
        sources.add(path)
        return json.loads((root / path).read_text())

    def add(identity: str, surface: str, **fields: Any) -> None:
        if identity in rows:
            raise ValueError("duplicate operation identity")
        rows[identity] = {"id": identity, "surface": surface, **fields}

    for item in load("actions.json")["actions"]:
        add(
            "action:" + item["name"],
            "declared-action",
            tools=item["owners"],
            schema=item["arguments_schema"]["$ref"],
        )
    for item in load("ssh-methods.json")["methods"]:
        add("rpc:" + item["name"], "declared-rpc", tools=["host-ops", "app-ops"])
    for item in load("owner-cli.json")["forms"]:
        tool = item["tokens"][0]
        add(
            "owner-form:" + item["name"],
            "declared-owner-form",
            tools=["host-ops", "app-ops"] if tool == "{tool}" else [tool],
            use_case=item["use_case"],
        )
    for item in load("client-commands.json")["commands"]:
        add("client:" + item["name"], "declared-client-command", tools=["domain-ops"])
    entrypoints: dict[str, str] = {}
    for component in components(root):
        path = component["path"] + "/pyproject.toml"
        scripts = read_toml(root / path)["project"].get("scripts", {})
        if scripts:
            sources.add(path)
        for tool, symbol in scripts.items():
            if component["role"] == "adapter-implementation":
                continue
            if tool in entrypoints:
                raise ValueError("ambiguous public entrypoint")
            entrypoints[tool] = symbol
    if set(entrypoints) != set(read_toml(root / "release.toml")["interfaces"]["cli_tools"]):
        raise ValueError("public entrypoints differ from the declared interface")
    for tool, symbol in sorted(entrypoints.items()):
        for command in runtime_commands(tool):
            add("cli:" + tool + ":" + command, "runtime-cli", tools=[tool], entrypoint=symbol)
    return rows, sources


def find_definition(path: Path, names: list[str]) -> None:
    nodes = ast.parse(path.read_text(encoding="utf-8")).body
    for name in names:
        matches = [
            node
            for node in nodes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == name
        ]
        if len(matches) != 1:
            raise ValueError("missing or ambiguous operation/test definition")
        nodes = matches[0].body


def symbol_path(symbol: str, root: Path) -> str:
    module, separator, qualified = symbol.partition(":")
    if not separator or not qualified:
        raise ValueError("implementation needs an explicit module:symbol")
    for item in components(root):
        if module == item["module"] or module.startswith(item["module"] + "."):
            tail = module.removeprefix(item["module"]).replace(".", "/")
            path: str = (
                item["path"] + "/src/" + item["module"] + (tail + ".py" if tail else "/__init__.py")
            )
            if not (root / path).resolve().is_relative_to(root.resolve()):
                raise ValueError("implementation escaped the checkout")
            find_definition(root / path, qualified.split("."))
            return path
    raise ValueError("implementation is outside the component inventory")


def test_path(reference: str, root: Path) -> str:
    parts = reference.split("::")
    path = root / parts[0]
    if (
        len(parts) < 2
        or not parts[0].startswith("tests/")
        or not path.resolve().is_relative_to(root.resolve())
        or not parts[-1].startswith("test_")
    ):
        raise ValueError("invalid test node reference")
    find_definition(path, parts[1:])
    return parts[0]


def build_map(root: Path = ROOT) -> dict[str, Any]:
    rows, sources = inventory(root)
    sources.update(
        {
            REGISTRY,
            "release.toml",
            "policy/components.toml",
            "fishhat/cli-support/src/fishhat_cli/validation.py",
        }
    )
    registry = read_toml(root / REGISTRY)
    if registry["format"] != "fishhat-operation-bindings/v1":
        raise ValueError("unsupported operation binding format")
    interface_tests = registry["interfaces"]["tests"]
    sources.add(read_toml(root / "release.toml")["interfaces"]["snapshot"])
    if not interface_tests or len(set(interface_tests)) != len(interface_tests):
        raise ValueError("public interface consistency requires reviewed test bindings")
    for reference in interface_tests:
        sources.add(test_path(reference, root))
    entries = registry["implementations"]
    by_id = {entry["id"]: entry for entry in entries}
    if len(by_id) != len(entries) or set(by_id) - set(rows):
        raise ValueError("duplicate or unknown operation implementation binding")
    if {key for key, row in rows.items() if row["surface"] == "runtime-cli"} - set(by_id):
        raise ValueError("runtime CLI operation lacks an implementation/test binding")
    if "client:info" in rows and "cli:domain-ops:info" in by_id:
        if "client:info" in by_id:
            raise ValueError("client info binding must use its runtime alias")
        by_id["client:info"] = by_id["cli:domain-ops:info"]
        rows["client:info"]["alias_of"] = "cli:domain-ops:info"
    for identity, row in rows.items():
        entry = by_id.get(identity)
        row.update(
            implementation=None,
            tests={"success": [], "failure": [], "recovery": []},
            recovery="required",
            status="unimplemented",
        )
        if entry is None:
            continue
        if entry["stage"] not in {"scaffold", "native"} or type(entry["read_only"]) is not bool:
            raise ValueError("invalid implementation stage or effect classification")
        if row.get("entrypoint", entry["symbol"]) != entry["symbol"]:
            raise ValueError("runtime binding differs from the installed entrypoint")
        path = symbol_path(entry["symbol"], root)
        sources.add(path)
        row["implementation"] = {"symbol": entry["symbol"], "path": path, "stage": entry["stage"]}
        row["status"] = "implemented-" + entry["stage"]
        row["recovery"] = "not-applicable-read-only" if entry["read_only"] else "required"
        for kind in ("success", "failure", "recovery"):
            tests = entry["tests"][kind]
            required = kind != "recovery" or not entry["read_only"]
            if (
                not isinstance(tests, list)
                or not all(isinstance(node, str) for node in tests)
                or len(set(tests)) != len(tests)
                or required != bool(tests)
            ):
                raise ValueError("operation proof requirements are incomplete")
            for reference in tests:
                sources.add(test_path(reference, root))
            row["tests"][kind] = tests
    return {
        "format": "fishhat-operation-coverage/v1",
        "production_qualified": False,
        "sources": {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sorted(sources)
        },
        "operations": [rows[name] for name in sorted(rows)],
        "interfaces": {
            "expectation": "release.toml#/interfaces",
            "snapshot": read_toml(root / "release.toml")["interfaces"]["snapshot"],
            "tests": interface_tests,
            "scope": "frozen signature, option and schema-byte consistency; no runtime or native qualification",
        },
    }


def check(root: Path = ROOT) -> dict[str, Any]:
    current = build_map(root)
    if current != json.loads((root / MAP_PATH).read_text()):
        raise ValueError("operation coverage changed; review and regenerate its map")
    return current


def report(root: Path = ROOT) -> dict[str, Any]:
    coverage = check(root)
    source = source_identity(root)
    selected = current_run(root, source)
    interface_proofs = {
        node: proof(node, "interface:public-snapshot", selected, purpose="public-contract")
        for node in coverage["interfaces"]["tests"]
    }
    rows = []
    for operation in coverage["operations"]:
        tests = [node for nodes in operation["tests"].values() for node in nodes]
        proofs = {
            node: proof(node, operation["id"], selected, purpose="public-contract")
            for node in tests
        }
        rows.append(
            {
                "id": operation["id"],
                "implementation_status": operation["status"],
                "proofs": proofs,
                "required_proofs_passed": bool(
                    operation["implementation"]
                    and tests
                    and all(p["passed"] for p in proofs.values())
                ),
                "native_qualified": False,
            }
        )
    result = {
        "format": "fishhat-operation-results/v1",
        "source": source,
        "production_qualified": False,
        "operations": rows,
        "interfaces": {
            **coverage["interfaces"],
            "proofs": interface_proofs,
            "required_proofs_passed": all(p["passed"] for p in interface_proofs.values()),
        },
        "selected_origin": selected["id"] if selected else None,
        "check_accounting": summary(selected["tests"]["evidence"]["groups"]) if selected else None,
        "unique_supported_obligations": len(
            {
                row.get("alias_of", row["id"])
                for row, result in zip(coverage["operations"], rows, strict=True)
                if result["required_proofs_passed"]
            }
        ),
        "unestablished_operations": [
            row["id"] for row in rows if not row["required_proofs_passed"]
        ],
        "scope": "read-only installed entrypoints exercised in-process; native effects and recovery unestablished",
    }
    destination = root / "artifacts/operation-qualification.json"
    if not destination.resolve().is_relative_to(root.resolve()):
        raise ValueError("operation results escaped the checkout")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", choices=["check", "generate", "report"], default="check", nargs="?"
    )
    parser.add_argument("--require-current-proofs", action="store_true")
    args = parser.parse_args()
    if args.require_current_proofs and args.command != "report":
        parser.error("--require-current-proofs applies to report")
    try:
        if args.command == "generate":
            coverage = build_map()
            (ROOT / MAP_PATH).write_text(
                json.dumps(coverage, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        elif args.command == "report":
            results = report()
            if args.require_current_proofs and any(
                row["implementation_status"] != "unimplemented"
                and not row["required_proofs_passed"]
                for row in results["operations"]
            ):
                parser.error(
                    "current complete proof receipts are required for implemented operations"
                )
            if args.require_current_proofs and not results["interfaces"]["required_proofs_passed"]:
                parser.error(
                    "current complete receipts are required for public interface consistency"
                )
            print(
                json.dumps(
                    {
                        "operations": len(results["operations"]),
                        "proofs_passed": sum(
                            row["required_proofs_passed"] for row in results["operations"]
                        ),
                        "production_qualified": False,
                        "unique_supported_obligations": results["unique_supported_obligations"],
                        "unestablished_operations": len(results["unestablished_operations"]),
                        "scope": results["scope"],
                        "check_accounting": results["check_accounting"],
                        "public_interface_structure_proved": results["interfaces"][
                            "required_proofs_passed"
                        ],
                    }
                )
            )
            return
        else:
            coverage = check()
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit(
            "operation coverage check failed; verify bindings and regenerate reviewed changes"
        ) from None
    implemented = sum(row["implementation"] is not None for row in coverage["operations"])
    print(
        json.dumps(
            {
                "passed": True,
                "operations": len(coverage["operations"]),
                "implemented": implemented,
                "unimplemented": len(coverage["operations"]) - implemented,
                "production_qualified": False,
            }
        )
    )


if __name__ == "__main__":
    main()
