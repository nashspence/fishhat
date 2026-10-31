from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import inspect
import json
import subprocess
import tomllib
from pathlib import Path
from typing import Any, cast

from fishhat_contracts import canonical

ROOT = Path(__file__).resolve().parents[1]


def read_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def workspace_projects(root: Path = ROOT) -> list[Path]:
    config = read_toml(root / "pyproject.toml")
    patterns = config["tool"]["uv"]["workspace"]["members"]
    return sorted(
        {
            p / "pyproject.toml"
            for pattern in patterns
            for p in root.glob(pattern)
            if (p / "pyproject.toml").is_file()
        }
    )


def components(root: Path = ROOT) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], read_toml(root / "policy/components.toml")["components"])


def fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot() -> dict[str, Any]:
    from fishhat_cli.validation import build_parser
    from fishhat_contracts.validation import SCHEMAS

    policy = read_toml(ROOT / "release.toml")
    public: dict[str, Any] = {}
    for module_name in policy["interfaces"]["python_modules"]:
        module = importlib.import_module(module_name)
        public[module_name] = {}
        for name in module.__all__:
            value = getattr(module, name)
            if inspect.isfunction(value):
                public[module_name][name] = {
                    "kind": "function",
                    "signature": str(inspect.signature(value)),
                }
            elif inspect.isclass(value):
                public[module_name][name] = {
                    "kind": "class",
                    "bases": [base.__module__ + "." + base.__name__ for base in value.__bases__],
                    "methods": {
                        key: str(inspect.signature(method))
                        for key, method in inspect.getmembers(value, inspect.isfunction)
                        if not key.startswith("_") or key == "__init__"
                    },
                }
            elif isinstance(value, dict):
                public[module_name][name] = {
                    "kind": "data",
                    "sha256": hashlib.sha256(canonical(value)).hexdigest(),
                }
            else:
                raise ValueError("public export needs a declared snapshot rule")
    parser = build_parser("domain-ops")
    cli: dict[str, Any] = {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, command in action.choices.items():
                cli[name] = [
                    {
                        "options": item.option_strings,
                        "destination": item.dest,
                        "required": item.required,
                        "nargs": item.nargs,
                        "choices": list(item.choices) if item.choices is not None else None,
                    }
                    for item in command._actions
                ]
    return {
        "format": "fishhat-interface-snapshot/v1",
        "python": public,
        "cli": {
            "tools": policy["interfaces"]["cli_tools"],
            "commands": cli,
            "info_keys": [
                "capabilities",
                "implementation",
                "native_mutations",
                "production_qualified",
                "tool",
                "version",
            ],
            "exit_status": {"success": 0, "rejected": 2},
        },
        "schemas": {
            name: {
                "id": data["$id"],
                "sha256": hashlib.sha256(canonical(data)).hexdigest(),
            }
            for name, data in sorted(SCHEMAS.items())
        },
    }


def boundary_errors(root: Path = ROOT) -> list[str]:
    units = components(root)
    by_module = {item["module"]: item for item in units}
    by_name = {item["distribution"]: item for item in units}
    errors = []
    actual = {str(path.parent.relative_to(root)) for path in workspace_projects(root)}
    if (
        actual != {item["path"] for item in units}
        or len(by_module) != len(units)
        or len(by_name) != len(units)
    ):
        errors.append("component inventory mismatch")
    graph: dict[str, set[str]] = {}
    for item in units:
        config = read_toml(root / item["path"] / "pyproject.toml")
        project = config["project"]
        declared = {
            value.split("==")[0]
            for value in project["dependencies"]
            if value.startswith(("fishhat-", "a-fishhat-"))
        }
        graph[item["distribution"]] = declared
        if (
            declared != set(item["internal_dependencies"])
            or project["name"] != item["distribution"]
        ):
            errors.append(item["id"] + ": dependency metadata mismatch")
        if (
            item["role"] != "adapter-implementation"
            and project["version"] != read_toml(root / "release.toml")["version"]
        ):
            errors.append(item["id"] + ": coordinated version mismatch")
        source = root / item["path"] / "src" / item["module"]
        if not (source / "py.typed").is_file():
            errors.append(item["id"] + ": missing inline type marker")
        for path in source.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                imports = (
                    [alias.name for alias in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                    if isinstance(node, ast.ImportFrom) and node.level == 0
                    else []
                )
                for imported in imports:
                    module_root = imported.partition(".")[0]
                    if (
                        module_root in by_module
                        and module_root != item["module"]
                        and by_module[module_root]["distribution"] not in declared
                    ):
                        errors.append(item["id"] + ": undeclared cross-component import")
                    if item["role"] in {"shared-contracts", "adapter-protocol"} and module_root in {
                        "sqlite3",
                        "subprocess",
                        "socket",
                    }:
                        errors.append(item["id"] + ": external effects in shared contracts")
    for item in units:
        seen: set[str] = set()
        pending = list(graph[item["distribution"]])
        while pending:
            name = pending.pop()
            if name == item["distribution"]:
                errors.append(item["id"] + ": dependency cycle")
                break
            if name not in by_name:
                errors.append(item["id"] + ": unknown internal dependency")
                continue
            if name not in seen:
                seen.add(name)
                pending.extend(graph[name])
        forbidden = (
            {
                "optional-reporting",
                "optional-discovery",
                "host-owner-scaffold",
                "app-owner-scaffold",
                "owner-state",
                "adapter-implementation",
            }
            if item["role"] == "portable-client"
            else {"optional-reporting", "optional-discovery", "adapter-implementation"}
            if item["role"] in {"host-owner-scaffold", "app-owner-scaffold", "owner-state"}
            else {
                "app-owner-scaffold",
                "host-owner-scaffold",
                "owner-state",
                "adapter-implementation",
            }
            if item["role"] in {"shared-contracts", "adapter-protocol", "adapter-support"}
            else {
                "app-owner-scaffold",
                "host-owner-scaffold",
                "owner-state",
                "portable-client",
                "adapter-implementation",
            }
            if item["role"] == "adapter-implementation"
            else set()
        )
        if any(by_name[name]["role"] in forbidden for name in seen if name in by_name):
            errors.append(item["id"] + ": forbidden dependency closure")
    return sorted(set(errors))


def relocated_migration(root: Path, name: str, introduced: str) -> Path | None:
    historical = subprocess.run(
        ["git", "show", introduced + ":state/inventory.toml"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if historical.returncode:
        return None
    suffix = name.split("/src/", 1)[1]
    previous = tomllib.loads(historical.stdout)["owners"]
    current = read_toml(root / "state/inventory.toml")["owners"]
    for owner in previous:
        prefix = owner["migrations"].replace(".", "/") + "/"
        if not suffix.startswith(prefix):
            continue
        matches = [item for item in current if item["id"] == owner["id"]]
        if len(matches) != 1:
            return None
        relative = matches[0]["migrations"].replace(".", "/") + "/" + suffix[len(prefix) :]
        candidates = [project.parent / "src" / relative for project in workspace_projects(root)]
        candidates = [candidate for candidate in candidates if candidate.is_file()]
        return candidates[0] if len(candidates) == 1 else None
    return None


def fixture_history_errors(root: Path) -> list[str]:
    if (
        subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        != "false"
    ):
        return ["full history required to check immutable state fixtures"]
    paths = set(
        subprocess.run(
            [
                "git",
                "log",
                "--diff-filter=A",
                "--name-only",
                "--format=",
                "--",
                "state/fixtures",
                ":(glob)**/src/*/migrations/versions/v*.py",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
    ) - {""}
    errors = []
    for name in sorted(paths):
        introduced = subprocess.run(
            ["git", "log", "--diff-filter=A", "--format=%H", "--", name],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()[-1]
        original = subprocess.run(
            ["git", "show", introduced + ":" + name], cwd=root, capture_output=True, check=True
        ).stdout
        path = root / name
        if not path.is_file() and "/src/" in name and (root / "pyproject.toml").exists():
            path = relocated_migration(root, name, introduced) or path
        if not path.is_file() or path.is_symlink() or path.read_bytes() != original:
            errors.append("immutable state fixture/migration changed or removed: " + name)
    return errors


def state_errors(root: Path = ROOT, history: bool = False) -> list[str]:
    inventory = read_toml(root / "state/inventory.toml")
    errors = fixture_history_errors(root) if history else []
    owners = inventory["owners"]
    modules = [owner["module"] for owner in owners + inventory.get("journals", [])]
    if len(set(modules)) != len(modules):
        errors.append("duplicate durable state owner")
    for owner in owners:
        module = root / owner["source"]
        if (
            not module.is_file()
            or owner["transition"] != "explicit-forward-only"
            or owner["qualification"] != "reference-model"
        ):
            errors.append("invalid durable state authority")
        fixture = root / owner["fixture"]
        if fingerprint(fixture) != owner["sha256"]:
            errors.append("state fixture digest changed")
    for journal in inventory.get("journals", []):
        module = root / journal["source"]
        if (
            not module.is_file()
            or journal["transition"] != "explicit-forward-only"
            or journal["qualification"] != "reference-model"
            or journal["version_authority"] != "journal-genesis"
        ):
            errors.append("invalid append-only state authority")
        if fingerprint(root / journal["fixture"]) != journal["sha256"]:
            errors.append("append-only state fixture digest changed")
    for item in components(root):
        for path in (root / item["path"] / "src").rglob("*.py"):
            tree = ast.parse(path.read_text())
            if any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "sqlite3"
                and node.func.attr == "connect"
                for node in ast.walk(tree)
            ):
                if str(path.relative_to(root)) not in {owner["source"] for owner in owners}:
                    errors.append("unclassified persistent store")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-snapshot", action="store_true")
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args()
    target = ROOT / "policy/interfaces.json"
    if args.write_snapshot:
        target.write_text(json.dumps(snapshot(), indent=2, sort_keys=True) + "\n")
        return
    from scripts.validation_watchdogs import check as watchdog_errors

    errors = boundary_errors() + state_errors(history=args.history) + watchdog_errors(ROOT)
    if snapshot() != json.loads(target.read_text()):
        errors.append("declared public interface changed; review and update its snapshot")
    if errors:
        raise SystemExit("\n".join(errors))
    print(json.dumps({"passed": True, "components": len(components()), "state_owners": 2}))


if __name__ == "__main__":
    main()
