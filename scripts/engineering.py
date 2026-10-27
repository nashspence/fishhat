"""Discover operation-owned engineering proofs and immutable migration histories."""

from __future__ import annotations

import argparse
import ast
import importlib
import inspect
import json
import textwrap
from dataclasses import asdict
from pathlib import Path
from typing import Any

from alembic.script import ScriptDirectory

from scripts.check_evidence import current_run, proof, summary
from scripts.operation_qualification import build_map, symbol_path, test_path
from scripts.project_policy import ROOT, components, fingerprint, read_toml
from scripts.validation import source_identity

MAP = "policy/engineering.json"


def _constant_setup(operation: Any, receiver: Any = None) -> bool:
    """Prove fixed setup from syntax; do not guess from names or annotations.

    Only argument-free/self-only bodies assigning or returning source literals
    qualify. Attribute assignments additionally require object.__setattr__ and
    no data descriptor on the receiver. Decorators, calls, input reads, loops,
    comprehensions and branches cannot be hidden in this classification.
    """
    node = ast.parse(textwrap.dedent(inspect.getsource(operation))).body[0]
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.decorator_list:
        return False
    args = node.args
    if (
        args.posonlyargs
        or args.vararg
        or args.kwarg
        or args.kwonlyargs
        or [arg.arg for arg in args.args] not in ([], ["self"], ["cls"])
    ):
        return False

    def literal(value: ast.AST | None) -> bool:
        if value is None or isinstance(value, ast.Constant):
            return True
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return all(literal(item) for item in value.elts)
        if isinstance(value, ast.Dict):
            return all(key is not None and literal(key) for key in value.keys) and all(
                literal(item) for item in value.values
            )
        return False

    def target(value: ast.AST) -> bool:
        return (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.value.id == "self"
            and inspect.isclass(receiver)
            and inspect.getattr_static(receiver, "__setattr__") is object.__setattr__
            and not inspect.isdatadescriptor(inspect.getattr_static(receiver, value.attr, None))
        )

    for statement in node.body:
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
            continue
        if isinstance(statement, ast.Assign) and all(target(item) for item in statement.targets):
            if literal(statement.value):
                continue
        if isinstance(statement, ast.AnnAssign) and target(statement.target):
            if literal(statement.value):
                continue
        if isinstance(statement, ast.Return) and literal(statement.value):
            continue
        if isinstance(statement, ast.Pass):
            continue
        return False
    return True


def public_implementations(root: Path = ROOT) -> dict[str, dict[str, Any]]:
    """Derive required API ownership from the existing release exports themselves."""
    found: dict[str, dict[str, Any]] = {}
    for module_name in read_toml(root / "release.toml")["interfaces"]["python_modules"]:
        module = importlib.import_module(module_name)
        for name in module.__all__:
            exported = getattr(module, name)
            operations: list[tuple[str, Any, type[Any] | None]] = []
            if inspect.isfunction(exported):
                operations = [(name, exported, None)]
            elif inspect.isclass(exported):
                operations = [
                    (name + "." + method, operation, exported)
                    for method, operation in inspect.getmembers(exported, inspect.isfunction)
                    if not method.startswith("_") or method == "__init__"
                ]
            for public_name, operation, receiver in operations:
                symbol = operation.__module__ + ":" + operation.__qualname__
                path = symbol_path(symbol, root)
                found[module_name + ":" + public_name] = {
                    "symbol": symbol,
                    "source": path,
                    "growth_requirement": "linear",
                    "classification": "constant-source-body"
                    if _constant_setup(operation, receiver)
                    else "input-sized-operation",
                }
    return found


def declarations(root: Path = ROOT) -> dict[str, Any]:
    policy = read_toml(root / "release.toml")["engineering"]
    if policy != {"growth": "linear", "implementations": "all"}:
        raise ValueError("all implementations require linear growth")
    found: dict[str, Any] = {}
    for component in components(root):
        source = root / component["path"] / "src"
        for path in sorted(source.rglob("*.py")):
            if "build" in path.relative_to(source).parts:
                continue
            module = ".".join(path.relative_to(source).with_suffix("").parts)
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not any(
                    isinstance(d, ast.Call)
                    and isinstance(d.func, ast.Name)
                    and d.func.id == "bounds"
                    for d in node.decorator_list
                ):
                    continue
                parents = [
                    p.name for p in tree.body if isinstance(p, ast.ClassDef) and node in p.body
                ]
                qualified = ".".join([*parents, node.name])
                operation: Any = importlib.import_module(module)
                for part in qualified.split("."):
                    operation = getattr(operation, part)
                declaration = getattr(operation, "__growth_bounds__", None)
                if (
                    declaration is None
                    or declaration.id in found
                    or not declaration.proofs
                    or declaration.growth != policy["growth"]
                    or not declaration.linear_proofs
                    or declaration.qualification != "reference-model"
                ):
                    raise ValueError("duplicate or incomplete operation bounds declaration")
                symbol = module + ":" + qualified
                if (
                    root / symbol_path(symbol, root) != path
                    or Path(inspect.getfile(operation)) != path
                ):
                    raise ValueError("operation bounds do not resolve to their owner")
                sources = {str(path.relative_to(root)): fingerprint(path)}
                for reference in (*declaration.proofs, *declaration.linear_proofs):
                    test = test_path(reference, root)
                    sources[test] = fingerprint(root / test)
                found[declaration.id] = {
                    **asdict(declaration),
                    "proofs": list(
                        dict.fromkeys((*declaration.proofs, *declaration.linear_proofs))
                    ),
                    "symbol": symbol,
                    "sources": sources,
                }
    symbols = {item["symbol"] for item in found.values()}
    missing = [
        name
        for name, item in public_implementations(root).items()
        if item["classification"] != "constant-source-body" and item["symbol"] not in symbols
    ]
    if missing:
        raise ValueError("public implementation lacks linear bounds: " + ", ".join(missing))
    return found


def implementation_coverage(root: Path, owned: dict[str, Any]) -> dict[str, Any]:
    """Join existing API and operation ownership; this creates no new promises."""
    by_symbol = {value["symbol"]: identity for identity, value in owned.items()}
    exported = public_implementations(root)
    for row in exported.values():
        row["bounds"] = by_symbol.get(row["symbol"])
    operations = build_map(root)
    return {
        "public_python": exported,
        "operations": {
            row["id"]: {
                "status": row["status"],
                "growth_requirement": "linear",
                "implementation": row["implementation"],
                "growth_proofs": row["tests"]["growth"],
                "native_qualified": False,
            }
            for row in operations["operations"]
        },
        "scope": "Every exported input-sized Python implementation requires source-owned bounds; implemented public operations require their existing operation-owned growth proofs. Literal-only setup is proved from its source body. Unimplemented native operations remain unestablished and cannot be qualified by reference witnesses.",
    }


def migration_histories(root: Path = ROOT) -> list[dict[str, Any]]:
    histories = []
    for owner in read_toml(root / "state/inventory.toml")["owners"]:
        module = importlib.import_module(owner["migrations"])
        if module.__file__ is None:
            raise ValueError("state owner migrations require a source path")
        directory = Path(module.__file__).parent
        scripts = ScriptDirectory(str(directory))
        if (
            scripts.get_heads() != [owner["migration_head"]]
            or module.HEAD != owner["migration_head"]
        ):
            raise ValueError("state owner must have exactly one reviewed migration head")
        revisions = list(scripts.walk_revisions())
        if not revisions or revisions[-1].down_revision is not None:
            raise ValueError("missing migration baseline")
        histories.append(
            {
                "owner": owner["id"],
                "head": owner["migration_head"],
                "source": owner["migrations"],
                "qualification": owner["qualification"],
                "revisions": {
                    str(Path(v.path).relative_to(root)): fingerprint(Path(v.path))
                    for v in revisions
                },
                "proofs": [
                    "tests/test_migrations.py::test_preserved_v1_adoption_is_idempotent",
                    "tests/test_migrations.py::test_alembic_baseline_matches_preserved_schema_and_refuses_downgrade",
                    "tests/test_migrations.py::test_unknown_or_corrupted_schema_is_not_adopted",
                    "tests/test_migrations.py::test_store_open_rejects_unknown_alembic_revision_without_changing_state",
                    "tests/test_migrations.py::test_alembic_requires_a_real_sqlite_transaction_before_ddl",
                    "tests/test_migrations.py::test_migration_failure_and_process_death_roll_back_then_retry",
                ],
            }
        )
        for reference in histories[-1]["proofs"]:
            test_path(reference, root)
    return histories


def projection(root: Path = ROOT) -> dict[str, Any]:
    owned = declarations(root)
    return {
        "format": "fishhat-engineering-map/v1",
        "production_qualified": False,
        "operations": owned,
        "implementation_coverage": implementation_coverage(root, owned),
        "state_owners": migration_histories(root),
        "metrics": {"collection": "required", "thresholds": "none", "non_contractual": True},
    }


def proof_passed(reference: str, outcomes: dict[str, str]) -> bool:
    matches = [
        result
        for node, result in outcomes.items()
        if node == reference or node.startswith(reference + "[")
    ]
    return bool(matches) and all(result == "passed" for result in matches)


def report() -> dict[str, Any]:
    data = projection()
    source = source_identity()
    selected = current_run(ROOT, source)
    subjects = [("engineering:" + name, s) for name, s in data["operations"].items()]
    subjects.extend(("migration:" + s["owner"], s) for s in data["state_owners"])
    for identity, subject in subjects:
        subject["executed_proofs"] = {
            node: proof(node, identity, selected, purpose="implementation")
            for node in subject["proofs"]
        }
        subject["current_proofs_passed"] = all(
            p["passed"] for p in subject["executed_proofs"].values()
        )
    implemented_growth = []
    for identity, operation in data["implementation_coverage"]["operations"].items():
        operation["executed_growth_proofs"] = {
            node: proof(node, identity, selected, purpose="public-contract")
            for node in operation["growth_proofs"]
        }
        operation["current_growth_proofs_passed"] = bool(
            operation["implementation"]
            and operation["executed_growth_proofs"]
            and all(p["passed"] for p in operation["executed_growth_proofs"].values())
        )
        if operation["implementation"]:
            implemented_growth.append(operation["current_growth_proofs_passed"])
    data["all_current_proofs_passed"] = all(
        s["current_proofs_passed"] for _, s in subjects
    ) and all(implemented_growth)
    data["unimplemented_operations"] = [
        identity
        for identity, operation in data["implementation_coverage"]["operations"].items()
        if operation["implementation"] is None
    ]
    data["source"] = source
    data["selected_origin"] = selected["id"] if selected else None
    data["check_accounting"] = (
        summary(selected["tests"]["evidence"]["groups"]) if selected else None
    )
    data["scope"] = (
        "required linear work, extent, crash and migration assertions; evidence is scoped to the measured implementation and inputs; no native deployment or recovery"
    )
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", choices=["check", "generate", "report"], default="check", nargs="?"
    )
    parser.add_argument("--require-current-proofs", action="store_true")
    args = parser.parse_args()
    path = ROOT / MAP
    if args.command == "report":
        value = report()
        path = ROOT / "artifacts/engineering-qualification.json"
    else:
        value = projection()
    content = json.dumps(value, sort_keys=True, indent=2) + "\n"
    if args.command == "check":
        if path.read_text() != content:
            raise SystemExit(
                "engineering map is stale; review declarations and run make engineering args=generate"
            )
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    if args.require_current_proofs and not value.get("all_current_proofs_passed"):
        raise SystemExit("current complete unit receipts do not prove all engineering bindings")
    print(
        json.dumps(
            {
                "passed": True,
                "operations": len(value["operations"]),
                "state_owners": len(value["state_owners"]),
                "production_qualified": False,
                "scope": value.get("scope", "source declarations only; no execution proof"),
                "check_accounting": value.get("check_accounting"),
            }
        )
    )


if __name__ == "__main__":
    main()
