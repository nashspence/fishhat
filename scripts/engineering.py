"""Discover operation-owned engineering proofs and immutable migration histories."""

from __future__ import annotations

import argparse
import ast
import importlib
import inspect
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from alembic.script import ScriptDirectory

from scripts.check_evidence import current_run, proof, summary
from scripts.operation_qualification import symbol_path, test_path
from scripts.project_policy import ROOT, components, fingerprint, read_toml
from scripts.validation import source_identity

MAP = "policy/engineering.json"


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
                declaration = operation.__growth_bounds__
                if (
                    declaration.id in found
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
    return found


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
    return {
        "format": "fishhat-engineering-map/v1",
        "production_qualified": False,
        "operations": declarations(root),
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
    data["all_current_proofs_passed"] = all(s["current_proofs_passed"] for _, s in subjects)
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
