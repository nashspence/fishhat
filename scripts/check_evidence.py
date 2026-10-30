"""Reviewed check accounting; contracts and their existing owners retain authority."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import platform
import re
import sys
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

import yaml
from fishhat_contracts import canonical

ROOT = Path(__file__).resolve().parents[1]

SNAPSHOT = "policy/checks.json"
FORMAT = "fishhat-check-evidence/v1"
PURPOSES = {"public-contract", "implementation", "repository-policy", "validation-tooling"}
RELATIONSHIPS = {"scoped-witness", "candidate", "no-product-claim"}
ACTIVE: ContextVar[set[str] | None] = ContextVar("evidence_groups", default=None)


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def conditions() -> dict[str, Any]:
    from scripts.validation_timeouts import execution_conditions

    return {
        **execution_conditions(),
        "platform": sys.platform,
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def execution_origin() -> dict[str, str]:
    names = {"run_id": "GITHUB_RUN_ID", "attempt": "GITHUB_RUN_ATTEMPT", "job": "GITHUB_JOB"}
    origin = {key: os.environ.get(name, "") for key, name in names.items()}
    if not (
        origin["run_id"].isdigit()
        and origin["attempt"].isdigit()
        and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", origin["job"])
    ):
        return {"kind": "local"}
    return {"kind": "github-actions", **origin}


@contextmanager
def evidence_group(name: str) -> Iterator[None]:
    """Attribute a coherent group in a mixed check only after its assertions return."""
    observed = ACTIVE.get()
    if observed is None or name in observed:
        raise ValueError("evidence group outside a check or executed more than once")
    yield
    observed.add(name)


def authority_exists(reference: str, root: Path) -> bool:
    name, _, selector = reference.partition("#")
    path = root / name
    if not name or not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        return False
    if selector.startswith("/"):
        import tomllib

        value = (
            json.loads(path.read_text())
            if path.suffix == ".json"
            else tomllib.loads(path.read_text())
        )
        try:
            for part in selector[1:].split("/"):
                key = part.replace("~1", "/").replace("~0", "~")
                value = value[int(key)] if isinstance(value, list) else value[key]
        except (KeyError, IndexError, TypeError, ValueError):
            return False
    elif selector:
        nodes = ast.parse(path.read_text()).body
        for name in selector.split("."):
            matches = [
                n
                for n in nodes
                if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name == name
            ]
            if len(matches) != 1:
                return False
            nodes = matches[0].body
    return True


def validate_groups(groups: Any, root: Path) -> None:
    if not isinstance(groups, dict) or not groups:
        raise ValueError("check needs reviewed assertion groups")
    for name, group in groups.items():
        if (
            not re.fullmatch(r"[a-z][a-z0-9-]*", name)
            or set(group) != {"purpose", "authority", "scope", "relationship", "reason", "claims"}
            or group["purpose"] not in PURPOSES
            or group["relationship"] not in RELATIONSHIPS
            or not group["scope"]
            or not group["reason"]
            or not isinstance(group["claims"], list)
            or len(group["claims"]) != len(set(group["claims"]))
            or not group["authority"]
            or not all(authority_exists(ref, root) for ref in group["authority"])
            or (group["claims"] and group["relationship"] != "scoped-witness")
            or (group["claims"] and group["purpose"] not in {"public-contract", "implementation"})
        ):
            raise ValueError("unsupported check purpose, authority or relationship")


def item_groups(item: Any, root: Path) -> dict[str, Any]:
    qualified = item.nodeid.split("::", 1)[1].split("[", 1)[0]
    declarations = getattr(item.module, "CHECK_OVERRIDES", {})
    default = getattr(item.module, "CHECK_CLASS_PURPOSE", {}).get(
        qualified.split("::")[0], getattr(item.module, "CHECK_PURPOSE", None)
    )
    group = declarations.get(qualified, default)
    if group is None:
        raise ValueError("unclassified check: " + item.nodeid)
    groups = group if "purpose" not in group else {"check": group}
    validate_groups(groups, root)
    return groups


def validate_overrides(items: list[Any]) -> None:
    modules: dict[Any, set[str]] = {}
    for item in items:
        modules.setdefault(item.module, set()).add(item.nodeid.split("::", 1)[1].split("[", 1)[0])
    for module, names in modules.items():
        if set(getattr(module, "CHECK_OVERRIDES", {})) - names or set(
            getattr(module, "CHECK_CLASS_PURPOSE", {})
        ) - {name.split("::")[0] for name in names}:
            raise ValueError("stale or unsupported source-local check override")


def entrypoints(root: Path) -> dict[str, Any]:
    """Inspect maintained entrypoints in place; no copied command or gate registry."""
    found: dict[str, Any] = {}
    pending: str | None = None
    recipes: dict[str, list[str]] = {}
    target = ""
    for line in (root / "Makefile").read_text().splitlines():
        if line.startswith("# check-purpose: "):
            pending = line.removeprefix("# check-purpose: ")
        elif re.match(r"^[A-Za-z0-9_.%/-]+(?: +[A-Za-z0-9_.%/-]+)*:(?!=)", line):
            name = line.split(":", 1)[0]
            if name == ".PHONY":
                continue
            if " " in name:
                raise ValueError("unsupported grouped Make entrypoint")
            if pending not in PURPOSES:
                raise ValueError("unclassified Make entrypoint: " + name)
            found["make:" + name] = {
                "purposes": [pending],
                "scope": "repository-local",
                "authority": "Makefile",
            }
            target = "make:" + name
            recipes[target] = [line]
            pending = None
        elif line.startswith("\t") and target:
            recipes[target].append(line)
    for name, recipe in recipes.items():
        found[name]["work_sha256"] = fingerprint(recipe)
    for path in sorted(
        [*(root / ".github/workflows").glob("*.yml"), *(root / ".github/workflows").glob("*.yaml")]
    ):
        workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        for name, job in workflow["jobs"].items():
            env = job.get("env", {})
            purposes = env.get("CHECK_PURPOSES", "").split(",")
            authority = env.get("CHECK_AUTHORITY", "")
            scope = env.get("CHECK_SCOPE", "")
            if not set(purposes) <= PURPOSES or not scope or not authority_exists(authority, root):
                raise ValueError("unclassified workflow job: " + path.name + ":" + name)
            found[path.relative_to(root).as_posix() + ":" + name] = {
                "purposes": purposes,
                "scope": scope,
                "authority": authority,
                "work_sha256": fingerprint(
                    {**job, "env": {k: v for k, v in env.items() if not k.startswith("CHECK_")}}
                ),
                "result_authority": "GitHub job conclusion; classification supplies no execution proof",
                "requiredness_authority": "release.toml#/governance/required_checks",
            }
    return found


def inventory(root: Path = ROOT) -> dict[str, Any]:
    value: dict[str, Any] = json.loads((root / SNAPSHOT).read_text())
    if value.get("format") != FORMAT or value["entrypoints"] != entrypoints(root):
        raise ValueError("check inventory is stale; review collection and entrypoints")
    rows = value["pytest"]
    if not isinstance(rows, list) or any(set(row) != {"node", "purpose_sha256"} for row in rows):
        raise ValueError("unsupported check inventory rows")
    value["pytest"] = {row["node"]: row["purpose_sha256"] for row in rows}
    if len(value["pytest"]) != len(rows):
        raise ValueError("duplicate check inventory rows")
    return value


def encode_inventory(value: dict[str, Any]) -> dict[str, Any]:
    # Explicit digest labels distinguish review fingerprints from credential-looking node names.
    return {
        **value,
        "pytest": [
            {"node": node, "purpose_sha256": digest}
            for node, digest in sorted(value["pytest"].items())
        ],
    }


def reconcile(
    collected: dict[str, Any], root: Path, *, complete: bool, generate: bool = False
) -> str:
    if not collected:
        raise ValueError("check collection is empty")
    for groups in collected.values():
        validate_groups(groups, root)
    if complete and (root / "policy/components.toml").exists():
        reconcile_relationships(collected, root)
    current = {
        "format": FORMAT,
        "pytest": {node: fingerprint(groups) for node, groups in sorted(collected.items())},
        "entrypoints": entrypoints(root),
    }
    if generate:
        if not complete:
            raise ValueError("reviewed inventory generation requires complete collection")
        (root / SNAPSHOT).write_text(
            json.dumps(encode_inventory(current), indent=2, sort_keys=True) + "\n"
        )
    else:
        expected = inventory(root)
        if (complete and set(collected) != set(expected["pytest"])) or any(
            expected["pytest"].get(node) != fingerprint(groups)
            for node, groups in collected.items()
        ):
            raise ValueError(
                "unreviewed, missing or stale collected checks; review and regenerate check inventory"
            )
    return fingerprint(current if generate else inventory(root))


def reconcile_relationships(collected: dict[str, Any], root: Path) -> None:
    from scripts.engineering import projection
    from scripts.operation_qualification import build_map, symbol_path

    expected: dict[str, list[str]] = {}
    authorities: dict[str, str] = {}
    coverage = build_map(root)
    expected["interface:public-snapshot"] = coverage["interfaces"]["tests"]
    authorities["interface:public-snapshot"] = coverage["interfaces"]["expectation"]
    for row in coverage["operations"]:
        if row["implementation"]:
            expected[row["id"]] = [ref for refs in row["tests"].values() for ref in refs]
            authorities[row["id"]] = "policy/interfaces.json#/cli"
    engineering = projection(root)
    expected.update(
        {
            "engineering:" + name: value["proofs"]
            for name, value in engineering["operations"].items()
        }
    )
    authorities.update(
        {
            "engineering:" + name: symbol_path(value["symbol"], root)
            + "#"
            + value["symbol"].split(":")[1]
            for name, value in engineering["operations"].items()
        }
    )
    authorities.update(
        {
            "migration:" + value["owner"]: "state/inventory.toml"
            for value in engineering["state_owners"]
        }
    )
    expected.update(
        {"migration:" + value["owner"]: value["proofs"] for value in engineering["state_owners"]}
    )
    for node, groups in collected.items():
        for group in groups.values():
            for claim in group["claims"]:
                if claim not in expected or not any(
                    node == ref or node.startswith(ref + "[") for ref in expected[claim]
                ):
                    raise ValueError("unbound or unrelated claim assertion: " + node)
                if authorities[claim] not in group["authority"]:
                    raise ValueError("unrelated expectation authority: " + node)
    for claim, references in expected.items():
        for reference in references:
            cases = [
                groups
                for node, groups in collected.items()
                if node == reference or node.startswith(reference + "[")
            ]
            purpose = (
                "public-contract"
                if claim.startswith(("cli:", "client:", "interface:"))
                else "implementation"
            )
            if not cases or not all(
                any(claim in g["claims"] and g["purpose"] == purpose for g in groups.values())
                for groups in cases
            ):
                raise ValueError("missing scoped assertion group for binding: " + claim)


def group_results(
    declarations: dict[str, Any],
    phases: dict[str, Any],
    observed: dict[str, set[str]],
    outcomes: dict[str, str],
) -> dict[str, Any]:
    result = {}
    for node, groups in declarations.items():
        actual = phases.get(node, {})
        passed = (
            outcomes.get(node) == "passed"
            and set(actual) == {"setup", "call", "teardown"}
            and all(
                phase["outcome"] == "passed" and not phase["expected_failure"]
                for phase in actual.values()
            )
        )
        result[node] = {
            name: {
                **group,
                "outcome": group_outcome(
                    actual,
                    outcomes.get(node),
                    passed and (len(groups) == 1 or name in observed.get(node, set())),
                ),
            }
            for name, group in groups.items()
        }
    return result


def group_outcome(phases: dict[str, Any], outcome: str | None, passed: bool) -> str:
    if any(p["expected_failure"] for p in phases.values()):
        return "expected-failure"
    if "call" not in phases:
        return "not-executed"
    if outcome in {"failed", "skipped"}:
        return outcome
    return "passed" if passed else "not-executed"


def valid_evidence(tests: dict[str, Any], root: Path) -> bool:
    """Integrity is distinct from successful execution or sufficiency for a claim."""
    try:
        from scripts.validation_timeouts import valid_report

        report = tests.get("watchdogs")
        if (
            not isinstance(report, dict)
            or not valid_report(report)
            or report["scale"] != tests.get("profile", {}).get("watchdog_scale")
        ):
            return False
        if any(
            not valid_report(worker) or worker["scale"] != report["scale"]
            for worker in tests.get("worker_watchdogs", {}).values()
        ):
            return False
        value = tests["evidence"]
        expected = inventory(root)
        groups = value["groups"]
        nodes = set(tests["outcomes"])
        if (
            value["format"] != FORMAT
            or value["inventory_sha256"] != fingerprint(expected)
            or set(groups) != nodes
            or not nodes <= set(expected["pytest"])
            or tests["collected_sha256"] != fingerprint(sorted(nodes))
        ):
            return False
        for node, actual in groups.items():
            if (
                fingerprint(
                    {
                        name: {k: v for k, v in g.items() if k != "outcome"}
                        for name, g in actual.items()
                    }
                )
                != expected["pytest"][node]
            ):
                return False
            for group in actual.values():
                if group["outcome"] not in {
                    "passed",
                    "failed",
                    "skipped",
                    "expected-failure",
                    "not-executed",
                }:
                    return False
                if group["outcome"] == "passed" and (
                    tests["outcomes"][node] != "passed"
                    or set(tests["phases"][node]) != {"setup", "call", "teardown"}
                    or any(
                        p["outcome"] != "passed" or p["expected_failure"]
                        for p in tests["phases"][node].values()
                    )
                ):
                    return False
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def current_run(root: Path, source: dict[str, Any]) -> dict[str, Any] | None:
    """Select the latest exact-source canonical run, retaining failures and missing cases."""
    from scripts.validation import CANONICAL, digest, full_check_passed
    from scripts.validation import FORMAT as RECEIPT_FORMAT

    runs: list[dict[str, Any]] = []
    for path in (root / "artifacts/validation").glob("*.json"):
        if path.is_symlink():
            continue
        try:
            value = json.loads(path.read_text())
            if (
                value["format"] == RECEIPT_FORMAT
                and value["id"] + ".json" == path.name
                and value["target"] == "unit"
                and value["source_before"] == source
                and source["clean"]
                and value["selection"]["canonical"]
            ):
                runs.append(value)
        except (OSError, ValueError, KeyError, TypeError):
            continue
    if not runs:
        return None
    selected = max(runs, key=lambda r: (r["started_at"], r["id"]))
    tests = selected.get("tests")
    if (
        not full_check_passed(selected, root)
        or selected["selection"].get("work_sha256") != digest(CANONICAL["unit"])
        or selected["selection"].get("environment_overrides") != []
        or selected.get("profile") != conditions()
        or not tests
        or not valid_evidence(tests, root)
        or tests["evidence"]["origin"] != selected["id"]
        or tests.get("profile") != selected["profile"]
        or set(tests["outcomes"]) != set(inventory(root)["pytest"])
    ):
        return None
    return selected


def proof(
    reference: str, claim: str, run: dict[str, Any] | None, *, purpose: str
) -> dict[str, Any]:
    if run is None:
        return {"passed": False, "origin": None, "cases": {}, "claim": claim}
    tests = run["tests"]
    cases = {}
    for node, groups in tests["evidence"]["groups"].items():
        if node == reference or node.startswith(reference + "["):
            cases[node] = {
                name: g
                for name, g in groups.items()
                if claim in g["claims"]
                and g["purpose"] == purpose
                and g["relationship"] == "scoped-witness"
            }
    return {
        "passed": bool(cases)
        and all(
            groups and all(g["outcome"] == "passed" for g in groups.values())
            for groups in cases.values()
        ),
        "origin": run["id"],
        "cases": cases,
        "claim": claim,
    }


def summary(groups: dict[str, Any]) -> dict[str, Any]:
    return {
        "selected_checks": len(groups),
        "assertion_groups": sum(map(len, groups.values())),
        "executed_groups": sum(
            g["outcome"] in {"passed", "failed", "expected-failure"}
            for gs in groups.values()
            for g in gs.values()
        ),
        "passed_groups": sum(
            g["outcome"] == "passed" for gs in groups.values() for g in gs.values()
        ),
        "purposes": dict(Counter(g["purpose"] for gs in groups.values() for g in gs.values())),
        "candidate_associations": sum(
            len(g["claims"]) for gs in groups.values() for g in gs.values()
        ),
        "relationships": dict(
            Counter(g["relationship"] for gs in groups.values() for g in gs.values())
        ),
        "unestablished_public_groups": sum(
            g["purpose"] == "public-contract"
            and (g["relationship"] != "scoped-witness" or g["outcome"] != "passed")
            for gs in groups.values()
            for g in gs.values()
        ),
        "production_qualified": False,
    }
