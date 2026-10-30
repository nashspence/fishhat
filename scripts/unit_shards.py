"""Duration-guided distribution and independently verified complete unit evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import math
import re
import statistics
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.check_evidence import (
    FORMAT as EVIDENCE_FORMAT,
)
from scripts.check_evidence import (
    conditions,
    entrypoints,
    execution_origin,
    fingerprint,
    inventory,
    valid_evidence,
)
from scripts.project_policy import ROOT
from scripts.run_stats import sharded_stats, valid_phases, valid_stats
from scripts.validation_timeouts import Deadline, current, invocation, valid_report

SHARDS = 2
WORKERS = 4
PLAN = Path("artifacts/unit-plan.json")
PLAN_FORMAT = "fishhat-unit-shards/v1"
ASSEMBLY_FORMAT = "fishhat-unit-assembly/v1"


def require(condition: Any, message: str) -> None:
    if not condition:
        raise ValueError(message)


def file_sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def xml_key(node: str) -> tuple[str, str]:
    path, *parts = node.split("::")
    return (".".join([path.removesuffix(".py").replace("/", "."), *parts[:-1]]), parts[-1])


def observations(
    nodes: list[str], reference: Path | None
) -> tuple[dict[str, float], dict[str, Any]]:
    measured: dict[tuple[str, str], float] = {}
    status: dict[str, Any] = {"status": "unavailable", "sha256": None}
    if reference and reference.is_file():
        try:
            for case in ET.parse(reference).iter("testcase"):
                key = (case.attrib["classname"], case.attrib["name"])
                value = float(case.attrib["time"])
                require(
                    key not in measured and math.isfinite(value) and value >= 0, "invalid reference"
                )
                measured[key] = value
            status = {"status": "available", "sha256": file_sha(reference)}
        except (OSError, ValueError, KeyError, ET.ParseError):
            measured = {}
            status = {"status": "unusable", "sha256": None}
    matches = [measured[xml_key(node)] for node in nodes if xml_key(node) in measured]
    fallback = max(0.001, statistics.median(matches)) if matches else 1.0
    weights = {node: max(0.001, measured.get(xml_key(node), fallback)) for node in nodes}
    return weights, {
        **status,
        "matched_nodes": len(matches),
        "unobserved_nodes": len(nodes) - len(matches),
    }


def partition(weights: dict[str, float]) -> list[list[str]]:
    slots: list[list[str]] = [[] for _ in range(SHARDS * WORKERS)]
    loads = [0.0] * len(slots)
    for node in sorted(weights, key=lambda name: (-weights[name], name)):
        slot = min(range(len(slots)), key=lambda index: (loads[index], index))
        slots[slot].append(node)
        loads[slot] += weights[node]
    return [
        sorted(node for slot in slots[i * WORKERS : (i + 1) * WORKERS] for node in slot)
        for i in range(SHARDS)
    ]


def execution_order(nodes: list[str], weights: dict[str, float]) -> list[str]:
    ordered = sorted(nodes, key=lambda node: (-weights[node], node))
    result: list[str] = []
    left, right = 0, len(ordered) - 1
    # The load scheduler initially buffers two cases per worker. Give each
    # expensive case a cheap companion instead of queuing the next expensive case.
    while left <= right:
        result.append(ordered[left])
        if left < right:
            result.append(ordered[right])
        left, right = left + 1, right - 1
    return result


def make_plan(nodes: list[str], root: Path, reference: Path | None) -> dict[str, Any]:
    from scripts.validation import SAFE_NODE, source_identity

    require(
        nodes and len(nodes) == len(set(nodes)) and all(SAFE_NODE.fullmatch(n) for n in nodes),
        "invalid complete collection",
    )
    require(
        set(nodes) == set(inventory(root)["pytest"]),
        "plan collection differs from reviewed inventory",
    )
    weights, observed = observations(sorted(nodes), reference)
    plan = {
        "format": PLAN_FORMAT,
        "source": source_identity(root),
        "profile": conditions(),
        "execution_origin": execution_origin(),
        "inventory_sha256": fingerprint(inventory(root)),
        "nodes": sorted(nodes),
        "weights_seconds": weights,
        "reference": observed,
        "shards": partition(weights),
        "workers_per_shard": WORKERS,
        "predictions_report_only": True,
    }
    return {**plan, "id": fingerprint(plan)}


def read_plan(path: Path, root: Path, *, context: bool = True) -> dict[str, Any]:
    from scripts.validation import source_identity

    require(
        path.resolve().is_relative_to(root.resolve()) and not path.is_symlink(),
        "plan outside checkout",
    )
    plan: dict[str, Any] = json.loads(path.read_text())
    require(
        plan["format"] == PLAN_FORMAT
        and plan["id"] == fingerprint({k: v for k, v in plan.items() if k != "id"}),
        "invalid plan identity",
    )
    nodes, weights = plan["nodes"], plan["weights_seconds"]
    require(
        isinstance(nodes, list)
        and nodes == sorted(set(nodes))
        and set(nodes) == set(inventory(root)["pytest"]),
        "incomplete plan collection",
    )
    require(
        set(weights) == set(nodes)
        and all(type(v) in {int, float} and math.isfinite(v) and v > 0 for v in weights.values()),
        "invalid scheduling weights",
    )
    require(
        plan["shards"] == partition(weights)
        and all(plan["shards"])
        and plan["workers_per_shard"] == WORKERS
        and plan["predictions_report_only"] is True,
        "invalid shard partition",
    )
    require(plan["inventory_sha256"] == fingerprint(inventory(root)), "stale reviewed inventory")
    require(plan["source"] == source_identity(root), "foreign plan source")
    if context:
        require(
            plan["profile"] == conditions() and plan["execution_origin"] == execution_origin(),
            "foreign plan conditions",
        )
    return plan


def shard_metadata(plan: dict[str, Any], index: int) -> dict[str, Any]:
    require(type(index) is int and 0 <= index < SHARDS, "invalid shard index")
    return {
        "plan_id": plan["id"],
        "index": index,
        "count": SHARDS,
        "complete_collection_sha256": fingerprint(plan["nodes"]),
    }


def command(index: int) -> list[str]:
    return [
        "python",
        "-m",
        "pytest",
        "-q",
        "tests",
        "-n",
        str(WORKERS),
        "--dist=load",
        "--maxschedchunk=1",
        "--max-worker-restart=0",
        "--durations=30",
        "--durations-min=0.25",
        "--junitxml=artifacts/unit-tests.xml",
        "--unit-shard-plan=" + PLAN.as_posix(),
        "--unit-shard-index=" + str(index),
    ]


def checked_cases(path: Path, nodes: list[str]) -> list[ET.Element]:
    expected = {xml_key(node) for node in nodes}
    tree = ET.parse(path)
    cases = list(tree.iter("testcase"))
    keys = [(case.attrib["classname"], case.attrib["name"]) for case in cases]
    require(
        len(keys) == len(set(keys)) and set(keys) == expected,
        "incomplete or duplicated JUnit cases",
    )
    require(
        not any(list(tree.iter(tag)) for tag in ("failure", "error", "skipped")),
        "unsuccessful JUnit cases",
    )
    require(
        all(
            math.isfinite(float(case.attrib["time"])) and float(case.attrib["time"]) >= 0
            for case in cases
        ),
        "invalid JUnit duration",
    )
    return cases


def check_constituents(
    plan: dict[str, Any], receipts: list[dict[str, Any]], root: Path, origin: dict[str, str]
) -> None:
    from scripts.validation import selection

    require(len(receipts) == SHARDS and plan["source"]["clean"], "missing shards or dirty source")
    require(plan["profile"] == conditions(), "aggregation conditions differ")
    expected_origin = plan["execution_origin"]
    if origin.get("kind") == "github-actions":
        require(
            origin["job"] == "tests"
            and expected_origin.get("job") == "unit-shards"
            and all(
                origin[key] == expected_origin.get(key) for key in ("kind", "run_id", "attempt")
            ),
            "mixed workflow attempts",
        )
    else:
        require(origin == expected_origin == {"kind": "local"}, "mixed execution origins")
    ids: set[str] = set()
    seen: set[str] = set()
    for index, receipt in enumerate(receipts):
        tests = receipt["tests"]
        require(
            re.fullmatch(r"[0-9a-f]{32}", receipt["id"]) and receipt["id"] not in ids,
            "duplicate or invalid receipt identity",
        )
        ids.add(receipt["id"])
        require(
            receipt["format"] == "fishhat-validation/v1"
            and receipt["target"] == "unit"
            and receipt["state"] == "completed"
            and receipt["exit_status"] == 0
            and receipt["full_check_passed"] is False,
            "unsuccessful shard receipt",
        )
        require(
            receipt["source_before"] == receipt["source_after"] == plan["source"]
            and receipt["profile"] == plan["profile"]
            and receipt["execution_origin"] == expected_origin,
            "foreign shard conditions",
        )
        require(
            receipt["selection"] == selection("unit", command(index)), "unexpected shard selection"
        )
        require(
            tests["shard"] == shard_metadata(plan, index) and tests["profile"] == plan["profile"],
            "mismatched shard identity",
        )
        require(
            valid_report(receipt["watchdogs"])
            and receipt["watchdogs"]["scale"]
            == tests["watchdogs"]["scale"]
            == plan["profile"]["watchdog_scale"],
            "invalid shard watchdog conditions",
        )
        require(
            tests["exit_status"] == 0
            and valid_evidence(tests, root)
            and valid_stats(tests["stats"])
            and valid_phases(tests["phases"]),
            "invalid required shard evidence",
        )
        require(tests["evidence"]["origin"] == receipt["id"], "foreign evidence origin")
        nodes = set(tests["outcomes"])
        require(
            nodes == set(plan["shards"][index]) and not seen & nodes,
            "missing or overlapping shard cases",
        )
        require(
            set(tests["outcomes"].values()) == {"passed"}
            and all(
                set(p) == {"setup", "call", "teardown"}
                and all(v["outcome"] == "passed" and not v["expected_failure"] for v in p.values())
                for p in tests["phases"].values()
            ),
            "failed, skipped or incomplete test phases",
        )
        require(
            all(
                not entry["expected_failure"] and entry["outcome"] == "passed"
                for entries in tests["subtests"].values()
                for entry in entries
            ),
            "unsuccessful subtests",
        )
        require(
            len(tests["worker_watchdogs"]) == WORKERS
            and len(tests["stats"]["processes"]) == WORKERS + 1,
            "missing worker evidence",
        )
        seen.update(nodes)
    require(seen == set(plan["nodes"]), "incomplete assembled collection")


def assembled_tests(
    plan: dict[str, Any], receipts: list[dict[str, Any]], origin: str
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        name: {} for name in ("outcomes", "phases", "fixtures", "subtests", "worker_watchdogs")
    }
    groups: dict[str, Any] = {}
    budgets = copy.deepcopy(receipts[0]["tests"]["watchdogs"])
    for index, receipt in enumerate(receipts):
        tests = receipt["tests"]
        for key in ("outcomes", "subtests"):
            fields[key].update(copy.deepcopy(tests[key]))
        for node, phases in tests["phases"].items():
            fields["phases"][node] = {
                name: {**value, "process": f"s{index}/" + value["process"]}
                for name, value in phases.items()
            }
        for worker, report in tests["worker_watchdogs"].items():
            fields["worker_watchdogs"][f"s{index}/{worker}"] = copy.deepcopy(report)
        for key in ("budgets_seconds", "unit_budgets"):
            budgets[key].update(tests["watchdogs"][key])
        groups.update(copy.deepcopy(tests["evidence"]["groups"]))
        for name, value in tests["fixtures"].items():
            require(
                type(value["count"]) is int
                and value["count"] >= 0
                and type(value["seconds"]) in {int, float}
                and math.isfinite(value["seconds"])
                and value["seconds"] >= 0,
                "invalid fixture statistics",
            )
            total = fields["fixtures"].setdefault(name, {"count": 0, "seconds": 0.0})
            total["count"] += value["count"]
            total["seconds"] += value["seconds"]
    return {
        **fields,
        "profile": plan["profile"],
        "watchdogs": budgets,
        "shard": None,
        "profiling_target": {
            "report_only": True,
            "status": "not-compared",
            "reason": "distributed-measurement-scope",
        },
        "collected_sha256": fingerprint(plan["nodes"]),
        "exit_status": 0,
        "stats": sharded_stats({str(i): r["tests"]["stats"] for i, r in enumerate(receipts)}),
        "evidence": {
            "format": EVIDENCE_FORMAT,
            "origin": origin,
            "inventory_sha256": plan["inventory_sha256"],
            "groups": groups,
        },
    }


def inside(root: Path, relative: str) -> Path:
    path = root / relative
    require(
        not Path(relative).is_absolute()
        and ".." not in Path(relative).parts
        and relative.startswith("artifacts/")
        and path.resolve().is_relative_to(root.resolve())
        and not path.is_symlink(),
        "evidence path outside artifact custody",
    )
    return path


def assembly_selection() -> dict[str, Any]:
    from scripts.validation import CANONICAL, selection

    return {
        **selection("unit", CANONICAL["unit"]),
        "invocation_sha256": fingerprint(["python", "-m", "scripts.unit_shards", "aggregate"]),
        "distribution": "verified-runner-shards",
    }


def valid_assembly(receipt: dict[str, Any], root: Path) -> bool:
    try:
        require(receipt["selection"] == assembly_selection(), "unexpected aggregation invocation")
        assembly = receipt["assembly"]
        require(
            assembly["format"] == ASSEMBLY_FORMAT
            and re.fullmatch(r"[0-9a-f]{64}", assembly["plan_id"]),
            "invalid assembly identity",
        )
        plan = read_plan(
            root / "artifacts/unit-plans" / (assembly["plan_id"] + ".json"), root, context=False
        )
        require(
            plan["id"] == assembly["plan_id"] and len(assembly["inputs"]) == SHARDS,
            "missing assembly inputs",
        )
        raw = []
        for index, entry in enumerate(assembly["inputs"]):
            require(
                re.fullmatch(r"[0-9a-f]{32}", entry["receipt_id"]), "invalid constituent identity"
            )
            path = root / "artifacts/validation" / (entry["receipt_id"] + ".json")
            require(
                not path.is_symlink() and file_sha(path) == entry["receipt_sha256"],
                "altered constituent receipt",
            )
            value = json.loads(path.read_text())
            require(value["id"] == entry["receipt_id"], "foreign constituent identity")
            xml = inside(root, entry["xml_path"])
            require(file_sha(xml) == entry["xml_sha256"], "altered constituent XML")
            checked_cases(xml, plan["shards"][index])
            raw.append(value)
        require(
            receipt["source_before"] == receipt["source_after"] == plan["source"]
            and receipt["profile"] == plan["profile"],
            "foreign assembly source",
        )
        check_constituents(plan, raw, root, receipt["execution_origin"])
        require(
            receipt["tests"] == assembled_tests(plan, raw, receipt["id"]),
            "altered assembled evidence",
        )
        return True
    except (OSError, ValueError, KeyError, TypeError, IndexError, ET.ParseError):
        return False


@invocation
def aggregate(root: Path = ROOT) -> int:
    from scripts.validation import (
        FORMAT,
        full_check_passed,
        source_identity,
        write_receipt,
    )
    from scripts.validation_pytest import write_stats

    started = time.monotonic()
    source = source_identity(root)
    receipt: dict[str, Any] = {
        "format": FORMAT,
        "scope": "repository-validation",
        "id": uuid.uuid4().hex,
        "target": "unit",
        "source_before": source,
        "source_after": None,
        "selection": assembly_selection(),
        "check_purpose": entrypoints(root).get(".github/workflows/ci.yml:tests")
        or entrypoints(root).get("make:unit"),
        "profile": conditions(),
        "execution_origin": execution_origin(),
        "started_at": datetime.now(UTC).isoformat(),
        "duration_seconds": None,
        "duration_scope": "aggregation-process",
        "state": "running",
        "exit_status": None,
        "tests": None,
        "full_check_passed": False,
        "production_qualified": False,
        "assembly": None,
        "watchdogs": current().report(),
    }
    directory = root / "artifacts/validation"
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / (receipt["id"] + ".json")
    write_receipt(destination, receipt)
    try:
        inputs = root / "artifacts/unit-shards"
        folders = sorted(path for path in inputs.iterdir() if path.is_dir())
        require(len(folders) == SHARDS, "missing shard artifacts")
        plan = read_plan(folders[0] / "unit-plan.json", root, context=False)
        origins = plan["execution_origin"]
        attempt = origins.get("attempt", "local")
        python = ".".join(plan["profile"]["python"].split(".")[:2])
        raw, entries, cases = [], [], []
        plan_bytes = (folders[0] / "unit-plan.json").read_bytes()
        for index, folder in enumerate(folders):
            require(
                folder.name == f"unit-shard-{python}-{index}-{attempt}", "foreign shard artifact"
            )
            require((folder / "unit-plan.json").read_bytes() == plan_bytes, "different shard plans")
            paths = list((folder / "validation").glob("*.json"))
            require(
                len(paths) == 1 and not paths[0].is_symlink(), "missing or repeated shard receipts"
            )
            value = json.loads(paths[0].read_text())
            require(
                re.fullmatch(r"[0-9a-f]{32}", value["id"])
                and paths[0].name == value["id"] + ".json",
                "invalid raw receipt name",
            )
            target = directory / paths[0].name
            require(
                not target.exists() or target.read_bytes() == paths[0].read_bytes(),
                "receipt custody collision",
            )
            target.write_bytes(paths[0].read_bytes())
            xml = folder / "unit-tests.xml"
            cases.extend(checked_cases(xml, plan["shards"][index]))
            entries.append(
                {
                    "receipt_id": value["id"],
                    "receipt_sha256": file_sha(target),
                    "xml_path": xml.relative_to(root).as_posix(),
                    "xml_sha256": file_sha(xml),
                }
            )
            raw.append(value)
        check_constituents(plan, raw, root, receipt["execution_origin"])
        plan_path = root / "artifacts/unit-plans" / (plan["id"] + ".json")
        plan_path.parent.mkdir(parents=True, exist_ok=True)
        require(
            not plan_path.exists() or plan_path.read_bytes() == plan_bytes, "plan custody collision"
        )
        plan_path.write_bytes(plan_bytes)
        receipt["assembly"] = {"format": ASSEMBLY_FORMAT, "plan_id": plan["id"], "inputs": entries}
        receipt["tests"] = assembled_tests(plan, raw, receipt["id"])
        combined = ET.Element("testsuites")
        suite = ET.SubElement(
            combined,
            "testsuite",
            {
                "name": "fishhat",
                "tests": str(len(cases)),
                "time": str(receipt["tests"]["stats"]["elapsed_seconds"]),
            },
        )
        suite.extend(cases)
        ET.ElementTree(combined).write(root / "artifacts/unit-tests.xml", encoding="unicode")
        write_stats(
            root,
            {
                "format": "fishhat-assembled-pytest-timing/v1",
                "qualification_eligible": False,
                **receipt["tests"],
            },
        )
        receipt["exit_status"] = 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, ET.ParseError) as error:
        receipt["exit_status"] = 2
        receipt["failure_kind"] = type(error).__name__
        print("Unit shard assembly failed: " + str(error), file=sys.stderr)
    receipt.update(
        state="completed",
        source_after=source_identity(root),
        duration_seconds=time.monotonic() - started,
        watchdogs=current().report(),
    )
    receipt["full_check_passed"] = full_check_passed(receipt, root)
    if receipt["exit_status"] == 0 and not receipt["full_check_passed"]:
        receipt["exit_status"] = 2
    write_receipt(destination, receipt)
    print(
        json.dumps(
            {
                "receipt": destination.relative_to(root).as_posix(),
                "exit_status": receipt["exit_status"],
                "full_check_passed": receipt["full_check_passed"],
            }
        )
    )
    return int(receipt["exit_status"])


def reference(repository: str, destination: Path) -> None:
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "invalid repository")
    destination.mkdir(parents=True, exist_ok=False)
    report: dict[str, Any] = {"advisory_only": True, "status": "unavailable", "files": {}}

    deadline = Deadline.after(30)

    def api(endpoint: str) -> bytes:
        require(deadline.remaining() > 0, "advisory reference observation exhausted")
        return subprocess.run(
            ["gh", "api", endpoint], capture_output=True, check=True, timeout=deadline.remaining()
        ).stdout

    try:
        runs = json.loads(
            api(
                f"repos/{repository}/actions/workflows/ci.yml/runs?branch=main&event=push&status=success&per_page=1"
            )
        )["workflow_runs"]
        if runs:
            run = runs[0]
            report.update(source_run=run["id"], source_commit=run["head_sha"])
            artifacts = []
            page = 1
            while True:
                values = json.loads(
                    api(
                        f"repos/{repository}/actions/runs/{run['id']}/artifacts?per_page=100&page={page}"
                    )
                )["artifacts"]
                artifacts.extend(values)
                if len(values) < 100:
                    break
                page += 1
            for python in ("3.11", "3.12", "3.13"):
                matches = [
                    v
                    for v in artifacts
                    if v["name"] == "unit-results-" + python and not v["expired"]
                ]
                if matches:
                    artifact = max(matches, key=lambda value: value["id"])
                    data = api(f"repos/{repository}/actions/artifacts/{artifact['id']}/zip")
                    require(
                        "sha256:" + hashlib.sha256(data).hexdigest() == artifact["digest"],
                        "reference digest mismatch",
                    )
                    with zipfile.ZipFile(io.BytesIO(data)) as archive:
                        xml = archive.read("unit-tests.xml")
                    ET.fromstring(xml)
                    path = destination / (python + ".xml")
                    path.write_bytes(xml)
                    report["files"][python] = file_sha(path)
            report["status"] = "available" if report["files"] else "unavailable"
    except (
        OSError,
        ValueError,
        KeyError,
        subprocess.SubprocessError,
        zipfile.BadZipFile,
        ET.ParseError,
    ):
        report["status"] = "partially-available" if report["files"] else "unavailable"
    (destination / "reference.json").write_text(json.dumps(report, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


@invocation
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    ref = sub.add_parser("reference")
    ref.add_argument("--repository", required=True)
    ref.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("run")
    run.add_argument("--index", type=int, required=True)
    sub.add_parser("aggregate")
    args = parser.parse_args()
    if args.command == "reference":
        reference(args.repository, args.output)
    elif args.command == "run":
        from scripts.validation import run as validate

        plan = read_plan(ROOT / PLAN, ROOT)
        shard_metadata(plan, args.index)
        raise SystemExit(validate("unit", command(args.index)))
    else:
        raise SystemExit(aggregate())


if __name__ == "__main__":
    main()
