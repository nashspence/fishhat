"""Mandatory observational pytest instrumentation, aligned with Riverhog's timing lane."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import sys
import time
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from filelock import FileLock

from scripts.check_evidence import (
    ACTIVE,
    group_results,
    item_groups,
    reconcile,
    summary,
    validate_overrides,
)
from scripts.check_evidence import (
    FORMAT as EVIDENCE_FORMAT,
)
from scripts.run_stats import RunStats, comparison, parallel_stats

REPORT_VARIABLE = "FISHHAT_TEST_REPORT"
SAFE_NODE = re.compile(r"tests/[A-Za-z0-9_./-]+\.py(?:::[A-Za-z0-9_]+)+(?:\[[A-Za-z0-9_.-]+\])?")


def safe_node(node: str) -> str:
    return (
        node
        if SAFE_NODE.fullmatch(node)
        else "redacted:" + hashlib.sha256(node.encode()).hexdigest()
    )


def write_stats(root: Path, value: dict[str, Any]) -> Path:
    directory = root / "artifacts/test-stats"
    if not directory.resolve().is_relative_to(root.resolve()):
        raise ValueError("test stats must stay inside the checkout")
    directory.mkdir(parents=True, exist_ok=True)
    content = json.dumps(value, sort_keys=True) + "\n"
    path = directory / (uuid.uuid4().hex + ".json")
    with FileLock(str(directory / ".lock"), timeout=10):
        # The receipt corpus is not a bounded work page. Retain all completed
        # observations until an explicit owner-managed retention operation; full
        # collection growth must never silently erase prior evidence.
        temporary = path.with_suffix(".tmp")
        temporary.write_text(content, encoding="utf-8", newline="\n")
        temporary.chmod(0o600)
        temporary.replace(path)
    return path


class TestResults:
    def __init__(
        self,
        root: Path,
        destination: Path | None,
        *,
        controller: bool = False,
        process_name: str = "controller",
    ) -> None:
        self.root, self.destination = root, destination
        self.stats = RunStats()
        self.controller = controller
        self.process_name = process_name
        self.expected_workers: set[str] = set()
        self.workers: dict[str, Any] = {}
        self.worker_error = False
        self.collected: list[str] = []
        self.outcomes: dict[str, str] = {}
        self.phases: dict[str, dict[str, Any]] = {}
        self.fixtures: dict[str, dict[str, int | float]] = {}
        self.output: Path | None = None
        self.target: dict[str, Any] = {}
        self.declarations: dict[str, Any] = {}
        self.observed: dict[str, set[str]] = {}
        self.inventory_hash = ""
        self.evidence: dict[str, Any] = {}
        self.subtests: dict[str, list[dict[str, Any]]] = {}

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        self.collected = [safe_node(item.nodeid) for item in session.items]
        try:
            if len(set(self.collected)) != len(self.collected):
                raise ValueError("duplicate collected checks")
            self.declarations = {
                safe_node(i.nodeid): item_groups(i, self.root) for i in session.items
            }
            complete = list(session.config.args) == ["tests"] and not (
                session.config.option.keyword
                or session.config.option.markexpr
                or session.config.option.deselect
                or session.config.option.lf
            )
            generate = session.config.getoption("evidence_generate")
            if complete:
                validate_overrides(session.items)
            if generate and not session.config.option.collectonly:
                raise ValueError("inventory generation requires --collect-only")
            self.inventory_hash = reconcile(
                self.declarations, self.root, complete=complete, generate=generate
            )
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise pytest.UsageError(str(error)) from error

    @pytest.hookimpl(optionalhook=True)
    def pytest_configure_node(self, node: Any) -> None:
        self.expected_workers.add(node.gateway.id)

    @pytest.hookimpl(optionalhook=True)
    def pytest_xdist_node_collection_finished(self, node: Any, ids: list[str]) -> None:
        collected = [safe_node(nodeid) for nodeid in ids]
        if self.collected and self.collected != collected:
            self.worker_error = True
        self.collected = collected

    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodedown(self, node: Any, error: Any) -> None:
        value = getattr(node, "workeroutput", {}).get("fishhat_results")
        name = node.gateway.id
        if error or name in self.workers or not isinstance(value, dict):
            self.worker_error = True
        else:
            self.workers[name] = value

    def merge_workers(self, stats: dict[str, Any], exitstatus: int) -> dict[str, Any]:
        if self.worker_error or set(self.workers) != self.expected_workers or not self.workers:
            raise ValueError("missing or failed worker evidence")
        groups: dict[str, Any] = {}
        seen: set[str] = set()
        processes = {"controller": stats}
        for name, value in self.workers.items():
            evidence = value["evidence"]
            if (
                value["collected"] != self.collected
                or evidence["origin"] != os.environ.get("FISHHAT_TEST_ORIGIN")
                or (self.inventory_hash and self.inventory_hash != evidence["inventory_sha256"])
                or (exitstatus == 0 and value["exit_status"] != 0)
            ):
                raise ValueError("inconsistent worker evidence")
            self.inventory_hash = evidence["inventory_sha256"]
            processes[name] = value["stats"]
            executed = {node for node, phases in value["phases"].items() if phases}
            if seen & executed or not executed <= set(self.collected):
                raise ValueError("duplicate or unexpected worker execution")
            seen.update(executed)
            for node in executed:
                self.outcomes[node] = value["outcomes"][node]
                self.phases[node] = value["phases"][node]
                groups[node] = evidence["groups"][node]
                if node in value["subtests"]:
                    self.subtests[node] = value["subtests"][node]
            for node in set(self.collected) - seen:
                groups[node] = evidence["groups"][node]
            for fixture, timing in value["fixtures"].items():
                entry = self.fixtures.setdefault(fixture, {"count": 0, "seconds": 0.0})
                for key in ("count", "seconds"):
                    entry[key] += timing[key]
        if exitstatus == 0 and seen != set(self.collected):
            raise ValueError("incomplete worker execution")
        self.evidence = {
            "format": EVIDENCE_FORMAT,
            "origin": os.environ.get("FISHHAT_TEST_ORIGIN"),
            "inventory_sha256": self.inventory_hash,
            "groups": groups,
        }
        return parallel_stats(processes)

    @pytest.hookimpl(wrapper=True)
    def pytest_runtest_call(self, item: pytest.Item) -> Generator[None, Any, Any]:
        observed: set[str] = set()
        token = ACTIVE.set(observed)
        try:
            return (yield)
        finally:
            ACTIVE.reset(token)
            self.observed[safe_node(item.nodeid)] = observed

    @pytest.hookimpl(wrapper=True)
    def pytest_fixture_setup(
        self, fixturedef: pytest.FixtureDef[Any], request: pytest.FixtureRequest
    ) -> Generator[None, Any, Any]:
        started = time.perf_counter()
        try:
            return (yield)
        finally:
            entry = self.fixtures.setdefault(fixturedef.argname, {"count": 0, "seconds": 0.0})
            entry["count"] += 1
            entry["seconds"] += time.perf_counter() - started

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if self.controller:
            return
        node = safe_node(report.nodeid)
        if hasattr(report, "context"):
            self.subtests.setdefault(node, []).append(
                {
                    "case_sha256": hashlib.sha256(repr(report.context).encode()).hexdigest(),
                    "outcome": report.outcome,
                    "expected_failure": hasattr(report, "wasxfail"),
                }
            )
        self.phases.setdefault(node, {})[report.when] = {
            "seconds": report.duration,
            "process": self.process_name,
            "outcome": report.outcome,
            "rss_sample_bytes": self.stats.sample(),
            "rss_scope": "process-snapshot-not-test-allocation",
            "expected_failure": hasattr(report, "wasxfail"),
        }
        previous = self.outcomes.get(node)
        if report.failed:
            self.outcomes[node] = "failed"
        elif previous != "failed" and report.skipped:
            self.outcomes[node] = "skipped"
        elif previous not in {"failed", "skipped"} and report.when == "call":
            self.outcomes[node] = "passed"

    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        stats = self.stats.finish()
        if self.controller:
            try:
                stats = self.merge_workers(stats, int(exitstatus))
            except (KeyError, TypeError, ValueError):
                session.exitstatus = pytest.ExitCode.USAGE_ERROR
                raise pytest.UsageError(
                    "Required parallel test statistics/evidence are invalid"
                ) from None
        for node in self.collected:
            self.outcomes.setdefault(node, "not-executed")
            self.phases.setdefault(node, {})
        filtered = any(
            (
                session.config.option.keyword,
                session.config.option.markexpr,
                session.config.option.collectonly,
                session.config.option.deselect,
                session.config.option.lf,
                session.config.option.failedfirst,
            )
        )
        target = comparison(
            self.root,
            list(session.config.args),
            stats,
            success=int(exitstatus) == 0,
            filtered=filtered,
        )
        self.target = target
        if not self.controller:
            self.evidence = {
                "format": EVIDENCE_FORMAT,
                "origin": os.environ.get("FISHHAT_TEST_ORIGIN"),
                "inventory_sha256": self.inventory_hash,
                "groups": group_results(
                    self.declarations, self.phases, self.observed, self.outcomes
                ),
            }
        value = {
            "profile": {
                "platform": sys.platform,
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "profiling_target": target,
            "format": "fishhat-pytest-timing/v1",
            "qualification_eligible": False,
            "collected": self.collected,
            "outcomes": self.outcomes,
            "exit_status": int(exitstatus),
            "stats": stats,
            "phases": self.phases,
            "fixtures": self.fixtures,
            "evidence": self.evidence,
            "subtests": self.subtests,
        }
        if hasattr(session.config, "workeroutput"):
            session.config.workeroutput["fishhat_results"] = value
            return
        self.output = write_stats(self.root, value)
        if self.destination:
            self.destination.write_text(json.dumps(value), encoding="utf-8")

    def pytest_terminal_summary(self, terminalreporter: Any) -> None:
        if self.output:
            terminalreporter.write_line(
                f"Non-contractual test stats: {self.output.relative_to(self.root)}"
            )
            if self.target.get("metrics"):
                metrics = self.target["metrics"]
                details = "; ".join(
                    f"{key}: {m['observed']:.3f}/{m['target']:g} {m['status']}"
                    for key, m in metrics.items()
                )
                terminalreporter.write_line("Profiling targets (report only): " + details)
            terminalreporter.write_line(
                "Check purposes/scopes (not native qualification): "
                + json.dumps(summary(self.evidence["groups"]), sort_keys=True)
            )


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--evidence-generate",
        action="store_true",
        help="Snapshot reviewed full collection and maintained entrypoints; no execution proof",
    )


def pytest_configure(config: pytest.Config) -> None:
    if not config.pluginmanager.hasplugin("fishhat-results"):
        destination = os.environ.get(REPORT_VARIABLE)
        config.pluginmanager.register(
            TestResults(
                config.rootpath,
                Path(destination) if destination else None,
                process_name=getattr(config, "workerinput", {}).get("workerid", "controller"),
                controller=bool(getattr(config.option, "numprocesses", 0))
                and not hasattr(config, "workerinput")
                and not config.option.collectonly,
            ),
            "fishhat-results",
        )
