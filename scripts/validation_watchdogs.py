"""Source-owned guards for maintained watchdog APIs and their runtime boundary."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml


class PythonGuard:
    def __init__(self, text: str, name: str) -> None:
        self.tree = ast.parse(text)
        self.name = name
        self.aliases: dict[str, str] = {}
        self.values: dict[str, ast.expr] = {}
        self.errors: list[str] = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = (
                        (node.module or "") + "." + alias.name
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.values[target.id] = node.value

    def qualified(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return self.qualified(node.value) + "." + node.attr
        return ""

    def budget(self, node: ast.expr, seen: frozenset[str] = frozenset()) -> bool:
        if isinstance(node, ast.Name) and node.id in self.values and node.id not in seen:
            return self.budget(self.values[node.id], seen | {node.id})
        if not isinstance(node, ast.Call):
            return False
        if self.qualified(node.func) == "scripts.validation_timeouts.watchdog":
            return not isinstance(node.func, ast.Name) or node.func.id not in self.values
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "remaining"
            and isinstance(node.func.value, ast.Name)
        ):
            source = self.values.get(node.func.value.id)
            return (
                isinstance(source, ast.Call)
                and self.qualified(source.func) == "scripts.validation_timeouts.Deadline.after"
            )
        return False

    def timing(self, node: ast.AST, seen: frozenset[str] = frozenset()) -> bool:
        for part in ast.walk(node):
            if isinstance(part, ast.Name) and part.id in self.values and part.id not in seen:
                if self.timing(self.values[part.id], seen | {part.id}):
                    return True
            if isinstance(part, ast.Call) and self.qualified(part.func) in {
                "time.monotonic",
                "time.perf_counter",
            }:
                return True
            if (
                isinstance(part, ast.Subscript)
                and isinstance(part.slice, ast.Constant)
                and part.slice.value in {"elapsed_seconds", "duration_seconds"}
            ):
                return True
        return False

    def owned(self, value: ast.expr, function: str) -> bool:
        return (
            self.name == "tests/test_adapter_process.py"
            and function == "expiry_probe"
            and isinstance(value, ast.Constant)
            and value.value == 0.1
        ) or (
            self.name == "scripts/smoke_installed.py"
            and function == "main"
            and ast.unparse(value) == "args.watchdog_seconds"
        )

    def error(self, node: ast.AST, message: str) -> None:
        self.errors.append(f"{self.name}:{getattr(node, 'lineno', 0)}: {message}")

    def call(self, node: ast.Call, function: str) -> None:
        for keyword in node.keywords:
            if (
                keyword.arg == "timeout"
                and not self.owned(keyword.value, function)
                and not self.budget(keyword.value)
            ):
                self.error(node, "unmanaged watchdog")
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"wait", "join"}
            and node.args
            and not isinstance(node.func.value, ast.Constant)
        ):
            if not self.budget(node.args[0]):
                self.error(node, "unmanaged positional wait")
        if self.qualified(node.func).endswith(".mark.timeout"):
            self.error(node, "unmanaged pytest timeout")
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"assertLess", "assertLessEqual"}
            and node.args
            and self.timing(node.args[0])
        ):
            self.error(node, "elapsed-time speed gate")

    def walk(self, node: ast.AST, function: str = "") -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = node.name
        if isinstance(node, ast.Call):
            self.call(node, function)
        if isinstance(node, ast.Assert):
            for comparison in ast.walk(node.test):
                if (
                    isinstance(comparison, ast.Compare)
                    and any(isinstance(op, (ast.Lt, ast.LtE)) for op in comparison.ops)
                    and self.timing(comparison.left)
                ):
                    self.error(node, "elapsed-time speed gate")
        for child in ast.iter_child_nodes(node):
            self.walk(child, function)


def python_errors(text: str, name: str, *, runtime: bool = False) -> list[str]:
    guard = PythonGuard(text, name)
    if runtime:
        if (
            any(
                "scripts.validation_timeouts" in target or "scripts.validation_workflows" in target
                for target in guard.aliases.values()
            )
            or "FISHHAT_VALIDATION_" in text
            or "scripts.validation_timeouts" in text
            or "scripts.validation_workflows" in text
        ):
            return [name + ": runtime imports or consults validation policy"]
        return []
    guard.walk(guard.tree)
    return guard.errors


def shell_errors(text: str, name: str) -> list[str]:
    errors = []
    for match in re.finditer(r"(?:--connect-timeout|--max-time|\btimeout)\s+([^\s;]+)", text):
        value = match[1]
        variable = re.fullmatch(r'["\']?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?["\']?', value)
        if variable is None or not re.search(
            r"^" + re.escape(variable[1]) + r"=.*(?:timeout_helper|validation_timeouts).*seconds",
            text,
            re.M,
        ):
            errors.append(name + ": unmanaged shell timeout")
    if re.search(r"for .*?(?:seq|attempt).*?;?\s*(?:do|\n)", text) and re.search(
        r"\bsleep\s", text
    ):
        errors.append(name + ": retry-count observation deadline")
    for block in re.findall(r"python[^\n]*<<[\"']?PY[\"']?\n(.*?)\nPY", text, re.S):
        errors.extend(python_errors(block, name + ":embedded-python"))
    return errors


def workflow_errors(text: str, name: str) -> list[str]:
    value = yaml.load(text, Loader=yaml.BaseLoader)
    jobs = value["jobs"]
    errors = []
    planner = jobs.get("watchdogs", {})
    if planner.get("timeout-minutes") != "5" or "scripts.validation_workflows" not in str(
        planner.get("steps")
    ):
        errors.append(name + ": missing watchdog planning/bootstrap ceiling")
    for key, job in jobs.items():
        if key == "watchdogs":
            continue
        case = "[matrix.watchdog_scale]" if key == "watchdog-regressions" else ""
        expected = "${{ fromJSON(needs.watchdogs.outputs.budgets)['" + key + "']" + case + " }}"
        needs = job.get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        env = job.get("env", {})
        if key == "tests" and "watchdog-regressions" not in needs:
            errors.append(name + ": unit gate bypasses watchdog regressions")
        if key == "watchdog-regressions" and job.get("strategy", {}).get("matrix", {}).get(
            "watchdog_scale"
        ) != ["1", "4"]:
            errors.append(name + ": required scale witnesses changed")
        if (
            job.get("timeout-minutes") != expected
            or "watchdogs" not in needs
            or env.get("FISHHAT_VALIDATION_JOB_MINUTES") != expected
            or env.get("UV_HTTP_TIMEOUT")
            != "${{ fromJSON(needs.watchdogs.outputs.contacts)['" + key + "']" + case + ".uv }}"
            or "FISHHAT_VALIDATION_NOMINAL_MINUTES" not in env
            or env.get("FISHHAT_VALIDATION_TIMEOUT_SCALE")
            != (
                "${{ matrix.watchdog_scale }}"
                if key == "watchdog-regressions"
                else "${{ needs.watchdogs.outputs.scale }}"
            )
        ):
            errors.append(name + ": unmanaged workflow budget/propagation: " + key)
    return errors


def check(root: Path) -> list[str]:
    errors = []
    for folder in ("tests", "scripts", "packages", "fishhat", "some-implementations"):
        for path in (root / folder).rglob("*.py"):
            if "build" in path.relative_to(root).parts:
                continue
            name = path.relative_to(root).as_posix()
            runtime = "src" in path.relative_to(root).parts or name == "scripts/bundle_install.py"
            errors.extend(python_errors(path.read_text(), name, runtime=runtime))
        for path in (root / folder).rglob("*.sh"):
            errors.extend(shell_errors(path.read_text(), path.relative_to(root).as_posix()))
    for path in (root / ".github/workflows").glob("*.y*ml"):
        errors.extend(workflow_errors(path.read_text(), path.relative_to(root).as_posix()))
    return errors
