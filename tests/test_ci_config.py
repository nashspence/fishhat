from __future__ import annotations

import subprocess
import unittest

import yaml

from scripts.validation_timeouts import watchdog
from tests.support import ROOT

CHECK_PURPOSE = {
    "purpose": "repository-policy",
    "authority": [".github/workflows/ci.yml"],
    "scope": "workflow and hook policy",
    "relationship": "no-product-claim",
    "reason": "Required workflow configuration and refusal guards, not execution of the selected native services.",
    "claims": [],
}


class WorkflowSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # BaseLoader keeps GitHub's `on` key as a string instead of YAML 1.1 boolean.
        cls.workflow = yaml.load(
            (ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader
        )

    def test_main_push_is_a_trigger(self):
        self.assertEqual(self.workflow["on"]["push"]["branches"], ["main"])

    def test_ci_matrix_selects_its_declared_python(self):
        commands = "\n".join(
            step.get("run", "") for step in self.workflow["jobs"]["tests"]["steps"]
        )
        self.assertIn(
            'uv sync --locked --all-packages --group dev --python "${{ matrix.python }}"', commands
        )
        self.assertIn(
            'uv run --locked --all-packages --group dev --python "${{ matrix.python }}"', commands
        )
        report = next(
            line for line in commands.splitlines() if "scripts.engineering report" in line
        )
        self.assertIn('--python "${{ matrix.python }}"', report)

    def test_no_privileged_pr_target(self):
        self.assertNotIn("pull_request_target", self.workflow["on"])
        self.assertNotIn("workflow_run", self.workflow["on"])

    def test_read_only_token(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        for name, job in self.workflow["jobs"].items():
            if name == "watchdogs":
                self.assertEqual(job["permissions"], {"contents": "read", "actions": "read"})
            else:
                self.assertNotIn("permissions", job)

    def test_no_self_hosted_runners_or_secrets(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertNotIn("secrets.", text)
        for name, job in self.workflow["jobs"].items():
            if name == "installed":
                self.assertEqual(job["runs-on"], "${{ matrix.os }}")
                self.assertEqual(
                    job["strategy"]["matrix"]["os"], ["ubuntu-24.04", "macos-15", "windows-2025"]
                )
            else:
                self.assertEqual(job["runs-on"], "ubuntu-24.04")

    def test_actions_are_sha_pinned(self):
        for job in self.workflow["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"^[\w-]+/[\w-]+(?:/[\w-]+)?@[0-9a-f]{40}$")

    def test_git_credentials_not_persisted(self):
        for job in self.workflow["jobs"].values():
            for step in job["steps"]:
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertEqual(step["with"]["persist-credentials"], "false")

    def test_native_job_not_on_pull_requests(self):
        cond = self.workflow["jobs"]["native-prerequisites"]["if"]
        self.assertIn("github.ref == 'refs/heads/main'", cond)
        self.assertNotIn("== 'pull_request'", cond)

    def test_native_script_refuses_ordinary_machine(self):
        proc = subprocess.run(
            ["bash", str(ROOT / "scripts/ci/native_smoke.sh")],
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True,
            text=True,
            timeout=watchdog(5),
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("Refusing", proc.stderr)

    def test_native_shell_syntax(self):
        for name in ("native_smoke.sh", "secret_scan.sh"):
            subprocess.run(["bash", "-n", str(ROOT / "scripts/ci" / name)], check=True)


class SecurityGates(unittest.TestCase):
    def test_codeql_covers_python_and_workflows_with_extended_queries(self):
        workflow = yaml.load(
            (ROOT / ".github/workflows/codeql.yml").read_text(), Loader=yaml.BaseLoader
        )
        self.assertEqual(workflow["on"]["pull_request"]["branches"], ["main"])
        job = workflow["jobs"]["analyze"]
        self.assertEqual(set(job["strategy"]["matrix"]["language"]), {"python", "actions"})
        self.assertEqual(
            job["permissions"], {"contents": "read", "security-events": "write", "packages": "read"}
        )
        init = next(step for step in job["steps"] if "codeql-action/init@" in step.get("uses", ""))
        self.assertEqual(init["with"]["queries"], "security-extended")
        for step in job["steps"]:
            if "uses" in step:
                self.assertRegex(step["uses"], r"^[\w-]+/[\w-]+(?:/[\w-]+)?@[0-9a-f]{40}$")

    def test_dependency_review_rejects_even_low_severity(self):
        workflow = yaml.load(
            (ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader
        )
        review = workflow["jobs"]["dependency-review"]
        step = next(
            step for step in review["steps"] if "dependency-review-action@" in step.get("uses", "")
        )
        self.assertEqual(step["with"]["fail-on-severity"], "low")
        audit = workflow["jobs"]["dependency-audit"]
        command = "\n".join(step.get("run", "") for step in audit["steps"])
        self.assertIn("--all-groups", command)
        self.assertIn("pip-audit --strict", command)

    def test_strict_mypy_and_ruff_are_unconditional_ci_gates(self):
        import tomllib

        config = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertTrue(config["tool"]["mypy"]["strict"])
        self.assertIn("packages", config["tool"]["mypy"]["files"])
        workflow = yaml.load(
            (ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader
        )
        for key in ("mypy", "ruff"):
            job = workflow["jobs"][key]
            self.assertNotIn("if", job)
            self.assertNotIn("continue-on-error", job)
        commands = "\n".join(step.get("run", "") for step in workflow["jobs"]["ruff"]["steps"])
        self.assertIn("ruff check packages fishhat some-implementations scripts tests", commands)
        self.assertIn(
            "ruff format --check packages fishhat some-implementations scripts tests",
            commands,
        )

    def test_commit_hook_propagates_unit_failure(self):
        import os
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp) / "mise"
            runner.write_text(
                '#!/bin/sh\ntest "${GIT_INDEX_FILE+x}" != x || exit 18\ncase "$*" in *SYNTHETIC_REPORT_FILTER*) exit 19;; esac\nexit 17\n'
            )
            runner.chmod(0o755)
            result = subprocess.run(
                [str(ROOT / ".githooks/pre-commit")],
                cwd=ROOT,
                env={
                    **os.environ,
                    "GIT_INDEX_FILE": ".git/index",
                    "UNIT_REPORT_ARGS": "-k SYNTHETIC_REPORT_FILTER",
                    "PATH": tmp + os.pathsep + os.environ["PATH"],
                },
                capture_output=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Error 17", result.stderr)


if __name__ == "__main__":
    unittest.main()
