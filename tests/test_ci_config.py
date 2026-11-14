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
            'uv sync --locked --all-packages --group dev --python "$FISHHAT_CI_PYTHON"', commands
        )
        self.assertIn(
            'uv run --locked --all-packages --group dev --python "$FISHHAT_CI_PYTHON"', commands
        )
        report = next(
            line for line in commands.splitlines() if "scripts.engineering report" in line
        )
        self.assertIn('--python "$FISHHAT_CI_PYTHON"', report)

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

    def test_native_controller_requires_main_and_early_regressions(self):
        job = self.workflow["jobs"]["native-controller"]
        self.assertIn("github.ref == 'refs/heads/main'", job["if"])
        self.assertIn("watchdog-regressions", job["needs"])
        self.assertEqual(job["env"]["CHECK_PURPOSES"], "validation-tooling")
        self.assertIn("no native owner qualification", job["env"]["CHECK_SCOPE"])
        self.assertIn("paused TCG/QMP identities", job["env"]["CHECK_SCOPE"])
        self.assertIn("owned-controller fault cleanup", job["env"]["CHECK_SCOPE"])
        regressions = self.workflow["jobs"]["watchdog-regressions"]["steps"]
        self.assertIn("tests/test_native_linux_controller.py", str(regressions))
        self.assertIn("tests/test_native_linux_images.py", str(regressions))
        self.assertIn("authenticated guest boot/SSH identity", job["env"]["CHECK_SCOPE"])
        self.assertIn("tests/test_native_linux_guest.py", str(regressions))
        self.assertIn("tests/test_native_linux_storage.py", str(regressions))
        self.assertIn("isolated guest filesystems/account permissions", job["env"]["CHECK_SCOPE"])
        self.assertIn("partial-storage setup cleanup", job["env"]["CHECK_SCOPE"])
        self.assertIn("tests/test_native_linux_processes.py", str(regressions))
        self.assertIn("tests/test_native_linux_transport.py", str(regressions))
        self.assertIn("owned guest process kill/reaping", job["env"]["CHECK_SCOPE"])
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        self.assertIn("scripts.native_linux_enrollment --github-hosted-only", commands)
        self.assertNotIn("secrets.", str(job))
        artifact = next(step for step in job["steps"] if "upload-artifact@" in step.get("uses", ""))
        self.assertEqual(
            artifact["with"]["path"], "artifacts/native-fixture/controller-enrollment.json"
        )
        self.assertEqual(artifact["with"]["if-no-files-found"], "error")

    def test_native_smoke_keeps_complete_normal_before_required_interruption_witness(self):
        job = self.workflow["jobs"]["native-prerequisites"]
        steps = job["steps"]
        normal = [
            index
            for index, step in enumerate(steps)
            if step.get("run") == "bash scripts/ci/native_smoke.sh --github-hosted-only"
        ]
        selected = [
            index
            for index, step in enumerate(steps)
            if "scripts.native_smoke_interruption --github-hosted-only" in step.get("run", "")
        ]
        self.assertEqual(len(normal), 1)
        self.assertEqual(len(selected), 1)
        self.assertLess(normal[0], selected[0])
        receipt = next(
            step
            for step in steps
            if step.get("with", {}).get("name") == "native-smoke-interruption"
        )
        self.assertEqual(receipt["with"]["path"], "artifacts/native-smoke-interruption.json")
        self.assertEqual(receipt["with"]["if-no-files-found"], "error")
        self.assertEqual(receipt["if"], "${{ always() }}")
        self.assertIn("validation-tooling", job["env"]["CHECK_PURPOSES"])
        self.assertIn("pre-manager interruption", job["env"]["CHECK_SCOPE"])

    def test_native_ssh_custody_retains_normal_and_selected_original_receipts(self):
        job = self.workflow["jobs"]["native-prerequisites"]
        steps = job["steps"]
        normal = next(
            i
            for i, step in enumerate(steps)
            if step.get("run") == "bash scripts/ci/native_smoke.sh --github-hosted-only"
        )
        account = next(
            i
            for i, step in enumerate(steps)
            if "scripts.native_smoke_interruption --github-hosted-only" in step.get("run", "")
        )
        selected = [
            i
            for i, step in enumerate(steps)
            if "scripts.native_smoke_ssh_qualification --github-hosted-only" in step.get("run", "")
        ]
        self.assertEqual(len(selected), 1)
        self.assertLess(normal, account)
        self.assertLess(account, selected[0])
        artifact = next(
            step
            for step in steps
            if step.get("with", {}).get("name") == "native-smoke-ssh-interruption"
        )
        self.assertEqual(artifact["with"]["path"], "artifacts/native-smoke-ssh-interruption.json")
        self.assertEqual(artifact["with"]["if-no-files-found"], "error")
        self.assertEqual(artifact["if"], "${{ always() }}")
        early = str(self.workflow["jobs"]["watchdog-regressions"])
        self.assertIn("tests/test_native_smoke_ssh.py", early)
        self.assertIn("root SSH lifetime/listener custody", job["env"]["CHECK_SCOPE"])

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

    def test_setup_leaves_commits_and_pushes_without_validation_hooks(self):
        import os
        import shutil
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "checkout"
            checkout.mkdir()
            tools = Path(tmp) / "tools"
            tools.mkdir()
            remote = Path(tmp) / "remote.git"
            shutil.copyfile(ROOT / "Makefile", checkout / "Makefile")
            if (ROOT / ".githooks").exists():
                shutil.copytree(ROOT / ".githooks", checkout / ".githooks")
            runner = tools / "mise"
            runner.write_text("#!/bin/sh\nexit 0\n")
            runner.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_ALLOW_PROTOCOL": "file",
            }

            def run(*command):
                return subprocess.run(
                    command, cwd=checkout, env=environment, capture_output=True, check=True
                ).stdout

            run("git", "init", "--quiet", "--template=", "--initial-branch=main")
            run("make", "setup")
            configured = subprocess.run(
                ["git", "config", "--local", "--get", "core.hooksPath"],
                cwd=checkout,
                env=environment,
                capture_output=True,
            )
            self.assertEqual(configured.returncode, 1)
            # Validation tools now fail. Ordinary Git operations still succeed;
            # complete validation is a separate pre-push maintainer obligation.
            runner.write_text("#!/bin/sh\nexit 17\n")
            make = tools / "make"
            make.write_text("#!/bin/sh\nexit 17\n")
            make.chmod(0o755)
            run("git", "add", "Makefile")
            run(
                "git",
                "-c",
                "user.name=Fixture Maintainer",
                "-c",
                "user.email=maintainer@example.invalid",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                "Synthetic fixture",
            )
            run("git", "init", "--quiet", "--bare", "--template=", str(remote))
            run("git", "push", "--quiet", str(remote), "HEAD:refs/heads/main")
            self.assertEqual(
                run("git", "rev-parse", "HEAD"),
                run("git", "--git-dir", str(remote), "rev-parse", "refs/heads/main"),
            )


if __name__ == "__main__":
    unittest.main()
