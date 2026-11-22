"""Check immutable refs for direct remote GitHub Actions and reusable workflows."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

CHECK_PURPOSE = {
    "purpose": "repository-policy",
    "authority": [".github/workflows/ci.yml"],
    "scope": "direct remote GitHub Actions and reusable workflow references",
    "relationship": "no-product-claim",
    "reason": "Require immutable commit references in repository-maintained CI workflows.",
    "claims": [],
}

ROOT = Path(__file__).resolve().parents[1]
COMMIT = re.compile(r"[0-9a-fA-F]{40}")
REMOTE = re.compile(r"[\w.-]+/[\w.-]+(?:/[^@\s]+)?@([0-9a-zA-Z._/-]+)")


def git(root, *args):
    return subprocess.check_output(("git", *args), cwd=root)


def mapping(node):
    if not isinstance(node, MappingNode):
        raise ValueError("expected a mapping")
    result = {}
    for key, value in node.value:
        if not isinstance(key, ScalarNode):
            raise ValueError("expected a scalar mapping key")
        if key.value in result:
            raise ValueError(f"duplicate key: {key.value}")
        if key.value == "<<":
            raise ValueError("unexpected YAML merge key")
        result[key.value] = value
    return result


def workflow_uses(source):
    """Return (job, kind, 1-based line, ref) for direct remote references."""
    document = yaml.compose(source, Loader=yaml.BaseLoader)
    jobs = mapping(document).get("jobs")
    if jobs is None:
        raise ValueError("missing jobs")

    def check_uses(job_id, kind, uses):
        if not isinstance(uses, ScalarNode):
            raise ValueError(f"job {job_id}: expected a scalar {kind} uses reference")
        if not uses.value.startswith(("./", "docker://")):
            yield job_id, kind, uses.start_mark.line + 1, uses.value

    for job_id, job in mapping(jobs).items():
        fields = mapping(job)
        if "uses" in fields:
            yield from check_uses(job_id, "reusable workflow", fields["uses"])
        if "steps" not in fields:
            continue
        steps = fields["steps"]
        if not isinstance(steps, SequenceNode):
            raise ValueError(f"job {job_id}: expected a steps sequence")
        for step in steps.value:
            uses = mapping(step).get("uses")
            if uses is not None:
                yield from check_uses(job_id, "step", uses)


def full_sha(ref):
    match = REMOTE.fullmatch(ref)
    return match is not None and COMMIT.fullmatch(match[1]) is not None


def repo_workflows(root):
    for entry in git(root, "ls-tree", "-z", "HEAD", ".github/workflows/").split(b"\0"):
        if not entry:
            continue
        metadata, workflow_bytes = entry.split(b"\t", 1)
        workflow = workflow_bytes.decode()
        if not workflow.endswith((".yaml", ".yml")):
            continue
        mode, kind, blob = metadata.decode().split()
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(f"{workflow}: expected a regular workflow")
        yield workflow, git(root, "cat-file", "blob", blob)


class ActionsPinTests(unittest.TestCase):
    def test_remote_actions_and_workflows_use_commit_shas(self):
        workflows = list(repo_workflows(ROOT))
        self.assertTrue(workflows, "expected at least one tracked workflow")
        for path, source in workflows:
            with self.subTest(workflow=path):
                failures = [
                    f"{path}:{line} ({job}, {kind}): {ref}"
                    for job, kind, line, ref in workflow_uses(source)
                    if not full_sha(ref)
                ]
                self.assertFalse(failures, "expected full commit SHAs:\n" + "\n".join(failures))

    def test_only_direct_remote_references_are_checked(self):
        sha = "a" * 40
        source = f"""
jobs:
  steps:
    steps:
      - uses: ./.github/actions/local
      - uses: docker://busybox:latest
      - uses: actions/checkout@v4
  local:
    uses: ./.github/workflows/local.yml
  pinned:
    uses: owner/repo/.github/workflows/test.yml@{sha}
  mutable:
    uses: owner/repo/.github/workflows/test.yml@main
"""
        self.assertEqual(
            [
                ("steps", "step", "actions/checkout@v4", False),
                (
                    "pinned",
                    "reusable workflow",
                    f"owner/repo/.github/workflows/test.yml@{sha}",
                    True,
                ),
                (
                    "mutable",
                    "reusable workflow",
                    "owner/repo/.github/workflows/test.yml@main",
                    False,
                ),
            ],
            [(job, kind, ref, full_sha(ref)) for job, kind, _, ref in workflow_uses(source)],
        )
        self.assertFalse(full_sha(f"owner/repo/.github/workflows/test.yml@{sha[:-1]}"))
