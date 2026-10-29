"""Actual Git primitives against temporary local fixtures; no SSH, restic or network."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.validation_timeouts import watchdog

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workspace.schema.json"
    ],
    "scope": "temporary local Git repositories",
    "relationship": "candidate",
    "reason": "Real Git fixture clone/fetch/bundle behavior; not the public session CLI, remote custody or native recovery.",
    "claims": [],
}


@unittest.skipUnless(shutil.which("git"), "local Git fixture prerequisites missing")
class GitWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = dict(
            os.environ,
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL="/dev/null",
            GIT_AUTHOR_NAME="Fixture",
            GIT_AUTHOR_EMAIL="fixture@example.invalid",
            GIT_COMMITTER_NAME="Fixture",
            GIT_COMMITTER_EMAIL="fixture@example.invalid",
            GIT_TERMINAL_PROMPT="0",
        )
        self.source = self.root / "source"
        self.git("init", "-b", "main", str(self.source))
        (self.source / "tracked.txt").write_text("first\n")
        self.git("add", "tracked.txt", cwd=self.source)
        self.git("commit", "-m", "initial", cwd=self.source)
        self.ws = self.root / "workspace"
        self.ws.mkdir()
        self.clone = self.ws / "domain"
        self.git("clone", "--no-local", str(self.source), str(self.clone))

    def git(self, *args, cwd=None, check=True):
        p = subprocess.run(
            ["git", *args],
            cwd=cwd or self.root,
            env=self.env,
            text=True,
            capture_output=True,
            timeout=watchdog(15),
        )
        if check and p.returncode:
            raise AssertionError(p.stderr)
        return p.stdout.strip() if check else p

    def next_upstream(self):
        (self.source / "remote.txt").write_text("second\n")
        self.git("add", "remote.txt", cwd=self.source)
        self.git("commit", "-m", "next", cwd=self.source)
        return self.git("rev-parse", "HEAD", cwd=self.source)

    def test_fetch_preserves_dirty_head_and_untracked(self):
        head = self.git("rev-parse", "HEAD", cwd=self.clone)
        (self.clone / "tracked.txt").write_text("local edit\n")
        (self.clone / "notes.txt").write_text("unpublished\n")
        new = self.next_upstream()
        self.git("fetch", "--no-auto-maintenance", "origin", cwd=self.clone)
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.clone), head)
        self.assertEqual(self.git("rev-parse", "origin/main", cwd=self.clone), new)
        self.assertEqual((self.clone / "tracked.txt").read_text(), "local edit\n")
        self.assertTrue((self.clone / "notes.txt").exists())

    def test_clone_self_contained_after_origin_lost(self):
        shutil.rmtree(self.source)
        self.assertEqual(self.git("rev-parse", "--is-shallow-repository", cwd=self.clone), "false")
        self.assertFalse((self.clone / ".git/objects/info/alternates").exists())
        self.git("fsck", "--full", cwd=self.clone)
        self.assertEqual(self.git("show", "HEAD:tracked.txt", cwd=self.clone), "first")

    def test_bundle_keeps_local_commits_not_untracked_work(self):
        (self.clone / "local.txt").write_text("local commit")
        self.git("add", "local.txt", cwd=self.clone)
        self.git("commit", "-m", "unpublished commit", cwd=self.clone)
        (self.clone / "dirty-note.txt").write_text("not in bundle")
        bundle = self.root / "source.bundle"
        self.git("bundle", "create", str(bundle), "--all", cwd=self.clone)
        shutil.rmtree(self.source)
        target = self.root / "restored"
        self.git("clone", str(bundle), str(target))
        self.assertTrue((target / "local.txt").exists())
        self.assertFalse((target / "dirty-note.txt").exists())
        self.git("fsck", "--full", cwd=target)

    def test_complete_workspace_restore_retains_dirty_linked_worktree(self):
        task = self.ws / "worktrees/task"
        task.parent.mkdir()
        self.git("worktree", "add", "-b", "task", str(task), cwd=self.clone)
        (task / "tracked.txt").write_text("task edit")
        (task / "private-note.txt").write_text("untracked work")
        restored = self.root / "restored-workspace"
        shutil.copytree(self.ws, restored)
        shutil.rmtree(self.ws)
        restored_repo = restored / "domain"
        restored_task = restored / "worktrees/task"
        self.git("worktree", "repair", str(restored_task), cwd=restored_repo)
        self.assertEqual((restored_task / "tracked.txt").read_text(), "task edit")
        self.assertTrue((restored_task / "private-note.txt").exists())
        self.assertIn("tracked.txt", self.git("status", "--porcelain", cwd=restored_task))

    def test_divergence_not_fast_forward(self):
        (self.clone / "local.txt").write_text("local")
        self.git("add", "local.txt", cwd=self.clone)
        self.git("commit", "-m", "local", cwd=self.clone)
        before = self.git("rev-parse", "HEAD", cwd=self.clone)
        self.next_upstream()
        self.git("fetch", "--no-auto-maintenance", "origin", cwd=self.clone)
        r = self.git("merge", "--ff-only", "origin/main", cwd=self.clone, check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.clone), before)


if __name__ == "__main__":
    unittest.main()
