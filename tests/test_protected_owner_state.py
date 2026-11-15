"""Ordinary-file storage mechanics with administrative enrollment replaced."""

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import bundle_install as installer

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/bundle_install.py"],
    "scope": "fresh private directory creation, preservation, synchronization and linear ancestry traversal",
    "relationship": "no-product-claim",
    "reason": "Replaced administrative enrollment and ordinary temporary files test installer mechanics only; no credentials, journal, native owner or actual administrative installation runs.",
    "claims": [],
}


@pytest.fixture
def custody(tmp_path, monkeypatch):
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)

    def enrolled(destination):
        assert destination.parent == parent
        return os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    monkeypatch.setattr(installer, "_protected_parent", enrolled)
    return parent


def test_fresh_state_is_private_empty_and_synced_without_initialization(custody, monkeypatch):
    calls = []
    original = os.fsync

    def synced(descriptor):
        row = os.fstat(descriptor)
        calls.append((row.st_dev, row.st_ino, stat.S_IMODE(row.st_mode)))
        original(descriptor)

    monkeypatch.setattr(installer.os, "fsync", synced)
    destination = custody / "state"
    assert installer._prepare_owner_state(destination) == destination
    info = destination.stat()
    assert info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
    assert list(destination.iterdir()) == []
    parent = custody.stat()
    assert calls == [(info.st_dev, info.st_ino, 0o700), (parent.st_dev, parent.st_ino, 0o700)]


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_existing_state_is_never_adopted_or_erased(custody, tmp_path, kind):
    target = tmp_path / "retained"
    target.mkdir()
    (target / "keep").write_bytes(b"unrelated retained contents")
    state = custody / "state"
    if kind == "directory":
        state.mkdir()
        (state / "canary").write_bytes(b"existing owner data")
    elif kind == "file":
        state.write_bytes(b"existing owner data")
    else:
        state.symlink_to(target, target_is_directory=True)
    before = state.lstat()
    with pytest.raises(FileExistsError):
        installer._prepare_owner_state(state)
    assert state.lstat() == before
    assert (target / "keep").read_bytes() == b"unrelated retained contents"
    if kind == "directory":
        assert (state / "canary").read_bytes() == b"existing owner data"
    elif kind == "file":
        assert state.read_bytes() == b"existing owner data"


@pytest.mark.parametrize("fail_at", ["open", "owner", "chmod", "sync-child", "sync-parent"])
def test_failed_provisioning_preserves_private_attempt_and_fresh_retry(
    custody, monkeypatch, fail_at
):
    state = custody / "interrupted"
    original_sync = os.fsync
    count = [0]

    def failed(*args, **kwargs):
        raise OSError("controlled interruption")

    def sync(descriptor):
        count[0] += 1
        if count[0] == (1 if fail_at == "sync-child" else 2):
            raise OSError("controlled interruption")
        original_sync(descriptor)

    with monkeypatch.context() as patch:
        if fail_at == "open":
            patch.setattr(installer, "_source_directory", failed)
        elif fail_at == "owner":
            original_stat = os.fstat
            patch.setattr(
                installer.os,
                "fstat",
                lambda fd: SimpleNamespace(st_uid=original_stat(fd).st_uid + 1),
            )
        elif fail_at == "chmod":
            patch.setattr(installer.os, "fchmod", failed)
        else:
            patch.setattr(installer.os, "fsync", sync)
        with pytest.raises((ValueError, OSError)):
            installer._prepare_owner_state(state)
    before = state.stat()
    assert stat.S_IMODE(before.st_mode) == 0o700 and not list(state.iterdir())
    with pytest.raises(FileExistsError):
        installer._prepare_owner_state(state)
    fresh = custody / "retry"
    assert installer._prepare_owner_state(fresh) == fresh
    assert state.stat() == before and fresh.stat().st_ino != before.st_ino


@pytest.mark.parametrize("custody_kind", ["platform", "unprivileged"])
def test_real_administrative_gate_refuses_before_creating(tmp_path, monkeypatch, custody_kind):
    state = tmp_path / "state"
    with monkeypatch.context() as patch:
        if custody_kind == "platform":
            patch.setattr(installer.sys, "platform", "unsupported")
        else:
            patch.setattr(installer.os, "geteuid", lambda: 12345)
        with pytest.raises(ValueError, match="administrative custody"):
            installer._prepare_owner_state(state)
    assert not state.exists()


@pytest.mark.parametrize("kind", ["symlink", "dotdot"])
def test_real_ancestry_traversal_refuses_substitutions(tmp_path, kind):
    parent = tmp_path / "retained"
    parent.mkdir()
    (parent / "canary").write_bytes(b"retained")
    if kind == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(parent, target_is_directory=True)
        path = alias
    else:
        path = parent / ".." / "retained"
    with pytest.raises((ValueError, OSError)):
        installer._directory_fd(path)
    assert list(parent.iterdir()) == [parent / "canary"]
    assert (parent / "canary").read_bytes() == b"retained"


def test_ancestry_work_remains_linear_over_complete_path_bytes(tmp_path, monkeypatch):
    original = os.open
    samples = []
    for depth in (4, 16, 64):
        parent = tmp_path / str(depth)
        for _ in range(depth):
            parent = parent / "part"
        parent.mkdir(parents=True)
        work = [0]

        def counted(path, flags, *args, counter=work, **kwargs):
            counter[0] += 1 + len(os.fspath(path))
            return original(path, flags, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(installer.os, "open", counted)
            descriptor = installer._directory_fd(parent)
            try:
                assert os.fstat(descriptor).st_ino == parent.stat().st_ino
            finally:
                os.close(descriptor)
        samples.append({"depth": depth, "input_bytes": len(str(parent)), "work": work[0]})
    observed = os.environ.get("FISHHAT_STATE_PATH_WORK_OBSERVATIONS")
    if observed:
        Path(observed).write_text(json.dumps(samples, indent=2) + "\n")
    first = samples[0]
    assert all(
        row["work"] * first["input_bytes"] <= 1.05 * first["work"] * row["input_bytes"]
        for row in samples[1:]
    )
