"""The disposable XFS byte and inode workloads, using admitted directory handles."""

from __future__ import annotations

import errno
import json
import os
import sys
from pathlib import Path


def grow(path: Path) -> None:
    target = 16 * 1048576
    with path.open("wb", buffering=0) as stream:
        while stream.tell() < target:
            written = stream.write(b"x" * min(1048576, target - stream.tell()))
            assert written and written > 0, "write made no progress"
        os.fsync(stream.fileno())
    assert path.stat().st_size == target


def byte_quota(project: Path, control: Path) -> dict[str, int | bool]:
    grow(control / "before")
    try:
        grow(project / "grow")
    except OSError as error:
        if error.errno != errno.ENOSPC:
            raise
    else:
        raise AssertionError("byte quota not enforced")
    size = (project / "grow").stat().st_size
    assert 0 < size <= 8 * 1048576
    grow(control / "after")
    for path in (project / "grow", control / "before", control / "after"):
        path.unlink()
    return {"quota_enforced": True, "admitted_bytes": size, "control_bytes": 16 * 1048576}


def inode_quota(project: Path, control: Path) -> dict[str, int | bool]:
    def controls(prefix: str) -> list[Path]:
        paths = [control / f"{prefix}-{index}" for index in range(256)]
        for path in paths:
            path.touch(exist_ok=False)
        return paths

    before = controls("before")
    created = []
    try:
        for index in range(256):
            path = project / str(index)
            path.touch(exist_ok=False)
            created.append(path)
    except OSError as error:
        if error.errno != errno.ENOSPC:
            raise
    else:
        raise AssertionError("inode quota not enforced")
    # The project directory consumes one of the 64 admitted inodes.
    assert 0 < len(created) < 64
    after = controls("after")
    for path in before + created + after:
        path.unlink()
    return {"quota_enforced": True, "admitted_files": len(created), "control_files": 256}


def main() -> int:
    assert len(sys.argv) == 4 and sys.argv[1] in {"bytes", "inodes"}
    project, control = (Path("/proc/self/fd") / str(int(value)) for value in sys.argv[2:])
    result = (byte_quota if sys.argv[1] == "bytes" else inode_quota)(project, control)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
