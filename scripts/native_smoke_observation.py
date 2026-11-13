"""Emit only numeric and fixed-label facts about the owned smoke generator."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


def metadata(path: Path) -> dict[str, Any]:
    result = path.lstat()
    target = path.stat()
    flags = os.statvfs(path).f_flag
    values = (result.st_mode, result.st_uid, result.st_gid, target.st_mode, flags)
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError("invalid metadata")
    return {
        "mode": stat.S_IMODE(result.st_mode),
        "uid": result.st_uid,
        "gid": result.st_gid,
        "directory": stat.S_ISDIR(result.st_mode),
        "regular": stat.S_ISREG(result.st_mode),
        "symlink": stat.S_ISLNK(result.st_mode),
        "target_mode": stat.S_IMODE(target.st_mode),
        "target_regular": stat.S_ISREG(target.st_mode),
        "mount_noexec": bool(flags & os.ST_NOEXEC),
    }


def observe_path(role: str, path: Path) -> dict[str, Any]:
    try:
        value = metadata(path)
    except (OSError, ValueError, TypeError, AttributeError):
        return {"role": role, "status": "unavailable", "reason": "metadata-unavailable"}
    return {"role": role, "status": "observed", **value}


def observe_generator(generator: Path) -> dict[str, Any]:
    roles = (
        ("prefix", Path("/usr")),
        ("library", Path("/usr/lib")),
        ("manager-library", Path("/usr/lib/systemd")),
        ("generator-directory", generator.parent),
        ("generator", generator),
        ("interpreter", Path("/bin/sh")),
    )
    observations = [observe_path(role, path) for role, path in roles]
    return {
        "scope": "owned-smoke-generator-observation-only",
        "measurement_scope": "observer-process-filesystem",
        "observer_uid": os.geteuid(),
        "status": "observed"
        if all(value["status"] == "observed" for value in observations)
        else "unavailable",
        "observations": observations,
        "native_qualified": False,
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    valid = len(arguments) == 1
    path = Path(arguments[0]) if valid else Path(".")
    valid = (
        valid
        and path.is_absolute()
        and path.parent == Path("/usr/lib/systemd/user-environment-generators")
        and re.fullmatch(r"99-fishhat-probe-[0-9]+", path.name) is not None
    )
    value = (
        observe_generator(path)
        if valid
        else {"status": "unavailable", "reason": "owned-generator-path-required"}
    )
    print("native-prerequisite generator-observation=" + json.dumps(value, sort_keys=True))
    return 0 if value["status"] == "observed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
