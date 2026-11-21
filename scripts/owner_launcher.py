"""Build data for a fixed static launcher in the enrolled Linux CI facility.

Ordinary tests replace command execution. This module never executes its output.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from scripts.bundle_install import (
    _owner_launcher_header,
    _verify_owner_launcher_elf,
)
from scripts.native_linux_guest import GuestBootError
from scripts.native_linux_images import Command
from scripts.validation_timeouts import current

target_header = _owner_launcher_header

SOURCE = Path(__file__).resolve().parents[1] / "fishhat/host-ops/launcher/launch.c"
PACKAGES = {
    "gcc-13-x86-64-linux-gnu": ("13.3.0-6ubuntu2~24.04.1", "amd64"),
    "binutils-x86-64-linux-gnu": ("2.42-4ubuntu2.10", "amd64"),
}
TOOLS = {
    "driver": Path("/usr/bin/x86_64-linux-gnu-gcc-13"),
    "frontend": Path("/usr/lib/gcc/x86_64-linux-gnu/13/cc1"),
    "assembler": Path("/usr/bin/x86_64-linux-gnu-as"),
    "linker": Path("/usr/bin/x86_64-linux-gnu-ld.bfd"),
}
FLAGS = (
    "-std=c11",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fno-pie",
    "-nostdinc",
    "-nostdlib",
    "-static",
    "-no-pie",
    "-fuse-ld=bfd",
    "-Wl,--build-id=none",
    "-Wl,-z,noexecstack",
)


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def provision_tools(
    command: Command,
    root_command: Callable[[list[str], str, float], None],
    progress: Callable[[str], AbstractContextManager[None]],
) -> dict[str, Any]:
    """Use the existing, already enrolled disposable hosted package rail only."""
    with progress("owner-launcher-build-tools"):
        contact = current().units(30, unit_seconds=1, maximum=2**31 - 1)
        options = [
            item
            for name in ("Acquire::http::Timeout", "Acquire::https::Timeout", "DPkg::Lock::Timeout")
            for item in ("-o", f"{name}={contact}")
        ]
        root_command(
            [
                "/usr/bin/apt-get",
                *options,
                "-o",
                "Acquire::Retries=0",
                "install",
                "-y",
                "--no-install-recommends",
                *(name + "=" + version for name, (version, _) in PACKAGES.items()),
            ],
            "owner-launcher-build-tools",
            300,
        )
        raw = command(
            [
                "/usr/bin/dpkg-query",
                "-W",
                "-f",
                "${Package}\t${Version}\t${Architecture}\n",
                *PACKAGES,
            ],
            "owner-launcher-build-tools",
            10,
            capture=True,
        )
        rows = [line.split("\t") for line in raw.splitlines()]
        if (
            len(rows) != len(PACKAGES)
            or any(len(row) != 3 for row in rows)
            or {row[0]: tuple(row[1:]) for row in rows} != PACKAGES
        ):
            raise GuestBootError("owner-launcher-build-tool-mismatch")
        hashes = {}
        for name, path in TOOLS.items():
            with path.open("rb") as stream:
                hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
        return {
            "packages": {name: list(version) for name, version in PACKAGES.items()},
            "sha256": hashes,
        }


def build(
    command: Command,
    directory: Path,
    *,
    interpreter: dict[str, str],
    program: dict[str, str],
    tools: dict[str, Any],
) -> dict[str, Any]:
    """Compile fixed approved targets; leave any partial build for owned teardown."""
    header = target_header(interpreter["path"], program["path"])
    directory.mkdir(mode=0o700)
    for name, raw in (("launch.c", SOURCE.read_bytes()), ("targets.h", header)):
        descriptor = os.open(
            directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    argv = [
        str(TOOLS["driver"]),
        *FLAGS,
        str(directory / "launch.c"),
        "-o",
        str(directory / "launch"),
    ]
    command(argv, "owner-launcher-build", 120)
    _verify_owner_launcher_elf(directory / "launch")
    files = {}
    for name in ("launch", "launch.c", "targets.h"):
        path = directory / name
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        files[name] = {"bytes": path.stat().st_size, "sha256": digest}
    manifest = {
        "format": "fishhat-owner-launcher/v1",
        "interpreter": interpreter,
        "program": program,
        "files": files,
        "build": {"argv": argv, "tools": tools, "output_executed": False},
    }
    raw = canonical(manifest)
    descriptor = os.open(
        directory / "launcher.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"manifest": manifest, "manifest_sha256": hashlib.sha256(raw).hexdigest()}
