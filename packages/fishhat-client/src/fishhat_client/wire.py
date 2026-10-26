"""Bounded sequential framing and ordinary SSH argument formatting."""

from __future__ import annotations

import re
import shlex
import struct
from typing import Any, BinaryIO

from fishhat_contracts.bounds import Bounds, bounds
from fishhat_contracts.validation import MAX_BYTES, ContractError, canonical, strict_json


def frame(message: dict[str, Any]) -> bytes:
    data = canonical(message)
    if not 0 < len(data) <= MAX_BYTES:
        raise ContractError("frame size")
    return struct.pack(">I", len(data)) + data


def _exact(stream: BinaryIO, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise ContractError("truncated frame")
        if len(chunk) > remaining:
            raise ContractError("invalid reader")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


@bounds(
    Bounds(
        id="wire.read-frame",
        linear_proofs=("tests/test_linear_growth.py::test_frame_linear_work",),
        work="O(frame_bytes)",
        extent="one-complete-frame",
        limits=(("frame_bytes", 1048576),),
        capacity=(),
        proofs=(
            "tests/test_engineering.py::test_frame_work_tracks_current_frame_not_stream_extent",
        ),
    )
)
def read_frame(stream: BinaryIO) -> dict[str, Any]:
    length = struct.unpack(">I", _exact(stream, 4))[0]
    if not 0 < length <= MAX_BYTES:
        raise ContractError("frame size")
    value = strict_json(_exact(stream, length))
    if type(value) is not dict:
        raise ContractError("message must be object")
    return value


def ssh_command(alias: str, argv: list[str], config: str | None = None) -> list[str]:
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", alias):
        raise ContractError("expected enrolled SSH alias, not options or URL")
    if (
        not argv
        or argv[0] not in ("host-ops", "app-ops")
        or any(type(a) is not str or "\x00" in a or "\n" in a for a in argv)
    ):
        raise ContractError("invalid fixed CLI argv")
    command = [
        "ssh",
        "-T",
        "-oBatchMode=yes",
        "-oForwardAgent=no",
        "-oControlMaster=no",
        "-oControlPath=none",
        "-oStrictHostKeyChecking=yes",
    ]
    if config is not None:
        if not config.startswith("/") or "\x00" in config:
            raise ContractError("absolute trusted SSH config required")
        command += ["-F", config]
    return [*command, alias, shlex.join(argv)]


def select_target(argument: str | None, environment: str | None, profile: str | None) -> str:
    target = next((x for x in (argument, environment, profile) if x is not None), None)
    if not target or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", target):
        raise ContractError("no valid configured target; no implicit fallback")
    return target
