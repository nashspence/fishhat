"""Exact byte custody over owner-opened streams, without path or access authority."""

from __future__ import annotations

import hashlib
from typing import Any, BinaryIO

from .bounds import Bounds, bounds
from .validation import ContractError, validate

CHUNK_BYTES = 65_536


@bounds(
    Bounds(
        id="custody.verify-artifact-stream",
        work="O(B) each complete artifact byte once with a fixed-size hashing buffer",
        extent="Complete owner-selected artifact, including empty files and trailing-byte rejection",
        limits=(("chunk_bytes", CHUNK_BYTES),),
        capacity=("owner-opened input and optional unpublished retention sink",),
        proofs=("tests/test_hook_results.py::test_artifact_stream_linear_work",),
        linear_proofs=("tests/test_hook_results.py::test_artifact_stream_linear_work",),
    )
)
def verify_artifact_stream(
    artifact: dict[str, Any], source: BinaryIO, *, destination: BinaryIO | None = None
) -> None:
    """Verify every byte; only the owner may publish the successfully verified sink.

    Streams are independently opened by the receiving owner after confinement,
    alias, regular-file and permission checks, and remain stable under its custody.
    A source begins at byte zero. An optional destination is empty and seekable;
    accepting an unseen prefix or retaining a stale suffix is never permitted.
    This helper neither opens a caller path nor authenticates those native facts.
    An I/O failure or mismatch leaves any partial sink unpublished. The fixed
    chunk bounds work per read, never total file size or collection extent.
    """
    validate("adapter.schema.json", artifact, "Artifact")
    if source.tell() != 0:
        raise ContractError("artifact source does not begin at byte zero")
    if destination is not None and (destination.tell() != 0 or destination.seek(0, 2) != 0):
        raise ContractError("artifact retention sink is not empty")
    expected_size, expected_digest = artifact["size_bytes"], artifact["digest"]
    size = 0
    checksum = hashlib.sha256()
    while True:
        chunk = source.read(CHUNK_BYTES)
        if not isinstance(chunk, bytes) or len(chunk) > CHUNK_BYTES:
            raise ContractError("artifact stream violates bounded byte reads")
        if not chunk:
            break
        size += len(chunk)
        if size > expected_size:
            raise ContractError("artifact size mismatch")
        checksum.update(chunk)
        if destination is not None and destination.write(chunk) != len(chunk):
            raise ContractError("incomplete artifact retention write")
    if size != expected_size or "sha256:" + checksum.hexdigest() != expected_digest:
        raise ContractError("artifact byte identity mismatch")
