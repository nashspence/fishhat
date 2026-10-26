"""Explicitly signed synthetic Operation snapshots for contract tests."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_contracts.validation import digest
from fishhat_contracts.witness import sign


def seal_operation(record: dict[str, Any]) -> dict[str, Any]:
    """Seal an intentionally constructed test outcome, preserving its workflow binding."""
    body = {key: value for key, value in record["witness"].items() if key != "signature"}
    body.update(
        owner=deepcopy(record["owner"]),
        kind="acceptance" if record["state"] == "accepted" else "effect",
        state=record["state"],
        generation=record["generation"],
        subject_digest=digest({key: value for key, value in record.items() if key != "witness"}),
    )
    record["witness"] = sign(body, Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))
    return record
