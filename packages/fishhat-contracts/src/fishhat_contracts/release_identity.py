"""Application release identity from independently selected immutable inputs."""

from itertools import pairwise
from typing import Any

from .host_intent import check_destination_tree
from .validation import ContractError, canonical, digest, validate


def validate_source_closure(source: dict[str, Any], files: dict[str, dict[str, str]]) -> None:
    """Verify the source commitment against the receiver's complete pinned-tree selection.

    The caller resolves the approved dependency closure and obtains each regular
    blob's actual mode and SHA-256 from the pinned tree. A manifest supplied by
    the source or provider alone cannot establish that membership or byte custody.
    """
    validate("common.schema.json", source, "Source")
    manifest = {
        "format": "fishhat.source-closure/v1",
        "entrypoint": source["entrypoint"],
        "files": files,
    }
    validate("source-closure.schema.json", manifest)
    check_destination_tree("/" + path for path in files)
    if source["entrypoint"] not in files or source["closure_digest"] != digest(manifest):
        raise ContractError("source closure differs from selected Git inputs")


def validate_release(release: dict[str, Any], *, expected_digest: str) -> None:
    """Check a complete Release against its independently reviewed material identity."""
    validate("records.schema.json", release, "Release")
    if any(a >= b for a, b in pairwise(map(canonical, release["sources"]))):
        raise ContractError("release sources must be in strictly increasing JCS byte order")
    for name in ("secret_receipts", "hook_closure", "recovery_closure"):
        if any(a >= b for a, b in pairwise(release[name])):
            raise ContractError("release material must be in strictly increasing digest order")
    if release["digest"] != expected_digest or release["digest"] != digest(
        {key: value for key, value in release.items() if key != "digest"}
    ):
        raise ContractError("application release identity mismatch")
