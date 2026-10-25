"""Canonical synthetic plaintext bundle model. No age decryption or extraction.

Call only inside a trusted materialization boundary. Never log returned values.
The real publisher/reader/extractor and independent key custody are native work.
"""

from __future__ import annotations

import io
import tarfile
from typing import Any

from fishhat_contracts.validation import ContractError, canonical, strict_json, validate

MAX_ENTRY = 1_048_576
MAX_ARCHIVE = 32 * 1_048_576


def build_tar(manifest: dict[str, Any], values: dict[str, bytes]) -> bytes:
    validate("bundle-manifest.schema.json", manifest)
    if manifest["entries"] != sorted(manifest["entries"]) or set(values) != set(
        manifest["entries"]
    ):
        raise ContractError("manifest entry set/order mismatch")
    manifest_data = canonical(manifest)
    if len(manifest_data) > MAX_ENTRY:
        raise ContractError("manifest limit")
    contents = [("bundle.json", manifest_data)]
    for entry in manifest["entries"]:
        value = values[entry]
        if type(value) is not bytes or len(value) > MAX_ENTRY:
            raise ContractError("entry limit/type")
        contents.append(("secrets/" + entry, value))
    # Count actual USTAR headers, block padding, end markers and record padding.
    # Byte capacity must not become an incidental ceiling on small entry counts.
    block, record = tarfile.BLOCKSIZE, tarfile.RECORDSIZE
    payload_size = sum(block + ((len(v) + block - 1) // block) * block for _, v in contents)
    archive_size = ((payload_size + 2 * block + record - 1) // record) * record
    if archive_size > MAX_ARCHIVE:
        raise ContractError("archive limit")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in contents:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            info.type = tarfile.REGTYPE
            archive.addfile(info, io.BytesIO(data))
    result = buffer.getvalue()
    if len(result) > MAX_ARCHIVE:
        raise ContractError("archive limit")
    return result


def inspect_tar(
    data: bytes,
    expected_repository: dict[str, Any],
    expected_catalogue: str,
    expected_entries: list[str],
) -> tuple[dict[str, Any], dict[str, bytes]]:
    if type(data) is not bytes or len(data) > MAX_ARCHIVE or len(data) % 512:
        raise ContractError("invalid archive size")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            # The uncompressed archive byte bound also bounds header traversal;
            # all members remain visible regardless of the logical entry count.
            members = list(archive)
            if not members:
                raise ContractError("missing manifest")
            seen = set()
            for member in members:
                if member.name in seen or member.type != tarfile.REGTYPE or member.size > MAX_ENTRY:
                    raise ContractError("duplicate/nonregular/large entry")
                if member.pax_headers:
                    raise ContractError("extended header")
                seen.add(member.name)
            if members[0].name != "bundle.json":
                raise ContractError("manifest must be first")
            stream = archive.extractfile(members[0])
            if stream is None:
                raise ContractError("no manifest")
            manifest = strict_json(stream.read(MAX_ENTRY + 1), max_bytes=MAX_ENTRY)
            validate("bundle-manifest.schema.json", manifest)
            if (
                manifest["repository"] != expected_repository
                or manifest["catalogue_digest"] != expected_catalogue
            ):
                raise ContractError("wrong repository/catalogue")
            if manifest["entries"] != sorted(set(expected_entries)):
                raise ContractError("wrong logical entry set/order")
            names = ["bundle.json"] + ["secrets/" + entry for entry in manifest["entries"]]
            if [m.name for m in members] != names:
                raise ContractError("noncanonical paths/order")
            values = {}
            for entry, member in zip(manifest["entries"], members[1:], strict=True):
                stream = archive.extractfile(member)
                if stream is None:
                    raise ContractError("no entry body")
                values[entry] = stream.read(MAX_ENTRY + 1)
            if build_tar(manifest, values) != data:
                raise ContractError("noncanonical headers/padding/trailing data")
            return manifest, values
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ContractError("invalid tar") from exc


def select_asset(assets: list[dict[str, Any]]) -> dict[str, Any]:
    """Small model of named-asset ambiguity/type checks, not a Forgejo client."""
    matches = [a for a in assets if a.get("name") == "secrets.tar.age"]
    if len(matches) != 1:
        raise ContractError("missing/ambiguous current asset")
    asset = matches[0]
    if type(asset.get("id")) is not int or asset["id"] < 1:
        raise ContractError("asset ID must be positive integer, not bool")
    if type(asset.get("size")) is not int or not 0 < asset["size"] <= 64 * 1_048_576:
        raise ContractError("asset size invalid")
    return asset
