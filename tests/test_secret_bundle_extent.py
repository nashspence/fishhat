"""Complete synthetic plaintext bundle traversal within the declared byte capacities."""

import io
import json
import tarfile

import pytest
from fishhat_contracts import secrets
from fishhat_contracts.validation import MAX_BYTES, ContractError, canonical

from tests.support import FIXTURES

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/bundle-manifest.schema.json"
    ],
    "scope": "complete canonical USTAR entry extent and symmetric manifest/archive byte capacity",
    "relationship": "candidate",
    "reason": "Synthetic in-memory archives exercise complete inspection and late corruption; no decryption, filesystem extraction, secret publication or native custody is established.",
    "claims": [],
}


def bundle(count, *, long_names=False):
    manifest = json.loads((FIXTURES / "bundle-manifest.json").read_text())
    suffix = "-" + "x" * 51 if long_names else ""
    manifest["entries"] = [f"secret-{i:05d}{suffix}" for i in range(count)]
    return manifest, {name: f"synthetic-{i}".encode() for i, name in enumerate(manifest["entries"])}


def inspect(data, manifest):
    return secrets.inspect_tar(
        data, manifest["repository"], manifest["catalogue_digest"], manifest["entries"]
    )


def raw_tar(contents, *, symlink_last=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for number, (name, value) in enumerate(contents):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(value), 0o600
            if symlink_last and number == len(contents) - 1:
                info.type, info.linkname, info.size = tarfile.SYMTYPE, "bundle.json", 0
            archive.addfile(info, io.BytesIO(value))
    return output.getvalue()


@pytest.mark.parametrize("count", [0, 257, 5000])
def test_reader_retains_every_declared_entry_beyond_one_frame(count):
    manifest, values = bundle(count, long_names=True)
    encoded = secrets.build_tar(manifest, values)
    if count == 5000:
        assert MAX_BYTES < len(encoded) <= secrets.MAX_ARCHIVE
        assert len(canonical(manifest)) < secrets.MAX_ENTRY
    assert inspect(encoded, manifest) == (manifest, values)


@pytest.mark.parametrize("corruption", ["duplicate", "unlisted", "wrong-order", "symlink"])
def test_late_noncanonical_member_is_inspected(corruption):
    manifest, values = bundle(300)
    contents = [("bundle.json", canonical(manifest))] + [
        ("secrets/" + name, value) for name, value in values.items()
    ]
    if corruption == "duplicate":
        contents[-1] = contents[1]
    elif corruption == "unlisted":
        contents[-1] = ("secrets/unlisted", b"synthetic")
    elif corruption == "wrong-order":
        contents[-1], contents[-2] = contents[-2], contents[-1]
    encoded = raw_tar(contents, symlink_last=corruption == "symlink")
    with pytest.raises(ContractError):
        inspect(encoded, manifest)


def test_reader_and_writer_reject_the_same_oversized_manifest():
    manifest, values = bundle(17000, long_names=True)
    encoded_manifest = canonical(manifest)
    assert len(encoded_manifest) > secrets.MAX_ENTRY
    with pytest.raises(ContractError, match="manifest limit"):
        secrets.build_tar(manifest, values)
    with pytest.raises(ContractError, match="large entry"):
        inspect(raw_tar([("bundle.json", encoded_manifest)]), manifest)


def test_archive_capacity_counts_actual_ustar_bytes(monkeypatch):
    manifest, _ = bundle(300)
    values = {name: b"" for name in manifest["entries"]}
    expected = raw_tar(
        [("bundle.json", canonical(manifest))]
        + [("secrets/" + name, value) for name, value in values.items()]
    )
    # Exercise a smaller explicit capacity with many small members, so a
    # conservative per-entry estimate cannot create an unrelated count ceiling.
    monkeypatch.setattr(secrets, "MAX_ARCHIVE", len(expected))
    assert secrets.build_tar(manifest, values) == expected
    assert inspect(expected, manifest) == (manifest, values)
    monkeypatch.setattr(secrets, "MAX_ARCHIVE", len(expected) - tarfile.BLOCKSIZE)
    with pytest.raises(ContractError, match="archive limit"):
        secrets.build_tar(manifest, values)
    with pytest.raises(ContractError, match="archive size"):
        inspect(expected, manifest)
