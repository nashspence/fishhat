"""Portable identity vectors for selected Git blobs and their application Release."""

import hashlib
import json
import subprocess
from copy import deepcopy

import pytest
from fishhat_contracts.release_identity import validate_release, validate_source_closure
from fishhat_contracts.validation import ContractError, digest

from scripts.validation_timeouts import watchdog
from tests.support import FIXTURES

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source-closure.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Release",
    ],
    "scope": "real Git blob payloads and modes, complete source selection, and a fixed application release digest",
    "relationship": "candidate",
    "reason": "Fixed independently computed commitments and adverse inputs exercise portable identity without claiming native input selection or custody.",
    "claims": [],
}


def test_pinned_git_source_and_release_identity(tmp_path):
    def git(*args, data=b""):
        return subprocess.run(
            ["git", *args],
            cwd=tmp_path,
            input=data,
            capture_output=True,
            check=True,
            timeout=watchdog(10),
        ).stdout

    git("init", "--quiet", "--object-format=sha1")
    blobs = []
    for path, mode, data in (
        (b"app.yaml", b"100644", b"kind: App\n"),
        (b"start", b"100755", b"#!/bin/sh\nexit 0\n"),
    ):
        oid = git("hash-object", "-w", "--stdin", data=data).strip()
        blobs.append(mode + b" blob " + oid + b"\t" + path + b"\n")
    tree = git("mktree", data=b"".join(blobs)).strip()
    actor = b"Fixture <fixture@example.invalid> 1000000000 +0000"
    commit = (
        git(
            "hash-object",
            "-w",
            "-t",
            "commit",
            "--stdin",
            data=b"tree "
            + tree
            + b"\nauthor "
            + actor
            + b"\ncommitter "
            + actor
            + b"\n\nsource identity vector\n",
        )
        .decode()
        .strip()
    )
    release = json.loads((FIXTURES / "release-identity/release.json").read_bytes())
    source = release["sources"][0]
    assert commit == source["commit"]
    files = {}
    for entry in git("ls-tree", "-rz", commit).split(b"\0")[:-1]:
        header, path = entry.split(b"\t")
        mode, kind, oid = header.split()
        assert kind == b"blob"
        payload = git("cat-file", "blob", oid.decode())
        files[path.decode()] = {
            "mode": mode.decode(),
            "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        }
    validate_source_closure(source, dict(reversed(files.items())))
    validate_release(release, expected_digest=release["digest"])

    for changed in (
        {"app.yaml": files["app.yaml"]},
        {**files, "unselected": files["start"]},
        {**files, "start": {**files["start"], "mode": "100644"}},
        {**files, "start": {**files["start"], "mode": "120000"}},
        {**files, "start": {**files["start"], "digest": files["app.yaml"]["digest"]}},
    ):
        with pytest.raises(ContractError):
            validate_source_closure(source, changed)
    changed_release = deepcopy(release)
    changed_release["native_input_digest"] = release["profile_digest"]
    with pytest.raises(ContractError):
        validate_release(changed_release, expected_digest=release["digest"])
    changed_release["hook_closure"].reverse()
    changed_release["digest"] = digest({k: v for k, v in changed_release.items() if k != "digest"})
    with pytest.raises(ContractError, match="order"):
        validate_release(changed_release, expected_digest=changed_release["digest"])
