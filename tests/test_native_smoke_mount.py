from __future__ import annotations

import copy
import dataclasses
import json
import os
import stat
import time
import uuid
from pathlib import Path

import pytest

from scripts import native_smoke_mount as mounts
from scripts.validation_timeouts import watchdog

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": ["scripts/native_smoke_mount.py"],
    "scope": "complete mount observations and exact disposable fixture identity",
    "relationship": "no-product-claim",
    "reason": "Isolated mount records test refusal and observation semantics; they do not execute or qualify native mounts.",
    "claims": [],
}

ROOT = "1 0 8:1 / / rw - ext4 /dev/root rw\n"
XFS = "2 1 7:3 / /owned/mount rw,nosuid,nodev - xfs /dev/loop3 rw,prjquota\n"


@pytest.fixture
def observed():
    enrollment = str(uuid.uuid4())
    namespace = {"device": 4, "inode": 1}
    directory = {
        "device": os.makedev(7, 3),
        "inode": 128,
        "uid": 0,
        "gid": 0,
        "mode": stat.S_IFDIR | 0o755,
    }
    loop = {
        "image": {"device": 47, "inode": 51},
        "association": {"node": {"rdevice": os.makedev(7, 3)}, "enrollment": enrollment},
    }
    view = mounts.table(ROOT + XFS)
    end = time.monotonic() + watchdog(10)
    identity = mounts.MountIdentity.capture(
        enrollment,
        namespace,
        view,
        directory,
        loop,
        Path("/owned/mount"),
        end,
    )
    return identity, namespace, view, directory, loop, end


def test_current_exact_identity_and_json_claim_are_accepted(observed):
    identity, namespace, view, directory, loop, end = observed
    claim = json.loads(json.dumps(identity.claim()))
    identity.check(claim, namespace, view, directory, loop, end)
    assert not identity.absent(namespace, view, end)
    assert "/owned/mount" not in json.dumps(claim)
    assert "/dev/loop3" not in json.dumps(claim)


@pytest.mark.parametrize(
    ("encoded", "decoded"),
    [
        (r"a\040b", "a b"),
        (r"a\011b", "a\tb"),
        (r"a\012b", "a\nb"),
        (r"a\134b", "a\\b"),
        (r"a\134040b", r"a\040b"),
    ],
    ids=["space", "tab", "newline", "backslash", "literal-escape"],
)
def test_kernel_path_escapes_are_decoded_once(encoded, decoded):
    assert mounts.unescape(encoded) == decoded


@pytest.mark.parametrize(
    "value",
    [r"a\999b", r"a\000b", "a\\", r"a\041b"],
    ids=["unknown", "nul", "incomplete", "unescaped-backslash"],
)
def test_unavailable_path_encoding_is_refused(value):
    with pytest.raises(ValueError, match="mount-path-observation-unavailable"):
        mounts.unescape(value)


@pytest.mark.parametrize(
    "row",
    [
        "",
        "2 1 7:3 / /owned/mount rw xfs /dev/loop3 rw\n",
        XFS.replace("7:3", "7:3:4"),
        XFS.replace("2 1", "02 1"),
        XFS.replace("rw,nosuid,nodev", "rw,rw"),
        XFS.replace(" /owned/mount ", " owned/mount "),
        XFS.replace(" - xfs", " future:1 - xfs"),
        XFS.replace(" - xfs", " shared:1 shared:2 - xfs"),
    ],
    ids=[
        "empty",
        "separator",
        "device",
        "noncanonical-id",
        "duplicate-option",
        "relative-target",
        "unknown-propagation",
        "duplicate-propagation",
    ],
)
def test_invalid_or_ambiguous_kernel_view_is_unavailable(row):
    with pytest.raises(ValueError):
        mounts.table(row if not row else ROOT + row)


def test_repeated_mount_id_is_not_a_valid_view():
    with pytest.raises(ValueError, match="mount-inventory-ambiguous"):
        mounts.table(ROOT + XFS + XFS)


@pytest.mark.parametrize(
    "propagation",
    ["shared:1", "master:1", "propagate_from:1"],
    ids=["shared", "slave", "propagation-source"],
)
def test_shared_or_slave_mounts_refuse_private_namespace_claim(propagation):
    view = mounts.table(ROOT.replace(" - ext4", " " + propagation + " - ext4") + XFS)
    with pytest.raises(ValueError, match="mount-namespace-not-private"):
        mounts.private(view)


def test_complete_view_retains_entries_beyond_a_page(observed):
    identity, namespace, _, _, _, end = observed
    extra = "".join(
        f"{index} 1 0:{index} / /unrelated/{index} rw - tmpfs none rw\n" for index in range(3, 1027)
    )
    view = mounts.table(ROOT + extra + XFS)
    assert len(view) == 1026
    assert not identity.absent(namespace, view, end)
    del view[2]
    assert identity.absent(namespace, view, end)
    view[2000] = dataclasses.replace(identity.mount, identifier=2000, target="/unrelated/alias")
    assert not identity.absent(namespace, view, end)


@pytest.mark.parametrize("field", ["namespace", "root", "loop", "mount", "target", "stack"])
def test_substituted_observations_refuse_the_original_claim(observed, field):
    identity, namespace, view, directory, loop, end = observed
    namespace, view, directory, loop = copy.deepcopy((namespace, view, directory, loop))
    if field == "namespace":
        namespace["inode"] += 1
    elif field == "root":
        directory["inode"] += 1
    elif field == "loop":
        loop["image"]["inode"] += 1
    elif field == "mount":
        view[2] = dataclasses.replace(view[2], identifier=3)
    elif field == "target":
        view[2] = dataclasses.replace(view[2], target="/foreign")
    else:
        view[3] = dataclasses.replace(view[2], identifier=3)
    with pytest.raises(ValueError):
        identity.check(identity.claim(), namespace, view, directory, loop, end)


@pytest.mark.parametrize("field", ["enrollment", "namespace-bool", "root-bool", "extra"])
def test_foreign_and_type_confused_claims_are_refused(observed, field):
    identity, namespace, view, directory, loop, end = observed
    claim = identity.claim()
    if field == "enrollment":
        claim["enrollment"] = str(uuid.uuid4())
    elif field == "namespace-bool":
        claim["namespace"]["inode"] = True
    elif field == "root-bool":
        claim["mount"]["directory"]["uid"] = False
    else:
        claim["extra"] = True
    with pytest.raises(ValueError, match="mount-foreign-claim-refused"):
        identity.check(claim, namespace, view, directory, loop, end)


def test_claim_and_input_mutations_do_not_change_retained_identity(observed):
    identity, namespace, view, directory, loop, end = observed
    original = identity.claim()
    identity.claim()["loop"]["image"]["inode"] += 1
    namespace["inode"] += 1
    directory["inode"] += 1
    loop["image"]["inode"] += 1
    assert identity.claim() == original
    identity.check(original, identity.namespace, view, identity.directory, identity.loop, end)


def test_empty_inventory_is_unavailable_rather_than_absent(observed):
    identity, namespace, _, _, _, end = observed
    with pytest.raises(ValueError, match="mount-view-unavailable"):
        identity.absent(namespace, {}, end)


def test_expired_observation_is_not_accepted(observed):
    identity, namespace, view, directory, loop, _ = observed
    with pytest.raises(ValueError, match="loop-deadline-unavailable"):
        identity.check(identity.claim(), namespace, view, directory, loop, time.monotonic() - 1)
