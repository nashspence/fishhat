"""Fixture transport and observation rejection; fabricated replies are not native proof."""

import ast
import base64
import copy
import hashlib
import itertools
import json

import pytest

from scripts import native_linux_install_inputs as native
from scripts.native_linux_guest import GuestBootError
from scripts.run_stats import valid_stats

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_linux_install_inputs.py", "scripts/native_linux_enrollment.py"],
    "scope": "enrolled fixture invocation, generated program syntax and rejection of fabricated observations",
    "relationship": "no-product-claim",
    "reason": "Fake transport replies test fixture wiring and evidence rejection only. No guest program, credential change, SSH, native account or native installation is executed locally; real permission witnesses require the enrolled hosted Linux run.",
    "claims": [],
}


def observation(configuration):
    inode = itertools.count(10)

    def metadata(uid, gid, mode, kind):
        return {
            "device": 42,
            "inode": next(inode),
            "uid": uid,
            "gid": gid,
            "mode": mode,
            "kind": kind,
        }

    def inventory(files, uid=0, gid=0):
        return {
            "files": {
                name: {
                    **metadata(uid, gid, 0o600, "regular"),
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
                for name, raw in files.items()
            },
            "directories": {
                name: metadata(uid, gid, 0o700, "directory") for name in (".", "wheels", "locks")
            },
        }

    files = {name: base64.b64decode(raw) for name, raw in configuration["files"].items()}
    uid, gid = configuration["peer_uid"], configuration["peer_gid"]
    before = inventory(files)
    source = inventory(files, uid, gid)
    after_source = copy.deepcopy(source)
    for name in ("locks/fixture.txt", "wheels/fixture.whl"):
        after_source["files"][name].update(
            bytes=len(b"caller replacement"),
            sha256=hashlib.sha256(b"caller replacement").hexdigest(),
        )
    rejected = []
    for name in native.REJECTIONS:
        kind, code = (
            ("NotADirectoryError", 20)
            if name in ("source-root-symlink", "symlink-ancestor")
            else ("FileExistsError", 17)
            if name.startswith("existing-")
            else ("ValueError", None)
        )
        rejected.append({"case": name, "error": kind, "errno": code})
    ancestors = [
        {
            "case": case,
            "ancestor": metadata(owner, group, mode, kind),
            "leaf_parent": metadata(0, 0, 0o700, "directory"),
        }
        for case, owner, group, mode, kind in (
            ("foreign-ancestor", uid, gid, 0o700, "directory"),
            ("writable-ancestor", 0, 0, 0o770, "directory"),
            ("symlink-ancestor", 0, 0, 0o777, "other"),
        )
    ]
    existing = []
    for kind, mode, node_kind in (
        ("directory", 0o700, "directory"),
        ("file", 0o600, "regular"),
        ("symlink", 0o777, "other"),
    ):
        content = inventory({"." if kind == "file" else "keep": b"retained existing input"})
        content["directories"] = {} if kind == "file" else {".": metadata(0, 0, 0o700, "directory")}
        retained = {"node": metadata(0, 0, mode, node_kind), "content": content}
        existing.append(
            {"case": "existing-" + kind, "before": retained, "after": copy.deepcopy(retained)}
        )
    return {
        "scope": native.SCOPE,
        "status": "passed",
        "native_product_qualified": False,
        **{
            name: configuration[name]
            for name in ("enrollment", "boot_id", "bootstrap_sha256", "manifest_sha256")
        },
        "observer_uid": 0,
        "observer_pid": 100,
        "peer_pid": 101,
        "primary_error": None,
        "cleanup_errors": [],
        "before": before,
        "after": copy.deepcopy(before),
        "source_before": source,
        "source_after": after_source,
        "peer": {
            "pid": 101,
            "parent_pid": 100,
            "uids": [uid] * 3,
            "gids": [gid] * 3,
            "groups": [],
            "effective_capabilities": "0000000000000000",
            "administrative_refusal": True,
            "denied": [{"operation": name, "errno": 13} for name in ("write", "unlink")],
        },
        "rejections": rejected,
        "ancestor_observations": ancestors,
        "preserved_existing": existing,
        "unrelated_canary": {
            **metadata(0, 0, 0o600, "regular"),
            "sha256": hashlib.sha256(b"unrelated retained fixture input").hexdigest(),
        },
        "cleanup": [
            {"identity": metadata(owner, group, 0o700, "directory"), "absent": True}
            for owner, group in ((uid, gid), (0, 0))
        ],
    }


class FakeGuest:
    enrollment = "11111111-1111-4111-8111-111111111111"
    accounts = ("fixture-admin", "fixture-peer")

    def __init__(self, change=None):
        self.observed = {
            "boot_id": "22222222-2222-4222-8222-222222222222",
            "accounts": {"fixture-peer": {"uid": 1002, "gid": 1002}},
        }
        self.change = change
        self.calls = []

    def guarded(self, command, enrollment, boot, *, deadline, nominal):
        assert command[:5] == ["/usr/bin/python3", "-I", "-S", "-B", "-c"]
        assert (
            command[5] == native.REMOTE
            and enrollment == self.enrollment
            and boot == self.observed["boot_id"]
        )
        assert nominal == 60 and deadline.remaining() > 0
        configuration = json.loads(command[6])
        self.calls.append(configuration)
        value = observation(configuration)
        if self.change:
            self.change(value)
        return json.dumps(value)


def test_fixture_uses_current_enrollment_and_retains_original_controller_statistics():
    guest, report = FakeGuest(), {}
    native.qualify_inputs(guest, report)
    assert len(guest.calls) == 1
    configuration = guest.calls[0]
    assert (
        configuration["bootstrap_sha256"]
        == hashlib.sha256(base64.b64decode(configuration["bootstrap"])).hexdigest()
    )
    assert report["observation"] == json.loads(report["original_reply"])
    assert report["status"] == "passed" and report["native_product_qualified"] is False
    assert (
        valid_stats(report["statistics"])
        and report["statistics"]["scope"] == "process-excludes-children"
    )


@pytest.mark.parametrize("program", ["REMOTE", "PEER"])
def test_generated_guest_program_is_syntax_checked_without_execution(program):
    assert isinstance(ast.parse(getattr(native, program)), ast.Module)


def damage(value, kind):
    if kind == "enrollment":
        value["enrollment"] = "33333333-3333-4333-8333-333333333333"
    elif kind == "boot":
        value["boot_id"] = "33333333-3333-4333-8333-333333333333"
    elif kind == "boolean-root":
        value["observer_uid"] = False
    elif kind == "bytes":
        for state in ("before", "after"):
            value[state]["files"]["wheels/fixture.whl"]["sha256"] = "0" * 64
    elif kind == "peer-root":
        value["peer"]["uids"] = [0, 0, 0]
    elif kind == "peer-capabilities":
        value["peer"]["effective_capabilities"] = "1"
    elif kind == "allowed-write":
        value["peer"]["denied"][0]["errno"] = 0
    elif kind == "missing-rejection":
        value["rejections"].pop()
    elif kind == "missing-cleanup":
        value["cleanup"][0]["absent"] = False
    elif kind == "source-owner":
        value["source_before"]["files"]["wheels/fixture.whl"]["uid"] = 0
    elif kind == "leaf-parent":
        value["ancestor_observations"][0]["leaf_parent"]["uid"] = 1002
    elif kind == "retained-bytes":
        for state in ("before", "after"):
            value["preserved_existing"][0][state]["content"]["files"]["keep"]["sha256"] = "0" * 64
    elif kind == "failed-observation":
        value["status"] = "failed"
    else:
        value["unreviewed"] = True


@pytest.mark.parametrize(
    "kind",
    [
        "enrollment",
        "boot",
        "boolean-root",
        "bytes",
        "peer-root",
        "peer-capabilities",
        "allowed-write",
        "missing-rejection",
        "missing-cleanup",
        "source-owner",
        "leaf-parent",
        "retained-bytes",
        "failed-observation",
        "unknown-field",
    ],
)
def test_fixture_refuses_incomplete_or_inconsistent_observations_and_retains_original(kind):
    guest, report = FakeGuest(lambda value: damage(value, kind)), {}
    with pytest.raises(GuestBootError):
        native.qualify_inputs(guest, report)
    assert report["status"] == "failed" and report["original_reply"]
    assert valid_stats(report["statistics"])


def test_unobserved_guest_never_runs_the_probe():
    guest = FakeGuest()
    guest.observed = None
    report = {}
    with pytest.raises(GuestBootError, match="guest-not-verified"):
        native.qualify_inputs(guest, report)
    assert guest.calls == [] and report["status"] == "failed"
    assert valid_stats(report["statistics"])
