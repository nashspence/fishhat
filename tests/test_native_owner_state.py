"""Controlled observations challenge guest-tooling validation, never native custody."""

import copy
import hashlib
import json
from types import SimpleNamespace

import pytest

from scripts import native_linux_owner_state as native
from scripts.native_linux_guest import GuestBootError
from scripts.run_stats import valid_stats

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_linux_owner_state.py", "scripts/native_linux_enrollment.py"],
    "scope": "original observation custody, exact state/process identities, permission denials and failed cleanup rejection",
    "relationship": "no-product-claim",
    "reason": "Invented observations and fake transport test the observer and coordinator only. Guest programs are parsed but never executed; no credentials, account, SSH or native owner is used locally.",
    "claims": [],
}


def configuration():
    return {
        "enrollment": "fc72c95b-177a-430a-b5db-f313266b0bbb",
        "boot_id": "443bb91e-ef79-42d6-9a17-134f00165bd0",
        "bootstrap_sha256": "a" * 64,
        "peer_uid": 1002,
        "peer_gid": 1002,
    }


def observation(c):
    def node(inode, mode=0o700, kind="directory", uid=0, gid=0):
        return {"device": 23, "inode": inode, "uid": uid, "gid": gid, "mode": mode, "kind": kind}

    def file(inode, raw):
        return {
            **node(inode, 0o600, "regular"),
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

    created = {"directory": node(40), "entries": {}}
    state = {"directory": node(40), "entries": {"canary": file(41, native.CANARY)}}
    interrupted = {"directory": node(42), "entries": {}}
    prefix = "/var/lib/fishhat-state-fixture-" + c["enrollment"]
    existing = {
        "file": file(43, b"unrelated existing installation data"),
        "alias": {**node(44, 0o777, "link"), "target": prefix + "/state"},
        "directory": state,
    }
    return copy.deepcopy(
        {
            "scope": native.SCOPE,
            "status": "passed",
            "native_product_qualified": False,
            **{k: c[k] for k in ("enrollment", "boot_id", "bootstrap_sha256")},
            "observer_uid": 0,
            "observer_pid": 120,
            "primary_error": None,
            "cleanup_errors": [],
            "created": created,
            "before": state,
            "after": state,
            "state_final": state,
            "interrupted_final": interrupted,
            "existing_before": existing,
            "existing_after": existing,
            "interruption": {
                "pid": 121,
                "parent_pid": 120,
                "uid": 0,
                "boot_id": c["boot_id"],
                "returncode": -9,
                "joined": True,
                "state": interrupted,
            },
            "peer_pid": 122,
            "peer": {
                "pid": 122,
                "parent_pid": 120,
                "uids": [1002] * 3,
                "gids": [1002] * 3,
                "groups": [],
                "capabilities": "0" * 16,
                "administrative_refusal": True,
                "denied": [{"operation": op, "errno": 13} for op in native.DENIALS],
            },
            "rejections": [
                {
                    "case": name,
                    "error": "FileExistsError"
                    if index < 4
                    else "NotADirectoryError"
                    if index == 6
                    else "ValueError",
                    "errno": 17 if index < 4 else 20 if index == 6 else None,
                }
                for index, name in enumerate(native.REJECTIONS)
            ],
            "ancestors": [
                {"case": name, "identity": node(50 + index, mode, kind, uid, gid)}
                for index, (name, uid, gid, mode, kind) in enumerate(
                    [
                        ("foreign-ancestor", 1002, 1002, 0o700, "directory"),
                        ("writable-ancestor", 0, 0, 0o770, "directory"),
                        ("symlink-ancestor", 0, 0, 0o777, "link"),
                    ]
                )
            ],
            "cleanup": [
                {"path": path, "device": 23, "inode": 60 + index, "absent": True}
                for index, path in enumerate(
                    ["/tmp/fishhat-state-fixture-" + c["enrollment"], prefix]
                )
            ],
        }
    )


def test_controlled_complete_observation_is_accepted_without_native_claim():
    c = configuration()
    value = observation(c)
    assert native.verify_observation(value, c) is None
    assert value["native_product_qualified"] is False


@pytest.mark.parametrize(
    "path,replacement",
    [
        (("scope",), "foreign"),
        (("status",), "failed"),
        (("native_product_qualified",), True),
        (("enrollment",), "foreign"),
        (("boot_id",), "foreign"),
        (("bootstrap_sha256",), "b" * 64),
        (("observer_uid",), 1002),
        (("primary_error",), {"type": "failure"}),
        (("cleanup_errors",), [{"type": "failure"}]),
        (("created", "directory", "mode"), 0o755),
        (("created", "directory", "uid"), 1002),
        (("created", "entries"), {"unexpected": {}}),
        (("after", "entries", "canary", "sha256"), "0" * 64),
        (("state_final", "directory", "inode"), 900),
        (("interrupted_final", "entries"), {"unexpected": {}}),
        (("existing_after", "file", "sha256"), "0" * 64),
        (("peer", "uids"), [0, 0, 0]),
        (("peer", "gids"), [0, 0, 0]),
        (("peer", "groups"), [0]),
        (("peer", "capabilities"), "0000000000000001"),
        (("peer", "administrative_refusal"), False),
        (("peer", "denied"), []),
        (("peer", "denied", 0, "errno"), 2),
        (("peer", "parent_pid"), 999),
        (("peer_pid",), 999),
        (("observer_pid",), True),
        (("interruption", "pid"), 122),
        (("interruption", "parent_pid"), 999),
        (("interruption", "joined"), False),
        (("interruption", "returncode"), 0),
        (("interruption", "boot_id"), "foreign"),
        (("rejections",), []),
        (("rejections", 0, "error"), "ValueError"),
        (("rejections", 6, "errno"), 2),
        (("ancestors",), []),
        (("ancestors", 0, "identity", "uid"), 0),
        (("cleanup", 0, "path"), "/unrelated"),
        (("cleanup", 0, "absent"), False),
        (("cleanup", 0, "inode"), 61),
    ],
    ids=[
        "scope",
        "status",
        "qualification",
        "enrollment",
        "boot",
        "bootstrap",
        "observer-uid",
        "primary-failure",
        "cleanup-failure",
        "state-mode",
        "state-owner",
        "unexpected-state",
        "changed-canary",
        "changed-inode",
        "interrupted-content",
        "existing-data",
        "peer-uid",
        "peer-gid",
        "peer-groups",
        "peer-caps",
        "admin-refusal",
        "missing-denials",
        "wrong-denial",
        "peer-parent",
        "peer-pid",
        "observer-pid",
        "duplicate-child",
        "interrupted-parent",
        "unjoined",
        "wrong-exit",
        "interrupted-boot",
        "missing-refusals",
        "wrong-refusal",
        "symlink-refusal",
        "missing-ancestors",
        "wrong-ancestor",
        "cleanup-path",
        "cleanup-presence",
        "cleanup-alias",
    ],
)
def test_incomplete_forged_or_failed_observations_are_rejected(path, replacement):
    c = configuration()
    value = observation(c)
    # Independent JSON decoding breaks repeated fixture-object references just
    # as the real serialized reply does.
    value = json.loads(json.dumps(value))
    row = value
    for part in path[:-1]:
        row = row[part]
    row[path[-1]] = replacement
    with pytest.raises(GuestBootError):
        native.verify_observation(value, c)


@pytest.mark.parametrize("reply", ["accepted", "invalid-json", "forged", "transport-error"])
def test_guarded_original_reply_and_statistics_are_retained(reply):
    c = configuration()
    guest = SimpleNamespace(
        enrollment=c["enrollment"],
        accounts=("admin", "peer"),
        observed={"boot_id": c["boot_id"], "accounts": {"peer": {"uid": 1002, "gid": 1002}}},
    )
    originals = []

    def guarded(argv, enrollment, boot, *, nominal):
        assert argv[:6] == ["/usr/bin/python3", "-I", "-S", "-B", "-c", native.REMOTE]
        assert enrollment == c["enrollment"] and boot == c["boot_id"] and nominal == 120
        config = json.loads(argv[-1])
        assert (
            config["peer_program"] == native.PEER
            and config["interrupt_program"] == native.INTERRUPTED
        )
        if reply == "transport-error":
            raise RuntimeError("controlled transport failure")
        value = observation(config)
        if reply == "forged":
            value["peer"]["groups"] = [0]
        raw = "not-json\n" if reply == "invalid-json" else json.dumps(value, sort_keys=True) + "\n"
        originals.append(raw)
        return raw

    guest.guarded = guarded
    report = {}
    if reply == "accepted":
        native.qualify_state(guest, report)
        assert report["status"] == "passed"
    else:
        with pytest.raises((GuestBootError, RuntimeError)):
            native.qualify_state(guest, report)
        assert report["status"] == "failed"
    assert report["native_product_qualified"] is False
    assert valid_stats(report["qualification_statistics"])
    assert report["qualification_statistics"]["scope"] == "process-excludes-children"
    if originals:
        assert report["original_reply_sha256"] == hashlib.sha256(originals[0].encode()).hexdigest()
        if reply == "invalid-json":
            assert report["unparsed_original_reply"] == originals[0]
        else:
            assert report["original_observation"] == json.loads(originals[0])


def test_unverified_guest_never_executes_observation():
    guest = SimpleNamespace(observed=None)
    with pytest.raises(GuestBootError, match="guest-not-verified"):
        native.qualify_state(guest, {})


@pytest.mark.parametrize("name", ["PEER", "INTERRUPTED", "REMOTE"])
def test_guest_programs_parse_without_local_execution(name):
    compile(getattr(native, name), "<unexecuted-disposable-guest-program>", "exec")
