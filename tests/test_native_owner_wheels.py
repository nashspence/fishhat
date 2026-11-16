"""Forged observations challenge tooling; no guest program executes locally."""

import ast
import copy
import hashlib
import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_linux_owner_wheels as native
from scripts.native_linux_guest import GuestBootError
from scripts.run_stats import valid_stats

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_owner_wheels.py",
        "scripts/native_linux_enrollment.py",
        ".github/workflows/ci.yml",
    ],
    "scope": "complete candidate/payload and isolated import observation custody, actual process/refusal identities and failed cleanup rejection",
    "relationship": "no-product-claim",
    "reason": "Invented observations and fake transport exercise observer/coordinator predicates. Guest programs are parsed but never executed; no native module, selected runtime, SSH, account or privileged installation runs locally.",
    "claims": [],
}


def configuration():
    return {
        "enrollment": "fc72c95b-177a-430a-b5db-f313266b0bbb",
        "boot_id": "443bb91e-ef79-42d6-9a17-134f00165bd0",
        "bootstrap_sha256": "a" * 64,
        "input_sha256": "b" * 64,
        "manifest_sha256": "c" * 64,
        "runtime_executable_sha256": "d" * 64,
        "peer_uid": 1002,
        "peer_gid": 1002,
        "manifest": {"components": {"host": {"dependencies": list(native.MODULES)}}},
    }


def observation(c):
    prefix = "/var/lib/fishhat-wheels-fixture-" + c["enrollment"]
    poison = "/tmp/fishhat-wheels-fixture-" + c["enrollment"]
    library = prefix + "/installed/lib"
    nodes = {}
    next_inode = [20]

    def node(kind="directory", mode=0o555):
        next_inode[0] += 1
        return {
            "device": 23,
            "inode": next_inode[0],
            "uid": 0,
            "gid": 0,
            "kind": kind,
            "mode": mode,
        }

    def file(name):
        if name not in nodes:
            raw = b"synthetic installed bytes"
            nodes[name] = {
                **node("regular", 0o444),
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        return {"path": library + "/" + name.removeprefix("lib/"), "sha256": nodes[name]["sha256"]}

    nodes["."] = node()
    modules = {
        name: {"module": module, **file("lib/" + module + ".py")}
        for name, module in native.MODULES.items()
    }
    binaries = {
        name: file("lib/" + name + ".so")
        for name in (
            "_cffi_backend",
            "yaml._yaml",
            "markupsafe._speedups",
            "cryptography.hazmat.bindings._rust",
            "rpds.rpds",
        )
    }
    c["expected_payloads"] = {
        name: {k: row[k] for k in ("kind",) if k in row}
        | {k: row[k] for k in ("bytes", "sha256") if k in row}
        for name, row in nodes.items()
    }
    partial = {
        ".": {**node(), "mode": 0o700},
        "lib/partial": {
            **node("regular", 0o600),
            "bytes": 5,
            "sha256": hashlib.sha256(b"bytes").hexdigest(),
        },
    }
    existing = {
        "file": {
            **node("regular", 0o600),
            "sha256": hashlib.sha256(b"unrelated existing bytes").hexdigest(),
        },
        "alias": {**node("link", 0o777), "target": prefix + "/installed"},
    }

    def imported(peer):
        uid = c["peer_uid"] if peer else 0
        gid = c["peer_gid"] if peer else 0
        return {
            "pid": 123 if peer else 122,
            "parent_pid": 120,
            "uids": [uid] * 3,
            "gids": [gid] * 3,
            "groups": [] if peer else [0],
            "capabilities": "0" * 16 if peer else "f" * 16,
            "executable": prefix + "/runtime/python/bin/python3.12",
            "version": [3, 12, 16],
            "cwd": poison,
            "isolated": 1,
            "no_site": 1,
            "no_bytecode": 1,
            "sys_path": [library, prefix + "/runtime/python/lib/python3.12"],
            "modules": modules,
            "binaries": binaries,
            "cli_status": 0,
            "cli_info": {
                "tool": "host-ops",
                "native_mutations": False,
                "production_qualified": False,
            },
            "poison_marker_absent": True,
            "denied": [{"operation": name, "errno": 13} for name in native.DENIALS] if peer else [],
            "administrative_refusal": peer,
        }

    return copy.deepcopy(
        {
            "scope": native.SCOPE,
            "status": "passed",
            "native_product_qualified": False,
            **{
                key: c[key]
                for key in (
                    "enrollment",
                    "boot_id",
                    "bootstrap_sha256",
                    "input_sha256",
                    "manifest_sha256",
                )
            },
            "observer_pid": 120,
            "observer_uid": 0,
            "primary_error": None,
            "cleanup_errors": [],
            "cleanup": [
                {"path": path, "device": 23, "inode": 1000 + i, "absent": True}
                for i, path in enumerate((poison, prefix))
            ],
            "runtime": {
                "path": prefix + "/runtime/python/bin/python3.12",
                "sha256": c["runtime_executable_sha256"],
                "archive_sha256": native.OWNER_PYTHON_SHA256,
            },
            "manifest": c["manifest"],
            "interruption": {
                "pid": 121,
                "parent_pid": 120,
                "uid": 0,
                "boot_id": c["boot_id"],
                "returncode": -9,
                "joined": True,
                "inventory": partial,
            },
            "rejections": [
                {"case": case, "error": "FileExistsError", "errno": 17}
                for case in (
                    "interrupted-destination",
                    "existing-directory",
                    "existing-file",
                    "existing-symlink",
                )
            ],
            "before": nodes,
            "after": nodes,
            "interrupted_final": partial,
            "existing_before": existing,
            "existing_after": existing,
            "root_pid": 122,
            "root": imported(False),
            "peer_pid": 123,
            "peer": imported(True),
        }
    )


def test_controlled_observation_has_no_native_qualification():
    c = configuration()
    value = observation(c)
    assert native.verify_observation(value, c) is None
    assert value["native_product_qualified"] is False


@pytest.mark.parametrize(
    "case",
    [
        "scope",
        "status",
        "qualification",
        "enrollment",
        "boot",
        "bootstrap",
        "input",
        "manifest-digest",
        "manifest",
        "runtime",
        "runtime-digest",
        "owner",
        "permissions",
        "digest",
        "missing-payload",
        "extra-payload",
        "alias",
        "changed-after",
        "interruption-join",
        "interruption-exit",
        "interruption-parent",
        "interruption-boot",
        "interruption-public",
        "interruption-empty",
        "interruption-alias",
        "process",
        "parent",
        "peer-uid",
        "peer-groups",
        "peer-caps",
        "denial",
        "denial-errno",
        "admin",
        "isolated",
        "site",
        "bytecode",
        "poison",
        "path",
        "module",
        "module-digest",
        "binary",
        "binary-digest",
        "cli",
        "existing",
        "refusal",
        "cleanup",
        "cleanup-errors",
        "primary",
        "unreported",
    ],
)
def test_forged_or_incomplete_observation_is_rejected(case):
    c = configuration()
    value = observation(c)

    def set_field(path, changed):
        target = value
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = changed

    actions = {
        "scope": lambda: set_field(("scope",), "unscoped"),
        "status": lambda: set_field(("status",), "failed"),
        "qualification": lambda: set_field(("native_product_qualified",), True),
        "enrollment": lambda: set_field(("enrollment",), "changed"),
        "boot": lambda: set_field(("boot_id",), "changed"),
        "bootstrap": lambda: set_field(("bootstrap_sha256",), "changed"),
        "input": lambda: set_field(("input_sha256",), "changed"),
        "manifest-digest": lambda: set_field(("manifest_sha256",), "changed"),
        "manifest": lambda: set_field(("manifest",), {}),
        "runtime": lambda: set_field(("runtime", "path"), "/caller/python"),
        "runtime-digest": lambda: set_field(
            ("runtime", "sha256"),
            "e" * 64,
        ),
        "owner": lambda: set_field(("before", ".", "uid"), 1002),
        "permissions": lambda: set_field(("before", ".", "mode"), 511),
        "digest": lambda: set_field(
            ("before", "lib/alembic.py", "sha256"),
            "e" * 64,
        ),
        "changed-after": lambda: set_field(("after",), {}),
        "interruption-join": lambda: set_field(("interruption", "joined"), False),
        "interruption-exit": lambda: set_field(("interruption", "returncode"), 0),
        "interruption-parent": lambda: set_field(("interruption", "parent_pid"), 99),
        "interruption-boot": lambda: set_field(("interruption", "boot_id"), "changed"),
        "interruption-public": lambda: set_field(("interruption", "inventory", ".", "mode"), 365),
        "process": lambda: set_field(("peer_pid",), 122),
        "parent": lambda: set_field(("peer", "parent_pid"), 99),
        "peer-uid": lambda: set_field(("peer", "uids"), [0, 0, 0]),
        "peer-groups": lambda: set_field(("peer", "groups"), [0]),
        "peer-caps": lambda: set_field(("peer", "capabilities"), "1"),
        "denial-errno": lambda: set_field(("peer", "denied", 0, "errno"), 2),
        "admin": lambda: set_field(("peer", "administrative_refusal"), False),
        "isolated": lambda: set_field(("peer", "isolated"), 0),
        "site": lambda: set_field(("peer", "no_site"), 0),
        "bytecode": lambda: set_field(("peer", "no_bytecode"), 0),
        "poison": lambda: set_field(("peer", "poison_marker_absent"), False),
        "module": lambda: set_field(("peer", "modules", "alembic", "path"), "/caller/module.py"),
        "module-digest": lambda: set_field(
            ("peer", "modules", "alembic", "sha256"),
            "e" * 64,
        ),
        "binary-digest": lambda: set_field(
            ("peer", "binaries", "_cffi_backend", "sha256"),
            "e" * 64,
        ),
        "cli": lambda: set_field(("peer", "cli_info", "native_mutations"), True),
        "existing": lambda: set_field(("existing_after",), {}),
        "refusal": lambda: set_field(("rejections", 0, "errno"), 13),
        "cleanup": lambda: set_field(("cleanup", 0, "absent"), False),
        "cleanup-errors": lambda: set_field(("cleanup_errors",), [{"type": "OSError"}]),
        "primary": lambda: set_field(("primary_error",), {"type": "OSError"}),
        "unreported": lambda: set_field(("unreported",), True),
        "missing-payload": lambda: value["before"].pop("lib/alembic.py"),
        "extra-payload": lambda: set_field(("before", "extra"), dict(value["before"]["."])),
        "alias": lambda: set_field(
            ("before", "lib/alembic.py", "inode"), value["before"]["."]["inode"]
        ),
        "interruption-empty": lambda: value["interruption"]["inventory"].pop("lib/partial"),
        "interruption-alias": lambda: set_field(
            ("interruption", "inventory", ".", "inode"), value["before"]["."]["inode"]
        ),
        "denial": lambda: value["peer"]["denied"].pop(),
        "path": lambda: value["peer"]["sys_path"].append(""),
        "binary": lambda: value["peer"]["binaries"].pop("_cffi_backend"),
    }
    actions[case]()
    with pytest.raises((GuestBootError, KeyError, TypeError, ValueError)):
        native.verify_observation(value, c)


def test_guest_programs_parse_without_execution():
    for program in (native.REMOTE, native.OBSERVE, native.INTERRUPTED):
        ast.parse(program)


def test_unverified_guest_never_prepares_or_transmits_inputs(tmp_path, monkeypatch):
    def refused(*args):
        pytest.fail("unverified guest prepared inputs")

    monkeypatch.setattr(native, "_prepare_inputs", refused)
    with pytest.raises(GuestBootError, match="guest-not-verified"):
        native.qualify_wheels(SimpleNamespace(observed=None), tmp_path, nullcontext, {})


@pytest.mark.parametrize("fault", ["none", "malformed", "claim", "cleanup", "transport"])
def test_fake_authenticated_transport_preserves_originals_and_scoped_stats(
    tmp_path, monkeypatch, fault
):
    c = configuration()
    observation(c)
    supplied = {
        key: c[key]
        for key in (
            "manifest",
            "expected_payloads",
            "manifest_sha256",
            "input_sha256",
            "runtime_executable_sha256",
        )
    }
    supplied.update(
        input_bytes=5,
        input_members={"runtime.tar.gz": native.OWNER_PYTHON_SHA256, "bundle.zip": "e" * 64},
    )
    path = tmp_path / "not-an-executed-archive"
    path.write_bytes(b"bytes")
    calls = []
    monkeypatch.setattr(native, "_prepare_inputs", lambda guest, directory: (path, supplied))

    def guarded(arguments, enrollment, boot, **kwargs):
        assert arguments[:6] == ["/usr/bin/python3", "-I", "-S", "-B", "-c", native.REMOTE]
        ast.parse(arguments[-2])
        wire = json.loads(arguments[-1])
        assert "manifest" not in wire and "expected_payloads" not in wire
        assert (
            enrollment == c["enrollment"] and boot == c["boot_id"] and kwargs["input_path"] == path
        )
        calls.append(wire)
        if fault == "transport":
            raise RuntimeError("controlled transport failure")
        if fault == "malformed":
            return "not JSON"
        value = observation({**c, **supplied, **wire})
        if fault == "claim":
            value["native_product_qualified"] = True
        elif fault == "cleanup":
            value["cleanup"][0]["absent"] = False
        return json.dumps(value, sort_keys=True) + "\n"

    guest = SimpleNamespace(
        enrollment=c["enrollment"],
        accounts=("root", "peer"),
        observed={
            "boot_id": c["boot_id"],
            "accounts": {"peer": {"uid": c["peer_uid"], "gid": c["peer_gid"]}},
        },
        guarded=guarded,
    )
    report = {}
    if fault == "none":
        native.qualify_wheels(guest, tmp_path, lambda name: nullcontext(), report)
    else:
        with pytest.raises((GuestBootError, RuntimeError)):
            native.qualify_wheels(guest, tmp_path, lambda name: nullcontext(), report)
    assert len(calls) == 1 and valid_stats(report["qualification_statistics"])
    assert report["qualification_statistics"]["scope"] == "process-excludes-children"
    assert report["native_product_qualified"] is False
    assert report["status"] == ("passed" if fault == "none" else "failed")
    if fault == "malformed":
        assert report["unparsed_original_reply"] == "not JSON"
    if fault == "none":
        raw = json.dumps(report["original_observation"], sort_keys=True) + "\n"
        assert hashlib.sha256(raw.encode()).hexdigest() == report["original_reply_sha256"]


def test_controller_downloads_same_run_candidate_after_installed_gate():
    import yaml

    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    job = workflow["jobs"]["native-controller"]
    assert "installed" in job["needs"]
    steps = job["steps"]
    selected = [
        (i, step)
        for i, step in enumerate(steps)
        if step.get("with", {}).get("name") == "scaffold-candidate-ubuntu-24.04"
    ]
    assert len(selected) == 1
    index, step = selected[0]
    assert step["with"]["path"] == "artifacts/native-owner-candidate"
    assert step["uses"] == "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
    assert "run-id" not in step["with"] and "repository" not in step["with"]
    assert any(
        "-m scripts.native_linux_enrollment" in item.get("run", "") for item in steps[index + 1 :]
    )


def candidate(path):
    import io
    import zipfile

    wheels = {}
    for distribution, module in native.MODULES.items():
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(module + ".py", b"synthetic non-executed bytes")
            archive.writestr("empty/", b"")
        wheels["wheels/" + distribution.replace("-", "_") + "-1.0-py3-none-any.whl"] = (
            stream.getvalue()
        )
    manifest = {
        "profile": {"platform": "linux", "machine": "x86_64", "python": "3.12"},
        "files": {
            name: {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for name, raw in wheels.items()
        },
        "components": {"host": {"dependencies": list(native.MODULES), "lock": "locks/host.txt"}},
    }
    provenance = {
        "source_commit": "a" * 40,
        "working_tree_dirty": False,
        "github_run_id": "123",
        "production_qualified": False,
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("locks/host.txt", b"synthetic lock bytes")
        archive.writestr(
            "install.py", Path(native.__file__).with_name("bundle_install.py").read_bytes()
        )
        archive.writestr("provenance.json", json.dumps(provenance))
        for name, raw in wheels.items():
            archive.writestr(name, raw)
    return manifest


def test_complete_expected_payload_derivation_includes_every_selected_byte(tmp_path):
    path = tmp_path / "candidate.zip"
    manifest = candidate(path)
    expected = native._expected_payloads(path, manifest)
    assert {
        name.removeprefix("lib/").removesuffix(".py")
        for name in expected
        if name.startswith("lib/") and name.endswith(".py")
    } == set(native.MODULES.values())
    assert expected["lib/empty"] == {"kind": "directory"}
    assert {name for name in expected if name.startswith("wheels/")} == set(manifest["files"])
    assert all(
        row["bytes"] > 0 and len(row["sha256"]) == 64
        for row in expected.values()
        if row["kind"] == "regular"
    )


@pytest.mark.parametrize(
    "fault", ["missing", "foreign-source", "dirty", "foreign-run", "profile", "bootstrap"]
)
def test_unapproved_candidate_never_downloads_or_transmits_runtime(tmp_path, monkeypatch, fault):
    import zipfile

    monkeypatch.chdir(tmp_path)
    parent = tmp_path / "artifacts/native-owner-candidate"
    parent.mkdir(parents=True)
    path = parent / "scaffold-bundle.zip"
    if fault != "missing":
        candidate(path)
        with zipfile.ZipFile(path) as archive:
            values = {name: archive.read(name) for name in archive.namelist()}
        provenance = json.loads(values["provenance.json"])
        if fault == "foreign-source":
            provenance["source_commit"] = "b" * 40
        elif fault == "dirty":
            provenance["working_tree_dirty"] = True
        elif fault == "foreign-run":
            provenance["github_run_id"] = "other"
        elif fault == "profile":
            manifest = json.loads(values["manifest.json"])
            manifest["profile"]["python"] = "0.0"
            values["manifest.json"] = json.dumps(manifest).encode()
        else:
            values["install.py"] = b"unapproved bootstrap"
        values["provenance.json"] = json.dumps(provenance).encode()
        with zipfile.ZipFile(path, "w") as archive:
            for name, raw in values.items():
                archive.writestr(name, raw)
    monkeypatch.setattr(native, "source_identity", lambda: {"commit": "a" * 40, "clean": True})
    monkeypatch.setenv("GITHUB_RUN_ID", "123")

    def refused(*args, **kwargs):
        pytest.fail("unapproved candidate started a runtime download")

    guest = SimpleNamespace(command=refused)
    with pytest.raises(GuestBootError, match=r"owner-wheel-candidate"):
        native._prepare_inputs(guest, tmp_path)
