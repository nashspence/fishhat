"""Invented native observations test only the receipt reader and guest source syntax."""

import ast
import copy
import hashlib
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from scripts import native_linux_owner_launcher as launcher
from scripts.native_linux_guest import GuestBootError

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_linux_owner_launcher.py"],
    "scope": "strict launch receipt reader and guest program syntax with invented credentials, files, processes and outcomes",
    "relationship": "no-product-claim",
    "reason": "No guest program is executed. Synthetic successful observations establish reader behavior only; actual launch and kernel denial evidence must be independently retained and inspected.",
    "claims": [],
}


def receipt():
    enrollment = "00000000-0000-4000-8000-000000000025"
    prefix = "/var/lib/fishhat-launcher-fixture-" + enrollment
    boot = "10000000-0000-4000-8000-000000000025"
    files = {
        name: {"bytes": 50, "sha256": hashlib.sha256(name.encode()).hexdigest()}
        for name in ("launch", "launch.c", "targets.h", "launcher.json")
    }
    c = {
        "enrollment": enrollment,
        "boot_id": boot,
        "peer_uid": 1001,
        "peer_gid": 1001,
        "launcher_files_original": files,
        "interpreter": {"path": prefix + "/runtime/python/bin/python3.12", "sha256": "a" * 64},
        "program": {"path": prefix + "/observe.py", "sha256": "b" * 64},
    }

    def metadata(inode, *, uid=0, mode=0o444, directory=False, expected=None):
        result = {
            "device": 7,
            "inode": inode,
            "uid": uid,
            "gid": uid,
            "mode": mode,
            "links": 2 if directory else 1,
            "kind": "directory" if directory else "regular",
        }
        if not directory:
            result.update(bytes=50, sha256="a" * 64, file_capability=None)
            if expected:
                result.update(expected)
        return result

    def tree(base, sealed):
        return {
            ".": metadata(base, mode=0o555 if sealed else 0o700, directory=True),
            **{
                name: metadata(
                    base + index + 1,
                    mode=(0o555 if name == "launch" else 0o444) if sealed else 0o600,
                    expected=expected,
                )
                for index, (name, expected) in enumerate(files.items())
            },
        }

    def principal(pid, uid):
        return {
            "pid": pid,
            "uids": [uid] * 3,
            "gids": [uid] * 3,
            "groups": [],
            "capabilities": {
                name: "0000000000000000" for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")
            },
        }

    value = {
        "scope": launcher.SCOPE,
        "status": "passed",
        "native_product_qualified": False,
        "enrollment": enrollment,
        "boot_id": boot,
        "observer_uid": 0,
        "observer_pid": 900,
        "primary_error": None,
        "cleanup_errors": [],
        "existing_refusal": {"type": "FileExistsError", "errno": 17},
        "interrupted_refusal": {"type": "FileExistsError", "errno": 17},
        "interruption": {
            "pid": 1000,
            "announced": {"pid": 1000, "uid": 0, "boot_id": boot},
            "returncode": -9,
            "joined": True,
        },
        "invocations": [],
        "refusals": [],
        "retry_executable_sha256": files["launch"]["sha256"],
        "cleanup": [
            {"path": path, "device": 7, "inode": inode, "removed": True}
            for inode, path in enumerate(
                (prefix, "/tmp/fishhat-launcher-fixture-" + enrollment), 20
            )
        ],
    }
    for name, base, sealed in (
        ("complete", 100, True),
        ("retry", 200, True),
        ("interrupted", 300, False),
        ("inputs", 400, False),
    ):
        value[name + "_before"] = tree(base, sealed)
        value[name + "_after"] = copy.deepcopy(value[name + "_before"])
    value["targets_before"] = {
        "interpreter": metadata(600, mode=0o555, expected={"sha256": c["interpreter"]["sha256"]}),
        "program": metadata(601, expected={"sha256": c["program"]["sha256"]}),
    }
    value["targets_after"] = copy.deepcopy(value["targets_before"])
    pid = 1100
    for role in ("root", "peer"):
        for scale in launcher.SCALES:
            pid += 1
            uid = 0 if role == "root" else 1001
            before = principal(pid, uid)
            before.update(inherited_descriptor_open=True, inherited_descriptor_inheritable=True)
            nonce = format(pid, "032x")
            arguments = [
                "",
                "-I",
                "-c",
                "--interpreter=/unapproved/python",
                "$(unapproved-command); literal",
                "unicode-π",
                "line\ntext",
                "non-utf8-\udcff",
            ] + [str(index) + ":literal" for index in range(scale)]
            observation = {
                **copy.deepcopy(before),
                "parent_pid": 900,
                "boot_id": boot,
                "enrollment": enrollment,
                "environment": dict(launcher.ENVIRONMENT),
                "cwd": "/tmp/fishhat-launcher-fixture-" + enrollment,
                "executable": c["interpreter"]["path"],
                "executable_sha256": c["interpreter"]["sha256"],
                "program": c["program"]["path"],
                "program_sha256": c["program"]["sha256"],
                "flags": {
                    name: 1
                    for name in (
                        "isolated",
                        "ignore_environment",
                        "no_site",
                        "no_user_site",
                        "safe_path",
                        "dont_write_bytecode",
                    )
                },
                "sys_path": [prefix + "/runtime/python/lib/python3.12"],
                "argv": arguments,
                "nonce": nonce,
                "extra_fd_closed": True,
                "denied": [{"name": name, "errno": 13} for name in launcher.DENIALS]
                if role == "peer" and scale == 0
                else [],
            }
            value["invocations"].append(
                {
                    "role": role,
                    "launcher_path": prefix
                    + ("/retry/launch" if scale == launcher.SCALES[-1] else "/complete/launch"),
                    "launcher": copy.deepcopy(
                        value[
                            ("retry" if scale == launcher.SCALES[-1] else "complete") + "_before"
                        ]["launch"]
                    ),
                    "scale": scale,
                    "pid": pid,
                    "before": before,
                    "returncode": 0,
                    "stderr": "",
                    "joined": True,
                    "nonce": nonce,
                    "arguments": arguments,
                    "observation": observation,
                    "marker": metadata(
                        pid + 1000,
                        uid=uid,
                        mode=0o600,
                        expected={
                            "bytes": len(nonce),
                            "sha256": hashlib.sha256(nonce.encode()).hexdigest(),
                        },
                    ),
                }
            )
    for index, mode in enumerate(launcher.REFUSALS):
        pid = 1200 + index
        before = principal(pid, 1001 if mode in ("ambient", "setuid", "filecap") else 0)
        if mode == "uid-mismatch":
            before["uids"] = [1001, 0, 0]
        if mode == "gid-mismatch":
            before["gids"] = [1001, 0, 0]
        if mode == "ambient":
            before["capabilities"] = {name: "0000000000000400" for name in before["capabilities"]}
        target = metadata(
            1500 + index, mode=0o4555 if mode == "setuid" else 0o555, expected=files["launch"]
        )
        if mode == "filecap":
            target["file_capability"] = "0100000200040000000000000000000000000000"
        value["refusals"].append(
            {
                "mode": mode,
                "pid": pid,
                "before": before,
                "target": target,
                "returncode": 126,
                "stdout": "",
                "stderr": "Unsupported invocation context\n",
                "joined": True,
                "marker_absent": True,
            }
        )
    return value, c


def test_invented_complete_observation_only_establishes_reader_behavior():
    value, c = receipt()
    launcher.verify_observation(value, c)


@pytest.mark.parametrize(
    "case",
    [
        "unsafe-root",
        "boolean-owner",
        "filecap",
        "aliased-retry",
        "changed-input",
        "unjoined-interruption",
        "missing-invocation",
        "duplicate-pid",
        "duplicate-nonce",
        "loader-environment",
        "import-path",
        "cwd",
        "credentials",
        "capabilities",
        "flags",
        "argv",
        "fd",
        "peer-denial",
        "refusal-success",
        "refusal-marker",
        "ineffective-uid",
        "ineffective-gid",
        "ineffective-ambient",
        "ineffective-setuid",
        "ineffective-filecap",
        "foreign-cleanup",
        "unremoved-cleanup",
        "qualified",
    ],
)
def test_malformed_or_incomplete_observations_fail_closed(case):
    value, c = receipt()
    first = value["invocations"][0]
    changes = {
        "unsafe-root": [
            (("complete_" + suffix, ".", "mode"), 0o777) for suffix in ("before", "after")
        ],
        "boolean-owner": [
            (("complete_" + suffix, ".", "uid"), False) for suffix in ("before", "after")
        ],
        "filecap": [
            (("complete_" + suffix, "launch", "file_capability"), "effective")
            for suffix in ("before", "after")
        ],
        "aliased-retry": [
            (("retry_" + suffix,), copy.deepcopy(value["complete_" + suffix]))
            for suffix in ("before", "after")
        ],
        "changed-input": [(("inputs_after", "launch", "sha256"), "0" * 64)],
        "unjoined-interruption": [(("interruption", "joined"), False)],
        "missing-invocation": [(("invocations",), value["invocations"][:-1])],
        "duplicate-pid": [
            (("invocations", 1, "pid"), first["pid"]),
            (("invocations", 1, "before", "pid"), first["pid"]),
            (("invocations", 1, "observation", "pid"), first["pid"]),
        ],
        "duplicate-nonce": [
            (("invocations", 1, "nonce"), first["nonce"]),
            (("invocations", 1, "observation", "nonce"), first["nonce"]),
        ],
        "loader-environment": [
            (
                ("invocations", 0, "observation", "environment", "LD_PRELOAD"),
                "/unapproved/loader.so",
            )
        ],
        "import-path": [
            (("invocations", 0, "observation", "sys_path"), [first["observation"]["cwd"]])
        ],
        "cwd": [(("invocations", 0, "observation", "cwd"), "/unapproved")],
        "credentials": [(("invocations", 0, "observation", "uids"), [1001] * 3)],
        "capabilities": [
            (("invocations", 0, "observation", "capabilities", "CapAmb"), "0000000000000400")
        ],
        "flags": [(("invocations", 0, "observation", "flags", "no_site"), 0)],
        "argv": [(("invocations", 0, "observation", "argv"), first["observation"]["argv"][:-1])],
        "fd": [(("invocations", 0, "observation", "extra_fd_closed"), False)],
        "peer-denial": [
            (
                ("invocations", 4, "observation", "denied"),
                value["invocations"][4]["observation"]["denied"][:-1],
            )
        ],
        "refusal-success": [(("refusals", 0, "returncode"), 0)],
        "refusal-marker": [(("refusals", 0, "marker_absent"), False)],
        "ineffective-uid": [(("refusals", 0, "before", "uids"), [0] * 3)],
        "ineffective-gid": [(("refusals", 1, "before", "gids"), [0] * 3)],
        "ineffective-ambient": [
            (("refusals", 2, "before", "capabilities", "CapAmb"), "0000000000000000")
        ],
        "ineffective-setuid": [(("refusals", 3, "target", "mode"), 0o555)],
        "ineffective-filecap": [(("refusals", 4, "target", "file_capability"), None)],
        "foreign-cleanup": [(("cleanup", 0, "path"), "/unapproved")],
        "unremoved-cleanup": [(("cleanup", 0, "removed"), False)],
        "qualified": [(("native_product_qualified",), True)],
    }
    for path, replacement in changes[case]:
        target = value
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = replacement
    with pytest.raises(GuestBootError):
        launcher.verify_observation(value, c)


@pytest.mark.parametrize("name", ["OBSERVE", "INTERRUPT", "REMOTE", "CLEANUP"])
def test_guest_program_source_parses_without_execution(name):
    ast.parse(getattr(launcher, name))


def test_unenrolled_guest_refused_before_build_or_package_commands(tmp_path):
    def unavailable(*args, **kwargs):
        raise AssertionError("unadmitted command")

    guest = SimpleNamespace(observed=None, command=unavailable)
    with pytest.raises(GuestBootError, match="guest-not-verified"):
        launcher.qualify_launcher(
            guest, tmp_path, lambda name: nullcontext(), {}, root_command=unavailable
        )
    assert list(tmp_path.iterdir()) == []
