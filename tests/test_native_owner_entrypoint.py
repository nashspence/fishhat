"""Synthetic receipt and collector challenges; guest programs are parsed as inert text only."""

import ast
import base64
import copy
import hashlib
import json
import os
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from scripts import native_linux_owner_entrypoint as native
from scripts.run_stats import valid_stats

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_linux_owner_entrypoint.py"],
    "scope": "synthetic full-closure custody and original syscall/proc observation inspection, malformed and abbreviated collector data, distinct interruption/retry, original-reply/statistics retention and guest-source syntax without native execution",
    "relationship": "no-product-claim",
    "reason": "Invented file/process/trace records and replaced guest/build callbacks challenge the evidence tooling only. No compiler, installed command, guest script, credential change, package installation or SSH transport executes locally.",
    "claims": [],
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def quoted(raw):
    raw = os.fsencode(raw) if isinstance(raw, str) else raw
    return '"' + "".join(f"\\x{value:02x}" for value in raw) + '"'


def execution(path, argv, environment):
    args = ", ".join(quoted(value) for value in argv)
    env = ", ".join(quoted(key + "=" + value) for key, value in environment.items())
    return f"execve({quoted(path)}, [{args}], [{env}]) = 0"


def refusal_rows(c, principal, command):
    rows = []
    for index, mode in enumerate(("uid-mismatch", "gid-mismatch", "ambient", "setuid", "filecap")):
        before = principal(500 + index, c["peer_uid"], c["peer_gid"])
        if mode == "uid-mismatch":
            before.update(uids=[c["peer_uid"], 0, 0], gids=[0] * 3)
        if mode == "gid-mismatch":
            before.update(gids=[c["peer_gid"], 0, 0], uids=[0] * 3)
        if mode == "ambient":
            for key in ("CapEff", "CapPrm", "CapInh", "CapAmb"):
                before["status"][key] = "0000000000000400"
        target = copy.deepcopy(command)
        if mode == "setuid":
            target["mode"] = 0o4555
        if mode == "filecap":
            target["file_capability"] = "0100000200040000000000000000000000000000"
        rows.append(
            {
                "pid": 500 + index,
                "mode": mode,
                "before": before,
                "target": target,
                "traced": False,
                "joined": True,
                "returncode": 126,
                "stdout": "",
                "stderr": "Unsupported invocation context\n",
            }
        )
    return rows


def observer_receipt(value, inputs, metadata, file, prefix):
    expected = {
        ".": {"kind": "directory", "mode": 0o555},
        "usr": {"kind": "directory", "mode": 0o555},
        "usr/bin": {"kind": "directory", "mode": 0o555},
        "usr/bin/strace": file(b"inert observer", 0o555),
    }
    inputs["expected_observer"] = expected
    value["observer_before"] = {name: metadata(row) for name, row in expected.items()}
    value["observer_after"] = copy.deepcopy(value["observer_before"])
    value["observer_tool"] = {
        "package_original": "strace\t6.8-0ubuntu2\tamd64\n",
        "executable_path": prefix + "/observer/usr/bin/strace",
        "executable": copy.deepcopy(value["observer_before"]["usr/bin/strace"]),
        "product_runtime_dependency": False,
        "offline": True,
        "packages": {
            name: {
                "bytes": pin["bytes"],
                "sha256": pin["sha256"],
                "fields": {
                    "Package": pin["package"],
                    "Version": pin["version"],
                    "Architecture": pin["architecture"],
                },
                "data_tar_sha256": "d" * 64,
            }
            for name, pin in native.OBSERVER_PINS.items()
        },
        "preparation_tool": {
            "path": "/usr/bin/dpkg-deb",
            "sha256": "e" * 64,
            "mode": "read-package-filesystem-only",
            "maintainer_scripts_executed": False,
        },
    }


def receipt():
    c = {
        "enrollment": "11111111-1111-4111-8111-111111111111",
        "boot_id": "22222222-2222-4222-8222-222222222222",
        "peer_uid": 1001,
        "peer_gid": 1002,
        "peer_account": "fixture-peer",
    }
    prefix = "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"]
    poison = "/tmp/fishhat-entrypoint-fixture-" + c["enrollment"]
    counter = 10

    def metadata(expected, uid=0, gid=0):
        nonlocal counter
        counter += 1
        return {
            "device": 3,
            "inode": counter,
            "uid": uid,
            "gid": gid,
            "links": 1,
            **expected,
            **({"file_capability": None} if expected["kind"] == "regular" else {}),
        }

    def file(raw, mode=0o444):
        return {"kind": "regular", "mode": mode, "bytes": len(raw), "sha256": sha(raw)}

    def principal(pid, uid, gid):
        status = {
            "Pid": str(pid),
            "PPid": "50",
            "Uid": " ".join([str(uid)] * 4),
            "Gid": " ".join([str(gid)] * 4),
            "Groups": "",
            **dict.fromkeys(("CapEff", "CapPrm", "CapInh", "CapAmb"), "0000000000000000"),
        }
        return {"pid": pid, "uids": [uid] * 3, "gids": [gid] * 3, "groups": [], "status": status}

    runtime = {
        "runtime": {"kind": "directory", "mode": 0o555},
        "runtime/python": {"kind": "directory", "mode": 0o555},
        "runtime/python/bin": {"kind": "directory", "mode": 0o555},
        "runtime/python/bin/python3.12": file(b"inert interpreter", 0o555),
        "runtime/runtime.tar.gz": file(b"inert archive", 0o400),
    }
    wheels = {".": {"kind": "directory"}, "lib": {"kind": "directory"}}
    for module in ("fishhat_host", "fishhat_cli", "fishhat_contracts"):
        wheels["lib/" + module] = {"kind": "directory"}
    for relative in (
        "fishhat_host/__init__.py",
        "fishhat_host/cli.py",
        "fishhat_cli/validation.py",
        "fishhat_contracts/validation.py",
    ):
        wheels["lib/" + relative] = {
            key: value for key, value in file(b"inert approved package").items() if key != "mode"
        }
    source = {".": {"kind": "directory", "mode": 0o700}, "bundle.zip": file(b"inert bundle", 0o600)}
    inputs = {
        "input_bytes": 31,
        "input_sha256": "f" * 64,
        "expected_inputs": source,
        "expected_runtime": runtime,
        "expected_wheels": wheels,
        "builds": {},
        "configuration": {"bindings": {}},
    }
    value = {
        "scope": native.SCOPE,
        "status": "passed",
        "native_product_qualified": False,
        "enrollment": c["enrollment"],
        "boot_id": c["boot_id"],
        "observer_pid": 50,
        "observer_uid": 0,
        "primary_error": None,
        "cleanup_errors": [],
        "transfer": {
            "bytes": 31,
            "sha256": "f" * 64,
            "members": {"bundle.zip": {"bytes": 12, "sha256": sha(b"inert bundle")}},
        },
    }
    value["inputs_before"] = {name: metadata(row) for name, row in source.items()}
    value["inputs_after"] = copy.deepcopy(value["inputs_before"])
    for name in ("complete", "interrupted", "retry"):
        program = ("inert approved program " + name).encode()
        originals = {
            role: {
                "bytes": len(data),
                "sha256": sha(data),
                "base64": base64.b64encode(data).decode(),
            }
            for role in native.LAUNCHER_ROLES
            for data in [("inert " + name + role).encode()]
        }
        inputs["builds"][name] = {
            "files_original": originals,
            "program_original_base64": base64.b64encode(program).decode(),
        }
        inputs["configuration"]["bindings"][name] = {
            "interpreter": {
                "path": prefix + "/" + name + "/runtime/python/bin/python3.12",
                "sha256": runtime["runtime/python/bin/python3.12"]["sha256"],
            },
            "program": {"path": prefix + "/" + name + "/host-ops.py", "sha256": sha(program)},
        }
        layout = {
            ".": {"kind": "directory", "mode": 0o700 if name == "interrupted" else 0o555},
            **runtime,
            "packages": {"kind": "directory", "mode": 0o555},
            "launcher": {"kind": "directory", "mode": 0o555},
            "host-ops.py": file(program),
        }
        for relative, row in wheels.items():
            if relative != ".":
                layout["packages/" + relative] = row | {
                    "mode": 0o555 if row["kind"] == "directory" else 0o444
                }
        for role, row in originals.items():
            layout["launcher/" + role] = {
                "kind": "regular",
                "mode": 0o555 if role == "launch" else 0o444,
                "bytes": row["bytes"],
                "sha256": row["sha256"],
            }
        layout["host-ops"] = layout["launcher/launch"] | {
            "mode": 0o600 if name == "interrupted" else 0o555
        }
        value[name + "_before"] = {key: metadata(row) for key, row in layout.items()}
        value[name + "_after"] = copy.deepcopy(value[name + "_before"])
    value.update(
        existing_refusal={"type": "FileExistsError", "errno": 17},
        interrupted_refusal={"type": "FileExistsError", "errno": 17},
        interruption={
            "pid": 51,
            "returncode": -9,
            "joined": True,
            "announced": {"pid": 51, "uid": 0, "boot_id": c["boot_id"]},
        },
    )
    value["symlink_refusals"] = []
    for name, error in (
        ("destination-link", "FileExistsError"),
        ("parent-link", "NotADirectoryError"),
    ):
        link = metadata({"kind": "symlink", "mode": 0o777, "target": prefix + "/complete"})
        value["symlink_refusals"].append(
            {
                "name": name,
                "before": link,
                "after": copy.deepcopy(link),
                "error": {"type": error, "errno": 17},
                "target_child_absent": True,
            }
        )
    observer_receipt(value, inputs, metadata, file, prefix)
    info = json.dumps(
        {
            "tool": "host-ops",
            "version": "0.1.0.dev0",
            "implementation": "scaffold",
            "capabilities": ["local-contract-validation"],
            "native_mutations": False,
            "production_qualified": False,
        }
    )
    value["negative_controls"] = []
    value["direct_invocations"] = []
    value["traced_invocations"] = []
    for number, role in enumerate(("root", "peer")):
        uid, gid = (0, 0) if role == "root" else (c["peer_uid"], c["peer_gid"])
        pid = 100 + number * 100
        negative = {
            "role": role,
            "pid": pid,
            "before": principal(pid, uid, gid),
            "joined": True,
            "returncode": 0,
            "stdout": info,
            "stderr": "diagnostic control only",
            "argv": [
                prefix + "/complete/runtime/python/bin/python3.12",
                "-I",
                "-S",
                "-B",
                prefix + "/complete/host-ops.py",
                "info",
                "--json",
            ],
            "environment": native._poison_environment(c["enrollment"])
            | {"LD_DEBUG_OUTPUT": poison + "/" + role + "/negative-loader"},
        }
        negative["loader"] = {
            "path": poison + "/" + role + "/negative-loader." + str(pid),
            **metadata(file(b"actual loader control", 0o600), uid, gid),
        }
        value["negative_controls"].append(negative)
        value["direct_invocations"].append(
            {
                "role": role,
                "pid": pid + 1,
                "before": principal(pid + 1, uid, gid),
                "joined": True,
                "returncode": 0,
                "stdout": info,
                "stderr": "",
                "argv": [prefix + "/complete/host-ops", "info", "--json"],
                "environment": native._poison_environment(c["enrollment"]),
            }
        )
        for index, label in enumerate(("help", "info", "validate")):
            profile = "retry" if label == "validate" else "complete"
            path = prefix + "/" + profile
            full_label = role + "-" + label
            args = (
                ["--help"]
                if label == "help"
                else ["info", "--json"]
                if label == "info"
                else [
                    "validate",
                    poison + "/" + role + "/" + full_label + ".json",
                    "--schema",
                    "readiness.schema.json",
                    "--json",
                ]
            )
            environment = native._poison_environment(c["enrollment"]) | {
                "LD_DEBUG_OUTPUT": poison + "/" + role + "/positive-loader-" + full_label
            }
            interpreter, program = path + "/runtime/python/bin/python3.12", path + "/host-ops.py"
            selected_argv = [interpreter, "-I", "-S", "-B", program, *args]
            strings = [
                path + "/host-ops",
                interpreter,
                program,
                *args,
                *[key + "=" + item for key, item in environment.items()],
            ]
            limit = max(len(os.fsencode(item)) for item in strings) + 1
            observer = [
                prefix + "/observer/usr/bin/strace",
                "-ff",
                "--kill-on-exit",
                "-s",
                str(limit),
                "-xx",
                "-v",
                "-q",
                "-e",
                "trace=%file,%process,%creds,%network,umask,close_range",
                "-o",
                prefix + "/traces/" + full_label,
                "-u",
                "root" if role == "root" else c["peer_account"],
            ]
            observer += [
                item
                for key, item_value in environment.items()
                for item in ("-E", key + "=" + item_value)
            ]
            observer += [path + "/host-ops", *args]
            opened = [
                path + "/host-ops.py",
                *[
                    path + "/packages/" + relative
                    for relative, row in wheels.items()
                    if row["kind"] == "regular"
                ],
            ]
            lines = [
                execution(path + "/host-ops", [path + "/host-ops", *args], environment),
                execution(interpreter, selected_argv, {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}),
            ]
            lines += [
                "openat(AT_FDCWD, " + quoted(item) + ", O_RDONLY|O_CLOEXEC) = 3" for item in opened
            ]
            if label == "validate":
                lines.append("openat(AT_FDCWD, " + quoted(args[1]) + ", O_RDONLY|O_CLOEXEC) = 3")
            log = "\n".join([*lines, "exit_group(0) = ?", "+++ exited with 0 +++", ""])
            tracer, tracee = pid + 2 + 2 * index, pid + 3 + 2 * index
            proc = None
            if label == "validate":
                facts = principal(tracee, uid, gid)["status"] | {
                    "PPid": str(tracer),
                    "Groups": str(gid),
                }
                proc = {
                    "pid": tracee,
                    "tracer_pid": tracer,
                    "status": facts,
                    "start_ticks": "1000",
                    "executable": interpreter,
                    "cmdline_hex": (
                        b"\0".join(os.fsencode(item) for item in selected_argv) + b"\0"
                    ).hex(),
                    "environment_hex": b"LANG=C.UTF-8\0LC_ALL=C.UTF-8\0".hex(),
                    "process_group": tracer,
                    "session": tracer,
                    "pidfd_open": True,
                }
            value["traced_invocations"].append(
                {
                    "role": role,
                    "label": full_label,
                    "command": path + "/host-ops",
                    "arguments": args,
                    "environment": environment,
                    "tracer_pid": tracer,
                    "tracee_pid": tracee,
                    "returncode": 0,
                    "stdout": "host-ops validate info scaffold"
                    if label == "help"
                    else info
                    if label == "info"
                    else json.dumps(
                        {
                            "tool": "host-ops",
                            "status": "valid",
                            "scope": "local-contracts-only",
                            "production_qualified": False,
                        }
                    ),
                    "stderr": "",
                    "tracer_joined": True,
                    "tracee_absent": True,
                    "observation": proc,
                    "initial_group_selection": [gid],
                    "observer_argv": observer,
                    "observer_environment": {
                        "LANG": "C.UTF-8",
                        "LC_ALL": "C.UTF-8",
                        "LD_LIBRARY_PATH": prefix + "/observer/usr/lib/x86_64-linux-gnu",
                    },
                    "string_limit": limit,
                    "trace_original": log,
                    "trace_metadata": metadata(file(log.encode(), 0o600)),
                    "positive_loader_files": [],
                    "code_opens": {
                        item: {
                            "resolved": item,
                            "metadata": copy.deepcopy(
                                value[profile + "_before"][item.removeprefix(path + "/")]
                            ),
                        }
                        for item in opened
                    },
                }
            )
    value["refusals"] = refusal_rows(c, principal, value["complete_before"]["host-ops"])
    value["dispatch_refusals"] = [{"joined": True, "returncode": 2, "stdout": ""} for _ in range(4)]
    value["peer_denials"] = {
        name: {
            "before": principal(600 + index, c["peer_uid"], c["peer_gid"]),
            "joined": True,
            "returncode": 1,
            "stderr": "PermissionError",
        }
        for index, name in enumerate(
            (
                "command-write",
                "program-write",
                "runtime-write",
                "library-write",
                "command-unlink",
                "create",
                "chmod",
                "rename",
            )
        )
    }
    value["administrative_refusal"] = {
        "before": principal(700, c["peer_uid"], c["peer_gid"]),
        "joined": True,
        "returncode": 1,
        "candidate_absent": True,
        "stderr": "protected staging requires Linux administrative custody",
    }
    value["cleanup"] = [
        {"path": name, "removed": True, "device": 3, "inode": 10000 + index}
        for index, name in enumerate((poison, prefix))
    ]
    return value, c | {"inputs": inputs}


def test_complete_invented_packet_is_accepted_without_native_execution():
    value, c = receipt()
    native.verify_observation(value, c)


CHALLENGES = [
    (("scope",), "other"),
    (("status",), "failed"),
    (("native_product_qualified",), True),
    (("observer_uid",), False),
    (("observer_pid",), True),
    (("boot_id",), "other"),
    (("primary_error",), {}),
    (("cleanup_errors",), [{}]),
    (("transfer", "sha256"), "0" * 64),
    (("transfer", "members"), {}),
    (("inputs_after",), {}),
    (("complete_after",), {}),
    (("retry_after",), {}),
    (("interrupted_after",), {}),
    (("interruption", "joined"), False),
    (("interruption", "announced", "uid"), 1),
    (("interruption", "returncode"), 0),
    (("existing_refusal", "type"), "ValueError"),
    (("interrupted_refusal", "errno"), None),
    (("symlink_refusals",), []),
    (("symlink_refusals", 0, "target_child_absent"), False),
    (("observer_tool", "package_original"), "strace\tunapproved\tamd64\n"),
    (("observer_tool", "product_runtime_dependency"), True),
    (("observer_tool", "offline"), False),
    (("observer_tool", "executable_path"), "/unapproved/strace"),
    (("observer_tool", "preparation_tool", "maintainer_scripts_executed"), True),
    (("observer_tool", "preparation_tool", "mode"), "install"),
    (("observer_tool", "packages"), {}),
    (("observer_after", "usr/bin/strace", "sha256"), "0" * 64),
    (("traced_invocations", 0, "observer_environment"), {"LD_PRELOAD": "/unapproved"}),
    (("observer_tool", "executable", "mode"), 0o4777),
    (("negative_controls",), []),
    (("negative_controls", 0, "loader", "bytes"), 0),
    (("negative_controls", 1, "environment", "LD_DEBUG"), ""),
    (("direct_invocations", 0, "returncode"), False),
    (("direct_invocations", 1, "before", "uids"), [0, 0, 0]),
    (("direct_invocations", 0, "environment", "PATH"), "/unapproved"),
    (("traced_invocations",), []),
    (("traced_invocations", 0, "tracer_joined"), False),
    (("traced_invocations", 0, "tracee_absent"), False),
    (("traced_invocations", 0, "positive_loader_files"), ["injected"]),
    (("traced_invocations", 0, "code_opens"), {}),
    (("traced_invocations", 0, "observer_argv"), []),
    (("traced_invocations", 0, "string_limit"), 0),
    (("traced_invocations", 2, "observation", "executable"), "/unapproved/python"),
    (("traced_invocations", 2, "observation", "pidfd_open"), False),
    (("traced_invocations", 5, "observation", "status", "Uid"), "0 0 0 0"),
    (("traced_invocations", 5, "observation", "status", "Groups"), "0"),
    (("traced_invocations", 5, "observation", "environment_hex"), "00"),
    (("traced_invocations", 5, "observation", "cmdline_hex"), "00"),
    (("refusals",), []),
    (("refusals", 0, "traced"), True),
    (("refusals", 2, "before", "status", "CapEff"), "0000000000000000"),
    (("refusals", 3, "target", "mode"), 0o555),
    (("refusals", 4, "target", "file_capability"), None),
    (("dispatch_refusals", 0, "returncode"), 0),
    (("peer_denials",), {}),
    (("peer_denials", "command-write", "returncode"), True),
    (("administrative_refusal", "candidate_absent"), False),
    (("cleanup",), []),
    (("cleanup", 0, "removed"), False),
]


@pytest.mark.parametrize(
    "keys,replacement",
    CHALLENGES,
    ids=["-".join(map(str, keys)).replace("/", "-") for keys, _ in CHALLENGES],
)
def test_incomplete_or_forged_observations_are_refused(keys, replacement):
    value, c = receipt()
    selected = value
    for key in keys[:-1]:
        selected = selected[key]
    selected[keys[-1]] = replacement
    with pytest.raises(native.GuestBootError):
        native.verify_observation(value, c)


@pytest.mark.parametrize(
    "name",
    [
        "changed-executable",
        "extra-program",
        "extra-network",
        "credential-change",
        "global-python",
        "abbreviated-array",
        "unjoined-exit",
    ],
)
def test_semantically_forged_original_trace_is_refused_even_with_matching_hash(name):
    value, c = receipt()
    row = value["traced_invocations"][0]
    log = row["trace_original"]
    if name == "changed-executable":
        log = log.replace(quoted(row["command"]), quoted("/unapproved/program"), 1)
    elif name == "extra-program":
        log = execution("/unapproved/program", ["/unapproved/program"], {}) + "\n" + log
    elif name == "extra-network":
        log = log.replace("exit_group(0)", "socket(AF_INET, SOCK_STREAM, 0) = 4\nexit_group(0)")
    elif name == "credential-change":
        log = log.replace("exit_group(0)", "setuid(0) = 0\nexit_group(0)")
    elif name == "global-python":
        log = log.replace(
            "exit_group(0)",
            "openat(AT_FDCWD, "
            + quoted("/usr/lib/python3.12/caller.py")
            + ", O_RDONLY) = 3\nexit_group(0)",
        )
    elif name == "abbreviated-array":
        log = log.replace("], [", ", ...], [", 1)
    else:
        log = log.removesuffix("+++ exited with 0 +++\n")
    row["trace_original"] = log
    row["trace_metadata"].update(bytes=len(log.encode()), sha256=sha(log.encode()))
    with pytest.raises(native.GuestBootError):
        native.verify_observation(value, c)


@pytest.mark.parametrize("extent", [0, 16, 64, 256, 1024])
def test_exec_trace_parser_retains_complete_literal_argument_extent(extent):
    argv = [
        b"",
        b"-c",
        b"$(literal); text",
        b"unicode-\xcf\x80",
        b"line\ntext",
        b"nonutf8-\xff",
        *[str(i).encode() for i in range(extent)],
    ]
    raw = execution("/fixed/program", argv, {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    assert native._execution(raw) == (
        b"/fixed/program",
        argv,
        {b"LANG": b"C.UTF-8", b"LC_ALL": b"C.UTF-8"},
    )


@pytest.mark.parametrize(
    "source",
    [native.REMOTE, native.INTERRUPTED, native.CLEANUP],
    ids=["observer", "interruption", "cleanup"],
)
def test_guest_programs_are_syntax_checked_without_running_them(source):
    tree = ast.parse(source)
    assert tree.body


def test_unverified_guest_refuses_before_any_facility_or_payload_call(tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("unverified guest touched facility")

    guest = SimpleNamespace(observed=None, command=forbidden, guarded=forbidden)
    with pytest.raises(native.GuestBootError, match="guest-not-verified"):
        native.qualify_entrypoint(
            guest, tmp_path, lambda name: nullcontext(), {}, root_command=forbidden
        )


@pytest.mark.parametrize("mode", ["passed", "invalid-json", "forged", "transport-failure"])
def test_coordinator_retains_original_reply_cleanup_and_statistics(tmp_path, monkeypatch, mode):
    value, c = receipt()
    inputs = c["inputs"] | {"bootstrap_sha256": "a" * 64, "interrupt_sha256": "b" * 64}
    path = tmp_path / "inputs.zip"
    path.write_bytes(b"inert transport input")
    monkeypatch.setattr(native.owner_launcher, "provision_tools", lambda *args: {"inert": True})
    monkeypatch.setattr(native, "_prepare_inputs", lambda *args: (path, inputs))
    cleanup = {
        "pid": 800,
        "uid": 0,
        "boot_id": c["boot_id"],
        "enrollment": c["enrollment"],
        "paths": [
            {"path": "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"], "absent": True},
            {"path": "/tmp/fishhat-entrypoint-fixture-" + c["enrollment"], "absent": True},
        ],
    }
    raw = "not JSON" if mode == "invalid-json" else json.dumps(value)
    if mode == "forged":
        raw = json.dumps(value | {"status": "failed"})
    calls = []

    def guarded(action, enrollment, boot, **kwargs):
        calls.append((action, enrollment, boot, kwargs))
        if len(calls) == 1:
            if mode == "transport-failure":
                raise native.GuestBootError("fixture transport lost")
            assert kwargs["input_path"] == path
            return raw
        assert "input_path" not in kwargs
        return json.dumps(cleanup)

    guest = SimpleNamespace(
        observed={
            "boot_id": c["boot_id"],
            "accounts": {c["peer_account"]: {"uid": c["peer_uid"], "gid": c["peer_gid"]}},
        },
        enrollment=c["enrollment"],
        accounts=("admin", c["peer_account"]),
        command=None,
        guarded=guarded,
    )
    report = {}

    def invoke():
        native.qualify_entrypoint(
            guest, tmp_path, lambda name: nullcontext(), report, root_command=lambda *args: None
        )

    if mode == "passed":
        invoke()
        assert report["status"] == "passed"
    else:
        with pytest.raises(native.GuestBootError):
            invoke()
        assert report["status"] == "failed"
    assert report["native_product_qualified"] is False
    assert valid_stats(report["qualification_statistics"])
    assert report["qualification_statistics"]["scope"] == "process-excludes-children"
    if mode != "transport-failure":
        assert report["original_reply_sha256"] == sha(raw.encode())
    if mode == "invalid-json":
        assert report["unparsed_original_reply"] == raw
    if mode in ("passed", "forged"):
        assert report["cleanup_observer_original_reply"] == json.dumps(cleanup)


def test_registered_runtime_alias_and_loader_parent_spelling_resolve_to_exact_owned_bytes():
    value, c = receipt()
    data = b"inert approved alias target"
    additions = {
        "runtime/python/lib": {"kind": "directory", "mode": 0o555},
        "runtime/python/lib/shared.py": {
            "kind": "regular",
            "mode": 0o444,
            "bytes": len(data),
            "sha256": sha(data),
        },
        "runtime/python/lib/alias.py": {"kind": "symlink", "mode": 0o777, "target": "shared.py"},
    }
    c["inputs"]["expected_runtime"].update(additions)
    for index, profile in enumerate(("complete", "interrupted", "retry")):
        for offset, (name, fields) in enumerate(additions.items()):
            row = {
                "device": 3,
                "inode": 20000 + 10 * index + offset,
                "uid": 0,
                "gid": 0,
                "links": 1,
                **fields,
            }
            if fields["kind"] == "regular":
                row["file_capability"] = None
            value[profile + "_before"][name] = row
            value[profile + "_after"][name] = copy.deepcopy(row)
    row = value["traced_invocations"][0]
    prefix = row["command"].removesuffix("/host-ops")
    raw = prefix + "/runtime/python/bin/../lib/alias.py"
    resolved = prefix + "/runtime/python/lib/shared.py"
    line = "openat(AT_FDCWD, " + quoted(raw) + ", O_RDONLY|O_CLOEXEC) = 3\n"
    log = row["trace_original"].replace("exit_group(0)", line + "exit_group(0)")
    row["trace_original"] = log
    row["trace_metadata"].update(bytes=len(log.encode()), sha256=sha(log.encode()))
    row["code_opens"][raw] = {
        "resolved": resolved,
        "metadata": copy.deepcopy(value["complete_before"]["runtime/python/lib/shared.py"]),
    }
    native.verify_observation(value, c)
    row["code_opens"][raw]["resolved"] = "/unapproved/caller.py"
    with pytest.raises(native.GuestBootError):
        native.verify_observation(value, c)


@pytest.mark.parametrize("fault", ["none", "changed-download", "escaping-alias", "hardlink"])
def test_offline_observer_preparation_uses_only_fixed_download_and_package_data_readers(
    tmp_path, monkeypatch, fault
):
    from pathlib import Path

    raw = b"inert package bytes; never executable"
    pins = {
        "observer.deb": {
            "url": "https://fixed.invalid/observer.deb",
            "bytes": len(raw),
            "sha256": sha(raw),
        }
    }
    monkeypatch.setattr(native, "OBSERVER_PINS", pins)
    calls = []

    def command(argv, purpose, nominal):
        calls.append((argv, purpose, nominal))
        if purpose.endswith("download"):
            assert argv[:4] == [native.sys.executable, "-I", "-S", "-B"]
            assert argv[4].endswith("/native_owner_python_download.py")
            assert argv[6:9] == [pins["observer.deb"]["url"], str(len(raw)), sha(raw)]
            Path(argv[5]).write_bytes(b"changed" if fault == "changed-download" else raw)
        else:
            assert argv == [
                "/usr/bin/dpkg-deb",
                "--extract",
                str(tmp_path / "observer.deb"),
                str(tmp_path / "observer-expected"),
            ]
            root = Path(argv[3])
            (root / "inert-library").write_bytes(b"non-executable library-shaped data")
            (root / "inert-library").chmod(0o644)
            if fault == "escaping-alias":
                (root / "alias").symlink_to(tmp_path)
            elif fault == "hardlink":
                os.link(root / "inert-library", root / "alias")
            else:
                (root / "alias").symlink_to("inert-library")
        return ""

    guest = SimpleNamespace(command=command)
    if fault != "none":
        with pytest.raises(native.GuestBootError):
            native._observer_payloads(guest, tmp_path)
        assert len(calls) == (1 if fault == "changed-download" else 2)
    else:
        members, expected = native._observer_payloads(guest, tmp_path)
        assert members == {"observer.deb": raw}
        assert expected == {
            ".": {"kind": "directory", "mode": 0o555},
            "inert-library": {
                "kind": "regular",
                "mode": 0o444,
                "bytes": 34,
                "sha256": sha(b"non-executable library-shaped data"),
            },
            "alias": {"kind": "symlink", "mode": 0o777, "target": "inert-library"},
        }
        assert len(calls) == 2
