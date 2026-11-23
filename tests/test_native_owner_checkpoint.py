"""Inert checkpoint evidence controls; embedded guest programs never execute here."""

import ast
import base64
import hashlib
import json
from types import SimpleNamespace

import pytest

from scripts import native_checkpoint_observation as observation
from scripts import native_linux_owner_checkpoint as native
from scripts.native_checkpoint_fixture import REMOTE
from scripts.native_checkpoint_probe import PROGRAM
from scripts.native_linux_guest import GuestBootError
from scripts.run_stats import valid_stats

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_checkpoint_probe.py",
        "scripts/native_checkpoint_fixture.py",
        "scripts/native_checkpoint_observation.py",
        "scripts/native_linux_owner_checkpoint.py",
    ],
    "scope": "invented checkpoint records and original-trace controls, publication/lock/reply ordering, protected input selection, and mocked enrolled-guest orchestration",
    "relationship": "no-product-claim",
    "reason": "Synthetic file/process/syscall records and parsed embedded programs challenge qualification tooling only. No guest payload, downloaded runtime, compiler, privilege change, real guest or native backend enrollment executes.",
    "claims": [],
}

ENROLLMENT = "09f38a1c-2c2b-4753-8107-3b39b08aeb54"
BOOT = "3535e5f7-240b-402b-b6cf-650944061b98"
AUTHORITY = "/var/lib/fixture/authority"


def quoted(value):
    raw = value.encode() if isinstance(value, str) else value
    return '"' + "".join("\\x" + format(byte, "02x") for byte in raw) + '"'


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def metadata(raw=None, *, inode=20, mode=0o600, kind="regular"):
    value = dict(
        device=10,
        inode=inode,
        uid=0,
        gid=0,
        mode=mode,
        links=1,
        kind=kind,
        mtime_ns=100,
        ctime_ns=200,
        file_capability=None,
    )
    if raw is not None:
        value.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    return value


def checkpoint():
    context = {
        "owner": native.fixture_owner(ENROLLMENT),
        "journal_id": "2620b7b5-71cc-4dc9-94e3-d8f8c4db38ca",
    }
    value = {
        "format": "fishhat.checkpoint-store/v1",
        **context,
        "anchor": {"device": 10, "inode": 20},
        "previous": None,
        "current": None,
    }
    raw = canonical(value)
    snapshot = {
        "directory": metadata(mode=0o700, kind="directory", inode=19),
        "entries": {"anchor": metadata(b""), "current": metadata(raw, inode=21)},
        "original_files_base64": {"anchor": "", "current": base64.b64encode(raw).decode()},
    }
    return context, value, snapshot


def publication_trace(*, initialize=False, uncertain=False, interrupted=False, reply=True):
    _, value, _ = checkpoint()
    value["current"] = "a" * 64
    payload = canonical(value)
    lines = [
        f"openat(AT_FDCWD, {quoted(AUTHORITY)}, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) = 4",
        f"openat(4, {quoted('anchor')}, O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 5",
        "flock(5, LOCK_EX|LOCK_NB) = 0",
    ]
    if initialize:
        lines.append("fsync(5) = 0")
    lines += [
        f"openat(4, {quoted('.pending')}, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600) = 6",
        f"write(6, {quoted(payload)}, {len(payload)}) = {len(payload)}",
        "fsync(6) = 0",
        "close(6) = 0",
    ]
    if not interrupted:
        if initialize:
            lines += [
                f"linkat(4, {quoted('.pending')}, 4, {quoted('current')}, 0) = 0",
                f"unlinkat(4, {quoted('.pending')}, 0) = 0",
            ]
        else:
            lines.append(f"renameat(4, {quoted('.pending')}, 4, {quoted('current')}) = 0")
        lines += [
            "fsync(4) = -1 EIO (Input/output error) (INJECTED)" if uncertain else "fsync(4) = 0",
            "flock(5, LOCK_UN) = 0",
        ]
    if reply:
        reply_bytes = b"reply\n"
        lines.append(f"write(1, {quoted(reply_bytes)}, 6) = 6")
    return value, lines


def test_guest_payloads_are_parsed_without_substituting_backend_calls():
    for text in (PROGRAM, REMOTE, native.CLEANUP, native.MEMORY_OBSERVATION):
        ast.parse(text)
    tree = ast.parse(PROGRAM)
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert {"initialize", "open", "read", "locked", "compare_and_swap"} <= calls
    assert not any(
        isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "checkpoint_store"
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        )
        for node in ast.walk(tree)
    )


def test_closed_workload_preserves_roles_domains_and_controlled_fault_scope():
    rows = observation.selection(
        {"heads": ["a" * 64, "b" * 64], "admin_account": "admin", "peer_account": "peer"}
    )
    assert len(rows) == 68 and len(native.CASES) == 19
    assert rows["refuse-admin-initialize"]["role"] == "admin"
    assert rows["refuse-peer-inspect"]["role"] == "peer"
    assert rows["refuse-same-domain"]["request"]["capture"] == "same-domain"
    assert rows["copy-lock-refused"]["request"]["journal_index"] == 1
    assert rows["pending-publication"]["inject"] == "--inject=renameat:signal=SIGSTOP:when=1"
    assert {name for name, row in rows.items() if row["outcome"] == "killed"} == {
        "incomplete-initialize",
        "pending-publication",
        "lost-before-reply",
    }
    assert [row["inject"] for row in rows.values() if row["outcome"] == "uncertain"] == [
        "--inject=fsync:error=EIO:when=2"
    ]


def test_versioned_record_binds_exact_original_bytes_and_anchor():
    context, value, snapshot = checkpoint()
    assert observation._record(snapshot, context) == value


@pytest.mark.parametrize(
    "field",
    [
        "owner",
        "epoch",
        "journal",
        "format",
        "anchor",
        "boolean-anchor",
        "head",
        "extra",
        "noncanonical",
        "mode",
        "links",
        "uid",
        "capability",
        "anchor-bytes",
        "digest",
        "namespace",
        "directory-mode",
        "directory-capability",
        "history",
    ],
)
def test_record_reader_refuses_changed_custody(field):
    context, value, snapshot = checkpoint()
    if field == "owner":
        value["owner"]["id"] = BOOT
        context = {**context, "owner": native.fixture_owner(ENROLLMENT)}
    elif field == "epoch":
        value["owner"]["epoch"] = BOOT
        context = {**context, "owner": native.fixture_owner(ENROLLMENT)}
    elif field == "journal":
        value["journal_id"] = BOOT
    elif field == "format":
        value["format"] = "foreign"
    elif field == "anchor":
        value["anchor"]["inode"] += 1
    elif field == "boolean-anchor":
        value["anchor"]["device"] = True
    elif field == "head":
        value["current"] = "invalid"
    elif field == "history":
        value["previous"] = "a" * 64
    elif field == "extra":
        value["unapproved"] = True
    raw = canonical(value)
    if field == "noncanonical":
        raw = json.dumps(value, indent=2).encode()
    snapshot["original_files_base64"]["current"] = base64.b64encode(raw).decode()
    snapshot["entries"]["current"] = metadata(raw, inode=21)
    if field in ("mode", "links", "uid", "capability"):
        key = {"capability": "file_capability"}.get(field, field)
        snapshot["entries"]["current"][key] = {
            "mode": 0o640,
            "links": 2,
            "uid": 1001,
            "capability": "capability",
        }[field]
    elif field == "anchor-bytes":
        snapshot["entries"]["anchor"] = metadata(b"retained")
        snapshot["original_files_base64"]["anchor"] = base64.b64encode(b"retained").decode()
    elif field == "digest":
        snapshot["entries"]["current"]["sha256"] = "0" * 64
    elif field == "directory-mode":
        snapshot["directory"]["mode"] = 0o750
    elif field == "directory-capability":
        snapshot["directory"]["file_capability"] = "capability"
    elif field == "namespace":
        snapshot["entries"]["unapproved"] = metadata(b"unknown", inode=22)
    with pytest.raises(GuestBootError):
        observation._record(snapshot, context)


@pytest.mark.parametrize("initialize", [False, True])
def test_original_publication_requires_sync_and_anchor_lock(initialize):
    value, lines = publication_trace(initialize=initialize)
    parsed = observation.trace_events("\n".join(lines), AUTHORITY)
    observation._publication(parsed["events"], AUTHORITY, value, initialize=initialize)
    assert parsed["stdout"] == b"reply\n"


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-file-sync",
        "missing-directory-sync",
        "early-reply",
        "early-unlock",
        "unlocked-write",
        "wrong-head",
        "wrong-target",
        "injected-directory-error",
    ],
)
def test_publication_reader_refuses_forged_ordering(mutation):
    value, lines = publication_trace()
    if mutation == "missing-file-sync":
        lines.remove("fsync(6) = 0")
    elif mutation == "missing-directory-sync":
        lines.remove("fsync(4) = 0")
    elif mutation == "early-reply":
        lines.insert(0, lines.pop())
    elif mutation == "early-unlock":
        lines.insert(lines.index("fsync(6) = 0"), "flock(5, LOCK_UN) = 0")
    elif mutation == "unlocked-write":
        lines.remove("flock(5, LOCK_EX|LOCK_NB) = 0")
    elif mutation == "wrong-head":
        value["current"] = "b" * 64
    elif mutation == "wrong-target":
        lines = [
            line.replace(quoted("current"), quoted("foreign"))
            if line.startswith("renameat(")
            else line
            for line in lines
        ]
    else:
        lines[lines.index("fsync(4) = 0")] = "fsync(4) = -1 EIO (Input/output error) (INJECTED)"
    with pytest.raises(GuestBootError):
        observation._publication(
            observation.trace_events("\n".join(lines), AUTHORITY)["events"], AUTHORITY, value
        )


def test_pending_interruption_and_lost_reply_do_not_create_acknowledgement():
    value, lines = publication_trace(interrupted=True, reply=False)
    observation._publication(
        observation.trace_events("\n".join(lines), AUTHORITY)["events"],
        AUTHORITY,
        value,
        interrupted=True,
    )
    value, lines = publication_trace(reply=False)
    observation._publication(
        observation.trace_events("\n".join(lines), AUTHORITY)["events"],
        AUTHORITY,
        value,
        unacknowledged=True,
    )
    lines.append(f"write(1, {quoted(b'ack')}, 3) = 3")
    with pytest.raises(GuestBootError):
        observation._publication(
            observation.trace_events("\n".join(lines), AUTHORITY)["events"],
            AUTHORITY,
            value,
            unacknowledged=True,
        )


def test_controlled_directory_error_is_not_a_successful_directory_sync():
    value, lines = publication_trace(uncertain=True)
    events = observation.trace_events("\n".join(lines), AUTHORITY)["events"]
    observation._publication(events, AUTHORITY, value, uncertain=True)
    with pytest.raises(GuestBootError):
        observation._publication(events, AUTHORITY, value)


def test_complete_reads_follow_duplicated_directory_descriptors():
    _, value, _ = checkpoint()
    raw = canonical(value)
    lines = [
        f"openat(AT_FDCWD, {quoted(AUTHORITY)}, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) = 4",
        "fcntl(4, F_DUPFD_CLOEXEC, 0) = 7",
        "close(4) = 0",
        f"openat(7, {quoted('current')}, O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 6",
        f"read(6, {quoted(raw[:10])}, 65536) = 10",
        f"read(6, {quoted(raw[10:])}, 65536) = {len(raw) - 10}",
        'read(6, "", 65536) = 0',
    ]
    events = observation.trace_events("\n".join(lines), AUTHORITY)["events"]
    assert observation._current_reads(events, AUTHORITY) == [raw]
    with pytest.raises(GuestBootError):
        observation._current_reads(
            observation.trace_events("\n".join(lines[:-1]), AUTHORITY)["events"], AUTHORITY
        )


@pytest.mark.parametrize(
    "mutation", ["unknown-dirfd", "no-nofollow", "no-cloexec", "abbreviated-read", "oversized-read"]
)
def test_trace_reader_rejects_ambiguous_or_incomplete_custody(mutation):
    lines = [
        f"openat(AT_FDCWD, {quoted(AUTHORITY)}, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) = 4",
        f"openat(4, {quoted('current')}, O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 6",
        f"read(6, {quoted(b'abc')}, 65536) = 3",
    ]
    if mutation == "unknown-dirfd":
        lines[1] = lines[1].replace("openat(4,", "openat(99,")
    elif mutation == "no-nofollow":
        lines[1] = lines[1].replace("|O_NOFOLLOW", "")
    elif mutation == "no-cloexec":
        lines[1] = lines[1].replace("|O_CLOEXEC", "")
    elif mutation == "abbreviated-read":
        lines[2] = lines[2].replace("= 3", "= 4")
    else:
        lines[2] = lines[2].replace("65536", "2")
    with pytest.raises(GuestBootError):
        observation.trace_events("\n".join(lines), AUTHORITY)


def guest_fixture():
    return SimpleNamespace(
        enrollment=ENROLLMENT,
        observed={
            "boot_id": BOOT,
            "accounts": {"admin": {"uid": 1001, "gid": 1001}, "peer": {"uid": 1002, "gid": 1002}},
        },
        accounts=("admin", "peer"),
    )


def test_context_keeps_installed_authority_separate_from_journal_capture():
    guest = guest_fixture()
    c = native.fixture_context(guest)
    assert c["owner"] == native.fixture_owner(ENROLLMENT) and c["boot_id"] == BOOT
    assert set(c["cases"]) == set(native.CASES)
    assert all(
        path.startswith("/var/lib/fishhat-checkpoint-fixture-" + ENROLLMENT + "/authority/")
        for path in c["cases"].values()
    )
    assert all(
        path.startswith("/run/fhs-" + ENROLLMENT.replace("-", "") + "/control/")
        for path in c["journals"]
    )
    assert c["local_journal"].startswith("/var/lib/")
    assert c["probe_sha256"] == hashlib.sha256(PROGRAM.encode()).hexdigest()


@pytest.mark.parametrize("failure", ["guest", "storage", "storage-context"])
def test_qualification_refuses_missing_enrollment_or_storage_before_actions(tmp_path, failure):
    guest = guest_fixture()
    storage = {
        "status": "passed",
        "permissions_verified": True,
        "filesystems": {"root": {}, "control": {}, "data": {}},
    }
    if failure == "guest":
        guest.observed = None
    elif failure == "storage":
        storage["status"] = "failed"
    else:
        storage["filesystems"].pop("control")
    with pytest.raises(GuestBootError):
        native.qualify_checkpoint(guest, tmp_path, lambda _: None, {}, storage)


@pytest.mark.parametrize(
    "failure",
    [
        None,
        "transport",
        "transport-baseline",
        "transport-diagnostics",
        "cleanup-identity",
        "cleanup-process",
        "validation",
    ],
)
def test_guarded_coordinator_retains_originals_cleanup_and_scoped_statistics(
    tmp_path, monkeypatch, failure
):
    from contextlib import nullcontext

    guest = guest_fixture()
    context = native.fixture_context(guest)
    inputs = {
        "context": context,
        "input_sha256": "a" * 64,
        "input_bytes": 1,
        "input_members": {"inert": "b" * 64},
        "bootstrap_sha256": "c" * 64,
        "manifest_sha256": "d" * 64,
    }
    prepared = tmp_path / "inert-input"
    prepared.write_bytes(b"inert")
    monkeypatch.setattr(native, "_prepare_inputs", lambda *args: (prepared, inputs))
    value = {"observer_pid": 300, "owned_children": [{"tracer_pid": 301, "tracee_pids": [302]}]}
    calls = []
    memory_calls = []
    transport_error = GuestBootError("controlled transport")

    def guarded(action, enrollment, boot, **options):
        assert (
            enrollment == ENROLLMENT
            and boot == BOOT
            and action[:5] == ["/usr/bin/python3", "-I", "-S", "-B", "-c"]
        )
        ast.parse(action[5])
        if action[5] == native.MEMORY_OBSERVATION:
            assert options == {"nominal": 15}
            memory_calls.append(action)
            if failure == "transport-baseline" and len(memory_calls) == 1:
                raise GuestBootError("fixture-private-value")
            if failure == "transport-diagnostics" and len(memory_calls) == 2:
                raise GuestBootError("fixture-private-value")
            return json.dumps(
                {
                    "scope": "checkpoint-guest-memory-diagnostics-only",
                    "pid": 500 + len(memory_calls),
                    "uid": 0,
                    "boot_id": BOOT,
                    "enrollment": ENROLLMENT,
                    "oom_kills": len(memory_calls) - 1,
                    "available_memory_kib": 1024,
                }
            )
        calls.append((action, options))
        if len(calls) == 1:
            assert action[5] == REMOTE and options["input_path"] == prepared
            if failure is not None and failure.startswith("transport"):
                raise transport_error
            return json.dumps(value)
        assert action[5] == native.CLEANUP
        request = json.loads(action[6])
        answer = {
            "pid": 303,
            "uid": 0,
            "boot_id": BOOT,
            "enrollment": ENROLLMENT,
            "paths": [{"path": name, "absent": True} for name in request["paths"]],
            "processes": [{"pid": pid, "absent": True} for pid in request["pids"]],
        }
        if failure == "cleanup-identity":
            answer["pid"] = 300
        if failure == "cleanup-process":
            answer["processes"][0]["absent"] = False
        return json.dumps(answer)

    guest.guarded = guarded

    def verify(received, c):
        assert received == value and c["inputs"] == inputs and c["boot_id"] == BOOT
        if failure == "validation":
            raise GuestBootError("controlled evidence")

    monkeypatch.setattr(observation, "verify_observation", verify)
    report = {}
    storage = {
        "status": "passed",
        "permissions_verified": True,
        "filesystems": {"root": {}, "control": {}, "data": {}},
    }
    if failure is None:
        native.qualify_checkpoint(guest, tmp_path, lambda _: nullcontext(), report, storage)
    else:
        with pytest.raises(GuestBootError) as caught:
            native.qualify_checkpoint(guest, tmp_path, lambda _: nullcontext(), report, storage)
        if failure.startswith("transport"):
            assert caught.value is transport_error
    assert report["status"] == ("passed" if failure is None else "failed")
    assert valid_stats(report["qualification_statistics"])
    assert (
        report["native_product_qualified"]
        is report["writer_authority_qualified"]
        is report["resources_destroyed_with_guest"]
        is False
    )
    assert calls[0][1]["nominal"] == 1200
    if failure is not None and failure.startswith("transport"):
        resources = report["failure_resources"]
        assert resources["qualification_claimed"] is False and len(memory_calls) == 2
        for name in ("before", "after"):
            observed = resources[name]
            assert observed["qualification_claimed"] is False
            if (failure == "transport-baseline" and name == "before") or (
                failure == "transport-diagnostics" and name == "after"
            ):
                assert observed == {"status": "unavailable", "qualification_claimed": False}
            else:
                assert observed["status"] == "observed"
                assert (
                    observed["original_reply_sha256"]
                    == hashlib.sha256(observed["original_reply"].encode()).hexdigest()
                )
        assert "fixture-private-value" not in json.dumps(report)
    else:
        assert "failure_resources" not in report and len(memory_calls) == 1
        assert (
            report["original_observation"] == value
            and report["original_reply_sha256"]
            == hashlib.sha256(json.dumps(value).encode()).hexdigest()
        )


@pytest.mark.parametrize(
    "mutation",
    [None, "missing-open", "missing-chmod", "changed-path", "allowed-open", "no-reply-denials"],
)
def test_unprivileged_modification_requires_original_kernel_refusals(mutation):
    context = {
        "library": "/var/lib/fixture/packages/lib",
        "cases": {"valid": AUTHORITY},
        "journals": ["/run/journal/original"],
    }
    paths = [
        context["library"] + "/fishhat_owner/checkpoint_store.py",
        "/var/lib/fixture/runtime/python/bin/python3.12",
        "/var/lib/fixture/probe.py",
        "/var/lib/fixture/context.json",
        AUTHORITY + "/anchor",
        AUTHORITY + "/current",
        "/run/journal/original/HEAD",
    ]
    lines = []
    denials = []
    for path in paths:
        lines.extend(
            [
                f"openat(AT_FDCWD, {quoted(path)}, O_WRONLY|O_NOFOLLOW|O_CLOEXEC) = -1 EACCES (Permission denied)",
                f"chmod({quoted(path)}, 0600) = -1 EPERM (Operation not permitted)",
            ]
        )
        denials.extend(
            {"path": path, "operation": operation, "errno": code}
            for operation, code in (("open-write", 13), ("chmod", 1))
        )
    if mutation == "missing-open":
        lines.pop(0)
    elif mutation == "missing-chmod":
        lines.pop(1)
    elif mutation == "changed-path":
        lines[0] = lines[0].replace(quoted(paths[0]), quoted("/foreign"))
    elif mutation == "allowed-open":
        lines[0] = lines[0].replace("-1 EACCES (Permission denied)", "5")
    elif mutation == "no-reply-denials":
        denials.pop()
    row = {"trace_originals": [{"original": "\n".join(lines)}]}
    reply = {"details": {"denied_modifications": denials}, "record": None, "error": None}
    if mutation is None:
        observation._modification_refusals(row, reply, context)
    else:
        with pytest.raises(GuestBootError):
            observation._modification_refusals(row, reply, context)


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "trace-pid",
        "exe",
        "exe-sha",
        "argv",
        "environment",
        "session",
        "parent",
        "uid",
        "gid",
        "capabilities",
        "marker-groups",
        "marker-capabilities",
        "stop-state",
        "stop-original",
    ],
)
def test_live_process_facts_require_exact_original_execution(mutation):
    import copy

    arguments = ["/runtime/python", "-I", "-S", "-B", "/probe", "{}"]
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    line = f"execve({quoted(arguments[0])}, [{', '.join(quoted(x) for x in arguments)}], [{', '.join(quoted(k + '=' + v) for k, v in environment.items())}]) = 0"
    raw = line + "\n--- SIGSTOP {si_signo=SIGSTOP, si_code=SI_KERNEL} ---\n"
    process = {
        "pid": 101,
        "executable": arguments[0],
        "executable_sha256": "a" * 64,
        "cmdline_hex": (b"\0".join(x.encode() for x in arguments) + b"\0").hex(),
        "environment_sha256": hashlib.sha256(
            b"\0".join((k + "=" + v).encode() for k, v in environment.items()) + b"\0"
        ).hexdigest(),
        "process_group": 100,
        "session": 100,
        "parent_pid": 100,
        "state": "T",
        "status": {"Uid": "0 0 0 0", "Gid": "0 0 0 0", "Groups": "0", "CapEff": "0000000000000001"},
    }
    live = {"process": copy.deepcopy(process), "trace_before_original": raw}
    row = {
        "tracer_pid": 100,
        "trace_originals": [{"pid": 101, "original": raw + "+++ killed by SIGKILL +++\n"}],
    }
    c = {"inputs": {"runtime_executable_sha256": "a" * 64}}
    if mutation in ("marker-groups", "marker-capabilities"):
        marker = {"origin": {"capabilities": "0000000000000001", "groups": [0]}}
        marker["origin"]["groups" if mutation == "marker-groups" else "capabilities"] = (
            [1] if mutation == "marker-groups" else "0000000000000002"
        )
        live["marker_original_base64"] = base64.b64encode(canonical(marker)).decode()
    elif mutation == "trace-pid":
        live["process"]["pid"] = 102
    elif mutation in ("exe", "exe-sha", "argv", "environment", "session", "parent", "stop-state"):
        key = {
            "exe": "executable",
            "exe-sha": "executable_sha256",
            "argv": "cmdline_hex",
            "environment": "environment_sha256",
            "session": "session",
            "parent": "parent_pid",
            "stop-state": "state",
        }[mutation]
        live["process"][key] = 102 if mutation in ("session", "parent") else "00"
    elif mutation in ("uid", "gid", "capabilities"):
        live["process"]["status"][
            {"uid": "Uid", "gid": "Gid", "capabilities": "CapEff"}[mutation]
        ] = "1 1 1 1" if mutation != "capabilities" else "invalid"
    elif mutation == "stop-original":
        live["trace_before_original"] += "invented"
    if mutation is None:
        observation._live_invocation(live, row, c)
    else:
        with pytest.raises(GuestBootError):
            observation._live_invocation(live, row, c)


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "boot",
        "enrollment",
        "scope",
        "uid",
        "boolean-uid",
        "pid",
        "boolean-pid",
        "oom",
        "boolean-oom",
        "memory",
        "extra",
        "malformed",
        "transport",
    ],
)
def test_memory_diagnostics_bind_guest_and_boot_without_granting_qualification(mutation):
    guest = guest_fixture()
    value = {
        "scope": "checkpoint-guest-memory-diagnostics-only",
        "pid": 500,
        "uid": 0,
        "boot_id": BOOT,
        "enrollment": ENROLLMENT,
        "oom_kills": 1,
        "available_memory_kib": 1024,
    }
    mutations = {
        "boot": ("boot_id", ENROLLMENT),
        "enrollment": ("enrollment", BOOT),
        "scope": ("scope", "fixture-private-value"),
        "uid": ("uid", 1000),
        "boolean-uid": ("uid", False),
        "pid": ("pid", 1),
        "boolean-pid": ("pid", True),
        "oom": ("oom_kills", -1),
        "boolean-oom": ("oom_kills", True),
        "memory": ("available_memory_kib", -1),
        "extra": ("extra", "fixture-private-value"),
    }
    if mutation in mutations:
        key, replacement = mutations[mutation]
        value[key] = replacement
    raw = "fixture-private-value" if mutation == "malformed" else json.dumps(value)

    def guarded(action, enrollment, boot, **options):
        assert action[:6] == ["/usr/bin/python3", "-I", "-S", "-B", "-c", native.MEMORY_OBSERVATION]
        assert json.loads(action[6]) == {"boot_id": BOOT, "enrollment": ENROLLMENT}
        assert enrollment == ENROLLMENT and boot == BOOT and options == {"nominal": 15}
        if mutation == "transport":
            raise GuestBootError("fixture-private-value")
        return raw

    guest.guarded = guarded
    observed = native.memory_observation(guest)
    assert observed["qualification_claimed"] is False
    if mutation is None:
        assert observed["status"] == "observed" and observed["observation"] == value
        assert observed["original_reply"] == raw
        assert observed["original_reply_sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    else:
        assert observed == {"status": "unavailable", "qualification_claimed": False}
    assert "fixture-private-value" not in json.dumps(observed)


def test_checkpoint_reply_streams_one_complete_json_without_monolithic_copy():
    tree = ast.parse(REMOTE)
    write, newline, flush = tree.body[-3:]
    assert ast.dump(write.value) == ast.dump(
        ast.parse("json.dump(result,sys.stdout,sort_keys=True)").body[0].value
    )
    assert ast.dump(newline.value) == ast.dump(ast.parse("sys.stdout.write('\\n')").body[0].value)
    assert ast.dump(flush.value) == ast.dump(ast.parse("sys.stdout.flush()").body[0].value)
