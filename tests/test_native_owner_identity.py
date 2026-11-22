"""Invented identity receipts; embedded guest code is parsed and never executed."""

import ast
import base64
import copy
import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

import pytest

from scripts import native_linux_owner_entrypoint as entrypoint
from scripts import native_linux_owner_identity as native
from scripts.native_linux_guest import GuestBootError
from tests.test_native_owner_entrypoint import execution, quoted, receipt

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_owner_identity.py",
        "scripts/native_linux_owner_entrypoint.py",
    ],
    "scope": "synthetic complete identity receipts, schema-journal and publication synchronization ordering, inert SQL originals, original trace/proc custody and adversarial collector mutations",
    "relationship": "no-product-claim",
    "reason": "Invented process/file/syscall records and ordinary in-memory SQLite data challenge only evidence validation. No guest program, compiler, installed command, privilege change or native payload executes.",
    "claims": [],
}


def _database_bytes(owner, sql=None, parameters=(), rows=0):
    with (
        tempfile.TemporaryDirectory(prefix="fh-identity-test-") as directory,
        closing(sqlite3.connect(Path(directory) / "fixture.sqlite3")) as database,
    ):
        for statement in native._installed_catalogue().values():
            if statement is not None:
                database.execute(statement)
        database.execute("PRAGMA user_version=1")
        database.execute("INSERT INTO alembic_version VALUES('v1_0003')")
        database.execute(
            "INSERT INTO meta VALUES(?,?,0)",
            (json.dumps(["host-ops", owner["id"]], separators=(",", ":")), owner["epoch"]),
        )
        database.executemany(
            "INSERT INTO requests VALUES(?,?,?,?,?)",
            [(str(i), "a" * 64, "fixture-canary", "accepted", "none") for i in range(rows)],
        )
        if sql is not None:
            database.execute(sql, parameters)
        database.commit()
        return (Path(directory) / "fixture.sqlite3").read_bytes()


def identity_receipt():
    value, c = receipt()
    c.update(
        identity_owner=native.fixture_owner(c["enrollment"]),
        identity_trace_filter=native.TRACE_FILTER,
    )
    owner = c["identity_owner"]
    prefix = "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"]
    root = prefix + "/identity"
    counter = 10000

    def metadata(kind="directory", raw=None, mode=0o700):
        nonlocal counter
        counter += 1
        row = dict(
            device=3,
            inode=counter,
            uid=0,
            gid=0,
            links=1,
            kind=kind,
            mode=mode,
            mtime_ns=123,
            ctime_ns=456,
        )
        if raw is not None:
            row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), file_capability=None)
        return row

    def snapshot(raw=None):
        return {
            "directory": metadata(),
            "entries": {} if raw is None else {"owner.sqlite3": metadata("regular", raw, 0o600)},
            "original_files_base64": {}
            if raw is None
            else {"owner.sqlite3": base64.b64encode(raw).decode()},
        }

    def data(sql=None, parameters=(), rows=0):
        return _database_bytes(owner, sql, parameters, rows)

    raw = data()
    published = snapshot(raw)
    poison = entrypoint._poison_environment(c["enrollment"])
    command = prefix + "/complete/host-ops"

    def reply(action, success):
        if success:
            return {
                "returncode": 0,
                "stderr": "",
                "stdout": json.dumps(
                    {
                        "tool": "host-ops",
                        "status": "initialized" if action == "initialize" else "verified",
                        "owner": owner,
                        "schema_revision": "v1_0003",
                        "generation": 0,
                        "native_mutations": False,
                        "production_qualified": False,
                    }
                ),
            }
        return {
            "returncode": 2,
            "stdout": "",
            "stderr": json.dumps(
                {
                    "tool": "host-ops",
                    "status": "unconfirmed" if action == "initialize" else "invalid",
                    "error": "OWNER_INITIALIZATION_UNCONFIRMED"
                    if action == "initialize"
                    else "OWNER_STATE_REJECTED",
                }
            ),
        }

    def direct(action, path, role="root", selected=None, success=False):
        nonlocal counter
        counter += 1
        pid = counter
        uid, gid = (0, 0) if role == "root" else (c["peer_uid"], c["peer_gid"])
        facts = {
            "Pid": str(pid),
            "PPid": "50",
            "Uid": " ".join([str(uid)] * 4),
            "Gid": " ".join([str(gid)] * 4),
            "Groups": "",
            **dict.fromkeys(("CapEff", "CapPrm", "CapInh", "CapAmb"), "0000000000000000"),
        }
        return {
            "pid": pid,
            "before": {
                "pid": pid,
                "uids": [uid] * 3,
                "gids": [gid] * 3,
                "groups": [],
                "status": facts,
            },
            "joined": True,
            "role": role,
            "environment": poison,
            "argv": [command, *native._arguments(action, path, selected or owner)],
            **reply(action, success),
        }

    for relative in ("fishhat_owner/identity_store.py", "fishhat_owner/migrations/__init__.py"):
        expected = {"kind": "regular", "bytes": 4, "sha256": hashlib.sha256(b"code").hexdigest()}
        c["inputs"]["expected_wheels"]["lib/" + relative] = expected
        value["complete_before"]["packages/lib/" + relative] = metadata("regular", b"code", 0o444)
    binding = c["inputs"]["configuration"]["bindings"]["complete"]

    def trace(action, name, label, inject=None, success=True, killed=False):
        nonlocal counter
        counter += 2
        tracer, tracee = counter, counter + 1
        path = root + "/" + name
        args = native._arguments(action, path, owner)
        environment = poison | {
            "LD_DEBUG_OUTPUT": "/tmp/fishhat-entrypoint-fixture-"
            + c["enrollment"]
            + "/root/positive-loader-"
            + label
        }
        strings = [
            command,
            binding["interpreter"]["path"],
            binding["program"]["path"],
            *args,
            *[key + "=" + val for key, val in environment.items()],
        ]
        strings.append(native._success_output(owner))
        limit = (
            max(
                max(
                    len(os.fsencode(prefix + "/complete/" + key))
                    for key in value["complete_before"]
                ),
                max(len(os.fsencode(item)) for item in strings),
            )
            + 1
        )
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
            native.TRACE_FILTER,
            "-o",
            prefix + "/traces/" + label,
            "-u",
            "root",
        ]
        if inject is not None:
            observer.append(inject)
        observer += [
            item for key, val in environment.items() for item in ("-E", key + "=" + val)
        ] + [command, *args]
        lines = [
            execution(command, [command, *args], environment),
            execution(
                binding["interpreter"]["path"],
                [
                    binding["interpreter"]["path"],
                    "-I",
                    "-S",
                    "-B",
                    binding["program"]["path"],
                    *args,
                ],
                {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            ),
        ]
        origins = {}
        files = [binding["program"]["path"]] + [
            prefix + "/complete/packages/lib/" + item
            for item in (
                "fishhat_host/cli.py",
                "fishhat_cli/validation.py",
                "fishhat_owner/identity_store.py",
                "fishhat_owner/migrations/__init__.py",
                "fishhat_contracts/validation.py",
            )
        ]
        for file in files:
            lines += [f"openat(AT_FDCWD, {quoted(file)}, O_RDONLY|O_CLOEXEC) = 9", "close(9) = 0"]
            origins[file] = {
                "resolved": file,
                "metadata": copy.deepcopy(
                    value["complete_before"][file.removeprefix(prefix + "/complete/")]
                ),
            }
        lines += [
            f"openat(AT_FDCWD, {quoted(path)}, O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY) = 3",
            "flock(3, LOCK_EX|LOCK_NB) = 0"
            if action == "initialize"
            else "flock(3, LOCK_SH|LOCK_NB) = 0",
        ]
        if action == "initialize":
            lines += [
                f"openat(3, {quoted('.initializing')}, O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600) = 4",
                "fchmod(4, 0600) = 0",
            ]
            if killed:
                lines += ["--- SIGSTOP {si_signo=SIGSTOP, si_code=SI_TKILL} ---"]
            else:
                if inject is not None and "SIGSTOP" in inject:
                    lines += [
                        "--- SIGSTOP {si_signo=SIGSTOP, si_code=SI_TKILL} ---",
                        "--- SIGCONT {si_signo=SIGCONT, si_code=SI_TKILL} ---",
                    ]
                lines += [
                    f"openat(3, {quoted('.initializing-journal')}, O_RDWR|O_CREAT|O_CLOEXEC, 0600) = 5",
                    "fsync(5) = 0",
                    "fsync(3) = 0",
                    "close(5) = 0",
                    "fsync(4) = 0",
                    f"linkat(3, {quoted('.initializing')}, 3, {quoted('owner.sqlite3')}, 0) = 0",
                    f"unlinkat(3, {quoted('.initializing')}, 0) = 0",
                    "fsync(3) = 0"
                    if success
                    else "fsync(3) = -1 EIO (Input/output error) (INJECTED)",
                ]
        else:
            lines += [
                f"openat(3, {quoted('owner.sqlite3')}, O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 4",
                "close(4) = 0",
            ]
        response = reply(action, success)
        if killed:
            response = {"returncode": -9, "stdout": "", "stderr": ""}
        else:
            output = response["stdout" if success else "stderr"]
            lines += [
                f"write({1 if success else 2}, {quoted(output)}, {len(output)}) = {len(output)}",
                "+++ exited with " + ("0" if success else "2") + " +++",
            ]
        original = "\n".join(lines) + "\n"
        return dict(
            role="root",
            label=label,
            command=command,
            arguments=args,
            environment=environment,
            observer_argv=observer,
            observer_environment={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "LD_LIBRARY_PATH": prefix + "/observer/usr/lib/x86_64-linux-gnu",
            },
            string_limit=limit,
            initial_group_selection=[0],
            tracer_pid=tracer,
            tracee_pid=tracee,
            tracer_joined=True,
            tracee_absent=True,
            joined=True,
            positive_loader_files=[],
            trace_original=original,
            trace_metadata=metadata("regular", original.encode(), 0o600),
            code_opens=origins,
            **response,
        )

    def live(trace):
        executable, argv, _ = entrypoint._execution(trace["trace_original"].splitlines()[1])
        return {
            "pid": trace["tracee_pid"],
            "tracer_pid": trace["tracer_pid"],
            "start_ticks": "12345",
            "status": {
                "Pid": str(trace["tracee_pid"]),
                "PPid": str(trace["tracer_pid"]),
                "Uid": "0 0 0 0",
                "Gid": "0 0 0 0",
                "Groups": "0",
            },
            "state": "T",
            "executable": executable.decode(),
            "cmdline_hex": (b"\0".join(argv) + b"\0").hex(),
            "environment_hex": b"LANG=C.UTF-8\0LC_ALL=C.UTF-8\0".hex(),
            "process_group": trace["tracer_pid"],
            "session": trace["tracer_pid"],
            "pidfd_open": True,
        }

    proof = {
        "scope": native.SCOPE,
        "status": "passed",
        "native_owner_qualified": False,
        "owner": owner,
        "root": root,
        "elapsed_seconds": 1.25,
        "genesis": {
            "before": snapshot(),
            "after": published,
            "inspection_after": copy.deepcopy(published),
        },
        "traced_invocations": [
            trace("initialize", "valid", "root-identity-initialize"),
            trace("inspect", "valid", "root-identity-inspect"),
        ],
        "refusals": [],
    }
    proof["refusals"] = _refusals(c, root, owner, raw, published, snapshot, data, metadata, direct)
    retained = snapshot(data(rows=256))
    proof["retained_rows"] = dict(
        rows=256,
        before=retained,
        after=copy.deepcopy(retained),
        invocation=direct("inspect", root + "/retained", success=True),
    )
    for key, name in (("concurrency", "concurrent"), ("interruption", "interrupted")):
        record = trace(
            "initialize",
            name,
            "root-identity-" + name,
            "--inject=fsync:signal=SIGSTOP:when=1",
            killed=key == "interruption",
        )
        private = snapshot()
        private["entries"][".initializing"] = metadata("regular", raw, 0o600)
        private["original_files_base64"][".initializing"] = base64.b64encode(raw).decode()
        row = dict(live=live(record), private_before=private, private_after=copy.deepcopy(private))
        if key == "concurrency":
            row.update(
                completed=record,
                competing=direct("initialize", root + "/" + name),
                inspecting=direct("inspect", root + "/" + name),
                published=snapshot(raw),
            )
        else:
            row.update(
                killed=record,
                rejected=direct("inspect", root + "/" + name),
                repeated=direct("initialize", root + "/" + name),
                fresh_retry=snapshot(raw),
                retry_invocation=direct("initialize", root + "/retry", success=True),
            )
        proof[key] = row
    uncertain = snapshot(raw)
    proof["unconfirmed_publication"] = dict(
        sync_ordinal=4,
        failed=trace(
            "initialize",
            "unconfirmed",
            "root-identity-unconfirmed",
            "--inject=fsync:error=EIO:when=4",
            success=False,
        ),
        published=uncertain,
        after=copy.deepcopy(uncertain),
        reconciled=direct("inspect", root + "/unconfirmed", success=True),
        repeated=direct("initialize", root + "/unconfirmed"),
    )
    value["owner_identity"] = proof
    traces = [
        *proof["traced_invocations"],
        proof["concurrency"]["completed"],
        proof["interruption"]["killed"],
        proof["unconfirmed_publication"]["failed"],
    ]
    value["identity_children"] = [
        dict(
            label=record["label"],
            pid=record["tracer_pid"],
            joined=True,
            returncode=record["returncode"],
        )
        for record in traces
    ]
    return value, c


def _refusals(c, root, owner, raw, published, snapshot, data, metadata, direct):
    result = []
    labels = (
        "existing-identity",
        "peer-initialize",
        "peer-inspect",
        "wrong-owner",
        "wrong-epoch",
        "missing",
        "foreign-role",
        "foreign-revision",
        "missing-index",
        "extra-table",
        "foreign-wide",
        "wrong-version",
        "multiple-owners",
        "malformed",
        "symlink",
        "hardlink",
        "file-mode",
        "directory-mode",
        "file-owner",
        "capability",
        "sidecar",
        "pending",
    )
    modifications = {
        "foreign-role": (
            "UPDATE meta SET owner=?",
            (json.dumps(["app-ops", owner["id"]], separators=(",", ":")),),
        ),
        "foreign-revision": ("UPDATE alembic_version SET version_num='foreign'", ()),
        "missing-index": ("DROP INDEX requests_active", ()),
        "extra-table": ("CREATE TABLE unapproved(value TEXT)", ()),
        "foreign-wide": (
            "CREATE TABLE unapproved_wide("
            + ",".join("c" + str(i) + " TEXT" for i in range(64))
            + ")",
            (),
        ),
        "wrong-version": ("PRAGMA user_version=2", ()),
        "multiple-owners": ("INSERT INTO meta VALUES('foreign','foreign',0)", ()),
    }
    for label in labels:
        selected = dict(owner)
        role = "peer" if label.startswith("peer-") else "root"
        action = "initialize" if label in ("existing-identity", "peer-initialize") else "inspect"
        path = root + ("/valid" if label in labels[:5] else "/" + label)
        if label in ("wrong-owner", "wrong-epoch"):
            import uuid

            selected["id" if label == "wrong-owner" else "epoch"] = str(
                uuid.uuid5(
                    uuid.UUID(c["enrollment"]),
                    "foreign-owner" if label == "wrong-owner" else "foreign-owner-epoch",
                )
            )
        snap = (
            copy.deepcopy(published)
            if label in labels[:5]
            else snapshot(
                None
                if label == "missing"
                else data(*modifications[label])
                if label in modifications
                else b"not an owner database"
                if label == "malformed"
                else raw
            )
        )
        if label == "symlink":
            snap["entries"]["retained"] = snap["entries"].pop("owner.sqlite3")
            snap["original_files_base64"]["retained"] = snap["original_files_base64"].pop(
                "owner.sqlite3"
            )
            snap["entries"]["owner.sqlite3"] = metadata("symlink")
            snap["entries"]["owner.sqlite3"]["target"] = path + "/retained"
        elif label == "hardlink":
            snap["entries"]["owner.sqlite3"]["links"] = 2
            snap["entries"]["alias"] = copy.deepcopy(snap["entries"]["owner.sqlite3"])
            snap["original_files_base64"]["alias"] = snap["original_files_base64"]["owner.sqlite3"]
        elif label == "file-mode":
            snap["entries"]["owner.sqlite3"]["mode"] = 0o640
        elif label == "directory-mode":
            snap["directory"]["mode"] = 0o750
        elif label == "file-owner":
            snap["entries"]["owner.sqlite3"].update(uid=c["peer_uid"], gid=c["peer_gid"])
        elif label == "capability":
            snap["entries"]["owner.sqlite3"]["file_capability"] = (
                "0100000200040000000000000000000000000000"
            )
        elif label in ("sidecar", "pending"):
            name = "owner.sqlite3-wal" if label == "sidecar" else ".initializing"
            content = (
                b"retained uncertain bytes"
                if label == "sidecar"
                else b"retained initialization attempt"
            )
            snap["entries"][name] = metadata("regular", content, 0o600)
            snap["original_files_base64"][name] = base64.b64encode(content).decode()
        result.append(
            dict(
                label=label,
                path=path,
                action=action,
                role=role,
                expected_owner=selected,
                before=snap,
                after=copy.deepcopy(snap),
                invocation=direct(action, path, role, selected),
            )
        )
    return result


def test_complete_synthetic_identity_receipt():
    value, c = identity_receipt()
    native.verify_observation(value, c)


@pytest.mark.parametrize(
    "fault",
    [
        "scope",
        "qualification",
        "owner",
        "missing-trace",
        "missing-refusal",
        "ack-before-sync",
        "replace-publication",
        "missing-file-sync",
        "missing-final-directory-sync",
        "failed-journal-sync",
        "failed-initial-directory-sync",
        "misplaced-final-directory-sync",
        "nscd-socket",
        "write-outside",
        "network",
        "extra-exec",
        "unsafe-runtime",
        "unjoined",
        "wrong-live-pid",
        "wrong-live-exe",
        "wrong-live-env",
        "lost-private-bytes",
        "changed-retained",
        "missing-sync-error",
        "wrong-fault-ordinal",
        "missing-cleanup",
        "duplicate-pid",
        "forged-file-hash",
        "missing-original",
        "genesis-not-empty",
        "fake-symlink-control",
        "fake-filecap-control",
        "wrong-schema",
        "wrong-owner-data",
        "boolean-generation",
        "unbounded-code-origin",
        "abbreviated-exec",
    ],
)
def test_rejects_corrupted_identity_receipts(fault):
    value, c = identity_receipt()
    proof = value["owner_identity"]
    trace = proof["traced_invocations"][0]
    if fault == "scope":
        proof["scope"] = "unrelated"
    elif fault == "qualification":
        proof["native_owner_qualified"] = True
    elif fault == "owner":
        proof["owner"] = dict(proof["owner"], tool="app-ops")
    elif fault == "missing-trace":
        proof["traced_invocations"].pop()
    elif fault == "missing-refusal":
        proof["refusals"].pop()
    elif fault in (
        "ack-before-sync",
        "replace-publication",
        "missing-file-sync",
        "missing-final-directory-sync",
        "failed-journal-sync",
        "failed-initial-directory-sync",
        "misplaced-final-directory-sync",
        "nscd-socket",
        "write-outside",
        "network",
        "extra-exec",
        "abbreviated-exec",
    ):
        _corrupt_identity_trace(trace, fault)
    elif fault == "unsafe-runtime":
        trace["environment"]["PYTHONPATH"] = "/caller"
    elif fault == "unjoined":
        trace["tracer_joined"] = False
    elif fault == "wrong-live-pid":
        proof["concurrency"]["live"]["pid"] += 1
    elif fault == "wrong-live-exe":
        proof["interruption"]["live"]["executable"] = "/caller/python"
    elif fault == "wrong-live-env":
        proof["concurrency"]["live"]["environment_hex"] = b"PATH=/caller\0".hex()
    else:
        _corrupt_identity_data(value, proof, trace, fault)
    with pytest.raises((GuestBootError, KeyError, TypeError, ValueError, sqlite3.DatabaseError)):
        native.verify_observation(value, c)


def _corrupt_identity_trace(trace, fault):
    lines = trace["trace_original"].splitlines()
    if fault == "ack-before-sync":
        ack = next(line for line in lines if line.startswith("write(1,"))
        lines.remove(ack)
        lines.insert(next(i for i, line in enumerate(lines) if line == "fsync(3) = 0"), ack)
    elif fault == "replace-publication":
        lines = [line.replace("linkat(", "renameat(") for line in lines]
    elif fault == "missing-file-sync":
        lines.remove("fsync(4) = 0")
    elif fault == "missing-final-directory-sync":
        final = max(i for i, line in enumerate(lines) if line == "fsync(3) = 0")
        lines.pop(final)
    elif fault == "failed-journal-sync":
        lines[lines.index("fsync(5) = 0")] = "fsync(5) = -1 EIO (Input/output error)"
    elif fault == "failed-initial-directory-sync":
        lines[lines.index("fsync(3) = 0")] = "fsync(3) = -1 EIO (Input/output error)"
    elif fault == "misplaced-final-directory-sync":
        final = max(i for i, line in enumerate(lines) if line == "fsync(3) = 0")
        line = lines.pop(final)
        lines.insert(next(i for i, line in enumerate(lines) if line.startswith("unlinkat(")), line)
    elif fault == "nscd-socket":
        lines.insert(-1, "socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 8")
    elif fault == "write-outside":
        lines.insert(
            -1, "openat(AT_FDCWD, " + quoted("/outside/store") + ", O_WRONLY|O_CREAT, 0600) = 8"
        )
    elif fault == "network":
        lines.insert(-1, "socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 8")
    elif fault == "extra-exec":
        lines.insert(-1, execution("/unapproved", ["/unapproved"], {}))
    else:
        lines[0] = lines[0].replace("], [", ", ...], [", 1)
    trace["trace_original"] = "\n".join(lines) + "\n"
    trace["trace_metadata"].update(
        bytes=len(trace["trace_original"].encode()),
        sha256=hashlib.sha256(trace["trace_original"].encode()).hexdigest(),
    )


def _corrupt_identity_data(value, proof, trace, fault):
    if fault == "lost-private-bytes":
        proof["interruption"]["private_after"]["entries"].clear()
    elif fault == "changed-retained":
        proof["retained_rows"]["after"]["entries"]["owner.sqlite3"]["bytes"] += 1
    elif fault == "missing-sync-error":
        proof["unconfirmed_publication"]["failed"]["trace_original"] = trace["trace_original"]
    elif fault == "wrong-fault-ordinal":
        proof["unconfirmed_publication"]["sync_ordinal"] += 1
    elif fault == "missing-cleanup":
        value["identity_children"].pop()
    elif fault == "duplicate-pid":
        proof["concurrency"]["completed"]["tracee_pid"] = trace["tracee_pid"]
    elif fault == "forged-file-hash":
        proof["genesis"]["after"]["entries"]["owner.sqlite3"]["sha256"] = "0" * 64
    elif fault == "missing-original":
        proof["genesis"]["after"]["original_files_base64"].clear()
    elif fault == "genesis-not-empty":
        proof["genesis"]["before"] = proof["genesis"]["after"]
    elif fault == "fake-symlink-control":
        next(row for row in proof["refusals"] if row["label"] == "symlink")["before"]["entries"][
            "owner.sqlite3"
        ]["target"] = "/elsewhere"
    elif fault == "fake-filecap-control":
        next(row for row in proof["refusals"] if row["label"] == "capability")["before"]["entries"][
            "owner.sqlite3"
        ]["file_capability"] = None
    elif fault == "wrong-schema":
        _change_database(proof["genesis"]["after"], "DROP INDEX requests_active")
        proof["genesis"]["inspection_after"] = copy.deepcopy(proof["genesis"]["after"])
    elif fault == "wrong-owner-data":
        _change_database(proof["genesis"]["after"], "UPDATE meta SET epoch='foreign'")
        proof["genesis"]["inspection_after"] = copy.deepcopy(proof["genesis"]["after"])
    elif fault == "boolean-generation":
        result = json.loads(trace["stdout"])
        result["generation"] = False
        trace["stdout"] = json.dumps(result)
    else:
        next(iter(trace["code_opens"].values()))["resolved"] = "/caller/code.py"


def _change_database(snapshot, sql):
    with tempfile.TemporaryDirectory(prefix="fh-identity-test-") as directory:
        path = Path(directory) / "fixture.sqlite3"
        path.write_bytes(base64.b64decode(snapshot["original_files_base64"]["owner.sqlite3"]))
        with closing(sqlite3.connect(path)) as database:
            database.execute(sql)
            database.commit()
        raw = path.read_bytes()
    snapshot["original_files_base64"]["owner.sqlite3"] = base64.b64encode(raw).decode()
    snapshot["entries"]["owner.sqlite3"].update(
        bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()
    )


def test_identity_helpers_and_composed_guest_source_are_only_parsed():
    assert ast.parse(native.REMOTE_HELPERS).body
    assert ast.parse(entrypoint.REMOTE).body
    assert "identity_cleanup()" in entrypoint.REMOTE
    assert "owner_identity_probe(command)" in entrypoint.REMOTE
