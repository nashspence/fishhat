"""Exercise the real storage owner protocol without privileged native operations."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from scripts.native_smoke_storage_process import Commands
from scripts.validation_timeouts import Deadline, watchdog
from tests.support import ROOT

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "scripts/native_smoke_storage_process.py",
        "scripts/native_smoke_storage.py",
        "scripts/native_smoke_storage_qualification.py",
        "scripts/ci/native_smoke.sh",
    ],
    "scope": "real unprivileged command/protocol/parent-loss cleanup, retained arena and descriptor identity, typed complete normal/interrupted fixture receipt/source/run bindings and actual Bash clients",
    "relationship": "no-product-claim",
    "reason": "Controlled processes, files and synthetic root observation records test fixture enforcement and receipt validation; no loop, mount, account or namespace operation runs.",
    "claims": [],
}

PROGRAM = r"""
import ctypes, json, os, select, signal, subprocess, sys, time, uuid
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from scripts.native_smoke_storage_process import Commands, Parent, receive, send, serve
from scripts.validation_timeouts import Deadline, watchdog
directory, mode, role = Path(sys.argv[2]), sys.argv[3], sys.argv[4]
end = float(sys.argv[5])
token = sys.argv[6]

class Backend:
    def __init__(self, commands):
        self.commands = commands
        self.handle = None
        self.events = []
    def claim(self):
        result = {'enrollment': token}
        if self.handle is not None:
            value = os.fstat(self.handle)
            result['image'] = {'inode': value.st_ino, 'device': value.st_dev, 'uid': os.getuid()}
        return result
    def setup(self, end):
        assert self.handle is None
        self.handle = os.open(directory / 'owned', os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        self.events.append('setup')
        return {'retained': True}
    def quota(self, dimension, end):
        self.events.append(dimension)
        if mode in ('command-failure', 'both-fail'):
            self.commands.run([sys.executable, '-c', 'raise SystemExit(17)'], end)
        elif mode in ('parent-active', 'deadline'):
            self.commands.run([sys.executable, '-c',
                "import os,time;from pathlib import Path;Path(" + repr(str(directory / 'command-started')) + ").write_text(str(os.getpid()));time.sleep(60)"], end)
        return {'complete': True}
    def cleanup(self, end):
        self.events.append('cleanup')
        assert (directory / 'unrelated').read_bytes() == b'protected'
        if self.handle is not None:
            assert os.fstat(self.handle).st_ino == (directory / 'owned').lstat().st_ino
            (directory / 'owned').unlink()
        if mode in ('cleanup-failure', 'both-fail'):
            raise ValueError('selected-cleanup-failure')
        return {'absent': not (directory / 'owned').exists()}
    def close(self):
        if self.handle is not None:
            os.close(self.handle)
        (directory / 'events').write_text(json.dumps(self.events))

if role == 'owner':
    parent = Parent.open(os.getppid(), os.getuid(), os.getgid(), end)
    try:
        result = serve(Backend(Commands(parent)), token, parent, 0, 1, end)
        (directory / 'outcome').write_text(json.dumps({'primary': result.primary, 'cleanup': result.cleanup}))
    finally:
        parent.close()
    raise SystemExit(result.status)
if role == 'parent':
    child = subprocess.Popen([sys.executable, __file__, sys.argv[1], str(directory), mode, 'owner', str(end), token])
    raise SystemExit(child.wait())

# Only this disposable test coordinator becomes a subreaper, so a deliberately
# exited parent cannot leave its owner or the owner's controlled command behind.
library = ctypes.CDLL(None, use_errno=True)
assert library.prctl(36, 1, 0, 0, 0) == 0
parent = subprocess.Popen([sys.executable, __file__, sys.argv[1], str(directory), mode, 'parent', str(end), token], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
handle = os.pidfd_open(parent.pid)
assert parent.stdin is not None and parent.stdout is not None
claim = {'enrollment': token}
def request(action, *, primary=0, modified=None, stage_end=None):
    global claim
    send(parent.stdin.fileno(), {'enrollment': token, 'action': action, 'claim': claim if modified is None else modified, 'end': end if stage_end is None else stage_end, 'primary': primary}, end)
    reply = receive(parent.stdout.fileno(), end)
    claim = reply['claim']
    return reply
try:
    assert request('setup')['status'] == 0
    status = 0
    if mode == 'foreign-claim':
        foreign = json.loads(json.dumps(claim)); foreign['image']['inode'] += 1
        status = request('bytes', modified=foreign)['status']
        assert status == 1
    elif mode == 'type-confused-claim':
        foreign = json.loads(json.dumps(claim)); foreign['image']['uid'] = bool(foreign['image']['uid'])
        status = request('bytes', modified=foreign)['status']
        assert status == 1
    elif mode in ('malformed', 'eof'):
        if mode == 'malformed':
            parent.stdin.write(b'{"enrollment":1,"enrollment":2}\n'); parent.stdin.flush()
        else:
            parent.stdin.close()
    elif mode in ('parent-idle', 'parent-active'):
        if mode == 'parent-active':
            send(parent.stdin.fileno(), {'enrollment': token, 'action': 'bytes', 'claim': claim, 'end': end, 'primary': 0}, end)
            ready = Deadline.after(5)
            while not (directory / 'command-started').exists():
                assert ready.remaining() > 0
                time.sleep(.01)
        signal.pidfd_send_signal(handle, signal.SIGKILL)
    elif mode == 'deadline':
        status = request('bytes', stage_end=time.monotonic() + watchdog(.2))['status']
        assert status == 1
    elif mode in ('command-failure', 'both-fail'):
        status = request('bytes')['status']
        assert status == 17
    else:
        assert request('bytes')['status'] == 0
        assert request('inodes')['status'] == 0
    if mode not in ('malformed', 'eof', 'parent-idle', 'parent-active'):
        reply = request('cleanup', primary=status)
        assert reply['status'] == (1 if mode in ('cleanup-failure', 'both-fail') else 0)
    parent.wait(timeout=Deadline(end).remaining())
    if mode in ('parent-idle', 'parent-active'):
        adopted, result = os.waitpid(-1, 0)
        assert adopted > 0 and os.waitstatus_to_exitcode(result) == 1
    try:
        os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        raise AssertionError('unreaped test child')
    print(json.dumps({'outcome': json.loads((directory / 'outcome').read_text()), 'events': json.loads((directory / 'events').read_text()), 'absent': not (directory / 'owned').exists(), 'canary': (directory / 'unrelated').read_text(), 'reaped': True}))
finally:
    if parent.poll() is None:
        signal.pidfd_send_signal(handle, signal.SIGKILL)
        parent.wait(timeout=watchdog(5))
    os.close(handle)
"""


@pytest.mark.parametrize(
    ("mode", "primary", "cleanup"),
    [
        ("normal", 0, 0),
        ("command-failure", 17, 0),
        ("foreign-claim", 1, 0),
        ("type-confused-claim", 1, 0),
        ("malformed", 1, 0),
        ("eof", 1, 0),
        ("parent-idle", 1, 0),
        ("parent-active", 1, 0),
        ("deadline", 1, 0),
        ("cleanup-failure", 0, 1),
        ("both-fail", 17, 1),
    ],
    ids=lambda value: str(value),
)
def test_real_owner_protocol_and_lost_parent_preserve_cleanup(tmp_path, mode, primary, cleanup):
    import uuid

    program = tmp_path / "processes.py"
    program.write_text(PROGRAM)
    (tmp_path / "unrelated").write_bytes(b"protected")
    result = subprocess.run(
        [
            "/usr/bin/python3",
            str(program),
            str(ROOT),
            str(tmp_path),
            mode,
            "coordinator",
            str(Deadline.after(20).end),
            str(uuid.uuid4()),
        ],
        capture_output=True,
        text=True,
        timeout=watchdog(25),
    )
    assert result.returncode == 0, result.stderr
    proof = json.loads(result.stdout)
    assert proof["outcome"] == {"primary": primary, "cleanup": cleanup}
    assert proof["absent"] is proof["reaped"] is True
    assert proof["canary"] == "protected"
    assert proof["events"][0] == "setup" and proof["events"][-1] == "cleanup"
    if mode in {"foreign-claim", "type-confused-claim"}:
        assert proof["events"] == ["setup", "cleanup"]
    if mode == "normal":
        assert proof["events"] == ["setup", "bytes", "inodes", "cleanup"]


def test_real_command_failure_keeps_the_original_status():
    bootstrap = "import sys;sys.path.insert(0,sys.argv[1]);from scripts.native_smoke_storage_process import Commands,CommandFailed;from scripts.validation_timeouts import Deadline\ntry:\n Commands(None).run([sys.executable,'-c','raise SystemExit(23)'],Deadline.after(5).end)\nexcept CommandFailed as error:\n print(error.status)"
    result = subprocess.run(
        ["/usr/bin/python3", "-c", bootstrap, str(ROOT)],
        capture_output=True,
        text=True,
        timeout=watchdog(10),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "23"


def test_command_rejects_an_expired_deadline_before_execution(tmp_path):
    canary = tmp_path / "not-created"
    with pytest.raises(ValueError, match="loop-deadline-unavailable"):
        Commands(None).run([sys.executable, "-c", f"open({str(canary)!r}, 'w').close()"], 0)
    assert not canary.exists()


@pytest.mark.parametrize(
    "selection",
    [[], ["observe"], ["--github-hosted-only", "observe"], ["--github-hosted-only", "owner"]],
    ids=["missing", "implicit-observer", "unenrolled-observer", "unenrolled-owner"],
)
def test_native_owner_cli_refuses_missing_hosted_enrollment(selection):
    result = subprocess.run(
        [sys.executable, "-m", "scripts.native_smoke_storage", *selection],
        cwd=ROOT,
        env={"PATH": os.defpath},
        capture_output=True,
        text=True,
        timeout=watchdog(5),
    )
    assert result.returncode == 1
    assert result.stderr.startswith("native-prerequisite storage-problem=unavailable")


@pytest.fixture
def root_receipt():
    import copy
    import stat
    import uuid

    from scripts.native_smoke_interruption import digest
    from scripts.run_stats import RunStats

    enrollment = str(uuid.uuid4())
    claim = {
        "enrollment": enrollment,
        "namespace": {"device": 4, "inode": 1},
        "mount": {
            "directory": {
                "device": 7,
                "inode": 128,
                "uid": 0,
                "gid": 0,
                "mode": stat.S_IFDIR | 0o755,
            }
        },
    }
    actor = {
        "pid": 10,
        "parent_pid": 42,
        "process_group": 3,
        "session": 3,
        "start_ticks": 100,
        "uids": [0] * 4,
        "gids": [0] * 4,
    }
    parent = {
        "parent_namespace": {"device": 4, "inode": 2},
        "baseline_mounts_preserved": True,
        "owned_mount_absent": True,
        "baseline_sha256": "a" * 64,
        "observer": copy.deepcopy(actor),
    }
    report = {
        "scope": "owned-smoke-storage-lifecycle-only",
        "enrollment": enrollment,
        "native_product_qualified": False,
        "original_primary_exit": 75,
        "cleanup_exit": 0,
        "completed_stages": ["setup"],
        "evidence_validation_exit": 0,
        "claim_sha256": digest(claim),
        "statistics": RunStats().finish(),
        "parent_before": copy.deepcopy(parent),
        "parent_after": copy.deepcopy(parent),
        "source_before": {"commit": "1" * 40, "clean": True, "fingerprint": "2" * 64},
        "execution_origin": {
            "kind": "github-actions",
            "run_id": "1",
            "attempt": "1",
            "job": "native-prerequisites",
        },
    }
    report["source_after"] = copy.deepcopy(report["source_before"])
    report["retained_identity"] = copy.deepcopy(claim)
    for index, phase in enumerate(("before", "after", "retired")):
        observer = copy.deepcopy(actor)
        observer["pid"] += index
        report[phase] = {
            "phase": phase,
            "enrollment": enrollment,
            "namespace": copy.deepcopy(claim["namespace"]),
            "inventory_sha256": "b" * 64,
            "identity_sha256": digest(claim),
            "association_observation": "bound" if phase == "before" else "ENXIO",
            "association_present": phase == "before",
            "mount_present": phase == "before",
            "image_present": phase == "before",
            "observation_complete": True,
            "observer": observer,
        }
        report[phase]["arena_absent" if phase == "retired" else "unrelated_image_preserved"] = True
    return report, enrollment, claim


def test_interruption_receipt_requires_actual_absence_scope_and_original_exit(root_receipt):
    from scripts.native_smoke_storage_qualification import validate

    report, enrollment, claim = root_receipt
    assert validate(report, enrollment, claim, 75) is report


@pytest.mark.parametrize(
    "field",
    [
        "loop-left",
        "mount-left",
        "image-left",
        "arena-left",
        "canary",
        "unavailable",
        "namespace",
        "root-bool",
        "root-foreign",
        "parent-bool",
        "parent-mount",
        "parent-not-isolated",
        "cleanup",
        "primary-bool",
        "claim",
        "source",
        "origin",
        "statistics",
        "missing-before",
    ],
)
def test_interruption_receipt_refuses_partial_or_unbound_native_evidence(root_receipt, field):
    from scripts.native_smoke_storage_qualification import validate

    report, enrollment, claim = root_receipt
    if field in {"loop-left", "mount-left", "image-left"}:
        report["after"][
            {"loop-left": "association", "mount-left": "mount", "image-left": "image"}[field]
            + "_present"
        ] = True
    elif field == "arena-left":
        report["retired"]["arena_absent"] = False
    elif field == "canary":
        report["after"]["unrelated_image_preserved"] = False
    elif field == "unavailable":
        report["after"]["observation_complete"] = False
    elif field == "namespace":
        report["retired"]["namespace"]["inode"] += 1
    elif field == "root-bool":
        report["after"]["observer"]["uids"][0] = False
    elif field == "root-foreign":
        report["after"]["observer"]["parent_pid"] += 1
    elif field == "parent-bool":
        report["parent_after"]["parent_namespace"]["device"] = True
    elif field == "parent-mount":
        report["parent_after"]["baseline_mounts_preserved"] = False
    elif field == "parent-not-isolated":
        report["parent_before"]["parent_namespace"] = claim["namespace"]
        report["parent_after"]["parent_namespace"] = claim["namespace"]
    elif field == "cleanup":
        report["cleanup_exit"] = 1
    elif field == "primary-bool":
        report["original_primary_exit"] = True
    elif field == "claim":
        report["claim_sha256"] = "c" * 64
    elif field == "source":
        report["source_after"]["commit"] = "3" * 40
    elif field == "origin":
        report["execution_origin"]["attempt"] = True
    elif field == "statistics":
        report["statistics"] = None
    else:
        del report["before"]
    with pytest.raises((ValueError, KeyError, TypeError)):
        validate(report, enrollment, claim, 75)


def test_normal_receipt_preserves_full_byte_inode_workloads(root_receipt):
    from scripts.native_smoke_storage_qualification import validate

    report, enrollment, claim = root_receipt
    report.update(
        original_primary_exit=0,
        completed_stages=["setup", "bytes", "inodes"],
        bytes={
            "quota_enforced": True,
            "admitted_bytes": 8 * 1048576,
            "control_bytes": 16 * 1048576,
        },
        inodes={"quota_enforced": True, "admitted_files": 63, "control_files": 256},
    )
    assert validate(report, enrollment, claim, 0, interrupted=False) is report
    report["bytes"]["control_bytes"] //= 2
    with pytest.raises(ValueError, match="storage-byte-workload-unavailable"):
        validate(report, enrollment, claim, 0, interrupted=False)
    report["bytes"]["control_bytes"] = 16 * 1048576
    report["inodes"]["control_files"] -= 1
    with pytest.raises(ValueError, match="storage-inode-workload-unavailable"):
        validate(report, enrollment, claim, 0, interrupted=False)


def test_shell_clients_retain_the_same_real_unprivileged_owner(tmp_path):
    import shlex
    import uuid

    program = tmp_path / "processes.py"
    program.write_text(PROGRAM)
    (tmp_path / "unrelated").write_bytes(b"protected")
    enrollment = str(uuid.uuid4())
    source = (ROOT / "scripts/ci/native_smoke.sh").read_text()
    functions = source[source.index("storage_call()") : source.index("observe_owned_cleanup()")]
    code = (
        "set -euo pipefail\ntimeout_helper="
        + shlex.quote(str(ROOT / "scripts/validation_timeouts.py"))
        + "\n"
        + functions
    )
    code += "\nstorage_enrollment=" + shlex.quote(enrollment) + "\n"
    code += "storage_claim=" + shlex.quote(json.dumps({"enrollment": enrollment})) + "\n"
    code += "stage_deadline=" + str(Deadline.after(10).end) + "\n"
    command = [
        "/usr/bin/python3",
        str(program),
        str(ROOT),
        str(tmp_path),
        "normal",
        "owner",
        str(Deadline.after(15).end),
        enrollment,
    ]
    code += "coproc STORAGE { exec " + shlex.join(command) + "; }\n"
    code += 'storage_pid="$STORAGE_PID"\nexec {storage_read}<&"${STORAGE[0]}"\nexec {storage_write}>&"${STORAGE[1]}"\n'
    code += 'original_read="${STORAGE[0]}"; original_write="${STORAGE[1]}"\nexec {original_read}<&-\nexec {original_write}>&-\n'
    code += 'storage_call setup\nstorage_call bytes\nstorage_call inodes\nstorage_call cleanup 0\nexec {storage_write}>&-\nexec {storage_read}<&-\nwait "$storage_pid"\n'
    result = subprocess.run(
        ["bash", "-c", code], capture_output=True, text=True, timeout=watchdog(20)
    )
    assert result.returncode == 0, result.stderr
    assert json.loads((tmp_path / "events").read_text()) == ["setup", "bytes", "inodes", "cleanup"]
    assert json.loads((tmp_path / "outcome").read_text()) == {"primary": 0, "cleanup": 0}
    assert (
        not (tmp_path / "owned").exists() and (tmp_path / "unrelated").read_bytes() == b"protected"
    )


@pytest.mark.parametrize(
    "change", ["replacement", "symlink", "missing", "permissions", "type-confused-record"]
)
def test_retained_arena_refuses_path_or_identity_changes(tmp_path, change):
    from scripts.native_smoke_storage import directory, private_arena

    arena = tmp_path / "arena"
    arena.mkdir(mode=0o700)
    descriptor = os.open(arena, os.O_RDONLY | os.O_DIRECTORY)
    expected = directory(descriptor)
    private_arena(arena, descriptor, expected)
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir(mode=0o700)
    (unrelated / "canary").write_bytes(b"preserve")
    try:
        if change in {"replacement", "symlink", "missing"}:
            arena.rename(tmp_path / "original")
            if change == "replacement":
                arena.mkdir(mode=0o700)
            elif change == "symlink":
                arena.symlink_to(unrelated)
        elif change == "permissions":
            arena.chmod(0o755)
        else:
            expected["uid"] = bool(expected["uid"])
        with pytest.raises((OSError, ValueError)):
            private_arena(arena, descriptor, expected)
        assert (unrelated / "canary").read_bytes() == b"preserve"
    finally:
        os.close(descriptor)


def test_quota_directory_admission_failure_closes_earlier_handle(tmp_path, monkeypatch):
    import errno
    import uuid

    from scripts import native_smoke_storage as storage

    class Commands:
        def run(self, *_args, **_kwargs):
            return b""

    owner = storage.NativeStorage(str(uuid.uuid4()), (os.getuid(), os.getgid()), Commands())
    owner.arena = tmp_path
    owner.completed = ["setup"]
    (tmp_path / "mount" / "account").mkdir(parents=True)
    (tmp_path / "mount" / "control").mkdir()
    monkeypatch.setattr(owner, "check", lambda _end: None)
    original = os.open
    handles = []

    def open_directory(path, flags):
        if str(path).endswith("/control"):
            raise OSError(errno.EACCES, "selected-admission-failure")
        result = original(path, flags)
        handles.append(result)
        return result

    monkeypatch.setattr(storage.os, "open", open_directory)
    with pytest.raises(OSError, match="selected-admission-failure"):
        owner.quota("bytes", Deadline.after(5).end)
    assert len(handles) == 1
    with pytest.raises(OSError) as error:
        os.fstat(handles[0])
    assert error.value.errno == errno.EBADF
