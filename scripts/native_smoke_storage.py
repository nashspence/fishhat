"""Retain one enrolled root XFS owner across the hosted smoke's existing stages."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from scripts import native_smoke_quota as quota_work
from scripts.native_smoke_interruption import digest, unique_object
from scripts.native_smoke_loop import (
    ImageLease,
    KernelLoops,
    LoopLease,
    association_absent,
    live,
    metadata,
    require,
    same_claim,
    token,
)
from scripts.native_smoke_mount import MountIdentity, private, table
from scripts.native_smoke_ssh import process_state, root_enrollment, termination_guard
from scripts.native_smoke_storage_process import Commands, Parent, receive, send, serve

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "owned-smoke-storage-lifecycle-only"
FAULT_STATUS = 75


def namespace(descriptor: int) -> dict[str, int]:
    value = os.fstat(descriptor)
    return {"device": value.st_dev, "inode": value.st_ino}


def directory(descriptor: int) -> dict[str, int]:
    value = metadata(os.fstat(descriptor))
    return {key: value[key] for key in ("device", "inode", "uid", "gid", "mode")}


def private_arena(path: Path, descriptor: int, expected: dict[str, int]) -> None:
    original = directory(descriptor)
    require(
        same_claim(original, expected)
        and original["uid"] == os.geteuid()
        and stat.S_IMODE(original["mode"]) == 0o700,
        "storage-arena-custody-changed",
    )
    named = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(same_claim(directory(named), expected), "storage-arena-path-changed")
    finally:
        os.close(named)


def syscall(name: str, arguments: tuple[Any, ...], types: list[Any]) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, name)
    function.argtypes, function.restype = types, ctypes.c_int
    if function(*arguments) != 0:
        raise OSError(ctypes.get_errno(), "storage-system-call-failed")


def mount_call(
    source: bytes | None, target: Path, filesystem: bytes | None, flags: int, data: bytes | None
) -> None:
    syscall(
        "mount",
        (source, os.fsencode(target), filesystem, flags, data),
        [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p],
    )


def switch_namespace(descriptor: int) -> None:
    syscall("setns", (descriptor, 0x00020000), [ctypes.c_int, ctypes.c_int])


def mount_view() -> str:
    return Path("/proc/self/mountinfo").read_text()


def path_absent(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def canary(path: Path) -> dict[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        value = os.fstat(descriptor)
        require(
            stat.S_ISREG(value.st_mode)
            and value.st_uid == value.st_gid == 0
            and stat.S_IMODE(value.st_mode) == 0o600
            and value.st_size == 32
            and value.st_nlink == 1,
            "storage-canary-unavailable",
        )
        data = os.read(descriptor, 33)
        require(
            len(data) == 32 and metadata(os.fstat(descriptor)) == metadata(value),
            "storage-canary-changed",
        )
        return {**metadata(value), "sha256": hashlib.sha256(data).hexdigest()}
    finally:
        os.close(descriptor)


def parent_observation(request: dict[str, Any]) -> dict[str, Any]:
    original = request["parent_namespace"]
    descriptor = request["parent_descriptor"]
    require(namespace(descriptor) == original, "storage-parent-namespace-changed")
    switch_namespace(descriptor)
    current = os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
    try:
        require(namespace(current) == original, "storage-parent-namespace-unavailable")
    finally:
        os.close(current)
    baseline, actual = table(request["parent_view"]), table(mount_view())
    require(
        all(actual.get(key) == row for key, row in baseline.items()), "storage-parent-mount-changed"
    )
    owned = request.get("mount")
    if owned is not None:
        require(
            all(
                row.device != tuple(owned["device"]) and row.target != owned["target"]
                for row in actual.values()
            ),
            "storage-owned-mount-in-parent",
        )
    return {
        "observer": process_state(os.getpid()),
        "parent_namespace": original,
        "baseline_sha256": digest(request["parent_view"]),
        "observed_sha256": digest(mount_view()),
        "baseline_mounts_preserved": True,
        "owned_mount_absent": True,
    }


def observe(request: dict[str, Any]) -> dict[str, Any]:
    """Independent root process observations; callers cannot provide observed booleans."""
    require(os.geteuid() == 0 and type(request) is dict, "storage-root-observer-required")
    end = request["end"]
    live(end)
    enrollment = token(request["enrollment"])
    actor = process_state(os.getpid())
    require(
        actor["parent_pid"] == request["owner_pid"]
        and actor["uids"] == [0] * 4
        and actor["gids"] == [0] * 4,
        "storage-observer-actor-mismatch",
    )
    owner = process_state(request["owner_pid"])
    require(
        owner["start_ticks"] == request["owner_start_ticks"] and owner["uids"] == [0] * 4,
        "storage-observer-owner-changed",
    )
    if request["phase"] == "parent":
        return parent_observation(request)
    require(
        request["phase"] in {"before", "after", "retired"}, "storage-observation-phase-unavailable"
    )
    current = os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
    try:
        require(namespace(current) == request["namespace"], "storage-observer-namespace-changed")
    finally:
        os.close(current)
    view = table(mount_view())
    private(view)
    arena = Path(request["arena"])
    loop_claim = request["loop"]
    association = loop_claim["association"]
    node = Path("/dev") / ("loop" + str(association["number"]))
    handle = os.open(node, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        value = os.fstat(handle)
        require(
            stat.S_ISBLK(value.st_mode)
            and value.st_uid == 0
            and {"device": value.st_dev, "inode": value.st_ino, "rdevice": value.st_rdev}
            == association["node"],
            "storage-observer-loop-node-changed",
        )
        if request["phase"] == "before":
            require(
                same_claim(KernelLoops().observe(handle), association),
                "storage-observer-loop-changed",
            )
            descriptor = os.open(arena / "image", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                require(
                    metadata(os.fstat(descriptor)) == loop_claim["image"],
                    "storage-observer-image-changed",
                )
            finally:
                os.close(descriptor)
            root = os.open(
                arena / "mount", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            try:
                identity = MountIdentity.capture(
                    enrollment,
                    request["namespace"],
                    view,
                    directory(root),
                    loop_claim,
                    arena / "mount",
                    end,
                )
                require(
                    same_claim(identity.claim(), request["claim"]), "storage-observer-mount-changed"
                )
            finally:
                os.close(root)
        else:
            require(association_absent(handle), "storage-association-remains")
            owned = request["mount"]
            require(
                all(
                    row.identifier != owned["identifier"]
                    and row.target != owned["target"]
                    and row.device != tuple(owned["device"])
                    for row in view.values()
                ),
                "storage-mount-remains",
            )
            require(path_absent(arena / "image"), "storage-image-remains")
    finally:
        # Never retain a witness handle across the owner's autoclear close.
        os.close(handle)
    result = {
        "phase": request["phase"],
        "enrollment": enrollment,
        "namespace": request["namespace"],
        "inventory_sha256": digest(request),
        "identity_sha256": digest(request["claim"]),
        "association_observation": "bound" if request["phase"] == "before" else "ENXIO",
        "association_present": request["phase"] == "before",
        "mount_present": request["phase"] == "before",
        "image_present": request["phase"] == "before",
        "observation_complete": True,
        "observer": process_state(os.getpid()),
    }
    if request["phase"] == "retired":
        require(path_absent(arena), "storage-arena-remains")
        result["arena_absent"] = True
    else:
        require(
            canary(arena / "unrelated-image") == request["canary"],
            "storage-unrelated-image-changed",
        )
        result["unrelated_image_preserved"] = True
    return result


class NativeStorage:
    def __init__(self, enrollment: str, actor: tuple[int, int], commands: Commands):
        self.enrollment, self.actor, self.commands = token(enrollment), actor, commands
        self.image: ImageLease | None = None
        self.loop: LoopLease | None = None
        self.identity: MountIdentity | None = None
        self.arena: Path | None = None
        self.arena_identity: dict[str, int] = {}
        self.handles: dict[str, int] = {}
        self.inventory: dict[str, Any] = {}
        self.report: dict[str, Any] = {
            "scope": SCOPE,
            "enrollment": enrollment,
            "native_product_qualified": False,
        }
        self.completed: list[str] = []
        self.cleanup_exit = 0

    def claim(self) -> dict[str, Any]:
        return {"enrollment": self.enrollment} if self.identity is None else self.identity.claim()

    def witness(self, phase: str, end: float) -> dict[str, Any]:
        request = {**self.inventory, "phase": phase, "end": end}
        output = self.commands.run(
            [
                sys.executable,
                "-m",
                "scripts.native_smoke_storage",
                "--github-hosted-only",
                "observe",
            ],
            end,
            descriptors=tuple(self.handles.values()),
            payload=json.dumps(request).encode(),
            cwd=ROOT,
            environment={
                "GITHUB_ACTIONS": "true",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "ImageOS": "ubuntu24",
                "SUDO_UID": os.environ["SUDO_UID"],
                "SUDO_GID": os.environ["SUDO_GID"],
            },
        )
        result = json.loads(output, object_pairs_hook=unique_object)
        if type(result) is not dict:
            raise ValueError("storage-observation-unavailable")
        return result

    def check(self, end: float) -> None:
        require(
            self.identity is not None and self.loop is not None and self.image is not None,
            "storage-custody-unavailable",
        )
        if self.identity is None or self.loop is None or self.image is None:
            raise ValueError("storage-custody-unavailable")
        if self.arena is None:
            raise ValueError("storage-arena-unavailable")
        private_arena(self.arena, self.handles["arena"], self.arena_identity)
        self.loop.check(self.loop.claim(), end)
        current = os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
        try:
            require(
                namespace(current) == namespace(self.handles["namespace"]),
                "storage-namespace-changed",
            )
        finally:
            os.close(current)
        target = os.open(
            self.arena / "mount", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            require(directory(self.handles["mount"]) == directory(target), "storage-target-changed")
        finally:
            os.close(target)
        self.identity.check(
            self.claim(),
            namespace(self.handles["namespace"]),
            table(mount_view()),
            directory(self.handles["mount"]),
            self.loop.claim(),
            end,
        )

    def setup(self, end: float) -> dict[str, Any]:
        live(end)
        require(self.arena is None and not self.completed, "storage-setup-already-attempted")
        self.handles["parent"] = os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
        parent_view = mount_view()
        parent_namespace = namespace(self.handles["parent"])
        syscall("unshare", (0x00020000,), [ctypes.c_int])
        self.handles["namespace"] = os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
        require(
            namespace(self.handles["namespace"]) != parent_namespace,
            "storage-namespace-not-isolated",
        )
        mount_call(None, Path("/"), None, (1 << 18) | 16384, None)
        private(table(mount_view()))
        self.arena = Path(tempfile.mkdtemp(prefix="fishhat-smoke-storage-", dir="/tmp"))
        self.arena.chmod(0o700)
        self.handles["arena"] = os.open(
            self.arena, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        self.arena_identity = directory(self.handles["arena"])
        private_arena(self.arena, self.handles["arena"], self.arena_identity)
        descriptor = os.open(
            self.arena / "unrelated-image",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            require(os.write(descriptor, os.urandom(32)) == 32, "storage-canary-write-unavailable")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.image = ImageLease.create(self.arena, end)
        image = self.image.descriptor(end)
        self.commands.run(
            ["/usr/sbin/mkfs.xfs", "-q", "-f", "/proc/self/fd/" + str(image)],
            end,
            descriptors=(image,),
        )
        self.loop = LoopLease.acquire(self.image, KernelLoops(), self.enrollment, end)
        target = self.arena / "mount"
        private_arena(self.arena, self.handles["arena"], self.arena_identity)
        os.mkdir("mount", mode=0o700, dir_fd=self.handles["arena"])
        self.handles["target"] = os.open(
            target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        self.loop.use(
            self.loop.claim(),
            end,
            lambda device: mount_call(
                os.fsencode("/proc/self/fd/" + str(device)), target, b"xfs", 2 | 4, b"prjquota"
            ),
        )
        self.handles["mount"] = os.open(
            target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        self.identity = MountIdentity.capture(
            self.enrollment,
            namespace(self.handles["namespace"]),
            table(mount_view()),
            directory(self.handles["mount"]),
            self.loop.claim(),
            target,
            end,
        )
        self.inventory = {
            "enrollment": self.enrollment,
            "owner_pid": os.getpid(),
            "owner_start_ticks": process_state(os.getpid())["start_ticks"],
            "arena": str(self.arena),
            "namespace": namespace(self.handles["namespace"]),
            "parent_namespace": parent_namespace,
            "parent_descriptor": self.handles["parent"],
            "parent_view": parent_view,
            "loop": self.loop.claim(),
            "claim": self.claim(),
            "canary": canary(self.arena / "unrelated-image"),
            "mount": {
                "identifier": self.identity.mount.identifier,
                "device": list(self.identity.mount.device),
                "target": str(target),
            },
        }
        before = self.witness("before", end)
        self.report["before"] = before
        self.report["claim_sha256"] = digest(self.claim())
        self.report["retained_identity"] = self.claim()
        self.report["parent_before"] = self.witness("parent", end)
        self.check(end)
        for role in ("account", "control"):
            (target / role).mkdir()
        self.commands.run(
            [
                "/usr/sbin/xfs_quota",
                "-x",
                "-c",
                "project -s -p " + str(target / "account") + " 1001",
                str(target),
            ],
            end,
        )
        for role in ("account", "control"):
            os.chown(target / role, *self.actor, follow_symlinks=False)
        self.completed.append("setup")
        return before

    def quota(self, dimension: str, end: float) -> dict[str, Any]:
        self.check(end)
        require(
            self.completed == (["setup"] if dimension == "bytes" else ["setup", "bytes"]),
            "storage-stage-order-refused",
        )
        require(
            dimension in {"bytes", "inodes"} and self.arena is not None,
            "storage-quota-selection-refused",
        )
        if self.arena is None:
            raise ValueError("storage-arena-unavailable")
        target = self.arena / "mount"
        limits = "bhard=8m ihard=0" if dimension == "bytes" else "bhard=0 ihard=64"
        self.commands.run(
            ["/usr/sbin/xfs_quota", "-x", "-c", "limit -p " + limits + " 1001", str(target)], end
        )
        handles: list[int] = []
        try:
            for role in ("account", "control"):
                handles.append(
                    os.open(
                        target / role, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                    )
                )
            output = self.commands.run(
                [
                    "/usr/bin/python3",
                    "-c",
                    Path(quota_work.__file__).read_text(),
                    dimension,
                    *map(str, handles),
                ],
                end,
                descriptors=tuple(handles),
                uid=self.actor[0],
                gid=self.actor[1],
            )
        finally:
            for descriptor in handles:
                os.close(descriptor)
        proof = json.loads(output, object_pairs_hook=unique_object)
        if type(proof) is not dict or proof.get("quota_enforced") is not True:
            raise ValueError("storage-quota-unobserved")
        self.check(end)
        self.completed.append(dimension)
        self.report[dimension] = proof
        return proof

    def cleanup(self, end: float) -> dict[str, Any]:
        # Parent loss must not prevent the read-only cleanup witnesses.
        self.commands.parent = None
        try:
            self.check(end)
            require(
                self.arena is not None and self.image is not None and self.loop is not None,
                "storage-cleanup-custody-unavailable",
            )
            if self.arena is None or self.image is None or self.loop is None:
                raise ValueError("storage-cleanup-custody-unavailable")
            # No other writer remains in this root-only private namespace.
            # Release our busy mount pin immediately before a normal no-follow
            # unmount; never claim lazy detach as observed mount absence.
            os.close(self.handles.pop("mount"))
            syscall(
                "umount2", (os.fsencode(self.arena / "mount"), 8), [ctypes.c_char_p, ctypes.c_int]
            )
            self.loop.check(self.loop.claim(), end)
            self.loop.close()
            self.loop = None
            self.image.check(end)
            os.unlink("image", dir_fd=self.image._directory)
            self.image.close()
            self.image = None
            self.report["after"] = self.witness("after", end)
            self.report["parent_after"] = self.witness("parent", end)
            require(
                self.report["parent_after"]["baseline_mounts_preserved"] is True,
                "storage-parent-preservation-unobserved",
            )
            require(
                canary(self.arena / "unrelated-image") == self.inventory["canary"],
                "storage-canary-changed",
            )
            (self.arena / "unrelated-image").unlink()
            (self.arena / "mount").rmdir()
            self.arena.rmdir()
            self.report["retired"] = self.witness("retired", end)
            self.report["completed_stages"] = list(self.completed)
            self.report["cleanup_exit"] = 0
            return self.report
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            self.cleanup_exit = 1
            self.report.update(cleanup_exit=1, cleanup_problem="storage-final-absence-unobserved")
            raise

    def close(self) -> None:
        failures = []
        for lease in (self.loop, self.image):
            if lease is not None:
                try:
                    lease.close()
                except OSError as error:
                    failures.append(error)
        for handle in self.handles.values():
            try:
                os.close(handle)
            except OSError as error:
                failures.append(error)
        self.handles.clear()
        if failures:
            raise ExceptionGroup("storage handle cleanup failed", failures)


def client(arguments: list[str]) -> int:
    require(
        arguments and arguments[0] in {"request", "reply"}, "storage-client-selection-unavailable"
    )
    if arguments[0] == "request":
        require(len(arguments) == 6, "storage-client-selection-unavailable")
        _, enrollment, action, end, primary, claim = arguments
        request = {
            "enrollment": token(enrollment),
            "action": action,
            "end": float(end),
            "primary": int(primary),
            "claim": json.loads(claim, object_pairs_hook=unique_object),
        }
        send(1, request, float(end))
        return 0
    require(len(arguments) == 3, "storage-client-selection-unavailable")
    _, end, enrollment = arguments
    reply = receive(0, float(end))
    require(
        type(reply) is dict and set(reply) == {"status", "claim", "proof"},
        "storage-reply-unavailable",
    )
    require(
        type(reply["status"]) is int and 0 <= reply["status"] < 256,
        "storage-reply-status-unavailable",
    )
    require(
        type(reply["claim"]) is dict and reply["claim"].get("enrollment") == token(enrollment),
        "storage-reply-enrollment-unavailable",
    )
    print(json.dumps(reply["claim"], sort_keys=True))
    print(
        "native-prerequisite storage-stage-observation="
        + json.dumps({"status": reply["status"], "proof": reply["proof"]}, sort_keys=True),
        file=sys.stderr,
    )
    return int(reply["status"])


def main(arguments: list[str] | None = None) -> int:
    args = sys.argv[1:] if arguments is None else arguments
    try:
        if args[:1] in (["request"], ["reply"]):
            return client(args)
        if args == ["--github-hosted-only", "observe"]:
            root_enrollment(args)
            print(
                json.dumps(
                    observe(json.loads(sys.stdin.buffer.read(), object_pairs_hook=unique_object)),
                    sort_keys=True,
                )
            )
            return 0
        runner, group = root_enrollment(args)
        require(len(args) == 7 and args[1] == "owner", "storage-owner-selection-unavailable")
        enrollment, pid, uid, gid, end = args[2:]
        end_time = float(end)
        token(enrollment)
        require(int(uid) > 0 and int(gid) > 0 and int(uid) != runner, "storage-actor-unavailable")
        import pwd

        actor = pwd.getpwnam("dtci" + str(runner))
        require(actor.pw_uid == int(uid) and actor.pw_gid == int(gid), "storage-actor-changed")
        from scripts.check_evidence import execution_origin
        from scripts.run_stats import RunStats, valid_stats
        from scripts.validation import source_identity
        from scripts.validation_timeouts import execution_conditions

        source = source_identity(ROOT)
        require(source["clean"], "storage-clean-source-required")
        origin = execution_origin()
        require(
            origin.get("kind") == "github-actions" and origin.get("job") == "native-prerequisites",
            "storage-origin-unavailable",
        )
        measurement = RunStats()
        parent = Parent.open(int(pid), runner, group, end_time)
        backend = NativeStorage(enrollment, (int(uid), int(gid)), Commands(parent))
        try:
            with termination_guard():
                outcome = serve(backend, enrollment, parent, 0, 1, end_time)
        finally:
            parent.close()
        backend.report.update(
            source_before=source,
            source_after=source_identity(ROOT),
            execution_origin=origin,
            conditions=execution_conditions(),
            original_primary_exit=outcome.primary,
            cleanup_exit=outcome.cleanup,
            statistics=measurement.finish(),
        )
        evidence_exit = 0
        backend.report["evidence_validation_exit"] = 0
        try:
            require(valid_stats(backend.report["statistics"]), "storage-statistics-unavailable")
            require(backend.report["source_after"] == source, "storage-source-changed")
            if outcome.status == 0:
                from scripts.native_smoke_storage_qualification import validate

                validate(backend.report, enrollment, backend.claim(), 0, interrupted=False)
        except (OSError, ValueError, KeyError, TypeError):
            evidence_exit = 1
            backend.report["evidence_problem"] = "storage-final-evidence-unavailable"
        backend.report["evidence_validation_exit"] = evidence_exit
        print(
            "native-prerequisite storage-observation=" + json.dumps(backend.report, sort_keys=True),
            file=sys.stderr,
        )
        return outcome.status or evidence_exit
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        category = str(error) if isinstance(error, ValueError) else "storage-operation-unavailable"
        if re.fullmatch(r"(?:storage|mount|loop|ssh)-[a-z-]+", category) is None:
            category = "storage-operation-unavailable"
        number = error.errno if isinstance(error, OSError) else None
        print(
            "native-prerequisite storage-problem=unavailable category="
            + category
            + " errno="
            + str(number),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
