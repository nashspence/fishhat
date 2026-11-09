"""Boot and authenticate one disposable guest without exposing seed material."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from shlex import join as shell_join
from typing import Any

import psutil
import yaml

from scripts.native_linux_images import Command, GuestInputs, digest, identity
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import Deadline, current, watchdog

TOOLS = {
    "genisoimage": ("9:1.1.11-3.5", "amd64"),
    "openssh-client": ("1:9.6p1-3ubuntu13.20", "amd64"),
    "seabios": ("1.16.3-2", "all"),
}
TOOL_PATHS = {
    "iso": Path("/usr/bin/genisoimage"),
    "ssh": Path("/usr/bin/ssh"),
    "keygen": Path("/usr/bin/ssh-keygen"),
    "firmware": Path("/usr/share/seabios/bios-256k.bin"),
}
KERNEL = "6.8.0-147-generic"
GUEST_PACKAGES = {
    "linux-image-" + KERNEL: "6.8.0-147.147",
    "systemd": "255.4-1ubuntu8.18",
    "openssh-server": "1:9.6p1-3ubuntu13.20",
}
MARKER = "/etc/fishhat-fixture-enrollment"

# This program only reads identity until the complete expected identity agrees.
# A guarded command executes in that same authenticated remote invocation.
REMOTE = r"""
import json, os, pathlib, platform, pwd, subprocess, sys, uuid
admin, peer, expected, action = sys.argv[1:]
fields = dict(line.split("=", 1) for line in pathlib.Path("/etc/os-release").read_text().splitlines() if "=" in line)
packages = subprocess.check_output(["/usr/bin/dpkg-query", "-W", "-f", "${Package}\t${Version}\n", "linux-image-6.8.0-147-generic", "systemd", "openssh-server"], stderr=subprocess.DEVNULL, timeout=10).decode()
accounts = {name: {"uid": pwd.getpwnam(name).pw_uid, "gid": pwd.getpwnam(name).pw_gid} for name in (admin, peer)}
cloud = json.loads(pathlib.Path("/run/cloud-init/status.json").read_text()).get("v1", {})
errors = sum(len(v.get("errors", [])) for v in cloud.values() if isinstance(v, dict))
info = {"distribution": fields.get("ID", "").strip('"'), "distribution_version": fields.get("VERSION_ID", "").strip('"'), "machine": platform.machine(), "kernel": platform.release(), "pid1": pathlib.Path("/proc/1/comm").read_text().strip(), "cgroup_v2": pathlib.Path("/sys/fs/cgroup/cgroup.controllers").is_file(), "boot_id": str(uuid.UUID(pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip())), "dmi_uuid": str(uuid.UUID(pathlib.Path("/sys/class/dmi/id/product_uuid").read_text().strip())), "enrollment": pathlib.Path("/etc/fishhat-fixture-enrollment").read_text().strip(), "instance_id": pathlib.Path("/var/lib/cloud/data/instance-id").read_text().strip(), "accounts": accounts, "ssh_principal": os.environ.get("SUDO_USER"), "packages": dict(line.split("\t", 1) for line in packages.splitlines()), "cloud_init_complete": pathlib.Path("/var/lib/cloud/instance/boot-finished").is_file() and not errors}
if expected != "null" and info != json.loads(expected):
    sys.exit(73)
if action != "null":
    if expected == "null":
        sys.exit(73)
    argv = json.loads(action)
    os.execv(argv[0], argv)
print(json.dumps(info, sort_keys=True))
"""
PEER = r"""
import json, os, pathlib, pwd
print(json.dumps({"account": pwd.getpwuid(os.geteuid()).pw_name, "uid": os.geteuid(), "boot_id": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "enrollment": pathlib.Path("/etc/fishhat-fixture-enrollment").read_text().strip()}))
"""


class GuestBootError(RuntimeError):
    stage = "guest-boot"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def command_failed(error: RuntimeError, code: int) -> bool:
    return (
        getattr(error, "stage", None) == "guest-ssh"
        and getattr(error, "reason", None) == f"command-exit-{code}"
    )


def provision_tools(
    command: Command,
    root_command: Callable[[list[str], str, float], None],
    progress: Callable[[str], AbstractContextManager[None]],
) -> dict[str, Any]:
    with progress("guest-tools"):
        contact = current().units(30, unit_seconds=1, maximum=2**31 - 1)
        options = [
            item
            for name in ("Acquire::http::Timeout", "Acquire::https::Timeout", "DPkg::Lock::Timeout")
            for item in ("-o", f"{name}={contact}")
        ]
        root_command(
            [
                "/usr/bin/apt-get",
                *options,
                "-o",
                "Acquire::Retries=0",
                "install",
                "-y",
                "--no-install-recommends",
                *(f"{name}={version}" for name, (version, _) in TOOLS.items()),
            ],
            "guest-tools",
            300,
        )
        text = command(
            [
                "/usr/bin/dpkg-query",
                "-W",
                "-f",
                "${Package}\t${Version}\t${Architecture}\n",
                *TOOLS,
            ],
            "guest-tools",
            10,
            capture=True,
        )
        rows = [line.split("\t") for line in text.splitlines()]
        if (
            len(rows) != len(TOOLS)
            or any(len(row) != 3 for row in rows)
            or {row[0]: tuple(row[1:]) for row in rows} != TOOLS
        ):
            raise GuestBootError("guest-tool-package-mismatch")
        return {
            "packages": {name: version for name, (version, _) in TOOLS.items()},
            "sha256": tool_hashes(),
        }


def tool_hashes() -> dict[str, str]:
    try:
        return {name: digest(path) for name, path in TOOL_PATHS.items()}
    except OSError:
        raise GuestBootError("guest-tool-unavailable") from None


def listening_endpoints(pid: int) -> list[tuple[str, int]]:
    return [
        (item.laddr.ip, item.laddr.port)
        for item in psutil.Process(pid).net_connections(kind="tcp")
        if item.status == psutil.CONN_LISTEN and item.laddr
    ]


def public_key(text: str) -> tuple[str, str]:
    parts = text.split()
    try:
        if len(parts) != 2 or parts[0] != "ssh-ed25519":
            raise ValueError("key format")
        raw = base64.b64decode(parts[1], validate=True)
        if len(raw) != 51 or raw[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20":
            raise ValueError("key encoding")
    except (ValueError, TypeError):
        raise GuestBootError("invalid-generated-public-key") from None
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    return " ".join(parts), fingerprint


@dataclass
class Guest:
    inputs: GuestInputs
    directory: Path
    command: Command
    tools: dict[str, Any]
    report: dict[str, Any]
    port: int
    qemu: Path
    directory_identity: tuple[int, int]
    files: dict[str, tuple[tuple[int, int], str]] = field(default_factory=dict)
    observed: dict[str, Any] | None = None
    process: subprocess.Popen[bytes] | None = None
    verify_process: Callable[[Deadline], None] | None = None

    @property
    def enrollment(self) -> str:
        return self.inputs.enrollment

    @property
    def accounts(self) -> tuple[str, str]:
        suffix = uuid.UUID(self.enrollment).hex[:16]
        return "fha" + suffix, "fhu" + suffix

    def register(self, name: str) -> None:
        path = self.directory / name
        self.files[name] = identity(path), digest(path)

    def path(self, name: str) -> Path:
        if identity(self.directory, directory=True) != self.directory_identity:
            raise GuestBootError("private-directory-replaced")
        path = self.directory / name
        if (
            name not in self.files
            or (identity(path), digest(path)) != self.files[name]
            or stat.S_IMODE(path.lstat().st_mode) != 0o600
        ):
            raise GuestBootError("private-input-changed")
        return path

    def write(self, name: str, content: str) -> None:
        if (
            identity(self.directory, directory=True) != self.directory_identity
            or name in self.files
        ):
            raise GuestBootError("unexpected-private-input")
        descriptor = os.open(
            self.directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
        self.register(name)

    def verify_tools(self) -> None:
        if tool_hashes() != self.tools["sha256"]:
            raise GuestBootError("guest-tool-changed")

    def seed(self) -> None:
        self.verify_tools()
        keys = {}
        for role in ("host", "admin", "peer"):
            path = self.directory / role
            self.command(
                [
                    str(TOOL_PATHS["keygen"]),
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "",
                    "-f",
                    str(path),
                ],
                "guest-keygen",
                30,
            )
            for name in (role, role + ".pub"):
                candidate = self.directory / name
                observed = candidate.lstat()
                if (
                    not stat.S_ISREG(observed.st_mode)
                    or observed.st_uid != os.geteuid()
                    or observed.st_nlink != 1
                ):
                    raise GuestBootError("foreign-generated-key")
                candidate.chmod(0o600)
                self.register(name)
            keys[role] = public_key(self.path(role + ".pub").read_text())
        if len({key for key, _ in keys.values()}) != 3:
            raise GuestBootError("generated-keys-not-independent")
        admin, peer = self.accounts
        config = {
            "users": [
                {
                    "name": admin,
                    "lock_passwd": True,
                    "shell": "/bin/bash",
                    "sudo": "ALL=(ALL) NOPASSWD:ALL",
                    "ssh_authorized_keys": ["restrict " + keys["admin"][0]],
                },
                {
                    "name": peer,
                    "lock_passwd": True,
                    "shell": "/bin/bash",
                    "sudo": False,
                    "ssh_authorized_keys": ["restrict " + keys["peer"][0]],
                },
            ],
            "disable_root": True,
            "ssh_pwauth": False,
            "ssh_deletekeys": True,
            "ssh_keys": {
                "ed25519_private": self.path("host").read_text(),
                "ed25519_public": keys["host"][0],
            },
            "ssh_quiet_keygen": True,
            "no_ssh_fingerprints": True,
            "ssh": {"emit_keys_to_console": False},
            "ssh_publish_hostkeys": {"enabled": False},
            "package_update": False,
            "package_upgrade": False,
            "write_files": [
                {
                    "path": MARKER,
                    "owner": "root:root",
                    "permissions": "0444",
                    "content": self.enrollment + "\n",
                },
                {
                    "path": "/etc/ssh/sshd_config.d/00-fishhat-fixture.conf",
                    "owner": "root:root",
                    "permissions": "0600",
                    "content": f"PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nAllowUsers {admin} {peer}\nAllowAgentForwarding no\nAllowTcpForwarding no\nX11Forwarding no\nPermitTunnel no\nHostKey /etc/ssh/ssh_host_ed25519_key\n",
                },
            ],
        }
        self.write("user-data", "#cloud-config\n" + yaml.safe_dump(config, sort_keys=True))
        self.write(
            "meta-data",
            yaml.safe_dump(
                {
                    "instance-id": self.enrollment,
                    "local-hostname": "fh-" + uuid.UUID(self.enrollment).hex,
                }
            ),
        )
        for name, key in [("known-hosts", keys["host"][0]), ("wrong-hosts", keys["peer"][0])]:
            self.write(name, f"[127.0.0.1]:{self.port} {key}\n")
        self.write("seed.iso", "")
        self.command(
            [
                str(TOOL_PATHS["iso"]),
                "-quiet",
                "-output",
                str(self.path("seed.iso")),
                "-volid",
                "cidata",
                "-joliet",
                "-rock",
                str(self.path("user-data")),
                str(self.path("meta-data")),
            ],
            "guest-seed",
            30,
        )
        # The seed writer may change bytes, but may not substitute the owned file.
        path = self.directory / "seed.iso"
        if identity(path) != self.files["seed.iso"][0]:
            raise GuestBootError("seed-file-replaced")
        self.files["seed.iso"] = identity(path), digest(path)
        self.report["key_fingerprints"] = {
            role: fingerprint for role, (_, fingerprint) in keys.items()
        }

    def launch(self, endpoint: Path, enrollment: str) -> subprocess.Popen[bytes]:
        if enrollment != self.enrollment or self.process is not None:
            raise GuestBootError("fixture-enrollment-mismatch")
        self.verify_tools()
        self.inputs.verify(enrollment)
        arguments = [
            str(self.qemu),
            "-no-user-config",
            "-machine",
            "pc-q35-8.2,dump-guest-core=off",
            "-accel",
            "tcg,thread=multi",
            "-cpu",
            "max",
            "-S",
            "-nodefaults",
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "none",
            "-parallel",
            "none",
            "-m",
            "2048M",
            "-smp",
            "2",
            "-boot",
            "strict=on",
            "-uuid",
            enrollment,
            "-bios",
            str(TOOL_PATHS["firmware"]),
            "-qmp",
            f"unix:{endpoint},server=on,wait=off",
        ]
        for name in ("root", "control", "data"):
            path = self.inputs.path(name + ".qcow2", enrollment)
            arguments += [
                "-drive",
                f"if=none,id={name},file={path},format=qcow2",
                "-device",
                f"virtio-blk-pci,drive={name},serial=fh-{name}"
                + (",bootindex=1" if name == "root" else ""),
            ]
        arguments += [
            "-drive",
            f"if=none,id=seed,file={self.path('seed.iso')},format=raw,readonly=on",
            "-device",
            "virtio-blk-pci,drive=seed,serial=fh-seed",
            "-netdev",
            f"user,id=isolated,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:{self.port}-:22",
            "-device",
            "virtio-net-pci,netdev=isolated",
        ]
        self.process = subprocess.Popen(
            arguments,
            cwd=endpoint.parent,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            umask=0o077,
        )
        return self.process

    def listener(self) -> None:
        if self.process is None:
            raise GuestBootError("owned-guest-unavailable")
        if listening_endpoints(self.process.pid) != [("127.0.0.1", self.port)]:
            raise GuestBootError("owned-loopback-endpoint-mismatch")

    def ssh(
        self,
        remote: str,
        *,
        role: str = "admin",
        hosts: str = "known-hosts",
        deadline: Deadline | None = None,
    ) -> str:
        self.verify_tools()
        if self.verify_process is None:
            raise GuestBootError("owned-guest-unavailable")
        deadline = Deadline.after(15) if deadline is None else deadline
        if deadline.remaining() <= 0:
            raise GuestBootError("guest-readiness-deadline")
        self.verify_process(deadline)
        self.listener()
        options = {
            "BatchMode": "yes",
            "IdentitiesOnly": "yes",
            "IdentityAgent": "none",
            "StrictHostKeyChecking": "yes",
            "UserKnownHostsFile": str(self.path(hosts)),
            "GlobalKnownHostsFile": "/dev/null",
            "UpdateHostKeys": "no",
            "CheckHostIP": "no",
            "HostKeyAlgorithms": "ssh-ed25519",
            "PubkeyAcceptedAlgorithms": "ssh-ed25519",
            "PasswordAuthentication": "no",
            "KbdInteractiveAuthentication": "no",
            "PreferredAuthentications": "publickey",
            "ProxyCommand": "none",
            "ProxyJump": "none",
            "ControlMaster": "no",
            "ControlPath": "none",
            "ClearAllForwardings": "yes",
            "PermitLocalCommand": "no",
            "RequestTTY": "no",
            "ConnectionAttempts": "1",
            "ConnectTimeout": str(current().units(5, unit_seconds=1, maximum=2**31 - 1)),
        }
        arguments = [str(TOOL_PATHS["ssh"]), "-n", "-F", "/dev/null"]
        for name, value in options.items():
            arguments += ["-o", name + "=" + value]
        if role not in {"admin", "peer"}:
            raise GuestBootError("unknown-fixture-account")
        account = self.accounts[0 if role == "admin" else 1]
        arguments += [
            "-i",
            str(self.path(role)),
            "-p",
            str(self.port),
            "-l",
            account,
            "--",
            "127.0.0.1",
            remote,
        ]
        remaining = deadline.remaining()
        if remaining <= 0:
            raise GuestBootError("guest-readiness-deadline")
        return self.command(
            arguments, "guest-ssh", min(15, remaining / current().scale), capture=True
        )

    def remote(self, expected: dict[str, Any] | None, action: list[str] | None = None) -> str:
        if action is not None and expected is None:
            raise GuestBootError("guest-not-verified")
        arguments = [
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/python3",
            "-I",
            "-S",
            "-c",
            REMOTE,
            *self.accounts,
            json.dumps(expected, sort_keys=True),
            json.dumps(action),
        ]
        return shell_join(arguments)

    def observe(self, deadline: Deadline | None = None) -> dict[str, Any]:
        try:
            value = json.loads(self.ssh(self.remote(None), deadline=deadline))
        except (ValueError, RecursionError):
            raise GuestBootError("invalid-guest-observation") from None
        if not isinstance(value, dict):
            raise GuestBootError("invalid-guest-observation")
        return value

    def validate(self, value: dict[str, Any]) -> None:
        expected = {
            "distribution": "ubuntu",
            "distribution_version": "24.04",
            "machine": "x86_64",
            "kernel": KERNEL,
            "pid1": "systemd",
            "cgroup_v2": True,
            "dmi_uuid": self.enrollment,
            "enrollment": self.enrollment,
            "instance_id": self.enrollment,
            "ssh_principal": self.accounts[0],
            "packages": GUEST_PACKAGES,
            "cloud_init_complete": True,
        }
        if (
            set(value) != {*expected, "boot_id", "accounts"}
            or type(value.get("cloud_init_complete")) is not bool
            or type(value.get("cgroup_v2")) is not bool
            or any(value.get(name) != wanted for name, wanted in expected.items())
        ):
            raise GuestBootError("guest-identity-mismatch")
        try:
            if str(uuid.UUID(value["boot_id"])) != value["boot_id"]:
                raise ValueError("boot identity")
            accounts = value["accounts"]
            if (
                set(accounts) != set(self.accounts)
                or any(
                    set(accounts[name]) != {"uid", "gid"}
                    or any(
                        type(number) is not int or number < 1000
                        for number in accounts[name].values()
                    )
                    for name in self.accounts
                )
                or accounts[self.accounts[0]]["uid"] == accounts[self.accounts[1]]["uid"]
            ):
                raise ValueError("account identity")
        except (ValueError, KeyError, TypeError, AttributeError):
            raise GuestBootError("guest-identity-mismatch") from None
        if self.observed is not None and value != self.observed:
            raise GuestBootError("guest-boot-or-identity-changed")

    def ready(self, verify_process: Callable[[Deadline], None]) -> None:
        self.verify_process = verify_process
        deadline = Deadline.after(600)
        while deadline.remaining() > 0:
            verify_process(deadline)
            try:
                value = self.observe(deadline)
            except RuntimeError as error:
                if not command_failed(error, 255):
                    raise
            else:
                # Bootstrap completion is the sole retryable observed condition;
                # an authenticated contradictory identity is never admitted.
                if type(value.get("cloud_init_complete")) is not bool:
                    raise GuestBootError("invalid-guest-observation")
                incomplete = dict(value, cloud_init_complete=True)
                self.validate(incomplete)
                if value["cloud_init_complete"]:
                    self.validate(value)
                    self.observed = value
                    self.report.update(
                        boot_verified=True,
                        identity=value,
                        endpoint={
                            "address": "127.0.0.1",
                            "port": self.port,
                            "owned_listener": True,
                        },
                    )
                    return
            time.sleep(min(watchdog(1), deadline.remaining()))
        raise GuestBootError("guest-readiness-deadline")

    def guarded(self, action: list[str], enrollment: str, boot: str) -> str:
        if self.observed is None or enrollment != self.enrollment:
            raise GuestBootError("fixture-enrollment-mismatch")
        expected = dict(self.observed, boot_id=boot)
        return self.ssh(self.remote(expected, action))

    def refusals(self) -> None:
        if self.observed is None:
            raise GuestBootError("guest-not-verified")
        self.guarded(["/usr/bin/true"], self.enrollment, self.observed["boot_id"])
        try:
            self.ssh(self.remote(None), hosts="wrong-hosts")
        except RuntimeError as error:
            if not command_failed(error, 255):
                raise
        else:
            raise GuestBootError("wrong-host-key-accepted")
        try:
            peer = json.loads(
                self.ssh(shell_join(["/usr/bin/python3", "-I", "-S", "-c", PEER]), role="peer")
            )
        except (ValueError, RecursionError):
            raise GuestBootError("invalid-peer-observation") from None
        if peer != {
            "account": self.accounts[1],
            "uid": self.observed["accounts"][self.accounts[1]]["uid"],
            "boot_id": self.observed["boot_id"],
            "enrollment": self.enrollment,
        }:
            raise GuestBootError("peer-identity-mismatch")
        canary = "/run/fh-denied-" + uuid.UUID(self.enrollment).hex
        for attribute in ("boot_id", "dmi_uuid", "enrollment"):
            expected = dict(self.observed)
            expected[attribute] = str(uuid.uuid4())
            try:
                self.ssh(self.remote(expected, ["/usr/bin/touch", canary]))
            except RuntimeError as error:
                if not command_failed(error, 73):
                    raise
            else:
                raise GuestBootError("foreign-or-stale-identity-accepted")
        try:
            self.guarded(["/usr/bin/touch", canary], str(uuid.uuid4()), self.observed["boot_id"])
        except GuestBootError as error:
            if error.reason != "fixture-enrollment-mismatch":
                raise
        else:
            raise GuestBootError("foreign-enrollment-accepted")
        self.guarded(
            ["/usr/bin/test", "!", "-e", canary], self.enrollment, self.observed["boot_id"]
        )
        self.validate(self.observe())
        self.report["refusals_verified"] = [
            "wrong-host-key",
            "stale-boot",
            "foreign-guest-uuid",
            "foreign-guest-enrollment",
            "stale-caller-enrollment",
        ]
        self.report["denied_mutation_canary_absent"] = True
        self.report["peer_authenticated"] = True


@contextmanager
def guest_session(
    inputs: GuestInputs,
    temporary: Path,
    command: Command,
    tools: dict[str, Any],
    qemu: Path,
    report: dict[str, Any],
) -> Iterator[Guest]:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="disposable-authenticated-guest-only",
        enrollment=inputs.enrollment,
        boot_verified=False,
        temporary_resources_removed=False,
    )
    directory: Path | None = None
    guest: Guest | None = None
    complete = False
    try:
        inputs.path("root.qcow2", inputs.enrollment)
        directory = Path(tempfile.mkdtemp(prefix="fhg-", dir=temporary))
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        guest = Guest(
            inputs,
            directory,
            command,
            tools,
            report,
            port,
            qemu,
            identity(directory, directory=True),
        )
        guest.seed()
        yield guest
        if guest.observed is None or report.get("refusals_verified") is None:
            raise GuestBootError("guest-proof-incomplete")
        if guest.process is None or guest.process.returncode is None:
            raise GuestBootError("guest-process-not-reaped")
        guest.verify_tools()
        for name in guest.files:
            guest.path(name)
        complete = True
    except (OSError, psutil.Error):
        raise GuestBootError("guest-resource-unavailable") from None
    finally:
        try:
            if directory is not None:
                try:
                    same = (
                        guest is not None
                        and identity(directory, directory=True) == guest.directory_identity
                    )
                except OSError:
                    same = False
                if not same or guest is None:
                    raise GuestBootError("private-directory-replaced")
                try:
                    shutil.rmtree(directory)
                except OSError:
                    raise GuestBootError("guest-private-cleanup-failed") from None
                report["temporary_resources_removed"] = not directory.exists()
                report["process_reaped"] = (
                    guest.process is None or guest.process.returncode is not None
                )
                if complete and report["temporary_resources_removed"]:
                    report["status"] = "passed"
        finally:
            report["statistics"] = metrics.finish()
            if not valid_stats(report["statistics"]):
                raise ValueError("invalid required guest statistics")
