"""Exercise the SSH owner's kernel backend under its native stdlib interpreter."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import select
import signal
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from scripts import native_smoke_ssh as ssh
from scripts.validation_timeouts import Deadline, current


def run(scenario: str) -> dict[str, Any]:
    if sys.platform != "linux" or os.geteuid() == 0:
        raise ValueError("requires-unprivileged-linux-kernel-probe")
    if not all(hasattr(os, name) for name in ("pidfd_open", "P_PIDFD")) or not hasattr(
        signal, "pidfd_send_signal"
    ):
        raise ValueError("native-kernel-handle-facility-unavailable")
    if scenario not in {"pid", "ticks", "actor", "image", "enrollment", "term-ignoring"}:
        raise ValueError("controlled-scenario-unavailable")
    arguments = ["/usr/bin/sleep", "60"]
    if scenario == "term-ignoring":
        arguments = ["/usr/bin/bash", "-c", "trap '' TERM; printf 'ready\\n'; while :; do :; done"]
    image_path = Path(arguments[0]).resolve(strict=True)
    deadline = Deadline.after(10)
    image = ssh.executable(image_path, deadline.end)
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if scenario == "term-ignoring" else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    canary = subprocess.Popen(
        ["/usr/bin/sleep", "60"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    child = None
    report: dict[str, Any] = {
        "scenario": scenario,
        "status": "failed",
        "unprivileged": True,
        "native_product_qualified": False,
    }
    try:
        child = ssh.OwnedChild.open(
            process,
            image,
            image_path,
            str(uuid.uuid4()),
            arguments,
            uid=os.geteuid(),
            gid=os.getegid(),
        )
        if scenario == "term-ignoring":
            assert process.stdout is not None
            assert select.select([process.stdout], [], [], deadline.remaining())[0]
            assert os.read(process.stdout.fileno(), 6) == b"ready\n"
        original = child.admit(deadline.end)
        if scenario == "term-ignoring":
            failed = False
            expiry = Deadline.after(0.02)
            try:
                child.finish(expiry.end)
            except ValueError:
                failed = True
            assert failed and process.returncode == -signal.SIGKILL
            report.update(original_deadline_failure_preserved=True, forced_reaping_verified=True)
        else:
            claim = copy.deepcopy(original)
            if scenario == "pid":
                claim["pid"] = canary.pid
            elif scenario == "ticks":
                claim["start_ticks"] += 1
            elif scenario == "actor":
                claim["uids"] = [0] * 4
            elif scenario == "image":
                claim["executable"]["sha256"] = "0" * 64
            else:
                claim["enrollment"] = str(uuid.uuid4())
            refused = False
            try:
                child.terminate(claim, deadline.end)
            except ValueError:
                refused = True
            assert refused and child.identity(deadline.end) == original and canary.poll() is None
            child.terminate(original, deadline.end)
            value = child.finish(deadline.end)
            assert value["reaped"] is value["stale_handle_refused"] is True
            assert value["pid"] == process.pid and value["parent_pid"] == os.getpid()
            assert process.returncode in {0, -15}
            report.update(foreign_claim_refused=True, owned_termination_and_reaping_verified=True)
        stale_refused = False
        try:
            signal.pidfd_send_signal(child.handle, 0)
        except ProcessLookupError:
            stale_refused = True
        assert stale_refused and canary.poll() is None
        report.update(
            status="passed",
            stale_handle_refused=True,
            unrelated_canary_preserved=True,
            source_sha256=hashlib.sha256(Path(ssh.__file__).read_bytes()).hexdigest(),
            interpreter_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        )
    finally:
        try:
            if child is not None:
                try:
                    if process.returncode is None:
                        child.finish(Deadline.after(5).end)
                finally:
                    child.close()
            elif process.returncode is None:
                process.kill()
                grace = Deadline.after(5)
                process.wait(timeout=grace.remaining())
        finally:
            if process.stdout is not None:
                process.stdout.close()
            canary.terminate()
            grace = Deadline.after(5)
            canary.wait(timeout=grace.remaining())
    report["watchdogs"] = current().report()
    return report


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(2)
    print(json.dumps(run(sys.argv[1]), sort_keys=True))
