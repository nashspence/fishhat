"""Image identity and custody checks with controlled local HTTP; no QEMU or guest."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import uuid
from contextlib import nullcontext
from pathlib import Path

import pytest

from scripts import native_linux_download as download
from scripts import native_linux_enrollment as native
from scripts import native_linux_images as images
from scripts.run_stats import valid_stats

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_images.py",
        "scripts/native_linux_enrollment.py",
        "scripts/native_linux_download.py",
    ],
    "scope": "pinned image bytes, enrollment-bound owned file identity, immutable backing, isolated local HTTP failure observations and partial setup cleanup with required measurement records",
    "relationship": "no-product-claim",
    "reason": "Controlled image bytes, loopback HTTP and qemu-img observations exercise tooling behavior only. No external image is downloaded or QEMU run here; the separate disposable main job must establish actual guest-input behavior. No guest boots or native owner is qualified.",
    "claims": [],
}


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    payload = b"controlled-authenticated-image"
    binary = tmp_path / "qemu-img"
    binary.write_bytes(b"controlled-image-tool")
    foreign = tmp_path / "foreign"
    foreign.write_bytes(payload)
    foreign.chmod(0o600)
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    monkeypatch.setattr(images, "IMAGE_SHA256", hashlib.sha256(payload).hexdigest())
    monkeypatch.setattr(images, "IMAGE_BYTES", len(payload))
    monkeypatch.setattr(images, "QEMU_IMG", binary)
    state = {"mode": "normal", "calls": [], "created": {}, "directories": []}

    def command(arguments, name, nominal, *, capture=False):
        state["calls"].append((arguments, name, nominal, capture))
        mode = state["mode"]
        if arguments[0] == sys.executable:
            assert arguments[1:3] == ["-I", "-S"]
            assert arguments[3] == str(images.DOWNLOAD_WORKER)
            assert arguments[5] == images.IMAGE_URL
            base = Path(arguments[4])
            assert stat.S_IMODE(base.parent.stat().st_mode) == 0o700
            assert not base.exists()
            state["directories"].append(base.parent)
            if mode == "symlink":
                base.symlink_to(foreign)
            elif mode == "hardlink":
                os.link(foreign, base)
            else:
                base.write_bytes(payload + b"x" if mode == "wrong-size" else payload)
                base.chmod(0o600)
                if mode == "wrong-hash":
                    base.write_bytes(b"x" * len(payload))
            if mode == "classified-download-failure":
                raise native.ImageDownloadCommandError(
                    "guest-image-download", 40, '{"http_status":503}'
                )
            if mode == "download-failure":
                raise images.GuestInputError("controlled-download-failure")
            return ""
        assert arguments[0] == str(binary)
        if arguments[1] == "--version":
            return (
                "qemu-img version 8.2.1\n" if mode == "wrong-tool" else "qemu-img version 8.2.2\n"
            )
        if arguments[1] == "create":
            path = Path(arguments[-2])
            size = int(arguments[-1])
            assert path.stat().st_size == 0 and stat.S_IMODE(path.stat().st_mode) == 0o600
            if mode == "create-failure" and path.name == "control.qcow2":
                raise images.GuestInputError("controlled-create-failure")
            if mode == "disk-replaced":
                replacement = path.parent / "replacement"
                replacement.write_bytes(b"replacement")
                replacement.chmod(0o600)
                replacement.replace(path)
            else:
                path.write_bytes(b"controlled-disk")
            state["created"][path.name] = size
            if mode == "base-changed":
                base = path.parent / "base.img"
                base.chmod(0o600)
                base.write_bytes(b"x" * len(payload))
                base.chmod(0o400)
            if mode == "tool-changed":
                binary.write_bytes(b"changed-tool")
            return ""
        assert arguments[1:5] == ["info", "--output=json", "-f", "qcow2"]
        path = Path(arguments[-1])
        if mode == "malformed-info":
            return "fixture-private-output"
        base = path.name == "base.img"
        value = {
            "format": "raw" if mode == "wrong-format" else "qcow2",
            "virtual-size": images.BASE_VIRTUAL_BYTES if base else state["created"][path.name],
        }
        if base and mode == "base-backing":
            value["backing-filename"] = str(foreign)
        if mode == "external-data":
            value["format-specific"] = {"type": "qcow2", "data": {"data-file": str(foreign)}}
        if not base and path.name == "root.qcow2":
            value.update(
                {
                    "full-backing-filename": str(
                        foreign if mode == "foreign-backing" else path.parent / "base.img"
                    ),
                    "backing-filename-format": "qcow2",
                }
            )
        if not base and mode == "wrong-extent":
            value["virtual-size"] += 1
        if not base and mode == "float-extent":
            value["virtual-size"] = float(value["virtual-size"])
        return json.dumps(value)

    return state, command, temporary, foreign


def prepare(fixture, report):
    _, command, temporary, _ = fixture
    return images.guest_inputs(
        str(uuid.uuid4()), temporary, command, lambda name: nullcontext(), report
    )


def test_owned_inputs_preserve_base_bind_enrollment_and_remove_all_disks(fixture):
    state, _, temporary, foreign = fixture
    report = {}
    with prepare(fixture, report) as owned:
        owned.verify(owned.enrollment)
        assert set(owned.files) == {"base.img", *images.DISK_BYTES}
        assert stat.S_IMODE(owned.path("base.img", owned.enrollment).stat().st_mode) == 0o400
        with pytest.raises(images.GuestInputError, match="fixture-enrollment-mismatch"):
            owned.path("root.qcow2", str(uuid.uuid4()))
        with pytest.raises(images.GuestInputError, match="unenrolled-resource"):
            owned.path("foreign", owned.enrollment)
        assert all(
            stat.S_IMODE(owned.path(name, owned.enrollment).stat().st_mode) == 0o600
            for name in images.DISK_BYTES
        )
    assert report["status"] == "passed" and report["base_preserved"]
    assert report["temporary_resources_removed"] and not list(temporary.iterdir())
    assert valid_stats(report["statistics"])
    assert report["statistics"]["scope"] == "process-excludes-children"
    assert {disk["name"]: disk["virtual_bytes"] for disk in report["disks"]} == images.DISK_BYTES
    assert (
        foreign.read_bytes() == b"controlled-authenticated-image"
        and stat.S_IMODE(foreign.stat().st_mode) == 0o600
    )
    assert all(not path.exists() for path in state["directories"])


@pytest.mark.parametrize(
    "mode",
    [
        "wrong-size",
        "wrong-hash",
        "symlink",
        "hardlink",
        "download-failure",
        "wrong-tool",
        "wrong-format",
        "base-backing",
        "external-data",
        "malformed-info",
        "create-failure",
        "foreign-backing",
        "wrong-extent",
        "float-extent",
        "disk-replaced",
        "base-changed",
        "tool-changed",
    ],
)
def test_changed_foreign_and_partial_inputs_never_pass_or_change_unrelated_files(fixture, mode):
    state, _, temporary, foreign = fixture
    state["mode"] = mode
    report = {}
    with pytest.raises(images.GuestInputError) as caught:
        with prepare(fixture, report):
            pass
    assert "fixture-private-output" not in str(caught.value)
    assert report["status"] == "failed"
    assert report["temporary_resources_removed"] and not list(temporary.iterdir())
    assert valid_stats(report["statistics"])
    assert (
        foreign.read_bytes() == b"controlled-authenticated-image"
        and stat.S_IMODE(foreign.stat().st_mode) == 0o600
    )
    if mode in {
        "wrong-size",
        "wrong-hash",
        "symlink",
        "hardlink",
        "download-failure",
        "wrong-tool",
    }:
        assert not any(call[1] == "guest-image-create" for call in state["calls"])


@pytest.mark.parametrize(
    "enrollment", ["", "not-an-enrollment", "A" * 32], ids=["empty", "invalid", "noncanonical"]
)
def test_invalid_enrollment_is_refused_before_files_or_commands(fixture, enrollment):
    state, command, temporary, _ = fixture
    with pytest.raises(images.GuestInputError, match="invalid-fixture-enrollment"):
        with images.guest_inputs(enrollment, temporary, command, lambda name: nullcontext(), {}):
            pass
    assert not state["calls"] and not list(temporary.iterdir())


def test_interrupted_use_preserves_base_and_records_cleanup_without_success(fixture):
    _, _, temporary, _ = fixture
    report = {}
    with pytest.raises(RuntimeError, match="controlled-use-failure"):
        with prepare(fixture, report):
            raise RuntimeError("controlled-use-failure")
    assert report["status"] == "failed" and report["base_preserved"]
    assert report["temporary_resources_removed"] and not list(temporary.iterdir())
    assert valid_stats(report["statistics"])


@pytest.mark.parametrize("failure", [False, True], ids=["accepted", "rejected"])
def test_main_retains_exact_source_scope_and_guest_input_failure(
    fixture, tmp_path, monkeypatch, failure
):
    state, command, temporary, _ = fixture
    if failure:
        state["mode"] = "create-failure"
    source = {"commit": "a" * 40, "clean": True, "fingerprint": "b" * 64}
    monkeypatch.setattr(native, "enroll", lambda *args, **kwargs: {})
    monkeypatch.setattr(native, "source_identity", lambda: source)
    monkeypatch.setattr(native, "provision", lambda: {"binary_sha256": "c" * 64})
    monkeypatch.setattr(native, "provision_tools", lambda *args: {})
    monkeypatch.setattr(native, "boot_guest", lambda *args: None)
    monkeypatch.setattr(native, "probe_controller", lambda *args: {"fixture_only": True})
    monkeypatch.setattr(native, "controller_faults", lambda *args: None)
    monkeypatch.setattr(native, "guest_storage_faults", lambda *a: None)
    monkeypatch.setattr(native, "guest_reboot_faults", lambda *a: None)
    monkeypatch.setattr(native, "verify_guest_cleanup", lambda *a: None)
    monkeypatch.setattr(native, "run", command)
    monkeypatch.setenv("RUNNER_TEMP", str(temporary))
    output = tmp_path / "report.json"
    assert native.main(["--github-hosted-only", "--output", str(output)]) == int(failure)
    report = json.loads(output.read_text())
    assert report["source_before"] == report["source_after"] == source
    assert report["guest_inputs"]["enrollment"] == report["fixture_enrollment"]
    assert report["guest_inputs"]["status"] == ("failed" if failure else "passed")
    assert report["guest_inputs"]["temporary_resources_removed"]
    assert valid_stats(report["guest_inputs"]["statistics"]) and valid_stats(report["statistics"])
    assert all(
        report[key] is False
        for key in ["guest_booted", "native_tools_qualified", "production_qualified"]
    )
    assert not list(temporary.iterdir())


def test_cleanup_failure_keeps_failed_status_and_required_statistics(fixture, monkeypatch):
    _, _, temporary, _ = fixture
    report = {}
    real_remove = images.shutil.rmtree

    def fail(path):
        raise OSError("fixture-private-output")

    monkeypatch.setattr(images.shutil, "rmtree", fail)
    try:
        with pytest.raises(images.GuestInputError, match="guest-input-cleanup-failed"):
            with prepare(fixture, report):
                pass
        assert report["status"] == "failed" and not report["temporary_resources_removed"]
        assert valid_stats(report["statistics"])
    finally:
        for path in temporary.iterdir():
            real_remove(path)


def test_substituted_directory_cannot_be_removed_as_owned(fixture, tmp_path):
    _, _, temporary, foreign = fixture
    foreign_directory = tmp_path / "foreign-directory"
    foreign_directory.mkdir(mode=0o700)
    marker = foreign_directory / "keep"
    marker.write_text("unrelated")
    report = {}
    relocated = tmp_path / "relocated-owned"
    original = None
    try:
        with pytest.raises(images.GuestInputError):
            with prepare(fixture, report) as owned:
                original = owned.directory
                original.rename(relocated)
                original.symlink_to(foreign_directory, target_is_directory=True)
        assert marker.read_text() == "unrelated" and foreign.exists()
        assert report["status"] == "failed" and not report["temporary_resources_removed"]
        assert valid_stats(report["statistics"])
    finally:
        if original is not None and original.is_symlink():
            original.unlink()
        if relocated.exists():
            images.shutil.rmtree(relocated)
    assert not list(temporary.iterdir())


@pytest.mark.parametrize("mode", ["complete", "oversized", "truncated"])
def test_download_worker_refuses_redirects_proxies_and_wrong_extent(tmp_path, monkeypatch, mode):
    import urllib.request

    destination = tmp_path / "download"
    payload = {"complete": b"abc", "oversized": b"abcd", "truncated": b"ab"}[mode]
    chunks = iter([payload, b""])
    calls = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            assert size == 1024 * 1024
            return next(chunks)

    class Opener:
        def open(self, url, *, timeout):
            calls.append((url, timeout))
            return Response()

    def build(*handlers):
        assert len(handlers) == 2 and handlers[0].proxies == {}
        assert (
            handlers[1].redirect_request(None, None, 302, None, None, "https://unrelated.invalid")
            is None
        )
        return Opener()

    monkeypatch.setattr(urllib.request, "build_opener", build)
    monkeypatch.setattr(sys, "argv", ["worker", str(destination), images.IMAGE_URL, "7.5", "3"])
    if mode == "complete":
        assert download.main() == 0
        assert destination.read_bytes() == b"abc"
    else:
        expected = {
            "oversized": download.Failure.EXCESSIVE_CONTENT,
            "truncated": download.Failure.INCOMPLETE_CONTENT,
        }[mode]
        assert download.main() == expected
    assert calls == [(images.IMAGE_URL, 7.5)]
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


@pytest.mark.parametrize("link", [False, True], ids=["file", "symlink"])
def test_download_worker_never_overwrites_existing_or_foreign_destination(
    tmp_path, monkeypatch, link
):
    import urllib.request

    target = tmp_path / "target"
    target.write_bytes(b"keep")
    destination = tmp_path / "destination"
    if link:
        destination.symlink_to(target)
    else:
        destination.write_bytes(b"keep")

    class Opener:
        def open(self, *args, **kwargs):
            pytest.fail("an existing destination reached the network")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    monkeypatch.setattr(sys, "argv", ["worker", str(destination), images.IMAGE_URL, "7.5", "3"])
    assert download.main() == download.Failure.DESTINATION_REFUSED
    assert target.read_bytes() == destination.read_bytes() == b"keep"


def test_http_response_failure_keeps_safe_status_and_original_exit(tmp_path, capsys):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    from scripts.validation_timeouts import watchdog

    observed = []

    class Unavailable(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
            observed.append(503)

        def log_message(self, *args):
            pass

    destination = tmp_path / "download"
    with HTTPServer(("127.0.0.1", 0), Unavailable) as server:
        server.timeout = watchdog(1)
        worker = Thread(target=server.handle_request)
        worker.start()
        try:
            with pytest.raises(native.EnrollmentError) as caught:
                native.run(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        str(images.DOWNLOAD_WORKER),
                        str(destination),
                        f"http://127.0.0.1:{server.server_port}/image",
                        str(watchdog(1)),
                        "3",
                    ],
                    "guest-image-download",
                    10,
                )
        finally:
            worker.join(watchdog(5))
        assert not worker.is_alive()
    assert observed == [503]
    assert caught.value.stage == "guest-image-download"
    assert caught.value.reason == "command-exit-40"
    assert getattr(caught.value, "classifications", None) == ("image-http-response-failure",)
    assert getattr(caught.value, "http_status", None) == 503
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize(
    "error,expected",
    [
        ("dns", download.Failure.TRANSPORT_FAILURE),
        ("wrapped-tls", download.Failure.TLS_FAILURE),
        ("wrapped-timeout", download.Failure.NETWORK_TIMEOUT),
        ("tls", download.Failure.TLS_FAILURE),
        ("timeout", download.Failure.NETWORK_TIMEOUT),
        ("incomplete", download.Failure.INCOMPLETE_CONTENT),
        ("protocol", download.Failure.TRANSPORT_FAILURE),
        ("unexpected", download.Failure.UNEXPECTED_WORKER_FAILURE),
    ],
)
@pytest.mark.parametrize("phase", ["open", "read"])
def test_download_worker_closes_destination_and_classifies_safe_failures(
    tmp_path, monkeypatch, capsys, error, expected, phase
):
    import ssl
    import urllib.error
    from http.client import HTTPException, IncompleteRead

    failures = {
        "dns": urllib.error.URLError(OSError("fixture-private-value")),
        "wrapped-tls": urllib.error.URLError(ssl.SSLError("fixture-private-value")),
        "wrapped-timeout": urllib.error.URLError(TimeoutError("fixture-private-value")),
        "tls": ssl.SSLError("fixture-private-value"),
        "timeout": TimeoutError("fixture-private-value"),
        "incomplete": IncompleteRead(b"fixture-private-value", 3),
        "protocol": HTTPException("fixture-private-value"),
        "unexpected": RuntimeError("fixture-private-value"),
    }

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            raise failures[error]

    class Opener:
        def open(self, *args, **kwargs):
            if phase == "open":
                raise failures[error]
            return Response()

    destination = tmp_path / "owned-download"
    monkeypatch.setattr(download.urllib.request, "build_opener", lambda *args: Opener())
    assert download.main([str(destination), images.IMAGE_URL, "7.5", "3"]) == expected
    assert destination.read_bytes() == b"" and stat.S_IMODE(destination.stat().st_mode) == 0o600
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize("timeout", ["nan", "inf", "0", "-1", "not-a-number"])
def test_download_worker_rejects_invalid_budget_before_destination_or_network(
    tmp_path, monkeypatch, capsys, timeout
):
    def forbidden(*args):
        pytest.fail("invalid budget reached the network")

    monkeypatch.setattr(download.urllib.request, "build_opener", forbidden)
    destination = tmp_path / "download"
    assert (
        download.main([str(destination), images.IMAGE_URL, timeout, "3"])
        == download.Failure.UNEXPECTED_WORKER_FAILURE
    )
    assert not destination.exists()
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize("payload,expected", [(b"abc", 0), (b"abcd", 45), (b"ab", 44)])
def test_isolated_worker_real_local_transfer_preserves_extent_and_private_output(
    tmp_path, payload, expected, capsys
):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    from scripts.validation_timeouts import watchdog

    observed = []

    class Image(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            observed.append(self.path)

        def log_message(self, *args):
            pass

    destination = tmp_path / "download"
    with HTTPServer(("127.0.0.1", 0), Image) as server:
        server.timeout = watchdog(2)
        worker = Thread(target=server.handle_request)
        worker.start()
        command = [
            sys.executable,
            "-I",
            "-S",
            str(images.DOWNLOAD_WORKER),
            str(destination),
            f"http://127.0.0.1:{server.server_port}/image",
            str(watchdog(2)),
            "3",
        ]
        try:
            if expected:
                with pytest.raises(native.ImageDownloadCommandError) as caught:
                    native.run(command, "guest-image-download", 10)
                assert caught.value.reason == f"command-exit-{expected}"
                assert caught.value.classifications == (
                    "image-excessive-content" if expected == 45 else "image-incomplete-content",
                )
                assert caught.value.http_status is None
            else:
                assert native.run(command, "guest-image-download", 10) == ""
                assert destination.read_bytes() == payload
        finally:
            worker.join(watchdog(5))
        assert not worker.is_alive()
    assert observed == ["/image"]
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_download_worker_write_failure_remains_destination_refusal(tmp_path, monkeypatch, capsys):
    import errno

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            return b"abc"

    class Opener:
        def open(self, *args, **kwargs):
            return Response()

    class Full:
        def write(self, content):
            raise OSError(errno.ENOSPC, "fixture-private-value")

    monkeypatch.setattr(download.urllib.request, "build_opener", lambda *args: Opener())
    args = download.Inputs(tmp_path / "download", images.IMAGE_URL, 7.5, 3)
    assert download._receive(Full(), args) == download.Failure.DESTINATION_REFUSED
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_classified_download_failure_preserves_partial_cleanup_and_statistics(fixture):
    state, _, temporary, foreign = fixture
    state["mode"] = "classified-download-failure"
    report = {}
    with pytest.raises(native.ImageDownloadCommandError) as caught:
        with prepare(fixture, report):
            pytest.fail("failed download admitted guest inputs")
    assert caught.value.stage == "guest-image-download"
    assert caught.value.reason == "command-exit-40"
    assert caught.value.classifications == ("image-http-response-failure",)
    assert caught.value.http_status == 503
    assert report["status"] == "failed" and report["temporary_resources_removed"]
    assert valid_stats(report["statistics"]) and not list(temporary.iterdir())
    assert foreign.read_bytes() == b"controlled-authenticated-image"
    assert not any(call[1] == "guest-image-create" for call in state["calls"])


def test_download_worker_close_failure_cannot_report_transfer_success(
    tmp_path, monkeypatch, capsys
):
    import errno

    real_fdopen = download.os.fdopen
    chunks = iter([b"abc", b""])

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            return next(chunks)

    class Opener:
        def open(self, *args, **kwargs):
            return Response()

    class FailedClose:
        def __init__(self, fd, mode):
            self.file = real_fdopen(fd, mode)

        def __enter__(self):
            return self.file

        def __exit__(self, *args):
            self.file.close()
            raise OSError(errno.ENOSPC, "fixture-private-value")

    monkeypatch.setattr(download.os, "fdopen", FailedClose)
    monkeypatch.setattr(download.urllib.request, "build_opener", lambda *args: Opener())
    destination = tmp_path / "download"
    assert (
        download.main([str(destination), images.IMAGE_URL, "7.5", "3"])
        == download.Failure.DESTINATION_REFUSED
    )
    assert destination.read_bytes() == b"abc"
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_isolated_download_refuses_actual_redirect_before_foreign_request(tmp_path, capsys):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    from scripts.validation_timeouts import watchdog

    observed = []

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            observed.append(self.path)
            self.send_response(302 if self.path == "/image" else 200)
            if self.path == "/image":
                self.send_header("Location", "/foreign")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    destination = tmp_path / "download"
    with HTTPServer(("127.0.0.1", 0), Redirect) as server:
        server.timeout = watchdog(0.5)

        def serve():
            for _ in range(2):
                server.handle_request()

        worker = Thread(target=serve)
        worker.start()
        try:
            with pytest.raises(native.ImageDownloadCommandError) as caught:
                native.run(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        str(images.DOWNLOAD_WORKER),
                        str(destination),
                        f"http://127.0.0.1:{server.server_port}/image",
                        str(watchdog(2)),
                        "3",
                    ],
                    "guest-image-download",
                    10,
                )
        finally:
            worker.join(watchdog(5))
        assert not worker.is_alive()
    assert observed == ["/image"]
    assert caught.value.reason == "command-exit-40"
    assert caught.value.classifications == ("image-http-response-failure",)
    assert caught.value.http_status == 302 and destination.read_bytes() == b""
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
