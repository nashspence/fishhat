"""No live network requests; fixed download mechanics and closed failure output."""

import hashlib
import io
import json
import sys
import urllib.request

import pytest

from scripts import native_owner_python_download as worker
from scripts.validation_watchdogs import PythonGuard

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_owner_python_download.py", "scripts/validation_watchdogs.py"],
    "scope": "bounded artifact transfer, exact identity, redirect origins and secret-safe failure observations",
    "relationship": "no-product-claim",
    "reason": "Invented in-memory responses exercise the isolated worker without networking or installing a runtime. They establish no upstream authentication or native installation claim.",
    "claims": [],
}


class Response(io.BytesIO):
    status = 200


@pytest.mark.parametrize("kind", ["exact", "truncated", "excessive", "changed", "exception"])
def test_download_preserves_complete_identity_and_closed_failure_output(
    tmp_path, monkeypatch, capsys, kind
):
    expected = b"complete public artifact"
    supplied = {
        "exact": expected,
        "truncated": expected[:-1],
        "excessive": expected + b"x",
        "changed": b"x" * len(expected),
    }

    def open_response(url, timeout):
        assert url == "https://github.com/public/pinned-input" and timeout == 3
        if kind == "exception":
            raise OSError("private-redirect-observation-must-not-leak")
        return Response(supplied[kind])

    def opener(*handlers):
        assert any(
            isinstance(handler, urllib.request.ProxyHandler) and handler.proxies == {}
            for handler in handlers
        )
        assert any(isinstance(handler, worker.ReleaseRedirect) for handler in handlers)
        return type("Opener", (), {"open": staticmethod(open_response)})()

    destination = tmp_path / "archive"
    monkeypatch.setattr(worker.urllib.request, "build_opener", opener)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker",
            str(destination),
            "https://github.com/public/pinned-input",
            str(len(expected)),
            hashlib.sha256(expected).hexdigest(),
            "3",
        ],
    )
    status = worker.main()
    output = capsys.readouterr().out
    assert status == (0 if kind == "exact" else 1)
    assert destination.stat().st_mode & 0o777 == 0o600
    if kind == "exact":
        assert destination.read_bytes() == expected and output == ""
    else:
        assert json.loads(output) == {"runtime_download_passed": False}
        assert "private-redirect" not in output


@pytest.mark.parametrize(
    "target",
    [
        "http://" + "release-assets.githubusercontent.com/input",
        "https://other.invalid/input",
        "file:///tmp/input",
        "https://user:credential@" + "release-assets.githubusercontent.com/input",
        "https://" + "release-assets.githubusercontent.com:8443/input",
    ],
    ids=["http", "foreign-host", "file-scheme", "credentials", "foreign-port"],
)
def test_redirect_origin_substitutions_are_rejected(target):
    request = urllib.request.Request("https://github.com/public/input")
    with pytest.raises(ValueError, match="unexpected runtime download origin"):
        worker.ReleaseRedirect().redirect_request(request, None, 302, "redirect", {}, target)


def test_release_asset_redirect_keeps_https_and_destination():
    request = urllib.request.Request("https://github.com/public/input")
    target = "https://" + "release-assets.githubusercontent.com/public/input?opaque=value"
    result = worker.ReleaseRedirect().redirect_request(request, None, 302, "redirect", {}, target)
    assert result.full_url == target


@pytest.mark.parametrize("timeout", ["0", "-1", "nan", "inf"])
def test_invalid_watchdog_rejects_before_destination_or_network(
    tmp_path, monkeypatch, capsys, timeout
):
    destination = tmp_path / "archive"
    monkeypatch.setattr(
        sys,
        "argv",
        ["worker", str(destination), "https://github.com/public/input", "1", "0" * 64, timeout],
    )
    monkeypatch.setattr(
        worker.urllib.request,
        "build_opener",
        lambda *args: pytest.fail("invalid watchdog reached network"),
    )
    assert worker.main() == 1
    assert not destination.exists()
    assert json.loads(capsys.readouterr().out) == {"runtime_download_passed": False}


def test_only_owned_worker_argument_is_a_delegated_watchdog():
    name = "scripts/native_owner_python_download.py"
    source = __import__("pathlib").Path(worker.__file__).read_text()
    accepted = PythonGuard(source, name)
    accepted.walk(accepted.tree)
    assert accepted.errors == []
    assert "timeout=args.watchdog_seconds" in source
    rejected = PythonGuard(source.replace("timeout=args.watchdog_seconds", "timeout=30"), name)
    rejected.walk(rejected.tree)
    assert len(rejected.errors) == 1 and "unmanaged watchdog" in rejected.errors[0]
