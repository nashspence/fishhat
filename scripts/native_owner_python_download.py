"""Download one selected public runtime without inherited proxy/configuration state."""

from __future__ import annotations

import hashlib
import json
import math
import os
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Inputs:
    destination: Path
    url: str
    extent: int
    expected: str
    watchdog_seconds: float


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Any,
        response: Any,
        code: int,
        message: str,
        headers: Any,
        newurl: str,
    ) -> Any:
        target = urllib.parse.urlsplit(newurl)
        if (
            target.scheme != "https"
            or target.hostname != "release-assets.githubusercontent.com"
            or target.username is not None
            or target.password is not None
            or target.port not in (None, 443)
        ):
            raise ValueError("unexpected runtime download origin")
        return super().redirect_request(request, response, code, message, headers, newurl)


def main() -> int:
    try:
        destination, url, size, expected, timeout = sys.argv[1:]
        args = Inputs(Path(destination), url, int(size), expected, float(timeout))
        if (
            not math.isfinite(args.watchdog_seconds)
            or args.watchdog_seconds <= 0
            or args.extent < 0
        ):
            raise ValueError("invalid runtime download observation bounds")
        checksum = hashlib.sha256()
        received = 0
        descriptor = os.open(
            args.destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as output:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ReleaseRedirect())
            with opener.open(args.url, timeout=args.watchdog_seconds) as source:
                if source.status != 200:
                    raise ValueError("runtime download response")
                while chunk := source.read(1_048_576):
                    received += len(chunk)
                    if received > args.extent:
                        raise ValueError("runtime download extent")
                    checksum.update(chunk)
                    output.write(chunk)
            if received != args.extent or checksum.hexdigest() != args.expected:
                raise ValueError("runtime download identity")
            output.flush()
            os.fsync(output.fileno())
        return 0
    except Exception:
        # Redirect locations can contain short-lived credentials. Emit no URL,
        # response body or exception text, even for this public fixed artifact.
        print(json.dumps({"runtime_download_passed": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
