"""Isolated image transfer with closed, secret-safe failure observations."""

from __future__ import annotations

import json
import math
import os
import ssl
import sys
import urllib.error
import urllib.request
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from enum import IntEnum
from http.client import HTTPException, IncompleteRead
from pathlib import Path
from typing import Any, BinaryIO


class Failure(IntEnum):
    HTTP_RESPONSE_FAILURE = 40
    TRANSPORT_FAILURE = 41
    TLS_FAILURE = 42
    NETWORK_TIMEOUT = 43
    INCOMPLETE_CONTENT = 44
    EXCESSIVE_CONTENT = 45
    DESTINATION_REFUSED = 46
    UNEXPECTED_WORKER_FAILURE = 47


def classification(status: int) -> str:
    try:
        failure = Failure(status)
    except ValueError:
        failure = Failure.UNEXPECTED_WORKER_FAILURE
    return "image-" + failure.name.lower().replace("_", "-")


@dataclass(frozen=True)
class Inputs:
    destination: Path
    url: str
    watchdog_seconds: float
    extent: int


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _http_failure(status: object) -> Failure:
    if type(status) is int and 100 <= status <= 599:
        print(json.dumps({"http_status": status}), flush=True)
    return Failure.HTTP_RESPONSE_FAILURE


def _receive(output: BinaryIO, args: Inputs) -> int:
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(args.url, timeout=args.watchdog_seconds) as response:
            if response.status != 200:
                return _http_failure(response.status)
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > args.extent:
                    return Failure.EXCESSIVE_CONTENT
                try:
                    output.write(chunk)
                except OSError:
                    return Failure.DESTINATION_REFUSED
            return 0 if total == args.extent else Failure.INCOMPLETE_CONTENT
    except urllib.error.HTTPError as error:
        with suppress(OSError):
            error.close()
        return _http_failure(error.code)
    except urllib.error.URLError as error:
        if isinstance(error.reason, ssl.SSLError):
            return Failure.TLS_FAILURE
        if isinstance(error.reason, TimeoutError):
            return Failure.NETWORK_TIMEOUT
        return Failure.TRANSPORT_FAILURE
    except ssl.SSLError:
        return Failure.TLS_FAILURE
    except TimeoutError:
        return Failure.NETWORK_TIMEOUT
    except IncompleteRead:
        return Failure.INCOMPLETE_CONTENT
    except (OSError, HTTPException):
        return Failure.TRANSPORT_FAILURE
    except Exception:
        return Failure.UNEXPECTED_WORKER_FAILURE


def main(argv: Sequence[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else list(argv)
    try:
        if len(values) != 4:
            return Failure.UNEXPECTED_WORKER_FAILURE
        args = Inputs(Path(values[0]), values[1], float(values[2]), int(values[3]))
        if (
            not math.isfinite(args.watchdog_seconds)
            or args.watchdog_seconds <= 0
            or args.extent < 0
        ):
            return Failure.UNEXPECTED_WORKER_FAILURE
        try:
            with os.fdopen(
                os.open(
                    args.destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                ),
                "wb",
            ) as output:
                return _receive(output, args)
        except OSError:
            return Failure.DESTINATION_REFUSED
    except Exception:
        return Failure.UNEXPECTED_WORKER_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
