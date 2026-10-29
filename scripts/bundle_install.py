from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
import venv
from pathlib import Path, PurePosixPath
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(bundle: Path, expected: str) -> dict[str, Any]:
    bundle = bundle.resolve()
    manifest_path = bundle / "manifest.json"
    if manifest_path.stat().st_size > 2_000_000 or sha256(manifest_path) != expected:
        raise ValueError("untrusted or changed manifest")
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        manifest.get("format") != "fishhat-scaffold-bundle/v1"
        or manifest.get("production_qualified") is not False
    ):
        raise ValueError("unsupported bundle qualification")
    profile = manifest["profile"]
    if (
        profile["platform"] != sys.platform
        or profile["python"] != f"{sys.version_info.major}.{sys.version_info.minor}"
    ):
        raise ValueError("bundle platform or Python mismatch")
    import platform

    if profile["machine"].lower() != platform.machine().lower():
        raise ValueError("bundle architecture mismatch")
    files = manifest["files"]
    for name, metadata in files.items():
        member = PurePosixPath(name)
        if member.is_absolute() or ".." in member.parts or "\\" in name or ":" in name:
            raise ValueError("unsafe bundle member")
        actual = bundle / name
        if (
            actual.is_symlink()
            or not actual.resolve().is_relative_to(bundle)
            or not actual.is_file()
        ):
            raise ValueError("missing or unsafe bundle member")
        if actual.stat().st_size != metadata["size"] or sha256(actual) != metadata["sha256"]:
            raise ValueError("bundle artifact changed")
    for selection in manifest["components"].values():
        lock = selection["lock"]
        if lock not in files or not re.fullmatch(r"locks/[a-z0-9-]+\.txt", lock):
            raise ValueError("unverified component lock")
        entries = (bundle / lock).read_text().splitlines()
        if not entries or any(
            not re.fullmatch(
                r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.!+-]+ --hash=sha256:[a-f0-9]{64}", entry
            )
            for entry in entries
        ):
            raise ValueError("component lock must contain hashed package pins only")
        names = {entry.split("==")[0] for entry in entries}
        if names != set(selection["dependencies"]) or selection["distribution"] not in names:
            raise ValueError("component dependency inventory mismatch")
    actual_files = set()
    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise ValueError("bundle contains a symbolic link")
        if path.is_file():
            actual_files.add(path.relative_to(bundle).as_posix())
    if actual_files != set(files) | {"manifest.json", "SHA256SUMS"}:
        raise ValueError("unclassified bundle contents")
    sums = {
        **{name: metadata["sha256"] for name, metadata in files.items()},
        "manifest.json": expected,
    }
    expected_sums = "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items()))
    if (bundle / "SHA256SUMS").read_text() != expected_sums:
        raise ValueError("bundle checksum inventory changed")
    return manifest


def install(
    bundle: Path, destination: Path, component: str, expected: str, *, timeout_seconds: float = 180
) -> Path:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("invalid installation timeout")
    manifest = verify(bundle, expected)
    if component not in manifest["components"] or destination.exists():
        raise ValueError("unknown component or existing installation destination")
    lock = bundle / manifest["components"][component]["lock"]
    venv.EnvBuilder(with_pip=True, symlinks=sys.platform != "win32").create(destination)
    python = destination / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    command = [
        str(python),
        "-I",
        "-m",
        "pip",
        "--isolated",
        "install",
        "--no-index",
        "--no-cache-dir",
        "--require-hashes",
        "--only-binary=:all:",
        "--find-links",
        str(bundle / "wheels"),
        "-r",
        str(lock),
    ]
    subprocess.run(command, check=True, capture_output=True, timeout=timeout_seconds)
    return python


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify or install a reference-scaffold bundle using an independently trusted manifest hash"
    )
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--component")
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    try:
        if args.component is None and args.destination is None:
            verify(args.bundle, args.manifest_sha256)
        elif args.component is not None and args.destination is not None:
            install(args.bundle, args.destination, args.component, args.manifest_sha256)
        else:
            raise ValueError("component and destination must be selected together")
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        raise SystemExit("scaffold bundle verification or installation failed") from None
    print(json.dumps({"passed": True, "production_qualified": False}))


if __name__ == "__main__":
    main()
