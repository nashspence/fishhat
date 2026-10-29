from __future__ import annotations

import argparse
import email
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from scripts.bundle_install import install, sha256, verify
from scripts.project_policy import ROOT, components, fingerprint, read_toml
from scripts.validation_timeouts import invocation, watchdog


def wheel_metadata(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        metadata = email.message_from_bytes(archive.read(name))
        return {
            "name": canonicalize_name(str(metadata["Name"])),
            "version": str(metadata["Version"]),
            "requires": metadata.get_all("Requires-Dist", []),
            "license": metadata.get("License-Expression") or metadata.get("License"),
        }


def closure(name: str, wheels: dict[str, tuple[Path, dict[str, Any]]]) -> set[str]:
    result: set[str] = set()
    pending = [name]
    while pending:
        current = pending.pop()
        if current in result:
            continue
        if current not in wheels:
            raise ValueError("missing locked runtime wheel")
        result.add(current)
        for raw in wheels[current][1]["requires"]:
            requirement = Requirement(raw)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                dependency = canonicalize_name(requirement.name)
                if (
                    dependency not in wheels
                    or wheels[dependency][1]["version"] not in requirement.specifier
                ):
                    raise ValueError("wheel dependency version is missing or incompatible")
                pending.append(dependency)
    return result


def prepare(dist: Path, output: Path) -> Path:
    if output.exists():
        raise ValueError("bundle output must be new")
    policy = read_toml(ROOT / "release.toml")
    if f"{sys.version_info.major}.{sys.version_info.minor}" not in policy["python_tests"]:
        raise ValueError("Python outside the scaffold test matrix")
    output.mkdir(parents=True)
    wheel_dir = output / "wheels"
    wheel_dir.mkdir()
    runtime = output / "runtime.txt"
    subprocess.run(
        [
            "uv",
            "export",
            "--quiet",
            "--locked",
            "--all-packages",
            "--no-dev",
            "--no-emit-workspace",
            "--format",
            "requirements-txt",
            "--output-file",
            str(runtime),
        ],
        cwd=ROOT,
        capture_output=True,
        check=True,
        timeout=watchdog(60),
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "--isolated",
            "--timeout",
            str(watchdog(15)),
            "download",
            "--only-binary=:all:",
            "--no-deps",
            "--require-hashes",
            "--dest",
            str(wheel_dir),
            "-r",
            str(runtime),
        ],
        capture_output=True,
        check=True,
        timeout=watchdog(180),
    )
    runtime.unlink()
    units = components()
    expected_versions = {
        item["distribution"]: read_toml(ROOT / item["path"] / "pyproject.toml")["project"][
            "version"
        ]
        for item in units
    }
    expected = set(expected_versions)
    found = set()
    for wheel in dist.glob("*.whl"):
        metadata = wheel_metadata(wheel)
        if (
            metadata["name"] not in expected
            or metadata["name"] in found
            or metadata["version"] != expected_versions[metadata["name"]]
        ):
            raise ValueError("unexpected, duplicated or mismatched workspace wheel")
        found.add(metadata["name"])
        shutil.copyfile(wheel, wheel_dir / wheel.name)
    if found != expected:
        raise ValueError("workspace wheel inventory is incomplete")
    wheels: dict[str, tuple[Path, dict[str, Any]]] = {}
    for wheel in wheel_dir.glob("*.whl"):
        metadata = wheel_metadata(wheel)
        if metadata["name"] in wheels:
            raise ValueError("ambiguous wheel identity")
        wheels[metadata["name"]] = (wheel, metadata)
    (output / "locks").mkdir()
    selections: dict[str, Any] = {}
    for item in units:
        selected = closure(item["distribution"], wheels)
        lock_name = "locks/" + item["id"] + ".txt"
        (output / lock_name).write_text(
            "".join(
                f"{name}=={wheels[name][1]['version']} --hash=sha256:{sha256(wheels[name][0])}\n"
                for name in sorted(selected)
            )
        )
        selections[item["id"]] = {
            "distribution": item["distribution"],
            "lock": lock_name,
            "dependencies": sorted(selected),
            "module": item["module"],
        }
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    provenance = {
        "format": "fishhat-build-provenance/v1",
        "source_repository": policy["governance"]["repository_name"],
        "source_commit": commit,
        "working_tree_dirty": dirty,
        "uv_lock_sha256": fingerprint(ROOT / "uv.lock"),
        "mise_lock_sha256": fingerprint(ROOT / "mise.lock"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "production_qualified": False,
    }
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    sbom = {
        "format": "fishhat-dependency-inventory/v1",
        "components": [
            {
                "name": name,
                "version": metadata["version"],
                "license": metadata["license"],
                "wheel_sha256": sha256(path),
            }
            for name, (path, metadata) in sorted(wheels.items())
        ],
    }
    (output / "dependencies.json").write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n")
    shutil.copyfile(ROOT / "scripts/bundle_install.py", output / "install.py")
    files = {
        path.relative_to(output).as_posix(): {"sha256": sha256(path), "size": path.stat().st_size}
        for path in output.rglob("*")
        if path.is_file()
    }
    manifest = {
        "format": "fishhat-scaffold-bundle/v1",
        "version": policy["version"],
        "production_qualified": False,
        "profile": {
            "platform": sys.platform,
            "machine": platform.machine(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        },
        "components": selections,
        "files": files,
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    sums = {
        **{name: item["sha256"] for name, item in files.items()},
        "manifest.json": sha256(manifest_path),
    }
    (output / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items()))
    )
    verify(output, sha256(manifest_path))
    return manifest_path


def smoke(bundle: Path) -> None:
    expected = sha256(bundle / "manifest.json")
    manifest = verify(bundle, expected)
    with tempfile.TemporaryDirectory(prefix="fishhat-installed-") as temporary:
        scratch = Path(temporary)
        for item in components():
            env = scratch / item["id"]
            python = install(bundle, env, item["id"], expected, timeout_seconds=watchdog(180))
            command = [
                str(python),
                "-I",
                str(ROOT / "scripts/smoke_installed.py"),
                "--watchdog-seconds",
                str(watchdog(15)),
                "--component",
                item["id"],
                "--bundle",
                str(bundle),
                "--fixtures",
                str(ROOT / "tests/fixtures"),
            ]
            subprocess.run(command, cwd=scratch, check=True, timeout=watchdog(90))
            # Keep only the environment needed by the final external typing check.
            if item["id"] != "contracts":
                shutil.rmtree(env)
        consumer = scratch / "consumer.py"
        consumer.write_text(
            'from typing import assert_type\nfrom fishhat_contracts import canonical, digest\nassert_type(canonical({"key": "value"}), bytes)\nassert_type(digest({"key": "value"}), str)\n'
        )
        python = (
            scratch
            / "contracts"
            / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        )
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "mypy",
                "--strict",
                "--no-incremental",
                "--python-executable",
                str(python),
                str(consumer),
            ],
            cwd=scratch,
            check=True,
            timeout=watchdog(90),
        )
    print(
        json.dumps(
            {
                "passed": True,
                "installed_components": len(manifest["components"]),
                "production_qualified": False,
            }
        )
    )


def build() -> None:
    from scripts.check_wheel import check_wheels

    for item in components():
        generated = ROOT / item["path"] / "build"
        if generated.is_symlink() or not generated.resolve().is_relative_to(ROOT):
            raise ValueError("unsafe component build directory")
        if generated.exists():
            shutil.rmtree(generated)
    subprocess.run(["uv", "build", "--all-packages", "--wheel", "--clear"], cwd=ROOT, check=True)
    check_wheels(ROOT / "dist")


def smoke_fresh(dist: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="fishhat-bundle-") as temporary:
        bundle = Path(temporary) / "bundle"
        prepare(dist, bundle)
        smoke(bundle)


def archive(bundle: Path) -> Path:
    verify(bundle, sha256(bundle / "manifest.json"))
    target = bundle.with_suffix(".zip")
    with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED) as output:
        for path in sorted(bundle.rglob("*")):
            if path.is_file():
                output.write(path, path.relative_to(bundle).as_posix())
    return target


@invocation
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["prepare", "smoke", "archive", "smoke-fresh", "build"])
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()
    if args.command == "build":
        build()
        return
    if args.command == "smoke-fresh":
        if args.bundle is not None:
            parser.error("smoke-fresh manages its own temporary bundle")
        smoke_fresh(args.dist.resolve())
        return
    if args.bundle is None:
        parser.error("--bundle is required for prepare, smoke and archive")
    if args.command == "prepare":
        path = prepare(args.dist.resolve(), args.bundle.resolve())
        print(json.dumps({"manifest_sha256": sha256(path), "production_qualified": False}))
    elif args.command == "smoke":
        smoke(args.bundle.resolve())
    else:
        path = archive(args.bundle.resolve())
        print(json.dumps({"archive_sha256": sha256(path), "production_qualified": False}))


if __name__ == "__main__":
    main()
