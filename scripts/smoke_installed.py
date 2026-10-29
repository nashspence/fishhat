from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import importlib.util
import io
import json
import math
import pkgutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--component", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--watchdog-seconds", type=float, required=True)
    args = parser.parse_args()
    if (
        not math.isfinite(args.watchdog_seconds)
        or not 0 < args.watchdog_seconds <= threading.TIMEOUT_MAX
    ):
        parser.error("invalid effective watchdog")
    manifest = json.loads((args.bundle / "manifest.json").read_text())
    selected = manifest["components"][args.component]
    expected = set(selected["dependencies"])
    for item in manifest["components"].values():
        present = importlib.util.find_spec(item["module"]) is not None
        if present != (item["distribution"] in expected):
            raise AssertionError("installed dependency closure changed")
        if present:
            module = importlib.import_module(item["module"])
            assert module.__file__ is not None
            if not (Path(module.__file__).parent / "py.typed").is_file():
                raise AssertionError("installed type marker missing")
            for entry in pkgutil.walk_packages(module.__path__, module.__name__ + "."):
                importlib.import_module(entry.name)
    from fishhat_contracts import canonical, digest, strict_json, strict_yaml, validate

    data = strict_yaml((args.fixtures / "domain/domain.yaml").read_text())
    validate("source.schema.json", data)
    assert strict_json(canonical(data)) == data
    assert digest(data).startswith("sha256:")
    if args.component in {"domain", "host", "app"}:
        tool = {"domain": "domain-ops", "host": "host-ops", "app": "app-ops"}[args.component]
        executable = Path(sys.executable).parent / (
            tool + ".exe" if sys.platform == "win32" else tool
        )
        result = subprocess.run(
            [str(executable), "info", "--json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=args.watchdog_seconds,
        )
        info = json.loads(result.stdout)
        assert (
            info["tool"] == tool
            and info["native_mutations"] is False
            and info["production_qualified"] is False
        )
        subprocess.run(
            [str(executable), "validate", str(args.fixtures / "domain/domain.yaml"), "--json"],
            capture_output=True,
            check=True,
            timeout=args.watchdog_seconds,
        )
        rejected = subprocess.run(
            [str(executable), "apply"], capture_output=True, timeout=args.watchdog_seconds
        )
        assert rejected.returncode == 2
    if selected["distribution"].startswith("a-fishhat-"):
        distribution = importlib.metadata.distribution(selected["distribution"])
        entrypoints = [
            entry for entry in distribution.entry_points if entry.group == "console_scripts"
        ]
        assert len(entrypoints) == 1
        executable = Path(sys.executable).parent / (
            entrypoints[0].name + ".exe" if sys.platform == "win32" else entrypoints[0].name
        )
        result = subprocess.run(
            [str(executable), "info", "--json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=args.watchdog_seconds,
        )
        info = json.loads(result.stdout)
        assert info["native_qualified"] is False
        rejected = subprocess.run(
            [str(executable), "qualify", "--json"],
            capture_output=True,
            timeout=args.watchdog_seconds,
        )
        assert rejected.returncode == 2
        if "bootstrap-source" in info["roles"]:
            provider = args.component.removesuffix("-bootstrap")
            source = (args.fixtures / "bootstrap" / (provider + "-source.json")).read_bytes()
            validated = subprocess.run(
                [str(executable), "validate-source", "--json"],
                input=source,
                capture_output=True,
                check=True,
                timeout=args.watchdog_seconds,
            )
            assert json.loads(validated.stdout) == {
                "status": "valid",
                "scope": "local-source-description-only",
            }
            rejected = subprocess.run(
                [str(executable), "recover", "--json"],
                capture_output=True,
                timeout=args.watchdog_seconds,
            )
            assert rejected.returncode == 2
    if args.component == "client":
        from fishhat_client.wire import frame, read_frame

        assert read_frame(io.BytesIO(frame({"test": True}))) == {"test": True}
    if args.component == "owner-support":
        from fishhat_owner.journal import Journal
        from fishhat_owner.migrations import upgrade

        with tempfile.TemporaryDirectory() as temporary:
            store = Journal(
                Path(temporary) / "journal.db", "fixture-owner", "fixture-epoch", initialize=True
            )
            assert store.generation == 0
            store.close()
            upgrade(Path(temporary) / "journal.db")
            reopened = Journal(Path(temporary) / "journal.db", "fixture-owner", "fixture-epoch")
            assert reopened.generation == 0
            reopened.close()
    if args.component == "reporting":
        from fishhat_reporting.migrations import upgrade as reporting_upgrade
        from fishhat_reporting.store import EventStore

        event = json.loads((args.fixtures / "tracking/event.json").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            reporting = EventStore(
                Path(temporary) / "index.db", event["domain_id"], "fixture-service", initialize=True
            )
            first, envelope = reporting.put(event, principal="fixture-reporter", scopes={"append"})
            repeated, _ = reporting.put(event, principal="fixture-reporter", scopes={"append"})
            assert first == 201 and repeated == 200 and envelope["event"] == event
            reporting.close()
            reporting_upgrade(Path(temporary) / "index.db")
            reopened_index = EventStore(
                Path(temporary) / "index.db", event["domain_id"], "fixture-service"
            )
            assert reopened_index.put(event, principal="reader", scopes={"append"})[0] == 200
            reopened_index.close()
    if args.component == "directory":
        from fishhat_directory.projection import load_directory, prepare_projection

        projection = prepare_projection(
            load_directory((args.fixtures / "directory/directory.yaml").read_text())
        )
        assert projection["catalogue"]["authority"].startswith("discovery-only")
    print(json.dumps({"component": args.component, "passed": True, "production_qualified": False}))


if __name__ == "__main__":
    main()
