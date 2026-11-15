from __future__ import annotations

import argparse
import copy
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
from collections.abc import Callable
from pathlib import Path


def check_source_validation(
    command: list[str],
    tool: str,
    fixtures: Path,
    run: Callable[[list[str], Path], subprocess.CompletedProcess[str]],
) -> dict[str, object]:
    """Witness the installed read-only boundary, without asserting owner admission."""
    from fishhat_contracts import strict_yaml

    paths = {
        "domain": fixtures / "domain/domain.yaml",
        "host": fixtures / "host-node-a/host.yaml",
        "app": fixtures / "demo-app/app.yaml",
        "host-catalogue": fixtures / "host-node-a/secrets.yaml",
        "app-catalogue": fixtures / "demo-app/secrets.yaml",
    }
    original = {name: path.read_bytes() for name, path in paths.items()}
    values = {name: strict_yaml(data.decode()) for name, data in original.items()}
    domain, host, app = (values[name] for name in ("domain", "host", "app"))
    cases: list[tuple[str, str, str | None, bool, list[str]]] = [
        ("domain", json.dumps(domain), None, True, []),
        ("host", json.dumps(host), "host-catalogue", True, []),
        ("app", json.dumps(app), "app-catalogue", True, []),
        ("catalogue", json.dumps(values["app-catalogue"]), None, True, []),
        ("duplicate-key", '{"kind":"Domain",' + json.dumps(domain)[1:], None, False, []),
    ]
    unknown = {**domain, "SYNTHETIC_PRIVATE_SENTINEL": "not-a-source-field"}
    cases.append(("unknown-field", json.dumps(unknown), None, False, []))
    unjoined = copy.deepcopy(domain)
    next(iter(unjoined["hosts"].values()))["source"] = "unbound-source"
    cases.append(("domain-source-join", json.dumps(unjoined), None, False, []))
    yaml_alias = json.dumps(domain).replace('"id": "', '"id": &blocked "', 1)
    yaml_alias = yaml_alias.replace('"name": ' + json.dumps(domain["name"]), '"name": *blocked', 1)
    cases.extend(
        [
            ("duplicate-yaml-key", "kind: Domain\n" + original["domain"].decode(), None, False, []),
            ("yaml-alias", yaml_alias, None, False, []),
        ]
    )
    absent_entry = {**values["host-catalogue"], "entries": {}}
    app_absent_entry = {**values["app-catalogue"], "entries": {}}
    escaped = copy.deepcopy(host)
    escaped["concerns"]["base"]["files"]["motd"]["destination"] = (
        "/etc/../SYNTHETIC_PRIVATE_SENTINEL"
    )
    shell = copy.deepcopy(app)
    shell["hooks"]["health"]["shell"] = "SYNTHETIC_PRIVATE_SENTINEL"
    executor = copy.deepcopy(app)
    executor["hooks"]["health"]["component"] = "unbound-component"
    secret_value = copy.deepcopy(values["app-catalogue"])
    next(iter(secret_value["entries"].values()))["value"] = "SYNTHETIC_PRIVATE_SENTINEL"
    cases.extend(
        [
            ("host-catalogue-entry", json.dumps(host), "missing-host-entry", False, []),
            ("app-catalogue-entry", json.dumps(app), "missing-app-entry", False, []),
            ("host-missing-catalogue", json.dumps(host), None, False, []),
            ("app-missing-catalogue", json.dumps(app), None, False, []),
            ("host-catalogue-type", json.dumps(host), "domain", False, []),
            ("escaping-target", json.dumps(escaped), "host-catalogue", False, []),
            ("unsupported-hook-grammar", json.dumps(shell), "app-catalogue", False, []),
            ("hook-executor", json.dumps(executor), "app-catalogue", False, []),
            ("secret-value", json.dumps(secret_value), None, False, []),
            ("explicit-capacity", json.dumps(domain), None, False, ["--capacity-bytes", "128"]),
        ]
    )
    with tempfile.TemporaryDirectory(prefix="fishhat-source-intake-") as temporary:
        root = Path(temporary)
        canary = root / "unrelated-canary"
        canary.write_bytes(b"unrelated-input-preserved")
        catalogues = {
            **{name: json.dumps(value) for name, value in values.items()},
            "missing-host-entry": json.dumps(absent_entry),
            "missing-app-entry": json.dumps(app_absent_entry),
        }
        for name, content, catalogue, valid, extra in cases:
            suffix = ".yaml" if name in {"duplicate-yaml-key", "yaml-alias"} else ".json"
            path = root / ("SYNTHETIC_PRIVATE_SOURCE-" + name + suffix)
            path.write_bytes(content.encode())
            args = [*command, "validate", str(path), "--json", *extra]
            expected_inputs = {path: content.encode()}
            if catalogue is not None:
                cat_path = root / "SYNTHETIC_PRIVATE_CATALOGUE.json"
                cat_bytes = catalogues[catalogue].encode()
                cat_path.write_bytes(cat_bytes)
                expected_inputs[cat_path] = cat_bytes
                args.extend(["--catalogue", str(cat_path)])
            result = run(args, root)
            expected = (
                {
                    "tool": tool,
                    "status": "valid",
                    "scope": "local-contracts-only",
                    "production_qualified": False,
                }
                if valid
                else {"tool": tool, "status": "invalid", "error": "INPUT_REJECTED"}
            )
            try:
                observed = json.loads(result.stdout if valid else result.stderr)
            except (ValueError, TypeError):
                raise AssertionError("installed source witness failed: " + name) from None
            if (
                result.returncode != (0 if valid else 2)
                or observed != expected
                or (result.stderr if valid else result.stdout)
            ):
                raise AssertionError("installed source witness failed: " + name)
            if any(
                not p.is_file() or p.read_bytes() != data for p, data in expected_inputs.items()
            ):
                raise AssertionError("installed source witness failed: input-custody")
            if not canary.is_file() or canary.read_bytes() != b"unrelated-input-preserved":
                raise AssertionError("installed source witness failed: canary-custody")
    if any(path.read_bytes() != original[name] for name, path in paths.items()):
        raise AssertionError("installed source witness failed: fixture-custody")
    return {
        "scope": "installed-local-contract-validation-only",
        "tool": tool,
        "valid_cases": 4,
        "invalid_cases": len(cases) - 4,
        "input_bytes_preserved": True,
        "unrelated_canary_preserved": True,
        "native_qualified": False,
    }


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
    source_validation: dict[str, object] | None = None
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
        source_validation = check_source_validation(
            [str(executable)],
            tool,
            args.fixtures,
            lambda command, cwd: subprocess.run(
                command, cwd=cwd, capture_output=True, text=True, timeout=args.watchdog_seconds
            ),
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
            try:
                first, ack = reporting.put(event, principal="fixture-reporter", scopes={"append"})
                repeated, duplicate = reporting.put(
                    event, principal="another-reporter", scopes={"append"}
                )
                assert first == 201 and repeated == 200
                validate("tracking-records.schema.json", ack, "AppendAcknowledgment")
                assert (
                    ack
                    == duplicate
                    == {
                        "format": "deployment-ops/index-append-ack/v1",
                        "workflow_id": event["workflow_id"],
                        "event_id": event["id"],
                        "content_digest": digest(event),
                    }
                )
                envelope = reporting.get(
                    event["workflow_id"], event["id"], principal="reader", scopes={"read"}
                )
                assert envelope is not None and envelope["event"] == event
                assert envelope["reporter"] == "fixture-reporter"
            finally:
                reporting.close()
            reporting_upgrade(Path(temporary) / "index.db")
            reopened_index = EventStore(
                Path(temporary) / "index.db", event["domain_id"], "fixture-service"
            )
            try:
                status, envelope = reopened_index.put(
                    event, principal="reader", scopes={"append", "read"}
                )
                assert status == 200 and envelope["event"] == event
                assert envelope["reporter"] == "fixture-reporter"
            finally:
                reopened_index.close()
    if args.component == "directory":
        from fishhat_directory.projection import load_directory, prepare_projection

        projection = prepare_projection(
            load_directory((args.fixtures / "directory/directory.yaml").read_text())
        )
        assert projection["catalogue"]["authority"].startswith("discovery-only")
    result_summary: dict[str, object] = {
        "component": args.component,
        "passed": True,
        "production_qualified": False,
    }
    if source_validation is not None:
        result_summary["source_validation"] = source_validation
    print(json.dumps(result_summary))


if __name__ == "__main__":
    main()
