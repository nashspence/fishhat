"""Strict data, local schema resolution and deterministic semantic reference checks.

No network access, source fetching, native execution or privileged path traversal is
performed here. Production code must add those separately qualified boundaries.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast
from urllib.parse import urldefrag, urljoin

import yaml
from jsonschema import Draft202012Validator, FormatChecker, validators
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from yaml.events import AliasEvent, DocumentStartEvent

from .bounds import Bounds, bounds
from .json_work import ordered_json, unique_items

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 1_048_576
FORMAT_CHECKER = FormatChecker()
RFC3339_TIME = re.compile(
    r"([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
    r"[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)"
    r"(?:\.[0-9]+)?([Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


@FORMAT_CHECKER.checks("date-time", raises=ValueError)
def _rfc3339_time(value: Any) -> bool:
    """Check RFC3339 grammar/calendar, without coercion or an IERS leap-second oracle."""
    if not isinstance(value, str):
        return True
    match = RFC3339_TIME.fullmatch(value)
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    # The Gregorian calendar repeats every 400 years. Use an equivalent safe
    # year so RFC3339's 0000..9999 range and offset shifts do not inherit
    # datetime's narrower year range. Fractional digits are never converted.
    point = datetime(2000 + year % 400, month, day, hour, minute, min(second, 59))
    if second != 60:
        return True
    zone = match[7]
    offset = 0 if zone in {"Z", "z"} else (int(zone[1:3]) * 60 + int(zone[4:6]))
    if zone.startswith("-"):
        offset = -offset
    utc = point - timedelta(minutes=offset)
    # Syntactic leap-second position only: the UTC end of a calendar month.
    # No dynamic insertion or negative-leap schedule is asserted here.
    return utc.hour == 23 and utc.minute == 59 and (utc + timedelta(seconds=1)).day == 1


class ContractError(ValueError):
    pass


def _data_bounds(name: str) -> Bounds:
    return Bounds(
        id="data." + name,
        work="O(B) complete JSON/source value bytes under the installed schema profile",
        extent="Complete values are validated or explicitly rejected; no truncated collections",
        limits=(),
        capacity=("JSON frame/source admission capacities remain explicit caller decisions",),
        proofs=("tests/test_export_growth.py::test_data_exports_linear_work",),
        linear_proofs=("tests/test_export_growth.py::test_data_exports_linear_work",),
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate key")
        result[key] = value
    return result


def value_check(value: Any, depth: int = 0) -> None:
    if depth > 64:
        raise ContractError("nesting exceeds 64")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > 9_007_199_254_740_991:
            raise ContractError("integer outside interoperable exact range")
        return
    if type(value) is str:
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ContractError("invalid Unicode surrogate")
        return
    if type(value) is list:
        for item in value:
            value_check(item, depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ContractError("object keys must be strings")
            value_check(key, depth + 1)
            value_check(item, depth + 1)
        return
    raise ContractError("non-JSON or floating point value")


@bounds(_data_bounds("canonical"))
def canonical(value: Any) -> bytes:
    value_check(value)
    return json.dumps(
        ordered_json(value), ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


@bounds(_data_bounds("digest"))
def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


@bounds(_data_bounds("strict_json"))
def strict_json(data: bytes | str, max_bytes: int = MAX_BYTES) -> Any:
    try:
        raw = data.encode("utf-8") if isinstance(data, str) else data
        if len(raw) > max_bytes:
            raise ContractError("input size limit")
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ContractError("nonfinite number")),
        )
        value_check(value)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractError("invalid bounded UTF-8 JSON") from exc


class SourceLoader(yaml.SafeLoader):
    """Reject duplicate keys; scalar restrictions are checked after parsing."""


# JSON-like scalar resolution; do not interpret yes/no, octal or timestamps as policy types.
SourceLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for char, rules in list(SourceLoader.yaml_implicit_resolvers.items()):
    SourceLoader.yaml_implicit_resolvers[char] = [
        (tag, regex)
        for tag, regex in rules
        if tag
        not in ("tag:yaml.org,2002:bool", "tag:yaml.org,2002:int", "tag:yaml.org,2002:timestamp")
    ]
SourceLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$"), list("tf")
)
SourceLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int", re.compile(r"^(?:0|-?[1-9][0-9]*)$"), list("-0123456789")
)


def _mapping(loader: SourceLoader, node: Any, deep: bool = False) -> dict[str, Any]:
    pairs = []
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if type(key) is not str or key == "<<":
            raise ContractError("complex/nonstring/merge key")
        pairs.append((key, loader.construct_object(value_node, deep=deep)))
    return _pairs(pairs)


SourceLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


@bounds(_data_bounds("strict_yaml"))
def strict_yaml(data: str, *, capacity_bytes: int | None = None) -> Any:
    """Parse a whole source document; a wire-frame limit is not a source extent limit.

    A receiving owner must enforce its independently approved memory/byte capacity
    before accepting or applying a document. Refusal is explicit, never truncation.
    """
    if capacity_bytes is not None:
        if type(capacity_bytes) is not int or capacity_bytes < 1:
            raise ContractError("invalid source capacity")
        if len(data.encode("utf-8")) > capacity_bytes:
            raise ContractError("source capacity exceeded")
    try:
        for event in yaml.parse(data):
            if isinstance(event, DocumentStartEvent) and (event.version is not None or event.tags):
                raise ContractError("YAML directives not permitted")
            if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
                raise ContractError("anchors/aliases not permitted")
            if getattr(event, "tag", None) is not None:
                raise ContractError("explicit tags not permitted")
        docs = list(yaml.load_all(data, Loader=SourceLoader))
        if len(docs) != 1:
            raise ContractError("one source document required")
        value_check(docs[0])
        return docs[0]
    except (yaml.YAMLError, RecursionError) as exc:
        raise ContractError("invalid source YAML") from exc


SCHEMAS = {p.name: json.loads(p.read_text()) for p in (ROOT / "contracts").glob("*.schema.json")}
REGISTRY = Registry().with_resources(
    # The installed dialect is fixed. Keep its declaration in SCHEMAS and its
    # published bytes; omit it only from evaluation resources so $ref evolution
    # retains our uniqueness validator instead of selecting the stock class.
    (
        d["$id"],
        Resource.from_contents(
            {key: value for key, value in d.items() if key != "$schema"},
            default_specification=DRAFT202012,
        ),
    )
    for d in SCHEMAS.values()
)

_SCHEMA_VALIDATOR = cast(Any, validators.extend)(
    Draft202012Validator, {"uniqueItems": unique_items}
)


@bounds(_data_bounds("validate"))
def validate(schema: str, value: Any, definition: str | None = None) -> None:
    value_check(value)
    base = SCHEMAS[schema]
    target = base if definition is None else {"$ref": base["$id"] + "#/$defs/" + definition}
    errors = list(
        _SCHEMA_VALIDATOR(target, registry=REGISTRY, format_checker=FORMAT_CHECKER).iter_errors(
            value
        )
    )
    if errors:
        # Do not put source values/secret sentinels into ordinary errors.
        raise ContractError(
            f"schema {schema} rejected input at " + "/".join(map(str, errors[0].absolute_path))
        )


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ContractError(code)


def validate_domain(
    domain: dict[str, Any], host_sources: dict[str, dict[str, Any]] | None = None
) -> None:
    validate("source.schema.json", domain)
    _require(domain["kind"] == "Domain", "expected domain")
    seen = set()
    for host_id, host in domain["hosts"].items():
        _require(host["source"] in domain["sources"], "unknown host source")
        source = domain["sources"][host["source"]]
        repo = source["repository"]
        # Repository custody is independent of machine identity. Several hosts may
        # share a repository, but aliases or mutable refs cannot duplicate a source.
        identity = repo["instance"], repo["repository_id"], source["entrypoint"]
        _require(identity not in seen, "duplicate canonical host source")
        seen.add(identity)
        if host_sources is not None:
            _require(
                host_id in host_sources and host_sources[host_id]["id"] == host_id,
                "host source identity mismatch",
            )
        if host["wake_relay"] is not None:
            _require(host["wake_relay"] in domain["hosts"], "unknown wake relay")
    for app in domain["apps"].values():
        _require(app["source"] in domain["sources"], "unknown app source")
        _require(app["host"] in domain["hosts"], "unknown app host")
    for provider in list(domain["providers"].values()) + list(domain["backup_backends"].values()):
        _require(provider["custodian_host"] in domain["hosts"], "unknown custodian host")


def _source_target(value: str) -> str:
    """Require one lexical absolute spelling without traversing the native filesystem."""
    _require(
        value.startswith("/") and all(part not in ("", ".", "..") for part in value[1:].split("/")),
        "noncanonical source target",
    )
    return value


def _validate_host_concerns(host: dict[str, Any], catalogue: dict[str, Any] | None) -> None:
    services: set[str] = set()
    units: set[bytes] = set()
    destinations: set[str] = set()
    packages: set[bytes] = set()
    membership_users: set[str] = set()
    for concern in host["concerns"].values():
        for key, service in concern["services"].items():
            _require(key not in services, "duplicate service binding")
            services.add(key)
            identity = _host_target_selection(host, service, "service")
            _require(identity not in units, "duplicate native service target")
            units.add(identity)
    for concern in host["concerns"].values():
        for kind in ("files", "secret_files", "artifacts"):
            for entry in concern[kind].values():
                target = _source_target(entry["destination"])
                _require(target not in destinations, "destination collision")
                destinations.add(target)
                if kind == "artifacts":
                    continue
                for note in entry["notify"]:
                    _require(note["service"] in services, "unknown notification service")
                if kind == "secret_files":
                    if host["repository_secrets"] is None or catalogue is None:
                        raise ContractError("missing secret catalogue")
                    _require(entry["entry"] in catalogue["entries"], "unknown host secret entry")
        for pkg in concern["packages"].values():
            identity = _host_target_selection(host, pkg, "software")
            _require(identity not in packages, "duplicate package target")
            packages.add(identity)
        for membership in concern["groups"].values():
            user = membership["user"]
            _require(user not in membership_users, "duplicate group membership target")
            membership_users.add(user)


def _host_target_selection(host: dict[str, Any], value: dict[str, Any], role: str) -> bytes:
    """Join source declarations only; approved native mappings remain with the receiver."""
    selection, scope = value["adapter"], value["scope"]
    instance = host["adapter_instances"].get(selection["instance"])
    _require(instance is not None and instance["role"] == role, "unknown host target adapter")
    assert instance is not None
    _require(
        any(
            grant["scope"] == scope and "observe" in grant["access"] for grant in instance["grants"]
        ),
        "host target scope not granted",
    )
    return canonical([selection["instance"], selection["source"]])


def validate_host(host: dict[str, Any], catalogue: dict[str, Any] | None = None) -> None:
    validate("source.schema.json", host)
    _require(host["kind"] == "Host", "expected host")
    if catalogue is not None:
        _validate_secret_catalogue(catalogue)
    _validate_host_concerns(host, catalogue)
    for key, instance in host["adapter_instances"].items():
        _require(key == instance["id"], "adapter instance identity mismatch")
    for app_id, account in host["app_accounts"].items():
        instance = host["adapter_instances"].get(account["runtime_instance"])
        _require(instance is not None and instance["role"] == "runtime", "unknown runtime instance")
        assert instance is not None
        _require(
            any(
                g["scope"]["kind"] == "application" and g["scope"]["handle"] == app_id
                for g in instance["grants"]
            ),
            "runtime instance lacks application scope",
        )
    for grant in host["grants"].values():
        _require(grant["app"] in host["app_accounts"], "grant for unknown app account")
    from fishhat_contracts.resources import validate_host_resources

    validate_host_resources(host)


def _validate_secret_catalogue(catalogue: dict[str, Any]) -> None:
    """Validate declarations; the receiving owner separately resolves the approved source."""
    validate("source.schema.json", catalogue)
    _require(catalogue["kind"] == "RepoSecrets", "expected secret catalogue")


def _validate_datasets(app: dict[str, Any]) -> None:
    """Check declared custody and recovery procedures, without executing them.

    A rebuild declaration does not authorize deletion or establish that data can
    actually be reconstructed. Native admission and recovery retain those duties.
    """
    components, hooks, datasets = app["components"], app["hooks"], app["datasets"]
    procedures = {
        "preserve": (
            ("capture", "capture", "read"),
            ("restore", "restore", "write"),
            ("verify_restore", "verify-restore", "read"),
        ),
        "rebuild": (
            ("rebuild", "rebuild", "write"),
            ("verify_rebuild", "verify-rebuild", "read"),
        ),
    }
    preserved = False
    for dataset_id, dataset in datasets.items():
        _require(
            set(dataset["writers"] + dataset["readers"]) <= set(components),
            "unknown data consumer",
        )
        if dataset["custody"] == "reference":
            _require(
                dataset["owner"] != {"kind": "app", "id": app["id"]},
                "reference dataset cannot name this app as its owner",
            )
            continue
        policy = dataset["recovery"]
        preserved = preserved or policy == "preserve"
        for field, role, mode in procedures[policy]:
            hook = hooks.get(dataset[field])
            _require(
                hook is not None and hook["role"] == role and hook["mode"] == mode,
                "missing/wrong dataset recovery procedure",
            )
            assert hook is not None
            _require(dataset_id in hook["datasets"], "recovery procedure omits its dataset")
    _require(
        not preserved or app["lifecycle"]["checkpoint_policy"] != "stateless",
        "preserved app data is incompatible with a stateless checkpoint policy",
    )
    recovery_roles = {
        role: policy for policy, entries in procedures.items() for _, role, _ in entries
    }
    for hook in hooks.values():
        if hook["role"] not in recovery_roles:
            continue
        for dataset_id in hook["datasets"]:
            dataset = datasets.get(dataset_id)
            _require(dataset is not None, "unknown hook dataset")
            assert dataset is not None
            _require(
                dataset["custody"] == "app" and dataset["recovery"] == recovery_roles[hook["role"]],
                "recovery hook crosses dataset custody or recovery policy",
            )


def validate_app(app: dict[str, Any], catalogue: dict[str, Any] | None = None) -> None:
    validate("source.schema.json", app)
    _require(app["kind"] == "App", "expected app")
    if catalogue is not None:
        _validate_secret_catalogue(catalogue)
    components, hooks, datasets = app["components"], app["hooks"], app["datasets"]
    _require(any(x["role"] == "primary" for x in components.values()), "primary component required")
    units = [canonical(x["native"]) for x in components.values()]
    _require(len(set(units)) == len(units), "duplicate native component selector")
    for entry in app["interfaces"].values():
        _require(entry["component"] in components, "unknown interface component")
        _require(components[entry["component"]]["role"] == "primary", "nonprimary export")
        _require(entry["readiness_hook"] in hooks, "unknown interface readiness")
        readiness = hooks[entry["readiness_hook"]]
        _require(
            readiness["role"] == "health" and readiness["mode"] == "read",
            "interface readiness requires read-only health hook",
        )
    for dependency in app["dependencies"].values():
        _require(set(dependency["consumers"]) <= set(components), "unknown dependency consumer")
    _validate_datasets(app)
    secret_targets: set[tuple[str, str]] = set()
    for binding in app["secret_bindings"].values():
        if app["repository_secrets"] is None or catalogue is None:
            raise ContractError("missing secret catalogue")
        _require(binding["entry"] in catalogue["entries"], "unknown secret entry")
        _require(binding["component"] in components, "unknown secret consumer")
        target = binding["component"], _source_target(binding["target"])
        _require(target not in secret_targets, "secret delivery target collision")
        secret_targets.add(target)
    for hook in hooks.values():
        _require(hook["component"] in components, "unknown hook executor")
        _require(set(hook["datasets"]) <= set(datasets), "unknown hook dataset")
        _require(set(hook["secrets"]) <= set(app["secret_bindings"]), "unknown hook secret binding")
        for binding_id in hook["secrets"]:
            _require(
                app["secret_bindings"][binding_id]["component"] == hook["component"],
                "hook borrows another components secret",
            )
    expected = {
        "health": "health",
        "configure": "configure",
        "verify_config": "verify-config",
        "quiesce": "quiesce",
        "transition_assess": "transition-assess",
        "transition_apply": "transition-apply",
        "transition_verify": "transition-verify",
    }
    for field, role in expected.items():
        names = app["lifecycle"][field]
        names = names if isinstance(names, list) else ([] if names is None else [names])
        for name in names:
            _require(name in hooks and hooks[name]["role"] == role, "missing/wrong lifecycle hook")
    for task in app["maintenance"].values():
        if task["action"] == "native-maintenance":
            _require(task["hook"] in hooks, "unknown maintenance hook")
    from fishhat_contracts.resources import validate_requirements

    validate_requirements(app["resources"], app=app)


def require_acyclic(edges: dict[str, list[str]]) -> None:
    active: set[str] = set()
    done: set[str] = set()

    def visit(node: str) -> None:
        if node in active:
            raise ContractError("hard dependency cycle")
        if node in done:
            return
        active.add(node)
        for dep in edges.get(node, []):
            _require(dep in edges, "unknown graph prerequisite")
            visit(dep)
        active.remove(node)
        done.add(node)

    for node in edges:
        visit(node)


def validate_cli(
    value: dict[str, Any],
    *,
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Validate a CLI envelope using independently installed historical readers.

    The registry is trusted receiving context; an envelope cannot supply it. Old
    records remain read-only references and cannot assert fresh execution success.
    """
    validate("cli-output.schema.json", value)
    if value["ok"] != (value["problem"] is None):
        raise ContractError("CLI success/problem mismatch")
    state = value["state"]
    unsuccessful = {"failed", "cancelled", "quarantined", "rejected", "unknown"}
    if value["ok"] != (state not in unsuccessful):
        raise ContractError("CLI outcome/success mismatch")
    terminal = {
        "observed",
        "planned",
        "succeeded",
        "failed",
        "cancelled",
        "quarantined",
        "rejected",
    }
    if value["complete"] != (state in terminal):
        raise ContractError("CLI outcome/completion mismatch")

    result = value["result"]
    from .handoffs import validate_cli_result

    validate_cli_result(
        result, retained_readers=retained_readers, recovery_readers=recovery_readers
    )
    if value["problem"] is not None:
        from .record_delivery import validate_problem

        validate_problem(value["problem"], retained_readers=retained_readers)
    operation = result if isinstance(result, dict) and result.get("kind") == "Operation" else None
    owner_states = {
        "accepted",
        "running",
        "waiting",
        "succeeded",
        "failed",
        "cancelled",
        "quarantined",
    }
    if state in owner_states and operation is None:
        raise ContractError("execution outcome requires owner Operation")
    if state == "planned" and (not isinstance(result, dict) or result.get("kind") != "Plan"):
        raise ContractError("planned outcome requires Plan")
    if isinstance(result, dict) and result.get("kind") == "Plan":
        _require(state == "planned", "CLI plan must be presented for review")
        validate_plan(result)
    if state == "observed" and result is None:
        raise ContractError("observed outcome requires result")
    if operation is not None:
        _require(state == operation["state"], "CLI/owner execution state mismatch")
        _require(value["request_id"] == operation["request_id"], "CLI/owner request mismatch")
        if value["problem"] is not None:
            _require(
                value["problem"]["owner"] == operation["owner"]
                and value["problem"]["resource"] == operation["subject"]["resource"],
                "CLI problem/operation identity mismatch",
            )

    delivery = value.get("delivery")
    if delivery is not None:
        _require(value["request_id"] == delivery["request_id"], "CLI/delivery request mismatch")
        if value["problem"] is not None:
            _require(
                value["problem"]["owner"] == delivery["owner"]
                and value["problem"]["resource"] == delivery["resource"],
                "CLI problem/delivery identity mismatch",
            )
        if operation is not None:
            _require(
                delivery["state"] == "accepted"
                and delivery["owner"] == operation["owner"]
                and delivery["plan_digest"] == operation["plan_digest"]
                and delivery["subject_digest"] == digest(operation["subject"])
                and delivery["action"] == operation["subject"]["action"]
                and delivery["resource"] == operation["subject"]["resource"],
                "CLI/delivery acceptance binding mismatch",
            )
        else:
            _require(
                (delivery["state"], state)
                in {
                    ("prepared", "planned"),
                    ("prepared", "paused"),
                    ("acceptance_unknown", "unknown"),
                    ("rejected", "rejected"),
                },
                "CLI/delivery acceptance state mismatch",
            )
    if value["problem"] is not None and value["problem"]["code"] == "ACCEPTANCE_UNKNOWN":
        _require(
            state == "unknown" and operation is None and value["request_id"] is not None,
            "unknown acceptance requires original request and no owner outcome",
        )


def _material_digests(value: Any, schema: Any, base: str) -> set[str]:
    """Follow only installed schema positions to find semantically typed inputs.

    Literal data in enum, const, examples and defaults never declares custody.
    The subject is already schema-valid; only applicable union branches count.
    """
    if not isinstance(schema, dict):
        return set()
    found: set[str] = set()
    if "$ref" in schema:
        target = urljoin(base, schema["$ref"])
        material = SCHEMAS["common.schema.json"]["$id"] + "#/$defs/MaterialDigest"
        if target == material:
            return {value} if isinstance(value, str) else set()
        resolved = REGISTRY.resolver(base_uri=base).lookup(schema["$ref"])
        found.update(_material_digests(value, resolved.contents, urldefrag(target)[0]))
    if isinstance(value, dict):
        for key, child in schema.get("properties", {}).items():
            if key in value:
                found.update(_material_digests(value[key], child, base))
    if isinstance(value, list) and "items" in schema:
        for child in value:
            found.update(_material_digests(child, schema["items"], base))
    for keyword in ("allOf", "anyOf", "oneOf"):
        for child in schema.get(keyword, []):
            validator = Draft202012Validator(
                REGISTRY.resolver().lookup(base).contents,
                registry=REGISTRY,
                format_checker=FORMAT_CHECKER,
            ).evolve(schema=child)
            if validator.is_valid(value):
                found.update(_material_digests(value, child, base))
    return found


def validate_plan(value: dict[str, Any]) -> None:
    validate("records.schema.json", value, "Plan")
    if value["subject"]["action"] == "publisher.publish":
        from .publication import validate_publication_intent

        arguments = value["subject"]["arguments"]
        validate_publication_intent(
            source=arguments["source"],
            entry=arguments["entry"],
            version=arguments["version"],
            expected_previous=arguments["expected_previous"],
        )
    expected = digest({k: v for k, v in value.items() if k not in ("digest", "witness")})
    if value["digest"] != expected or value["witness"]["subject_digest"] != expected:
        raise ContractError("plan digest mismatch")
    if value["witness"]["owner"] != value["owner"] or value["witness"]["kind"] != "plan":
        raise ContractError("plan witness mismatch")
    steps = [v["step"] for v in value["effects"]]
    if len(set(steps)) != len(steps):
        raise ContractError("duplicate effect step")
    # Bind the administrator-visible scope to the exact owner/resource checks.
    # These finite sets avoid rescanning every precondition for every effect.
    preconditions = {
        canonical([item["owner"], item["resource"]]) for item in value["preconditions"]
    }
    if len(preconditions) != len(value["preconditions"]):
        raise ContractError("duplicate resource precondition")
    if canonical([value["owner"], value["subject"]["resource"]]) not in preconditions:
        raise ContractError("subject lacks resource precondition")
    inputs = set(value["input_digests"])
    actions = SCHEMAS["actions.schema.json"]
    arguments = actions["$defs"][value["subject"]["action"]]
    if not _material_digests(value["subject"]["arguments"], arguments, actions["$id"]) <= inputs:
        raise ContractError("subject material input outside reviewed plan")
    from .history import validate_recovery_plan_origin

    validate_recovery_plan_origin(value)
    for effect in value["effects"]:
        if canonical([effect["executor"], effect["resource"]]) not in preconditions:
            raise ContractError("effect lacks resource precondition")
        if effect["input_digest"] not in inputs:
            raise ContractError("effect input outside reviewed plan")
    from .live_change import validate_host_preimages

    validate_host_preimages(value)
    if "none-needed" in value["recovery"] and len(value["recovery"]) != 1:
        raise ContractError("conflicting recovery procedures")
    if datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")) <= datetime.fromisoformat(
        value["created_at"].replace("Z", "+00:00")
    ):
        raise ContractError("plan expiry not after creation")
