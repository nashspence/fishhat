"""Pure, bounded discovery projection. No server, SSH, network probes or mutations."""

from __future__ import annotations

import copy
import datetime as dt
import html
import ipaddress
import re
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml
from fishhat_contracts.bounds import Bounds, bounds
from fishhat_contracts.validation import (
    SCHEMAS,
    ContractError,
    canonical,
    strict_yaml,
    validate,
)

AUTHORITY = "discovery-only; independently authenticate source and owner SSH"
NOW = dt.datetime(2026, 10, 18, 12, tzinfo=dt.UTC)
WORKFLOWS = {
    "start": [
        "Use the advertised tools and domain repositories as hints; independently verify source identity and enrolled SSH host trust. Forgejo API/Git access is not owner SSH authority.",
        "Retrieve both sources in a private task workspace; use an independently verified native installation bundle and a new user-level Python virtual environment. Do not run sudo pip or require a container engine.",
        "Select the domain directory and your reviewed SSH configuration explicitly. Do not automatically execute repository SSH ProxyCommand or Match directives.",
        "Run domain-ops --domain <domain-path> info --json and then status. Local info does not prove remote permissions; receiving host-ops/app-ops authorize each operation.",
        "Inspect, test, plan and confirm before mutations. Local owners retain accepted work; Forgejo Issues and optional reference reports are nonblocking conveniences. No directory tool performs these steps.",
    ],
    "test-domain": [
        "Select the exact domain source snapshot and qualified test lock; use a separate test virtual environment. Missing dependencies are preparation blockers, not automatic installs.",
        "Run domain-ops --domain <domain-path> test --offline --json by default. Explicitly select a worktree to test edited inputs.",
        "Use live observations only with enrolled SSH authority. Mutating suites require an explicit finite target set and normal owner plans and confirmations.",
        "Record actual executed/skipped coverage, source/runtime digests and child request identities. A venv or offline label is not malicious-code isolation.",
    ],
    "plan-change": [
        "Inspect the independently authenticated native owner, its epoch, accepted source and active holds for the finite intended resources.",
        "Prepare a source/image/secret-pinned plan with checkpoint, interruption and recovery consequences. A source commit or test pass is not deployment approval.",
        "Allocate the owner/epoch/request identity once before submission and reuse it after uncertainty. No client file or tracker write is required; the owner durably accepts the reviewed plan before effects.",
        "A timeout means uncertain acceptance. Do not replay under another request ID or endpoint just because a command returned an SSH error.",
    ],
    "resume": [
        "Find the original owner ID, owner-store epoch and request ID in optional receipt references or authorized owner operation listings.",
        "Import preserved records as evidence, not bearer authorization. Reauthenticate to the original owner using independently trusted SSH configuration.",
        "Query the same request and reconcile its accepted or uncertain effects. A changed epoch or missing source requires recovery, not assumed non-execution.",
        "Resume a cross-owner workflow only with explicit participant evidence and authorized driver transfer; do not automatically execute imported work.",
    ],
    "recover": [
        "Use independently retained source bundles or the pinned public Forgejo/restic bootstrap to recover fishhat and the domain repository into fresh private staging.",
        "The bootstrap helper restores Git only. Obtain the native Python/tool/dependency bundle from its separately recorded backup path; verify it before local installation.",
        "If source or installation is unavailable, use ordinary SSH to an independently enrolled surviving host-ops/app-ops endpoint for bounded direct inspection and recovery. Destroyed hosts need replacement provisioning.",
        "Keep Git-source recovery distinct from Forgejo database/attachments, encrypted secret generations, app datasets and native issuer recovery. No current directory is required.",
    ],
    "cleanup": [
        "Stop local writers and account for every branch, stash, staged/dirty/untracked file and linked worktree. Commit and checked push do not prove all other work was preserved.",
        "Publish, retain or export required source and test-work obligations outside the task tree. Git bundles alone do not contain unfinished files. Optional receipt-only reporting is not a cleanup prerequisite.",
        "Inspect accepted or uncertain work at the actual owners when necessary. Retaining original request references is useful, but missing tracking alone does not block cleanup or cancel an operation.",
        "Run workspace close --plan, then recheck with --apply. The initial close command records closure but never recursively deletes files. Remove only the explicitly verified disposable paths afterward. Missing optional tracking produces a warning, not a deletion veto.",
    ],
}


def _text(value: object) -> str:
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ContractError("invalid directory text")
    return value


def host(value: str) -> str:
    _text(value)
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if len(value) > 253 or not all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p) for p in value.split(".")
    ):
        raise ContractError("invalid host")
    return value


def url(value: str, *, clone: bool = False) -> str:
    _text(value)
    try:
        p = urlsplit(value)
        port = p.port
    except ValueError as e:
        raise ContractError("invalid URL") from e
    if (
        p.scheme not in (("ssh", "https") if clone else ("https",))
        or not p.hostname
        or p.password
        or p.query
        or p.fragment
    ):
        raise ContractError("invalid source URL")
    if p.scheme == "https" and p.username:
        raise ContractError("URL credentials forbidden")
    if p.username and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", p.username):
        raise ContractError("invalid SSH URL user")
    host(p.hostname)
    if port is not None and not (1 <= port <= 65535):
        raise ContractError("invalid URL port")
    path = unquote(p.path)
    if (
        not path.startswith("/")
        or any(x in (".", "..") for x in path.split("/"))
        or "//" in path
        or any(c in path for c in "`$;&|<>\\\n\r\x00")
    ):
        raise ContractError("unsafe source URL path")
    return value


def validate_directory(v: dict[str, Any]) -> dict[str, Any]:
    validate("directory.schema.json", v)
    host(v["domain_name"])
    _text(v["display_name"])
    _text(v["recovery_hint"])
    if set(x["id"] for x in v["repositories"]) != {"fishhat", "domain"}:
        raise ContractError("two distinct source hints required")
    for r in v["repositories"]:
        url(r["clone_url"], clone=True)
        url(r["documentation_url"])
        if (
            ".." in r["ref_hint"]
            or "@{" in r["ref_hint"]
            or any(c in r["ref_hint"] for c in "\\~^:?*[")
            or r["ref_hint"].endswith(("/", ".", ".lock"))
        ):
            raise ContractError("invalid ref hint")
    ids = set()
    for e in v["owner_endpoints"]:
        if e["id"] in ids:
            raise ContractError("duplicate owner endpoint ID")
        ids.add(e["id"])
        host(e["host"])
        for name in ("ssh_alias", "trust_profile"):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", e[name]):
                raise ContractError("unsafe endpoint label")
    return v


@bounds(
    Bounds(
        id="directory.load",
        linear_proofs=("tests/test_linear_growth.py::test_directory_linear_work",),
        work="O(input_bytes)-bounded-parser-depth",
        extent="complete-document-or-rejection",
        limits=(("input_bytes", 65536), ("nesting", 16)),
        capacity=(),
        proofs=(
            "tests/test_engineering.py::test_directory_capacity_is_rejection_not_silent_truncation",
        ),
    )
)
def load_directory(text: str) -> dict[str, Any]:
    if len(text.encode()) > 65536:
        raise ContractError("directory input limit")
    depth = 0
    try:
        for event in yaml.parse(text):
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                depth += 1
                if depth > 16:
                    raise ContractError("directory nesting limit")
            elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                depth -= 1
    except yaml.YAMLError as e:
        raise ContractError("invalid directory YAML") from e
    return validate_directory(strict_yaml(text))


def validate_runtime(v: dict[str, Any]) -> dict[str, Any]:
    validate("directory-runtime.schema.json", v)
    for b in v["bind_addresses"]:
        try:
            a = ipaddress.ip_address(b)
        except ValueError as e:
            raise ContractError("listener must be explicit IP") from e
        if a.is_unspecified or a.is_multicast:
            raise ContractError("wildcard/multicast listener forbidden")
    nets = []
    for c in v["allowed_cidrs"]:
        try:
            n = ipaddress.ip_network(c, strict=True)
        except ValueError as e:
            raise ContractError("invalid network") from e
        if n.prefixlen == 0 or n.is_multicast:
            raise ContractError("unbounded admitted network")
        nets.append(n)
    for b in v["bind_addresses"]:
        if not any(ipaddress.ip_address(b) in n for n in nets):
            raise ContractError("listener outside approved network")
    for h in v["allowed_hosts"]:
        if "*" in h or any(c in h for c in "/@?#"):
            raise ContractError("invalid allowed Host")
        try:
            p = urlsplit("https://" + h)
            port = p.port
        except ValueError as e:
            raise ContractError("invalid allowed Host") from e
        host(p.hostname or "")
        if port is not None and port != v["port"]:
            raise ContractError("Host port mismatch")
    for o in v["allowed_origins"]:
        p = urlsplit(o)
        if (
            p.scheme != "https"
            or p.netloc not in v["allowed_hosts"]
            or p.path
            or p.query
            or p.fragment
        ):
            raise ContractError("invalid allowed Origin")
    return v


def allowed_request(
    runtime: dict[str, Any], *, remote_ip: str, host_header: str, origin: str | None = None
) -> bool:
    validate_runtime(runtime)
    try:
        address = ipaddress.ip_address(remote_ip)
    except ValueError:
        return False
    return (
        any(address in ipaddress.ip_network(n) for n in runtime["allowed_cidrs"])
        and host_header in runtime["allowed_hosts"]
        and (origin is None or origin in runtime["allowed_origins"])
    )


def catalogue(v: dict[str, Any], now: dt.datetime = NOW) -> dict[str, Any]:
    validate_directory(v)
    if now.tzinfo is None:
        raise ContractError("timezone required")
    at = dt.datetime.fromisoformat(v["published_at"].replace("Z", "+00:00"))
    age = (now - at).total_seconds()
    out = {
        k: copy.deepcopy(v[k])
        for k in (
            "domain_id",
            "domain_name",
            "display_name",
            "generation",
            "published_at",
            "repositories",
            "owner_endpoints",
            "recovery_hint",
        )
    }
    out.update(
        format="domain-ops-directory/catalogue/v2",
        freshness="clock-uncertain"
        if age < 0
        else ("stale" if age > v["refresh_after_seconds"] else "current"),
        authority=AUTHORITY,
    )
    validate("directory-result.schema.json", out, "Catalogue")
    return out


def workflow(intent: str) -> dict[str, Any]:
    validate("directory-result.schema.json", {"intent": intent}, "WorkflowArguments")
    out = {
        "format": "domain-ops-directory/workflow/v2",
        "intent": intent,
        "steps": WORKFLOWS[intent].copy(),
        "executes": False,
    }
    validate("directory-result.schema.json", out, "Workflow")
    return out


def discover(
    v: dict[str, Any], args: dict[str, Any] | None = None, now: dt.datetime = NOW
) -> dict[str, Any]:
    args = {} if args is None else args
    validate("directory-result.schema.json", args, "DiscoverArguments")
    c = catalogue(v, now)
    network = args.get("network", "all")
    if network != "all":
        c["owner_endpoints"] = [e for e in c["owner_endpoints"] if e["network"] == network]
    out = {
        "format": "domain-ops-directory/discovery/v2",
        "catalogue": c,
        "workflow": WORKFLOWS["start"].copy(),
    }
    validate("directory-result.schema.json", out, "Discovery")
    return out


def _expand_schema(
    node: Any, base: str = "directory-result.schema.json", seen: tuple[tuple[str, str], ...] = ()
) -> Any:
    if isinstance(node, list):
        return [_expand_schema(x, base, seen) for x in node]
    if not isinstance(node, dict):
        return node
    if "$ref" in node:
        ref = node["$ref"]
        file, _, fragment = ref.partition("#")
        file = file or base
        file = file.rsplit("/", 1)[-1]
        key = (file, fragment)
        if key in seen:
            raise ContractError("recursive public schema")
        target = SCHEMAS[file]
        for x in fragment.lstrip("/").split("/"):
            if x:
                target = target[x.replace("~1", "/").replace("~0", "~")]
        result = _expand_schema(target, file, (*seen, key))
        result.update({k: _expand_schema(v, base, seen) for k, v in node.items() if k != "$ref"})
        return result
    return {
        k: _expand_schema(v, base, seen) for k, v in node.items() if k not in ("$id", "$schema")
    }


def metadata(v: dict[str, Any]) -> dict[str, Any]:
    validate_directory(v)
    p = v["tool_prefix"]
    defs = SCHEMAS["directory-result.schema.json"]["$defs"]
    # Serve self-contained public schemas: clients must not fetch .invalid references.
    tools = []
    for suffix, title, desc, input_def, output_def in [
        (
            "discover_management",
            "Find domain management source and SSH owners",
            "Find tools/domain repositories and direct SSH owner hints. It does not grant credentials, install software or connect to hosts.",
            "DiscoverArguments",
            "Discovery",
        ),
        (
            "get_management_workflow",
            "Explain the local management workflow",
            "Explain install, tests, planning, recovery or cleanup using caller Git/Python/SSH. Guidance only; it performs no operations.",
            "WorkflowArguments",
            "Workflow",
        ),
    ]:
        tools.append(
            {
                "name": p + "_" + suffix,
                "title": title,
                "description": desc,
                "inputSchema": _expand_schema(defs[input_def]),
                "outputSchema": _expand_schema(defs[output_def]),
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": False,
                },
            }
        )
    return {
        "server": {
            "name": p,
            "title": v["display_name"],
            "version": "specification-10",
            "instructions": "Read-only source and SSH-owner discovery for "
            + v["domain_name"]
            + ". Establish independent source/SSH trust and caller authority. Clone or recover sources, install a verified portable toolkit, then inspect/test/plan. This service never executes instructions.",
        },
        "tools": tools,
        "resources": [
            {
                "uri": "domain-ops://" + v["domain_id"] + "/" + s,
                "name": s,
                "mimeType": "application/json" if s == "catalogue" else "text/plain",
            }
            for s in ("catalogue", "workflow")
        ],
        "prompts": [
            {
                "name": p + "_manage_domain",
                "description": "Guide local domain operations; no credential enrollment or execution.",
                "arguments": [
                    {
                        "name": "intent",
                        "description": "start, test-domain, plan-change, resume, recover, cleanup",
                        "required": True,
                    }
                ],
            }
        ],
    }


def render_html(c: dict[str, Any]) -> str:
    validate("directory-result.schema.json", c, "Catalogue")

    def e(value: str, *, quote: bool = True) -> str:
        return html.escape(value, quote=quote)

    rows = "".join(
        "<tr><td>"
        + e(r["id"])
        + '</td><td><a href="'
        + e(r["documentation_url"], quote=True)
        + '">Documentation</a></td><td><code>'
        + e(r["clone_url"])
        + "</code></td></tr>"
        for r in c["repositories"]
    )
    owners = "".join(
        "<li><strong>"
        + e(x["tool"])
        + "</strong> — "
        + e(x["id"])
        + " ("
        + e(x["network"])
        + ", "
        + e(x["role_hint"])
        + " hint): <code>"
        + e(x["user"])
        + "@"
        + e("[" + x["host"] + "]" if ":" in x["host"] else x["host"])
        + ":"
        + str(x["port"])
        + "</code>; trust "
        + e(x["trust_profile"])
        + "</li>"
        for x in c["owner_endpoints"]
    )
    steps = "".join("<li>" + e(x) + "</li>" for x in WORKFLOWS["start"])
    return (
        '<!doctype html>\n<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'
        + e(c["display_name"])
        + "</title><body><main><h1>"
        + e(c["display_name"])
        + "</h1><p>Source and direct SSH-owner guide. No management execution.</p><p>Catalogue "
        + str(c["generation"])
        + " · "
        + e(c["freshness"])
        + " · published "
        + e(c["published_at"])
        + "</p><h2>Source repositories</h2><table><thead><tr><th>Source</th><th>Guide</th><th>Git URL</th></tr></thead><tbody>"
        + rows
        + "</tbody></table><h2>Direct owners in configured order</h2><ul>"
        + owners
        + "</ul><p>Hints are not host trust, reachability, or permission. Authenticate independently.</p><h2>Workflow</h2><ol>"
        + steps
        + "</ol><h2>Recovery</h2><p>"
        + e(c["recovery_hint"])
        + '</p><p><a href="/catalogue.json">Machine-readable catalogue</a> · <a href="/workflow.txt">Workflow text</a></p></main></body></html>\n'
    )


def prepare_projection(
    v: dict[str, Any], now: dt.datetime = NOW, limit: int = 131072
) -> dict[str, Any]:
    c = catalogue(v, now)
    out = {
        "catalogue": c,
        "discovery": discover(v, now=now),
        "workflow": workflow("start"),
        "html": render_html(c),
        "mcp": metadata(v),
    }
    for x in out.values():
        n = len(x.encode()) if isinstance(x, str) else len(canonical(x))
        if n > limit:
            raise ContractError("response exceeds bounded projection")
    return out


class ReloadModel:
    def __init__(self, text: str, now: dt.datetime = NOW) -> None:
        self.value = load_directory(text)
        prepare_projection(self.value, now)
        self.last_error: str | None = None

    def reload(self, text: str, now: dt.datetime = NOW) -> bool:
        try:
            candidate = load_directory(text)
            prepare_projection(candidate, now)
        except (ContractError, ValueError):
            self.last_error = "invalid-candidate"
            return False
        self.value = candidate
        self.last_error = None
        return True
