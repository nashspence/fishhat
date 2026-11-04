"""Offline portable-client contract models, not a deployed CLI or path-security layer.

No SSH, package installation, repository mutation, deletion, or backup restoration.
Path checks are lexical; actual no-follow/mount/ownership checks need native code.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from itertools import chain, combinations
from pathlib import PurePosixPath
from typing import Any, cast

from fishhat_contracts.validation import ContractError, digest, validate


def clean_path(value: str, *, absolute: bool = True) -> str:
    if type(value) is not str or not value or "\\" in value or any(ord(c) < 32 for c in value):
        raise ContractError("invalid path")
    if (
        value.startswith("/") != absolute
        or "//" in value
        or any(x in (".", "..") for x in value.split("/"))
    ):
        raise ContractError("noncanonical path")
    if str(PurePosixPath(value)) != value or value == "/":
        raise ContractError("noncanonical path")
    return value


def valid_branch(value: str) -> str:
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,159}", value)
        or ".." in value
        or "@{" in value
        or value.endswith(("/", ".", ".lock"))
        or "//" in value
        or "/." in value
    ):
        raise ContractError("unsafe branch")
    return value


def within(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def validate_session(value: dict[str, Any]) -> dict[str, Any]:
    validate("workspace.schema.json", value)
    clean_path(value["root"])
    directories = [value["domain_dir"], value["tool_env"], value["test_env"]]
    if value["tools_dir"] is not None:
        directories.append(value["tools_dir"])
    evidence = value.get("evidence_dir")
    if evidence is not None:
        directories.append(evidence)
    for path in directories:
        clean_path(path)
    if not within(value["domain_dir"], value["root"]) or value["domain_dir"] == value["root"]:
        raise ContractError("domain outside registered root")
    if evidence and (within(evidence, value["root"]) or within(value["root"], evidence)):
        raise ContractError("optional external evidence path overlaps disposable root")
    for left, right in combinations(directories, 2):
        if within(left, right) or within(right, left):
            raise ContractError("session checkout, environment or evidence directories overlap")
    return value


def validate_bundle(
    value: dict[str, Any],
    *,
    platform: str | None = None,
    python: str | None = None,
    require_qualified: bool = False,
) -> dict[str, Any]:
    validate("install-bundle.schema.json", value)
    if platform is not None and platform != value["platform"]:
        raise ContractError("wrong install platform")
    if python is not None and python != value["python"]:
        raise ContractError("wrong interpreter ABI")
    if require_qualified and (value["qualification"] != "qualified" or not value["evidence"]):
        raise ContractError("unqualified install bundle")
    paths = set()
    for x in [value["lock"]] + value["wheels"] + value["build_inputs"]:
        clean_path(x["path"], absolute=False)
        if x["path"] in paths:
            raise ContractError("duplicate artifact path")
        paths.add(x["path"])
    if value["qualification"] == "qualified" and not value["evidence"]:
        raise ContractError("qualification needs evidence")
    if not all(
        x["path"].startswith("wheels/") and x["path"].endswith(".whl") for x in value["wheels"]
    ):
        raise ContractError("runtime bundle must contain wheels")
    return value


def check_closeout(value: dict[str, Any]) -> dict[str, Any]:
    """Protect source/jobs. Missing tracking alone never blocks and no files are deleted."""
    validate("client-records.schema.json", value, "Closeout")
    clean_path(value["root"])
    blockers = []
    warnings = []
    if value["active_jobs"]:
        blockers.append("active-local-work")
    if value["foreign_worktrees"]:
        blockers.append("foreign-worktree-obligation")
    ids = set()
    for x in value["obligations"]:
        if x["id"] in ids:
            raise ContractError("duplicate closeout obligation")
        ids.add(x["id"])
        missing = x["disposition"] == "unresolved" or x["evidence_digest"] is None
        if x["kind"] == "receipt":
            if missing:
                warnings.append("tracking-not-retained")
        else:
            if missing:
                blockers.append("unpreserved-" + x["kind"])
            if (
                x["disposition"] in ("retained", "exported")
                and not value["evidence_outside_workspace"]
            ):
                blockers.append("source-evidence-not-retained")
    if value["unresolved_requests"]:
        warnings.append("resolve-pending-work-at-owner")
        if not value["receipt_export_digest"]:
            warnings.append("tracking-not-retained")
    return {
        "safe_to_close": not blockers,
        "blockers": sorted(set(blockers)),
        "warnings": sorted(set(warnings)),
        "plan_digest": digest(value),
        "deletes_files": False,
    }


def _delivery_key(delivery: dict[str, Any]) -> tuple[str, str, str, str]:
    owner = delivery["owner"]
    return owner["tool"], owner["id"], owner["epoch"], delivery["request_id"]


def validate_export(value: dict[str, Any]) -> dict[str, Any]:
    validate("client-records.schema.json", value, "ReceiptExport")
    keys = set()
    for d in value["deliveries"]:
        if d["domain_id"] != value["domain_id"]:
            raise ContractError("receipt domain binding mismatch")
        k = _delivery_key(d)
        if k in keys:
            raise ContractError("duplicate owner request identity")
        keys.add(k)
    return value


def merge_exports(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    import copy

    validate_export(a)
    validate_export(b)
    if a["domain_id"] != b["domain_id"]:
        raise ContractError("wrong domain evidence")
    result = copy.deepcopy(a)
    result["participant_evidence"] = list(
        dict.fromkeys(chain(a["participant_evidence"], b["participant_evidence"]))
    )
    known = {_delivery_key(d): d for d in a["deliveries"]}
    for d in b["deliveries"]:
        k = _delivery_key(d)
        if k in known:
            for f in (
                "domain_id",
                "owner",
                "action",
                "resource",
                "expected_generation",
                "plan_digest",
                "subject_digest",
                "workflow_id",
            ):
                if known[k][f] != d[f]:
                    raise ContractError("conflicting immutable receipt")
            # Do not accept a newer unverified status merely because a file says so.
        else:
            result["deliveries"].append(copy.deepcopy(d))
            known[k] = d
    return result


def validate_suite(value: dict[str, Any]) -> dict[str, Any]:
    validate("test-suite.schema.json", value)
    if "offline" not in value["suites"] or value["suites"]["offline"]["class"] != "offline":
        raise ContractError("offline default required")
    for x in value["suites"].values():
        clean_path(x["cwd"], absolute=False)
        if x["argv"][0] != "python" or any("\x00" in a or "\n" in a for a in x["argv"]):
            raise ContractError("qualified test interpreter argv required")
        if x["class"] == "mutate" and not x["targets_required"]:
            raise ContractError("finite mutation targets required")
    return value


def select_suite(
    value: dict[str, Any],
    name: str | None = None,
    *,
    targets: list[Any] | None = None,
    allow_mutations: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    validate_suite(value)
    name = name or "offline"
    if name not in value["suites"]:
        raise ContractError("unknown suite")
    suite = value["suites"][name]
    if suite["class"] == "mutate" and not (targets and allow_mutations and confirm):
        raise ContractError("explicit mutation admission needed")
    if suite["targets_required"] and not targets:
        raise ContractError("missing finite targets")
    return cast(dict[str, Any], suite)


def validate_run(value: dict[str, Any]) -> dict[str, Any]:
    validate("client-records.schema.json", value, "TestRun")
    if value["status"] == "passed" and (
        value["skipped_required"] or value["executed"] < value["required"]
    ):
        raise ContractError("required coverage missing")
    if value["class"] == "offline" and value["deliveries"]:
        raise ContractError("offline run includes remote work")
    if value["class"] == "mutate" and not value["targets"]:
        raise ContractError("unbounded mutation test")
    return value


def validate_recovery_set(
    value: dict[str, Any],
    bundle: dict[str, Any],
    *,
    expected_domain_id: str,
    retained_application_closures: Collection[str],
) -> dict[str, Any]:
    """Check complete application obligations from independent same-domain custody."""
    validate("recovery-set.schema.json", value)
    validate_bundle(bundle)
    if value["domain_id"] != expected_domain_id or set(value["application_closure_digests"]) != set(
        retained_application_closures
    ):
        raise ContractError("recovery application closure coverage mismatch")
    if value["installation_bundle_digest"] != digest(bundle):
        raise ContractError("recovery install bundle mismatch")
    clean_path(value["installation_bundle_path"])
    if value["platform"] != bundle["platform"]:
        raise ContractError("recovery platform mismatch")
    if value["qualified"] and (
        not value["independent_custody"]
        or not value["evidence"]
        or bundle["qualification"] != "qualified"
    ):
        raise ContractError("recovery set not qualified")
    return value
