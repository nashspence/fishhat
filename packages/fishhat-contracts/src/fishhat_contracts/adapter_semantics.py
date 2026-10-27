"""Shared typed adapter request, response and retained-result semantics.

These checks bind evidence to exact immutable inputs. They do not enroll an
executor, authenticate an owner or grant authority to perform native effects.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any, cast

from .bounds import Bounds, bounds
from .dns import _rrset_identity, validate_changes, validate_rrsets
from .publication import validate_publication_intent
from .targets import check_target_request, check_target_response
from .validation import ROOT, ContractError, canonical, digest, validate

ROLES: dict[str, dict[str, dict[str, Any]]] = json.loads(
    (ROOT / "contracts/adapter-roles.json").read_text(encoding="utf-8")
)


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ContractError(code)


def _semantic_bounds(name: str) -> Bounds:
    proof = "tests/test_export_growth.py::test_adapter_semantics_linear_work"
    return Bounds(
        id="adapters." + name,
        work="O(B) complete typed request, retained invocation and response bytes",
        extent="Exact whole inputs and outputs; observation pages retain explicit continuation",
        limits=(),
        capacity=("Existing typed scalar and page limits remain explicit admission boundaries",),
        proofs=(proof,),
        linear_proofs=(proof,),
    )


@bounds(_semantic_bounds("check_request"))
def check_request(role: str, value: dict[str, Any]) -> None:
    """Check a typed payload; mutation execution additionally requires an Invocation."""
    require(role in ROLES, "UNKNOWN_CONTRACT")
    validate(role + "-adapter.schema.json", value)
    method, inputs = value["method"], value["input"]
    if method == "reconcile":
        invocation = inputs["invocation"]
        check_invocation(role, invocation)
        original = invocation["attempt"]
        require(
            original["contract"] == value["contract"]
            and original["scope"] == inputs["scope"]
            and original["method"] in ROLES[role]
            and ROLES[role][original["method"]]["effect"],
            "RECONCILIATION_IDENTITY",
        )
        return
    check_target_request(role, value)
    if role == "compute" and method in {"plan", "set-limits"}:
        _check_limits(inputs["limits"])
    if role == "dns" and method in {"plan", "publish"}:
        validate_changes(inputs["change"])
        require(inputs["scope"] == inputs["change"]["scope"], "DNS_SCOPE_IDENTITY")
    binding = _handoff_binding(role, value)
    if binding is not None:
        require(
            binding["role"] == role and binding["scope"] == inputs["scope"],
            "HANDOFF_BINDING_SCOPE",
        )
    if role == "capture" and method in {"restore", "verify"}:
        snapshot = inputs["snapshot"]
        require(
            snapshot["dataset"] == inputs["dataset"] and snapshot["producer"]["role"] == "capture",
            "SNAPSHOT_INPUT_IDENTITY",
        )
    if role == "secret-source" and method == "publish":
        validate_publication_intent(
            source=inputs["binding"],
            entry=inputs["entry"],
            version=inputs["version"],
            expected_previous=inputs["expected_previous"],
        )
    if role == "repository" and method == "publish":
        require(
            inputs["candidate"]["repository"] == inputs["repository"],
            "REPOSITORY_CANDIDATE_IDENTITY",
        )
    if role == "runtime" and method in {"observe", "inventory"}:
        barrier = inputs["barrier"]
        if barrier is not None:
            require(
                barrier["scope"] == inputs["scope"]
                and barrier["owner"]["id"] == inputs["scope"]["authority"],
                "OBSERVATION_BARRIER_SCOPE",
            )
    if role == "bootstrap-source" and method in {"recover", "verify"}:
        require(
            inputs["scope"]["handle"] == inputs["selection"]["source_id"],
            "BOOTSTRAP_SCOPE_IDENTITY",
        )


@bounds(_semantic_bounds("check_invocation"))
def check_invocation(role: str, value: dict[str, Any]) -> None:
    """Verify the owner-retained mutation closure, not authorization to dispatch it."""
    validate("adapter.schema.json", value, "Invocation")
    request, attempt = value["request"], value["attempt"]
    check_request(role, request)
    executor = attempt["executor"]
    require(
        ROLES[role][request["method"]]["effect"]
        and attempt["contract"] == request["contract"]
        and attempt["method"] == request["method"]
        and attempt["scope"] == request["input"]["scope"] == executor["scope"]
        and executor["role"] == role
        and attempt["input_digest"] == digest(request),
        "INVOCATION_IDENTITY",
    )
    binding = _handoff_binding(role, request)
    require(binding is None or binding == executor, "INVOCATION_EXECUTOR_IDENTITY")
    if role == "bootstrap-source":
        selected = request["input"]["selection"]["adapter"]
        require(
            all(
                executor[key] == selected[key]
                for key in ("installation_digest", "configuration_digest")
            ),
            "BOOTSTRAP_EXECUTOR_IDENTITY",
        )


def _handoff_binding(role: str, request: dict[str, Any]) -> dict[str, Any] | None:
    method, inputs = request["method"], request["input"]
    if role in {"service", "software"} and method != "reconcile":
        return cast(
            dict[str, Any],
            inputs["binding"] if method == "observe" else inputs["target"]["executor"],
        )
    if (role == "capture" and method in {"assess", "capture", "restore", "verify"}) or (
        role == "secret-source" and method in {"resolve", "publish"}
    ):
        return cast(dict[str, Any], inputs["binding"])
    if role == "credential-issuer":
        if method == "issue":
            return cast(dict[str, Any], inputs["issuer"])
        if method in {"renew", "revoke"}:
            return cast(dict[str, Any], inputs["lease"]["issuer"])
    if role == "repository":
        if method in {"resolve", "fetch", "publish"}:
            return cast(dict[str, Any], inputs["repository"]["binding"])
        if method == "observe":
            return cast(dict[str, Any], inputs["binding"])
    return None


def _attempt_identity(attempt: dict[str, Any]) -> dict[str, Any]:
    mutable = {"state", "certainty", "outcome", "native_task"}
    return {key: value for key, value in attempt.items() if key not in mutable}


@bounds(_semantic_bounds("check_response"))
def check_response(
    role: str,
    request: dict[str, Any],
    response: dict[str, Any],
    *,
    invocation: dict[str, Any] | None = None,
) -> None:
    check_request(role, request)
    validate(role + "-adapter.schema.json", response, "Response")
    require(
        response["contract"] == request["contract"]
        and response["method"] == request["method"]
        and response["request_digest"] == digest(request)
        and response["scope"] == request["input"]["scope"],
        "RESPONSE_IDENTITY",
    )
    require(
        response["coverage"] != "complete" or response["continuation"] is None,
        "INCOMPLETE_RESPONSE_COVERAGE",
    )
    if request["method"] == "reconcile":
        require(invocation is not None, "EFFECT_INVOCATION_REQUIRED")
        assert invocation is not None
        check_invocation(role, invocation)
        original = request["input"]["invocation"]
        require(
            _attempt_identity(invocation["attempt"]) == _attempt_identity(original["attempt"])
            and invocation["request"] == original["request"],
            "RECONCILIATION_IDENTITY",
        )
        check_result(invocation["attempt"], response["effect"])
        request = invocation["request"]
        # Recovery has the same output obligations as the original method.
        validate(
            role + "-adapter.schema.json",
            {**response, "method": request["method"], "request_digest": digest(request)},
            "Response",
        )
    elif ROLES[role][request["method"]]["effect"]:
        require(invocation is not None, "EFFECT_INVOCATION_REQUIRED")
        assert invocation is not None
        check_invocation(role, invocation)
        require(
            invocation["request"] == request,
            "RESPONSE_EFFECT_IDENTITY",
        )
        check_result(invocation["attempt"], response["effect"])
    _check_handoff_response(role, request, response)
    _check_observation_page(request, response)
    _check_observed_quantities(role, response["output"])
    check_target_response(role, request, response, invocation["attempt"] if invocation else None)
    if "effect" in response and _succeeded(response["effect"]):
        assert invocation is not None
        _check_success_output(role, request, response["output"], invocation["attempt"]["executor"])
        if role == "credential-issuer" and request["method"] in {"issue", "renew"}:
            _check_issued_lifetime(request, response["output"])


def _succeeded(effect: dict[str, Any]) -> bool:
    return bool(
        effect["task_state"] == "terminal"
        and effect["effect_certainty"] == "known"
        and effect["postcondition"] == "satisfied"
    )


def _check_observation_page(request: dict[str, Any], response: dict[str, Any]) -> None:
    """Bound returned top-level collection entries and require resumable progress.

    Opaque cursors still need receiver-owned snapshot, executor and query checks;
    structural progress is not evidence of native completeness or authorization.
    """
    if request["method"] not in {"observe", "inventory"}:
        return
    inputs, output = request["input"], response["output"]
    count = sum(len(value) for value in output.values() if isinstance(value, list))
    require(count <= inputs["limit"], "OBSERVATION_PAGE_CAPACITY")
    if response["coverage"] == "incomplete":
        require(
            response["continuation"] is not None and response["continuation"] != inputs["cursor"],
            "OBSERVATION_CURSOR_PROGRESS",
        )
    else:
        require(response["continuation"] is None, "OBSERVATION_NOT_RESUMABLE")


def _check_handoff_response(role: str, request: dict[str, Any], response: dict[str, Any]) -> None:
    method, inputs, output = request["method"], request["input"], response["output"]
    if role == "secret-source" and method == "resolve":
        version = output["version"]
        require(
            response["coverage"] == ("unknown" if output["state"] == "unknown" else "complete")
            and response["continuation"] is None,
            "SECRET_RESOLUTION_COVERAGE",
        )
        require(
            version is None
            or (
                version["source"] == inputs["binding"]["instance"]
                and version["entry"] == inputs["entry"]
                and version["version"] == inputs["version"]
            ),
            "SECRET_RESOLUTION_IDENTITY",
        )
    if role == "capture" and method in {"assess", "capture", "restore", "verify"}:
        for snapshot in output["snapshots"]:
            require(snapshot["dataset"] == inputs["dataset"], "SNAPSHOT_OUTPUT_IDENTITY")
            if method in {"restore", "verify"}:
                require(snapshot == inputs["snapshot"], "SNAPSHOT_OUTPUT_IDENTITY")
            else:
                require(snapshot["producer"] == inputs["binding"], "SNAPSHOT_OUTPUT_IDENTITY")
    if role == "credential-issuer" and method in {"issue", "renew", "revoke"}:
        target = inputs if method == "issue" else inputs["lease"]
        for lease in output["leases"]:
            require(
                all(lease[key] == target[key] for key in ("issuer", "identity", "consumer"))
                and (method == "issue" or lease["lease"] == target["lease"]),
                "LEASE_RESULT_IDENTITY",
            )
    if role == "secret-source" and method == "publish":
        require(
            all(
                version["source"] == inputs["binding"]["instance"]
                and version["entry"] == inputs["entry"]
                and version["version"] == inputs["version"]
                for version in output["versions"]
            ),
            "PUBLICATION_RESULT_IDENTITY",
        )
    if role == "repository":
        _check_repository_response(request, response)
    if role == "runtime" and method in {"observe", "inventory"}:
        observation = output["observation"]
        if observation is not None:
            require(
                observation["scope"] == inputs["scope"]
                and observation["barrier"] == inputs["barrier"],
                "OBSERVATION_BARRIER_IDENTITY",
            )
            if inputs["barrier"] is not None:
                require(
                    observation["admission_generation"]
                    == inputs["barrier"]["admission_generation"],
                    "OBSERVATION_BARRIER_GENERATION",
                )


def _check_repository_response(request: dict[str, Any], response: dict[str, Any]) -> None:
    """Correlate repository observations and immutable custody with the exact request."""
    method, inputs, output = request["method"], request["input"], response["output"]
    if method == "resolve":
        resolution = output["resolution"]
        require(
            resolution["repository"] == inputs["repository"] and resolution["ref"] == inputs["ref"],
            "REPOSITORY_RESOLUTION_IDENTITY",
        )
        require(
            response["coverage"] == ("unknown" if resolution["state"] == "unknown" else "complete")
            and response["continuation"] is None,
            "REPOSITORY_RESOLUTION_COVERAGE",
        )
    elif method == "fetch":
        snapshot = output["snapshot"]
        require(
            snapshot is None
            or (
                snapshot["repository"] == inputs["repository"]
                and snapshot["commit"] == inputs["commit"]
            ),
            "REPOSITORY_FETCH_IDENTITY",
        )
    elif method == "publish":
        publication = output["publication"]
        require(
            publication is None
            or (
                publication["repository"] == inputs["repository"]
                and publication["ref"] == inputs["ref"]
                and publication["object_id"] == inputs["candidate"]["commit"]
                and publication["previous"] == inputs["expected_previous"]
                and publication["snapshot"] == inputs["candidate"]
            ),
            "REPOSITORY_PUBLICATION_IDENTITY",
        )
    elif method == "observe":
        identities: set[bytes] = set()
        for resolution in output["refs"]:
            require(
                resolution["repository"]["binding"] == inputs["binding"],
                "REPOSITORY_OBSERVATION_EXECUTOR",
            )
            identity = canonical([resolution["repository"]["canonical"], resolution["ref"]])
            require(identity not in identities, "DUPLICATE_REPOSITORY_REF")
            identities.add(identity)


def _same_set(a: list[Any], b: list[Any]) -> bool:
    return len(a) == len(b) and {canonical(item) for item in a} == {canonical(item) for item in b}


def _check_issued_lifetime(request: dict[str, Any], output: dict[str, Any]) -> None:
    """An approved lifetime is a maximum measured from native issuance/renewal.

    Historical expiry, revocation and unknown observations may have null times;
    they cannot be presented as successful bounded issuance or renewal.
    """
    leases = output["leases"]
    require(len(leases) == 1, "LEASE_RESULT_CARDINALITY")
    lease = leases[0]
    start, end = lease["valid_from"], lease["expires_at"]
    require(
        lease["validity"] == "valid" and start is not None and end is not None,
        "LEASE_LIFETIME_UNVERIFIED",
    )
    if start is None or end is None:
        return
    begin = datetime.fromisoformat(start.replace("Z", "+00:00"))
    finish = datetime.fromisoformat(end.replace("Z", "+00:00"))
    require(
        begin < finish
        and finish - begin <= timedelta(seconds=request["input"]["lifetime_seconds"]),
        "LEASE_LIFETIME_EXCEEDED",
    )


def _check_success_output(
    role: str, request: dict[str, Any], output: dict[str, Any], executor: dict[str, Any]
) -> None:
    """Bind complete, method-specific result custody to its original requested identities."""
    inputs = request["input"]
    checks: dict[str, Callable[[], bool]] = {
        "runtime": lambda: output["deployment"] == inputs["deployment"],
        "compute": lambda: (
            output["allocation"] == inputs["allocation"]
            and _same_set(output["limits"], inputs["limits"])
        ),
        "storage": lambda: (
            output["allocations"][0]["handle"] == inputs["allocation"]
            and _same_set(output["allocations"][0]["purposes"], inputs["purposes"])
            and (not inputs["hard_isolation"] or output["allocations"][0]["hard_isolation"])
            and output["allocations"][0]["capacity_bytes"] == inputs["capacity_bytes"]
            and output["allocations"][0]["capacity_inodes"] == inputs["capacity_inodes"]
        ),
        "backup": lambda: (
            output["objects"][0]["handle"] == inputs["object"]
            and output["objects"][0]["repository"] == inputs["repository"]
            and _same_set(output["objects"][0]["artifacts"], inputs["artifacts"])
        ),
        "ingress": lambda: output["serving_generation"] == inputs["generation_digest"],
        "network": lambda: output["policy_generation"] == inputs["policy_digest"],
        "dns": lambda: (
            {_rrset_identity(value) for value in output["rrsets"]}
            == {
                _rrset_identity(change["after"])
                for change in inputs["change"]["changes"]
                if change["after"] is not None
            }
        ),
        "secret-source": lambda: all(
            item["source"] == executor["instance"]
            and item["entry"] == inputs["entry"]
            and item["version"] == inputs["version"]
            for item in output["versions"]
        ),
        "bootstrap-source": lambda: (
            output["receipt"] is not None
            and output["receipt"]["selection_digest"] == digest(inputs["selection"])
            and output["receipt"]["domain_id"] == inputs["selection"]["domain_id"]
            and output["receipt"]["source_id"] == inputs["selection"]["source_id"]
            and output["receipt"]["ref"] == inputs["selection"]["ref"]
            and output["receipt"]["commit"] == inputs["selection"]["expected_commit"]
            and output["receipt"]["destination"].startswith(
                inputs["selection"]["recovery_root"].rstrip("/") + "/"
            )
            and (
                request["method"] != "verify"
                or output["receipt"]["output_digest"] == inputs["output"]["digest"]
            )
        ),
    }
    check = checks.get(role)
    require(check is None or check(), "SUCCESS_OUTPUT_IDENTITY")


def _check_limits(limits: list[dict[str, Any]]) -> None:
    keys = [(limit["quantity"], limit["target"]) for limit in limits]
    require(len(keys) == len(set(keys)), "DUPLICATE_LIMIT")
    values = {limit["quantity"]: limit["value"] for limit in limits if limit["target"] is None}
    require(
        "memory-high" not in values
        or "memory-max" not in values
        or values["memory-high"] <= values["memory-max"],
        "INCONSISTENT_MEMORY_LIMITS",
    )


def _check_counters(counters: list[dict[str, Any]], allocation: str | None) -> None:
    keys = [(item["allocation"], item["metric"], item["target"]) for item in counters]
    require(len(keys) == len(set(keys)), "DUPLICATE_COUNTER")
    for item in counters:
        require(item["allocation"] == allocation, "COUNTER_ALLOCATION_IDENTITY")
        require(
            item["coverage"] not in {"unsupported", "unknown"} or item["value"] is None,
            "UNKNOWN_COUNTER_VALUE",
        )
        start = item["interval_start"]
        require(
            start is None
            or datetime.fromisoformat(start) < datetime.fromisoformat(item["observed_at"]),
            "COUNTER_INTERVAL",
        )


def _check_observed_quantities(role: str, output: dict[str, Any]) -> None:
    if role == "compute":
        _check_limits(output["limits"])
        _check_counters(output["counters"], output["allocation"])
        require(
            output["allocation"] is not None or not (output["counters"] or output["limits"]),
            "UNKNOWN_ALLOCATION_QUANTITIES",
        )
    if role == "storage":
        for allocation in output["allocations"]:
            _check_counters(allocation["counters"], allocation["handle"])
    if role == "dns":
        validate_rrsets(output["rrsets"])


@bounds(_semantic_bounds("check_result"))
def check_result(attempt: dict[str, Any], result: dict[str, Any]) -> None:
    validate("adapter.schema.json", attempt, "EffectAttempt")
    validate("adapter.schema.json", result, "EffectResult")
    require(
        result["attempt_id"] == attempt["attempt_id"]
        and result["input_digest"] == attempt["input_digest"],
        "RESULT_IDENTITY",
    )
    if result["acknowledgment"] == "rejected":
        require(
            result["effect_certainty"] == "none" and result["task_state"] == "terminal",
            "CONTRADICTORY_REJECTION",
        )
    if result["postcondition"] == "satisfied":
        require(result["effect_certainty"] == "known", "UNKNOWN_EFFECT_CANNOT_SUCCEED")
    if result["task_state"] == "running":
        require(result["native_task"] is not None, "MISSING_NATIVE_TASK")


def check_retained_result(role: str, value: dict[str, Any], *, operation: dict[str, Any]) -> None:
    """Check the complete response against its retained invocation and owning Operation.

    A reconcile response retains the invocation exactly as inspected by that
    request, so its complete request preimage can be reconstructed without
    rewriting the response or treating recovered evidence as a direct reply.
    """
    validate(role + "-adapter.schema.json", value, "RetainedResult")
    invocation, response = value["invocation"], value["response"]
    request, attempt = invocation["request"], invocation["attempt"]
    checked_request = request
    if response["method"] == "reconcile":
        checked_request = {
            "contract": request["contract"],
            "method": "reconcile",
            "input": {"scope": request["input"]["scope"], "invocation": invocation},
        }
    check_response(role, checked_request, response, invocation=invocation)
    arguments, executor = operation["subject"]["arguments"], attempt["executor"]
    require(
        operation["subject"]["action"] == "adapter.execute"
        and attempt["owner"] == operation["owner"]
        and attempt["operation_id"] == operation["id"]
        and executor["instance"] == arguments["adapter_id"]
        and executor["installation_digest"] == arguments["adapter_release"]
        and request["method"] == arguments["action"]
        and arguments["input"]["owner"] == operation["owner"]
        and arguments["input"]["digest"] == digest(request)
        and arguments["input"]["size"] == len(canonical(request)),
        "RETAINED_RESULT_OPERATION_IDENTITY",
    )
    require(
        operation["effect_certainty"] == response["effect"]["effect_certainty"],
        "RETAINED_RESULT_EFFECT_CERTAINTY",
    )
    require(
        operation["state"] != "succeeded" or _succeeded(response["effect"]),
        "SUCCESSFUL_OPERATION_REQUIRES_ADAPTER_SUCCESS",
    )
