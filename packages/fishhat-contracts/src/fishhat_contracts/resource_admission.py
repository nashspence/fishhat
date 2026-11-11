"""Pure host admission joins, never a native scheduler or authorization ledger.

The receiving owner supplies current approved policy, context and launch records
independently. Atomic capacity accounting, one-use grant consumption, native
placement, enforcement, identity authentication and cessation are not implemented
by these validators. Unknown native facts never become grants or release proof.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .bounds import Bounds, bounds
from .validation import ContractError, digest, validate

_SCHEMA = "resource-admission.schema.json"
_QUANTITIES = ("cpu_millis", "memory_bytes")


def _bounds(name: str) -> Bounds:
    return Bounds(
        id="resource_admission." + name,
        work="O(B) complete selected policy, request, grant and evidence bytes",
        extent="Every device, account and storage prerequisite in the exact inputs; no truncation",
        limits=(),
        capacity=("Receiving owner memory; native ledgers and scheduler work are not implemented",),
        proofs=("tests/test_resource_admission.py::test_resource_admission_contract_boundaries",),
        linear_proofs=("tests/test_resource_admission.py::test_resource_admission_linear_work",),
    )


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ContractError(code)


def _time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ContractError("ADMISSION_TIME") from exc
    _require(result.tzinfo is not None, "ADMISSION_TIME")
    return result


def _fits(required: dict[str, Any], available: dict[str, Any]) -> bool:
    return all(required[key] <= available[key] for key in _QUANTITIES) and all(
        quantity <= available["devices"].get(key, 0)
        for key, quantity in required["devices"].items()
    )


def _available(policy: dict[str, Any]) -> dict[str, Any]:
    capacity, control, resident = (
        policy["capacity"],
        policy["control_reserve"],
        policy["resident_reserve"],
    )
    _require(
        set(control["devices"]) | set(resident["devices"]) <= set(capacity["devices"]),
        "ADMISSION_UNKNOWN_RESERVED_DEVICE",
    )
    result: dict[str, Any] = {
        key: capacity[key] - control[key] - resident[key] for key in _QUANTITIES
    }
    result["devices"] = {
        key: quantity - control["devices"].get(key, 0) - resident["devices"].get(key, 0)
        for key, quantity in capacity["devices"].items()
    }
    _require(
        all(result[key] >= 0 for key in _QUANTITIES)
        and all(value >= 0 for value in result["devices"].values()),
        "ADMISSION_RESERVES_EXCEED_CAPACITY",
    )
    return result


def _domain(domain: dict[str, Any]) -> None:
    validate(_SCHEMA, domain, "DomainIdentity")
    scope = domain["scheduler"]["scope"]
    _require(
        scope["kind"] == "allocation"
        and scope["authority"] == domain["owner"]["id"]
        and scope["handle"] == domain["capacity_domain"],
        "ADMISSION_DOMAIN_SCOPE",
    )


@bounds(_bounds("validate_admission_policy"))
def validate_admission_policy(policy: dict[str, Any]) -> None:
    """Check one independently selected policy; not current free-capacity evidence."""
    validate(_SCHEMA, policy, "AdmissionPolicy")
    _domain(policy["domain"])
    available = _available(policy)
    _require(
        policy["control_reserve"]["cpu_millis"] > 0
        and policy["control_reserve"]["memory_bytes"] > 0,
        "ADMISSION_CONTROL_RESERVE_REQUIRED",
    )
    for account in policy["accounts"].values():
        _require(_fits(account["maximum"], available), "ADMISSION_ACCOUNT_EXCEEDS_DOMAIN")


def _request(request: dict[str, Any]) -> None:
    validate(_SCHEMA, request, "ResourceRequest")
    _domain(request["domain"])
    context, demand, limits = request["context"], request["demand"], request["limits"]
    _require(
        context["target_host"] == request["domain"]["host"]
        and context["subject"]["authority"] == context["owner"]["id"],
        "ADMISSION_WORK_LOCALITY",
    )
    _require(
        demand["cpu_millis"] > 0
        and demand["cpu_millis"] <= limits["cpu_max_millis"]
        and demand["memory_bytes"] == limits["memory_max_bytes"],
        "ADMISSION_DEMAND_LIMITS",
    )
    _require(
        request["lifetime"] == "resident" or limits["walltime_seconds"] is not None,
        "ADMISSION_TRANSIENT_WALLTIME",
    )
    storage_ids = {item["operation_id"] for item in request["storage_requests"]}
    _require(
        len(storage_ids) == len(request["storage_requests"]),
        "ADMISSION_DUPLICATE_STORAGE_REQUEST",
    )


def _required_capabilities(request: dict[str, Any]) -> set[str]:
    required = {"cpu-reservation", "memory-reservation", "cpu-max", "memory-max", "tasks-max"}
    if request["limits"]["walltime_seconds"] is not None:
        required.add("walltime")
    if request["demand"]["devices"]:
        required.add("device-isolation")
    if request["lifetime"] == "resident":
        required.add("resident-lifetime")
    return required


@bounds(_bounds("validate_resource_request"))
def validate_resource_request(
    request: dict[str, Any], *, policy: dict[str, Any], context: dict[str, Any]
) -> None:
    """Join a request to independently current accepted policy and exact work context."""
    _request(request)
    validate_admission_policy(policy)
    _require(request["domain"] == policy["domain"], "ADMISSION_CURRENT_DOMAIN")
    _require(request["context"] == context, "ADMISSION_CURRENT_CONTEXT")
    account = policy["accounts"].get(request["account"])
    _require(account is not None, "ADMISSION_ACCOUNT_NOT_APPROVED")
    assert account is not None
    _require(
        request["queue"]["class"] in account["classes"]
        and _fits(request["demand"], account["maximum"])
        and request["limits"]["cpu_max_millis"] <= account["maximum"]["cpu_millis"]
        and request["limits"]["memory_max_bytes"] <= account["maximum"]["memory_bytes"],
        "ADMISSION_ACCOUNT_LIMIT",
    )
    capabilities = policy["capabilities"]
    _require(
        request["lifetime"] in capabilities["lifetimes"]
        and _required_capabilities(request) <= set(capabilities["limits"])
        and capabilities["host_affinity"] == "enforced"
        and capabilities["supervision"] == "verified",
        "ADMISSION_UNSUPPORTED_CAPABILITY",
    )


def _submission(submission: dict[str, Any], request: dict[str, Any]) -> None:
    validate(_SCHEMA, submission, "SubmissionIdentity")
    _require(
        submission["executor"] == request["domain"]["scheduler"],
        "ADMISSION_SUBMISSION_EXECUTOR",
    )


def _grant(grant: dict[str, Any], request: dict[str, Any]) -> None:
    validate(_SCHEMA, grant, "ResourceGrant")
    _request(request)
    _submission(grant["execution"]["submission"], request)
    _require(
        grant["request_digest"] == digest(request)
        and grant["context_digest"] == digest(request["context"])
        and grant["domain"] == request["domain"]
        and grant["account"] == request["account"]
        and grant["host"] == request["context"]["target_host"]
        and grant["lifetime"] == request["lifetime"]
        and grant["admission_generation"] == request["context"]["admission_generation"],
        "ADMISSION_GRANT_IDENTITY",
    )
    _require(grant["limits"] == request["limits"], "ADMISSION_LIMITS_CHANGED")
    _require(
        _fits(request["demand"], grant["charged"])
        and grant["charged"]["devices"] == request["demand"]["devices"],
        "ADMISSION_UNDERCHARGED_GRANT",
    )
    _require(
        grant["expires_at"] is None or _time(grant["issued_at"]) < _time(grant["expires_at"]),
        "ADMISSION_GRANT_INTERVAL",
    )


@bounds(_bounds("validate_resource_grant"))
def validate_resource_grant(
    grant: dict[str, Any], *, request: dict[str, Any], policy: dict[str, Any]
) -> None:
    """Check one grant and its debit, not concurrent native capacity availability."""
    validate_resource_request(request, policy=policy, context=request["context"])
    _grant(grant, request)
    _require(grant["policy_digest"] == digest(policy), "ADMISSION_GRANT_POLICY")
    capabilities = policy["capabilities"]
    for quantity, key in (
        ("cpu_millis", "cpu_quantum_millis"),
        ("memory_bytes", "memory_quantum_bytes"),
    ):
        quantum = capabilities[key]
        expected = ((request["demand"][quantity] + quantum - 1) // quantum) * quantum
        _require(grant["charged"][quantity] == expected, "ADMISSION_QUANTUM_CHARGE")
    _require(
        _fits(grant["charged"], _available(policy))
        and _fits(grant["charged"], policy["accounts"][request["account"]]["maximum"]),
        "ADMISSION_GRANT_EXCEEDS_CAPACITY",
    )


@bounds(_bounds("require_resource_launch"))
def require_resource_launch(
    grant: dict[str, Any],
    *,
    request: dict[str, Any],
    policy: dict[str, Any],
    context: dict[str, Any],
    now: str,
) -> None:
    """Require a current unused allocation; native owner must atomically consume it."""
    validate_resource_request(request, policy=policy, context=context)
    validate_resource_grant(grant, request=request, policy=policy)
    when = _time(now)
    _require(grant["state"] == "allocated", "ADMISSION_GRANT_NOT_LAUNCHABLE")
    _require(
        _time(grant["issued_at"]) <= when
        and (grant["expires_at"] is None or when < _time(grant["expires_at"]))
        and (request["queue"]["deadline"] is None or when < _time(request["queue"]["deadline"])),
        "ADMISSION_LAUNCH_DEADLINE",
    )


def _release_identity(
    evidence: dict[str, Any], *, grant: dict[str, Any], request: dict[str, Any]
) -> None:
    _grant(grant, request)
    _require(
        evidence["request_digest"] == grant["request_digest"]
        and evidence["grant_id"] == grant["id"]
        and evidence["grant_generation"] == grant["generation"]
        and evidence["execution"] == grant["execution"]
        and evidence["fence_generation"] >= grant["admission_generation"],
        "ADMISSION_RELEASE_IDENTITY",
    )
    _require(
        _time(evidence["observed_at"]) >= _time(grant["issued_at"]),
        "ADMISSION_RELEASE_PREDATES_GRANT",
    )


@bounds(_bounds("validate_release_authorization"))
def validate_release_authorization(
    authorization: dict[str, Any], *, grant: dict[str, Any], request: dict[str, Any]
) -> None:
    """Authorize the request to release a ceased grant, without preclaiming release."""
    validate(_SCHEMA, authorization, "ReleaseAuthorization")
    _release_identity(authorization, grant=grant, request=request)
    _require(
        authorization["no_future_starts"] is True and authorization["descendants_stopped"] is True,
        "ADMISSION_RELEASE_NOT_AUTHORIZED",
    )


@bounds(_bounds("validate_release_evidence"))
def validate_release_evidence(
    evidence: dict[str, Any], *, grant: dict[str, Any], request: dict[str, Any]
) -> None:
    """Check exact positive release evidence; authentication stays with its native owner."""
    validate(_SCHEMA, evidence, "ReleaseEvidence")
    _release_identity(evidence, grant=grant, request=request)
    _require(
        all(
            evidence[key] is True
            for key in (
                "no_future_starts",
                "descendants_stopped",
                "native_resources_released",
                "accounting_verified",
            )
        ),
        "ADMISSION_RELEASE_UNVERIFIED",
    )


@bounds(_bounds("validate_process_admission"))
def validate_process_admission(
    admission: dict[str, Any],
    *,
    expected: dict[str, Any],
    executor: dict[str, Any],
    payload: dict[str, Any],
) -> None:
    """Join a manifest to independently loaded current, one-use owner launch custody."""
    validate(_SCHEMA, admission, "ProcessAdmission")
    if admission["class"] == "workload":
        _domain(admission["domain"])
    _require(admission == expected, "PROCESS_ADMISSION_NOT_APPROVED")
    _require(
        admission["executor"] == executor
        and admission["request_digest"] == digest(payload)
        and admission["host"] == admission["domain"]["host"],
        "PROCESS_ADMISSION_IDENTITY",
    )
    request = payload["request"] if "attempt" in payload else payload
    if executor["role"] == "scheduler" or request.get("method") == "reconcile":
        _require(admission["class"] == "control", "PROCESS_CONTROL_ADMISSION_REQUIRED")
    if "attempt" in payload:
        _require(admission["owner"] == payload["attempt"]["owner"], "PROCESS_ADMISSION_OWNER")
    elif payload.get("method") == "reconcile":
        original_owner = payload["input"]["invocation"]["attempt"]["owner"]
        _require(
            all(admission["owner"][key] == original_owner[key] for key in ("tool", "id")),
            "PROCESS_ADMISSION_OWNER",
        )
    if admission["class"] == "control":
        budget = admission["control_budget"]
        _require(
            budget["limits"]["walltime_seconds"] is not None
            and budget["limits"]["cpu_max_millis"] <= budget["maximum"]["cpu_millis"]
            and budget["limits"]["memory_max_bytes"] <= budget["maximum"]["memory_bytes"],
            "PROCESS_CONTROL_BUDGET",
        )


def _known_grant(inputs: dict[str, Any]) -> dict[str, Any] | None:
    return inputs.get("grant")


@bounds(_bounds("check_scheduler_request"))
def check_scheduler_request(request: dict[str, Any]) -> None:
    """Check the typed role request without inferring independent native approval."""
    validate("scheduler-adapter.schema.json", request)
    if request["method"] == "reconcile":
        return
    inputs = request["input"]
    resource = inputs["request"]
    _request(resource)
    _require(inputs["scope"] == resource["domain"]["scheduler"]["scope"], "SCHEDULER_SCOPE")
    if inputs.get("submission") is not None:
        _submission(inputs["submission"], resource)
    grant = _known_grant(inputs)
    if grant is not None:
        _grant(grant, resource)
        if request["method"] == "observe":
            _require(
                inputs["submission"] == grant["execution"]["submission"],
                "SCHEDULER_RETAINED_SUBMISSION",
            )
    if request["method"] == "release":
        assert grant is not None
        validate_release_authorization(inputs["authorization"], grant=grant, request=resource)


def _same_grant(previous: dict[str, Any], current: dict[str, Any]) -> bool:
    return {key: value for key, value in previous.items() if key != "state"} == {
        key: value for key, value in current.items() if key != "state"
    }


def _grant_transition(previous: dict[str, Any], current: dict[str, Any]) -> None:
    _require(_same_grant(previous, current), "SCHEDULER_EXECUTION_REPLACED")
    allowed = {
        "allocated": {"allocated", "running", "stopping", "released"},
        "running": {"running", "stopping", "released"},
        "stopping": {"stopping", "released"},
        "released": {"released"},
        "unknown": {"allocated", "running", "stopping", "released", "unknown"},
    }
    _require(current["state"] in allowed[previous["state"]], "SCHEDULER_GRANT_STATE_REGRESSION")


def _closed_submission(observation: dict[str, Any]) -> None:
    closure = observation["closure"]
    _require(closure is not None, "SCHEDULER_CLOSURE_REQUIRED")
    assert closure is not None
    _require(
        closure["request_digest"] == observation["request_digest"]
        and closure["submission"] == observation["submission"]
        and closure["no_future_starts"] is True
        and closure["allocations_absent"] is True,
        "SCHEDULER_CLOSURE_UNVERIFIED",
    )


def _observation_grant(observation: dict[str, Any], inputs: dict[str, Any]) -> None:
    request, state = inputs["request"], observation["state"]
    grant, release = observation["grant"], observation["release"]
    if grant is not None:
        _grant(grant, request)
        _require(
            observation["submission"] == grant["execution"]["submission"],
            "SCHEDULER_GRANT_SUBMISSION",
        )
        previous = _known_grant(inputs)
        if previous is not None:
            _grant_transition(previous, grant)
    elif _known_grant(inputs) is not None:
        raise ContractError("SCHEDULER_RETAINED_GRANT_LOST")
    if state in {"allocated", "running", "released"}:
        _require(grant is not None and grant["state"] == state, "SCHEDULER_GRANT_STATE")
    elif state == "stop-requested":
        _require(grant is None or grant["state"] != "released", "SCHEDULER_PREMATURE_RELEASE")
    else:
        _require(grant is None, "SCHEDULER_UNGRANTED_STATE")
    if state == "released":
        _require(release is not None and grant is not None, "SCHEDULER_RELEASE_REQUIRED")
        assert release is not None and grant is not None
        validate_release_evidence(release, grant=grant, request=request)
    else:
        _require(release is None, "SCHEDULER_PREMATURE_RELEASE")


def _observation(observation: dict[str, Any], inputs: dict[str, Any], coverage: str) -> None:
    validate(_SCHEMA, observation, "AdmissionObservation")
    request = inputs["request"]
    _require(
        observation["request_digest"] == digest(request)
        and observation["domain"] == request["domain"],
        "SCHEDULER_OBSERVATION_IDENTITY",
    )
    state, submission, grant, release, closure = (
        observation["state"],
        observation["submission"],
        observation["grant"],
        observation["release"],
        observation["closure"],
    )
    if submission is not None:
        _submission(submission, request)
    if inputs.get("submission") is not None and submission is not None:
        _require(submission == inputs["submission"], "SCHEDULER_SUBMISSION_REPLACED")
    if coverage == "unknown":
        _require(
            state == "unknown" and grant is None and release is None and closure is None,
            "SCHEDULER_UNKNOWN_CLEARANCE",
        )
        return
    _require(state != "unknown", "SCHEDULER_STATUS_UNKNOWN")
    _require(state == "rejected" or submission is not None, "SCHEDULER_SUBMISSION_REQUIRED")
    _observation_grant(observation, inputs)
    if state == "cancelled":
        _closed_submission(observation)
    else:
        _require(closure is None, "SCHEDULER_PREMATURE_CLOSURE")
    _require(
        not observation["unsupported"] or state in {"queued", "rejected"},
        "SCHEDULER_UNSUPPORTED_GRANT",
    )


@bounds(_bounds("check_scheduler_response"))
def check_scheduler_response(original_request: dict[str, Any], response: dict[str, Any]) -> None:
    """Validate original-method output after the common response/reconciliation joins."""
    method, inputs = original_request["method"], original_request["input"]
    _require(method != "reconcile", "SCHEDULER_ORIGINAL_REQUEST_REQUIRED")
    _require(
        response["coverage"] in {"complete", "unknown"} and response["continuation"] is None,
        "SCHEDULER_SCALAR_COVERAGE",
    )
    effect = response.get("effect")
    succeeded = effect is not None and (
        effect["task_state"],
        effect["effect_certainty"],
        effect["postcondition"],
    ) == ("terminal", "known", "satisfied")
    observation = response["output"]["observation"]
    if observation is None:
        _require(not succeeded and response["coverage"] == "unknown", "SCHEDULER_MISSING_STATUS")
        return
    _observation(observation, inputs, response["coverage"])
    if not succeeded:
        return
    _require(response["coverage"] == "complete", "SCHEDULER_UNKNOWN_SUCCESS")
    if method == "submit":
        _require(
            observation["submission"] is not None
            and observation["state"] not in {"rejected", "unknown"},
            "SCHEDULER_SUBMISSION_NOT_ACCEPTED",
        )
    elif method == "cancel":
        _require(
            observation["state"] in {"stop-requested", "cancelled", "released"},
            "SCHEDULER_CANCELLATION_NOT_CONFIRMED",
        )
    elif method == "release":
        _require(observation["state"] == "released", "SCHEDULER_RELEASE_NOT_CONFIRMED")
