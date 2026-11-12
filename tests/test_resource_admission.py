"""Portable resource admission identities, guarded launch and scheduler evidence."""

from __future__ import annotations

from copy import deepcopy
from functools import partial
from uuid import UUID

import pytest
from fishhat_adapters import check_invocation, check_request, check_response
from fishhat_contracts import resource_admission as admission
from fishhat_contracts.validation import ContractError, digest, validate

from tests.linear_support import assert_linear, measure

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-admission.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/scheduler-adapter.schema.json",
    ],
    "scope": "exact portable admission and scheduler request/result joins",
    "relationship": "candidate",
    "reason": "Synthetic reference checks reject stale authority, substituted execution, unsupported limits and premature release. They supply no durable scheduler, native enforcement, authenticated observation or one-use launch consumption.",
    "claims": [],
}

NOW = "2026-11-11T10:00:00Z"
LATER = "2026-11-11T11:00:00Z"
GIB = 1024**3
MIB = 1024**2
DIGEST = "sha256:" + "a" * 64
API_NAMES = (
    "validate_admission_policy",
    "validate_resource_request",
    "validate_resource_grant",
    "require_resource_launch",
    "validate_release_authorization",
    "validate_release_evidence",
    "validate_process_admission",
    "check_scheduler_request",
    "check_scheduler_response",
)


def uid(value):
    return str(UUID(int=value))


def vector(cpu, memory, devices=None):
    return {"cpu_millis": cpu, "memory_bytes": memory, "devices": devices or {}}


def records(count=0):
    host_owner = {"tool": "host-ops", "id": uid(1), "epoch": uid(2)}
    app_owner = {"tool": "app-ops", "id": uid(3), "epoch": uid(4)}
    scope = {"authority": host_owner["id"], "kind": "allocation", "handle": "host-capacity"}
    executor = {
        "instance": "host-scheduler",
        "role": "scheduler",
        "installation_digest": DIGEST,
        "configuration_digest": DIGEST,
        "instance_generation": 1,
        "instance_digest": DIGEST,
        "scope": scope,
    }
    domain = {
        "owner": host_owner,
        "host": "node-a",
        "capacity_domain": "host-capacity",
        "incarnation": "native-domain-one",
        "generation": 1,
        "scheduler": executor,
    }
    devices = {f"device-{index:04d}": 1 for index in range(count)}
    policy = {
        "domain": domain,
        "capacity": vector(8000, 8 * GIB, {key: 2 for key in devices}),
        "control_reserve": vector(1000, GIB),
        "resident_reserve": vector(1000, GIB),
        "accounts": {
            "demo-app": {"maximum": vector(4000, 4 * GIB, devices), "classes": ["maintenance"]}
        },
        "capabilities": {
            "cpu_quantum_millis": 1000,
            "memory_quantum_bytes": MIB,
            "lifetimes": ["transient"],
            "limits": [
                "cpu-reservation",
                "memory-reservation",
                "cpu-max",
                "memory-max",
                "tasks-max",
                "walltime",
                "device-isolation",
            ],
            "host_affinity": "enforced",
            "supervision": "verified",
        },
    }
    context = {
        "owner": app_owner,
        "operation_id": uid(5),
        "stage_id": uid(6),
        "stage": "backup",
        "work_digest": DIGEST,
        "target_host": "node-a",
        "account": "demo-app",
        "subject": {"authority": app_owner["id"], "kind": "application", "handle": "demo-app"},
        "authorization": {"kind": "accepted-continuation", "digest": DIGEST},
        "admission_generation": 7,
    }
    request = {
        "format": "fishhat.resource-admission/v1",
        "kind": "ResourceRequest",
        "id": uid(7),
        "context": context,
        "domain": domain,
        "account": "demo-app",
        "lifetime": "transient",
        "demand": vector(1500, 512 * MIB, devices),
        "limits": {
            "cpu_max_millis": 2000,
            "memory_max_bytes": 512 * MIB,
            "tasks_max": 64,
            "walltime_seconds": 3600,
        },
        "storage_requests": [
            {"operation_id": uid(1000 + index), "request_digest": DIGEST} for index in range(count)
        ],
        "queue": {"class": "maintenance", "deadline": LATER},
    }
    submission = {"executor": executor, "handle": "native-job", "incarnation": "job-one"}
    execution = {
        "submission": submission,
        "handle": "native-allocation",
        "incarnation": "allocation-one",
        "attempt": uid(8),
    }
    grant = {
        "format": "fishhat.resource-admission/v1",
        "kind": "ResourceGrant",
        "id": uid(9),
        "generation": 1,
        "request_digest": digest(request),
        "context_digest": digest(context),
        "policy_digest": digest(policy),
        "domain": domain,
        "account": "demo-app",
        "host": "node-a",
        "lifetime": "transient",
        "execution": execution,
        "charged": vector(2000, 512 * MIB, devices),
        "limits": deepcopy(request["limits"]),
        "state": "allocated",
        "admission_generation": 7,
        "issued_at": NOW,
        "expires_at": LATER,
    }
    authorization = {
        "request_digest": grant["request_digest"],
        "grant_id": grant["id"],
        "grant_generation": grant["generation"],
        "execution": execution,
        "fence_generation": 8,
        "no_future_starts": True,
        "descendants_stopped": True,
        "observed_at": NOW,
        "evidence_digest": DIGEST,
    }
    released = {**authorization, "native_resources_released": True, "accounting_verified": True}
    return {
        "policy": policy,
        "context": context,
        "request": request,
        "submission": submission,
        "grant": grant,
        "authorization": authorization,
        "released": released,
    }


def role_request(value, method="submit", known_grant=False):
    request = value["request"]
    inputs = {"scope": request["domain"]["scheduler"]["scope"], "request": request}
    if method in {"observe", "cancel"}:
        inputs["submission"] = value["submission"]
    if method == "observe":
        inputs["grant"] = value["grant"] if known_grant else None
    elif method == "release":
        inputs.update(grant=value["grant"], authorization=value["authorization"])
    return {"contract": "fishhat.scheduler", "method": method, "input": inputs}


def invocation_for(request):
    domain = request["input"]["request"]["domain"]
    return {
        "request": request,
        "attempt": {
            "owner": domain["owner"],
            "operation_id": uid(20),
            "effect_id": uid(21),
            "attempt_id": uid(22),
            "binding_generation": domain["generation"],
            "native_incarnation": uid(23),
            "contract": "fishhat.scheduler",
            "method": request["method"],
            "scope": request["input"]["scope"],
            "input_digest": digest(request),
            "state": "dispatched",
            "certainty": "unknown",
            "outcome": "pending",
            "native_task": None,
            "executor": domain["scheduler"],
        },
    }


def response_for(value, request, state="queued", grant=None):
    resource = value["request"]
    observation = {
        "request_digest": digest(resource),
        "domain": resource["domain"],
        "state": state,
        "submission": value["submission"],
        "grant": grant,
        "release": None,
        "closure": None,
        "reasons": ["capacity"] if state == "queued" else [],
        "unsupported": [],
    }
    result = {
        "contract": request["contract"],
        "method": request["method"],
        "request_digest": digest(request),
        "scope": request["input"]["scope"],
        "coverage": "unknown" if state == "unknown" else "complete",
        "continuation": None,
        "proposal": None,
        "output": {"observation": observation},
        "problem": None,
    }
    if request["method"] != "observe":
        result["effect"] = {
            "attempt_id": uid(22),
            "input_digest": digest(request),
            "acknowledgment": "accepted",
            "task_state": "terminal",
            "effect_certainty": "known",
            "postcondition": "satisfied",
            "native_task": "scheduler-control-task",
        }
    if state == "released":
        observation["release"] = value["released"]
    elif state == "cancelled":
        observation["closure"] = {
            "request_digest": digest(resource),
            "submission": value["submission"],
            "no_future_starts": True,
            "allocations_absent": True,
            "observed_at": NOW,
            "evidence_digest": DIGEST,
        }
    return result


def process_record(value, payload):
    domain = value["policy"]["domain"]
    return {
        "use_id": uid(30),
        "owner": domain["owner"],
        "executor": domain["scheduler"],
        "request_digest": digest(payload),
        "host": domain["host"],
        "domain": {key: entry for key, entry in domain.items() if key != "scheduler"},
        "policy_digest": digest(value["policy"]),
        "class": "control",
        "admission_generation": 7,
        "control_budget": {
            "id": "scheduler-control",
            "generation": 1,
            "maximum": vector(100, 64 * MIB),
            "limits": {
                "cpu_max_millis": 100,
                "memory_max_bytes": 64 * MIB,
                "tasks_max": 16,
                "walltime_seconds": 60,
            },
        },
        "grant": None,
    }


def api_calls(value):
    policy, request, context, grant = (
        value["policy"],
        value["request"],
        value["context"],
        value["grant"],
    )
    query = role_request(value)
    payload = invocation_for(query)
    record = process_record(value, payload)
    response = response_for(value, query)
    return {
        "validate_admission_policy": partial(admission.validate_admission_policy, policy),
        "validate_resource_request": partial(
            admission.validate_resource_request, request, policy=policy, context=context
        ),
        "validate_resource_grant": partial(
            admission.validate_resource_grant, grant, request=request, policy=policy
        ),
        "require_resource_launch": partial(
            admission.require_resource_launch,
            grant,
            request=request,
            policy=policy,
            context=context,
            now=NOW,
        ),
        "validate_release_authorization": partial(
            admission.validate_release_authorization,
            value["authorization"],
            grant=grant,
            request=request,
        ),
        "validate_release_evidence": partial(
            admission.validate_release_evidence, value["released"], grant=grant, request=request
        ),
        "validate_process_admission": partial(
            admission.validate_process_admission,
            record,
            expected=deepcopy(record),
            executor=record["executor"],
            payload=payload,
        ),
        "check_scheduler_request": partial(admission.check_scheduler_request, query),
        "check_scheduler_response": partial(admission.check_scheduler_response, query, response),
    }


def test_resource_admission_contract_boundaries():
    value = records(3)
    for function in api_calls(value).values():
        function()
    request = role_request(value)
    invocation = invocation_for(request)
    check_request("scheduler", request)
    check_invocation("scheduler", invocation)
    response = response_for(value, request)
    check_response("scheduler", request, response, invocation=invocation)
    assert response["effect"]["postcondition"] == "satisfied"
    assert response["output"]["observation"]["state"] == "queued"
    assert response["output"]["observation"]["grant"] is None
    # Submission completion never makes its unallocated workload launchable.
    with pytest.raises(ContractError):
        admission.require_resource_launch(
            {**value["grant"], "state": "unknown"},
            request=value["request"],
            policy=value["policy"],
            context=value["context"],
            now=NOW,
        )


@pytest.mark.parametrize("field", ["owner", "stage_id", "work_digest", "admission_generation"])
def test_waiting_request_needs_independently_current_exact_context(field):
    value = records()
    expected = deepcopy(value["context"])
    expected[field] = {
        "owner": {**expected["owner"], "epoch": uid(99)},
        "stage_id": uid(99),
        "work_digest": "sha256:" + "b" * 64,
        "admission_generation": 8,
    }[field]
    with pytest.raises(ContractError, match="ADMISSION_CURRENT_CONTEXT"):
        admission.validate_resource_request(
            value["request"], policy=value["policy"], context=expected
        )


@pytest.mark.parametrize("replace_context", [False, True])
def test_work_cannot_select_another_approved_accounts_capacity(replace_context):
    value = records()
    expected = deepcopy(value["context"])
    value["policy"]["accounts"]["other-app"] = deepcopy(value["policy"]["accounts"]["demo-app"])
    request = deepcopy(value["request"])
    request["account"] = "other-app"
    if replace_context:
        request["context"]["account"] = "other-app"
    error = "ADMISSION_CURRENT_CONTEXT" if replace_context else "ADMISSION_WORK_ACCOUNT"
    with pytest.raises(ContractError, match=error):
        admission.validate_resource_request(request, policy=value["policy"], context=expected)


def test_account_change_requires_a_new_independently_approved_work_context():
    value = records()
    value["policy"]["accounts"]["other-app"] = deepcopy(value["policy"]["accounts"]["demo-app"])
    expected = deepcopy(value["context"])
    expected["account"] = "other-app"
    expected["authorization"]["digest"] = "sha256:" + "b" * 64
    request = deepcopy(value["request"])
    request.update(id=uid(99), account="other-app", context=deepcopy(expected))
    admission.validate_resource_request(request, policy=value["policy"], context=expected)


def test_unbound_work_context_is_not_an_admission_request():
    value = records()
    del value["request"]["context"]["account"]
    with pytest.raises(ContractError):
        admission.validate_resource_request(
            value["request"], policy=value["policy"], context=value["context"]
        )


@pytest.mark.parametrize("field", ["host_affinity", "supervision", "limits"])
def test_unknown_or_unsupported_enforcement_cannot_admit_work(field):
    value = records()
    value["policy"]["capabilities"][field] = [] if field == "limits" else "unknown"
    with pytest.raises(ContractError, match="ADMISSION_UNSUPPORTED_CAPABILITY"):
        admission.validate_resource_request(
            value["request"], policy=value["policy"], context=value["context"]
        )


def test_demands_limits_reserves_and_rounding_are_distinct():
    value = records()
    admission.validate_resource_grant(
        value["grant"], request=value["request"], policy=value["policy"]
    )
    assert value["request"]["demand"]["cpu_millis"] == 1500
    assert value["grant"]["charged"]["cpu_millis"] == 2000
    changed = deepcopy(value["grant"])
    changed["charged"]["cpu_millis"] = 1500
    with pytest.raises(ContractError, match="ADMISSION_QUANTUM_CHARGE"):
        admission.validate_resource_grant(changed, request=value["request"], policy=value["policy"])
    changed = deepcopy(value["request"])
    changed["limits"]["memory_max_bytes"] *= 2
    with pytest.raises(ContractError, match="ADMISSION_DEMAND_LIMITS"):
        admission.validate_resource_request(
            changed, policy=value["policy"], context=value["context"]
        )
    changed = deepcopy(value["policy"])
    changed["resident_reserve"]["memory_bytes"] = 8 * GIB
    with pytest.raises(ContractError, match="ADMISSION_RESERVES_EXCEED_CAPACITY"):
        admission.validate_admission_policy(changed)


def test_integer_valued_float_quantities_keep_exact_quantum_charges():
    value = records()
    amount = 9_007_199_254_740_990.0
    policy, request, grant = value["policy"], value["request"], value["grant"]
    policy["capacity"]["memory_bytes"] = 9_007_199_254_740_991
    policy["control_reserve"]["memory_bytes"] = 1
    policy["resident_reserve"]["memory_bytes"] = 0
    policy["accounts"]["demo-app"]["maximum"]["memory_bytes"] = amount
    policy["capabilities"]["memory_quantum_bytes"] = 10.0
    request["demand"]["memory_bytes"] = amount
    request["limits"]["memory_max_bytes"] = amount
    grant["charged"]["memory_bytes"] = 9_007_199_254_740_990
    grant["limits"]["memory_max_bytes"] = amount
    grant["request_digest"] = digest(request)
    grant["policy_digest"] = digest(policy)
    admission.validate_resource_grant(grant, request=request, policy=policy)


def test_release_authorization_does_not_preclaim_native_release():
    value = records()
    query = role_request(value, "release")
    assert "native_resources_released" not in query["input"]["authorization"]
    assert "accounting_verified" not in query["input"]["authorization"]
    check_request("scheduler", query)
    grant = {**value["grant"], "state": "released"}
    response = response_for(value, query, "released", grant)
    invocation = invocation_for(query)
    check_response("scheduler", query, response, invocation=invocation)
    response["output"]["observation"]["release"]["native_resources_released"] = False
    with pytest.raises(ContractError, match="ADMISSION_RELEASE_UNVERIFIED"):
        check_response("scheduler", query, response, invocation=invocation)


@pytest.mark.parametrize(
    "fact",
    ["no_future_starts", "descendants_stopped", "native_resources_released", "accounting_verified"],
)
def test_expiry_or_partial_cessation_never_releases_capacity(fact):
    value = records()
    value["released"][fact] = False
    with pytest.raises(ContractError, match="ADMISSION_RELEASE_UNVERIFIED"):
        admission.validate_release_evidence(
            value["released"], grant=value["grant"], request=value["request"]
        )
    assert value["grant"]["state"] == "allocated"
    with pytest.raises(ContractError, match="ADMISSION_LAUNCH_DEADLINE"):
        admission.require_resource_launch(
            value["grant"],
            request=value["request"],
            policy=value["policy"],
            context=value["context"],
            now=LATER,
        )
    assert value["grant"]["state"] == "allocated"


def test_queued_cancellation_has_no_grant_or_invented_release():
    value = records()
    query = role_request(value, "cancel")
    invocation = invocation_for(query)
    requested = response_for(value, query, "stop-requested")
    check_response("scheduler", query, requested, invocation=invocation)
    assert requested["output"]["observation"]["grant"] is None
    assert requested["output"]["observation"]["release"] is None
    finished = response_for(value, query, "cancelled")
    check_response("scheduler", query, finished, invocation=invocation)
    finished["output"]["observation"]["closure"]["allocations_absent"] = False
    with pytest.raises(ContractError, match="SCHEDULER_CLOSURE_UNVERIFIED"):
        check_response("scheduler", query, finished, invocation=invocation)


@pytest.mark.parametrize("retain_submission", [False, True])
def test_rejection_cannot_erase_a_retained_scheduler_submission(retain_submission):
    value = records()
    query = role_request(value, "observe")
    response = response_for(value, query, "rejected")
    if not retain_submission:
        response["output"]["observation"]["submission"] = None
    with pytest.raises(ContractError, match="SCHEDULER_ACCEPTED_SUBMISSION_REJECTED"):
        check_response("scheduler", query, response)


def test_initial_rejection_has_no_accepted_backend_submission():
    value = records()
    query = role_request(value, "observe")
    query["input"]["submission"] = None
    response = response_for(value, query, "rejected")
    with pytest.raises(ContractError, match="SCHEDULER_ACCEPTED_SUBMISSION_REJECTED"):
        check_response("scheduler", query, response)
    response["output"]["observation"]["submission"] = None
    check_response("scheduler", query, response)


@pytest.mark.parametrize("field", ["incarnation", "attempt", "handle"])
def test_requeued_or_replaced_execution_cannot_reuse_a_retained_grant(field):
    value = records()
    query = role_request(value, "observe", known_grant=True)
    changed = deepcopy(value["grant"])
    changed["execution"][field] = uid(99) if field == "attempt" else "replacement"
    changed["state"] = "running"
    response = response_for(value, query, "running", changed)
    with pytest.raises(ContractError, match="SCHEDULER_EXECUTION_REPLACED"):
        check_response("scheduler", query, response)


def test_unknown_observation_preserves_original_grant_and_cannot_supply_clearance():
    value = records()
    query = role_request(value, "observe", known_grant=True)
    original = deepcopy(query)
    response = response_for(value, query, "unknown")
    response["output"]["observation"]["submission"] = None
    check_response("scheduler", query, response)
    assert query == original
    response["output"]["observation"]["grant"] = {**value["grant"], "state": "released"}
    with pytest.raises(ContractError, match="SCHEDULER_UNKNOWN_CLEARANCE"):
        check_response("scheduler", query, response)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("released", "allocated"),
        ("released", "running"),
        ("stopping", "allocated"),
        ("stopping", "running"),
    ],
)
def test_known_grant_state_cannot_regress_to_launchable_work(before, after):
    value = records()
    value["grant"]["state"] = before
    query = role_request(value, "observe", known_grant=True)
    changed = {**value["grant"], "state": after}
    response = response_for(value, query, after, changed)
    with pytest.raises(ContractError, match="SCHEDULER_GRANT_STATE_REGRESSION"):
        check_response("scheduler", query, response)


def test_scheduler_mutation_custody_belongs_to_host_owner():
    value = records()
    query = role_request(value)
    invocation = invocation_for(query)
    invocation["attempt"]["owner"] = value["context"]["owner"]
    with pytest.raises(ContractError, match="SCHEDULER_DOMAIN_OWNER"):
        check_invocation("scheduler", invocation)


def test_reconciliation_retains_submission_instead_of_dispatching_again():
    value = records()
    query = role_request(value)
    invocation = invocation_for(query)
    reconcile = {
        "contract": "fishhat.scheduler",
        "method": "reconcile",
        "input": {"scope": query["input"]["scope"], "invocation": invocation},
    }
    response = response_for(value, query)
    response.update(method="reconcile", request_digest=digest(reconcile))
    check_response("scheduler", reconcile, response, invocation=invocation)
    assert response["output"]["observation"]["state"] == "queued"
    assert invocation["attempt"]["state"] == "dispatched"


def test_resident_lifetime_is_explicit_and_requires_support():
    value = records()
    request = value["request"]
    request["lifetime"] = "resident"
    request["limits"]["walltime_seconds"] = None
    with pytest.raises(ContractError, match="ADMISSION_UNSUPPORTED_CAPABILITY"):
        admission.validate_resource_request(
            request, policy=value["policy"], context=value["context"]
        )
    value["policy"]["capabilities"]["lifetimes"].append("resident")
    value["policy"]["capabilities"]["limits"].append("resident-lifetime")
    admission.validate_resource_request(request, policy=value["policy"], context=value["context"])


def test_process_control_budget_and_exact_owner_custody_are_required():
    value = records()
    payload = invocation_for(role_request(value))
    record = process_record(value, payload)
    expected = deepcopy(record)
    admission.validate_process_admission(
        record, expected=expected, executor=record["executor"], payload=payload
    )
    record["control_budget"]["limits"]["walltime_seconds"] = None
    with pytest.raises(ContractError):
        admission.validate_process_admission(
            record, expected=record, executor=record["executor"], payload=payload
        )
    record = deepcopy(expected)
    record["use_id"] = uid(99)
    with pytest.raises(ContractError, match="PROCESS_ADMISSION_NOT_APPROVED"):
        admission.validate_process_admission(
            record, expected=expected, executor=record["executor"], payload=payload
        )


@pytest.mark.parametrize("method", ["submit", "observe", "cancel", "release"])
def test_scheduler_control_cannot_depend_on_workload_admission(method):
    value = records()
    request = role_request(value, method)
    payload = request if method == "observe" else invocation_for(request)
    record = process_record(value, payload)
    record.update(
        {
            "class": "workload",
            "control_budget": None,
            "domain": deepcopy(value["policy"]["domain"]),
            "grant": {
                "id": value["grant"]["id"],
                "generation": value["grant"]["generation"],
                "digest": digest(value["grant"]),
            },
        }
    )
    with pytest.raises(ContractError, match="PROCESS_CONTROL_ADMISSION_REQUIRED"):
        admission.validate_process_admission(
            record, expected=deepcopy(record), executor=record["executor"], payload=payload
        )


def test_current_reconciliation_admission_can_use_a_separately_approved_recovery_epoch():
    value = records()
    query = role_request(value)
    original = deepcopy(invocation_for(query))
    payload = {
        "contract": "fishhat.scheduler",
        "method": "reconcile",
        "input": {"scope": query["input"]["scope"], "invocation": deepcopy(original)},
    }
    record = deepcopy(process_record(value, payload))
    record["owner"]["epoch"] = uid(99)
    record["domain"]["owner"]["epoch"] = uid(99)
    admission.validate_process_admission(
        record, expected=deepcopy(record), executor=record["executor"], payload=payload
    )
    assert payload["input"]["invocation"] == original
    for field, replacement in (("tool", "app-ops"), ("id", uid(100))):
        changed = deepcopy(record)
        changed["owner"] = {**changed["owner"], field: replacement}
        with pytest.raises(ContractError, match="PROCESS_ADMISSION_OWNER"):
            admission.validate_process_admission(
                changed, expected=changed, executor=changed["executor"], payload=payload
            )


def test_resource_request_has_no_native_or_automatic_restart_escape():
    value = records()
    for field in ("partition", "namespace", "requeue", "restart", "argv", "owner_approved"):
        changed = {**value["request"], field: True}
        with pytest.raises(ContractError):
            validate("resource-admission.schema.json", changed, "ResourceRequest")


def test_resource_admission_linear_work():
    for name in API_NAMES:
        samples = []
        for count in (8, 32, 128):
            value = records(count)
            call = api_calls(value)[name]
            _, work = measure(call, modules=(admission,))
            samples.append((count, work))
        assert_linear(samples)


CHECK_OVERRIDES = {
    name: {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/resource_admission.py#" + symbol
            for symbol in API_NAMES
        ]
        + ["release.toml#/engineering"],
        "scope": "pure exact admission joins over complete growing device and storage-prerequisite inputs",
        "relationship": "scoped-witness",
        "reason": "The boundary case exercises every declared helper; the growth witness counts real complete work at increasing extents. Neither verifies native scheduling, aggregate ledger transactions, enforcement or durable launch consumption.",
        "claims": ["engineering:resource_admission." + symbol for symbol in API_NAMES],
    }
    for name in (
        "test_resource_admission_contract_boundaries",
        "test_resource_admission_linear_work",
    )
}
