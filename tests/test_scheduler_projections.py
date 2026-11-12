"""Contrasting provider translations without native scheduling or release claims."""

from copy import deepcopy
from typing import Any

import pytest
from a_fishhat_nomad_adapter import projections as nomad
from a_fishhat_slurm_adapter import projections as slurm
from fishhat_contracts.validation import ContractError, digest, strict_json

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "some-implementations/fishhat/schedulers/slurm/src/a_fishhat_slurm_adapter/projections.py",
        "some-implementations/fishhat/schedulers/nomad/src/a_fishhat_nomad_adapter/projections.py",
    ],
    "scope": "pure provider translation, acceptance correlation and uncertain lifecycle states",
    "relationship": "candidate",
    "reason": "Synthetic projections exercise distinct batch and declarative interfaces; they provide no native scheduler qualification, enforcement or execution authority.",
    "claims": [],
}

_MIB = 1024 * 1024
_OWNER_ID = "11111111-1111-4111-8111-111111111111"
_REQUEST_ID = "33333333-3333-4333-8333-333333333333"
_DIGEST = "sha256:" + "a" * 64


def request() -> dict[str, Any]:
    owner = {
        "tool": "host-ops",
        "id": _OWNER_ID,
        "epoch": "22222222-2222-4222-8222-222222222222",
    }
    return {
        "format": "fishhat.resource-admission/v1",
        "kind": "ResourceRequest",
        "id": _REQUEST_ID,
        "context": {
            "owner": owner,
            "account": "app-demo",
            "operation_id": "44444444-4444-4444-8444-444444444444",
            "stage_id": "55555555-5555-4555-8555-555555555555",
            "stage": "build",
            "work_digest": _DIGEST,
            "target_host": "node-a",
            "subject": {"authority": _OWNER_ID, "kind": "application", "handle": "demo"},
            "authorization": {"kind": "accepted-continuation", "digest": _DIGEST},
            "admission_generation": 3,
        },
        "domain": {
            "owner": deepcopy(owner),
            "host": "node-a",
            "capacity_domain": "host-capacity",
            "incarnation": "boot-a",
            "generation": 2,
            "scheduler": {
                "instance": "scheduler",
                "role": "scheduler",
                "installation_digest": _DIGEST,
                "configuration_digest": _DIGEST,
                "instance_generation": 1,
                "instance_digest": _DIGEST,
                "scope": {
                    "authority": _OWNER_ID,
                    "kind": "allocation",
                    "handle": "host-capacity",
                },
            },
        },
        "account": "app-demo",
        "lifetime": "transient",
        "demand": {"cpu_millis": 1250, "memory_bytes": 64 * _MIB, "devices": {}},
        "limits": {
            "cpu_max_millis": 2000,
            "memory_max_bytes": 64 * _MIB,
            "tasks_max": 64,
            "walltime_seconds": 120,
        },
        "storage_requests": [],
        "queue": {"class": "maintenance", "deadline": None},
    }


def configuration(provider: str) -> dict[str, Any]:
    if provider == "slurm":
        return {
            "cluster": "host-cluster",
            "partition": "maintenance",
            "account": "fishhat",
            "node": "node-a-native",
            "target_host": "node-a",
            "worker_script": "/opt/fishhat/worker.sbatch",
            "cpu_unit": "logical-cpu",
        }
    return {
        "endpoint_handle": "host-nomad",
        "region": "local",
        "namespace": "fishhat",
        "datacenter": "host",
        "node_id": "66666666-6666-4666-8666-666666666666",
        "target_host": "node-a",
        "worker_executable": "/opt/fishhat/worker",
        "driver": "exec",
        "cpu_unit": "logical-cpu",
    }


def test_slurm_projects_host_pinned_batch_with_explicit_charged_cpu_quantum():
    value = request()
    result = slurm.project_submission(value, configuration("slurm"))
    assert result.argv is not None
    assert "--nodelist=node-a-native" in result.argv
    assert "--nodes=1" in result.argv
    assert "--cpus-per-task=2" in result.argv
    assert "--mem=64M" in result.argv
    assert "--time=2" in result.argv
    assert "--no-requeue" in result.argv
    assert "--export=NIL" in result.argv
    assert result.argv[-5:] == (
        "/opt/fishhat/worker.sbatch",
        "--resource-request",
        _REQUEST_ID,
        "--resource-request-digest",
        digest(value),
    )
    assert result.charged_cpu_millis == 2000
    assert result.charged_memory_bytes == 64 * _MIB
    assert set(result.unsupported) == {"tasks-max", "supervision"}
    assert not result.admissible and not result.native_qualified


def test_nomad_projects_create_only_cas_with_separate_job_and_task_policy():
    result = nomad.project_submission(request(), configuration("nomad"))
    assert result.body is not None
    native = strict_json(result.body)
    assert result.method == "PUT" and result.path == "/v1/jobs"
    assert native["EnforceIndex"] is True and native["JobModifyIndex"] == 0
    job = native["Job"]
    assert job["ID"] == "fishhat-" + _REQUEST_ID
    assert job["Type"] == "batch"
    assert job["Constraints"] == [
        {
            "LTarget": "${node.unique.id}",
            "Operand": "=",
            "RTarget": configuration("nomad")["node_id"],
        }
    ]
    group = job["TaskGroups"][0]
    assert group["Count"] == 1
    assert group["RestartPolicy"] == {"Attempts": 0, "Mode": "fail"}
    assert group["ReschedulePolicy"] == {"Attempts": 0, "Unlimited": False}
    assert group["Disconnect"]["Replace"] is False
    assert group["MaxRunDuration"] == 120_000_000_000
    assert group["Tasks"][0]["Resources"] == {"Cores": 2, "MemoryMB": 64}
    assert result.charged_cpu_millis == 2000
    assert set(result.unsupported) == {"cpu-max", "tasks-max", "supervision"}
    assert not result.admissible and not result.native_qualified


@pytest.mark.parametrize("provider", [slurm, nomad], ids=["slurm", "nomad"])
def test_provider_projection_never_converts_fractional_memory_into_a_weaker_hard_cap(provider):
    value = request()
    value["demand"]["memory_bytes"] += 1
    value["limits"]["memory_max_bytes"] += 1
    config = configuration("slurm" if provider is slurm else "nomad")
    result = provider.project_submission(value, config)
    assert "memory-max" in result.unsupported
    assert result.charged_memory_bytes == 65 * _MIB
    assert (result.argv if provider is slurm else result.body) is None


def test_slurm_does_not_substitute_whole_cpu_allocation_for_a_fractional_bandwidth_cap():
    value = request()
    value["limits"]["cpu_max_millis"] = 1500
    result = slurm.project_submission(value, configuration("slurm"))
    assert "cpu-max" in result.unsupported
    assert result.argv is None


@pytest.mark.parametrize("seconds", [1, 61, 119])
def test_slurm_does_not_round_walltime_up_to_a_weaker_hard_cap(seconds):
    value = request()
    value["limits"]["walltime_seconds"] = seconds
    result = slurm.project_submission(value, configuration("slurm"))
    assert "walltime" in result.unsupported
    assert result.argv is None


def test_nomad_duration_conversion_preserves_seconds_and_rejects_json_overflow():
    value = request()
    value["limits"]["walltime_seconds"] = 61
    result = nomad.project_submission(value, configuration("nomad"))
    assert result.body is not None
    assert strict_json(result.body)["Job"]["TaskGroups"][0]["MaxRunDuration"] == 61_000_000_000
    value["limits"]["walltime_seconds"] = 9_007_200
    result = nomad.project_submission(value, configuration("nomad"))
    assert "walltime" in result.unsupported
    assert result.body is None


@pytest.mark.parametrize("provider", [slurm, nomad], ids=["slurm", "nomad"])
@pytest.mark.parametrize("change", ["zero-memory", "resident", "devices"])
def test_partial_profiles_report_unsupported_work_instead_of_native_defaults(provider, change):
    value = request()
    expected = {
        "zero-memory": "quantities",
        "resident": "resident-lifetime",
        "devices": "device-isolation",
    }
    if change == "zero-memory":
        value["demand"]["memory_bytes"] = 0
    elif change == "resident":
        value["lifetime"] = "resident"
        value["limits"]["walltime_seconds"] = None
    else:
        value["demand"]["devices"] = {"gpu": 1}
    config = configuration("slurm" if provider is slurm else "nomad")
    result = provider.project_submission(value, config)
    assert expected[change] in result.unsupported
    assert (result.argv if provider is slurm else result.body) is None
    assert not result.admissible


@pytest.mark.parametrize("provider", [slurm, nomad], ids=["slurm", "nomad"])
@pytest.mark.parametrize("field", ["context", "domain"])
def test_provider_native_node_binding_cannot_relocate_an_exact_host_request(provider, field):
    value = request()
    value[field]["target_host" if field == "context" else "host"] = "node-b"
    config = configuration("slurm" if provider is slurm else "nomad")
    with pytest.raises(ContractError, match="SCHEDULER_HOST_BINDING_MISMATCH"):
        provider.project_submission(value, config)


@pytest.mark.parametrize("provider", [slurm, nomad], ids=["slurm", "nomad"])
def test_provider_configuration_rejects_caller_native_script_options(provider):
    config = configuration("slurm" if provider is slurm else "nomad")
    config["native_args"] = ["--arbitrary-option"]
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        provider.project_submission(request(), config)


def test_integral_json_floats_have_the_same_native_projection_and_commitment():
    value = request()
    native = slurm.project_submission(value, configuration("slurm"))
    for section in ["demand", "limits"]:
        for key, number in value[section].items():
            if isinstance(number, int):
                value[section][key] = float(number)
    assert slurm.project_submission(value, configuration("slurm")) == native


def test_slurm_acceptance_response_contains_no_execution_identity_or_launch_permission():
    receipt = slurm.parse_submission("431;host-cluster\n", cluster="host-cluster")
    assert receipt == slurm.SubmissionReceipt("431", "host-cluster")
    for uncertain in ["431", "431;other-cluster", "431;host-cluster\n432;host-cluster", ""]:
        with pytest.raises(ContractError, match="SCHEDULER_SUBMISSION_UNCERTAIN"):
            slurm.parse_submission(uncertain, cluster="host-cluster")


def test_nomad_registration_receipt_does_not_conflate_job_evaluation_and_allocation():
    projection = nomad.project_submission(request(), configuration("nomad"))
    receipt = nomad.parse_registration(
        projection,
        {"JobModifyIndex": 19, "EvalCreateIndex": 20, "EvalID": _REQUEST_ID},
    )
    assert receipt.job_id == projection.job_id
    assert receipt.job_modify_index == 19
    assert receipt.evaluation_id == _REQUEST_ID
    assert receipt.evaluation_create_index == 20
    with pytest.raises(ContractError, match="SCHEDULER_SUBMISSION_UNCERTAIN"):
        nomad.parse_registration(projection, {"JobModifyIndex": 19, "Status": "complete"})


@pytest.mark.parametrize("field", ["ID", "Namespace", "Region", "Meta"])
def test_nomad_uncertain_create_rejects_colliding_job_identity(field):
    projection = nomad.project_submission(request(), configuration("nomad"))
    assert projection.body is not None
    observed = strict_json(projection.body)["Job"]
    assert (
        nomad.reconcile_job_identity(projection, observed)
        == "matching-correlation-requires-observation"
    )
    observed[field] = "other"
    with pytest.raises(ContractError, match="SCHEDULER_SUBMISSION_IDENTITY_CONFLICT"):
        nomad.reconcile_job_identity(projection, observed)


def test_nomad_cancellation_stops_the_job_instead_of_rescheduling_one_allocation():
    projection = nomad.project_submission(request(), configuration("nomad"))
    method, path, query = nomad.cancellation_request(projection)
    assert method == "DELETE"
    assert path == "/v1/job/" + projection.job_id
    assert ("purge", "false") in query


@pytest.mark.parametrize("state", ["PREEMPTED", "REQUEUED", "REQUEUE_HOLD"])
def test_slurm_repeated_execution_and_cleanup_are_not_resource_release(state):
    assert slurm.normalize_state(state) == slurm.JobState("unknown", may_repeat=True)
    assert slurm.normalize_state("COMPLETED", ("COMPLETING",)).phase == "stopping"
    assert slurm.normalize_state("SUSPENDED").phase == "unknown"
    assert slurm.normalize_state("COMPLETED").outcome == "backend-exit-zero"


@pytest.mark.parametrize(
    ("state", "flags", "phase"),
    [
        ("PREEMPTED", ("COMPLETING",), "stopping"),
        ("PREEMPTED", ("CONFIGURING",), "allocated"),
        ("PREEMPTED", ("UNRECOGNIZED",), "unknown"),
        ("RUNNING", ("SPECIAL_EXIT",), "unknown"),
        ("SPECIAL_EXIT", (), "unknown"),
        ("REQUEUED", ("COMPLETING",), "stopping"),
        ("REQUEUE_FED", ("CONFIGURING",), "allocated"),
        ("RUNNING", ("COMPLETING", "REQUEUE_HOLD"), "unknown"),
    ],
)
def test_slurm_phase_flags_preserve_preemption_and_requeue_risk(state, flags, phase):
    assert slurm.normalize_state(state, flags) == slurm.JobState(phase, may_repeat=True)


def test_nomad_timeout_complete_and_replacement_cannot_become_success_or_release():
    assert nomad.normalize_allocation(
        "complete", description="allocation exceeded max_run_duration"
    ) == nomad.AllocationState("terminal", "timed-out")
    assert nomad.normalize_allocation("running", desired_status="stop").phase == "stopping"
    assert nomad.normalize_allocation("lost") == nomad.AllocationState("unknown", may_repeat=True)
    assert nomad.normalize_allocation(
        "complete", replacement_observed=True
    ) == nomad.AllocationState("unknown", may_repeat=True)
