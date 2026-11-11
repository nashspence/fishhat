"""Every native process needs independent current admission before any launch."""

from copy import deepcopy

import pytest
from fishhat_adapters.process import validate_process_launch
from fishhat_contracts.validation import ContractError

from tests.adapter_support import D, identifier
from tests.test_adapter_process import invocation, launch

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter-process.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-admission.schema.json",
    ],
    "scope": "required process admission and independent current owner record joins",
    "relationship": "candidate",
    "reason": "Synthetic launch validation; no native ledger, scheduler or process containment.",
    "claims": [],
}


def case():
    call, installation, descriptor, configuration = invocation()
    manifest, payload = launch(call, configuration)
    kwargs = {
        "descriptor": descriptor,
        "approved_installation": installation,
        "expected_executor": call["attempt"]["executor"],
        "expected_private_use": None,
        "expected_execution_admission": deepcopy(manifest["execution_admission"]),
    }
    return manifest, payload, configuration, kwargs


def test_control_launch_requires_explicit_finite_independent_budget():
    manifest, payload, configuration, kwargs = case()
    assert "scheduler" not in manifest["execution_admission"]["domain"]
    validate_process_launch(manifest, payload, configuration, **kwargs)
    del manifest["execution_admission"]
    with pytest.raises(ContractError):
        validate_process_launch(manifest, payload, configuration, **kwargs)


@pytest.mark.parametrize(
    "field", ["use_id", "host", "request_digest", "policy_digest", "admission_generation"]
)
def test_manifest_cannot_substitute_owner_launch_custody(field):
    manifest, payload, configuration, kwargs = case()
    admission = manifest["execution_admission"]
    if field == "use_id":
        admission[field] = identifier(702)
    elif field == "host":
        admission[field] = "node-b"
    elif field == "admission_generation":
        admission[field] += 1
    else:
        admission[field] = "sha256:" + "b" * 64
    with pytest.raises(ContractError):
        validate_process_launch(manifest, payload, configuration, **kwargs)


def use_workload_grant(admission):
    admission.update(
        {
            "class": "workload",
            "control_budget": None,
            "grant": {"id": identifier(703), "generation": 1, "digest": D},
        }
    )
    scheduler = deepcopy(admission["executor"])
    scheduler.update(
        instance="synthetic-scheduler",
        role="scheduler",
        scope={
            "authority": admission["domain"]["owner"]["id"],
            "kind": "allocation",
            "handle": admission["domain"]["capacity_domain"],
        },
    )
    admission["domain"]["scheduler"] = scheduler


def test_old_process_record_cannot_reuse_withdrawn_grant():
    manifest, payload, configuration, kwargs = case()
    admission = manifest["execution_admission"]
    use_workload_grant(admission)
    kwargs["expected_execution_admission"] = deepcopy(admission)
    validate_process_launch(manifest, payload, configuration, **kwargs)
    kwargs["expected_execution_admission"]["grant"]["generation"] += 1
    with pytest.raises(ContractError, match="PROCESS_ADMISSION_NOT_APPROVED"):
        validate_process_launch(manifest, payload, configuration, **kwargs)


def test_even_owner_selected_control_budget_must_be_finite_and_consistent():
    manifest, payload, configuration, kwargs = case()
    budget = manifest["execution_admission"]["control_budget"]
    budget["limits"]["memory_max_bytes"] = budget["maximum"]["memory_bytes"] + 1
    kwargs["expected_execution_admission"] = deepcopy(manifest["execution_admission"])
    with pytest.raises(ContractError, match="PROCESS_CONTROL_BUDGET"):
        validate_process_launch(manifest, payload, configuration, **kwargs)


def test_reconciliation_has_a_fresh_control_admission_without_changing_original_effect():
    call, installation, descriptor, configuration = invocation()
    original = deepcopy(call)
    mutation_manifest, _ = launch(call, configuration)
    manifest, payload = launch(call, configuration, mode="query")
    kwargs = {
        "descriptor": descriptor,
        "approved_installation": installation,
        "expected_executor": call["attempt"]["executor"],
        "expected_private_use": None,
        "expected_execution_admission": deepcopy(manifest["execution_admission"]),
        "retained_invocation": call,
    }
    validate_process_launch(manifest, payload, configuration, **kwargs)
    assert call == original
    manifest["execution_admission"] = mutation_manifest["execution_admission"]
    with pytest.raises(ContractError):
        validate_process_launch(manifest, payload, configuration, **kwargs)


@pytest.mark.parametrize("restored_epoch", [False, True], ids=["current", "restored"])
def test_reconciliation_cannot_depend_on_workload_admission(restored_epoch):
    call, installation, descriptor, configuration = invocation()
    manifest, payload = launch(call, configuration, mode="query")
    admission = manifest["execution_admission"]
    use_workload_grant(admission)
    if restored_epoch:
        admission["owner"]["epoch"] = identifier(704)
    with pytest.raises(ContractError, match="PROCESS_CONTROL_ADMISSION_REQUIRED"):
        validate_process_launch(
            manifest,
            payload,
            configuration,
            descriptor=descriptor,
            approved_installation=installation,
            expected_executor=call["attempt"]["executor"],
            expected_private_use=None,
            expected_execution_admission=deepcopy(admission),
            retained_invocation=call,
        )
