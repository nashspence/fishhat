from __future__ import annotations

import copy

import pytest
from fishhat_adapters import Registry, check_request, runtime_binding_digest
from fishhat_contracts.validation import ContractError, digest
from fishhat_owner.adapter_state import AdapterCoordinator

from tests.adapter_support import (
    NAMESPACE,
    OWNER,
    SCOPE,
    D,
    binding,
    fresh_observation,
    identifier,
    request,
    runtime_registry,
    runtime_sources,
    service_instance,
    service_request,
)
from tests.test_adapter_effects import coordinator, prepare, result

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
        "fishhat/owner-support/src/fishhat_owner/adapter_state.py",
    ],
    "scope": "accepted runtime identity and delegated mutation authority in a local owner model",
    "relationship": "candidate",
    "reason": "Synthetic canonical native domains test authority joins and durable dispatch ordering; alias resolution, native exclusion and actual service behavior remain unqualified.",
    "claims": [],
}


def delegated(c):
    instance = service_instance(c.registry)
    c.registry.enroll(instance, owner_approved=True)
    return instance


def prepare_service(c, activity="running", **changes):
    values = {
        "operation_id": identifier(8),
        "effect_id": identifier(9),
        "attempt_id": identifier(10),
        "owner_approved": True,
        **runtime_sources(c.registry),
        **changes,
    }
    return c.prepare_service("demo", "service-demo", service_request(activity), **values)


def test_binding_identity_survives_close_and_restore_admission_fences():
    c, _ = coordinator()
    identity = runtime_binding_digest(c.snapshot()["bindings"]["demo"])
    c.close_admission("demo")
    c.restore(c.snapshot())
    current = c.snapshot()["bindings"]["demo"]
    assert current["admission_generation"] == 2
    assert runtime_binding_digest(current) == identity
    assert request()["input"]["deployment"]["binding_digest"] == identity


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject", "other"),
        ("instance", "other-runtime"),
        ("generation", 2),
        ("installation_digest", "sha256:" + "b" * 64),
        ("configuration_digest", "sha256:" + "b" * 64),
        ("scope", {**SCOPE, "handle": "other"}),
        ("native_incarnation", identifier(99)),
        ("instance_generation", 2),
        ("instance_digest", "sha256:" + "b" * 64),
    ],
    ids=[
        "subject",
        "instance",
        "generation",
        "installation-digest",
        "configuration-digest",
        "scope",
        "native-incarnation",
        "instance-generation",
        "instance-digest",
    ],
)
def test_every_stable_binding_field_changes_deployment_identity(field, value):
    original = binding()
    changed = {**original, field: value}
    assert runtime_binding_digest(original) != runtime_binding_digest(changed)


@pytest.mark.parametrize("selector", ["host", "app", "both"])
def test_host_assignment_app_selection_and_binding_must_agree(selector):
    registry, _, _ = runtime_registry()
    sources = runtime_sources(registry)
    if selector in {"host", "both"}:
        sources["host"]["app_accounts"]["demo"]["runtime_instance"] = "other-runtime"
    if selector in {"app", "both"}:
        sources["app"]["runtime"]["instance"] = "other-runtime"
    c = AdapterCoordinator(OWNER, registry, lambda value: None)
    with pytest.raises(ContractError, match="RUNTIME_SELECTION_MISMATCH"):
        c.bind(binding(), **sources, owner_approved=True)
    assert not c.snapshot()["bindings"]


def test_host_source_cannot_replace_enrolled_configuration_during_admission():
    registry, _, _ = runtime_registry()
    sources = runtime_sources(registry)
    sources["host"]["adapter_instances"]["native-demo"]["configuration"]["account"] = "other"
    c = AdapterCoordinator(OWNER, registry, lambda value: None)
    with pytest.raises(ContractError, match="SOURCE_INSTANCE_REBIND_REQUIRED"):
        c.bind(binding(), **sources, owner_approved=True)
    assert not c.snapshot()["bindings"]


def test_deployment_for_another_binding_is_rejected_before_an_attempt_is_committed():
    c, commits = coordinator()
    bad = request()
    bad["input"]["deployment"]["binding_digest"] = runtime_binding_digest(
        {**binding(), "generation": 2}
    )
    before = copy.deepcopy(commits)
    with pytest.raises(ContractError, match="DEPLOYMENT_BINDING_IDENTITY"):
        c.prepare(
            "demo",
            bad,
            **runtime_sources(c.registry),
            operation_id=identifier(8),
            effect_id=identifier(9),
            attempt_id=identifier(10),
            owner_approved=True,
        )
    assert commits == before
    assert not c.snapshot()["attempts"]


@pytest.mark.parametrize("change", ["unchanged", "observe-only", "controller", "namespace"])
def test_runtime_dispatch_rechecks_exact_accepted_mutation_authority_after_restore(change):
    c, _ = coordinator()
    c.close_admission("demo")
    attempt = c.prepare(
        "demo",
        request("deactivate"),
        **runtime_sources(c.registry),
        operation_id=identifier(8),
        effect_id=identifier(9),
        attempt_id=identifier(10),
        owner_approved=True,
    )
    saved = c.snapshot()
    _, descriptor, instance = runtime_registry()
    registry = Registry()
    registry.install(
        {
            "implementation": descriptor["id"],
            "artifact": {"digest": D, "media_type": "application/zip", "size_bytes": 100},
            "descriptor_digest": digest(descriptor),
            "enabled": True,
        },
        descriptor,
        owner_approved=True,
    )
    grant = instance["grants"][0]
    if change == "observe-only":
        grant.update(access=["observe"], mutation=None)
    elif change == "controller":
        controller = copy.deepcopy(instance)
        controller["id"] = "other-runtime"
        controller["grants"][0]["mutation"]["controller"] = "other-runtime"
        registry.enroll(controller, owner_approved=True)
        grant["mutation"]["controller"] = "other-runtime"
    elif change == "namespace":
        grant["mutation"]["namespaces"][0]["resource"] = "reassigned.service"
    registry.enroll(instance, owner_approved=True)
    restored = AdapterCoordinator(OWNER, registry, lambda value: None)
    restored.restore(saved)
    assert restored.snapshot()["attempts"] == saved["attempts"]
    if change == "unchanged":
        assert restored.dispatch("demo", attempt["attempt_id"])["attempt"]["state"] == "dispatched"
    else:
        expected = (
            "STALE_BINDING_AUTHORITY" if change == "namespace" else "RUNTIME_MUTATION_AUTHORITY"
        )
        with pytest.raises(ContractError, match=expected):
            restored.dispatch("demo", attempt["attempt_id"])
        assert restored.snapshot()["attempts"] == saved["attempts"]


def test_binding_without_exact_instance_pin_cannot_be_newly_admitted():
    registry, _, _ = runtime_registry()
    c = AdapterCoordinator(OWNER, registry, lambda value: None)
    value = binding()
    del value["instance_digest"]
    with pytest.raises(ContractError, match="BINDING_AUTHORITY_UNPINNED"):
        c.bind(value, **runtime_sources(registry), owner_approved=True)
    assert not c.snapshot()["bindings"]


@pytest.mark.parametrize("dispatched", [False, True], ids=["prepared", "dispatched"])
@pytest.mark.parametrize(
    "executor_available", [False, True], ids=["executor-absent", "executor-present"]
)
def test_unpinned_binding_preserves_custody_without_inventing_dispatch_authority(
    dispatched, executor_available
):
    c, _ = coordinator()
    c.close_admission("demo")
    attempt = c.prepare(
        "demo",
        request("deactivate"),
        **runtime_sources(c.registry),
        operation_id=identifier(8),
        effect_id=identifier(9),
        attempt_id=identifier(10),
        owner_approved=True,
    )
    if dispatched:
        c.dispatch("demo", attempt["attempt_id"])
    saved = c.snapshot()
    retained_binding = saved["bindings"]["demo"]
    del retained_binding["instance_digest"]
    retained_request = request("deactivate")
    retained_request["input"]["deployment"]["binding_digest"] = runtime_binding_digest(
        retained_binding
    )
    retained_attempt = saved["attempts"][attempt["attempt_id"]]
    retained_attempt["input_digest"] = digest(retained_request)
    saved["requests"][attempt["attempt_id"]] = retained_request
    registry = runtime_registry()[0] if executor_available else Registry()
    restored = AdapterCoordinator(OWNER, registry, lambda value: None)
    restored.restore(saved)
    assert restored.snapshot()["attempts"] == saved["attempts"]
    assert restored.snapshot()["admission"]["demo"] is False
    expected = "BINDING_AUTHORITY_UNPINNED" if executor_available else "UNENROLLED_ADAPTER"
    with pytest.raises(ContractError, match=expected):
        restored.dispatch("demo", attempt["attempt_id"])
    if executor_available:
        with pytest.raises(ContractError, match="BINDING_AUTHORITY_UNPINNED"):
            restored.prepare(
                "demo",
                retained_request,
                **runtime_sources(registry),
                operation_id=identifier(18),
                effect_id=identifier(19),
                attempt_id=identifier(20),
                owner_approved=True,
            )
    if dispatched:
        assert restored.snapshot()["attempts"][attempt["attempt_id"]]["certainty"] == "unknown"
        restored.settle(attempt["attempt_id"], *result(restored, retained_attempt))
    else:
        restored.cancel_prepared(attempt["attempt_id"], owner_approved=True)
    with pytest.raises(ContractError, match="BINDING_AUTHORITY_UNPINNED"):
        restored.observation_request("demo", owner_approved=True)
    with pytest.raises(ContractError, match="QUIESCENCE_REQUIRED"):
        restored.open_admission("demo", owner_approved=True)
    assert restored.snapshot()["quiescent"]["demo"] is False
    assert "instance_digest" not in restored.snapshot()["bindings"]["demo"]


def test_source_drift_blocks_new_work_without_retargeting_an_accepted_attempt():
    c, _ = coordinator()
    accepted = prepare(c)
    changed = runtime_sources(c.registry)
    changed["app"]["runtime"]["instance"] = "other-runtime"
    with pytest.raises(ContractError, match="RUNTIME_SELECTION_MISMATCH"):
        c.prepare(
            "demo",
            request(),
            **changed,
            operation_id=identifier(18),
            effect_id=identifier(19),
            attempt_id=identifier(20),
            owner_approved=True,
        )
    assert (
        c.dispatch("demo", accepted["attempt_id"])["attempt"]["executor"]["instance"]
        == "native-demo"
    )
    assert c.snapshot()["bindings"]["demo"] == binding()


@pytest.mark.parametrize("different_scope", [False, True], ids=["same-scope", "different-scope"])
def test_independent_service_cannot_claim_runtime_lifecycle_namespace(different_scope):
    registry, _, _ = runtime_registry()
    instance = service_instance(registry, controller="service-demo")
    if different_scope:
        instance["grants"][0]["scope"] = {**SCOPE, "kind": "service", "handle": "other"}
    with pytest.raises(ContractError, match="NATIVE_MUTATION_AUTHORITY_CONFLICT"):
        registry.enroll(instance, owner_approved=True)
    with pytest.raises(ContractError, match="UNENROLLED_ADAPTER"):
        registry.inspect_instance(instance["id"])


def test_two_runtime_instances_cannot_independently_own_one_native_namespace():
    registry, _, instance = runtime_registry()
    instance["id"] = "other-runtime"
    instance["grants"][0]["mutation"]["controller"] = instance["id"]
    with pytest.raises(ContractError, match="NATIVE_MUTATION_AUTHORITY_CONFLICT"):
        registry.enroll(instance, owner_approved=True)


def test_lifecycle_and_resource_envelope_can_have_distinct_owners_on_one_resource():
    registry, descriptor, instance = runtime_registry()
    descriptor.update(
        id="independent-author.example-compute",
        roles=["compute"],
        implemented=["compute.set-limits"],
    )
    artifact = "sha256:" + "c" * 64
    registry.install(
        {
            "implementation": descriptor["id"],
            "artifact": {"digest": artifact, "media_type": "application/zip", "size_bytes": 100},
            "descriptor_digest": digest(descriptor),
            "enabled": True,
        },
        descriptor,
        owner_approved=True,
    )
    instance.update(
        id="compute-demo",
        implementation=descriptor["id"],
        role="compute",
        installation_digest=artifact,
    )
    grant = instance["grants"][0]
    grant["scope"] = {**SCOPE, "kind": "allocation"}
    grant["mutation"] = {
        "controller": instance["id"],
        "namespaces": [{**NAMESPACE, "facet": "resource-envelope"}],
    }
    registry.enroll(instance, owner_approved=True)
    assert (
        registry.authorize(
            "compute-demo", "compute", "set-limits", grant["scope"], owner_approved=True
        )
        == instance
    )
    assert (
        registry.authorize("native-demo", "runtime", "activate", SCOPE, owner_approved=True)["id"]
        == "native-demo"
    )


def test_disjoint_service_namespace_can_remain_independently_owned():
    registry, _, _ = runtime_registry()
    instance = service_instance(registry, controller="service-demo")
    instance["grants"][0]["mutation"]["namespaces"][0]["resource"] = "host-agent.service"
    registry.enroll(instance, owner_approved=True)
    assert (
        registry.authorize("service-demo", "service", "set-activity", SCOPE, owner_approved=True)
        == instance
    )


@pytest.mark.parametrize("change", ["controller", "scope", "namespace"])
def test_delegation_cannot_invent_a_controller_or_widen_its_accepted_scope(change):
    registry, _, _ = runtime_registry()
    instance = service_instance(registry)
    grant = instance["grants"][0]
    if change == "controller":
        grant["mutation"]["controller"] = "unknown"
        expected = "UNKNOWN_MUTATION_CONTROLLER"
    elif change == "scope":
        grant["scope"]["handle"] = "other"
        expected = "SCOPE_NOT_GRANTED"
    else:
        grant["mutation"]["namespaces"][0]["resource"] = "other.service"
        expected = "MUTATION_DELEGATION_SCOPE"
    with pytest.raises(ContractError, match=expected):
        registry.enroll(instance, owner_approved=True)


def test_a_subordinate_cannot_become_an_independent_delegation_controller():
    registry, _, _ = runtime_registry()
    instance = service_instance(registry)
    registry.enroll(instance, owner_approved=True)
    instance["id"] = "nested-service"
    instance["grants"][0]["mutation"]["controller"] = "service-demo"
    with pytest.raises(ContractError, match="MUTATION_DELEGATION_SCOPE"):
        registry.enroll(instance, owner_approved=True)


def test_subordinate_cannot_use_generic_authorization_as_a_dispatch_bypass():
    registry, _, _ = runtime_registry()
    registry.enroll(service_instance(registry), owner_approved=True)
    with pytest.raises(ContractError, match="MUTATION_OWNER_REQUIRED"):
        registry.authorize("service-demo", "service", "set-activity", SCOPE, owner_approved=True)


@pytest.mark.parametrize("field", ["controller", "mutation", "runtime_control"])
def test_a_service_request_cannot_supply_its_own_control_authority(field):
    value = service_request()
    value["input"][field] = {"controller": "native-demo"}
    with pytest.raises(ContractError):
        check_request("service", value)


@pytest.mark.parametrize("activity", ["running", "oneshot-complete"])
def test_service_start_and_oneshot_cannot_escape_closed_runtime_admission(activity):
    c, _ = coordinator()
    delegated(c)
    c.close_admission("demo")
    attempt = prepare_service(c, activity)
    with pytest.raises(ContractError, match="ADMISSION_CLOSED"):
        c.dispatch("demo", attempt["attempt_id"])
    stored = c.snapshot()["attempts"][attempt["attempt_id"]]
    assert stored["state"] == "prepared"
    assert stored["certainty"] == "none"


def test_delegated_stop_obeys_containment_gate_and_commits_before_native_dispatch():
    c, commits = coordinator()
    delegated(c)
    attempt = prepare_service(c, "stopped")
    with pytest.raises(ContractError, match="ADMISSION_NOT_CLOSED"):
        c.dispatch("demo", attempt["attempt_id"])
    c.close_admission("demo")
    dispatched = c.dispatch("demo", attempt["attempt_id"])
    assert commits[-1]["attempts"][attempt["attempt_id"]] == dispatched["attempt"]
    assert dispatched["attempt"]["executor"]["instance"] == "service-demo"
    assert dispatched["attempt"]["certainty"] == "unknown"


def test_delegated_service_target_is_confined_to_enrolled_lifecycle_namespace():
    c, _ = coordinator()
    delegated(c)
    value = service_request()
    value["input"]["service"] = "unrelated.service"
    with pytest.raises(ContractError, match="SERVICE_OUTSIDE_MUTATION_NAMESPACE"):
        c.prepare_service(
            "demo",
            "service-demo",
            value,
            **runtime_sources(c.registry),
            operation_id=identifier(8),
            effect_id=identifier(9),
            attempt_id=identifier(10),
            owner_approved=True,
        )
    assert not c.snapshot()["attempts"]


@pytest.mark.parametrize("first", ["runtime", "service"])
def test_runtime_and_service_attempts_cannot_reuse_each_others_identity(first):
    c, _ = coordinator()
    delegated(c)
    if first == "runtime":
        prepare(c)
        replay = prepare_service
    else:
        prepare_service(c)
        replay = prepare
    with pytest.raises(ContractError, match="ATTEMPT_IDENTITY_CONFLICT"):
        replay(c)


def test_delegate_uncertainty_blocks_quiescence_in_the_same_runtime_owner():
    c, _ = coordinator()
    delegated(c)
    attempt = prepare_service(c)
    c.dispatch("demo", attempt["attempt_id"])
    c.close_admission("demo")
    with pytest.raises(ContractError, match="PENDING_NATIVE_WORK"):
        c.observation_request("demo", owner_approved=True)
    c.settle(attempt["attempt_id"], *result(c, attempt))
    c.prove_quiescent("demo", fresh_observation(c), owner_approved=True)
    assert c.snapshot()["quiescent"]["demo"] is True


def test_missing_service_executor_does_not_erase_accepted_uncertain_work_on_restore():
    c, _ = coordinator()
    delegated(c)
    attempt = prepare_service(c)
    c.dispatch("demo", attempt["attempt_id"])
    saved = c.snapshot()
    registry, _, _ = runtime_registry()
    restored = AdapterCoordinator(OWNER, registry, lambda value: None)
    restored.restore(saved)
    state = restored.snapshot()
    assert state["attempts"] == saved["attempts"]
    assert state["attempts"][attempt["attempt_id"]]["certainty"] == "unknown"
    assert state["admission"]["demo"] is False
    with pytest.raises(ContractError, match="PENDING_NATIVE_WORK"):
        restored.observation_request("demo", owner_approved=True)
    with pytest.raises(ContractError, match="INSTANCE_ROLE"):
        restored.dispatch("demo", attempt["attempt_id"])


@pytest.mark.parametrize("changed", ["unchanged", "generation", "configuration"])
def test_restored_service_attempt_stays_pinned_to_accepted_executor_instance(changed):
    c, _ = coordinator()
    delegated(c)
    c.close_admission("demo")
    attempt = prepare_service(c, "stopped")
    saved = c.snapshot()
    registry, _, _ = runtime_registry()
    replacement = service_instance(registry)
    if changed == "generation":
        replacement["generation"] += 1
    elif changed == "configuration":
        replacement["configuration"]["manager_handle"] = "another-manager"
    registry.enroll(replacement, owner_approved=True)
    restored = AdapterCoordinator(OWNER, registry, lambda value: None)
    restored.restore(saved)
    assert restored.snapshot()["attempts"] == saved["attempts"]
    assert restored.snapshot()["admission"]["demo"] is False
    if changed == "unchanged":
        assert restored.dispatch("demo", attempt["attempt_id"])["attempt"]["state"] == "dispatched"
    else:
        with pytest.raises(ContractError, match="STALE_EXECUTOR_INSTANCE"):
            restored.dispatch("demo", attempt["attempt_id"])


def test_retained_service_activity_cannot_be_relabelled_as_a_containment_effect():
    c, _ = coordinator()
    delegated(c)
    attempt = prepare_service(c)
    state = c.snapshot()
    state["attempts"][attempt["attempt_id"]]["runtime_control"]["activity"] = "stopped"
    with pytest.raises(ContractError, match="DELEGATED_INPUT_IDENTITY"):
        c.restore(state)


def test_delegated_record_without_runtime_control_cannot_gain_dispatch_authority():
    c, _ = coordinator()
    delegated(c)
    attempt = prepare_service(c)
    state = c.snapshot()
    del state["attempts"][attempt["attempt_id"]]["runtime_control"]
    with pytest.raises(ContractError, match="RUNTIME_CONTROL_REQUIRED"):
        c.restore(state)
