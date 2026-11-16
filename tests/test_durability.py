"""Deterministic replay economics, not native persistence or effect authority."""

from __future__ import annotations

import math
from copy import deepcopy
from dataclasses import asdict, replace
from itertools import product

import pytest
from fishhat_contracts.discovery import require_v1_decision_reader
from fishhat_contracts.durability import (
    CheckpointCandidate,
    RecoveryBudget,
    RecoveryPolicy,
    checkpoint_decision,
    recovery_policy,
)
from fishhat_contracts.handoffs import schema_identity
from fishhat_contracts.validation import SCHEMAS, ContractError, validate

from tests.linear_support import assert_linear, measure
from tests.support import ROOT

AUTHORITY = "packages/fishhat-contracts/src/fishhat_contracts/contracts/durability.schema.json"
CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [AUTHORITY],
    "scope": "installed recovery configuration and deterministic optional-checkpoint admission",
    "relationship": "scoped-witness",
    "reason": "Independent boundary tables, arithmetic and composed-cost cases challenge the policy. No native authorization, crash consistency, reservation serialization or measured latency is claimed.",
    "claims": [],
}
CHECK_OVERRIDES = {
    name: {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/durability.py#recovery_policy",
            "packages/fishhat-contracts/src/fishhat_contracts/durability.py#checkpoint_decision",
            "release.toml#/engineering",
            AUTHORITY,
        ],
        "scope": "complete scalar policy/decision work over sixteenfold candidate counts",
        "relationship": "scoped-witness",
        "reason": "Actual work is counted for both helpers without a timing threshold or history-sized setup. This does not qualify native checkpoint creation or concurrent accounting.",
        "claims": [
            "engineering:durability.recovery_policy",
            "engineering:durability.checkpoint_decision",
        ],
    }
    for name in ("test_policy_and_candidate_boundaries", "test_candidate_work_is_linear")
}
CHECK_OVERRIDES["test_developer_guide_routes_to_owned_policy"] = {
    "purpose": "repository-policy",
    "authority": ["AGENTS.md", AUTHORITY],
    "scope": "onboarding routes durability decisions to the executable contract and tests",
    "relationship": "no-product-claim",
    "reason": "Text routing prevents an independent informal policy; it proves no runtime behavior.",
    "claims": [],
}


def candidate(saved=120.0, cost=0.2, **changes):
    return replace(
        CheckpointCandidate(
            saved_seconds=saved,
            cost_seconds=cost,
            replay_safe=True,
            consistent_boundary=True,
            storage_admitted=True,
        ),
        **changes,
    )


def test_policy_and_candidate_boundaries():
    policy = recovery_policy()
    assert asdict(policy) == {
        "recovery_mode": "adaptive",
        "replay_target_seconds": 120,
        "max_optional_overhead_fraction": 0.125,
        "max_optional_checkpoints": None,
        "retained_checkpoint_generations": 2,
    }
    assert policy == RecoveryPolicy()
    supplied = asdict(policy)
    decoded = recovery_policy(supplied)
    supplied["recovery_mode"] = "restart"
    assert decoded.recovery_mode == "adaptive"
    assert checkpoint_decision(policy, RecoveryBudget(120), candidate()).action == "checkpoint"
    assert checkpoint_decision(policy, RecoveryBudget(119), candidate(119)).reason == "cheap-replay"
    assert (
        checkpoint_decision(policy, RecoveryBudget(120), candidate(120, 30)).reason
        == "insufficient-local-value"
    )
    assert (
        checkpoint_decision(policy, RecoveryBudget(210), candidate(210, 30)).action
        == "checkpoint"
    )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("recovery_mode", "fast"),
        ("replay_target_seconds", 0),
        ("replay_target_seconds", -1),
        ("replay_target_seconds", True),
        ("replay_target_seconds", "120"),
        ("replay_target_seconds", float("nan")),
        ("replay_target_seconds", float("inf")),
        ("max_optional_overhead_fraction", -0.1),
        ("max_optional_overhead_fraction", 1),
        ("max_optional_overhead_fraction", float("inf")),
        ("max_optional_checkpoints", -1),
        ("max_optional_checkpoints", True),
        ("max_optional_checkpoints", 1.5),
        ("max_optional_checkpoints", 9_007_199_254_740_992),
        ("retained_checkpoint_generations", 1),
        ("retained_checkpoint_generations", True),
        ("retained_checkpoint_generations", None),
    ],
    ids=[
        "mode",
        "zero-target",
        "negative-target",
        "boolean-target",
        "string-target",
        "nan-target",
        "infinite-target",
        "negative-fraction",
        "unit-fraction",
        "infinite-fraction",
        "negative-cap",
        "boolean-cap",
        "fractional-cap",
        "inexact-cap",
        "missing-predecessor",
        "boolean-retention",
        "unknown-retention",
    ],
)
def test_policy_rejects_invalid_configuration(key, value):
    source = asdict(RecoveryPolicy()) | {key: value}
    with pytest.raises(ContractError):
        recovery_policy(source)
    with pytest.raises(ContractError):
        RecoveryPolicy(**source)


def test_policy_is_closed_and_never_a_request_permission():
    source = asdict(RecoveryPolicy())
    with pytest.raises(ContractError):
        recovery_policy(source | {"authorize_effects": True})
    del source["recovery_mode"]
    with pytest.raises(ContractError):
        recovery_policy(source)
    # Policy knobs are not added to wire parameters or admitted source fields.
    for name in ("ssh-request.schema.json", "source.schema.json"):
        assert "RecoveryPolicy" not in SCHEMAS[name].get("$defs", {})


@pytest.mark.parametrize("number", [-1, float("nan"), float("inf"), True, "1", -(10**400)])
def test_scalar_context_rejects_nonfinite_or_coerced_costs(number):
    for factory in (
        lambda: RecoveryBudget(useful_seconds=number),
        lambda: RecoveryBudget(charged_seconds=number),
        lambda: RecoveryBudget(reserved_seconds=number),
        lambda: CheckpointCandidate(saved_seconds=number),
        lambda: CheckpointCandidate(cost_seconds=number),
        lambda: CheckpointCandidate(remaining_seconds=number),
    ):
        with pytest.raises(ContractError):
            factory()


def test_flags_and_counts_are_not_truthy_claims():
    for factory in (
        lambda: RecoveryBudget(attempts=True),
        lambda: RecoveryBudget(accounting_complete=1),
        lambda: candidate(replay_safe="yes"),
        lambda: candidate(consistent_boundary=1),
        lambda: candidate(storage_admitted=1),
        lambda: candidate(domain_in_flight=0),
    ):
        with pytest.raises(ContractError):
            factory()
    with pytest.raises(ContractError):
        checkpoint_decision(RecoveryPolicy(), RecoveryBudget(), candidate(), completion_ready=1)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"replay_safe": False}, "not-replay-safe"),
        ({"consistent_boundary": False}, "no-consistent-generation"),
        ({"storage_admitted": False}, "storage-unavailable"),
        ({"domain_in_flight": True}, "domain-checkpoint-in-flight"),
        ({"cost_seconds": None}, "unknown-cost"),
        ({"remaining_seconds": 0.2}, "finish-before-saving"),
        ({"remaining_seconds": 0}, "finish-before-saving"),
    ],
    ids=["effects", "inconsistent", "capacity", "in-flight", "unknown-cost", "near-end", "done"],
)
def test_ineligible_candidates_continue_without_a_checkpoint(changes, reason):
    result = checkpoint_decision(RecoveryPolicy(), RecoveryBudget(1000), candidate(**changes))
    assert (result.action, result.reason) == ("continue", reason)


@pytest.mark.parametrize(
    "policy",
    [
        RecoveryPolicy(recovery_mode="restart"),
        RecoveryPolicy(max_optional_overhead_fraction=0),
        RecoveryPolicy(max_optional_checkpoints=0),
    ],
    ids=["restart", "zero-budget", "zero-count"],
)
def test_disabled_optional_recovery_never_blocks_required_work(policy):
    budget = RecoveryBudget(1000, charged_seconds=1000, accounting_complete=False)
    probe = CheckpointCandidate()  # Unknown, unsafe and unadmitted for optional recovery.
    assert checkpoint_decision(policy, budget, probe).action == "continue"
    assert (
        checkpoint_decision(policy, budget, probe, completion_ready=True).action
        == "required-work"
    )
    assert (
        checkpoint_decision(policy, budget, probe, required_anchor_ready=True).action
        == "required-work"
    )


def test_exact_default_boundary_and_no_overflow():
    policy = RecoveryPolicy()
    assert (
        checkpoint_decision(policy, RecoveryBudget(210), candidate(210, 30)).action
        == "checkpoint"
    )
    assert (
        checkpoint_decision(
            policy, RecoveryBudget(210), candidate(210, math.nextafter(30, math.inf))
        ).action
        == "continue"
    )
    assert (
        checkpoint_decision(
            policy, RecoveryBudget(210), candidate(math.nextafter(210, 0), 30)
        ).action
        == "continue"
    )
    assert (
        checkpoint_decision(policy, RecoveryBudget(120), candidate(120, 0)).action
        == "checkpoint"
    )
    # Large finite inputs must not overflow intermediate arithmetic into inf <= inf.
    huge = checkpoint_decision(policy, RecoveryBudget(1e308), candidate(1e308, 1e308))
    assert huge.reason == "insufficient-local-value"
    debt = checkpoint_decision(policy, RecoveryBudget(1e308, 1e308, 1e308), candidate(1e308, 1))
    assert debt.reason == "insufficient-shared-budget"


def test_integer_oracle_for_replay_value_and_shared_budget():
    policy = RecoveryPolicy()
    for saved, cost, useful, charged, reserved in product(
        (0, 119, 120, 210, 1000),
        (0, 1, 20, 30, 200),
        (120, 210, 1000),
        (0, 20, 100),
        (0, 20),
    ):
        result = checkpoint_decision(
            policy, RecoveryBudget(useful, charged, reserved), candidate(saved, cost)
        )
        expected = (
            120 <= saved <= useful
            and 7 * cost <= saved
            and 7 * (charged + reserved + cost) <= useful
        )
        assert (result.action == "checkpoint") == expected


@pytest.mark.parametrize(
    ("beta", "saved", "cost"),
    [(0.1, 135, 15), (0.2, 120, 30), (0.5, 120, 120)],
    ids=["tenth", "fifth", "half"],
)
def test_nondefault_fraction_uses_total_time_denominator(beta, saved, cost):
    policy = RecoveryPolicy(max_optional_overhead_fraction=beta)
    budget = RecoveryBudget(saved)
    assert checkpoint_decision(policy, budget, candidate(saved, cost)).action == "checkpoint"
    assert (
        checkpoint_decision(
            policy, budget, candidate(saved, math.nextafter(cost, math.inf))
        ).action
        == "continue"
    )
    assert (
        checkpoint_decision(
            policy, replace(budget, charged_seconds=1), candidate(saved, cost)
        ).reason
        == "insufficient-shared-budget"
    )


def test_reserved_failed_cost_and_limits_are_not_fresh_phase_budgets():
    policy = RecoveryPolicy(max_optional_checkpoints=2)
    budget = RecoveryBudget(210)
    probe = candidate(210, 20)
    assert checkpoint_decision(policy, budget, probe).action == "checkpoint"
    reserved = replace(budget, reserved_seconds=20, attempts=1)
    assert checkpoint_decision(policy, reserved, probe).reason == "insufficient-shared-budget"
    failed = replace(reserved, reserved_seconds=0, charged_seconds=20)
    assert checkpoint_decision(policy, failed, probe).reason == "insufficient-shared-budget"
    later = replace(failed, useful_seconds=420)
    assert checkpoint_decision(policy, later, probe).action == "checkpoint"
    assert checkpoint_decision(policy, replace(later, attempts=2), probe).reason == "attempt-limit"
    assert (
        checkpoint_decision(policy, replace(later, accounting_complete=False), probe).reason
        == "unreconciled-accounting"
    )
    assert checkpoint_decision(policy, RecoveryBudget(10), probe).reason == "uncredited-replay"


def test_overrun_debt_defers_optional_work_without_resetting_frontier():
    policy = RecoveryPolicy()
    budget = RecoveryBudget(210, charged_seconds=40, attempts=1)
    assert (
        checkpoint_decision(policy, budget, candidate(210, 1)).reason
        == "insufficient-shared-budget"
    )
    assert (
        checkpoint_decision(policy, replace(budget, useful_seconds=287), candidate(210, 1)).action
        == "checkpoint"
    )
    assert (
        checkpoint_decision(policy, budget, candidate(), required_anchor_ready=True).action
        == "required-work"
    )


def execute_model(seconds, cost, policy):
    """Independent serial model: saves protect completed work, not semantic validity."""
    frontier = 0
    budget = RecoveryBudget()
    saves = []
    result = 0
    for elapsed in range(1, seconds + 1):
        result += elapsed
        budget = replace(budget, useful_seconds=elapsed)
        decision = checkpoint_decision(
            policy,
            budget,
            candidate(elapsed - frontier, cost, remaining_seconds=seconds - elapsed),
            completion_ready=elapsed == seconds,
        )
        if decision.action == "checkpoint":
            # The model completes an admitted save immediately. Native reservation,
            # publication and fault handling require their own integration witnesses.
            budget = replace(
                budget,
                charged_seconds=budget.charged_seconds + cost,
                attempts=budget.attempts + 1,
            )
            frontier = elapsed
            saves.append(elapsed)
    return result, saves, budget


@pytest.mark.parametrize(
    ("seconds", "cost", "saves"),
    [
        (30, 0.2, []),
        (120, 0.2, []),
        (600, 0.2, [120, 240, 360, 480]),
        (600, 30, [210, 420]),
    ],
    ids=["small", "terminal-priority", "long-cheap-save", "long-expensive-save"],
)
def test_adaptive_and_restart_execute_identical_complete_work(seconds, cost, saves):
    adaptive = execute_model(seconds, cost, RecoveryPolicy())
    restart = execute_model(seconds, cost, RecoveryPolicy(recovery_mode="restart"))
    assert adaptive[0] == restart[0] == seconds * (seconds + 1) // 2
    assert adaptive[1] == saves
    assert restart[1] == []
    assert 7 * adaptive[2].charged_seconds <= adaptive[2].useful_seconds


def test_attempt_cap_reduces_recovery_not_complete_extent():
    result, saves, _ = execute_model(600, 0.2, RecoveryPolicy(max_optional_checkpoints=1))
    assert saves == [120]
    assert result == 600 * 601 // 2


def test_candidate_work_is_linear():
    samples = []
    for count in (4, 16, 64):
        source = asdict(RecoveryPolicy())
        budget, probe = RecoveryBudget(210), candidate(210, 30)

        def run():
            for _ in range(count):
                assert (
                    checkpoint_decision(recovery_policy(source), budget, probe).action
                    == "checkpoint"
                )

        _, work = measure(run)
        samples.append((count, work))
    assert_linear(samples)


@pytest.mark.parametrize(
    "name",
    [
        "ssh-request.schema.json",
        "ssh-response.schema.json",
        "cli-output.schema.json",
        "source.schema.json",
        "records.schema.json",
        "adapter.schema.json",
        "workflow.schema.json",
        "workflow-journal.schema.json",
    ],
)
def test_installed_boundaries_include_the_common_policy(name):
    assert (
        "durability.schema.json#/$defs/RecoveryPolicy"
        in SCHEMAS[name]["x-fishhat-contract-dependencies"]
    )
    # Reachable Rules are part of the policy's installed schema identity, not a request claim.
    assert SCHEMAS["durability.schema.json"]["x-fishhat-contract-dependencies"] == ["#/$defs/Rules"]


def test_rules_and_defaults_change_installed_policy_identity_without_changing_frozen_reader(
    monkeypatch,
):
    uri = SCHEMAS["durability.schema.json"]["$id"] + "#/$defs/RecoveryPolicy"
    original = schema_identity(uri)
    source = deepcopy(SCHEMAS["durability.schema.json"])
    document = deepcopy(source)
    document["$defs"]["Rules"]["const"]["admission"] += " different policy"
    monkeypatch.setitem(SCHEMAS, "durability.schema.json", document)
    assert schema_identity(uri) != original
    require_v1_decision_reader()
    document = deepcopy(source)
    document["$defs"]["RecoveryPolicy"]["default"]["replay_target_seconds"] = 240
    monkeypatch.setitem(SCHEMAS, "durability.schema.json", document)
    assert schema_identity(uri) != original
    assert recovery_policy().replay_target_seconds == 240
    require_v1_decision_reader()
    # Common primitives, introduced state and historical readers are not rewritten.
    assert "x-fishhat-contract-dependencies" not in SCHEMAS["owner-decision-v1.schema.json"]


def test_policy_schema_and_python_ranges_agree():
    for beta in (0, 0.01, 0.125, 0.9):
        source = asdict(RecoveryPolicy(max_optional_overhead_fraction=beta))
        validate("durability.schema.json", source, "RecoveryPolicy")
        assert recovery_policy(source) == RecoveryPolicy(**source)


def test_developer_guide_routes_to_owned_policy():
    guide = (ROOT / "AGENTS.md").read_text()
    assert "contracts/durability.schema.json" in guide
    assert "fishhat_contracts/durability.py" in guide
    assert "tests/test_durability.py" in guide
    assert "a yield or internal phase does not automatically require a durable cursor" in guide
    assert (
        "Long operations progress through bounded steps that can resume after interruption."
        not in guide
    )
