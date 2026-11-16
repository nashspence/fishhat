"""Owner-selected recovery economics, not authority to persist, resume or execute.

The installed durability schema owns the normative rules. These bounded pure
checks consume independently measured owner context; they do not authenticate
it, allocate storage, implement a journal, or promise native crash safety. Run
required acceptance/effect/settlement work independently of optional scheduling.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Literal

from .bounds import Bounds, bounds
from .validation import SCHEMAS, ContractError, validate

_MAX_COUNTER = 9_007_199_254_740_991


def _seconds(value: int | float, name: str) -> None:
    if (
        type(value) not in (int, float)
        or (type(value) is int and abs(value) > _MAX_COUNTER)
        or not math.isfinite(value)
        or value < 0
    ):
        raise ContractError("invalid recovery " + name)


def _counter(value: int, name: str) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_COUNTER:
        raise ContractError("invalid recovery " + name)


def _flag(value: bool, name: str) -> None:
    if type(value) is not bool:
        raise ContractError("invalid recovery " + name)


def _amount(value: int | float) -> Fraction:
    # Fixed-size interoperable numbers only. Compare decimal quantities exactly,
    # without float overflow, division by beta, or repeated JSON serialization.
    return Fraction(str(value))


@dataclass(frozen=True)
class RecoveryPolicy:
    """Trusted installed-owner configuration; never a submitted authority claim."""

    recovery_mode: str = "adaptive"
    replay_target_seconds: float = 120.0
    max_optional_overhead_fraction: float = 0.125
    max_optional_checkpoints: int | None = None
    retained_checkpoint_generations: int = 2

    def __post_init__(self) -> None:
        if type(self.recovery_mode) is not str or self.recovery_mode not in ("adaptive", "restart"):
            raise ContractError("invalid recovery mode")
        _seconds(self.replay_target_seconds, "target")
        if self.replay_target_seconds <= 0:
            raise ContractError("recovery target must be positive")
        _seconds(self.max_optional_overhead_fraction, "fraction")
        if self.max_optional_overhead_fraction >= 1:
            raise ContractError("recovery fraction must be less than one")
        if self.max_optional_checkpoints is not None:
            _counter(self.max_optional_checkpoints, "checkpoint limit")
        _counter(self.retained_checkpoint_generations, "retention")
        if self.retained_checkpoint_generations < 2:
            raise ContractError("recovery retention must preserve a predecessor")


@dataclass(frozen=True)
class RecoveryBudget:
    """One logical-execution allocation, not a new allowance per phase or worker.

    `attempts` includes already reserved/started optional saves, including failed
    saves. Reserved cost includes outstanding lifecycle work. A caller must use
    exclusive current accounting and reserve before acting on a decision; this
    value is not a concurrency primitive or a bearer grant. Incomplete restored
    accounting disables optional saves until conservatively reconciled.
    """

    useful_seconds: float = 0.0
    charged_seconds: float = 0.0
    reserved_seconds: float = 0.0
    attempts: int = 0
    accounting_complete: bool = True

    def __post_init__(self) -> None:
        _seconds(self.useful_seconds, "useful time")
        _seconds(self.charged_seconds, "charged time")
        _seconds(self.reserved_seconds, "reserved time")
        _counter(self.attempts, "attempt count")
        _flag(self.accounting_complete, "accounting completeness")


@dataclass(frozen=True)
class CheckpointCandidate:
    """Net saved replay and incremental lifecycle cost at one safe boundary.

    A missing cost or remaining-time estimate is unknown, not zero. Positive
    flags require independent owner proofs; setting them does not provide those
    proofs. The default is ineligible. A mandatory backup, continuity checkpoint
    or authoritative effect receipt is not a candidate for this policy.
    """

    saved_seconds: float = 0.0
    cost_seconds: float | None = None
    remaining_seconds: float | None = None
    replay_safe: bool = False
    consistent_boundary: bool = False
    storage_admitted: bool = False
    domain_in_flight: bool = False

    def __post_init__(self) -> None:
        _seconds(self.saved_seconds, "saved time")
        if self.cost_seconds is not None:
            _seconds(self.cost_seconds, "cost")
        if self.remaining_seconds is not None:
            _seconds(self.remaining_seconds, "remaining time")
        for name in ("replay_safe", "consistent_boundary", "storage_admitted", "domain_in_flight"):
            _flag(getattr(self, name), name)


@dataclass(frozen=True)
class CheckpointDecision:
    """Scheduling result only; never acceptance, an effect permit or a receipt."""

    action: Literal["required-work", "continue", "checkpoint"]
    reason: str


def _policy_bounds(name: str) -> Bounds:
    return Bounds(
        id="durability." + name,
        work=(
            "O(B) for the complete fixed-shape policy; O(1) per scalar decision, "
            "O(K) for K candidate boundaries, with no history traversal or I/O"
        ),
        extent="No collection bound; optional count/retention limits affect derived saves only",
        limits=(),
        capacity=("Snapshot resources and actual durable primitives remain owner-admitted",),
        proofs=("tests/test_durability.py::test_policy_and_candidate_boundaries",),
        linear_proofs=("tests/test_durability.py::test_candidate_work_is_linear",),
    )


@bounds(_policy_bounds("recovery_policy"))
def recovery_policy(value: dict[str, Any] | None = None) -> RecoveryPolicy:
    """Decode closed owner-selected configuration; None selects installed defaults.

    Validate once at owner admission/configuration load, not per semantic record.
    The effective policy is retained with existing authority/accounting anchors,
    outside accepted payload identities. Historical policy is not current authority.
    """
    selected = (
        SCHEMAS["durability.schema.json"]["$defs"]["RecoveryPolicy"]["default"]
        if value is None
        else value
    )
    validate("durability.schema.json", selected, "RecoveryPolicy")
    # JSON integers include integral floats. Normalize only after schema admission
    # so invalid types, fractions and out-of-range counts are never coerced.
    decoded = dict(selected)
    for name in ("max_optional_checkpoints", "retained_checkpoint_generations"):
        if decoded[name] is not None:
            decoded[name] = int(decoded[name])
    return RecoveryPolicy(**decoded)


@bounds(_policy_bounds("checkpoint_decision"))
def checkpoint_decision(
    policy: RecoveryPolicy,
    budget: RecoveryBudget,
    candidate: CheckpointCandidate,
    *,
    completion_ready: bool = False,
    required_anchor_ready: bool = False,
) -> CheckpointDecision:
    """Apply the budgeted replay-exposure heuristic without performing a save.

    S is net completed replay saved; C is the complete incremental save cost;
    U is once-credited useful elapsed work; O is charged plus reserved optional
    cost. At beta=1/8, both 7*C <= S and 7*(O+C) <= U must hold, in addition
    to S >= 120 seconds. An eligible result must be rechecked/reserved under
    the existing owner exclusion before creation; never act on a stale copy.
    Mandatory work is not conditional on this helper or its cost telemetry.
    """
    _flag(completion_ready, "completion readiness")
    _flag(required_anchor_ready, "anchor readiness")
    if completion_ready or required_anchor_ready:
        return CheckpointDecision("required-work", "completion-or-authoritative-anchor")
    reason = _ineligible(policy, budget, candidate)
    if reason is not None:
        return CheckpointDecision("continue", reason)
    assert candidate.cost_seconds is not None
    saved = _amount(candidate.saved_seconds)
    useful = _amount(budget.useful_seconds)
    cost = _amount(candidate.cost_seconds)
    beta = _amount(policy.max_optional_overhead_fraction)
    optional = _amount(budget.charged_seconds) + _amount(budget.reserved_seconds)
    if saved > useful:
        return CheckpointDecision("continue", "uncredited-replay")
    if saved < _amount(policy.replay_target_seconds):
        return CheckpointDecision("continue", "cheap-replay")
    if candidate.remaining_seconds is not None and _amount(candidate.remaining_seconds) <= cost:
        return CheckpointDecision("continue", "finish-before-saving")
    if cost * (1 - beta) > beta * saved:
        return CheckpointDecision("continue", "insufficient-local-value")
    if (optional + cost) * (1 - beta) > beta * useful:
        return CheckpointDecision("continue", "insufficient-shared-budget")
    return CheckpointDecision("checkpoint", "budgeted-replay-exposure")


def _ineligible(
    policy: RecoveryPolicy, budget: RecoveryBudget, candidate: CheckpointCandidate
) -> str | None:
    if policy.recovery_mode == "restart" or policy.max_optional_overhead_fraction == 0:
        return "optional-recovery-disabled"
    if (
        policy.max_optional_checkpoints is not None
        and budget.attempts >= policy.max_optional_checkpoints
    ):
        return "attempt-limit"
    if not budget.accounting_complete:
        return "unreconciled-accounting"
    if not candidate.replay_safe:
        return "not-replay-safe"
    if not candidate.consistent_boundary:
        return "no-consistent-generation"
    if not candidate.storage_admitted:
        return "storage-unavailable"
    if candidate.domain_in_flight:
        return "domain-checkpoint-in-flight"
    if candidate.cost_seconds is None:
        return "unknown-cost"
    return None
