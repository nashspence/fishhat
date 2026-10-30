"""Offline host.apply comparisons; native observation and custody belong to executors."""

from __future__ import annotations

from collections.abc import Mapping, Set
from dataclasses import dataclass, field
from hmac import compare_digest
from typing import Any

from .bounds import Bounds, bounds
from .validation import ContractError, validate_plan


@dataclass(frozen=True)
class ProtectedHostPreimage:
    """Independently loaded owner-private custody, never a wire observation.

    The native executor authenticates the reference, retains the complete
    immutable projection and excludes concurrent edits before constructing this
    value. A caller-created instance establishes none of those native facts.
    Projection bytes are intentionally absent from the representation.
    """

    reference: dict[str, Any]
    projection: bytes = field(repr=False)


@dataclass(frozen=True)
class ProtectedHostCapture:
    """Independently verified private or encrypted recovery custody."""

    reference: dict[str, Any]
    projection: bytes = field(repr=False)


def validate_host_preimages(plan: dict[str, Any]) -> None:
    """Check joins after Plan schema validation, in linear work over its effects."""
    if plan["subject"]["action"] != "host.apply":
        return
    preimages = {item["effect_step"]: item for item in plan["host_preimages"]}
    if len(preimages) != len(plan["host_preimages"]):
        raise ContractError("duplicate host preimage step")
    effects = {effect["step"]: effect for effect in plan["effects"]}
    if set(preimages) != set(effects):
        raise ContractError("host preimages must cover every effect exactly")
    for item in preimages.values():
        if item["disclosure"] == "public":
            if item["disposition"] == "preserve" and item["proposed_digest"] != item["live_digest"]:
                raise ContractError("preserved live state differs from proposed state")
            continue
        effect = effects[item["effect_step"]]
        references = [item[role] for role in ("baseline", "live", "proposed")]
        if item["capture"] is not None:
            references.append(item["capture"])
            if item["capture"]["live"] != item["live"]:
                raise ContractError("protected capture must bind the reviewed live reference")
        for reference in references:
            if (
                reference["owner"] != effect["executor"]
                or reference["resource"] != effect["resource"]
                or reference["effect_step"] != effect["step"]
            ):
                raise ContractError("protected host reference is outside the exact effect scope")


@bounds(
    Bounds(
        id="host-preimages.current",
        work="O(B) reviewed Plan metadata and referenced private projection bytes; indexed custody lookups per effect",
        extent="Every reviewed effect and complete private projection/capture; no total collection or private-content cap",
        limits=(),
        capacity=("owner-admitted complete private projection custody",),
        proofs=("tests/test_confidential_host_preimages.py::test_private_comparison_linear_work",),
        linear_proofs=(
            "tests/test_confidential_host_preimages.py::test_private_comparison_linear_work",
        ),
    )
)
def require_current_host_preimages(
    plan: dict[str, Any],
    current_by_step: Mapping[str, str | bytes],
    verified_captures: Mapping[str, tuple[str, str]] | None = None,
    *,
    confidential_steps: Set[str],
    protected_preimages: Mapping[str, ProtectedHostPreimage] | None = None,
    protected_captures: Mapping[str, ProtectedHostCapture] | None = None,
) -> None:
    """Compare owner-supplied observations and verified custody with a reviewed plan.

    confidential_steps is independently classified by the native executor, both
    before publication of a Plan and again before mutation. Secret-bearing or
    unclassified scopes require confidential references. The Plan cannot grant
    permission to disclose hashes or classify its own native contents as public.

    Public capture values are (artifact digest, captured live digest). Private
    references resolve by opaque ID to separately authenticated retained bytes;
    neither the Plan nor wire input may populate those stores. Current private
    observations are projection bytes, not publicly guessable content hashes.
    Missing custody, changed scope or epoch, or changed bytes reject. Preserve
    compares live/proposed bytes privately, without exposing an equality digest.
    Capture requires exact private or encrypted recovery custody, never an
    ordinary source proposal. Neither supplied facts nor a successful comparison
    establish native authority, encryption, durability or source adoption.
    The executor must hold native exclusion or supply an equivalent atomic check
    through each mutation, and recheck after interruption. This pure batch check
    performs no reads, captures, writes, admission or source adoption.
    """
    validate_plan(plan)
    if plan["subject"]["action"] != "host.apply":
        raise ContractError("host preimage check requires a host.apply plan")
    preimages = {item["effect_step"]: item for item in plan["host_preimages"]}
    private_steps = {
        step for step, item in preimages.items() if item["disclosure"] == "confidential"
    }
    if set(confidential_steps) != private_steps:
        raise ContractError("host preimage disclosure differs from independent classification")
    if set(current_by_step) != set(preimages):
        raise ContractError("current host preimages must cover every effect exactly")
    captures = {} if verified_captures is None else verified_captures
    capture_steps = {
        step
        for step, item in preimages.items()
        if item["disposition"] == "capture" and item["disclosure"] == "public"
    }
    if set(captures) != capture_steps:
        raise ContractError("verified captures must cover capture dispositions exactly")
    private_captures = {} if protected_captures is None else protected_captures
    private_capture_steps = {
        step for step in private_steps if preimages[step]["disposition"] == "capture"
    }
    if set(private_captures) != private_capture_steps:
        raise ContractError(
            "protected captures must cover confidential capture dispositions exactly"
        )
    private_store = {} if protected_preimages is None else protected_preimages
    for step, item in preimages.items():
        if item["disclosure"] == "confidential":
            _require_private_preimage(item, current_by_step[step], private_store, private_captures)
            continue
        if current_by_step[step] != item["live_digest"]:
            raise ContractError("live host state changed after review")
        if item["disposition"] == "capture" and captures[step] != (
            item["capture_digest"],
            item["live_digest"],
        ):
            raise ContractError("capture does not preserve reviewed live state")


def _require_private_preimage(
    item: dict[str, Any],
    current: str | bytes,
    store: Mapping[str, ProtectedHostPreimage],
    captures: Mapping[str, ProtectedHostCapture],
) -> None:
    projections: dict[str, bytes] = {}
    for role in ("baseline", "live", "proposed"):
        reference = item[role]
        retained = store.get(reference["id"])
        if (
            retained is None
            or retained.reference != reference
            or type(retained.projection) is not bytes
        ):
            raise ContractError("protected host preimage custody is absent or misbound")
        projections[role] = retained.projection
    if type(current) is not bytes or not compare_digest(current, projections["live"]):
        raise ContractError("live host state changed after review")
    if item["disposition"] == "preserve" and not compare_digest(
        projections["proposed"], projections["live"]
    ):
        raise ContractError("preserved live state differs from proposed state")
    if item["disposition"] == "capture":
        capture = captures[item["effect_step"]]
        if (
            capture.reference != item["capture"]
            or type(capture.projection) is not bytes
            or not compare_digest(capture.projection, projections["live"])
        ):
            raise ContractError("protected capture does not preserve reviewed live state")
