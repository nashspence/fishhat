"""Cutover evidence and independent owner approval for one resource and target state."""

from collections.abc import Mapping, Set
from typing import Any

from .validation import ContractError, digest, validate

GATED_STATES = {"ready", "cutting-over", "accepted"}


def validate_readiness(packet: dict[str, Any]) -> None:
    """Check internal consistency. Current cutover eligibility requires receiver context."""
    validate("readiness.schema.json", packet)
    if packet["state"] not in GATED_STATES:
        return
    if packet["old_owner"] == packet["new_owner"]:
        raise ContractError("readiness requires distinct owners")
    for case in packet["required_cases"]:
        result = packet["case_evidence"].get(case)
        if result is None or result["status"] not in {"passed", "not_applicable"}:
            raise ContractError("missing or unsuccessful required readiness case")


def require_readiness(
    packet: dict[str, Any],
    *,
    expected_resource: dict[str, Any],
    expected_state: str,
    approved_packet_digest: str,
    required_cases: Set[str],
    approved_exemptions: Mapping[str, str],
    verified_cases: Mapping[str, str],
    required_material: Mapping[str, str | Set[str]],
) -> None:
    """Consume an exact previously authenticated packet under current receiver policy.

    The receiver selects cases from its current profile, verifies all evidence and
    any case-specific exemptions, and authenticates approval for this entire packet
    before supplying its digest. A packet cannot supply that independent approval.
    """
    validate_readiness(packet)
    if (
        expected_state not in GATED_STATES
        or packet["state"] != expected_state
        or packet["resource"] != expected_resource
        or digest(packet) != approved_packet_digest
        or set(packet["required_cases"]) != required_cases
    ):
        raise ContractError("readiness differs from current approved resource, state or profile")
    material_fields = {
        "checkpoint",
        "independent_restore_evidence",
        "credential_custody_record",
        "fence_evidence",
    }
    present = {name for name in material_fields if packet[name]}
    if present != required_material.keys():
        raise ContractError("readiness omits or adds profile-required evidence")
    for name, expected in required_material.items():
        actual = packet[name]
        if name == "fence_evidence":
            if not isinstance(expected, Set) or set(actual) != expected:
                raise ContractError("readiness fence evidence differs from verified profile")
        elif actual != expected:
            raise ContractError("readiness material differs from verified profile")
    for case in required_cases:
        result = packet["case_evidence"][case]
        if result["status"] == "passed" and verified_cases.get(case) != result["evidence"]:
            raise ContractError("required readiness case lacks independently verified evidence")
        if (
            result["status"] == "not_applicable"
            and approved_exemptions.get(case) != result["evidence"]
        ):
            raise ContractError("readiness case lacks independently approved exemption")
