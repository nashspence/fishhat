"""Canonical restricted DNS RRsets; native publication remains adapter-owned."""

from __future__ import annotations

import ipaddress
from typing import Any

from .bounds import Bounds, bounds
from .validation import ContractError, canonical, validate


def rrset_key(value: dict[str, Any]) -> tuple[str, str, str]:
    return value["name"], value["class"], value["type"]


def _rrset_identity(value: dict[str, Any]) -> tuple[bytes, frozenset[bytes]]:
    """Compare validated RRsets by unordered members, retaining each member's structure.

    TXT chunks and other ordered data inside one member keep their order. This
    projection does not rewrite the exact request bytes retained for invocation.
    """
    return (
        canonical({key: field for key, field in value.items() if key != "rdata"}),
        frozenset(canonical(member) for member in value["rdata"]),
    )


def validate_rrsets(values: list[dict[str, Any]]) -> None:
    keys: set[tuple[str, str, str]] = set()
    cnames: set[str] = set()
    ordinary: set[str] = set()
    for value in values:
        validate("dns-intent.schema.json", value, "RRset")
        key = rrset_key(value)
        if key in keys:
            raise ContractError("DUPLICATE_RRSET")
        keys.add(key)
        if value["type"] == "CNAME":
            if len(value["rdata"]) != 1:
                raise ContractError("CNAME_CARDINALITY")
            cnames.add(value["name"])
        else:
            ordinary.add(value["name"])
        data = []
        for member in value["rdata"]:
            for name in ("target", "exchange"):
                if name in member and len(member[name].encode("ascii")) > 254:
                    raise ContractError("DNS_NAME_CAPACITY")
            if value["type"] in ("A", "AAAA"):
                address = ipaddress.ip_address(member["address"])
                if str(address) != member["address"]:
                    raise ContractError("NONCANONICAL_ADDRESS")
            if value["type"] == "TXT" and any(
                len(x.encode("utf-8")) > 255 for x in member["chunks"]
            ):
                raise ContractError("DNS_CHARACTER_STRING_CAPACITY")
            data.append(canonical(member))
        if len(data) != len(set(data)):
            raise ContractError("DUPLICATE_RDATA")
    if cnames & ordinary:
        raise ContractError("CNAME_COLLISION")


def validate_changes(value: dict[str, Any]) -> None:
    validate("dns-changes.schema.json", value)
    if value["scope"]["kind"] != "dns-service":
        raise ContractError("WRONG_DNS_SCOPE")
    validate_generation(
        value["expected_generation"], owner=value["custodian"], scope=value["scope"]
    )
    before, after, changed = [], [], set()
    for change in value["changes"]:
        a, b = change["before"], change["after"]
        if (a is None and b is None) or (
            a is not None
            and b is not None
            and (_rrset_identity(a) == _rrset_identity(b) or rrset_key(a) != rrset_key(b))
        ):
            raise ContractError("INVALID_RRSET_REPLACEMENT")
        identity = rrset_key(a if a is not None else b)
        if identity in changed:
            raise ContractError("DUPLICATE_RRSET_CHANGE")
        changed.add(identity)
        if a is not None:
            before.append(a)
        if b is not None:
            after.append(b)
    validate_rrsets(before)
    validate_rrsets(after)


def validate_generation(
    generation: dict[str, Any], *, owner: dict[str, Any], scope: dict[str, Any]
) -> None:
    """Bind a revision's data identity without authenticating its native producer."""
    validate("dns-changes.schema.json", generation, "DNSGeneration")
    if (
        generation["owner"] != owner
        or owner["id"] != scope["authority"]
        or generation["binding"]["role"] != "dns"
        or generation["binding"]["scope"] != scope
        or scope["kind"] != "dns-service"
    ):
        raise ContractError("DNS_GENERATION_IDENTITY")


@bounds(
    Bounds(
        id="dns.publication-precondition",
        work="O(B) complete current RRsets and changeset bytes; one indexed before-state join",
        extent="Complete authoritative scoped RRsets and every requested change",
        limits=(),
        capacity=("No total RRset or changeset cap; native capacity must refuse explicitly",),
        proofs=("tests/test_dns_generations.py::test_dns_precondition_linear_work",),
        linear_proofs=("tests/test_dns_generations.py::test_dns_precondition_linear_work",),
    )
)
def validate_publication_precondition(
    change: dict[str, Any],
    *,
    current_generation: dict[str, Any],
    current_rrsets: list[dict[str, Any]],
) -> None:
    """Compare a reviewed change to independently acquired complete native state.

    The native owner supplies the current generation and complete scoped RRsets
    under the same exclusion used for mutation, after authenticating authority.
    Caller-provided state or this pure check alone cannot authorize publication.
    Incomplete observation pages must not be passed as a complete native view.
    """
    validate_changes(change)
    validate_generation(current_generation, owner=change["custodian"], scope=change["scope"])
    if current_generation != change["expected_generation"]:
        raise ContractError("DNS_STALE_GENERATION")
    if current_generation["generation"] == 9007199254740991:
        raise ContractError("DNS_GENERATION_EXHAUSTED")
    validate_rrsets(current_rrsets)
    projected = {rrset_key(rrset): rrset for rrset in current_rrsets}
    for item in change["changes"]:
        before, after = item["before"], item["after"]
        key = rrset_key(before if before is not None else after)
        observed = projected.get(key)
        if (before is None) != (observed is None) or (
            before is not None
            and observed is not None
            and _rrset_identity(before) != _rrset_identity(observed)
        ):
            raise ContractError("DNS_BEFORE_STATE_CHANGED")
        if after is None:
            del projected[key]
        else:
            projected[key] = after
    validate_rrsets(list(projected.values()))
