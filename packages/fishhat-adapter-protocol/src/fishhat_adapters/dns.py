"""Canonical restricted DNS RRsets; native publication remains adapter-owned."""

from __future__ import annotations

import ipaddress
from typing import Any

from fishhat_contracts.validation import ContractError, canonical, validate


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
