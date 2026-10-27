"""Conditional nsupdate source compilation; credentials and execution remain protected."""

from __future__ import annotations

from typing import Any

from fishhat_contracts.dns import validate_changes
from fishhat_contracts.validation import ContractError


def _data(rrset: dict[str, Any], value: dict[str, Any]) -> str:
    if rrset["type"] in {"A", "AAAA"}:
        return str(value["address"])
    if rrset["type"] in {"CNAME", "PTR"}:
        return str(value["target"])
    raise ContractError("UNSUPPORTED_RRTYPE")


def render_update(change: dict[str, Any], *, zone: str) -> bytes:
    validate_changes(change)
    # Validate the selected zone using the same absolute ASCII DNS-name grammar.
    from fishhat_contracts.validation import validate

    validate(
        "dns-intent.schema.json",
        {
            "name": zone,
            "class": "IN",
            "type": "A",
            "ttl": {"mode": "exact", "seconds": 0},
            "rdata": [{"address": "192.0.2.1"}],
        },
        "RRset",
    )
    lines = ["zone " + zone]
    additions = []
    for item in change["changes"]:
        before, after = item["before"], item["after"]
        rrset = before if before is not None else after
        name, typ = rrset["name"], rrset["type"]
        if name != zone and not name.endswith("." + zone):
            raise ContractError("DNS_SCOPE_ESCAPE")
        if before is None:
            lines.append(f"prereq nxrrset {name} {typ}")
        else:
            for value in before["rdata"]:
                lines.append(f"prereq yxrrset {name} {typ} " + _data(before, value))
            additions.append(f"update delete {name} {typ}")
        if after is not None:
            if after["ttl"]["mode"] != "exact":
                raise ContractError("EXPLICIT_TTL_REQUIRED")
            ttl = after["ttl"]["seconds"]
            for value in after["rdata"]:
                additions.append(f"update add {name} {ttl} {typ} " + _data(after, value))
    return ("\n".join(lines + additions + ["send", ""])).encode("ascii")
