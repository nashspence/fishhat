"""dnsmasq host-data compilation, not appliance publication or serving evidence."""

from __future__ import annotations

from typing import Any

from fishhat_contracts.dns import validate_rrsets
from fishhat_contracts.validation import ContractError


def render_hosts(rrsets: list[dict[str, Any]], *, local_ttl: int) -> bytes:
    validate_rrsets(rrsets)
    lines = []
    for rrset in rrsets:
        if rrset["type"] not in {"A", "AAAA"}:
            raise ContractError("UNSUPPORTED_RRTYPE")
        ttl = rrset["ttl"]
        if ttl["mode"] == "exact" and ttl["seconds"] != local_ttl:
            raise ContractError("UNSUPPORTED_PER_RRSET_TTL")
        for value in rrset["rdata"]:
            lines.append(value["address"] + " " + rrset["name"].rstrip("."))
    return ("\n".join(sorted(lines)) + ("\n" if lines else "")).encode("ascii")
