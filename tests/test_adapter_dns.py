from __future__ import annotations

import copy

import pytest
from a_fishhat_bind_rfc2136_adapter.render import render_update
from a_fishhat_dnsmasq_appliance_adapter.render import render_hosts
from fishhat_contracts.dns import validate_changes, validate_rrsets
from fishhat_contracts.validation import ContractError

from tests.adapter_support import OWNER, identifier
from tests.test_adapter_handoffs import installed

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/dns-intent.schema.json"
    ],
    "scope": "DNS RRset semantics and effect-free native source compilation",
    "relationship": "candidate",
    "reason": "Native rendering contrasts are not appliance or live named qualification.",
    "claims": [],
}


def rrset(typ="A", name="web.example.test."):
    return {
        "name": name,
        "class": "IN",
        "type": typ,
        "ttl": {"mode": "exact", "seconds": 0},
        "rdata": [{"address": "192.0.2.10" if typ == "A" else "2001:db8::10"}],
    }


def generation(executor=None, revision=1):
    if executor is None:
        _, executor = installed("dns")
    return {
        "owner": copy.deepcopy(OWNER),
        "binding": copy.deepcopy(executor),
        "native_incarnation": identifier(56),
        "generation": revision,
    }


def change(before=None, after=None):
    observed = generation()
    return {
        "format": "deployment-ops/dns-change/v1",
        "id": identifier(55),
        "scope": copy.deepcopy(observed["binding"]["scope"]),
        "expected_generation": observed,
        "changes": [{"before": before, "after": after}],
        "custodian": OWNER,
    }


def test_dnsmasq_zero_ttl_and_service_default_are_not_cloud_record_ids():
    a, aaaa = rrset(), rrset("AAAA")
    aaaa["ttl"] = {"mode": "service-default"}
    assert render_hosts([a, aaaa], local_ttl=0) == (
        b"192.0.2.10 web.example.test\n2001:db8::10 web.example.test\n"
    )


def test_dnsmasq_refuses_per_rrset_ttl_it_cannot_enforce():
    value = rrset()
    value["ttl"]["seconds"] = 30
    with pytest.raises(ContractError, match="UNSUPPORTED_PER_RRSET_TTL"):
        render_hosts([value], local_ttl=0)


def test_real_native_grammars_differ_without_changing_dns_ontology():
    value = rrset()
    script = render_update(change(after=value), zone="example.test.")
    assert b"prereq nxrrset web.example.test. A\n" in script
    assert b"update add web.example.test. 0 A 192.0.2.10\n" in script
    assert script.endswith(b"send\n")
    assert b"prereq" not in render_hosts([value], local_ttl=0)


def test_bind_compiles_exact_rrset_preconditions_and_not_zone_wide_deletion():
    before, after = rrset(), rrset()
    after["rdata"] = [{"address": "192.0.2.11"}]
    script = render_update(change(before, after), zone="example.test.")
    assert b"prereq yxrrset web.example.test. A 192.0.2.10" in script
    assert b"update delete web.example.test. A" in script
    assert b"update delete example.test." not in script


def test_cname_is_not_a_hosts_alias():
    value = {
        "name": "alias.example.test.",
        "class": "IN",
        "type": "CNAME",
        "ttl": {"mode": "exact", "seconds": 0},
        "rdata": [{"target": "web.example.test."}],
    }
    with pytest.raises(ContractError, match="UNSUPPORTED_RRTYPE"):
        render_hosts([value], local_ttl=0)
    assert b"CNAME web.example.test." in render_update(change(after=value), zone="example.test.")


@pytest.mark.parametrize(
    "member,value",
    [("proxied", True), ("record_id", "provider-record"), ("provider", "cloudflare")],
)
def test_provider_specific_fields_are_not_common_dns_fields(member, value):
    v = rrset()
    v[member] = value
    with pytest.raises(ContractError):
        validate_rrsets([v])


def test_duplicate_and_conflicting_rrsets_are_rejected():
    with pytest.raises(ContractError, match="DUPLICATE_RRSET"):
        validate_rrsets([rrset(), rrset()])
    alias = {
        "name": "web.example.test.",
        "class": "IN",
        "type": "CNAME",
        "ttl": {"mode": "exact", "seconds": 0},
        "rdata": [{"target": "other.example.test."}],
    }
    with pytest.raises(ContractError, match="CNAME_COLLISION"):
        validate_rrsets([rrset(), alias])


def test_dns_scope_uses_label_boundaries_not_suffix_strings():
    with pytest.raises(ContractError, match="DNS_SCOPE_ESCAPE"):
        render_update(change(after=rrset(name="notexample.test.")), zone="example.test.")


def test_unchanged_or_renamed_rrset_is_not_a_replacement():
    value = rrset()
    with pytest.raises(ContractError, match="INVALID_RRSET_REPLACEMENT"):
        validate_changes(change(value, copy.deepcopy(value)))
    with pytest.raises(ContractError, match="INVALID_RRSET_REPLACEMENT"):
        validate_changes(change(value, rrset(name="different.example.test.")))


def test_txt_octet_limits_do_not_assume_python_character_count():
    value = {
        "name": "txt.example.test.",
        "class": "IN",
        "type": "TXT",
        "ttl": {"mode": "exact", "seconds": 0},
        "rdata": [{"chunks": ["é" * 128]}],
    }
    with pytest.raises(ContractError, match="DNS_CHARACTER_STRING_CAPACITY"):
        validate_rrsets([value])
