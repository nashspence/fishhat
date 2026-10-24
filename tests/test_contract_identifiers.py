"""Exact identifier grammars across schema, source, DNS and SSH boundaries."""

import copy

import pytest
from fishhat_client.wire import select_target, ssh_command
from fishhat_contracts.validation import ContractError, validate, validate_domain

from tests.test_adapter_dns import rrset
from tests.test_contracts import load

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/source.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/dns-intent.schema.json",
    ],
    "scope": "exact lexical identifiers and embedded source names at declared boundaries",
    "relationship": "candidate",
    "reason": "Explicit valid names retain their bytes; trailing control characters are rejected by schema, source, DNS and SSH consumers without normalization. No native execution is claimed.",
    "claims": [],
}


@pytest.mark.parametrize(
    "definition,value",
    [
        ("Id", "app"),
        ("Entry", "target"),
        ("Commit", "a" * 40),
        ("GitRef", "refs/heads/main"),
        ("RelativePath", "config/app.yaml"),
        ("AbsolutePath", "/srv/app/config"),
    ],
    ids=["id", "entry", "commit", "git-ref", "relative-path", "absolute-path"],
)
@pytest.mark.parametrize("suffix", ["\n", "\r\n", "\r", "\x00"], ids=["lf", "crlf", "cr", "nul"])
def test_constrained_strings_reject_control_suffixes(definition, value, suffix):
    validate("common.schema.json", value, definition)
    with pytest.raises(ContractError):
        validate("common.schema.json", value + suffix, definition)


@pytest.mark.parametrize("alias", ["target", "a" * 64], ids=["ordinary", "maximum"])
def test_schema_and_ssh_consumers_preserve_valid_aliases_and_reject_newlines(alias):
    validate("common.schema.json", alias, "Entry")
    assert select_target(alias, None, None) == alias
    assert ssh_command(alias, ["app-ops", "version", "--json"])[-2] == alias
    invalid = alias + "\n"
    with pytest.raises(ContractError):
        validate("common.schema.json", invalid, "Entry")
    with pytest.raises(ContractError):
        select_target(invalid, "fallback", None)
    with pytest.raises(ContractError):
        ssh_command(invalid, ["app-ops", "version", "--json"])


@pytest.mark.parametrize("location", ["host-id", "source-id", "ssh-alias", "repository-name"])
def test_embedded_domain_identifiers_reject_final_newline(location):
    domain = load("examples/domain/domain.yaml")
    validate_domain(domain)
    changed = copy.deepcopy(domain)
    if location == "host-id":
        changed["hosts"]["node-a\n"] = changed["hosts"].pop("node-a")
    elif location == "source-id":
        changed["sources"]["host-node-a\n"] = changed["sources"].pop("host-node-a")
    elif location == "ssh-alias":
        changed["hosts"]["node-a"]["host_ops_alias"] += "\n"
    else:
        changed["sources"]["host-node-a"]["repository"]["name"] += "\n"
    with pytest.raises(ContractError):
        validate("source.schema.json", changed, "Domain")
    with pytest.raises(ContractError):
        validate_domain(changed)


@pytest.mark.parametrize("location", ["name", "target"])
def test_dns_names_reject_final_newline_before_rendering(location):
    value = rrset()
    if location == "target":
        value["type"] = "CNAME"
        value["rdata"] = [{"target": "target.example.test."}]
    validate("dns-intent.schema.json", value, "RRset")
    changed = copy.deepcopy(value)
    if location == "name":
        changed["name"] += "\n"
    else:
        changed["rdata"][0]["target"] += "\n"
    with pytest.raises(ContractError):
        validate("dns-intent.schema.json", changed, "RRset")
