"""Installed regex assertions have bounded paths and portable scalar semantics."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fishhat_adapters import check_configuration, check_schema
from fishhat_contracts import digest, handoffs
from fishhat_contracts.schema_profile import regex_degree
from fishhat_contracts.validation import ContractError
from jsonschema import _keywords

from tests.test_result_schema_admission import URI, document, retained

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/adapter.execute/properties/result_schema",
    ],
    "scope": "optional regex path admission, portable lexical subset and Unicode scalar matching",
    "relationship": "candidate",
    "reason": "Fixed semantic vectors and guarded rejected payload matching exercise schema admission and retained meanings; they do not qualify arbitrary host regex engines or native providers.",
    "claims": [],
}


@pytest.mark.parametrize(
    "pattern",
    [
        r"^a?b?c?d?e(?![\s\S])",
        r"^(?:ab)?c?d?e?f(?![\s\S])",
        r"^a{0,1}b{0,1}c{0,1}d{0,1}e(?![\s\S])",
        "^" + "a?" * 80 + r"a{80}(?![\s\S])",
    ],
    ids=["optional-atoms", "optional-group-and-atoms", "explicit-optionals", "long-chain"],
)
def test_optional_paths_reject_at_approval_before_any_payload_matching(pattern):
    body = {"type": "string", "pattern": pattern}
    value = "a" * 80 + "!"
    record, data, installed = retained(body, value)
    original = _keywords.re.search

    def guarded(expression, instance, *args, **kwargs):
        assert expression != pattern, "rejected optional chain reached payload matching"
        return original(expression, instance, *args, **kwargs)

    with patch.object(_keywords.re, "search", guarded):
        with pytest.raises(ContractError, match="SCHEMA_REGEX_CAPACITY"):
            check_schema(body)
        with pytest.raises(ContractError, match="SCHEMA_REGEX_CAPACITY"):
            handoffs.schema_identity(URI, {URI: document(URI, body)})
        with pytest.raises(ContractError, match="SCHEMA_REGEX_CAPACITY"):
            check_configuration(body, value, digest(body))
        with pytest.raises(ContractError, match="SCHEMA_REGEX_CAPACITY"):
            handoffs.validate_result_payload(record, data, installed=installed)


@pytest.mark.parametrize("repeat", ["{COUNT}", "{0,COUNT}", "{COUNT,}"])
def test_unrepresentable_repeat_counts_are_typed_capacity_rejections(repeat):
    pattern = "^a" + repeat.replace("COUNT", "9" * 80) + r"(?![\s\S])"
    body = {"type": "string", "pattern": pattern}
    record, data, installed = retained(body, "a")
    original = _keywords.re.search

    def guarded(expression, instance, *args, **kwargs):
        assert expression != pattern, "unrepresentable repeat reached payload matching"
        return original(expression, instance, *args, **kwargs)

    with patch.object(_keywords.re, "search", guarded):
        with pytest.raises(ContractError, match="SCHEMA_REGEX_CAPACITY"):
            regex_degree(pattern)
        with pytest.raises(ContractError, match="SCHEMA_REGEX_CAPACITY"):
            check_schema(body)
        with pytest.raises(ContractError, match="SCHEMA_REGEX_CAPACITY"):
            handoffs.schema_identity(URI, {URI: document(URI, body)})
        with pytest.raises(ContractError, match="SCHEMA_REGEX_CAPACITY"):
            check_configuration(body, "a", digest(body))
        with pytest.raises(ContractError, match="SCHEMA_REGEX_CAPACITY"):
            handoffs.validate_result_payload(record, data, installed=installed)


@pytest.mark.parametrize(
    "pattern,accepted,rejected",
    [
        (r"^a?b?c?d(?![\s\S])", "abcd", "aacd"),
        (r"^(?:ab)?c?d?e(?![\s\S])", "abcde", "abcddde"),
        (r"^a{0,1}b{0,1}c{0,1}d(?![\s\S])", "d", "abccd"),
        (r"^(?:aa|bb|cc|dd|ee|ff|gg|hh)(?![\s\S])", "hh", "ii"),
    ],
    ids=["eight-optional-paths", "mixed-eight-paths", "explicit-eight-paths", "eight-branches"],
)
def test_eight_paths_remain_accepted_with_exact_matching(pattern, accepted, rejected):
    body = {"type": "string", "pattern": pattern}
    check_schema(body)
    handoffs.schema_identity(URI, {URI: document(URI, body)})
    check_configuration(body, accepted, digest(body))
    record, data, installed = retained(body, accepted)
    handoffs.validate_result_payload(record, data, installed=installed)
    with pytest.raises(ContractError):
        check_configuration(body, rejected, digest(body))
    record, data, installed = retained(body, rejected)
    with pytest.raises(ContractError):
        handoffs.validate_result_payload(record, data, installed=installed)


@pytest.mark.parametrize(
    "pattern",
    [
        r"\a",
        r"\0",
        r"\012",
        r"\U0001F600",
        r"\uD83D\uDE00",
        r"\-",
        r"\!",
        r"\ ",
        r"\b",
        r"[\b]",
        r"\B",
        r"\w",
        r"[\w]",
        r"\d",
        r"[\s]",
        r"\S",
        r".",
        r"x$",
        r"a{,3}",
        r"a{z}",
        r"[]a]",
        r"[[]",
        r"(?=a)?",
        r"[\u0000-\uffff]",
    ],
)
def test_python_only_or_host_dependent_spellings_cannot_be_installed(pattern):
    body = {"type": "string", "pattern": pattern}
    with pytest.raises(ContractError, match="UNSUPPORTED_SCHEMA_REGEX"):
        check_schema(body)
    with pytest.raises(ContractError, match="UNSUPPORTED_SCHEMA_REGEX"):
        handoffs.schema_identity(URI, {URI: document(URI, body)})


UNICODE_VECTORS = [
    (r"^[0-9]+(?![\s\S])", "123", True),
    (r"^[0-9]+(?![\s\S])", "١٢٣", False),
    (r"^[A-Za-z_]+(?![\s\S])", "hello_world", True),
    (r"^[A-Za-z_]+(?![\s\S])", "é", False),
    (r"^[ \t\r\n\v\f]+(?![\s\S])", " \t\r\n\v\f", True),
    (r"^[ \t\r\n\v\f]+(?![\s\S])", "\u00a0", False),
    (r"^[ \t\r\n\v\f]+(?![\s\S])", "\u0085", False),
    (r"^[ \t\r\n\v\f]+(?![\s\S])", "\u2028", False),
    (r"^[ \t\r\n\v\f]+(?![\s\S])", "\ufeff", False),
    (r"^x(?![\s\S])", "x", True),
    (r"^x(?![\s\S])", "x\n", False),
    (r"^x(?![\s\S])", "x\r", False),
    (r"^x(?![\s\S])", "x\u2028", False),
    (r"^x(?![\s\S])", "x\u2029", False),
    (r"^[\s\S](?![\s\S])", "\n", True),
    (r"^[\s\S](?![\s\S])", "\r", True),
    (r"^[\s\S](?![\s\S])", "\u2028", True),
    (r"^[\s\S](?![\s\S])", "\u2029", True),
    (r"^[\s\S](?![\s\S])", "\u0085", True),
    (r"^[\s\S](?![\s\S])", "\ufeff", True),
    (r"^[\s\S](?![\s\S])", "😀", True),
    (r"^[\s\S](?![\s\S])", "😀x", False),
    (r"^[\s\S](?![\s\S])", "", False),
    (r"^[😀-🙏]+(?![\s\S])", "😀🙏", True),
    (r"^[😀-🙏]+(?![\s\S])", "🚀", False),
    (r"^[éΩ漢]+(?![\s\S])", "éΩ漢", True),
    (r"^\u00E9\x21(?![\s\S])", "é!", True),
    (r"^\u00E9\x21(?![\s\S])", "e\u0301!", False),
    (r"^[a\-z]+(?![\s\S])", "-aaz", True),
    (r"^[a\-z]+(?![\s\S])", "b", False),
    (r"^[^/]+(?![\s\S])", "😀\n\u2028", True),
    (r"^[^/]+(?![\s\S])", "a/b", False),
    (r"^\^\$\.\*\+\?\(\)\[\]\{\}\|\\\/(?![\s\S])", "^$.*+?()[]{}|\\/", True),
]


@pytest.mark.parametrize("pattern,value,accepted", UNICODE_VECTORS)
def test_scalar_regex_vectors_have_explicit_meanings(pattern, value, accepted):
    body = {"type": "string", "pattern": pattern}
    check_schema(body)
    if accepted:
        check_configuration(body, value, digest(body))
    else:
        with pytest.raises(ContractError):
            check_configuration(body, value, digest(body))
