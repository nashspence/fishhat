"""Installed custom result schemas admit safe assertions before matching payloads."""

from __future__ import annotations

import copy
from unittest.mock import patch

import pytest
from fishhat_contracts import canonical, digest, handoffs
from fishhat_contracts.schema_profile import MAX_SCHEMA_DEPTH
from fishhat_contracts.validation import ContractError
from jsonschema import _keywords

from tests.linear_support import assert_linear, measure
from tests.test_owner_handoffs import adapter_result
from tests.test_workflow_continuations import attach_result

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/adapter.execute/properties/result_schema",
        "packages/fishhat-contracts/src/fishhat_contracts/handoffs.py#schema_identity",
    ],
    "scope": "installed custom result schema admission, exact identity and complete accepted values",
    "relationship": "candidate",
    "reason": "Direct and referenced unsafe assertions fail before matching a payload. Literal annotations, escaped pointers, ordinary matching and large complete collections retain their meaning. This supplies no native adapter or installation qualification.",
    "claims": [],
}

URI = "https://synthetic.invalid/adapter-result.schema.json"
LEAF = "https://synthetic.invalid/result-value.schema.json"
DIALECT = "https://json-schema.org/draft/2020-12/schema"


def document(uri, body):
    return {"$schema": DIALECT, "$id": uri, **copy.deepcopy(body)}


def retained(body, value, *, extra=None):
    record, _, installed = adapter_result()
    selected = {URI: document(URI, body), **(extra or {})}
    installed.update(selected)
    # Construct a correctly pinned but not pre-admitted fixture. The receiving
    # boundary itself must reject unsafe schemas, even if earlier checks did not.
    identity = {"uri": URI, "digest": digest({"root": URI, "documents": selected})}
    record["subject"]["arguments"]["result_schema"] = identity
    attach_result(record, value, record["owner"])
    return record, canonical(value), installed


@pytest.mark.parametrize("location", ["pattern", "pattern-properties", "definition", "reference"])
@pytest.mark.parametrize(
    "pattern",
    ["^(a+)+$", "^a*a*$", "a*$"],
    ids=["exponential", "quadratic", "unanchored-repeat"],
)
def test_unsafe_custom_regex_rejects_before_payload_matching(location, pattern):
    extra = None
    body = {"type": "string", "pattern": pattern}
    if location == "pattern-properties":
        body = {"type": "object", "patternProperties": {pattern: {"type": "integer"}}}
    elif location == "definition":
        body = {"type": "string", "$defs": {"Unsafe": body}}
    elif location == "reference":
        extra = {LEAF: document(LEAF, body)}
        body = {"$ref": LEAF}
    record, data, installed = retained(body, "a" * 8192 + "!", extra=extra)
    original = _keywords.re.search

    def guarded(expression, instance, *args, **kwargs):
        assert expression != pattern, "unsafe regex reached payload matcher"
        return original(expression, instance, *args, **kwargs)

    with patch.object(_keywords.re, "search", guarded):
        with pytest.raises(ContractError, match=r"(?:UNSUPPORTED|NONLINEAR)_SCHEMA_REGEX"):
            handoffs.validate_result_payload(record, data, installed=installed)


@pytest.mark.parametrize(
    "body,code",
    [
        ({"type": "string", "pattern": "("}, "INVALID_INSTALLED_SCHEMA"),
        ({"type": "string", "format": "regex"}, "UNSUPPORTED_SCHEMA_FORMAT"),
        ({"type": "string", "unknownAssertion": True}, "UNSUPPORTED_SCHEMA_KEYWORD"),
        ({"type": "string", "unevaluatedProperties": False}, "UNSUPPORTED_SCHEMA_KEYWORD"),
        ({"$ref": "#"}, "RECURSIVE_SCHEMA_REFERENCE"),
        ({"default": {"pattern": "^(a+)+$"}, "$ref": "#/default"}, "not a schema position"),
        ({"const": True, "$ref": "#/const"}, "not a schema position"),
        ({"$ref": "#/$defs/a~2b", "$defs": {"a~2b": True}}, "invalid result schema pointer escape"),
    ],
    ids=[
        "invalid-regex",
        "format",
        "unknown-keyword",
        "unevaluated",
        "cycle",
        "literal-schema",
        "literal-boolean",
        "pointer-escape",
    ],
)
def test_unsupported_custom_schema_fails_explicit_admission(body, code):
    record, data, installed = retained(body, "value")
    with pytest.raises(ContractError, match=code):
        handoffs.validate_result_payload(record, data, installed=installed)


def test_cross_document_cycle_and_execution_depth_are_checked_without_unfolding():
    record, data, installed = retained(
        {"$ref": LEAF}, 1, extra={LEAF: document(LEAF, {"$ref": URI})}
    )
    with pytest.raises(ContractError, match="RECURSIVE_SCHEMA_REFERENCE"):
        handoffs.validate_result_payload(record, data, installed=installed)
    definitions = {"End": {"type": "integer"}}
    previous = "End"
    for index in range(MAX_SCHEMA_DEPTH + 1):
        name = f"Alias{index}"
        definitions[name] = {"$ref": "#/$defs/" + previous}
        previous = name
    record, data, installed = retained({"$defs": definitions, "$ref": "#/$defs/" + previous}, 1)
    with pytest.raises(ContractError, match="SCHEMA_DEPTH"):
        handoffs.validate_result_payload(record, data, installed=installed)


@pytest.mark.parametrize("keyword", ["const", "enum", "default", "examples"])
def test_schema_looking_instance_literals_are_preserved(keyword):
    literal = {
        "pattern": "^(a+)+$",
        "$ref": "https://synthetic.invalid/literal",
        "unknownAssertion": True,
    }
    if keyword == "const":
        body, value = {keyword: literal}, literal
    elif keyword == "enum":
        body, value = {keyword: [literal]}, literal
    else:
        body, value = (
            {"type": "string", keyword: literal if keyword == "default" else [literal]},
            "value",
        )
    record, data, installed = retained(body, value)
    before = canonical(installed)
    assert handoffs.validate_result_payload(record, data, installed=installed) == value
    identity = record["result_handle"]["schema"]
    assert handoffs.schema_identity(URI, installed) == identity
    assert canonical(installed) == before


def test_accepted_pattern_search_and_complete_large_values_keep_their_semantics():
    body = {
        "type": "object",
        "patternProperties": {"x-": {"type": "string", "pattern": "needle"}},
        "additionalProperties": False,
    }
    value = {"prefix-x-" + "k" * 8192: "prefix-needle-" + "v" * 8192}
    record, data, installed = retained(body, value)
    assert handoffs.validate_result_payload(record, data, installed=installed) == value
    # Provider-only regex input limits are not copied onto independent results.
    record, data, installed = retained(
        {"type": "array", "items": {"type": "integer"}}, list(range(20000))
    )
    assert handoffs.validate_result_payload(record, data, installed=installed) == list(range(20000))


def test_cross_document_and_escaped_schema_position_identity_is_exact():
    body = {"$ref": LEAF + "#/$defs/a~1b~0c"}
    extra = {LEAF: document(LEAF, {"$defs": {"a/b~c": {"type": "string", "pattern": "^ok$"}}})}
    record, data, installed = retained(body, "ok", extra=extra)
    before = canonical(installed)
    assert handoffs.validate_result_payload(record, data, installed=installed) == "ok"
    assert handoffs.schema_identity(URI, installed) == record["result_handle"]["schema"]
    assert canonical(installed) == before


@pytest.mark.parametrize("outcome", ["success", "rejected"])
def test_custom_result_complete_validation_linear_work(outcome):
    samples = []
    for count in (16, 64, 256):
        pattern = "^[a-z]+/[a-z]+$"
        leaf = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "pattern": pattern},
                "tag": {"type": "string", "pattern": "tag"},
            },
            "required": ["name", "tag"],
            "additionalProperties": False,
        }
        value = [{"name": "alpha/beta", "tag": f"prefix-tag-{index:04d}"} for index in range(count)]
        if outcome == "rejected":
            value[-1]["name"] = "alpha/!"
        record, data, installed = retained(
            {"type": "array", "items": {"$ref": LEAF}, "uniqueItems": True},
            value,
            extra={LEAF: document(LEAF, leaf)},
        )
        matched_bytes = 0
        original = _keywords.re.search

        def matching(expression, instance, *args, pattern=pattern, original=original, **kwargs):
            nonlocal matched_bytes
            if expression in {pattern, "tag"}:
                matched_bytes += len(instance)
            return original(expression, instance, *args, **kwargs)

        def run(record=record, data=data, installed=installed):
            if outcome == "rejected":
                with pytest.raises(ContractError, match="result payload violates action schema"):
                    handoffs.validate_result_payload(record, data, installed=installed)
                return None
            return handoffs.validate_result_payload(record, data, installed=installed)

        with patch.object(_keywords.re, "search", matching):
            decoded, work = measure(run)
        assert decoded == (value if outcome == "success" else None)
        assert matched_bytes > count
        work["regex_input_characters"] = matched_bytes
        samples.append((count, work))
    assert_linear(samples)


def test_custom_schema_closure_admission_linear_work():
    samples = []
    for count in (16, 64, 256):
        body = {
            "type": "integer",
            "$defs": {f"V{index}": {"type": "string", "pattern": "^a+$"} for index in range(count)},
        }
        record, _, installed = retained(body, 1)
        identity, work = measure(
            lambda installed=installed: handoffs.schema_identity(URI, installed)
        )
        assert identity == record["result_handle"]["schema"]
        assert len(installed[URI]["$defs"]) == count
        samples.append((count, work))
    assert_linear(samples)


def test_unsafe_regex_regression_is_detected_without_executing_it(monkeypatch):
    monkeypatch.setattr(handoffs, "check_assertions", lambda node: None)
    with pytest.raises(AssertionError, match="unsafe regex reached payload matcher"):
        test_unsafe_custom_regex_rejects_before_payload_matching("pattern", "^(a+)+$")


CHECK_OVERRIDES = {
    "test_unsafe_regex_regression_is_detected_without_executing_it": {
        "purpose": "validation-tooling",
        "authority": [
            "tests/test_result_schema_admission.py#test_unsafe_custom_regex_rejects_before_payload_matching"
        ],
        "scope": "schema admission regression detection",
        "relationship": "no-product-claim",
        "reason": "Bypassing assertion admission must trigger the guarded matcher assertion before an unsafe expression executes; it supplies no product qualification.",
        "claims": [],
    },
}
for _name in (
    "test_custom_result_complete_validation_linear_work",
    "test_custom_schema_closure_admission_linear_work",
):
    CHECK_OVERRIDES[_name] = {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/handoffs.py#validate_result_payload",
            "release.toml#/engineering",
        ],
        "scope": "complete custom result validation and schema-position admission under fixed admitted profiles",
        "relationship": "scoped-witness",
        "reason": "Growing complete values, including a last-item rejection, and full admitted schema documents measure actual Python, serialization, native uniqueness and regex subject extent. Structural admission proves the accepted regex subset; byte counts alone do not prove a native matcher linear. No native custody or adapter qualification is supplied.",
        "claims": ["engineering:handoffs.retained-result"],
    }
