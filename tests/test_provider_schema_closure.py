from __future__ import annotations

import copy

import pytest
from fishhat_adapters import check_configuration, check_schema
from fishhat_contracts.validation import ContractError, digest

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": ["packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json"],
    "scope": "closed provider-schema value boundaries and local schema-position references",
    "relationship": "candidate",
    "reason": "Adversarial accepted-value and literal-data cases exercise the closed subset without native adapter execution.",
    "claims": [],
}


def object_schema(properties=None):
    return {"type": "object", "properties": properties or {}, "additionalProperties": False}


@pytest.mark.parametrize(
    "schema",
    [
        {},
        {"not": {"type": "null"}},
        {"required": ["name"]},
        {"properties": {"name": {"type": "string"}}},
        object_schema({"nested": {}}),
        object_schema({"nested": True}),
        {"anyOf": [{"type": "string"}, {}]},
        {"oneOf": [object_schema(), {"type": "object"}]},
        {"type": "array"},
        {"type": "array", "items": {}},
        {"type": "array", "prefixItems": [{"type": "string"}]},
        {"$defs": {"Value": {}}, "$ref": "#/$defs/Value"},
        {"then": object_schema(), "else": object_schema()},
    ],
    ids=[
        "unconstrained-root",
        "implicit-object",
        "required-only",
        "implicit-properties",
        "nested-empty",
        "nested-true",
        "open-union",
        "open-object-branch",
        "array-no-items",
        "array-open-items",
        "array-open-tail",
        "referenced-empty",
        "inactive-conditionals",
    ],
)
def test_open_value_boundaries_cannot_enter_approved_provider_schemas(schema):
    with pytest.raises(ContractError, match=r"OPEN_(OBJECT|ARRAY)_SCHEMA"):
        check_schema(schema)


@pytest.mark.parametrize(
    "schema,value",
    [
        ({"type": "string"}, "value"),
        (
            {"anyOf": [{"type": "null"}, object_schema({"name": {"type": "string"}})]},
            {"name": "one"},
        ),
        (
            {"type": "array", "items": object_schema({"name": {"type": "string"}})},
            [{"name": "one"}],
        ),
        ({"type": "array", "prefixItems": [{"type": "string"}], "items": False}, ["one"]),
        (
            {"allOf": [object_schema({"name": {"type": "string"}}), {"required": ["name"]}]},
            {"name": "one"},
        ),
        ({"allOf": [{"type": "integer"}, {"minimum": 1}]}, 3),
        (
            {
                "$defs": {"Value": object_schema({"name": {"type": "string"}})},
                "$ref": "#/$defs/Value",
            },
            {"name": "one"},
        ),
        (
            {
                "type": "object",
                "patternProperties": {"^x-": {"type": "integer"}},
                "additionalProperties": False,
            },
            {"x-one": 1},
        ),
    ],
    ids=[
        "scalar",
        "nullable-object",
        "typed-array",
        "closed-tuple",
        "object-refinement",
        "scalar-refinement",
        "local-reference",
        "typed-map",
    ],
)
def test_closed_compositions_validate_their_declared_values(schema, value):
    check_configuration(schema, value, digest(schema))


@pytest.mark.parametrize(
    "schema,accepted,rejected",
    [
        ({"const": 0.5}, 0.5, 0.5000000000000001),
        ({"enum": [0.5, 1.5]}, 1.5, 1),
        ({"const": 1.0}, 1, True),
        ({"enum": [-0.0, 2.0]}, 0, False),
        ({"const": True}, True, 1.0),
    ],
    ids=["fraction-const", "fraction-enum", "integer-equality", "zero-equality", "boolean"],
)
def test_provider_numeric_literals_are_closed_and_preserve_json_number_equality(
    schema, accepted, rejected
):
    check_configuration(schema, accepted, digest(schema))
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        check_configuration(schema, rejected, digest(schema))


@pytest.mark.parametrize("keyword", ["const", "enum", "default", "examples"])
def test_schema_looking_literal_values_are_not_interpreted_as_schemas(keyword):
    literal = {
        "$ref": "https://untrusted.example/value",
        "$id": "literal",
        "type": "object",
        "properties": {},
    }
    if keyword == "const":
        schema, value = {"const": literal}, literal
    elif keyword == "enum":
        schema, value = {"enum": [literal]}, literal
    else:
        schema, value = (
            {"type": "string", keyword: literal if keyword == "default" else [literal]},
            "value",
        )
    check_configuration(schema, value, digest(schema))
    if keyword in {"const", "enum"}:
        changed = copy.deepcopy(value)
        changed["extra"] = "not-declared"
        with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
            check_configuration(schema, changed, digest(schema))


@pytest.mark.parametrize(
    "schema,code",
    [
        ({"$ref": "https://untrusted.example/schema"}, "NONLOCAL_SCHEMA_REFERENCE"),
        ({"$ref": "#/$defs/Missing"}, "UNRESOLVED_SCHEMA_REFERENCE"),
        (
            {"$defs": {"Loop": {"$ref": "#/$defs/Loop"}}, "$ref": "#/$defs/Loop"},
            "RECURSIVE_SCHEMA_REFERENCE",
        ),
        ({"default": {"type": "string"}, "$ref": "#/default"}, "UNRESOLVED_SCHEMA_REFERENCE"),
        (
            object_schema({"child": {"$id": "https://untrusted.example/child", "type": "string"}}),
            "NESTED_SCHEMA_IDENTITY",
        ),
        (
            {"$dynamicRef": "#/$defs/Value", "$defs": {"Value": {"type": "string"}}},
            "DYNAMIC_SCHEMA_REFERENCE",
        ),
    ],
    ids=["remote", "missing", "cycle", "literal-target", "nested-id", "dynamic"],
)
def test_only_acyclic_local_schema_position_references_are_admissible(schema, code):
    with pytest.raises(ContractError, match=code):
        check_schema(schema)


def test_local_pointer_escaping_preserves_exact_schema_identity():
    schema = {"$defs": {"a/b~c": {"type": "integer"}}, "$ref": "#/$defs/a~1b~0c"}
    check_configuration(schema, 2, digest(schema))
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        check_configuration(schema, {"unapproved": True}, digest(schema))


@pytest.mark.parametrize(
    "name", ["hostname", "uri", "duration", "json-pointer", "time", "regex", "unknown-format"]
)
def test_unsupported_format_assertions_fail_at_descriptor_approval(name):
    with pytest.raises(ContractError, match="UNSUPPORTED_SCHEMA_FORMAT"):
        check_schema({"type": "string", "format": name})


@pytest.mark.parametrize(
    "name,good,bad",
    [
        ("date", "2024-02-29", "2025-02-29"),
        ("date-time", "2026-10-25T12:30:00.123456+02:00", "2026-02-30T12:00:00Z"),
        ("ipv4", "192.0.2.1", "192.0.2.999"),
        ("ipv6", "2001:db8::1", "2001:::1"),
        ("uuid", "00000000-0000-4000-8000-000000000001", "not-a-uuid"),
    ],
    ids=["date", "date-time", "ipv4", "ipv6", "uuid"],
)
def test_every_supported_provider_format_asserts_its_declared_semantics(name, good, bad):
    schema = {"type": "string", "format": name}
    check_configuration(schema, good, digest(schema))
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        check_configuration(schema, bad, digest(schema))


@pytest.mark.parametrize(
    "keyword",
    ["$vocabulary", "unknownAssertion", "unevaluatedItems", "unevaluatedProperties"],
    ids=["vocabulary", "unknown-assertion", "unevaluated-items", "unevaluated-properties"],
)
def test_unimplemented_schema_assertion_or_vocabulary_is_not_silently_ignored(keyword):
    schema = {"type": "string", keyword: {"https://example.invalid/assertions": True}}
    with pytest.raises(ContractError, match="UNSUPPORTED_SCHEMA_KEYWORD"):
        check_schema(schema)


def test_nested_dialect_cannot_replace_the_budgeted_validator():
    schema = object_schema(
        {
            "value": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "array",
                "items": {"type": "integer"},
                "uniqueItems": True,
            }
        }
    )
    with pytest.raises(ContractError, match="NESTED_SCHEMA_DIALECT"):
        check_schema(schema)


def test_acyclic_references_cannot_hide_exponential_schema_expansion():
    definitions = {"L0": {"type": "string", "const": "x"}}
    for level in range(1, 5):
        definitions["L" + str(level)] = {"allOf": [{"$ref": "#/$defs/L" + str(level - 1)}] * 8}
    schema = {"$defs": definitions, "$ref": "#/$defs/L4"}
    with pytest.raises(ContractError, match="SCHEMA_EXPANSION_CAPACITY"):
        check_schema(schema)


@pytest.mark.parametrize(
    "pattern",
    [r"(a+)+$", r"(a|aa)+$", r"a*a*a*", r"(a)\1", r"(?<=a)b", r"(?i)a"],
    ids=["nested-repeat", "branch-repeat", "three-repeats", "backreference", "lookbehind", "flags"],
)
def test_provider_regex_cannot_enter_unbounded_backtracking_or_nonportable_features(pattern):
    with pytest.raises(ContractError, match=r"(?:UNSUPPORTED_SCHEMA_REGEX|SCHEMA_REGEX_CAPACITY)"):
        check_schema({"type": "string", "pattern": pattern})


def test_provider_value_work_limit_is_explicit_rejection_not_partial_success():
    schema = {"type": "array", "items": {"allOf": [{"type": "integer"}] * 128}}
    with pytest.raises(ContractError, match="SCHEMA_EVALUATION_CAPACITY"):
        check_configuration(schema, list(range(20000)), digest(schema))


def test_provider_uniqueness_does_not_charge_for_pairwise_work():
    for schema, value in [
        ({"type": "array", "items": {"type": "integer"}, "uniqueItems": True}, list(range(1500))),
        (
            {
                "type": "array",
                "items": {"type": "array", "items": {"type": "integer"}},
                "uniqueItems": True,
            },
            [[0] * 1000 + [index] for index in range(100)],
        ),
    ]:
        check_configuration(schema, value, digest(schema))


@pytest.mark.parametrize(
    "pattern",
    ["^a*a*$", "a*$", "^x|a*a*$"],
    ids=["anchored-pair", "unanchored-repeat", "branch-pair"],
)
def test_nonlinear_regex_requires_a_different_implementation(pattern):
    with pytest.raises(ContractError, match="NONLINEAR_SCHEMA_REGEX"):
        check_schema({"type": "string", "pattern": pattern})


def test_pattern_property_names_share_the_bounded_regex_input_contract():
    schema = {
        "type": "object",
        "additionalProperties": False,
        "patternProperties": {"^x-": {"type": "integer"}},
    }
    with pytest.raises(ContractError, match="SCHEMA_REGEX_INPUT_CAPACITY"):
        check_configuration(schema, {"x-" + "a" * 4096: 1}, digest(schema))
