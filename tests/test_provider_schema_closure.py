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
