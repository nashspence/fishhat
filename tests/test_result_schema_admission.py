"""Installed custom result schemas admit safe assertions before matching payloads."""

from __future__ import annotations

import copy
from unittest.mock import patch

import pytest
from fishhat_adapters import check_configuration, check_schema
from fishhat_contracts import canonical, digest, handoffs, schema_profile
from fishhat_contracts.schema_profile import MAX_SCHEMA_DEPTH
from fishhat_contracts.validation import ContractError
from jsonschema import Draft202012Validator, _keywords

from tests.linear_support import assert_linear, measure
from tests.test_owner_handoffs import adapter_result
from tests.test_workflow_continuations import attach_result

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/adapter.execute/properties/result_schema",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/SchemaIdentity",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/adapter.schema.json",
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
    # Invalid installation fixtures still reach the receiving boundary. A valid
    # identity does not let that boundary skip its independent schema admission.
    try:
        identity = handoffs.schema_identity(URI, installed)
    except ContractError:
        identity = {"uri": URI, "digest": digest(selected)}
    record["subject"]["arguments"]["result_schema"] = identity
    attach_result(record, value, record["owner"])
    return record, canonical(value), installed


def test_rooted_schema_identity_has_an_explicit_graph_preimage():
    uri = URI + "#/$defs/Result"
    literal = {"$ref": "literal://not-a-reference", "$defs": {"unused": False}}
    selected = {
        URI: document(
            URI,
            {
                "$defs": {
                    "Result": {
                        "type": "object",
                        "properties": {"a/b~%": {"$ref": LEAF + "#/$defs/Value"}},
                        "required": ["a/b~%"],
                        "additionalProperties": False,
                        "description": "The accepted resource retains custody.",
                    },
                    "Unused": {"type": "integer"},
                }
            },
        ),
        LEAF: document(LEAF, {"$defs": {"Value": {"const": literal}, "Other": True}}),
    }
    before = canonical(selected)
    expected = {
        "profile": "fishhat.schema-closure/v1",
        "root": uri,
        "documents": {
            URI: {"$schema": DIALECT, "$id": URI},
            LEAF: {"$schema": DIALECT, "$id": LEAF},
        },
        "nodes": {
            URI: {
                "/$defs/Result": {
                    "type": "object",
                    "properties": {"a/b~%": "/$defs/Result/properties/a~1b~0%"},
                    "required": ["a/b~%"],
                    "additionalProperties": "/$defs/Result/additionalProperties",
                    "description": "The accepted resource retains custody.",
                },
                "/$defs/Result/properties/a~1b~0%": {"$ref": LEAF + "#/$defs/Value"},
                "/$defs/Result/additionalProperties": False,
            },
            LEAF: {"/$defs/Value": {"const": literal}},
        },
    }
    assert handoffs.schema_identity(uri, selected) == {"uri": uri, "digest": digest(expected)}
    assert canonical(selected) == before


def test_schema_identity_excludes_unused_definitions_but_pins_reachable_meaning():
    uri = URI + "#/$defs/Result"
    selected = {
        URI: document(
            URI,
            {"$defs": {"Result": {"$ref": LEAF + "#/$defs/Value"}, "Unused": True}},
        ),
        LEAF: document(
            LEAF,
            {"$defs": {"Value": {"type": "integer", "description": "Exact count."}}},
        ),
    }
    original = handoffs.schema_identity(uri, selected)
    unrelated = copy.deepcopy(selected)
    unrelated[URI]["$defs"]["Unused"] = {"type": "string", "description": "Unrelated."}
    unrelated[LEAF]["$defs"]["Other"] = {"type": "string"}
    assert handoffs.schema_identity(uri, unrelated) == original
    for key, value in [
        ("type", "number"),
        ("description", "Count after independent verification."),
    ]:
        changed = copy.deepcopy(selected)
        changed[LEAF]["$defs"]["Value"][key] = value
        assert handoffs.schema_identity(uri, changed) != original
    for identity in selected:
        changed = copy.deepcopy(selected)
        changed[identity]["description"] = "Every definition requires independent custody."
        assert handoffs.schema_identity(uri, changed) != original


def test_unrelated_core_discovery_definition_does_not_reidentify_retained_workflows(monkeypatch):
    uri = "https://fishhat.invalid/contracts/records.schema.json#/$defs/Workflow"
    original = handoffs.schema_identity(uri)
    changed = copy.deepcopy(handoffs.SCHEMAS["records.schema.json"])
    changed["$defs"]["Info"]["description"] = "Discovery presentation clarification."
    monkeypatch.setitem(handoffs.SCHEMAS, "records.schema.json", changed)
    assert handoffs.schema_identity(uri) == original


def test_core_normative_dependencies_are_pinned_and_resolved_offline(monkeypatch):
    schema = document(
        URI,
        {
            "type": "integer",
            "x-fishhat-contract-dependencies": [LEAF + "#/$defs/Obligations"],
        },
    )
    obligations = document(
        LEAF,
        {"$defs": {"Obligations": {"const": {"custody": "required"}}, "Unused": True}},
    )
    monkeypatch.setitem(handoffs.SCHEMAS, "identity-root.schema.json", schema)
    monkeypatch.setitem(handoffs.SCHEMAS, "identity-obligations.schema.json", obligations)
    original = handoffs.schema_identity(URI)
    obligations["$defs"]["Unused"] = {"type": "string"}
    assert handoffs.schema_identity(URI) == original
    obligations["$defs"]["Obligations"]["const"]["custody"] = "independently verified"
    assert handoffs.schema_identity(URI) != original
    for reference, error in [
        (LEAF + "#/$defs/Obligations/const", "not a schema position"),
        (LEAF + "#/$defs/a~2b", "invalid result schema pointer escape"),
        ("https://uninstalled.invalid/obligations.schema.json", "not installed"),
    ]:
        schema["x-fishhat-contract-dependencies"] = [reference]
        with pytest.raises(ContractError, match=error):
            handoffs.schema_identity(URI)
    # These installed bodies are decoded or interpreted outside a structural
    # $ref: handles, digest preimages and inlined witnesses still pin their rules.
    base = "https://fishhat.invalid/contracts/"
    dependencies = [
        ("ssh-request.schema.json", "plan-input.schema.json", "PrepareRequest"),
        ("ssh-request.schema.json", "workflow.schema.json", "PrepareRequest"),
        ("ssh-request.schema.json", "workflow-recovery.schema.json", "RecoveryRequest"),
        ("ssh-request.schema.json", "observation.schema.json", "SelectionInput"),
        ("ssh-request.schema.json", "lifecycle-evidence.schema.json", "PrepareRequest"),
        ("records.schema.json#/$defs/Workflow", "workflow.schema.json", "PreparationWitness"),
        ("records.schema.json#/$defs/Plan", "records.schema.json", "Witness"),
        (
            "lifecycle-evidence.schema.json#/$defs/EvidenceReference",
            "lifecycle-evidence.schema.json",
            "Evidence",
        ),
        ("ingress-adapter.schema.json", "ingress-adapter.schema.json", "GenerationDocument"),
        ("network-adapter.schema.json", "network-adapter.schema.json", "GenerationDocument"),
        ("runtime-adapter.schema.json", "adapter.schema.json", "Instance"),
        ("runtime-adapter.schema.json", "adapter.schema.json", "EffectKnowledge"),
    ]
    for root, filename, definition in dependencies:
        before = handoffs.schema_identity(base + root)
        changed = copy.deepcopy(handoffs.SCHEMAS[filename])
        node = changed["$defs"][definition]
        node["description"] = node.get("description", "") + " Independently approved semantics."
        with monkeypatch.context() as installed:
            installed.setitem(handoffs.SCHEMAS, filename, changed)
            assert handoffs.schema_identity(base + root) != before, (root, definition)


def test_complete_document_digest_is_not_a_rooted_schema_identity():
    body = {"type": "integer"}
    record, data, installed = retained(body, 1)
    old = {"uri": URI, "digest": digest({"root": URI, "documents": {URI: installed[URI]}})}
    record["subject"]["arguments"]["result_schema"] = old
    attach_result(record, 1, record["owner"])
    with pytest.raises(ContractError, match="schema"):
        handoffs.validate_result_payload(record, data, installed=installed)


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


def test_encoded_pointer_separators_cannot_hide_recursive_schemas():
    pointer = "#/$defs/a%2F$defs%2Fb"
    body = {
        "$defs": {
            "a/$defs/b": {"type": "integer"},
            "a": {"$defs": {"b": {"$ref": pointer}}},
        },
        "$ref": pointer,
    }
    record, data, installed = retained(body, 1)
    with pytest.raises(ContractError, match="RECURSIVE_SCHEMA_REFERENCE"):
        check_schema(body)
    with pytest.raises(ContractError, match="RECURSIVE_SCHEMA_REFERENCE"):
        handoffs.schema_identity(URI, installed)
    with pytest.raises(ContractError, match="RECURSIVE_SCHEMA_REFERENCE"):
        handoffs.validate_result_payload(record, data, installed=installed)


def test_shared_references_cannot_expand_exponentially_during_value_validation():
    definitions = {"L0": {"type": "integer"}}
    for level in range(1, 6):
        definitions["L" + str(level)] = {"allOf": [{"$ref": "#/$defs/L" + str(level - 1)}] * 8}
    record, data, installed = retained({"$defs": definitions, "$ref": "#/$defs/L5"}, 1)
    with pytest.raises(ContractError, match="SCHEMA_EXPANSION_CAPACITY"):
        handoffs.schema_identity(URI, installed)
    with pytest.raises(ContractError, match="SCHEMA_EXPANSION_CAPACITY"):
        handoffs.validate_result_payload(record, data, installed=installed)


def test_unused_definition_count_is_independent_of_execution_expansion_capacity():
    # Declarations are inspected once; unused definitions are not unfolded as
    # assertions on the value. A schema-work budget is not a declaration cap.
    definitions = {f"V{index}": {"type": "integer"} for index in range(5000)}
    record, data, installed = retained({"type": "integer", "$defs": definitions}, 1)
    assert handoffs.validate_result_payload(record, data, installed=installed) == 1
    assert len(installed[URI]["$defs"]) == 5000


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


@pytest.mark.parametrize(
    "fragment,name",
    [
        ("/$defs/a~1b~0c", "a/b~c"),
        ("/$defs%2Fa~1b~0c", "a/b~c"),
        ("/%24defs/a%7E1b%7E0c", "a/b~c"),
        ("/$defs/a~01b", "a~1b"),
        ("/$defs/a%252Fb", "a%2Fb"),
        ("/$defs/%E2%98%83", "\u2603"),
    ],
    ids=[
        "escaped-name",
        "encoded-separator",
        "encoded-escapes",
        "tilde-once",
        "percent-once",
        "unicode",
    ],
)
def test_cross_document_and_escaped_schema_position_identity_is_exact(fragment, name):
    definition = {"$defs": {name: {"type": "string", "pattern": r"^ok(?![\s\S])"}}}
    provider = {**copy.deepcopy(definition), "$ref": "#" + fragment}
    check_configuration(provider, "ok", digest(provider))
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        check_configuration(provider, "bad", digest(provider))
    body = {"$ref": LEAF + "#" + fragment}
    extra = {LEAF: document(LEAF, definition)}
    record, data, installed = retained(body, "ok", extra=extra)
    before = canonical(installed)
    assert handoffs.validate_result_payload(record, data, installed=installed) == "ok"
    assert handoffs.schema_identity(URI, installed) == record["result_handle"]["schema"]
    assert canonical(installed) == before


@pytest.mark.parametrize("outcome", ["success", "rejected"])
def test_custom_result_complete_validation_linear_work(outcome):
    samples = []
    for count in (16, 64, 256):
        pattern = r"^[a-z]+/[a-z]+(?![\s\S])"
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


@pytest.mark.parametrize("shape", ["definitions", "required"])
def test_custom_schema_closure_admission_linear_work(shape):
    samples = []
    for count in (16, 64, 256):
        if shape == "definitions":
            body = {
                "type": "integer",
                "$defs": {
                    f"V{index}": {"type": "string", "pattern": r"^a+(?![\s\S])"}
                    for index in range(count)
                },
            }
        else:
            names = [f"V{index:04d}" for index in sorted(range(count), key=digest)]
            body = {
                "type": "object",
                "properties": {name: {"type": "integer"} for name in names},
                "required": names,
                "additionalProperties": False,
            }
        record, _, installed = retained(body, 1)
        identity, work = measure(
            lambda installed=installed: handoffs.schema_identity(URI, installed)
        )
        assert identity == record["result_handle"]["schema"]
        assert len(installed[URI]["$defs" if shape == "definitions" else "required"]) == count
        samples.append((count, work))
    assert_linear(samples)


@pytest.mark.parametrize("boundary", ["provider", "result"])
def test_schema_admission_uses_linear_uniqueness_through_metaschema_references(boundary):
    def stock(*args, **kwargs):
        raise AssertionError("stock metaschema uniqueness reached")

    for duplicate in (False, True):
        body = {
            "type": "object",
            "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
            "required": ["a", "a"] if duplicate else ["b", "a"],
            "additionalProperties": False,
        }
        record, _, installed = retained(body, {})
        with patch.object(_keywords, "uniq", stock):

            def admit(body=body, installed=installed):
                return (
                    check_schema(body)
                    if boundary == "provider"
                    else handoffs.schema_identity(URI, installed)
                )

            if duplicate:
                with pytest.raises(
                    ContractError, match=r"INVALID_(?:CONFIGURATION|INSTALLED)_SCHEMA"
                ):
                    admit()
            else:
                admit()
        assert record["result_handle"]["schema"]["uri"] == URI


def test_metaschema_uniqueness_regression_is_detected(monkeypatch):
    monkeypatch.setattr(schema_profile, "_META_VALIDATOR", Draft202012Validator)
    with pytest.raises(AssertionError, match="stock metaschema uniqueness reached"):
        test_schema_admission_uses_linear_uniqueness_through_metaschema_references("result")


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
CHECK_OVERRIDES["test_metaschema_uniqueness_regression_is_detected"] = {
    "purpose": "validation-tooling",
    "authority": [
        "tests/test_result_schema_admission.py#test_schema_admission_uses_linear_uniqueness_through_metaschema_references"
    ],
    "scope": "schema syntax-check uniqueness regression detection",
    "relationship": "no-product-claim",
    "reason": "Restoring the stock schema-syntax validator must fail the guarded uniqueness witness through referenced metaschemas before any expensive matching; it supplies no product qualification.",
    "claims": [],
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
