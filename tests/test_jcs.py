"""Fixed cross-language JCS bytes, hash preimages and owner witness signatures."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fishhat_adapters import check_configuration, check_schema
from fishhat_contracts import ContractError, canonical, digest, strict_json, strict_yaml
from fishhat_contracts.json_work import unique_items
from fishhat_contracts.record_delivery import RecordSnapshot
from fishhat_contracts.schema_profile import check_document
from fishhat_contracts.validation import _SCHEMA_VALIDATOR, SCHEMAS, validate
from fishhat_contracts.witness import sign, verify
from jsonschema import Draft202012Validator, validators

from scripts.check_evidence import fingerprint
from scripts.validation import digest as validation_digest
from tests.test_owner_handoffs import U, operation, request

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Witness",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
    ],
    "scope": "RFC 8785 bytes, numeric and Unicode admission, SHA-256 preimages and the exact Ed25519 witness profile",
    "relationship": "candidate",
    "reason": "Fixed independent ECMAScript vectors and negative cases check encoding interoperability without establishing key enrollment, native truth or execution authority.",
    "claims": [],
}

VECTORS = json.loads((Path(__file__).parent / "fixtures/jcs/vectors.json").read_text())


@pytest.mark.parametrize("vector", VECTORS["values"], ids=lambda vector: vector["name"])
def test_fixed_jcs_bytes_and_digests_match_ecmascript(vector):
    value = strict_json(vector["input_json"])
    expected = bytes.fromhex(vector["canonical_hex"])
    assert canonical(value) == expected
    assert digest(value) == vector["digest"]
    assert canonical(strict_json(expected)) == expected
    assert (
        fingerprint(value) == validation_digest(value) == vector["digest"].removeprefix("sha256:")
    )


def test_witness_profile_matches_independent_ed25519_vector():
    vector = VECTORS["witness"]
    body = vector["body"]
    assert canonical(body).hex() == vector["canonical_hex"]
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["synthetic_seed_hex"]))
    witness = sign(body, key)
    assert witness["signature"] == vector["signature"]
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(vector["public_key_hex"]))
    verify(witness, public, body["owner"], body["subject_digest"])
    for field, value in (("generation", 1), ("boot_id", body["id"]), ("state", "changed")):
        changed = {**witness, field: value}
        with pytest.raises(ContractError, match="untrusted witness signature"):
            verify(changed, public, body["owner"], body["subject_digest"])


def test_witness_requires_canonical_base64_padding_bits():
    witness = {**VECTORS["witness"]["body"], "signature": VECTORS["witness"]["signature"]}
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = alphabet.index(witness["signature"][-3])
    witness["signature"] = witness["signature"][:-3] + alphabet[last + 1] + "=="
    with pytest.raises(ContractError):
        validate("records.schema.json", witness, "Witness")


@pytest.mark.parametrize(
    "raw",
    ["NaN", "Infinity", "-Infinity", "1e999", "-1e999", "9" * 5000],
    ids=["nan", "infinity", "negative-infinity", "overflow", "negative-overflow", "long-integer"],
)
def test_nonfinite_numeric_input_is_rejected(raw):
    with pytest.raises(ContractError, match="nonfinite number"):
        strict_json(raw)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_programmatic_numbers_are_rejected(value):
    with pytest.raises(ContractError, match="nonfinite number"):
        canonical(value)


@pytest.mark.parametrize(
    "raw",
    ['{"x":1,"x":2}', '"\\ud800"', '{"\\udfff":0}'],
    ids=["duplicate-name", "lone-surrogate", "surrogate-name"],
)
def test_ambiguous_names_and_invalid_unicode_are_rejected(raw):
    with pytest.raises(ContractError):
        strict_json(raw)


def test_jcs_numbers_preserve_domain_integer_bounds_and_string_identity():
    assert canonical(strict_json("1.0")) == b"1"
    assert canonical(strict_json("-0.0")) == b"0"
    assert canonical(strict_yaml("x: 1.5")) == b'{"x":1.5}'
    assert canonical("é") != canonical("e\u0301")
    assert strict_json("9007199254740991") == 9007199254740991
    witness = {**VECTORS["witness"]["body"], "signature": VECTORS["witness"]["signature"]}
    for number in (1.5, 9007199254740992.0):
        with pytest.raises(ContractError):
            validate("records.schema.json", {**witness, "generation": number}, "Witness")
    with pytest.raises(ContractError, match="integer outside interoperable exact range"):
        canonical(9007199254740992)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("-0", b"0"),
        ("-0e0", b"0"),
        ("1e20", b"100000000000000000000"),
        ("1e-7", b"1e-7"),
        ("1.25", b"1.25"),
        ("9007199254740993", b"9007199254740992"),
    ],
)
def test_source_numbers_use_the_same_json_grammar_and_binary64_domain(raw, expected):
    value = strict_yaml("value: " + raw)["value"]
    assert canonical(value) == expected == canonical(strict_json(raw))
    assert canonical(strict_json(expected)) == expected


@pytest.mark.parametrize(
    "raw,expected_type",
    [
        ("-0.0", int),
        ("1e0", int),
        ("-2.0", int),
        ("9007199254740991.0", int),
        ("9007199254740992.0", float),
        ("0.5", float),
    ],
)
def test_integral_binary64_spellings_preserve_safe_native_integer_admission(raw, expected_type):
    decoded = strict_json(raw)
    source = strict_yaml("value: " + raw)["value"]
    assert type(decoded) is type(source) is expected_type
    assert canonical(decoded) == canonical(source)


def test_json_numeric_spellings_reach_the_same_record_read_range():
    snapshot = RecordSnapshot(operation(), U)
    body = request("record.read", {"reference": snapshot.reference, "offset": 0, "length": 1})
    original = canonical(body)
    alternate = original.replace(b'"offset":0', b'"offset":0.0').replace(
        b'"length":1', b'"length":1e0'
    )
    assert alternate != original
    decoded = strict_json(alternate)
    validate("ssh-request.schema.json", decoded)
    assert canonical(decoded) == original
    assert snapshot.chunk(**decoded["params"]) == snapshot.chunk(**strict_json(original)["params"])


@pytest.mark.parametrize(
    "raw",
    ["1:20.0", "1_000.5", "+1.5", "+1", ".5", "1.", "01", "-01", "0x10", ".inf", ".nan"],
    ids=[
        "sexagesimal",
        "underscores",
        "positive-fraction",
        "positive-integer",
        "leading-dot",
        "trailing-dot",
        "leading-zero",
        "negative-leading-zero",
        "hexadecimal",
        "infinity",
        "nan",
    ],
)
def test_yaml_only_numeric_spellings_remain_literal_source_strings(raw):
    assert strict_yaml("value: " + raw) == {"value": raw}


@pytest.mark.parametrize(
    "raw", ["1e999", "-1e999", "9" * 5000], ids=["positive", "negative", "integer"]
)
def test_source_numeric_overflow_is_rejected_without_unbounded_integer_parsing(raw):
    with pytest.raises(ContractError, match="nonfinite number"):
        strict_yaml("value: " + raw)


@pytest.mark.parametrize("values", [[1, 1.0], [-0.0, 0], [{"a": 1.0}, {"a": 1}]])
def test_schema_uniqueness_uses_json_numeric_equality(values):
    validator = validators.extend(Draft202012Validator, {"uniqueItems": unique_items})
    assert not validator({"type": "array", "uniqueItems": True}).is_valid(values)
    assert validator({"type": "array", "uniqueItems": True}).is_valid([True, 1])


@pytest.mark.parametrize(
    "value,divisor,accepted",
    [
        (0.3, 0.1, True),
        (0.31, 0.1, False),
        (-0.3, 0.1, True),
        (5e-324, 5e-324, True),
        (1, 0.5, True),
        (1.0, 1, True),
        (0, 1.0, True),
        (True, 1, False),
        (False, 1, False),
    ],
    ids=[
        "decimal",
        "nonmultiple",
        "negative",
        "subnormal",
        "integer-value",
        "integer-divisor",
        "zero",
        "boolean-true",
        "boolean-false",
    ],
)
def test_core_and_provider_multiples_use_exact_canonical_decimal_values(value, divisor, accepted):
    schema = {"type": "number", "multipleOf": divisor}
    assert _SCHEMA_VALIDATOR(schema).is_valid(value) is accepted
    if accepted:
        check_configuration(schema, value, digest(schema))
    else:
        with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
            check_configuration(schema, value, digest(schema))


@pytest.mark.parametrize("divisor", [0, 0.0, -0.1, True, False])
def test_schema_metadata_requires_a_positive_numeric_multiple_divisor(divisor):
    schema = {"type": "number", "multipleOf": divisor}
    with pytest.raises(ContractError, match="INVALID_SCHEMA"):
        check_document(schema, code="INVALID_SCHEMA")
    with pytest.raises(ContractError, match="INVALID_CONFIGURATION_SCHEMA"):
        check_schema(schema)


def test_encoding_never_mutates_signed_or_schema_values():
    value = copy.deepcopy(SCHEMAS["common.schema.json"])
    before = copy.deepcopy(value)
    canonical(value)
    assert value == before
