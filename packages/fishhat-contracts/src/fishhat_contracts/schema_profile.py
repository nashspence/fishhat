"""Shared conservative assertion profile; value ownership and reference resolution stay local."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from typing import Any

from jsonschema import Draft202012Validator, validators
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from .validation import _SCHEMA_VALIDATOR, FORMAT_CHECKER, ContractError, value_check

SINGLE = (
    "additionalProperties",
    "unevaluatedProperties",
    "items",
    "contains",
    "propertyNames",
    "not",
    "if",
    "then",
    "else",
    "contentSchema",
    "unevaluatedItems",
)
MAPPINGS = ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas")
SEQUENCES = ("allOf", "anyOf", "oneOf", "prefixItems")
FORMATS = frozenset({"date", "date-time", "ipv4", "ipv6", "uuid"})
KEYWORDS = (
    frozenset(Draft202012Validator.VALIDATORS) - {"unevaluatedItems", "unevaluatedProperties"}
) | frozenset(
    {
        "$schema",
        "$id",
        "$ref",
        "$defs",
        "definitions",
        "$comment",
        "title",
        "description",
        "default",
        "examples",
        "deprecated",
        "readOnly",
        "writeOnly",
        "then",
        "else",
        "minContains",
        "maxContains",
    }
)

MAX_SCHEMA_DEPTH = 32
MAX_EXPANDED_SCHEMA = 4096


# Keep published metaschema identities intact. Evaluation omits only the dialect
# selector so local/dynamic references retain the same linear uniqueness class.
_META_REGISTRY = Registry().with_resources(
    (
        uri,
        Resource.from_contents(
            {key: value for key, value in resource.contents.items() if key != "$schema"},
            default_specification=DRAFT202012,
        ),
    )
    for uri, resource in vars(validators)["SPECIFICATIONS"].items()
    if "/draft/2020-12/" in uri
)
_META_SCHEMA = {
    key: value for key, value in Draft202012Validator.META_SCHEMA.items() if key != "$schema"
}
_META_VALIDATOR = _SCHEMA_VALIDATOR


def check_document(schema: dict[str, Any], *, code: str) -> None:
    """Check schema syntax with linear uniqueness, including referenced metaschemas."""
    value_check(schema)
    try:
        error = next(
            _META_VALIDATOR(
                _META_SCHEMA,
                registry=_META_REGISTRY,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            ).iter_errors(schema),
            None,
        )
    except RecursionError as exc:
        raise ContractError(code) from exc
    if error is not None:
        raise ContractError(code)


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ContractError(code)


def _atom_accepts(atom: Any, character: int) -> bool:
    operation, argument = atom
    name = str(operation)
    if name == "LITERAL":
        return bool(character == argument)
    if name == "NOT_LITERAL":
        return bool(character != argument)
    if name == "ANY":
        return character != 10
    if name != "IN":
        return True
    negated = bool(argument and str(argument[0][0]) == "NEGATE")
    matches = False
    for kind, value in argument:
        if str(kind) == "LITERAL":
            matches |= character == value
        elif str(kind) == "RANGE":
            matches |= value[0] <= character <= value[1]
        elif str(kind) != "NEGATE":
            # Unknown/category alphabets cannot establish delimiter exclusion.
            return True
    return not matches if negated else matches


def _separated_repetitions(tokens: Any) -> bool:
    """Prove that two variable runs cannot backtrack across their delimiter.

    Branches and assertions do not supply a delimiter proof. An optional group
    can supply a delimiter to a run inside it, never to a run after that group.
    """
    previous: Any = None
    delimiters: list[int] = []
    runs = 0
    separated = False
    supported = True

    def walk(parts: Any) -> None:
        nonlocal previous, runs, separated, supported, delimiters
        for operation, argument in parts:
            name = str(operation)
            if name == "LITERAL":
                delimiters.append(argument)
            elif name == "SUBPATTERN":
                walk(argument[3])
            elif name == "BRANCH":
                supported = False
            elif name in {"ASSERT", "ASSERT_NOT"}:
                if argument[1].getwidth() != (1, 1):
                    supported = False
            elif name in {"MAX_REPEAT", "MIN_REPEAT"}:
                minimum, maximum, child = argument
                if len(child) == 1 and str(child[0][0]) in {
                    "LITERAL",
                    "NOT_LITERAL",
                    "ANY",
                    "IN",
                    "CATEGORY",
                }:
                    if minimum != maximum and maximum > 1:
                        if previous is not None:
                            separated = any(not _atom_accepts(previous, c) for c in delimiters)
                        previous, delimiters = child[0], []
                        runs += 1
                else:
                    before, saved = runs, delimiters.copy()
                    walk(child)
                    if minimum == 0 and before == runs:
                        delimiters = saved

    walk(tokens)
    return supported and runs == 2 and separated


def regex_degree(pattern: str) -> int:
    """Admit a bounded regular-expression subset, never backtracking group repeats.

    Variable repetition is restricted to single characters/classes, except a
    single optional group. There are at most two variable repetitions and eight
    total alternatives. Lookbehind, backreferences and inline flags reject.
    """
    require(len(pattern) <= 256, "SCHEMA_REGEX_CAPACITY")
    require(
        not any(marker in pattern for marker in ("(?P", "(?#", r"\A", r"\Z", r"\N")),
        "UNSUPPORTED_SCHEMA_REGEX",
    )
    parser: Any = vars(re)["_parser"]
    try:
        parsed = parser.parse(pattern, 0)
    except re.error as exc:
        raise ContractError("INVALID_SCHEMA_REGEX") from exc
    require(parsed.state.flags == re.UNICODE, "UNSUPPORTED_SCHEMA_REGEX")
    repetitions, alternatives = 0, 1

    def walk(tokens: Any) -> None:
        nonlocal repetitions, alternatives
        for operation, argument in tokens:
            name = str(operation)
            if name in {"LITERAL", "NOT_LITERAL", "ANY", "IN", "AT", "CATEGORY"}:
                continue
            if name == "SUBPATTERN":
                require(argument[1] == argument[2] == 0, "UNSUPPORTED_SCHEMA_REGEX")
                walk(argument[3])
            elif name == "BRANCH":
                alternatives *= len(argument[1])
                require(alternatives <= 8, "SCHEMA_REGEX_CAPACITY")
                for branch in argument[1]:
                    walk(branch)
            elif name in {"MAX_REPEAT", "MIN_REPEAT"}:
                minimum, maximum, child = argument
                atom = len(child) == 1 and str(child[0][0]) in {
                    "LITERAL",
                    "NOT_LITERAL",
                    "ANY",
                    "IN",
                    "CATEGORY",
                }
                require(atom or (minimum == 0 and maximum == 1), "UNSUPPORTED_SCHEMA_REGEX")
                if not atom:
                    alternatives *= 2
                    require(alternatives <= 8, "SCHEMA_REGEX_CAPACITY")
                    walk(child)
                elif minimum != maximum and maximum > 1:
                    repetitions += 1
                require(repetitions <= 2, "SCHEMA_REGEX_CAPACITY")
            elif name in {"ASSERT", "ASSERT_NOT"}:
                require(argument[0] >= 0, "UNSUPPORTED_SCHEMA_REGEX")
                walk(argument[1])
            else:
                raise ContractError("UNSUPPORTED_SCHEMA_REGEX")

    walk(parsed)
    anchored = (
        bool(parsed)
        and str(parsed[0][0]) == "AT"
        and str(parsed[0][1]) in {"AT_BEGINNING", "AT_BEGINNING_STRING"}
    )
    if repetitions == 2 and anchored and _separated_repetitions(parsed):
        repetitions = 1
    degree = max(1, repetitions + (not anchored))
    require(degree == 1, "NONLINEAR_SCHEMA_REGEX")
    return degree


def check_assertions(node: dict[str, Any]) -> None:
    """Admit known assertions and prove regex work before any value is matched."""
    require(not node.keys() - KEYWORDS, "UNSUPPORTED_SCHEMA_KEYWORD")
    if "format" in node:
        require(
            node["format"] in FORMATS and node["format"] in FORMAT_CHECKER.checkers,
            "UNSUPPORTED_SCHEMA_FORMAT",
        )
    for pattern in ([node["pattern"]] if "pattern" in node else []) + list(
        node.get("patternProperties", {})
    ):
        regex_degree(pattern)


def schema_children(node: dict[str, Any]) -> Iterator[tuple[tuple[str, ...], Any]]:
    """Visit schema positions, never const/default/example instance data."""
    for key in SINGLE:
        if key in node:
            yield (key,), node[key]
    for key in MAPPINGS:
        for name, child in node.get(key, {}).items():
            yield (key, name), child
    for key in SEQUENCES:
        for index, child in enumerate(node.get(key, [])):
            yield (key, str(index)), child


SchemaNode = tuple[str, tuple[str, ...]]


def check_reference_graph(
    graph: Mapping[SchemaNode, list[SchemaNode]],
    execution: Mapping[SchemaNode, list[SchemaNode]],
) -> None:
    """Check every custom node in linear graph work without unfolding shared references.

    Schema depth and static expansion use the existing provider-profile capacities.
    It is independent of the number of array items or documents in a collection.
    Source-reviewed core nodes are terminal dependencies of this custom graph;
    they cannot refer back to independently installed extension documents.
    """
    depths: dict[SchemaNode, int] = {}
    expanded: dict[SchemaNode, int] = {}
    active: set[SchemaNode] = set()
    for start in graph:
        pending = [(start, False)]
        while pending:
            node, returning = pending.pop()
            if node in depths or node not in graph:
                continue
            if returning:
                depths[node] = 1 + max((depths.get(child, 0) for child in graph[node]), default=0)
                require(depths[node] <= MAX_SCHEMA_DEPTH, "SCHEMA_DEPTH")
                expanded[node] = 1 + sum(expanded.get(child, 1) for child in execution[node])
                require(expanded[node] <= MAX_EXPANDED_SCHEMA, "SCHEMA_EXPANSION_CAPACITY")
                active.remove(node)
                continue
            require(node not in active, "RECURSIVE_SCHEMA_REFERENCE")
            active.add(node)
            pending.append((node, True))
            pending.extend((child, False) for child in graph[node])
