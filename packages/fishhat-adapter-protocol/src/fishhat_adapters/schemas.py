"""Closed provider-schema validation, with schema positions distinct from literal data."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from contextvars import ContextVar
from datetime import datetime
from typing import Any, cast

from fishhat_contracts.json_work import unique_items
from fishhat_contracts.schema_profile import (
    FORMATS,
    MAX_EXPANDED_SCHEMA,
    MAX_SCHEMA_DEPTH,
    check_assertions,
    check_document,
    pointer_tokens,
    regex_degree,
    schema_children,
)
from fishhat_contracts.validation import FORMAT_CHECKER, ContractError, canonical
from jsonschema import Draft202012Validator, FormatChecker, validators

Path = tuple[str, ...]
ALL_TYPES = frozenset({"null", "boolean", "number", "string", "object", "array"})
PROVIDER_FORMAT_CHECKER = FormatChecker()
PROVIDER_FORMAT_CHECKER.checkers = {name: FORMAT_CHECKER.checkers[name] for name in FORMATS}
MAX_EVALUATION_WORK = 2_000_000
_WORK: ContextVar[list[int] | None] = ContextVar("provider_schema_work", default=None)


@PROVIDER_FORMAT_CHECKER.checks("date", raises=ValueError)
def _calendar_date(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
        return False
    year, month, day = map(int, value.split("-"))
    datetime(2000 + year % 400, month, day)
    return True


def _charge(keyword: str, constraint: Any, value: Any, schema: Any) -> None:
    work = _WORK.get()
    if work is None:
        return
    cost = 1
    if keyword == "uniqueItems" and constraint and isinstance(value, list):
        cost += len(canonical(value))
    elif keyword == "const":
        cost += len(canonical(value)) + len(canonical(constraint))
    elif keyword == "enum":
        cost += len(constraint) * len(canonical(value)) + len(canonical(constraint))
    patterns: Iterable[tuple[str, str]] = ()
    if keyword == "pattern" and isinstance(value, str):
        patterns = [(constraint, value)]
    elif keyword == "patternProperties" and isinstance(value, dict):
        patterns = ((pattern, key) for pattern in constraint for key in value)
    elif keyword == "additionalProperties" and isinstance(value, dict):
        patterns = (
            (pattern, key) for pattern in schema.get("patternProperties", {}) for key in value
        )
    work[0] += cost
    require(work[0] <= MAX_EVALUATION_WORK, "SCHEMA_EVALUATION_CAPACITY")
    for pattern, subject in patterns:
        require(len(subject) <= 4096, "SCHEMA_REGEX_INPUT_CAPACITY")
        work[0] += 8 * (len(subject) + 1) ** regex_degree(pattern)
        require(work[0] <= MAX_EVALUATION_WORK, "SCHEMA_EVALUATION_CAPACITY")


def _bounded(keyword: str, function: Any) -> Any:
    def check(validator: Any, constraint: Any, value: Any, schema: Any) -> Any:
        _charge(keyword, constraint, value, schema)
        yield from function(validator, constraint, value, schema)

    return check


_VALIDATOR = cast(Callable[..., Any], validators.extend)(
    Draft202012Validator,
    {
        key: _bounded(key, unique_items if key == "uniqueItems" else function)
        for key, function in Draft202012Validator.VALIDATORS.items()
    },
)


def validate_configuration(schema: dict[str, Any], value: Any) -> bool:
    """Apply the declared assertion profile under an explicit work admission limit."""
    token = _WORK.set([0])
    try:
        errors = _VALIDATOR(schema, format_checker=PROVIDER_FORMAT_CHECKER).iter_errors(value)
        return next(errors, None) is None
    finally:
        _WORK.reset(token)


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ContractError(code)


def check_closed_schema(schema: dict[str, Any]) -> None:
    """Require structural closure, static acyclic local references and bounded schema work.

    Finite const/enum values are exact data. An unconstrained predicate may refine
    an already closed value, but cannot introduce an arbitrary object or array.
    """
    require(len(canonical(schema)) <= 262144, "SCHEMA_CAPACITY")
    check_document(schema, code="INVALID_CONFIGURATION_SCHEMA")
    checker = _ClosedSchema(schema)
    checker.check()


class _ClosedSchema:
    def __init__(self, schema: dict[str, Any]) -> None:
        self.schema = schema
        self.nodes: dict[Path, Any] = {}
        self.edges: dict[Path, list[Path]] = {}
        self.references: dict[Path, Path] = {}
        self.active: set[Path] = set()
        self.done: set[Path] = set()
        self.type_cache: dict[Path, frozenset[str]] = {}
        self.closed_cache: dict[tuple[Path, str], bool] = {}
        self.checked: set[tuple[Path, frozenset[str], bool, bool]] = set()

    def check(self) -> None:
        self._walk(self.schema)
        for path, target in self.references.items():
            require(target in self.nodes, "UNRESOLVED_SCHEMA_REFERENCE")
            self.edges[path].append(target)
        self._acyclic(())
        self._expanded((), {})
        self._shape(())

    def _walk(self, node: Any, path: Path = (), depth: int = 0) -> None:
        require(depth <= MAX_SCHEMA_DEPTH, "SCHEMA_DEPTH")
        self.nodes[path], self.edges[path] = node, []
        if isinstance(node, bool):
            return
        require(not path or "$id" not in node, "NESTED_SCHEMA_IDENTITY")
        require(not path or "$schema" not in node, "NESTED_SCHEMA_DIALECT")
        require(
            not {"$dynamicRef", "$recursiveRef", "$dynamicAnchor", "$recursiveAnchor"}
            & node.keys(),
            "DYNAMIC_SCHEMA_REFERENCE",
        )
        require(
            "$schema" not in node
            or node["$schema"] == "https://json-schema.org/draft/2020-12/schema",
            "UNSUPPORTED_SCHEMA_DIALECT",
        )
        check_assertions(node)
        if "$ref" in node:
            self.references[path] = self._target(node["$ref"])
        children = schema_children(node)
        for suffix, child in children:
            child_path = (*path, *suffix)
            self.edges[path].append(child_path)
            self._walk(child, child_path, depth + 1)

    @staticmethod
    def _target(ref: str) -> Path:
        require(ref == "#" or ref.startswith("#/"), "NONLOCAL_SCHEMA_REFERENCE")
        return pointer_tokens(ref[1:], code="INVALID_SCHEMA_REFERENCE")

    def _acyclic(self, path: Path) -> None:
        require(path not in self.active, "RECURSIVE_SCHEMA_REFERENCE")
        require(len(self.active) <= MAX_SCHEMA_DEPTH, "SCHEMA_DEPTH")
        if path in self.done:
            return
        self.active.add(path)
        for child in self.edges[path]:
            self._acyclic(child)
        self.active.remove(path)
        self.done.add(path)

    def _expanded(self, path: Path, sizes: dict[Path, int]) -> int:
        if path not in sizes:
            sizes[path] = 1 + sum(self._expanded(child, sizes) for child in self.edges[path])
            require(sizes[path] <= MAX_EXPANDED_SCHEMA, "SCHEMA_EXPANSION_CAPACITY")
        return sizes[path]

    @staticmethod
    def _literal_type(value: Any) -> str:
        return {
            type(None): "null",
            bool: "boolean",
            int: "number",
            str: "string",
            dict: "object",
            list: "array",
        }[type(value)]

    def _possible(self, path: Path) -> frozenset[str]:
        if path in self.type_cache:
            return self.type_cache[path]
        node = self.nodes[path]
        result = ALL_TYPES if node is not False else frozenset()
        if isinstance(node, dict):
            if "type" in node:
                types = node["type"] if isinstance(node["type"], list) else [node["type"]]
                result &= {"number" if kind == "integer" else kind for kind in types}
            if "const" in node:
                result &= {self._literal_type(node["const"])}
            if "enum" in node:
                result &= {self._literal_type(value) for value in node["enum"]}
            if path in self.references:
                result &= self._possible(self.references[path])
            for i, _ in enumerate(node.get("allOf", [])):
                result &= self._possible((*path, "allOf", str(i)))
            for key in ("anyOf", "oneOf"):
                if key in node:
                    result &= frozenset().union(
                        *(self._possible((*path, key, str(i))) for i, _ in enumerate(node[key]))
                    )
        self.type_cache[path] = frozenset(result)
        return self.type_cache[path]

    def _closed(self, path: Path, kind: str) -> bool:
        cache_key = path, kind
        if cache_key in self.closed_cache:
            return self.closed_cache[cache_key]
        node = self.nodes[path]
        result = kind not in self._possible(path)
        if isinstance(node, dict):
            result = result or "const" in node or "enum" in node
            result = result or (kind == "object" and node.get("additionalProperties") is False)
            result = result or (kind == "array" and "items" in node and node["items"] is not True)
            result = result or (
                path in self.references and self._closed(self.references[path], kind)
            )
            result = result or any(
                self._closed((*path, "allOf", str(i)), kind)
                for i, _ in enumerate(node.get("allOf", []))
            )
            for key in ("anyOf", "oneOf"):
                result = result or (
                    key in node
                    and all(
                        self._closed((*path, key, str(i)), kind) for i, _ in enumerate(node[key])
                    )
                )
            result = result or (
                "if" in node
                and "then" in node
                and "else" in node
                and self._closed((*path, "then"), kind)
                and self._closed((*path, "else"), kind)
            )
        self.closed_cache[cache_key] = result
        return result

    def _shape(
        self,
        path: Path,
        allowed: frozenset[str] = ALL_TYPES,
        obj: bool = False,
        array: bool = False,
    ) -> None:
        types = self._possible(path) & allowed
        obj, array = obj or self._closed(path, "object"), array or self._closed(path, "array")
        key = path, types, obj, array
        if key in self.checked:
            return
        self.checked.add(key)
        require("object" not in types or obj, "OPEN_OBJECT_SCHEMA")
        require("array" not in types or array, "OPEN_ARRAY_SCHEMA")
        node = self.nodes[path]
        if not isinstance(node, dict):
            return
        if "object" in types:
            for field in ("properties", "patternProperties"):
                for name in node.get(field, {}):
                    self._shape((*path, field, name))
            if "propertyNames" in node:
                self._shape((*path, "propertyNames"), frozenset({"string"}))
            for name in node.get("dependentSchemas", {}):
                self._shape((*path, "dependentSchemas", name), types, obj, array)
        if "array" in types:
            if "items" in node:
                self._shape((*path, "items"))
            for i, _ in enumerate(node.get("prefixItems", [])):
                self._shape((*path, "prefixItems", str(i)))
        if path in self.references:
            self._shape(self.references[path], types, obj, array)
        for field in ("allOf", "anyOf", "oneOf"):
            for i, _ in enumerate(node.get(field, [])):
                self._shape((*path, field, str(i)), types, obj, array)
        for field in ("then", "else"):
            if field in node:
                self._shape((*path, field), types, obj, array)
