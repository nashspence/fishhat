"""Exact scoped adapter observations and incremental stable-snapshot intake.

These data checks do not authenticate an executor, approve historical mappings,
verify native snapshot identity or replace current receiver authorization.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .bounds import Bounds, bounds
from .validation import ContractError, canonical, digest, validate

_ROLES = {"runtime", "secret-source", "credential-issuer"}


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ContractError(code)


def _issuer_matches(issuer: dict[str, Any], binding: dict[str, Any]) -> bool:
    return bool(
        issuer["role"] == "credential-issuer"
        and issuer["scope"] == binding["scope"]
        and issuer["instance"] == binding["instance"]
    )


def _observation_keys(role: str, request: dict[str, Any], response: dict[str, Any]) -> set[bytes]:
    """Check each page once, retaining exact historical producer identities."""
    if role not in _ROLES or request["method"] not in {"observe", "inventory"}:
        return set()
    inputs, output = request["input"], response["output"]
    binding = inputs["binding"]
    records = output[{"runtime": "objects", "secret-source": "versions"}.get(role, "leases")]
    keys: set[bytes] = set()
    for record in records:
        if role == "runtime":
            _require(record["scope"] == inputs["scope"], "OBSERVATION_OBJECT_SCOPE")
            key = canonical(record["handle"])
        elif role == "secret-source":
            _require(record["source"] == binding["instance"], "OBSERVATION_SOURCE_IDENTITY")
            key = canonical([record["source"], record["entry"], record["version"]])
        else:
            _require(_issuer_matches(record["issuer"], binding), "OBSERVATION_ISSUER_IDENTITY")
            key = canonical(record["lease"])
        _require(key not in keys, "OBSERVATION_DUPLICATE_IDENTITY")
        keys.add(key)
    if role == "runtime" and output["observation"] is not None:
        observed = output["observation"]
        _require(
            observed["instance"] == binding["instance"]
            and observed["installation_digest"] == binding["installation_digest"],
            "OBSERVATION_EXECUTOR_IDENTITY",
        )
    return keys


def _query(request: dict[str, Any]) -> bytes:
    return canonical(
        {
            **request,
            "input": {key: value for key, value in request["input"].items() if key != "cursor"},
        }
    )


def _sequence_bounds(name: str) -> Bounds:
    proof = "tests/test_adapter_observation_identity.py::test_observation_sequence_linear_work"
    return Bounds(
        id="adapters.observation-sequence." + name,
        work=(
            "O(B) complete initial request and independently approved issuer references once; "
            "then O(P) each page and retry, O(B + sum(P)) for the complete traversal"
        ),
        extent="All records and pages; indexed logical identities and exact page retry commitments",
        limits=(),
        capacity=("Receiver capacity failures remain explicit; no total record or page cap",),
        proofs=(proof,),
        linear_proofs=(proof,),
    )


class ObservationSequence:
    """Incrementally check one independently authorized adapter snapshot traversal.

    The owner supplies its exact approved observer binding, the separately
    approved runtime target for runtime observations, and any independently
    approved historical issuer-to-observer mappings. Request or response data
    cannot populate those approvals. Each page still requires native snapshot,
    current-permission and cursor checks outside this pure reference model.

    Logical identities occur once per snapshot. Exact page retries are accepted
    without consuming records twice; a repeated identity on a different page or
    changed reply to the same request rejects. Failed intake leaves state intact.
    """

    @bounds(_sequence_bounds("start"))
    def __init__(
        self,
        role: str,
        request: dict[str, Any],
        *,
        approved_binding: dict[str, Any],
        approved_runtime_binding: dict[str, Any] | None = None,
        approved_issuers: Iterable[dict[str, Any]] = (),
    ) -> None:
        from .adapter_semantics import check_request

        check_request(role, request)
        _require(
            role in _ROLES
            and request["method"] in {"observe", "inventory"}
            and request["input"]["cursor"] is None,
            "OBSERVATION_SEQUENCE_START",
        )
        _require(request["input"]["binding"] == approved_binding, "OBSERVATION_APPROVED_BINDING")
        _require(
            (role == "runtime" and request["input"]["target"] == approved_runtime_binding)
            or (role != "runtime" and approved_runtime_binding is None),
            "OBSERVATION_APPROVED_TARGET",
        )
        self._role = role
        self._query = _query(request)
        self._issuers = {canonical(approved_binding)}
        for issuer in approved_issuers:
            validate("adapter.schema.json", issuer, "InstanceReference")
            _require(
                role == "credential-issuer" and _issuer_matches(issuer, approved_binding),
                "OBSERVATION_APPROVED_ISSUER",
            )
            self._issuers.add(canonical(issuer))
        self._next_cursor: str | None = None
        self._cursors: set[str | None] = set()
        self._replies: dict[str, str] = {}
        self._identities: set[bytes] = set()
        self._closed = False
        self._complete = False

    @property
    def complete(self) -> bool:
        """Whether an accepted final page claimed complete, not unknown, coverage."""
        return self._complete

    @bounds(_sequence_bounds("accept"))
    def accept(self, request: dict[str, Any], response: dict[str, Any]) -> bool:
        """Accept one new page (True) or exact prior retry (False), with page-only work."""
        from .adapter_semantics import check_response

        check_response(self._role, request, response)
        _require(_query(request) == self._query, "OBSERVATION_SEQUENCE_QUERY")
        request_digest, response_digest = digest(request), digest(response)
        previous = self._replies.get(request_digest)
        if previous is not None:
            _require(previous == response_digest, "OBSERVATION_PAGE_REPLAY_CHANGED")
            return False
        cursor, continuation = request["input"]["cursor"], response["continuation"]
        _require(not self._closed and cursor == self._next_cursor, "OBSERVATION_SEQUENCE_CURSOR")
        _require(
            continuation is None or continuation not in self._cursors,
            "OBSERVATION_CURSOR_CYCLE",
        )
        identities = _observation_keys(self._role, request, response)
        _require(
            all(identity not in self._identities for identity in identities),
            "OBSERVATION_DUPLICATE_IDENTITY",
        )
        if self._role == "credential-issuer":
            _require(
                all(
                    canonical(lease["issuer"]) in self._issuers
                    for lease in response["output"]["leases"]
                ),
                "OBSERVATION_HISTORICAL_ISSUER_UNAPPROVED",
            )
        self._identities.update(identities)
        self._cursors.add(cursor)
        self._replies[request_digest] = response_digest
        self._next_cursor = continuation
        self._closed = response["coverage"] != "incomplete"
        self._complete = response["coverage"] == "complete"
        return True
