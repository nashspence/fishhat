"""Typed protected-value delivery; metadata never proves private byte custody."""

from __future__ import annotations

from typing import Any

from .bounds import Bounds, bounds
from .validation import ContractError


def _bounds(name: str) -> Bounds:
    proof = "tests/test_protected_values.py::test_protected_value_transfer_linear_work"
    return Bounds(
        id="adapters.protected-values." + name,
        work="O(B) complete request and result metadata bytes",
        extent="Complete exact original invocation and returned value identities",
        limits=(),
        capacity=("Owner capacity failures preserve original effects and unresolved delivery",),
        proofs=(proof,),
        linear_proofs=(proof,),
    )


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ContractError(code)


def _selected(role: str, request: dict[str, Any]) -> bool:
    return (role == "secret-source" and request["method"] == "retrieve") or (
        role == "credential-issuer" and request["method"] in {"issue", "renew"}
    )


@bounds(_bounds("check_request"))
def check_value_request(
    role: str, request: dict[str, Any], *, owner: dict[str, Any] | None = None
) -> None:
    """Join the approved destination to the exact requested consumer and authority."""
    if not _selected(role, request):
        return
    inputs = request["input"]
    consumer = inputs["lease"]["consumer"] if request["method"] == "renew" else inputs["consumer"]
    destination = inputs["value_destination"]
    _require(
        destination["consumer"] == consumer
        and destination["owner"]["id"] == inputs["scope"]["authority"]
        and (owner is None or destination["owner"] == owner),
        "PROTECTED_VALUE_DESTINATION",
    )


@bounds(_bounds("check_response"))
def check_value_response(
    role: str,
    request: dict[str, Any],
    response: dict[str, Any],
    invocation: dict[str, Any] | None,
) -> None:
    """Validate delivery identity independently of the native effect's outcome."""
    if not _selected(role, request):
        return
    _require(invocation is not None, "PROTECTED_VALUE_INVOCATION")
    assert invocation is not None
    attempt, inputs, output = invocation["attempt"], request["input"], response["output"]
    handoff = output["handoff"]
    _require(
        handoff["destination"] == inputs["value_destination"]
        and handoff["destination"]["owner"] == attempt["owner"],
        "PROTECTED_VALUE_DESTINATION",
    )
    records = output["versions" if role == "secret-source" else "leases"]
    if role == "secret-source":
        _require(
            all(
                record["source"] == attempt["executor"]["instance"]
                and record["entry"] == inputs["entry"]
                and record["version"] == inputs["version"]
                for record in records
            ),
            "PROTECTED_VALUE_SOURCE",
        )
    handle = handoff["value_handle"]
    _require(
        handle is None or sum(record["value_handle"] == handle for record in records) == 1,
        "PROTECTED_VALUE_IDENTITY",
    )


@bounds(_bounds("require_custody"))
def require_value_custody(role: str, request: dict[str, Any], response: dict[str, Any]) -> None:
    """Reject a successful Operation with unresolved value delivery metadata.

    Native receivers separately commit exact private bytes before signing success;
    a declared available handoff is necessary and never sufficient proof of custody.
    """
    if _selected(role, request):
        _require(
            response["output"]["handoff"]["state"] == "available",
            "SUCCESSFUL_OPERATION_REQUIRES_VALUE_CUSTODY",
        )
