"""Provider-neutral publication joins; signatures and provider effects remain external."""

from __future__ import annotations

from typing import Any

from .validation import ContractError, digest, validate


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def validate_publication(value: dict[str, Any]) -> None:
    """Validate immutable publication identity without trusting embedded authority."""
    validate("publisher-receipt.schema.json", value)
    previous = value["previous"]
    if previous is not None:
        _require(
            previous["source"] == value["source"] and previous["entry"] == value["entry"],
            "publication predecessor destination mismatch",
        )
        _require(
            value["version"] != previous["version"],
            "publication cannot replace an immutable version",
        )
    candidate = value["recovery_handle"]
    _require(
        candidate["owner"] == value["custodian"] and candidate["purpose"] == "secret-candidate",
        "publication candidate custody mismatch",
    )
    current = value["current"]
    if current is not None:
        _require(
            current["artifact_digest"] == candidate["digest"]
            and current["bytes"] == candidate["size"]
            and current["version"] == value["version"],
            "publication material identity mismatch",
        )
    evidence = value["provider_evidence"]
    if evidence["handle"] is not None:
        _require(
            evidence["handle"]["owner"] == value["custodian"]
            and evidence["handle"]["purpose"] == "content",
            "publication provider evidence custody mismatch",
        )
    witness = value["witness"]
    _require(
        witness["owner"] == value["custodian"]
        and witness["kind"] == "publication"
        and witness["state"] == value["state"]
        and witness["subject_digest"] == digest({k: v for k, v in value.items() if k != "witness"}),
        "publication witness identity mismatch",
    )


def validate_publication_result(
    value: dict[str, Any],
    subject: dict[str, Any],
    *,
    expected_custodian: dict[str, Any],
    original_receipt: dict[str, Any] | None = None,
) -> None:
    """Join an outcome to retained reviewed intent and independently known custody.

    Recovery requires the receiver's retained original receipt. An embedded source
    binding or schema never grants permission, supplies a reader or authenticates
    the outcome. Independently verified provider evidence is required for use.
    """
    validate_publication(value)
    validate("actions.schema.json", subject)
    _require(value["custodian"] == expected_custodian, "publication custodian epoch mismatch")
    arguments = subject["arguments"]
    action = subject["action"]
    if action == "publisher.publish":
        _require(
            all(
                value[key] == arguments[key]
                for key in ("source", "entry", "consumer", "version", "catalogue_digest")
            )
            and value["previous"] == arguments["expected_previous"]
            and value["recovery_handle"] == arguments["candidate"]
            and value["provider_evidence"]["schema"] == arguments["evidence_schema"],
            "publication reviewed destination or candidate mismatch",
        )
        if value["current"] is not None:
            _require(
                value["current"]["version"] == arguments["version"],
                "publication reviewed version mismatch",
            )
    elif action == "publisher.recover":
        _require(original_receipt is not None, "publication recovery lacks retained origin")
        assert original_receipt is not None
        validate_publication(original_receipt)
        if original_receipt["state"] == "completed":
            _require(value == original_receipt, "completed publication outcome is immutable")
        _require(
            value["id"] == original_receipt["id"] == arguments["publication_id"]
            and value["recovery_handle"]["digest"] == arguments["candidate_digest"]
            and value["provider_evidence"]["schema"]
            == original_receipt["provider_evidence"]["schema"]
            and all(
                value[key] == original_receipt[key]
                for key in (
                    "source",
                    "entry",
                    "consumer",
                    "version",
                    "catalogue_digest",
                    "previous",
                    "custodian",
                    "recovery_handle",
                )
            ),
            "publication recovery changed retained intent",
        )
        if original_receipt["current"] is not None:
            _require(
                value["current"] == original_receipt["current"],
                "publication recovery changed immutable version",
            )
    else:
        raise ContractError("publication result has no matching action")
