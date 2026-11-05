"""Provider-neutral publication joins; signatures and provider effects remain external."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .validation import ContractError, digest, validate


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def require_bootstrap_ref_target(ref: str, object_id: str, commit: str) -> None:
    """Check relationships after schema validation, before native Git verification."""
    _require(
        len(object_id) == len(commit)
        and (not ref.startswith("refs/heads/") or object_id == commit),
        "bootstrap ref object differs from selected repository format or branch commit",
    )


def validate_publication_intent(
    *,
    source: dict[str, Any],
    entry: str,
    version: str,
    expected_previous: dict[str, Any] | None,
) -> None:
    """Reject contradictory publication intent before admission or native effects.

    The receiver still independently checks current provider state, protected
    candidate custody and permission. Null means verified absence is required;
    these data checks do not establish it or authorize a publication.
    """
    validate("adapter.schema.json", source, "InstanceReference")
    validate("common.schema.json", entry, "Entry")
    validate("adapter.schema.json", version, "Handle")
    _require(source["role"] == "secret-source", "publication source role mismatch")
    if expected_previous is None:
        return
    validate("adapter.schema.json", expected_previous, "SecretPublicationPredecessor")
    _require(
        expected_previous["source"] == source and expected_previous["entry"] == entry,
        "publication predecessor destination mismatch",
    )
    _require(
        version != expected_previous["version"],
        "publication cannot replace an immutable version",
    )


def validate_publication(value: dict[str, Any]) -> None:
    """Validate immutable publication identity without trusting embedded authority."""
    validate("publisher-receipt.schema.json", value)
    validate_publication_intent(
        source=value["source"],
        entry=value["entry"],
        version=value["version"],
        expected_previous=value["previous"],
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
        validate_publication_intent(
            source=arguments["source"],
            entry=arguments["entry"],
            version=arguments["version"],
            expected_previous=arguments["expected_previous"],
        )
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


def require_repository_publication(
    request: dict[str, Any],
    *,
    current_object_id: str | None,
    symbolic: bool,
    is_ancestor: Callable[[str, str], bool],
    source_proposal: dict[str, Any] | None = None,
    read_commit_parents: Callable[[str], tuple[str, ...]] | None = None,
    verify_proposal_tree: Callable[[dict[str, Any], str], bool] | None = None,
) -> None:
    """Check independently observed literal-ref facts under native CAS or exclusion.

    The adapter reads directness and the unpeeled object without dereferencing.
    A null current_object_id means positively verified literal absence. An
    uncertain observation cannot supply these facts. The adapter supplies
    verified reachability in the exact retained repository, rejecting
    incomplete history. A source publisher also supplies the independently
    retained reviewed proposal and the entire parent list from the raw candidate
    commit, without grafts or replace refs. Its verifier compares the candidate commit's
    complete Git root tree with the tree independently derived by applying the
    verified proposal to its pinned base, preserving every unselected entry.
    The native caller must preserve these facts
    atomically through its update; this pure check never mutates or reserves a ref.
    """
    validate("repository-adapter.schema.json", request)
    _require(request["method"] == "publish", "expected repository publication")
    inputs = request["input"]
    candidate = inputs["candidate"]
    _require(candidate["repository"] == inputs["repository"], "repository candidate changed")
    _require(symbolic is False, "symbolic or unverified publication target")
    if current_object_id is not None:
        validate("repository-adapter.schema.json", current_object_id, "ObjectId")
    previous = inputs["expected_previous"]
    _require(previous.get("object_id") == current_object_id, "repository predecessor changed")
    if source_proposal is not None:
        from .action_results import validate_source_proposal

        validate_source_proposal(source_proposal)
        base = source_proposal["base_commit"]
        if current_object_id is not None and inputs["ref"].startswith("refs/heads/"):
            _require(current_object_id == base, "branch advanced beyond reviewed base")
        _require(
            source_proposal["repository"] == inputs["repository"]["canonical"]
            and source_proposal["ref"] == inputs["ref"]
            and read_commit_parents is not None
            and read_commit_parents(candidate["commit"]) == (base,),
            "candidate differs from reviewed source history",
        )
        _require(
            verify_proposal_tree is not None
            and verify_proposal_tree(source_proposal, candidate["commit"]) is True,
            "candidate tree differs from reviewed proposal",
        )
    elif current_object_id is not None and inputs["ref"].startswith("refs/heads/"):
        _require(
            is_ancestor(current_object_id, candidate["commit"]) is True,
            "divergent or unverified publication",
        )
