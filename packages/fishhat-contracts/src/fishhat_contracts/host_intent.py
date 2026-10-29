"""Offline host intent projections; native custody, identity and effects stay with owners.

These values are review models, not durable records or authorization tokens. An
owner supplies the independently retained accepted claims and their original
source closure, verifies native aliases and live preimages, and commits changes
only through its ordinary accepted Operation. A projected retirement is not an
observed removal, and a projected membership set is not a native observation.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from .bounds import Bounds, bounds
from .validation import ContractError, validate

_DESTINATIONS = {
    "files": "HostFile",
    "secret_files": "HostSecretFile",
    "artifacts": "HostArtifact",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _bounds(name: str, proof: str) -> Bounds:
    return Bounds(
        id="host-intent." + name,
        work="O(B) complete accepted/proposed destination and supplementary-membership bytes; indexed target joins",
        extent="Every accepted target and every proposed patch member; no collection-count ceiling",
        limits=(),
        capacity=("receiving owner retains complete accepted claims and original input custody",),
        proofs=("tests/test_host_intent.py::" + proof,),
        linear_proofs=("tests/test_host_intent.py::test_host_intent_linear_work",),
    )


def _destination(kind: str, entry: dict[str, Any]) -> str:
    _require(kind in _DESTINATIONS, "unknown host destination kind")
    definition = (
        "HostDestinationRetirement" if entry.get("state") == "retired" else _DESTINATIONS[kind]
    )
    validate("source.schema.json", entry, definition)
    path = str(entry["destination"])
    _require(
        path.startswith("/") and all(part not in ("", ".", "..") for part in path[1:].split("/")),
        "noncanonical source target",
    )
    return path


@dataclass(frozen=True)
class DestinationProjection:
    """Proposed effective claims plus the exact explicitly selected work.

    Each effective value has kind, declaration and source_closure_digest. An
    omitted target keeps all three unchanged. Retirements retain the original
    accepted values independently of their proposed tombstones so a caller
    cannot mistake replacement metadata for permission to release old custody.
    Settled tombstones are inert; native identity checks still prevent an
    in-flight retirement from deleting a replacement at the same pathname.
    """

    effective: dict[str, dict[str, Any]]
    selected: frozenset[str]
    retirements: dict[str, dict[str, Any]]


@bounds(_bounds("destinations", "test_omission_and_destination_move_retain_original_claims"))
def project_destinations(
    accepted: Mapping[str, dict[str, Any]],
    proposed: dict[str, Any],
    *,
    source_closure_digest: str,
) -> DestinationProjection:
    """Merge complete file-like intent without authorizing any native effect.

    accepted is receiving-owner context, never data supplied by the proposal.
    Its entries are previously settled effective claims, including inert
    retirement tombstones; unresolved accepted work remains separately pinned.
    proposed is a complete Host source whose other semantic joins are checked
    by validate_host. Return values are not committed accepted state.
    """
    validate("common.schema.json", source_closure_digest, "MaterialDigest")
    validate("source.schema.json", proposed, "Host")
    effective: dict[str, dict[str, Any]] = {}
    for path, record in accepted.items():
        _require(
            set(record) == {"kind", "declaration", "source_closure_digest"},
            "invalid accepted destination claim",
        )
        _require(
            _destination(record["kind"], record["declaration"]) == path,
            "accepted destination identity mismatch",
        )
        validate("common.schema.json", record["source_closure_digest"], "MaterialDigest")
        effective[path] = deepcopy(record)
    selected: set[str] = set()
    seen: set[str] = set()
    retirements: dict[str, dict[str, Any]] = {}
    for concern in proposed["concerns"].values():
        for kind in _DESTINATIONS:
            for entry in concern[kind].values():
                path = _destination(kind, entry)
                _require(path not in seen, "destination collision")
                seen.add(path)
                previous = accepted.get(path)
                if entry["state"] == "retired":
                    _require(
                        previous is not None and previous["kind"] == kind,
                        "retirement lacks the exact accepted managed destination",
                    )
                    assert previous is not None
                    if previous["declaration"]["state"] == "retired":
                        # New live content at a settled path is not the retired object.
                        continue
                    retirements[path] = deepcopy(previous)
                else:
                    selected.add(path)
                effective[path] = {
                    "kind": kind,
                    "declaration": deepcopy(entry),
                    "source_closure_digest": source_closure_digest,
                }
    return DestinationProjection(effective, frozenset(selected), retirements)


@bounds(
    _bounds("supplementary-patch", "test_supplementary_patch_rejects_conflicts_and_legacy_shape")
)
def validate_supplementary_patch(value: dict[str, Any]) -> None:
    """Check a source patch's shape and disjoint sets, without inventing ownership."""
    validate("source.schema.json", value, "HostSupplementaryGroups")
    patch = value["supplementary"]
    _require(
        not set(patch["add"]) & set(patch["remove"]),
        "supplementary add/remove overlap",
    )


def _memberships(values: Iterable[str]) -> set[str]:
    names = list(values)
    validate("source.schema.json", names, "HostGroupNames")
    return set(names)


@dataclass(frozen=True)
class SupplementaryProjection:
    """Finite patch result with unrequested live drift kept visible for review."""

    managed: frozenset[str]
    retired: frozenset[str]
    supplementary: frozenset[str]
    additions: frozenset[str]
    removals: frozenset[str]
    adoptions: frozenset[str]
    unmanaged: frozenset[str]
    missing_managed: frozenset[str]


@bounds(_bounds("supplementary", "test_membership_patch_preserves_unowned_and_omitted_memberships"))
def project_supplementary_memberships(
    intent: dict[str, Any],
    *,
    expected_user: str,
    managed: Iterable[str],
    retired: Iterable[str],
    live_supplementary: Iterable[str],
    primary_group: str,
) -> SupplementaryProjection:
    """Project the patch against independently loaded same-user accepted claims.

    Current native user/group identities, live preimage and claim provenance are
    owner-supplied facts, not established by comparing these lexical names.
    The returned claims become accepted only after verified native settlement.
    An omitted missing managed membership remains visible drift; only an
    explicit add proposes its repair. A settled removal cannot revoke a later
    unmanaged membership, and arbitrary live membership is never a managed claim.
    """
    validate_supplementary_patch(intent)
    _require(intent["user"] == expected_user, "supplementary user identity mismatch")
    _memberships([primary_group])
    accepted = _memberships(managed)
    settled = _memberships(retired)
    live = _memberships(live_supplementary)
    add, remove = (set(intent["supplementary"][key]) for key in ("add", "remove"))
    _require(not accepted & settled, "conflicting accepted supplementary claims")
    _require(
        primary_group not in accepted | settled | live | add | remove,
        "primary group is outside supplementary intent",
    )
    _require(remove <= accepted | settled, "cannot revoke unowned supplementary membership")
    active_remove = remove & accepted
    desired = (live | add) - active_remove
    return SupplementaryProjection(
        managed=frozenset((accepted | add) - active_remove),
        retired=frozenset((settled | active_remove) - add),
        supplementary=frozenset(desired),
        additions=frozenset(add - live),
        removals=frozenset(active_remove & live),
        adoptions=frozenset((add & live) - accepted),
        unmanaged=frozenset(live - accepted - add),
        missing_managed=frozenset(accepted - live - add - remove),
    )
