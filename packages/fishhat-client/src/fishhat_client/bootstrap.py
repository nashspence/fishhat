"""Bounded, provider-neutral source-bootstrap record and handoff models.

These functions do not fetch, decrypt, restore, authorize, load an implementation,
or execute native code. Independently trusted catalogue/kit digests are caller
inputs, not values discovered from the candidate records. Artifact bytes, staging
permissions, native verification and effect reconciliation need native evidence.
"""

from __future__ import annotations

import copy
from typing import Any, BinaryIO

from fishhat_adapters import check_configuration, check_descriptor, check_request
from fishhat_contracts.artifact_custody import verify_artifact_stream
from fishhat_contracts.bounds import Bounds, bounds
from fishhat_contracts.publication import require_bootstrap_ref_target
from fishhat_contracts.validation import MAX_BYTES, ContractError, canonical, digest, validate

from fishhat_client.workspace import clean_path, within


def _bounded(value: dict[str, Any]) -> None:
    if len(canonical(value)) > MAX_BYTES:
        raise ContractError("bootstrap record capacity")


def validate_selection(selection: dict[str, Any]) -> dict[str, Any]:
    _bounded(selection)
    validate("bootstrap-recovery.schema.json", selection)
    root = clean_path(selection["recovery_root"], absolute=True)
    if (
        root in ("/workspace", "/var", "/etc", "/home", "/tmp", "/recovery")
        or len(root.split("/")) < 4
    ):
        raise ContractError("dedicated fresh staging root required")
    require_bootstrap_ref_target(
        selection["ref"], selection["ref_object_id"], selection["expected_commit"]
    )
    return selection


@bounds(
    Bounds(
        id="bootstrap.catalogue",
        linear_proofs=("tests/test_linear_growth.py::test_catalogue_linear_work",),
        work="O(B + S) bounded reference record validation and one source identity pass",
        extent="All S sources in the catalogue; no prefix selection or silent truncation",
        limits=(),
        capacity=("native readers enforce explicitly approved capacity without omitting sources",),
        proofs=("tests/test_bootstrap.py::test_catalogue_extent_and_source_visits",),
    )
)
def validate_catalogue(
    catalogue: dict[str, Any],
    *,
    selection: dict[str, Any] | None = None,
    require_published: bool = False,
) -> dict[str, Any]:
    # A full catalogue can exceed one wire frame; native acquisition uses bounded
    # reads over a pinned complete document rather than rejecting a fixed source count.
    validate("bootstrap-catalogue.schema.json", catalogue)
    if require_published and catalogue["publication_state"] != "independently-verified":
        raise ContractError("candidate is not independently retrievable recovery evidence")
    ids = set()
    matched = None
    for item in catalogue["sources"]:
        require_bootstrap_ref_target(item["ref"], item["ref_object_id"], item["commit"])
        if item["source_id"] in ids:
            raise ContractError("ambiguous recovery source")
        ids.add(item["source_id"])
        if selection is not None and item["source_id"] == selection.get("source_id"):
            matched = item
    if selection is not None:
        validate_selection(selection)
        if digest(catalogue) != selection["catalogue_digest"] or any(
            catalogue[k] != selection[k] for k in ("domain_id", "kit_manifest_digest")
        ):
            raise ContractError("selection/catalogue mismatch")
        if matched is None or any(
            matched[a] != selection[b]
            for a, b in (
                ("ref", "ref"),
                ("ref_object_id", "ref_object_id"),
                ("commit", "expected_commit"),
                ("adapter", "adapter"),
                ("capture", "capture"),
                ("tree", "tree"),
            )
        ):
            raise ContractError("selected source not in recovery catalogue")
    return catalogue


def prepare_request(
    selection: dict[str, Any],
    catalogue: dict[str, Any],
    *,
    installation: dict[str, Any],
    descriptor: dict[str, Any],
    configuration: dict[str, Any],
    source: dict[str, Any],
    scope: dict[str, Any],
    trusted_catalogue_digest: str,
    trusted_kit_digest: str,
) -> dict[str, Any]:
    """Check pinned records and construct a request, never an execution permission.

    The caller supplies an authenticated authority scope. This model does not
    enroll an adapter or recover an owner journal; an executor still has to
    establish its own authorization, verify installed bytes and reconcile effects.
    """
    validate_catalogue(catalogue, selection=selection, require_published=True)
    if (
        selection["catalogue_digest"] != trusted_catalogue_digest
        or selection["kit_manifest_digest"] != trusted_kit_digest
    ):
        raise ContractError("independent recovery pins mismatch")
    _bounded(descriptor)
    _bounded(installation)
    check_descriptor(descriptor)
    validate("adapter.schema.json", installation, "Installation")
    binding = selection["adapter"]
    if (
        "bootstrap-source" not in descriptor["roles"]
        or descriptor["id"] != binding["implementation"]
        or installation["implementation"] != descriptor["id"]
        or not installation["enabled"]
        or installation["artifact"]["digest"] != binding["installation_digest"]
        or installation["descriptor_digest"] != binding["descriptor_digest"]
        or digest(descriptor) != binding["descriptor_digest"]
    ):
        raise ContractError("bootstrap adapter binding mismatch")
    _bounded(configuration)
    if digest(configuration) != binding["configuration_digest"]:
        raise ContractError("bootstrap configuration mismatch")
    check_configuration(
        descriptor["configuration_schema"],
        configuration,
        digest(descriptor["configuration_schema"]),
    )
    _bounded(source)
    check_configuration(descriptor["source_schema"], source, binding["source_schema_digest"])
    capture = selection["capture"]
    if (
        capture["media_type"] != "application/json"
        or capture["digest"] != digest(source)
        or capture["size_bytes"] != len(canonical(source))
    ):
        raise ContractError("bootstrap capture identity mismatch")
    request = {
        "contract": "fishhat.bootstrap-source",
        "method": "recover",
        "input": {"scope": copy.deepcopy(scope), "selection": copy.deepcopy(selection)},
    }
    check_request("bootstrap-source", request)
    if scope["kind"] != "repository" or scope["handle"] != selection["source_id"]:
        raise ContractError("bootstrap source scope mismatch")
    return request


def validate_receipt(receipt: dict[str, Any], selection: dict[str, Any]) -> dict[str, Any]:
    """Check receipt correlation, not native success or independently authenticated evidence."""
    validate_selection(selection)
    _bounded(receipt)
    validate("client-records.schema.json", receipt, "SourceRecovery")
    if receipt["selection_digest"] != digest(selection) or any(
        receipt[a] != selection[b]
        for a, b in (
            ("domain_id", "domain_id"),
            ("source_id", "source_id"),
            ("ref", "ref"),
            ("ref_object_id", "ref_object_id"),
            ("commit", "expected_commit"),
            ("tree", "tree"),
        )
    ):
        raise ContractError("source recovery receipt identity mismatch")
    destination = clean_path(receipt["destination"], absolute=True)
    root = selection["recovery_root"]
    if destination == root or not within(destination, root):
        raise ContractError("source recovery output outside staging")
    return receipt


def prepare_verification(
    receipt: dict[str, Any],
    selection: dict[str, Any],
    *,
    scope: dict[str, Any],
    retained_bundle: BinaryIO,
) -> dict[str, Any]:
    """Join an authenticated original recovery receipt to independently retained bytes.

    The caller supplies an independently trusted selection and scope, verifies
    original receiver provenance and opens immutable bundle custody at byte zero.
    Git ref, object graph and tree verification belongs to the receiving adapter.
    """
    validate_receipt(receipt, selection)
    verify_artifact_stream(receipt["output"], retained_bundle)
    request = {
        "contract": "fishhat.bootstrap-source",
        "method": "verify",
        "input": {
            "scope": copy.deepcopy(scope),
            "selection": copy.deepcopy(selection),
            "recovery": copy.deepcopy(receipt),
        },
    }
    check_request("bootstrap-source", request)
    return request
