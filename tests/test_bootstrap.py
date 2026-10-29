"""Synthetic bootstrap records and read-only adapter handoffs, not native recovery."""

from __future__ import annotations

import contextlib
import copy
import io
import json
from unittest.mock import patch

import pytest
from fishhat_adapter_support import main as adapter_main
from fishhat_adapters import ROLES, Registry, check_configuration, check_request, check_response
from fishhat_client.bootstrap import (
    prepare_request,
    validate_catalogue,
    validate_receipt,
    validate_selection,
)
from fishhat_contracts.validation import ContractError, canonical, digest

from tests.adapter_support import OWNER, D, descriptors, identifier
from tests.support import FIXTURES

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/bootstrap-recovery.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/bootstrap-source-adapter.schema.json",
    ],
    "scope": "bounded offline bootstrap records, provider schemas and reference handoffs",
    "relationship": "candidate",
    "reason": "Fixed synthetic identities and rejection checks; no backend restore, trusted installation, native authorization or failure reconciliation is executed.",
    "claims": [],
}

PROVIDERS = ("forgejo-restic", "git-bundle")


def fixture(name):
    return json.loads((FIXTURES / "bootstrap" / (name + ".json")).read_text())


def records(provider):
    prefix = "" if provider == "forgejo-restic" else "git-bundle-"
    descriptor = json.loads(next(p for p in descriptors() if provider in p.parts).read_text())
    selection = fixture(prefix + "selection")
    return {
        "selection": selection,
        "catalogue": fixture(prefix + "catalogue"),
        "installation": {
            "implementation": descriptor["id"],
            "artifact": {"digest": D, "media_type": "application/zip", "size_bytes": 100},
            "descriptor_digest": digest(descriptor),
            "enabled": True,
        },
        "descriptor": descriptor,
        "configuration": fixture(provider + "-configuration"),
        "source": fixture(provider + "-source"),
        "scope": {
            "authority": "00000000-0000-4000-8000-000000000001",
            "kind": "repository",
            "handle": "domain",
        },
        "trusted_catalogue_digest": selection["catalogue_digest"],
        "trusted_kit_digest": selection["kit_manifest_digest"],
    }


def reseal(value):
    """An explicitly reselected synthetic input, never independent trust evidence."""
    selection, catalogue = value["selection"], value["catalogue"]
    descriptor = value["descriptor"]
    value["installation"]["implementation"] = descriptor["id"]
    value["installation"]["descriptor_digest"] = digest(descriptor)
    selection["adapter"].update(
        implementation=descriptor["id"],
        descriptor_digest=digest(descriptor),
        configuration_digest=digest(value["configuration"]),
        source_schema_digest=digest(descriptor["source_schema"]),
    )
    selection["capture"] = {
        "digest": digest(value["source"]),
        "size_bytes": len(canonical(value["source"])),
        "media_type": "application/json",
    }
    catalogue["sources"][0].update(
        adapter=copy.deepcopy(selection["adapter"]),
        capture=copy.deepcopy(selection["capture"]),
    )
    selection["catalogue_digest"] = digest(catalogue)
    value["trusted_catalogue_digest"] = digest(catalogue)


@pytest.mark.parametrize("provider", PROVIDERS)
def test_both_providers_share_one_inert_source_request(provider):
    value = records(provider)
    original = copy.deepcopy(value)
    request = prepare_request(**value)
    assert value == original
    assert request == {
        "contract": "fishhat.bootstrap-source",
        "method": "recover",
        "input": {"scope": value["scope"], "selection": value["selection"]},
    }
    request["input"]["selection"]["source_id"] = "another"
    assert value == original
    assert "configuration" not in request["input"]
    assert "source" not in request["input"]


def test_bundle_needs_no_forge_identity_snapshot_or_credentials():
    value = records("git-bundle")
    assert set(value["configuration"]) == {"bundle_handle"}
    assert set(value["source"]) == {"bundle", "require_self_contained"}
    prepare_request(**value)


@pytest.mark.parametrize(
    "member",
    [
        "snapshot_id",
        "restic_repository_id",
        "bare_repository_path",
        "helper_commit",
        "helper_blob",
        "source_identity",
        "private_profile_handle",
        "branch",
    ],
)
def test_provider_details_are_not_generic_selection_fields(member):
    selection = records("git-bundle")["selection"]
    selection[member] = "unselected"
    with pytest.raises(ContractError):
        validate_selection(selection)


@pytest.mark.parametrize("member", ["force_checkout", "install_dependencies", "download_tools"])
def test_selection_cannot_enable_ambient_bootstrap_effects(member):
    selection = records("forgejo-restic")["selection"]
    selection[member] = True
    with pytest.raises(ContractError):
        validate_selection(selection)


@pytest.mark.parametrize(
    "value",
    ["HEAD", "main", "refs/heads/a..b", "refs/heads/a.lock/b", "refs/heads/a/.b", "refs/heads/a b"],
    ids=["symbolic", "abbreviated", "range", "lock-component", "hidden-component", "space"],
)
def test_only_literal_git_refs_are_selected(value):
    selection = records("git-bundle")["selection"]
    selection["ref"] = value
    with pytest.raises(ContractError):
        validate_selection(selection)


@pytest.mark.parametrize(
    "root",
    ["/tmp", "/recovery", "/tmp/../live", "/recovery//run", "relative"],
    ids=["shared-tmp", "shared-recovery", "traversal", "empty-component", "relative"],
)
def test_staging_root_is_not_ambiguous(root):
    selection = records("git-bundle")["selection"]
    selection["recovery_root"] = root
    with pytest.raises(ContractError):
        validate_selection(selection)


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("pin", ["trusted_catalogue_digest", "trusted_kit_digest"])
def test_independent_pins_are_not_discovered_from_supplied_metadata(provider, pin):
    value = records(provider)
    value[pin] = "sha256:" + "f" * 64
    with pytest.raises(ContractError, match="independent recovery pins mismatch"):
        prepare_request(**value)


def test_self_consistent_catalogue_replacement_does_not_reauthorize_inputs():
    value = records("git-bundle")
    trusted = value["trusted_catalogue_digest"]
    value["source"]["bundle"]["digest"] = "sha256:" + "e" * 64
    reseal(value)
    value["trusted_catalogue_digest"] = trusted
    with pytest.raises(ContractError, match="independent recovery pins mismatch"):
        prepare_request(**value)


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize(
    "member",
    ["installation_digest", "descriptor_digest", "configuration_digest", "source_schema_digest"],
)
def test_every_adapter_binding_identity_is_checked(provider, member):
    value = records(provider)
    value["selection"]["adapter"][member] = "sha256:" + "f" * 64
    value["catalogue"]["sources"][0]["adapter"] = copy.deepcopy(value["selection"]["adapter"])
    value["selection"]["catalogue_digest"] = digest(value["catalogue"])
    value["trusted_catalogue_digest"] = digest(value["catalogue"])
    with pytest.raises(ContractError):
        prepare_request(**value)


@pytest.mark.parametrize("provider", PROVIDERS)
def test_disabled_installation_is_not_selected(provider):
    value = records(provider)
    value["installation"]["enabled"] = False
    with pytest.raises(ContractError, match="bootstrap adapter binding mismatch"):
        prepare_request(**value)


@pytest.mark.parametrize("provider", PROVIDERS)
def test_source_capture_bytes_are_bound_not_just_its_schema(provider):
    value = records(provider)
    if provider == "git-bundle":
        value["source"]["bundle"]["digest"] = "sha256:" + "f" * 64
    else:
        value["source"]["snapshot_id"] = "f" * 64
    with pytest.raises(ContractError, match="bootstrap capture identity mismatch"):
        prepare_request(**value)


@pytest.mark.parametrize(
    "member,change",
    [("size_bytes", 1), ("media_type", "application/zip")],
    ids=["size", "media-type"],
)
def test_capture_size_and_type_are_verified(member, change):
    value = records("git-bundle")
    value["selection"]["capture"][member] = change
    value["catalogue"]["sources"][0]["capture"] = copy.deepcopy(value["selection"]["capture"])
    value["selection"]["catalogue_digest"] = digest(value["catalogue"])
    value["trusted_catalogue_digest"] = digest(value["catalogue"])
    with pytest.raises(ContractError, match="bootstrap capture identity mismatch"):
        prepare_request(**value)


@pytest.mark.parametrize("snapshot", ["latest", "abcd", "C" * 64])
def test_restic_requires_an_immutable_full_snapshot_identity(snapshot):
    value = records("forgejo-restic")
    value["source"]["snapshot_id"] = snapshot
    reseal(value)
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        prepare_request(**value)


@pytest.mark.parametrize(
    "path",
    [
        "/repos/*/domain.git",
        "/../domain.git",
        "/repos/../domain.git",
        "/repos//domain.git",
        "repos/domain.git",
        "/repos/domain.git\n",
    ],
    ids=["wildcard", "root-traversal", "traversal", "empty-component", "relative", "newline"],
)
def test_restic_source_owns_literal_snapshot_path_rules(path):
    value = records("forgejo-restic")
    value["source"]["bare_repository_path"] = path
    reseal(value)
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        prepare_request(**value)


def test_bundle_cannot_relax_self_contained_requirement():
    value = records("git-bundle")
    value["source"]["require_self_contained"] = False
    reseal(value)
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        prepare_request(**value)


@pytest.mark.parametrize("provider", PROVIDERS)
def test_capture_consistency_is_provider_owned(provider):
    value = records(provider)
    if provider == "forgejo-restic":
        value["source"]["capture_consistency"] = "live-unverified"
    else:
        value["source"]["capture_consistency"] = "forgejo-stopped"
    reseal(value)
    with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
        prepare_request(**value)


def test_third_party_bootstrap_schema_needs_no_core_provider_switch():
    value = records("git-bundle")
    value["descriptor"]["id"] = "independent-author.offline-source"
    empty = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    value["descriptor"]["configuration_schema"] = copy.deepcopy(empty)
    value["descriptor"]["source_schema"] = copy.deepcopy(empty)
    value["configuration"] = {}
    value["source"] = {}
    reseal(value)
    request = prepare_request(**value)
    assert request["input"]["selection"]["adapter"]["implementation"] == value["descriptor"]["id"]


def test_candidate_catalogue_is_not_publication_evidence():
    value = records("git-bundle")
    value["catalogue"]["publication_state"] = "candidate"
    reseal(value)
    validate_catalogue(value["catalogue"])
    with pytest.raises(ContractError, match="candidate"):
        prepare_request(**value)


@pytest.mark.parametrize(
    "member,replacement",
    [("ref", "refs/heads/other"), ("expected_commit", "f" * 40), ("source_id", "missing")],
    ids=["ref", "commit", "source"],
)
def test_catalogue_binds_the_exact_source_ref_and_commit(member, replacement):
    value = records("git-bundle")
    value["selection"][member] = replacement
    with pytest.raises(ContractError, match="selected source not in recovery catalogue"):
        prepare_request(**value)


def test_catalogue_rejects_duplicate_logical_source_even_across_providers():
    value = records("git-bundle")
    value["catalogue"]["sources"].append(records("forgejo-restic")["catalogue"]["sources"][0])
    with pytest.raises(ContractError, match="ambiguous recovery source"):
        validate_catalogue(value["catalogue"])


@pytest.mark.parametrize("provider", PROVIDERS)
def test_preparation_never_enrolls_or_authorizes_a_native_adapter(provider):
    value = records(provider)
    prepare_request(**value)
    registry = Registry()
    registry.install(value["installation"], value["descriptor"], owner_approved=True)
    registry.enroll(
        {
            "id": "offline-source",
            "implementation": value["descriptor"]["id"],
            "installation_digest": D,
            "role": "bootstrap-source",
            "schema_digest": digest(value["descriptor"]["configuration_schema"]),
            "configuration": value["configuration"],
            "grants": [
                {
                    "scope": value["scope"],
                    "access": ["observe", "change"],
                    "mutation": {
                        "controller": "offline-source",
                        "namespaces": [
                            {
                                "authority": value["scope"]["authority"],
                                "resource": value["scope"]["handle"],
                                "facet": "recovery-source",
                            }
                        ],
                    },
                }
            ],
            "generation": 1,
        },
        owner_approved=True,
    )
    with pytest.raises(ContractError, match="NATIVE_EXECUTOR_UNIMPLEMENTED"):
        registry.authorize(
            "offline-source", "bootstrap-source", "recover", value["scope"], owner_approved=True
        )
    assert all(
        x["repeat"] == "reconcile-before-repeat"
        for method, x in ROLES["bootstrap-source"].items()
        if method != "reconcile"
    )
    assert ROLES["bootstrap-source"]["reconcile"]["repeat"] == "read-only"


@pytest.mark.parametrize("member,replacement", [("kind", "application"), ("handle", "another")])
def test_prepare_does_not_widen_source_scope(member, replacement):
    value = records("git-bundle")
    value["scope"][member] = replacement
    with pytest.raises(ContractError):
        prepare_request(**value)


def test_receipt_is_inert_and_bound_to_the_exact_selection():
    selection = records("forgejo-restic")["selection"]
    receipt = fixture("source-receipt")
    validate_receipt(receipt, selection)
    for field in (
        "policy_activated",
        "services_restored",
        "assets_restored",
        "uncommitted_work_restored",
    ):
        bad = {**receipt, field: True}
        with pytest.raises(ContractError):
            validate_receipt(bad, selection)
    for field in ("selection_digest", "commit", "source_id", "ref"):
        bad = {**receipt, field: records("git-bundle")["selection"]["catalogue_digest"]}
        with pytest.raises(ContractError):
            validate_receipt(bad, selection)


@pytest.mark.parametrize(
    "destination",
    [
        "/home/example/live",
        "/recovery/staging/run-001",
        "/recovery/staging/run-001-other/source.git",
    ],
    ids=["live-directory", "staging-root", "prefix-collision"],
)
def test_receipt_cannot_claim_an_output_outside_dedicated_staging(destination):
    receipt = fixture("source-receipt")
    receipt["destination"] = destination
    with pytest.raises(ContractError, match="outside staging"):
        validate_receipt(receipt, records("forgejo-restic")["selection"])


@pytest.mark.parametrize("provider", PROVIDERS)
def test_adapter_source_validation_is_read_only_and_redacts_rejections(provider):
    value = records(provider)
    path = next(p for p in descriptors() if provider in p.parts)
    out = io.StringIO()
    with (
        contextlib.redirect_stdout(out),
        patch("sys.stdin", io.TextIOWrapper(io.BytesIO(canonical(value["source"])))),
    ):
        assert adapter_main(str(path.with_name("cli.py")), ["validate-source", "--json"]) == 0
    assert json.loads(out.getvalue()) == {
        "status": "valid",
        "scope": "local-source-description-only",
    }
    rejected = {**value["source"], "private": "SYNTHETIC_PRIVATE_SENTINEL"}
    err = io.StringIO()
    with (
        contextlib.redirect_stderr(err),
        patch("sys.stdin", io.TextIOWrapper(io.BytesIO(canonical(rejected)))),
    ):
        assert adapter_main(str(path.with_name("cli.py")), ["validate-source", "--json"]) == 2
    assert json.loads(err.getvalue()) == {"error": "INPUT_REJECTED"}


def test_configuration_and_capture_schemas_are_not_interchangeable():
    for provider in PROVIDERS:
        value = records(provider)
        descriptor = value["descriptor"]
        with pytest.raises(ContractError, match="CONFIGURATION_REJECTED"):
            check_configuration(
                descriptor["source_schema"],
                value["configuration"],
                digest(descriptor["source_schema"]),
            )


@pytest.mark.parametrize("method", ["recover", "verify"])
def test_bootstrap_wire_requires_repository_scope_and_an_evidenced_result(method):
    value = records("forgejo-restic")
    request = prepare_request(**value)
    request["method"] = method
    if method == "verify":
        request["input"]["output"] = {
            "digest": D,
            "media_type": "application/x-git-bundle",
            "size_bytes": 100,
        }
    check_request("bootstrap-source", request)
    invalid = copy.deepcopy(request)
    invalid["input"]["scope"]["kind"] = "application"
    with pytest.raises(ContractError):
        check_request("bootstrap-source", invalid)
    attempt = {
        "owner": OWNER,
        "operation_id": identifier(8),
        "effect_id": identifier(9),
        "attempt_id": identifier(10),
        "executor": {
            "instance": "offline-source",
            "role": "bootstrap-source",
            "installation_digest": D,
            "configuration_digest": digest(value["configuration"]),
            "instance_generation": 1,
            "instance_digest": D,
            "scope": value["scope"],
        },
        "binding_generation": 1,
        "native_incarnation": identifier(11),
        "contract": request["contract"],
        "method": method,
        "scope": value["scope"],
        "input_digest": digest(request),
        "state": "dispatched",
        "certainty": "unknown",
        "outcome": "pending",
        "native_task": None,
    }
    response = {
        "contract": request["contract"],
        "method": method,
        "request_digest": digest(request),
        "scope": value["scope"],
        "coverage": "complete",
        "continuation": None,
        "proposal": None,
        "problem": None,
        "output": {"receipt": fixture("source-receipt")},
        "effect": {
            "attempt_id": attempt["attempt_id"],
            "input_digest": digest(request),
            "acknowledgment": "accepted",
            "task_state": "terminal",
            "effect_certainty": "known",
            "postcondition": "satisfied",
            "native_task": None,
        },
    }
    invocation = {"attempt": attempt, "request": copy.deepcopy(request)}
    check_response("bootstrap-source", request, response, invocation=invocation)
    if method == "verify":
        response["output"]["receipt"]["output_digest"] = "sha256:" + "f" * 64
        with pytest.raises(ContractError, match="SUCCESS_OUTPUT_IDENTITY"):
            check_response("bootstrap-source", request, response, invocation=invocation)
        response["output"]["receipt"] = fixture("source-receipt")
    for changed_field, replacement in (("commit", "f" * 40), ("source_id", "other")):
        response["output"]["receipt"][changed_field] = replacement
        with pytest.raises(ContractError, match="SUCCESS_OUTPUT_IDENTITY"):
            check_response("bootstrap-source", request, response, invocation=invocation)
        response["output"]["receipt"] = fixture("source-receipt")
    response["output"]["receipt"] = None
    with pytest.raises(ContractError):
        check_response("bootstrap-source", request, response, invocation=invocation)
    response["output"]["receipt"] = fixture("source-receipt")
    response["effect"]["effect_certainty"] = "unknown"
    with pytest.raises(ContractError, match="UNKNOWN_EFFECT_CANNOT_SUCCEED"):
        check_response("bootstrap-source", request, response, invocation=invocation)


def test_catalogue_extent_and_source_visits():
    import fishhat_client.bootstrap as bootstrap

    for count in (1, 16, 256, 257):
        catalogue = records("git-bundle")["catalogue"]
        source = catalogue["sources"][0]
        source["file_count"] = 1_000_001
        catalogue["sources"] = [
            {**copy.deepcopy(source), "source_id": f"source-{n}"} for n in range(count)
        ]
        with patch.object(bootstrap, "_ref", wraps=bootstrap._ref) as counted:
            validate_catalogue(catalogue)
        assert counted.call_count == count
        assert len(catalogue["sources"]) == count
        catalogue["sources"][-1]["ref"] = "refs/heads/invalid..ref"
        with pytest.raises(ContractError):
            validate_catalogue(catalogue)
    catalogue = records("git-bundle")["catalogue"]
    source = catalogue["sources"][0]
    catalogue["sources"] = [
        {**copy.deepcopy(source), "source_id": f"source-{n}"} for n in range(257)
    ]
    with patch.object(bootstrap, "_ref", wraps=bootstrap._ref) as counted:
        validate_catalogue(catalogue)
    assert counted.call_count == 257
    catalogue["sources"][-1]["ref"] = "refs/heads/invalid..ref"
    with pytest.raises(ContractError):
        validate_catalogue(catalogue)


CHECK_OVERRIDES = {
    "test_catalogue_extent_and_source_visits": {
        "purpose": "implementation",
        "authority": ["packages/fishhat-client/src/fishhat_client/bootstrap.py#validate_catalogue"],
        "scope": "bounded reference catalogue validation and complete source iteration",
        "relationship": "scoped-witness",
        "reason": "Counts every source at multiple catalogue extents and rejects an invalid terminal source; not native restore complexity or performance.",
        "claims": ["engineering:bootstrap.catalogue"],
    }
}
