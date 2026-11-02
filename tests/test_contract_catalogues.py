"""Normative catalogues participate in exact schemas and signed workflow semantics."""

from __future__ import annotations

import copy
import re
from urllib.parse import urldefrag, urljoin

import pytest
from fishhat_contracts import digest, handoffs
from fishhat_contracts.discovery import owner_contract_schemas, require_owner_contracts
from fishhat_contracts.validation import CATALOGUES, SCHEMAS, ContractError, validate
from fishhat_contracts.workflow_evidence import REQUIREMENTS, procedure_commitment

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/SchemaIdentity",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Info",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json#/$defs/Header",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/client-commands.json",
    ],
    "scope": "installed normative catalogue identity, procedure commitments and declared client routing",
    "relationship": "candidate",
    "reason": "Catalogue changes alter the exact affected contract identity and require independently approved discovery policy. Ordered phases and lifecycle semantics enter the signed-header commitment. Client resume names an admitted live command and typed journal result. These checks do not authenticate an owner or qualify native execution.",
    "claims": [],
}

BASE = "https://fishhat.invalid/contracts/"
DIALECT = "https://json-schema.org/draft/2020-12/schema"
ROOT_URI = "https://synthetic.invalid/root.schema.json"
CATALOGUE_URI = "https://synthetic.invalid/rules.json"
ID = "00000000-0000-4000-8000-000000000001"


def installed_catalogue_root(monkeypatch, dependencies):
    schema = {
        "$schema": DIALECT,
        "$id": ROOT_URI,
        "x-fishhat-catalogue-dependencies": dependencies,
        "$defs": {"Result": {"type": "integer"}, "Unused": {"type": "string"}},
    }
    monkeypatch.setitem(SCHEMAS, "catalogue-root.schema.json", schema)
    monkeypatch.setitem(
        CATALOGUES,
        CATALOGUE_URI,
        {"phases": ["prepared", "active"], "$ref": "literal://not-a-schema-reference"},
    )
    return schema


def test_catalogue_identity_has_a_complete_literal_preimage(monkeypatch):
    schema = installed_catalogue_root(monkeypatch, ["rules.json"])
    uri = ROOT_URI + "#/$defs/Result"
    expected = {
        "profile": "fishhat.schema-closure/v1",
        "root": uri,
        "documents": {
            ROOT_URI: {
                "$schema": DIALECT,
                "$id": ROOT_URI,
                "x-fishhat-catalogue-dependencies": ["rules.json"],
            }
        },
        "nodes": {ROOT_URI: {"/$defs/Result": {"type": "integer"}}},
        "catalogues": {CATALOGUE_URI: CATALOGUES[CATALOGUE_URI]},
    }
    original = handoffs.schema_identity(uri)
    document_digest = handoffs.schema_document_digest(ROOT_URI)
    assert original == {"uri": uri, "digest": digest(expected)}
    monkeypatch.setitem(CATALOGUES, "https://synthetic.invalid/unrelated.json", {"rule": "new"})
    assert handoffs.schema_identity(uri) == original
    schema["$defs"]["Unused"]["description"] = "Unreached schema definition."
    assert handoffs.schema_identity(uri) == original
    assert handoffs.schema_document_digest(ROOT_URI) != document_digest
    document_digest = handoffs.schema_document_digest(ROOT_URI)
    CATALOGUES[CATALOGUE_URI]["phases"].reverse()
    assert handoffs.schema_identity(uri) != original
    assert handoffs.schema_document_digest(ROOT_URI) != document_digest


@pytest.mark.parametrize(
    ("dependencies", "error"),
    [
        ("rules.json", "invalid catalogue dependencies"),
        ([1], "invalid catalogue dependencies"),
        (["rules.json", "rules.json"], "invalid catalogue dependencies"),
        (["rules.json", CATALOGUE_URI], "duplicate catalogue dependency target"),
        (["rules.json#"], "complete document"),
        (["rules.json#/phases"], "complete document"),
        (["https://uninstalled.invalid/rules.json"], "not installed"),
        ([ROOT_URI], "not installed"),
    ],
)
def test_catalogue_dependencies_reject_unapproved_or_ambiguous_targets(
    monkeypatch, dependencies, error
):
    installed_catalogue_root(monkeypatch, dependencies)
    with pytest.raises(ContractError, match=error):
        handoffs.schema_identity(ROOT_URI)


def test_catalogue_dependencies_require_a_core_document_root(monkeypatch):
    schema = installed_catalogue_root(monkeypatch, [])
    schema["$defs"]["Result"]["x-fishhat-catalogue-dependencies"] = ["rules.json"]
    with pytest.raises(ContractError, match="document root"):
        handoffs.schema_identity(ROOT_URI)
    extension = copy.deepcopy(schema)
    extension["$id"] = "https://synthetic.invalid/extension.schema.json"
    extension.pop("$defs")
    extension["x-fishhat-catalogue-dependencies"] = [CATALOGUE_URI]
    with pytest.raises(ContractError):
        handoffs.schema_identity(extension["$id"], {extension["$id"]: extension})


@pytest.mark.parametrize(
    ("root", "catalogue", "path", "replacement"),
    [
        (
            "records.schema.json#/$defs/Workflow",
            "states.json",
            ("workflow_lifecycle", "paused"),
            ["cancelled"],
        ),
        (
            "workflow-evidence.schema.json",
            "states.json",
            ("workflow_phases", "host-drain"),
            ["prepared", "completed"],
        ),
        (
            "actions.schema.json#/$defs/app.deploy",
            "actions.json",
            ("actions", 0, "minimum_role"),
            "administrator",
        ),
        (
            "adapter.schema.json#/$defs/EffectKnowledge",
            "adapter-roles.json",
            ("runtime", "activate", "effect"),
            False,
        ),
        ("ssh-request.schema.json", "ssh-methods.json", ("max_frame_bytes",), 524288),
        ("ssh-response.schema.json", "ssh-methods.json", ("max_content_chunk_bytes",), 98304),
        (
            "cli-output.schema.json",
            "owner-cli.json",
            ("forms", 1, "description"),
            "Approved owner discovery.",
        ),
        (
            "cli-output.schema.json",
            "client-commands.json",
            ("commands", 0, "description"),
            "Describe approved client capabilities.",
        ),
        ("directory-result.schema.json", "directory-mcp.json", ("no_network_effects",), False),
        (
            "tracking-records.schema.json",
            "receipts-api.openapi.json",
            ("info", "description"),
            "Independent metadata-only index.",
        ),
    ],
)
def test_normative_catalogue_changes_reidentify_their_installed_boundaries(
    monkeypatch, root, catalogue, path, replacement
):
    original = handoffs.schema_identity(BASE + root)
    changed = copy.deepcopy(CATALOGUES[BASE + catalogue])
    node = changed
    for key in path[:-1]:
        node = node[key]
    assert node[path[-1]] != replacement
    node[path[-1]] = replacement
    monkeypatch.setitem(CATALOGUES, BASE + catalogue, changed)
    assert handoffs.schema_identity(BASE + root) != original


def test_procedure_commitment_pins_order_lifecycle_and_obligations(monkeypatch):
    procedure = "host-drain"
    states = CATALOGUES[BASE + "states.json"]
    expected = {
        "profile": "fishhat.workflow-procedure/v1",
        "procedure": procedure,
        "phases": states["workflow_phases"][procedure],
        "lifecycle": states["workflow_lifecycle"],
        "lifecycle_meanings": states["workflow_meanings"],
        "rules": states["rules"],
        "requirements": REQUIREMENTS[procedure],
    }
    original = digest(expected)
    assert digest(procedure_commitment(procedure)) == original
    for key in ("workflow_phases", "workflow_lifecycle", "workflow_meanings", "rules"):
        changed = copy.deepcopy(states)
        if key == "workflow_phases":
            changed[key][procedure][1:3] = reversed(changed[key][procedure][1:3])
        elif key == "workflow_lifecycle":
            changed[key]["paused"].remove("prepared")
        elif key == "workflow_meanings":
            changed[key]["paused"] += " Independent reconciliation is required."
        else:
            changed[key].append("Independent reconciliation is required.")
        with monkeypatch.context() as installed:
            installed.setitem(CATALOGUES, BASE + "states.json", changed)
            assert digest(procedure_commitment(procedure)) != original, key
    changed_requirements = copy.deepcopy(REQUIREMENTS[procedure])
    changed_requirements["child_completion"]["draining"] = "host-effect"
    monkeypatch.setitem(REQUIREMENTS, procedure, changed_requirements)
    assert digest(procedure_commitment(procedure)) != original


def test_changed_whole_boundary_requires_independent_revision_approval(monkeypatch):
    owner = {"tool": "host-ops", "id": ID, "epoch": ID}
    approved = owner_contract_schemas()
    changed = copy.deepcopy(CATALOGUES[BASE + "actions.json"])
    changed["actions"][0]["minimum_role"] = "administrator"
    monkeypatch.setitem(CATALOGUES, BASE + "actions.json", changed)
    current = owner_contract_schemas()
    advertised = {
        "owner": owner,
        "wire": "deployment-ops/owner/v1",
        "contract_schemas": current,
        "source_formats": ["deployment-ops/source/v2"],
        "actions": [],
        "adapters": [],
    }
    validate("records.schema.json", advertised, "Info")
    with pytest.raises(ContractError, match="contract identity"):
        require_owner_contracts(
            advertised, expected_owner=owner, expected_contracts={"request": approved["request"]}
        )
    # This separately supplied policy represents the coordinated approval step;
    # reading an advertisement does not install it as the expected revision.
    require_owner_contracts(
        advertised, expected_owner=owner, expected_contracts={"request": current["request"]}
    )
    assert approved["request"] != current["request"]


def test_client_resume_maps_to_the_installed_journal_protocol():
    commands = CATALOGUES[BASE + "client-commands.json"]["commands"]
    resume = next(command for command in commands if command["name"] == "workflow resume")
    methods = {method["name"] for method in CATALOGUES[BASE + "ssh-methods.json"]["methods"]}
    forms = CATALOGUES[BASE + "owner-cli.json"]["forms"]
    assert resume["use_case"] in methods
    assert any(form["use_case"] == resume["use_case"] for form in forms)
    mentioned = set(
        re.findall(r"\b(?:workflow|record)\.[a-z][a-z.]*[a-z]\b", resume["description"])
    )
    assert mentioned <= methods
    for filename, field, reference in (
        ("ssh-request.schema.json", "params", "InputReference"),
        ("ssh-response.schema.json", "result", "RecordReference"),
    ):
        branch = next(
            branch
            for branch in SCHEMAS[filename]["oneOf"]
            if branch.get("properties", {}).get("method", {}).get("const") == resume["use_case"]
        )
        assert branch["properties"][field]["$ref"] == (
            "workflow-journal.schema.json#/$defs/" + reference
        )
    command_uri, command_pointer = urldefrag(urljoin(BASE, resume["command_schema"]))
    record_uri, record_pointer = urldefrag(urljoin(BASE, resume["record_schema"]))
    assert command_uri == record_uri == SCHEMAS["workflow-journal.schema.json"]["$id"]
    command_definition = command_pointer.removeprefix("/$defs/")
    record_definition = record_pointer.removeprefix("/$defs/")
    command = {
        "id": ID,
        "workflow_id": ID,
        "action": "resume",
        "payload": {"expected_generation": 0, "driver_term": 1},
    }
    validate("workflow-journal.schema.json", command, command_definition)
    validate("workflow-journal.schema.json", command, "Command")
    record = SCHEMAS["workflow-journal.schema.json"]["$defs"][record_definition]
    assert record["properties"]["kind"]["const"] == "WorkflowJournalRecord"
    assert record["properties"]["body"]["$ref"].endswith("#/$defs/LifecycleBody")
