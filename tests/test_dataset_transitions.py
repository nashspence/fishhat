"""Dataset obligations survive source edits until explicit verified owner transitions."""

from copy import deepcopy

import pytest
from fishhat_contracts import datasets
from fishhat_contracts.backup_results import validate_backup_selection
from fishhat_contracts.datasets import (
    dataset_transition_material,
    require_dataset_source,
    require_dataset_transition,
    validate_dataset_inventory,
)
from fishhat_contracts.relocation import validate_relocation
from fishhat_contracts.validation import (
    ContractError,
    digest,
    strict_yaml,
    validate_app,
    validate_plan,
)

from tests.dataset_support import dataset_inventory, obligation, selected_bindings
from tests.linear_support import assert_linear, measure
from tests.support import FIXTURES
from tests.test_contracts import OWNER, plan, uid
from tests.test_dataset_contracts import application
from tests.test_plan_review import reseal

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/dataset-obligations.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Plan",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/backup-result.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/app.relocate",
    ],
    "scope": "complete original dataset obligations through reviewed release, backup and relocation joins",
    "relationship": "candidate",
    "reason": "Independent predecessor/admission contexts and refusal callbacks challenge omission, rename, custody changes and stale/replayed selections. Synthetic records do not establish native authorization, storage or recovery custody.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_dataset_transition_linear_work": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/datasets.py#validate_dataset_inventory",
            "packages/fishhat-contracts/src/fishhat_contracts/datasets.py#require_dataset_transition",
            "release.toml#/engineering",
        ],
        "scope": "complete active/discharged inventory, source and transition validation over sixteenfold dataset extent",
        "relationship": "scoped-witness",
        "reason": "Measured work includes indexed complete joins and immutable copies; the batch verifier is invoked once and supplies no native proof or timing guarantee.",
        "claims": ["engineering:datasets.inventory", "engineering:datasets.transition"],
    }
}

OLD = digest("synthetic accepted release")
NEW = digest("synthetic proposed release")
EVIDENCE = digest("synthetic independently retained retirement evidence")


def source_check(app):
    validate_app(app, strict_yaml((FIXTURES / "demo-app/secrets.yaml").read_text()))


def prepared(count=1):
    app = application()
    original = deepcopy(app["datasets"]["state"])
    app["datasets"] = {
        ("state" if count == 1 else f"dataset-{i:06d}"): deepcopy(original) for i in range(count)
    }
    for hook in app["hooks"].values():
        if hook["datasets"]:
            hook["datasets"] = list(app["datasets"])
    inventory = dataset_inventory(app, OWNER, OLD)
    value = {
        "format": "deployment-ops/dataset-obligations/v1",
        "kind": "DatasetTransition",
        "owner": deepcopy(OWNER),
        "resource": deepcopy(inventory["resource"]),
        "app_instance": inventory["app_instance"],
        "expected_generation": inventory["generation"],
        "before_inventory_digest": digest(inventory),
        "previous_release_digest": OLD,
        "release_digest": NEW,
        "bindings": [
            {"dataset": entry["dataset"], "obligation_id": entry["obligation"]["id"]}
            for entry in inventory["entries"]
        ],
        "admissions": [],
        "discharges": [],
    }
    context = {
        "current_inventory": deepcopy(inventory),
        "proposed_app": deepcopy(app),
        "proposed_release_digest": NEW,
        "approved_admissions": {},
        "approved_bindings": selected_bindings(inventory),
        "authorize_transition": lambda *_: None,
        "verify_discharges": lambda *_: None,
    }
    return value, context


def remove_source_datasets(app):
    app["datasets"] = {}
    app["hooks"] = {"health": app["hooks"]["health"]}
    app["maintenance"] = {}
    app["lifecycle"]["checkpoint_policy"] = "stateless"


def discharge(value, context):
    value["bindings"] = []
    value["discharges"] = [
        {
            "obligation_id": entry["obligation"]["id"],
            "obligation_digest": digest(entry["obligation"]),
            "evidence_digest": EVIDENCE,
        }
        for entry in context["current_inventory"]["entries"]
        if entry["discharge"] is None
    ]
    remove_source_datasets(context["proposed_app"])
    context["approved_bindings"] = {}


def test_source_omission_cannot_become_an_accepted_data_free_release():
    value, context = prepared()
    source_check(context["proposed_app"])
    remove_source_datasets(context["proposed_app"])
    source_check(context["proposed_app"])
    value["bindings"] = []
    context["approved_bindings"] = {}
    original = deepcopy(context["current_inventory"])
    with pytest.raises(ContractError, match="omits or resurrects"):
        require_dataset_transition(value, **context)
    assert context["current_inventory"] == original


def test_explicit_rename_preserves_original_native_obligation_and_recovery_closure():
    value, context = prepared()
    app = context["proposed_app"]
    app["datasets"]["renamed"] = app["datasets"].pop("state")
    for hook in app["hooks"].values():
        if hook["datasets"]:
            hook["datasets"] = ["renamed"]
    value["bindings"][0]["dataset"] = "renamed"
    context["approved_bindings"]["renamed"] = context["approved_bindings"].pop("state")
    source_check(app)
    after = require_dataset_transition(value, **context)
    assert after["entries"][0]["dataset"] == "renamed"
    assert (
        after["entries"][0]["obligation"]
        == context["current_inventory"]["entries"][0]["obligation"]
    )
    assert after["accepted_release_digest"] == NEW
    assert after["generation"] == context["current_inventory"]["generation"] + 1
    require_dataset_source(after, accepted_app=app, accepted_release_digest=NEW)


@pytest.mark.parametrize("kind", ["rebuild", "external"])
def test_policy_or_custody_reclassification_cannot_continue_old_obligation(kind):
    value, context = prepared()
    context["proposed_app"] = application(kind)
    source_check(context["proposed_app"])
    with pytest.raises(ContractError, match="changes custody or recovery"):
        require_dataset_transition(value, **context)


@pytest.mark.parametrize("field", ["grant", "native_format"])
def test_changed_native_mapping_is_not_an_ordinary_source_continuation(field):
    value, context = prepared()
    context["proposed_app"]["datasets"]["state"][field] = "replacement"
    with pytest.raises(ContractError, match="changes custody or recovery"):
        require_dataset_transition(value, **context)


def test_unreviewed_native_rebinding_is_rejected_even_with_same_source():
    value, context = prepared()
    context["approved_bindings"]["state"]["incarnation"] = digest("replacement native object")
    with pytest.raises(ContractError, match="approved native incarnation"):
        require_dataset_transition(value, **context)


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("before_inventory_digest", EVIDENCE),
        ("previous_release_digest", EVIDENCE),
        ("release_digest", EVIDENCE),
        ("expected_generation", 2),
        ("app_instance", "prod:" + "b" * 64),
        ("resource", {"kind": "app", "id": "other-app"}),
        ("owner", {**OWNER, "epoch": uid("other-epoch")}),
    ],
    ids=["inventory", "previous-release", "release", "generation", "instance", "resource", "epoch"],
)
def test_transition_rejects_stale_or_substituted_accepted_context(field, replacement):
    value, context = prepared()
    value[field] = replacement
    with pytest.raises(ContractError, match="predecessor or application"):
        require_dataset_transition(value, **context)


def test_verified_retirement_retains_original_obligation_and_complete_evidence():
    value, context = prepared()
    discharge(value, context)
    calls = []

    def verify(inventory, selected):
        assert digest(inventory) == value["before_inventory_digest"]
        assert set(selected) == {entry["obligation"]["id"] for entry in inventory["entries"]}
        assert all(item["evidence_digest"] == EVIDENCE for item in selected.values())
        calls.append("verified")

    context["authorize_transition"] = lambda selected, role: calls.append((selected["kind"], role))
    context["verify_discharges"] = verify
    original = deepcopy(context["current_inventory"])
    after = require_dataset_transition(value, **context)
    assert calls == [("DatasetTransition", "administrator"), "verified"]
    assert after["entries"][0]["obligation"] == original["entries"][0]["obligation"]
    assert after["entries"][0]["dataset"] is None
    assert after["entries"][0]["discharge"] == value["discharges"][0]
    assert context["current_inventory"] == original


@pytest.mark.parametrize("boundary", ["authorize_transition", "verify_discharges"])
def test_request_fields_cannot_override_independent_refusal(boundary):
    value, context = prepared()
    discharge(value, context)

    def refuse(*_):
        raise ContractError("independent refusal")

    context[boundary] = refuse
    with pytest.raises(ContractError, match="independent refusal"):
        require_dataset_transition(value, **context)


@pytest.mark.parametrize(
    "change", ["missing", "wrong-original", "also-continued", "verified-boolean"]
)
def test_discharge_requires_exact_explicit_selection(change):
    value, context = prepared()
    original = deepcopy(value["bindings"])
    discharge(value, context)
    if change == "missing":
        value["discharges"] = []
    elif change == "wrong-original":
        value["discharges"][0]["obligation_digest"] = digest("different obligation")
    elif change == "also-continued":
        value["bindings"] = original
    else:
        value["discharges"][0]["verified"] = True
    with pytest.raises(ContractError):
        require_dataset_transition(value, **context)


def test_new_dataset_requires_complete_independent_native_admission():
    value, context = prepared()
    app = context["proposed_app"]
    app["datasets"]["new-data"] = deepcopy(app["datasets"]["state"])
    for hook in app["hooks"].values():
        if hook["datasets"]:
            hook["datasets"].append("new-data")
    source_check(app)
    admitted = obligation("new-data", app["datasets"]["new-data"], NEW, OWNER)
    value["bindings"].append({"dataset": "new-data", "obligation_id": admitted["id"]})
    value["admissions"].append(admitted)
    context["approved_bindings"]["new-data"] = deepcopy(admitted["native_identity"])
    with pytest.raises(ContractError, match="independent approval"):
        require_dataset_transition(value, **context)
    context["approved_admissions"][admitted["id"]] = deepcopy(admitted)
    after = require_dataset_transition(value, **context)
    assert len(after["entries"]) == 2
    assert after["entries"][1]["obligation"] == admitted


@pytest.mark.parametrize("recovery", ["rebuild", "external"])
def test_explicit_reclassification_admits_a_verified_successor_and_retains_original(recovery):
    value, context = prepared()
    original = deepcopy(context["current_inventory"]["entries"][0]["obligation"])
    discharge(value, context)
    app = application(recovery)
    source_check(app)
    context["proposed_app"] = app
    successor = obligation("state", app["datasets"]["state"], NEW, OWNER)
    successor["id"] = uid("explicit successor obligation")
    successor["native_identity"]["incarnation"] = digest("verified successor native incarnation")
    value["bindings"] = [{"dataset": "state", "obligation_id": successor["id"]}]
    value["admissions"] = [successor]
    context["approved_admissions"] = {successor["id"]: deepcopy(successor)}
    context["approved_bindings"] = {"state": deepcopy(successor["native_identity"])}
    checked = []

    def authorize(selected, role):
        assert role == "administrator" and selected == value
        checked.append("authorized")

    def verify(inventory, selected):
        assert inventory["entries"][0]["obligation"] == original
        assert selected[original["id"]]["obligation_digest"] == digest(original)
        checked.append("verified custody")

    context.update(authorize_transition=authorize, verify_discharges=verify)
    after = require_dataset_transition(value, **context)
    assert checked == ["authorized", "verified custody"]
    assert after["entries"][0] == {
        "obligation": original,
        "dataset": None,
        "discharge": value["discharges"][0],
    }
    assert after["entries"][1] == {
        "obligation": successor,
        "dataset": "state",
        "discharge": None,
    }


def test_source_identity_cannot_borrow_another_applications_inventory():
    value, context = prepared()
    context["proposed_app"]["id"] = "another-app"
    with pytest.raises(ContractError, match="application identity"):
        require_dataset_transition(value, **context)
    with pytest.raises(ContractError, match="source application identity"):
        require_dataset_source(
            context["current_inventory"],
            accepted_app=context["proposed_app"],
            accepted_release_digest=OLD,
        )


def test_discharge_cannot_relabel_same_native_incarnation_as_fresh_data():
    value, context = prepared()
    original = deepcopy(context["current_inventory"]["entries"][0]["obligation"])
    discharge(value, context)
    declaration = original["declaration"]
    context["proposed_app"]["datasets"]["renamed"] = deepcopy(declaration)
    admitted = obligation("renamed", declaration, NEW, OWNER)
    admitted["native_identity"] = deepcopy(original["native_identity"])
    value["bindings"] = [{"dataset": "renamed", "obligation_id": admitted["id"]}]
    value["admissions"] = [admitted]
    context["approved_admissions"] = {admitted["id"]: deepcopy(admitted)}
    context["approved_bindings"] = {"renamed": deepcopy(admitted["native_identity"])}
    with pytest.raises(ContractError, match="native incarnation reused"):
        require_dataset_transition(value, **context)


def test_stale_transition_does_not_reapply_or_rewrite_accepted_inventory():
    value, context = prepared()
    after = require_dataset_transition(value, **context)
    context["current_inventory"] = deepcopy(after)
    with pytest.raises(ContractError, match="predecessor or application"):
        require_dataset_transition(value, **context)
    assert context["current_inventory"] == after


def test_old_obligations_block_source_only_backup_and_release_relocation():
    _, context = prepared()
    app = context["proposed_app"]
    remove_source_datasets(app)
    source_check(app)
    inventory = context["current_inventory"]
    args = {
        "destination_host": "node-b",
        "placement_generation": 2,
        "dataset_inventory_digest": digest(inventory),
        "recovery_basis": {"kind": "release", "release_digest": OLD},
    }
    with pytest.raises(ContractError, match="omits dataset obligations"):
        validate_relocation(
            args,
            accepted_app=app,
            accepted_release_digest=OLD,
            accepted_inventory=inventory,
            expected_owner=OWNER,
            expected_resource=inventory["resource"],
            expected_app_instance=inventory["app_instance"],
        )
    selection = {
        "app_instance": inventory["app_instance"],
        "release_digest": OLD,
        "preserved_datasets": ["another-dataset"],
        "secret_generations": [],
        "dataset_inventory_digest": digest(inventory),
    }
    with pytest.raises(ContractError, match="omits retained preserved"):
        validate_backup_selection(
            selection,
            resource=inventory["resource"],
            expected_resource=inventory["resource"],
            expected_selection=deepcopy(selection),
            expected_owner=OWNER,
            expected_inventory=inventory,
        )


@pytest.mark.parametrize("action", ["app.deploy", "app.upgrade"])
def test_release_plan_commits_complete_dataset_transition(action):
    transition, _ = prepared()
    proposal = plan()
    proposal["subject"] = {
        "action": action,
        "resource": deepcopy(transition["resource"]),
        "arguments": {"release_digest": NEW},
    }
    proposal["dataset_transition"] = transition
    proposal["effects"][0]["input_digest"] = digest(transition)
    proposal["input_digests"] = sorted(dataset_transition_material(transition))
    reseal(proposal)
    validate_plan(proposal)
    del proposal["dataset_transition"]
    reseal(proposal)
    with pytest.raises(ContractError):
        validate_plan(proposal)


@pytest.mark.parametrize("scale", [1, 4, 16])
def test_inventory_checks_every_obligation_without_a_count_cap(scale):
    _, context = prepared(scale * 20)
    inventory = context["current_inventory"]
    validate_dataset_inventory(inventory)
    inventory["entries"][-1]["obligation"]["native_identity"] = deepcopy(
        inventory["entries"][0]["obligation"]["native_identity"]
    )
    with pytest.raises(ContractError, match="native incarnation reused"):
        validate_dataset_inventory(inventory)


@pytest.mark.parametrize("kind", ["continue", "admit", "discharge"])
def test_dataset_transition_linear_work(kind):
    samples = []
    for count in (8, 32, 128):
        transition, context = prepared(count)
        if kind == "discharge":
            discharge(transition, context)
        elif kind == "admit":
            inventory = context["current_inventory"]
            admissions = [deepcopy(entry["obligation"]) for entry in inventory["entries"]]
            for admission in admissions:
                admission["origin_release_digest"] = NEW
                admission["recovery_closure"] = [NEW]
            inventory.update(entries=[], generation=0, accepted_release_digest=None)
            transition.update(
                before_inventory_digest=digest(inventory),
                expected_generation=0,
                previous_release_digest=None,
                admissions=admissions,
            )
            context["approved_admissions"] = {item["id"]: deepcopy(item) for item in admissions}
        calls = []
        context["verify_discharges"] = lambda inventory, selected, calls=calls: calls.append(
            len(selected)
        )

        def exercise(context=context, transition=transition, count=count):
            validate_dataset_inventory(context["current_inventory"])
            result = require_dataset_transition(transition, **context)
            assert len(result["entries"]) == count
            assert all(
                (entry["dataset"] is None) == (kind == "discharge") for entry in result["entries"]
            )

        _, work = measure(exercise, modules=(datasets,))
        assert calls == ([count] if kind == "discharge" else [])
        samples.append((count, work))
    assert_linear(samples)
