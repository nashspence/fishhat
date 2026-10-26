"""Required linear work witnesses over real local implementations, not wall time."""

from __future__ import annotations

import copy
import io
import json
from contextlib import redirect_stdout

import pytest
from fishhat_adapters import check_configuration
from fishhat_client.bootstrap import validate_catalogue
from fishhat_client.wire import frame, read_frame
from fishhat_contracts import json_work
from fishhat_contracts.record_delivery import RecordSnapshot
from fishhat_contracts.validation import ContractError, canonical, digest
from fishhat_contracts.workflow_evidence import validate_phase_evidence
from fishhat_directory.projection import load_directory
from fishhat_owner.journal import Journal
from fishhat_reporting.store import EventStore
from jsonschema import Draft202012Validator, validators

from scripts.engineering import declarations
from scripts.project_policy import ROOT, read_toml
from tests.linear_support import assert_linear, measure
from tests.test_bootstrap import records
from tests.test_contracts import uid
from tests.test_engineering import AUTH, EPOCH, OWNER, SERVICE, event, seed, subject
from tests.test_operation_coverage import TOOLS, invoke
from tests.test_owner_handoffs import workflow
from tests.workflow_evidence_support import advance_request, seal_phase_participant

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": ["release.toml#/engineering"],
    "scope": "real reference operations; deterministic Python, JSON byte and SQLite VM work counts",
    "relationship": "candidate",
    "reason": "Increasing complete inputs challenge work growth independently of elapsed time; evidence supplies no native execution qualification.",
    "claims": [],
}

SCALES = (16, 64, 256)


def test_frame_linear_work():
    samples = []
    for count in (256, 1024, 4096):
        encoded = frame({"payload": "x" * count})
        value, work = measure(lambda encoded=encoded: read_frame(io.BytesIO(encoded)))
        assert value == {"payload": "x" * count}
        samples.append((count, work))
    assert_linear(samples)


def test_directory_linear_work():
    text = (ROOT / "tests/fixtures/directory/directory.yaml").read_text()
    samples = []
    for count in (256, 1024, 4096):
        data = text + "\n# " + "x" * count + "\n"
        value, work = measure(lambda data=data: load_directory(data))
        assert value["domain_name"] == "example.invalid"
        samples.append((len(data.encode()), work))
    # The fixed document is work too; the variable comment spans sixteenfold.
    assert_linear(
        [(count, work) for count, (_, work) in zip((256, 1024, 4096), samples, strict=True)]
    )


def test_catalogue_linear_work():
    samples = []
    for count in SCALES:
        value = records("git-bundle")["catalogue"]
        template = value["sources"][0]
        value["sources"] = [
            {**copy.deepcopy(template), "source_id": f"source-{index:04d}"}
            for index in range(count)
        ]
        result, work = measure(lambda value=value: validate_catalogue(value))
        assert len(result["sources"]) == count
        samples.append((count, work))
    assert_linear(samples)


def test_record_chunk_linear_work():
    value = workflow()
    snapshot = RecordSnapshot(value, uid("growth-snapshot"))
    reference = snapshot.reference
    samples = []
    for count in (64, 256, 1024):
        result, work = measure(
            lambda count=count: snapshot.chunk(reference, offset=0, length=count)
        )
        assert result["offset"] == 0
        samples.append((count, work))
    assert_linear(samples)


def test_journal_linear_work(tmp_path):
    samples = []
    for count in SCALES:
        journal = Journal(tmp_path / f"journal-{count}.sqlite", OWNER, EPOCH, initialize=True)
        try:
            with journal.db:
                journal.db.executemany(
                    "INSERT INTO requests VALUES(?,?,?,?,?)",
                    [
                        (uid(f"retained-{index}"), "digest", "reader", "succeeded", "known")
                        for index in range(count)
                    ],
                )
            result, work = measure(
                lambda journal=journal: journal.submit(
                    uid("new-request"),
                    subject(),
                    principal="reader",
                    authorized=True,
                    expected_epoch=EPOCH,
                    expected_generation=0,
                    expires=200,
                    now=100,
                ),
                database=journal.db,
            )
            assert result["state"] == "accepted"
            samples.append((count, work))
        finally:
            journal.close()
    assert_linear(samples)


def test_event_put_linear_work(tmp_path):
    samples = []
    for count in SCALES:
        original = event()
        store = EventStore(
            tmp_path / f"put-{count}.sqlite", original["domain_id"], SERVICE, initialize=True
        )
        try:
            seed(store, count)
            previous = None
            rows = store.db.execute(
                "SELECT sequence,event_id,canonical_event FROM events ORDER BY sequence"
            ).fetchall()
            with store.db:
                for sequence, identity, encoded in rows:
                    retained = json.loads(encoded)
                    if previous is not None:
                        retained.update(kind="correction", supersedes=previous)
                        store.db.execute(
                            "UPDATE events SET canonical_event=? WHERE sequence=?",
                            (canonical(retained), sequence),
                        )
                    previous = identity
            original.update(kind="correction", supersedes=previous)
            result, work = measure(
                lambda store=store, original=original: store.put(
                    original, principal="reader", scopes={"append"}
                ),
                database=store.db,
            )
            assert result[0] == 201
            samples.append((count, work))
        finally:
            store.close()
    assert_linear(samples)


def test_event_page_linear_work(tmp_path):
    samples = []
    for count in (4, 16, 64):
        original = event()
        store = EventStore(
            tmp_path / f"page-{count}.sqlite", original["domain_id"], SERVICE, initialize=True
        )
        try:
            seed(store, count)
            result, work = measure(
                lambda store=store, original=original, count=count: store.events(
                    original["workflow_id"], limit=count, **AUTH
                ),
                database=store.db,
            )
            assert len(result["items"]) == count and result["next_after"] is None
            samples.append((count, work))
        finally:
            store.close()
    assert_linear(samples)


def test_workflow_pages_linear_work(tmp_path):
    samples = []
    for count in SCALES:
        original = event()
        store = EventStore(
            tmp_path / f"workflows-{count}.sqlite", original["domain_id"], SERVICE, initialize=True
        )
        try:
            seed(store, count, workflows=True)

            def complete(store=store):
                results, after = [], 0
                while True:
                    page = store.workflows(
                        after=after, limit=4, expected_store_epoch=store.epoch, **AUTH
                    )
                    results.extend(page["items"])
                    if page["next_after"] is None:
                        return results
                    assert page["next_after"] > after
                    after = page["next_after"]

            result, work = measure(complete, database=store.db)
            assert len(result) == count
            samples.append((count, work))
        finally:
            store.close()
    assert_linear(samples)


def test_phase_evidence_linear_work():
    samples = []
    for count in SCALES:
        value = workflow()
        query = advance_request(value, "draining")
        proof = query["phase_evidence"]["participants"][0]
        template = proof["native_evidence"][0]
        proof["native_evidence"] = [
            {**copy.deepcopy(template), "id": uid(f"evidence-{index}")} for index in range(count)
        ]
        seal_phase_participant(query["phase_evidence"], proof)
        _, work = measure(lambda query=query, value=value: validate_phase_evidence(query, value))
        samples.append((count, work))
    assert_linear(samples)


def test_cli_linear_work(tmp_path):
    for tool, main in TOOLS.items():
        samples = []
        for count in (16, 64, 256):
            path = tmp_path / "input.json"
            value = records("git-bundle")["catalogue"]
            source = value["sources"][0]
            value["sources"] = [
                {**copy.deepcopy(source), "source_id": f"source-{index:04d}"}
                for index in range(count)
            ]
            path.write_bytes(canonical(value))
            output = io.StringIO()
            with redirect_stdout(output):
                result, work = measure(
                    lambda main=main, path=path: invoke(
                        main,
                        [
                            "validate",
                            str(path),
                            "--schema",
                            "bootstrap-catalogue.schema.json",
                            "--json",
                        ],
                    )
                )
            assert result == 0 and json.loads(output.getvalue())["tool"] == tool
            samples.append((count, work))
        assert_linear(samples)
        samples = []
        for count in SCALES:

            def repeat_info(count=count, main=main):
                for _ in range(count):
                    assert invoke(main, ["info", "--json"]) == 0

            with redirect_stdout(io.StringIO()):
                _, work = measure(repeat_info)
            samples.append((count, work))
        assert_linear(samples)


def test_structural_uniqueness_preserves_json_semantics():
    validator = validators.extend(Draft202012Validator, {"uniqueItems": json_work.unique_items})
    for values, valid in [
        ([True, 1, False, 0, None], True),
        ([{"a": 1, "b": [False]}, {"b": [False], "a": 1}], False),
        ([[1, 2], [2, 1]], True),
        ([{"a": True}, {"a": 1}], True),
        ([{"nested": [{"x": 1}]}, {"nested": [{"x": 1}]}], False),
    ]:
        assert validator({"uniqueItems": True}).is_valid(values) is valid
        assert Draft202012Validator({"uniqueItems": True}).is_valid(values) is valid


def test_provider_uniqueness_linear_work():
    schema = {
        "type": "array",
        "uniqueItems": True,
        "items": {
            "type": "object",
            "properties": {"id": {"type": "integer"}},
            "required": ["id"],
            "additionalProperties": False,
        },
    }
    samples = []
    for count in SCALES:
        value = [{"id": index} for index in range(count)]
        _, work = measure(lambda value=value: check_configuration(schema, value, digest(schema)))
        samples.append((count, work))
        value[-1] = value[0]
        with pytest.raises(ContractError):
            check_configuration(schema, value, digest(schema))
    assert_linear(samples)


def test_linear_oracle_rejects_quadratic_work_and_repeated_prefix_serialization():
    for operation in (
        lambda n: sum(sum(1 for _ in range(n)) for _ in range(n)),
        lambda n: [canonical(list(range(index))) for index in range(n)],
    ):
        samples = [
            (count, measure(lambda count=count, operation=operation: operation(count))[1])
            for count in SCALES
        ]
        with pytest.raises(AssertionError):
            assert_linear(samples)


def test_every_declared_implementation_requires_linear_proofs():
    assert read_toml(ROOT / "release.toml")["engineering"] == {
        "growth": "linear",
        "implementations": "all",
    }
    assert all(
        value["growth"] == "linear" and value["linear_proofs"] for value in declarations().values()
    )


_OWNERS = {
    "frame": "packages/fishhat-client/src/fishhat_client/wire.py#read_frame",
    "directory": "some-implementations/fishhat/applications/directory/src/fishhat_directory/projection.py#load_directory",
    "catalogue": "packages/fishhat-client/src/fishhat_client/bootstrap.py#validate_catalogue",
    "record_chunk": "packages/fishhat-contracts/src/fishhat_contracts/record_delivery.py#RecordSnapshot.chunk",
    "journal": "fishhat/owner-support/src/fishhat_owner/journal.py#Journal.submit",
    "event_put": "some-implementations/fishhat/applications/receipts/src/fishhat_reporting/store.py#EventStore.put",
    "event_page": "some-implementations/fishhat/applications/receipts/src/fishhat_reporting/store.py#EventStore.events",
    "workflow_pages": "some-implementations/fishhat/applications/receipts/src/fishhat_reporting/store.py#EventStore.workflows",
    "phase_evidence": "packages/fishhat-contracts/src/fishhat_contracts/workflow_evidence.py#validate_phase_evidence",
}
_IDS = dict(
    zip(
        _OWNERS,
        (
            "wire.read-frame",
            "directory.load",
            "bootstrap.catalogue",
            "record-delivery.chunk",
            "journal.submit",
            "reporting.put",
            "reporting.events",
            "reporting.workflows",
            "workflow.phase-evidence",
        ),
        strict=True,
    )
)
CHECK_OVERRIDES = {
    f"test_{name}_linear_work": {
        **CHECK_PURPOSE,
        "authority": [owner, "release.toml#/engineering"],
        "relationship": "scoped-witness",
        "claims": ["engineering:" + _IDS[name]],
    }
    for name, owner in _OWNERS.items()
}
CHECK_OVERRIDES["test_cli_linear_work"] = {
    **CHECK_PURPOSE,
    "purpose": "public-contract",
    "authority": ["policy/interfaces.json#/cli", "release.toml#/engineering"],
    "relationship": "scoped-witness",
    "claims": [
        "cli:domain-ops:info",
        "cli:host-ops:info",
        "cli:app-ops:info",
        "client:info",
        "cli:domain-ops:validate",
        "cli:host-ops:validate",
        "cli:app-ops:validate",
    ],
}


def test_nonlinear_or_missing_growth_declarations_block_implementation(monkeypatch):
    from dataclasses import replace

    original = validate_phase_evidence.__growth_bounds__
    for change in ({"growth": "quadratic"}, {"linear_proofs": ()}):
        monkeypatch.setattr(
            validate_phase_evidence, "__growth_bounds__", replace(original, **change)
        )
        with pytest.raises(ValueError, match="incomplete operation bounds"):
            declarations()


def test_phase_growth_witness_rejects_pairwise_schema_regression(monkeypatch):
    from fishhat_contracts import validation

    monkeypatch.setitem(
        validation._SCHEMA_VALIDATOR.VALIDATORS,
        "uniqueItems",
        Draft202012Validator.VALIDATORS["uniqueItems"],
    )
    with pytest.raises(AssertionError):
        test_phase_evidence_linear_work()


for _name, _authority in {
    "test_linear_oracle_rejects_quadratic_work_and_repeated_prefix_serialization": "tests/linear_support.py#assert_linear",
    "test_nonlinear_or_missing_growth_declarations_block_implementation": "scripts/engineering.py#declarations",
    "test_phase_growth_witness_rejects_pairwise_schema_regression": "tests/test_linear_growth.py#test_phase_evidence_linear_work",
    "test_every_declared_implementation_requires_linear_proofs": "release.toml#/engineering",
}.items():
    CHECK_OVERRIDES[_name] = {
        "purpose": "validation-tooling",
        "authority": [_authority],
        "scope": "growth gate admission and regression detection",
        "relationship": "no-product-claim",
        "reason": "Challenges the work oracle and admission rules; a gate self-check supplies no implementation qualification.",
        "claims": [],
    }


def test_workflow_pagination_refreshes_same_connection_and_external_appends(tmp_path):
    original = event()
    path = tmp_path / "shared.sqlite"
    store = EventStore(path, original["domain_id"], SERVICE, initialize=True)
    external = EventStore(path, original["domain_id"], SERVICE)
    try:
        seed(store, 16, workflows=True)
        first = store.workflows(limit=16, **AUTH)
        assert len(first["items"]) == 16 and first["next_after"] is None
        seed(store, 1, workflows=True)
        assert len(store.workflows(limit=100, **AUTH)["items"]) == 17
        seed(external, 1, workflows=True)
        after = first["items"][-1]["first_sequence"]
        page = store.workflows(after=after, limit=100, expected_store_epoch=store.epoch, **AUTH)
        assert len(page["items"]) == 2
        assert all(item["first_sequence"] > after for item in page["items"])
        assert len(store.workflows(limit=100, **AUTH)["items"]) == 18
    finally:
        external.close()
        store.close()
