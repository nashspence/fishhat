from __future__ import annotations

import ast
import copy
import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from fishhat_client.submission import prepare_delivery, submit_once
from fishhat_client.workspace import check_closeout, validate_session
from fishhat_contracts.validation import ContractError, canonical, digest, validate
from fishhat_owner.journal import Journal
from fishhat_reporting.reports import (
    comment_match,
    render_issue_comment,
    report,
    validate_event,
    validate_index_auth,
    validate_profile,
)
from fishhat_reporting.store import EventStore

from tests.operation_support import seal_operation
from tests.support import ROOT, fixture_path

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/tracking-records.schema.json"
    ],
    "scope": "offline reporting/store reference models",
    "relationship": "candidate",
    "reason": "Synthetic adapters and local SQLite state test optional reporting isolation, immutable records and pagination; no running report API or forge publication is qualified.",
    "claims": [],
}

CHECK_CLASS_PURPOSE = {
    "Noninterference": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/client-records.schema.json",
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/tracking-records.schema.json",
        ],
        "scope": "offline submission, owner journal and reporting reference models",
        "relationship": "candidate",
        "reason": "Injected transport and local state exercise exact request binding, separate acceptance and execution outcomes, and reporting noninterference; no authenticated native owner is qualified.",
        "claims": [],
    }
}


def load(p):
    return json.loads(fixture_path(p).read_text())


def event():
    return load("examples/tracking/event.json")


class TrackingContracts(unittest.TestCase):
    def test_progress(self):
        validate_event(event())

    def test_optional_index_link(self):
        validate_event(load("examples/tracking/index-link.json"))

    def test_index_link_wrong_workflow(self):
        e = load("examples/tracking/index-link.json")
        e["index_reference"]["workflow_id"] = str(uuid.uuid4())
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_index_link_disposition(self):
        e = load("examples/tracking/index-link.json")
        e["coordination_copies"] = "issue-only"
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_index_auth_shape(self):
        validate_index_auth(load("examples/receipts-app/auth-shape.json"))

    def test_index_auth_no_principals(self):
        a = load("examples/receipts-app/auth-shape.json")
        a["principals"] = []
        with self.assertRaises(ContractError):
            validate_index_auth(a)

    def test_index_auth_duplicate_id(self):
        a = load("examples/receipts-app/auth-shape.json")
        b = copy.deepcopy(a["principals"][0])
        b["token_sha256"] = "f" * 64
        a["principals"].append(b)
        with self.assertRaises(ContractError):
            validate_index_auth(a)

    def test_index_auth_duplicate_token(self):
        a = load("examples/receipts-app/auth-shape.json")
        b = copy.deepcopy(a["principals"][0])
        b["id"] = "different-principal"
        a["principals"].append(b)
        with self.assertRaises(ContractError):
            validate_index_auth(a)

    def test_intent_only(self):
        validate_event(load("examples/tracking/intent.json"))

    def test_unknown_top_fields(self):
        for key in ["actor", "credentials", "ssh_command", "payload", "approved", "plan", "token"]:
            e = event()
            e[key] = "untrusted"
            with self.subTest(key=key), self.assertRaises(ContractError):
                validate_event(e)

    def test_reported_status_is_not_authority(self):
        e = event()
        e["operations"][0]["reported_state"] = "succeeded"
        validate_event(e)
        self.assertNotIn("verified", canonical(e).decode())

    def test_invalid_status(self):
        e = event()
        e["operations"][0]["reported_state"] = "approve-and-run"
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_boolean_issue_number(self):
        e = event()
        e["issue"]["number"] = True
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_missing_issue_disposition(self):
        e = event()
        e["issue"] = None
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_index_only_does_not_need_issue(self):
        e = event()
        e["issue"] = None
        e["coordination_copies"] = "index-only"
        validate_event(e)

    def test_unknown_participant(self):
        e = event()
        e["participants"] = []
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_duplicate_operation_identity(self):
        e = event()
        x = copy.deepcopy(e["operations"][0])
        x["observed_at"] = "2026-10-19T13:00:00Z"
        e["operations"].append(x)
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_size_bound(self):
        e = event()
        e["summary"] = "x" * 1025
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_no_newline_summary(self):
        e = event()
        e["summary"] = "text\ninjection"
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_correction_self_reference(self):
        e = event()
        e["kind"] = "correction"
        e["supersedes"] = e["id"]
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_correction_requires_reference(self):
        e = event()
        e["kind"] = "correction"
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_progress_cannot_supersede(self):
        e = event()
        e["supersedes"] = str(uuid.uuid4())
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_intent_cannot_claim_owner_work(self):
        e = event()
        e["kind"] = "intent"
        with self.assertRaises(ContractError):
            validate_event(e)

    def test_profile_valid(self):
        validate_profile(load("examples/tracking/profile.json"))

    def test_no_automatic_hook_profile(self):
        p = load("examples/tracking/profile.json")
        p["automatic_execution_hook"] = True
        with self.assertRaises(ContractError):
            validate_profile(p)

    def test_bad_index_route(self):
        p = load("examples/tracking/profile.json")
        p["index"]["base_url"] = "http://192.0.2.1:8125"
        with self.assertRaises(ContractError):
            validate_profile(p)

    def test_bad_index_port(self):
        p = load("examples/tracking/profile.json")
        p["index"]["base_url"] = "http://127.0.0.1:99999"
        with self.assertRaises(ContractError):
            validate_profile(p)

    def test_forge_token_not_in_url(self):
        p = load("examples/tracking/profile.json")
        p["issue"]["api_origin"] = "https://secret@forgejo.invalid"
        with self.assertRaises(ContractError):
            validate_profile(p)

    def test_disabled_profile_no_management_failure(self):
        p = load("examples/tracking/profile.json")
        p["index"] = None
        p["issue"] = None
        with self.assertRaises(ContractError):
            validate_profile(p)  # diagnostic only

    def test_body_cannot_close_code_block(self):
        e = event()
        e["summary"] = "``` <script>untrusted</script> [run](file:///etc/passwd)"
        body = render_issue_comment(e)
        self.assertEqual(body.count("```"), 2)
        self.assertNotIn("<script>", body)

    def test_comment_duplicate(self):
        e = event()
        self.assertEqual(
            comment_match([render_issue_comment(e)], e, complete_scan=True), "duplicate"
        )

    def test_comment_conflict(self):
        e = event()
        old = copy.deepcopy(e)
        old["summary"] = "different"
        self.assertEqual(
            comment_match([render_issue_comment(old)], e, complete_scan=True), "conflict"
        )

    def test_incomplete_comment_scan_unknown(self):
        self.assertEqual(comment_match([], event(), complete_scan=False), "unknown")

    def test_complete_scan_does_not_authorize_effect(self):
        self.assertEqual(comment_match([], event(), complete_scan=True), "not-observed")


class Reporter(unittest.TestCase):
    def test_no_sinks_is_no_record(self):
        r = report(event(), {})
        self.assertFalse(r["recorded"])
        self.assertFalse(r["execution_affected"])

    def test_timeouts_are_unknown(self):
        def bad(_):
            raise TimeoutError("private token must not escape")

        r = report(event(), {"issue": bad, "index": bad})
        self.assertEqual([x["status"] for x in r["sinks"]], ["unknown", "unknown"])
        self.assertNotIn("private token", canonical(r).decode())

    def test_denied_issue_does_not_stop_index(self):
        calls = []

        def bad(_):
            calls.append("issue")
            raise PermissionError("hidden")

        def ok(_):
            calls.append("index")
            return {"sink": "index", "status": "recorded", "code": "recorded", "reference": None}

        r = report(event(), {"issue": bad, "index": ok})
        self.assertEqual(calls, ["issue", "index"])
        self.assertTrue(r["recorded"])
        self.assertFalse(r["complete"])

    def test_no_write_retry(self):
        calls = []

        def bad(_):
            calls.append(1)
            raise ConnectionError()

        r = report(event(), {"issue": bad})
        self.assertEqual(len(calls), 1)
        self.assertEqual(r["sinks"][0]["status"], "unknown")

    def test_disabled_index(self):
        self.assertEqual(report(event(), {"index": None})["sinks"][0]["status"], "not-configured")

    def test_invalid_event_no_adapter_call(self):
        e = event()
        e["token"] = "bad"
        calls = []
        r = report(e, {"issue": lambda _: calls.append(1)})
        self.assertEqual(calls, [])
        self.assertFalse(r["recorded"])

    def test_mutating_fake_adapter_cannot_change_original(self):
        e = event()
        before = canonical(e)

        def fake(x):
            x["summary"] = "changed"
            return {"sink": "index", "status": "recorded", "code": "ok", "reference": None}

        report(e, {"index": fake})
        self.assertEqual(canonical(e), before)

    def test_invalid_adapter_output_is_reporting_failure(self):
        r = report(event(), {"index": lambda _: {"state": "accepted"}})
        self.assertFalse(r["recorded"])

    def test_no_execution_result_input(self):
        self.assertNotIn("owner_transport", __import__("inspect").signature(report).parameters)


class OptionalIndex(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "index.sqlite"
        self.e = event()
        self.service = str(uuid.uuid4())
        self.s = EventStore(self.path, self.e["domain_id"], self.service, initialize=True)
        self.auth = {"principal": "reporter-one", "scopes": {"read", "append"}}

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def test_put_get_durable(self):
        status, row = self.s.put(self.e, **self.auth)
        self.assertEqual(status, 201)
        validate("tracking-records.schema.json", row, "Envelope")
        self.s.close()
        self.s = EventStore(self.path, self.e["domain_id"], self.service)
        self.assertEqual(
            self.s.get(self.e["workflow_id"], self.e["id"], **self.auth)["event"], self.e
        )

    def test_duplicate_after_lost_response(self):
        self.s.put(self.e, **self.auth)
        code, _ = self.s.put(self.e, **self.auth)
        self.assertEqual(code, 200)

    def test_different_reporter_duplicate_preserves_original(self):
        self.s.put(self.e, **self.auth)
        _, r = self.s.put(self.e, principal="another-reporter", scopes={"append"})
        self.assertEqual(r["reporter"], "reporter-one")

    def test_conflicting_content_retains_original(self):
        self.s.put(self.e, **self.auth)
        e = copy.deepcopy(self.e)
        e["summary"] = "newer claim"
        with self.assertRaises(ContractError):
            self.s.put(e, **self.auth)
        self.assertEqual(self.s.get(e["workflow_id"], e["id"], **self.auth)["event"], self.e)

    def test_auth_before_dedup(self):
        self.s.put(self.e, **self.auth)
        with self.assertRaises(ContractError):
            self.s.put(self.e, principal="reader", scopes={"read"})

    def test_no_anonymous_read(self):
        with self.assertRaises(ContractError):
            self.s.get(self.e["workflow_id"], self.e["id"], principal="", scopes={"read"})

    def test_cross_domain_rejected(self):
        self.e["domain_id"] = str(uuid.uuid4())
        with self.assertRaises(ContractError):
            self.s.put(self.e, **self.auth)

    def test_path_mismatch(self):
        with self.assertRaises(ContractError):
            self.s.put(self.e, event_id=str(uuid.uuid4()), **self.auth)

    def test_no_record_is_only_no_report(self):
        self.assertIsNone(self.s.get(self.e["workflow_id"], self.e["id"], **self.auth))

    def test_reverse_status_order_not_a_state_machine(self):
        self.e["operations"][0]["reported_state"] = "succeeded"
        self.s.put(self.e, **self.auth)
        old = event()
        old["id"] = str(uuid.uuid4())
        old["reported_at"] = "2026-10-18T00:00:00Z"
        self.s.put(old, **self.auth)
        records = self.s.events(self.e["workflow_id"], **self.auth)["items"]
        self.assertEqual(
            [x["event"]["operations"][0]["reported_state"] for x in records],
            ["succeeded", "submission-unknown"],
        )

    def test_page_scope_and_epoch(self):
        self.s.put(self.e, **self.auth)
        e = copy.deepcopy(self.e)
        e["id"] = str(uuid.uuid4())
        self.s.put(e, **self.auth)
        p = self.s.events(self.e["workflow_id"], limit=1, **self.auth)
        validate("tracking-records.schema.json", p, "EventPage")
        self.assertIsNotNone(p["next_after"])
        q = self.s.events(
            self.e["workflow_id"],
            after=p["next_after"],
            expected_store_epoch=p["store_epoch"],
            **self.auth,
        )
        self.assertEqual(q["items"][0]["event"]["id"], e["id"])

    def test_restore_does_not_replay(self):
        self.s.put(self.e, **self.auth)
        old = self.s.epoch
        self.s.restore_epoch()
        self.assertNotEqual(old, self.s.epoch)
        with self.assertRaises(ContractError):
            self.s.events(self.e["workflow_id"], after=1, expected_store_epoch=old, **self.auth)
        self.assertEqual(
            self.s.get(self.e["workflow_id"], self.e["id"], **self.auth)["event"], self.e
        )

    def test_page_requires_epoch_after_first(self):
        with self.assertRaises(ContractError):
            self.s.events(self.e["workflow_id"], after=1, **self.auth)

    def test_bool_limit_rejected(self):
        with self.assertRaises(ContractError):
            self.s.events(self.e["workflow_id"], limit=True, **self.auth)

    def test_page_bounds(self):
        for limit in [0, 101, -1]:
            with self.subTest(limit=limit), self.assertRaises(ContractError):
                self.s.events(self.e["workflow_id"], limit=limit, **self.auth)

    def test_workflow_list_no_status_claim(self):
        self.s.put(self.e, **self.auth)
        r = self.s.workflows(**self.auth)
        validate("tracking-records.schema.json", r, "WorkflowPage")
        self.assertNotIn("state", r["items"][0])

    def test_workflow_first_time_is_first_sequence_even_after_clock_change(self):
        _, first = self.s.put(self.e, **self.auth)
        e = copy.deepcopy(self.e)
        e["id"] = str(uuid.uuid4())
        _, second = self.s.put(e, **self.auth)
        with self.s.db:
            self.s.db.execute(
                "UPDATE events SET received_at=? WHERE sequence=?",
                ("2000-01-01T00:00:00Z", second["sequence"]),
            )
        item = self.s.workflows(**self.auth)["items"][0]
        self.assertEqual(item["first_sequence"], first["sequence"])
        self.assertEqual(item["first_received_at"], first["received_at"])

    def test_quota_affects_new_events_not_existing(self):
        self.s.max_events = 1
        self.s.put(self.e, **self.auth)
        e = copy.deepcopy(self.e)
        e["id"] = str(uuid.uuid4())
        with self.assertRaises(ContractError):
            self.s.put(e, **self.auth)
        self.assertEqual(self.s.put(self.e, **self.auth)[0], 200)

    def test_workflow_quota(self):
        self.s.max_workflows = 1
        self.s.put(self.e, **self.auth)
        e = copy.deepcopy(self.e)
        e["workflow_id"] = str(uuid.uuid4())
        with self.assertRaises(ContractError):
            self.s.put(e, **self.auth)

    def test_missing_commissioned_store_not_created(self):
        with self.assertRaises(ContractError):
            EventStore(Path(self.tmp.name) / "absent.sqlite", self.e["domain_id"], self.service)

    def test_forged_actor_field_rejected(self):
        self.e["reporter"] = "administrator"
        with self.assertRaises(ContractError):
            self.s.put(self.e, **self.auth)

    def test_correction_cycle(self):
        e = event()
        a = e["id"]
        b = str(uuid.uuid4())
        e["kind"] = "correction"
        e["supersedes"] = b
        self.s.put(e, **self.auth)
        e["id"] = b
        e["supersedes"] = a
        with self.assertRaises(ContractError):
            self.s.put(e, **self.auth)

    def test_database_failure_is_index_only(self):
        self.s.db.execute("PRAGMA query_only=ON")
        with self.assertRaises(sqlite3.DatabaseError):
            self.s.put(self.e, **self.auth)

    def test_only_reporting_tables(self):
        names = {
            r[0] for r in self.s.db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        self.assertEqual(names, {"meta", "events", "sqlite_sequence"})


class Noninterference(unittest.TestCase):
    def setUp(self):
        self.template = load("examples/session/receipt-export.json")["deliveries"][0]
        self.operation = load("examples/operation.json")
        self.template.update(
            owner=copy.deepcopy(self.operation["owner"]),
            plan_digest=self.operation["plan_digest"],
            subject_digest=digest(self.operation["subject"]),
            action=self.operation["subject"]["action"],
            resource=copy.deepcopy(self.operation["subject"]["resource"]),
            expected_generation=self.operation["generation"],
        )

    def receipt(self, delivery, state="accepted"):
        # The injected transport represents authentication; the signed synthetic
        # snapshot preserves the independent decoded-record integrity boundary.
        operation = copy.deepcopy(self.operation)
        operation["request_id"] = delivery["request_id"]
        operation["state"] = state
        if state == "succeeded":
            operation["effect_certainty"] = "known"
        return seal_operation(operation)

    def test_no_files_required(self):
        with patch("pathlib.Path.open", side_effect=OSError("read-only client home")):
            d = prepare_delivery(self.template)
            r = submit_once(d, self.receipt)
        self.assertEqual(r["exit_code"], 0)
        self.assertEqual(r["tracking"], "not-attempted")
        self.assertEqual(d["state"], "prepared")
        self.assertEqual(r["delivery"]["state"], "accepted")

    def test_no_tracking_import_dependency(self):
        tree = ast.parse(
            (ROOT / "packages/fishhat-client/src/fishhat_client/submission.py").read_text()
        )
        imports = [
            ast.unparse(n) for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
        ]
        self.assertFalse(
            any(
                any(s in n for s in ["tracking", "client_store", "sqlite", "requests", "socket"])
                for n in imports
            )
        )

    def test_tracking_unavailable_cannot_be_called_by_submission(self):
        with patch("fishhat_reporting.reports.report", side_effect=AssertionError("must not run")):
            d = prepare_delivery(self.template)
            r = submit_once(d, self.receipt)
        self.assertEqual(r["exit_code"], 0)

    def test_running_and_waiting_are_execution_not_delivery_states(self):
        for state in ("running", "waiting"):
            with self.subTest(state=state):
                d = prepare_delivery(self.template)
                r = submit_once(d, lambda x, state=state: self.receipt(x, state))
                self.assertEqual(r["delivery"]["state"], "accepted")
                self.assertEqual(r["owner_receipt"]["state"], state)
                self.assertEqual(r["exit_code"], 0)
                validate("client-records.schema.json", r["delivery"], "Delivery")

    def test_unsuccessful_owner_outcomes_are_accepted_without_success_exit(self):
        for state in ("failed", "cancelled", "quarantined"):
            with self.subTest(state=state):
                d = prepare_delivery(self.template)
                receipt = self.receipt(d, state)
                receipt["effect_certainty"] = "unknown"
                receipt["holds"] = [str(uuid.uuid4())]
                seal_operation(receipt)
                r = submit_once(d, lambda _, receipt=receipt: receipt)
                self.assertEqual(r["exit_code"], 1)
                self.assertEqual(r["delivery"]["state"], "accepted")
                self.assertEqual(r["owner_receipt"], receipt)
                validate("client-records.schema.json", r["delivery"], "Delivery")

    def test_successful_execution_stays_in_owner_receipt(self):
        d = prepare_delivery(self.template)
        r = submit_once(d, lambda x: self.receipt(x, "succeeded"))
        self.assertEqual(r["exit_code"], 0)
        self.assertEqual(r["delivery"]["state"], "accepted")
        self.assertEqual(r["owner_receipt"]["state"], "succeeded")
        self.assertEqual(r["owner_receipt"]["effect_certainty"], "known")

    def test_missing_or_partial_receipt_does_not_prove_acceptance_or_rejection(self):
        for form in ("missing", "empty", "partial"):
            with self.subTest(form=form):
                d = prepare_delivery(self.template)
                receipt = {
                    "missing": None,
                    "empty": {},
                    "partial": {"request_id": d["request_id"], "state": "accepted"},
                }[form]
                r = submit_once(d, lambda _, receipt=receipt: receipt)
                self.assertEqual(r["exit_code"], 8)
                self.assertEqual(r["delivery"]["state"], "acceptance_unknown")
                self.assertEqual(r["delivery"]["request_id"], d["request_id"])
                self.assertIsNone(r["owner_receipt"])

    def test_owner_reply_cannot_substitute_the_request_or_reviewed_inputs(self):
        changes = (
            (("request_id",), str(uuid.uuid4())),
            (("owner", "id"), str(uuid.uuid4())),
            (("owner", "epoch"), str(uuid.uuid4())),
            (("plan_digest",), "sha256:" + "f" * 64),
            (("subject", "resource", "id"), "another-app"),
            (("subject", "arguments", "components"), ["another-component"]),
            (("witness", "owner", "id"), str(uuid.uuid4())),
        )
        for path, replacement in changes:
            with self.subTest(path=path):
                d = prepare_delivery(self.template)
                receipt = self.receipt(d)
                target = receipt
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                if path[0] != "witness":
                    seal_operation(receipt)
                r = submit_once(d, lambda _, receipt=receipt: receipt)
                self.assertEqual(r["exit_code"], 8)
                self.assertEqual(r["delivery"]["state"], "acceptance_unknown")
                self.assertEqual(r["delivery"]["request_id"], d["request_id"])
                self.assertIsNone(r["owner_receipt"])

    def test_unknown_effect_cannot_be_reported_as_success(self):
        d = prepare_delivery(self.template)
        receipt = self.receipt(d, "succeeded")
        receipt["effect_certainty"] = "unknown"
        seal_operation(receipt)
        r = submit_once(d, lambda _: receipt)
        self.assertEqual(r["exit_code"], 8)
        self.assertEqual(r["delivery"]["state"], "acceptance_unknown")
        self.assertIsNone(r["owner_receipt"])

    def test_delivery_rejects_execution_states_and_old_preparation_labels(self):
        for state in (
            "reserved",
            "attempting",
            "paused",
            "running",
            "waiting",
            "succeeded",
            "failed",
            "cancelled",
            "quarantined",
        ):
            d = prepare_delivery(self.template)
            d["state"] = state
            with self.subTest(state=state), self.assertRaises(ContractError):
                validate("client-records.schema.json", d, "Delivery")

    def test_timeout_same_id_no_retry(self):
        d = prepare_delivery(self.template)
        seen = []

        def timeout(x):
            seen.append(x["request_id"])
            raise TimeoutError()

        r = submit_once(d, timeout)
        self.assertEqual(seen, [d["request_id"]])
        self.assertEqual(r["delivery"]["request_id"], d["request_id"])
        self.assertEqual(r["exit_code"], 8)

    def test_unknown_cannot_be_reclassified_new_in_same_model(self):
        d = prepare_delivery(self.template)
        d["state"] = "acceptance_unknown"
        with self.assertRaises(ContractError):
            submit_once(d, lambda _: None)

    def test_owner_acceptance_survives_client_and_trackers(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "owner.sqlite"
            d = prepare_delivery(self.template)
            o = d["owner"]
            j = Journal(p, o["id"], o["epoch"], initialize=True)

            def lost(x):
                j.submit(
                    x["request_id"],
                    {"plan_digest": x["plan_digest"]},
                    principal="caller",
                    authorized=True,
                    expected_epoch=o["epoch"],
                    expected_generation=0,
                    expires=100,
                    now=0,
                )
                raise TimeoutError()

            result = submit_once(d, lost)
            self.assertEqual(result["exit_code"], 8)
            request = d["request_id"]
            plan = d["plan_digest"]
            j.close()
            del d, result
            # New authorized client has only an independently inspected owner listing.
            j = Journal(p, o["id"], o["epoch"])
            listed = j.db.execute("SELECT request_id FROM requests").fetchall()
            self.assertEqual(listed, [(request,)])
            replay = j.submit(
                request,
                {"plan_digest": plan},
                principal="new-client",
                authorized=True,
                expected_epoch=o["epoch"],
                expected_generation=0,
                expires=100,
                now=200,
            )
            self.assertEqual(replay["state"], "accepted")
            self.assertEqual(replay["principal"], "caller")
            j.close()

    def test_owner_journal_failure_still_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = prepare_delivery(self.template)
            o = d["owner"]
            j = Journal(Path(tmp) / "o.db", o["id"], o["epoch"], initialize=True)
            j.db.execute("PRAGMA query_only=ON")
            with self.assertRaises(sqlite3.DatabaseError):
                j.submit(
                    d["request_id"],
                    {},
                    principal="user",
                    authorized=True,
                    expected_epoch=o["epoch"],
                    expected_generation=0,
                    expires=100,
                    now=0,
                )
            j.close()

    def test_closed_issue_not_execution_input(self):
        self.assertNotIn("issue", __import__("inspect").signature(submit_once).parameters)

    def test_cleanup_without_tracking(self):
        c = load("examples/session/closeout.json")
        c["receipt_export_digest"] = None
        r = check_closeout(c)
        self.assertTrue(r["safe_to_close"])
        self.assertIn("tracking-not-retained", r["warnings"])

    def test_tracking_only_obligation_never_blocks(self):
        c = load("examples/session/closeout.json")
        c["obligations"] = [
            {"id": "issue", "kind": "receipt", "disposition": "unresolved", "evidence_digest": None}
        ]
        c["evidence_outside_workspace"] = False
        c["receipt_export_digest"] = None
        self.assertTrue(check_closeout(c)["safe_to_close"])

    def test_source_obligation_still_blocks(self):
        c = load("examples/session/closeout.json")
        c["obligations"][0]["disposition"] = "unresolved"
        self.assertFalse(check_closeout(c)["safe_to_close"])

    def test_session_without_any_evidence_path(self):
        s = load("examples/session/session.json")
        s.pop("evidence_dir", None)
        validate_session(s)

    def test_reports_cannot_execute(self):
        api = load("contracts/receipts-api.openapi.json")
        ops = []
        for x in api["paths"].values():
            for m, v in x.items():
                if m in ["get", "put", "post", "patch", "delete"]:
                    ops.append(v["operationId"])
        self.assertEqual(
            set(ops), {"recordEvent", "getEvent", "listEvents", "listWorkflows", "health"}
        )

    def test_scaffold_has_no_tracking_side_effects(self):
        import contextlib
        import io

        from fishhat_cli.validation import main

        with patch(
            "fishhat_reporting.reports.report",
            side_effect=AssertionError("reporting must be explicit"),
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main("domain-ops", ["info", "--json"]), 0)


class DiscoveryNonblocking(unittest.TestCase):
    def test_directory_has_no_receipt_preflight_or_storage_gate(self):
        from fishhat_directory.projection import WORKFLOWS

        text = " ".join(x for steps in WORKFLOWS.values() for x in steps).lower()
        for obsolete in [
            "persist the original",
            "retain per-user receipts",
            "preserve request receipts outside",
        ]:
            self.assertNotIn(obsolete, text)
        self.assertIn("no client file or tracker write is required", text)
        self.assertIn("missing tracking alone does not block", text)
