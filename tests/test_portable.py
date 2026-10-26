from __future__ import annotations

import base64
import copy
import csv
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from fishhat_client.workspace import (
    check_closeout,
    clean_path,
    merge_exports,
    select_suite,
    validate_bundle,
    validate_export,
    validate_recovery_set,
    validate_run,
    validate_session,
    validate_suite,
)
from fishhat_contracts.validation import ContractError, digest, strict_yaml, validate, validate_cli
from fishhat_owner.commands import FORMS, parse_command

from tests.operation_support import seal_operation
from tests.support import fixture_path

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workspace.schema.json"
    ],
    "scope": "offline portable/client helpers",
    "relationship": "candidate",
    "reason": "Synthetic sessions, closeout, merge, owner grammar and wheel experiments exercise reference helpers, not end-to-end execution of declared CLI forms.",
    "claims": [],
}

CHECK_CLASS_PURPOSE = {
    "CliOutcomes": {
        "purpose": "public-contract",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/cli-output.schema.json"
        ],
        "scope": "decoded CLI and owner receipt reference data",
        "relationship": "candidate",
        "reason": "Contradictory acceptance, execution, completion and identity claims are rejected by local validation; transport authentication and native outcomes are not qualified.",
        "claims": [],
    }
}


def load(p):
    x = fixture_path(p)
    return strict_yaml(x.read_text()) if x.suffix == ".yaml" else json.loads(x.read_text())


class Portable(unittest.TestCase):
    def setUp(self):
        self.session = load("examples/session/session.json")
        self.bundle = load("examples/session/install-bundle.json")
        self.closeout = load("examples/session/closeout.json")
        self.receipts = load("examples/session/receipt-export.json")
        self.suite = load("examples/domain/domain-tests.yaml")

    def test_valid_session(self):
        validate_session(self.session)

    def test_optional_evidence_not_disposable(self):
        self.session["evidence_dir"] = self.session["root"] + "/state"
        with self.assertRaises(ContractError):
            validate_session(self.session)

    def test_workspace_not_inside_optional_evidence(self):
        self.session["evidence_dir"] = "/home/example"
        with self.assertRaises(ContractError):
            validate_session(self.session)

    def test_wrong_domain_path(self):
        self.session["domain_dir"] = "/elsewhere/domain"
        with self.assertRaises(ContractError):
            validate_session(self.session)

    def test_no_relative_paths(self):
        self.session["root"] = "relative"
        with self.assertRaises(ContractError):
            validate_session(self.session)

    def test_noncanonical_paths(self):
        for p in ["/work/../state", "/work//x", "/work/./x", "/work/", "/", "/work\x00bad"]:
            with self.subTest(p=p), self.assertRaises(ContractError):
                clean_path(p)

    def test_two_envs(self):
        self.session["test_env"] = self.session["tool_env"]
        with self.assertRaises(ContractError):
            validate_session(self.session)

    def test_no_env_in_domain(self):
        self.session["tool_env"] = self.session["domain_dir"] + "/.venv"
        with self.assertRaises(ContractError):
            validate_session(self.session)

    def test_candidate_not_production_qualified(self):
        validate_bundle(self.bundle)
        with self.assertRaises(ContractError):
            validate_bundle(self.bundle, require_qualified=True)

    def test_wrong_platform(self):
        with self.assertRaises(ContractError):
            validate_bundle(self.bundle, platform="macos-arm64")

    def test_wrong_abi(self):
        with self.assertRaises(ContractError):
            validate_bundle(self.bundle, python="cpython-9.9")

    def test_duplicate_artifact(self):
        self.bundle["wheels"].append(copy.deepcopy(self.bundle["wheels"][0]))
        with self.assertRaises(ContractError):
            validate_bundle(self.bundle)

    def test_no_sdist_runtime(self):
        self.bundle["wheels"][0]["path"] = "wheels/example.tar.gz"
        with self.assertRaises(ContractError):
            validate_bundle(self.bundle)

    def test_bundle_path_escape(self):
        self.bundle["wheels"][0]["path"] = "wheels/../../bad.whl"
        with self.assertRaises(ContractError):
            validate_bundle(self.bundle)

    def test_qualified_requires_evidence(self):
        self.bundle["qualification"] = "qualified"
        self.bundle["evidence"] = []
        with self.assertRaises(ContractError):
            validate_bundle(self.bundle)

    def test_no_credentials_in_bundle(self):
        self.bundle["token"] = "test-sentinel"
        with self.assertRaises(ContractError):
            validate_bundle(self.bundle)

    def test_close_never_deletes(self):
        x = check_closeout(self.closeout)
        self.assertTrue(x["safe_to_close"])
        self.assertFalse(x["deletes_files"])

    def test_close_blocks_work(self):
        self.closeout["active_jobs"] = 1
        self.assertFalse(check_closeout(self.closeout)["safe_to_close"])

    def test_close_blocks_foreign_tree(self):
        self.closeout["foreign_worktrees"] = 1
        self.assertFalse(check_closeout(self.closeout)["safe_to_close"])

    def test_close_needs_durable_evidence(self):
        self.closeout["evidence_outside_workspace"] = False
        self.assertFalse(check_closeout(self.closeout)["safe_to_close"])

    def test_close_unresolved_source(self):
        self.closeout["obligations"][0]["disposition"] = "unresolved"
        self.assertFalse(check_closeout(self.closeout)["safe_to_close"])

    def test_close_missing_source_receipt(self):
        self.closeout["obligations"][0]["evidence_digest"] = None
        self.assertFalse(check_closeout(self.closeout)["safe_to_close"])

    def test_close_pending_identity_without_export_is_warning(self):
        self.closeout["receipt_export_digest"] = None
        result = check_closeout(self.closeout)
        self.assertTrue(result["safe_to_close"])
        self.assertIn("tracking-not-retained", result["warnings"])

    def test_close_digest_changes_when_tree_changes(self):
        a = check_closeout(self.closeout)["plan_digest"]
        self.closeout["tree_digest"] = "sha256:" + "9" * 64
        self.assertNotEqual(a, check_closeout(self.closeout)["plan_digest"])

    def test_close_no_recursive_delete_option(self):
        self.closeout["would_delete"] = True
        with self.assertRaises(ContractError):
            check_closeout(self.closeout)

    def test_merge_deduplicates(self):
        self.assertEqual(len(merge_exports(self.receipts, self.receipts)["deliveries"]), 1)

    def test_merge_conflict(self):
        b = copy.deepcopy(self.receipts)
        b["deliveries"][0]["plan_digest"] = "sha256:" + "9" * 64
        with self.assertRaises(ContractError):
            merge_exports(self.receipts, b)

    def test_merge_domain_conflict(self):
        b = copy.deepcopy(self.receipts)
        b["domain_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with self.assertRaises(ContractError):
            merge_exports(self.receipts, b)

    def test_merge_cannot_assert_new_state(self):
        b = copy.deepcopy(self.receipts)
        b["deliveries"][0]["state"] = "accepted"
        self.assertEqual(
            merge_exports(self.receipts, b)["deliveries"][0]["state"],
            self.receipts["deliveries"][0]["state"],
        )

    def test_import_cannot_mix_execution_outcome_into_delivery(self):
        self.receipts["deliveries"][0]["state"] = "succeeded"
        with self.assertRaises(ContractError):
            validate_export(self.receipts)

    def test_epoch_is_distinct_identity(self):
        b = copy.deepcopy(self.receipts)
        b["deliveries"][0]["owner"]["epoch"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        self.assertEqual(len(merge_exports(self.receipts, b)["deliveries"]), 2)

    def test_exports_no_keys(self):
        self.receipts["credential_material"] = True
        with self.assertRaises(ContractError):
            validate_export(self.receipts)

    def test_default_offline(self):
        self.assertEqual(select_suite(self.suite)["class"], "offline")

    def test_mutation_all_optins(self):
        for kw in [
            {},
            {"targets": [1]},
            {"targets": [1], "allow_mutations": True},
            {"allow_mutations": True, "confirm": True},
        ]:
            with self.subTest(kw=kw), self.assertRaises(ContractError):
                select_suite(self.suite, "mutate", **kw)

    def test_explicit_mutation(self):
        self.assertEqual(
            select_suite(
                self.suite,
                "mutate",
                targets=[{"kind": "app", "id": "demo-app"}],
                allow_mutations=True,
                confirm=True,
            )["class"],
            "mutate",
        )

    def test_missing_suite(self):
        with self.assertRaises(ContractError):
            select_suite(self.suite, "invented")

    def test_bad_test_interpreter(self):
        self.suite["suites"]["offline"]["argv"][0] = "/bin/sh"
        with self.assertRaises(ContractError):
            validate_suite(self.suite)

    def test_incomplete_pass(self):
        x = load("examples/session/test-run.json")
        x["skipped_required"] = 1
        with self.assertRaises(ContractError):
            validate_run(x)

    def test_offline_remote_effect(self):
        x = load("examples/session/test-run.json")
        x["deliveries"] = self.receipts["deliveries"]
        with self.assertRaises(ContractError):
            validate_run(x)

    def test_recovery_set_candidate(self):
        validate_recovery_set(load("examples/bootstrap/native-recovery-set.json"), self.bundle)

    def test_recovery_set_no_unproven_qualification(self):
        x = load("examples/bootstrap/native-recovery-set.json")
        x["qualified"] = True
        with self.assertRaises(ContractError):
            validate_recovery_set(x, self.bundle)

    def test_source_receipt_cannot_claim_services(self):
        x = load("examples/bootstrap/source-receipt.json")
        x["services_restored"] = True
        with self.assertRaises(ContractError):
            validate("client-records.schema.json", x, "SourceRecovery")


class CliOutcomes(unittest.TestCase):
    def result(self, state):
        value = load("examples/cli-accepted.json")
        value["state"] = state
        value["result"]["state"] = state
        value["complete"] = state in ("succeeded", "failed", "cancelled", "quarantined")
        if state == "succeeded":
            value["result"]["effect_certainty"] = "known"
        if state in ("failed", "cancelled", "quarantined"):
            value["ok"] = False
            value["problem"] = load("examples/cli-unknown.json")["problem"]
            value["problem"]["code"] = {
                "failed": "CHECK_FAILED",
                "cancelled": "CANCELLED",
                "quarantined": "EFFECT_UNKNOWN",
            }[state]
            value["result"]["effect_certainty"] = "unknown"
            value["result"]["holds"] = [value["request_id"]]
        seal_operation(value["result"])
        return value

    def delivery(self, value):
        delivery = load("examples/session/receipt-export.json")["deliveries"][0]
        operation = value["result"]
        delivery.update(
            request_id=value["request_id"],
            owner=copy.deepcopy(operation["owner"]),
            plan_digest=operation["plan_digest"],
            subject_digest=digest(operation["subject"]),
            action=operation["subject"]["action"],
            resource=copy.deepcopy(operation["subject"]["resource"]),
            state="accepted",
        )
        return delivery

    def test_owner_execution_states_and_terminal_outcomes_are_distinct(self):
        for state in (
            "accepted",
            "running",
            "waiting",
            "succeeded",
            "failed",
            "cancelled",
            "quarantined",
        ):
            with self.subTest(state=state):
                value = self.result(state)
                value["delivery"] = self.delivery(value)
                validate_cli(value)
                self.assertEqual(value["delivery"]["state"], "accepted")
                if state in ("failed", "cancelled", "quarantined"):
                    self.assertTrue(value["complete"])
                    self.assertFalse(value["ok"])
                    self.assertTrue(value["result"]["holds"])

    def test_acknowledged_work_cannot_claim_completion(self):
        for state in ("accepted", "running", "waiting"):
            value = self.result(state)
            value["complete"] = True
            with self.subTest(state=state), self.assertRaises(ContractError):
                validate_cli(value)

    def test_failed_cancelled_and_quarantined_work_cannot_claim_success(self):
        for state in ("failed", "cancelled", "quarantined"):
            value = self.result(state)
            value["ok"] = True
            value["problem"] = None
            with self.subTest(state=state), self.assertRaises(ContractError):
                validate_cli(value)

    def test_envelope_cannot_disagree_with_owner_execution_outcome(self):
        for state in ("accepted", "running", "waiting", "failed", "cancelled", "quarantined"):
            value = self.result("succeeded")
            value["result"]["state"] = state
            seal_operation(value["result"])
            with self.subTest(state=state), self.assertRaises(ContractError):
                validate_cli(value)

    def test_success_requires_verified_effects_and_matching_request(self):
        for field, replacement in (
            ("effect_certainty", "unknown"),
            ("request_id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        ):
            value = self.result("succeeded")
            value["result"][field] = replacement
            seal_operation(value["result"])
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_cli(value)

    def test_terminal_success_cannot_use_generic_complete_state(self):
        value = self.result("succeeded")
        value["state"] = "complete"
        with self.assertRaises(ContractError):
            validate_cli(value)

    def test_execution_outcome_needs_owner_evidence(self):
        for state in (
            "accepted",
            "running",
            "waiting",
            "succeeded",
            "failed",
            "cancelled",
            "quarantined",
        ):
            value = self.result(state)
            value["result"] = None
            with self.subTest(state=state), self.assertRaises(ContractError):
                validate_cli(value)

    def test_delivery_cannot_replace_owner_epoch_request_or_reviewed_plan(self):
        for field, replacement in (
            ("request_id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            ("plan_digest", "sha256:" + "f" * 64),
            ("subject_digest", "sha256:" + "f" * 64),
            ("state", "rejected"),
        ):
            value = self.result("accepted")
            value["delivery"] = self.delivery(value)
            value["delivery"][field] = replacement
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_cli(value)
        value = self.result("accepted")
        value["delivery"] = self.delivery(value)
        value["delivery"]["owner"]["epoch"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with self.assertRaises(ContractError):
            validate_cli(value)

    def test_unknown_acceptance_keeps_original_request_without_owner_outcome(self):
        value = load("examples/cli-unknown.json")
        validate_cli(value)
        value["request_id"] = None
        with self.assertRaises(ContractError):
            validate_cli(value)

    def test_problem_cannot_refer_to_another_owner_or_resource(self):
        for field, replacement in (
            (
                "owner",
                {
                    **load("examples/operation.json")["owner"],
                    "epoch": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                },
            ),
            ("resource", {"kind": "app", "id": "another-app"}),
        ):
            value = self.result("failed")
            value["problem"][field] = replacement
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_cli(value)

    def test_read_and_plan_results_have_their_own_completed_response(self):
        value = self.result("accepted")
        for state, result in (
            ("planned", load("examples/owner-response.json")["result"]),
            ("observed", load("examples/session/info.json")),
        ):
            with self.subTest(state=state):
                value.update(state=state, result=result, complete=True, request_id=None)
                validate_cli(value)


class DirectOwner(unittest.TestCase):
    def test_all_declared_forms_parse(self):
        tokens = {
            "{tool}": "app-ops",
            "{uuid}": "11111111-1111-4111-8111-111111111111",
            "{id}": "demo-app",
            "{digest}": "sha256:" + "a" * 64,
            "{cursor}": "abc_123",
            "{kind}": "app",
            "{resource}": "demo-app",
        }
        for form in FORMS:
            command = " ".join(tokens.get(t, t) for t in form["tokens"])
            with self.subTest(form=form["name"]):
                self.assertEqual(parse_command(command, "app-ops")["form"], form["name"])

    def test_wrong_receiver(self):
        with self.assertRaises(ContractError):
            parse_command("host-ops info --json", "app-ops")

    def test_shell_injection(self):
        for tail in ["; id", " && id", " | id", "\nwhoami", " $(id)", " `id`", " >file"]:
            with self.subTest(tail=tail), self.assertRaises(ContractError):
                parse_command("app-ops info --json" + tail, "app-ops")

    def test_arbitrary_argv_rejected(self):
        for cmd in [
            "app-ops exec bash",
            "bash",
            "app-ops app restart demo-app --force",
            "app-ops info --role administrator",
            "app-ops plan --subject-stdin --json extra",
        ]:
            with self.subTest(cmd=cmd), self.assertRaises(ContractError):
                parse_command(cmd, "app-ops")

    def test_missing_apply_epoch(self):
        cmd = (
            "app-ops plan apply 11111111-1111-4111-8111-111111111111 --digest sha256:"
            + "a" * 64
            + " --request-id 22222222-2222-4222-8222-222222222222 --confirm --json"
        )
        with self.assertRaises(ContractError):
            parse_command(cmd, "app-ops")

    def test_bounded_parser(self):
        with self.assertRaises(ContractError):
            parse_command("a" * 5000, "app-ops")

    def test_host_cannot_use_app_grammar(self):
        with self.assertRaises(ContractError):
            parse_command("host-ops app restart demo-app --plan --json", "host-ops")


class NativeInstallationExperiment(unittest.TestCase):
    def test_hashed_local_wheel_install_without_index(self):
        # A synthetic benign package exercises pip, not a production domain-ops artifact.
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            w = r / "wheels"
            w.mkdir()
            name = "ops_fixture"
            di = "ops_fixture-0.0.1.dist-info"
            wheel = w / "ops_fixture-0.0.1-py3-none-any.whl"
            parts = {
                name + "/__init__.py": b"VALUE = 7\n",
                di + "/METADATA": b"Metadata-Version: 2.1\nName: ops-fixture\nVersion: 0.0.1\n",
                di
                + "/WHEEL": b"Wheel-Version: 1.0\nGenerator: spec-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            }
            output = io.StringIO()
            writer = csv.writer(output, lineterminator="\n")
            for path, b in parts.items():
                writer.writerow(
                    [
                        path,
                        "sha256="
                        + base64.urlsafe_b64encode(hashlib.sha256(b).digest())
                        .rstrip(b"=")
                        .decode(),
                        str(len(b)),
                    ]
                )
            writer.writerow([di + "/RECORD", "", ""])
            parts[di + "/RECORD"] = output.getvalue().encode()
            with zipfile.ZipFile(wheel, "w") as z:
                for p, b in parts.items():
                    z.writestr(p, b)
            lock = r / "lock.txt"
            lock.write_text(
                "ops-fixture==0.0.1 --hash=sha256:"
                + hashlib.sha256(wheel.read_bytes()).hexdigest()
                + "\n"
            )
            subprocess.run(
                [sys.executable, "-m", "venv", str(r / "venv")],
                check=True,
                capture_output=True,
                timeout=30,
            )
            py = str(r / "venv/bin/python")
            env = os.environ.copy()
            env.update(
                PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INDEX="1"
            )
            env.pop("PYTHONPATH", None)
            cmd = [
                py,
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--require-hashes",
                "--only-binary=:all:",
                "--no-cache-dir",
                "--find-links",
                str(w),
                "-r",
                str(lock),
            ]
            p = subprocess.run(cmd, env=env, capture_output=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr.decode())
            p = subprocess.run(
                [py, "-c", "import ops_fixture; assert ops_fixture.VALUE == 7"], env=env, timeout=10
            )
            self.assertEqual(p.returncode, 0)
            lock.write_text("ops-fixture==0.0.1 --hash=sha256:" + "0" * 64 + "\n")
            p = subprocess.run(
                [*cmd, "--force-reinstall"],
                env=env,
                capture_output=True,
                timeout=30,
            )
            self.assertNotEqual(p.returncode, 0)
