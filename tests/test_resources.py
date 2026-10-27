"""Current synthetic resource contract tests, never native enforcement tests."""

import json
import unittest
from copy import deepcopy

from a_fishhat_podman_quadlet_runtime.commands import podman_delete_argv
from a_fishhat_systemd_cgroup_adapter.commands import systemd_compute_settings
from fishhat_contracts.resources import (
    ReservationModel,
    check_capacity,
    plan_cleanup,
    pressure,
    retained_runtime_handles,
    revalidate_cleanup,
    validate_host_resources,
    validate_requirements,
)
from fishhat_contracts.validation import ContractError, digest, strict_yaml, validate, validate_host

from tests.support import fixture_path

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resources.schema.json"
    ],
    "scope": "offline resource decision models",
    "relationship": "candidate",
    "reason": "Fixed synthetic cgroup, capacity, cleanup, pressure and retention inputs; no kernel enforcement, runtime reclamation or native restore.",
    "claims": [],
}

CHECK_OVERRIDES = {
    name: {
        **CHECK_PURPOSE,
        "authority": ["packages/fishhat-contracts/src/fishhat_contracts/resources.py#" + symbol],
        "relationship": "scoped-witness",
        "claims": ["engineering:" + identity],
    }
    for name, (identity, symbol) in {
        "HostEnvelopes::test_complete_host": ("resources.host", "validate_host_resources"),
        "Cleanup::test_missing_graph_node_blocks": ("resources.inventory", "validate_inventory"),
        "Cleanup::test_expected_candidates": ("resources.cleanup-plan", "plan_cleanup"),
    }.items()
}


def load(name):
    p = fixture_path(name)
    return strict_yaml(p.read_text()) if p.suffix == ".yaml" else json.loads(p.read_text())


NOW = "2026-10-19T12:00:00Z"


class HostEnvelopes(unittest.TestCase):
    def setUp(self):
        self.h = load("examples/host-node-a/host.yaml")
        self.a = self.h["resources"]["accounts"]["app-demo-app"]
        self.app = load("examples/demo-app/app.yaml")

    def bad(self):
        with self.assertRaises(ContractError):
            validate_host_resources(self.h)

    def test_complete_host(self):
        validate_host(self.h, load("examples/host-node-a/secrets.yaml"))

    def test_missing_resource_profile(self):
        self.h["resources"] = None
        self.bad()

    def test_platform_does_not_select_native_implementation(self):
        self.h["platform"] = "macos"
        validate_host_resources(self.h)

    def test_missing_account(self):
        self.h["app_accounts"]["demo-app"]["resource_account"] = "missing"
        self.bad()

    def test_wrong_app_login(self):
        self.a["login"] = "ordinary"
        self.bad()

    def test_duplicate_login(self):
        self.h["resources"]["accounts"]["maintainer"]["login"] = self.a["login"]
        self.bad()

    def test_root_account_refused(self):
        self.h["resources"]["accounts"]["maintainer"]["login"] = "root"
        self.bad()

    def test_user_auto_gc_disallowed(self):
        self.h["resources"]["accounts"]["maintainer"]["automatic_gc"] = True
        self.bad()

    def test_memory_high_over_max(self):
        self.a["compute"]["memory_high_bytes"] = self.a["compute"]["memory_max_bytes"] + 1
        self.bad()

    def test_tmpfs_over_memory(self):
        self.a["compute"]["tmpfs_max_bytes"] = self.a["compute"]["memory_max_bytes"]
        self.bad()

    def test_bad_pressure_hysteresis(self):
        self.h["resources"]["policy"]["clear_percent"] = 95
        self.bad()

    def test_overlap_roots(self):
        self.a["storage"]["scratch"]["root"] = self.a["storage"]["runtime"]["root"] + "/tmp"
        self.bad()

    def test_root_outside_pool(self):
        self.a["storage"]["scratch"]["root"] = "/var/tmp"
        self.bad()

    def test_path_normalization(self):
        self.a["storage"]["scratch"]["root"] = "/srv/ops//scratch"
        self.bad()

    def test_root_cannot_be_pool(self):
        self.a["storage"]["scratch"]["root"] = "/srv/ops"
        self.bad()

    def test_shared_control_pool(self):
        pool = self.h["resources"]["pools"]["app-disk"]
        self.h["resources"]["control"].update(instance=pool["instance"], pool=pool["pool"])
        self.bad()

    def test_byte_overcommit(self):
        self.h["resources"]["pools"]["app-disk"]["allocation_budget_bytes"] = 1 << 30
        self.bad()

    def test_inode_overcommit(self):
        self.h["resources"]["pools"]["app-disk"]["allocation_budget_inodes"] = 1024
        self.bad()

    def test_boolean_not_quota(self):
        self.a["storage"]["runtime"]["max_bytes"] = True
        self.bad()

    def test_unknown_adapter_instance(self):
        self.h["resources"]["pools"]["app-disk"]["instance"] = "unapproved-storage"
        self.bad()

    def test_insufficient_headroom(self):
        self.a["storage"]["runtime"]["headroom_bytes"] = self.a["storage"]["runtime"]["max_bytes"]
        self.bad()

    def test_duplicate_io_device(self):
        self.a["compute"]["io_limits"] = [{"device_id": "disk", "read_bps": 1, "write_bps": 1}] * 2
        self.bad()

    def test_valid_app_minimums(self):
        validate_requirements(self.app["resources"], app=self.app, account=self.a)

    def test_minimum_memory_exceeds_ceiling(self):
        self.app["resources"]["minimum_memory_bytes"] = self.a["compute"]["memory_max_bytes"] + 1
        with self.assertRaises(ContractError):
            validate_requirements(self.app["resources"], account=self.a)

    def test_missing_host_gc_permission(self):
        self.a["automatic_gc"] = False
        with self.assertRaises(ContractError):
            validate_requirements(self.app["resources"], account=self.a)

    def test_log_total_exceeds_budget(self):
        self.app["resources"]["logs"]["max_file_bytes"] = self.a["storage"]["logs"]["max_bytes"]
        with self.assertRaises(ContractError):
            validate_requirements(self.app["resources"], app=self.app, account=self.a)

    def test_native_cpu_units(self):
        self.assertEqual(
            systemd_compute_settings(self.a["compute"])["CPUQuota"],
            str(self.a["compute"]["cpu_millis"] // 10) + "%",
        )

    def test_cpu_fraction_no_rounding(self):
        self.a["compute"]["cpu_millis"] = 1001
        self.assertEqual(systemd_compute_settings(self.a["compute"])["CPUQuota"], "100.1%")

    def test_optional_io_not_falsely_enforced(self):
        self.assertNotIn("IOWeight", systemd_compute_settings(self.a["compute"]))


class Capacity(unittest.TestCase):
    def setUp(self):
        self.s = load("examples/resources/capacity-snapshot.json")
        self.r = load("examples/resources/capacity-request.json")

    def run_check(self):
        return check_capacity(
            self.s, self.r, approved_bindings_digest=self.r["bindings_digest"], now=NOW
        )

    def test_valid_growth(self):
        self.assertTrue(self.run_check()["admissible"])

    def test_quota_bytes(self):
        self.r["growth"][0]["bytes"] = 100 << 30
        self.assertFalse(self.run_check()["admissible"])

    def test_quota_inodes(self):
        self.r["growth"][0]["inodes"] = 100000000
        self.assertFalse(self.run_check()["admissible"])

    def test_shared_pool_capacity(self):
        self.s["pools"][0]["available_bytes"] = 18 << 30
        self.assertFalse(self.run_check()["admissible"])

    def test_pool_inode_reserve(self):
        self.s["pools"][0]["available_inodes"] = 100
        self.assertFalse(self.run_check()["admissible"])

    def test_outstanding_claims(self):
        self.s["quotas"][0]["reserved_remaining_bytes"] = 5 << 30
        self.assertFalse(self.run_check()["admissible"])

    def test_stale_snapshot(self):
        self.s["observed_at"] = "2026-10-18T12:00:00Z"
        self.assertFalse(self.run_check()["admissible"])

    def test_future_snapshot(self):
        self.s["observed_at"] = "2026-10-20T12:00:00Z"
        self.assertFalse(self.run_check()["admissible"])

    def test_unknown_growth(self):
        self.r["estimate"] = "unknown"
        self.assertFalse(self.run_check()["admissible"])

    def test_bounded_prepare(self):
        self.r["estimate"] = "bounded-preparation"
        self.assertTrue(self.run_check()["admissible"])

    def test_prepare_estimate_not_live_activation(self):
        self.r["estimate"] = "bounded-preparation"
        self.r["stage"] = "activate"
        self.assertFalse(self.run_check()["admissible"])

    def test_missing_enforcement(self):
        self.s["quotas"][0]["enforced"] = False
        self.assertFalse(self.run_check()["admissible"])

    def test_missing_control_space(self):
        self.s["control_writable"] = False
        self.assertFalse(self.run_check()["admissible"])

    def test_incomplete_accounting(self):
        self.s["coverage_complete"] = False
        self.assertFalse(self.run_check()["admissible"])

    def test_wrong_pool_incarnation(self):
        self.s["quotas"][0]["storage"]["pool"]["incarnation"] = "replaced-pool"
        with self.assertRaises(ContractError):
            self.run_check()

    def test_duplicate_allocation(self):
        self.s["quotas"][1]["storage"]["handle"] = self.s["quotas"][0]["storage"]["handle"]
        with self.assertRaises(ContractError):
            self.run_check()

    def test_duplicate_growth(self):
        self.r["growth"][1] = deepcopy(self.r["growth"][0])
        with self.assertRaises(ContractError):
            self.run_check()

    def test_wrong_account(self):
        self.r["account"] = "other"
        with self.assertRaises(ContractError):
            self.run_check()

    def test_concurrent_reservation(self):
        self.s["pools"][0]["available_bytes"] = 20 << 30
        book = ReservationModel(self.s, approved_bindings_digest=self.r["bindings_digest"])
        book.reserve(self.r, now=NOW)
        other = deepcopy(self.r)
        other["operation_id"] = "00000000-0000-4000-8000-000000000009"
        with self.assertRaises(ContractError):
            book.reserve(other, now=NOW)

    def test_reservation_idempotent(self):
        book = ReservationModel(self.s, approved_bindings_digest=self.r["bindings_digest"])
        one = book.reserve(self.r, now=NOW)
        snap = deepcopy(book.snapshot)
        self.assertEqual(book.reserve(self.r, now=NOW), one)
        self.assertEqual(book.snapshot, snap)

    def test_reservation_identity_conflict(self):
        book = ReservationModel(self.s, approved_bindings_digest=self.r["bindings_digest"])
        book.reserve(self.r, now=NOW)
        self.r["growth"][0]["bytes"] += 1
        with self.assertRaises(ContractError):
            book.reserve(self.r, now=NOW)

    def test_expiry_preserves_claim(self):
        book = ReservationModel(self.s, approved_bindings_digest=self.r["bindings_digest"])
        book.reserve(self.r, now=NOW)
        snap = deepcopy(book.snapshot)
        book.timeout(self.r["operation_id"])
        self.assertEqual(book.snapshot, snap)
        self.assertEqual(book.requests[self.r["operation_id"]]["phase"], "reconciling")

    def test_release_requires_cessation(self):
        book = ReservationModel(self.s, approved_bindings_digest=self.r["bindings_digest"])
        book.reserve(self.r, now=NOW)
        with self.assertRaises(ContractError):
            book.release(self.r["operation_id"], writer_stopped=False)

    def test_released_claim_not_subtracted_twice(self):
        book = ReservationModel(self.s, approved_bindings_digest=self.r["bindings_digest"])
        book.reserve(self.r, now=NOW)
        book.release(self.r["operation_id"], writer_stopped=True)
        book.release(self.r["operation_id"], writer_stopped=True)
        self.assertEqual(book.snapshot, self.s)


class Cleanup(unittest.TestCase):
    def setUp(self):
        self.i = load("examples/resources/cleanup-inventory.json")
        self.policy = load("examples/resources/accepted-retention-policy.json")
        self.retention = load("examples/resources/retention-inventory.json")

    def plan(self):
        return plan_cleanup(
            self.i, accepted_policy=self.policy, retention_inventory=self.retention, now=NOW
        )

    def revalidate(self, plan, *, now=NOW):
        revalidate_cleanup(
            plan,
            self.i,
            accepted_policy=self.policy,
            retention_inventory=self.retention,
            now=now,
        )

    def test_expected_candidates(self):
        self.assertEqual(
            [x["kind"] for x in self.plan()["candidates"]], ["container", "scratch", "image"]
        )

    def test_accepted_inactive_retained(self):
        self.assertNotIn(
            self.i["items"][0]["handle"], [x["handle"] for x in self.plan()["candidates"]]
        )

    def test_previous_release_retained(self):
        self.assertNotIn(
            self.i["items"][1]["handle"], [x["handle"] for x in self.plan()["candidates"]]
        )

    def test_checkpoint_parent_retained(self):
        self.assertNotIn(
            self.i["items"][3]["handle"], [x["handle"] for x in self.plan()["candidates"]]
        )

    def test_stopped_container_image_retained(self):
        self.assertNotIn(
            self.i["items"][2]["handle"], [x["handle"] for x in self.plan()["candidates"]]
        )

    def test_named_volume_never_candidate(self):
        self.assertNotIn("volume", [x["kind"] for x in self.plan()["candidates"]])

    def test_missing_graph_node_blocks(self):
        self.i["items"][0]["references"] = ["sha256:" + "f" * 64]
        with self.assertRaises(ContractError):
            self.plan()

    def test_foreign_object_blocks_store(self):
        self.i["items"][5]["managed"] = False
        self.assertEqual(self.plan()["candidates"], [])

    def test_user_store_report_only(self):
        self.i["account_kind"] = "user"
        self.assertIn("USER_STORE_REPORT_ONLY", self.plan()["blocked"])

    def test_busy_store(self):
        self.i["busy"] = True
        self.assertEqual(self.plan()["candidates"], [])

    def test_uncontrolled_store(self):
        self.i["exclusive_control"] = False
        self.assertEqual(self.plan()["candidates"], [])

    def test_incomplete_store(self):
        self.i["coverage_complete"] = False
        self.assertEqual(self.plan()["candidates"], [])

    def test_control_not_durable(self):
        self.i["control_writable"] = False
        self.assertEqual(self.plan()["candidates"], [])

    def test_running_object_retained(self):
        self.i["items"][4]["running"] = True
        self.assertNotIn("container", [x["kind"] for x in self.plan()["candidates"]])

    def test_grace_period(self):
        self.i["items"][5]["last_used_at"] = "2026-10-19T11:00:00Z"
        self.assertNotIn(
            self.i["items"][5]["handle"], [x["handle"] for x in self.plan()["candidates"]]
        )

    def test_missing_producer_kept(self):
        self.i["items"][6]["producer_operation"] = None
        self.assertNotIn("scratch", [x["kind"] for x in self.plan()["candidates"]])

    def test_active_producer_retained(self):
        self.i["items"][6]["producer_state"] = "active"
        self.assertNotIn("scratch", [x["kind"] for x in self.plan()["candidates"]])

    def test_unknown_producer_retained(self):
        self.i["items"][6]["producer_state"] = "unknown"
        self.assertNotIn("scratch", [x["kind"] for x in self.plan()["candidates"]])

    def test_bounded_batch(self):
        self.i["max_objects"] = 1
        plan = self.plan()
        self.assertEqual(len(plan["candidates"]), 3)
        traversal = revalidate_cleanup(
            plan,
            self.i,
            accepted_policy=self.policy,
            retention_inventory=self.retention,
            now=NOW,
        )
        self.assertEqual([len(traversal.next_batch()) for _ in range(4)], [1, 1, 1, 0])

    def test_stale_scan_blocked(self):
        self.i["observed_at"] = "2026-10-18T12:00:00Z"
        self.assertEqual(self.plan()["candidates"], [])

    def test_revalidation(self):
        self.revalidate(self.plan())

    def test_refresh_does_not_invalidate_reviewed_cleanup_candidates(self):
        reviewed = self.plan()
        self.i["observed_at"] = "2026-10-19T12:00:01Z"
        revalidate_cleanup(
            reviewed,
            self.i,
            accepted_policy=self.policy,
            retention_inventory=self.retention,
            now="2026-10-19T12:00:02Z",
        )

    def test_confirmed_first_deletion_can_resume_without_reauthorizing_unsafe_objects(self):
        reviewed = self.plan()
        removed = reviewed["candidates"][0]["handle"]
        self.i["items"] = [item for item in self.i["items"] if item["handle"] != removed]
        self.i["generation"] += 1
        with self.assertRaisesRegex(ContractError, "without confirmed outcome"):
            self.revalidate(reviewed)
        revalidate_cleanup(
            reviewed,
            self.i,
            accepted_policy=self.policy,
            retention_inventory=self.retention,
            now=NOW,
            confirmed_removed={removed},
        )
        self.i["items"][4]["protected_by"].append("new-hold")
        with self.assertRaises(ContractError):
            revalidate_cleanup(
                reviewed,
                self.i,
                accepted_policy=self.policy,
                retention_inventory=self.retention,
                now=NOW,
                confirmed_removed={removed},
            )

    def test_cleanup_revalidates_complete_large_graph_beyond_batch_boundary(self):
        template = self.i["items"][5]
        self.i["items"].extend(
            {
                **deepcopy(template),
                "handle": "sha256:" + f"{index:064x}",
                "native_id": f"{index:064x}",
            }
            for index in range(100, 5100)
        )
        self.i["max_objects"] = 3
        reviewed = self.plan()
        self.assertEqual(len(reviewed["candidates"]), 5003)
        self.revalidate(reviewed)
        self.i["items"][-1]["references"] = [reviewed["candidates"][0]["handle"]]
        with self.assertRaisesRegex(ContractError, "candidate no longer safe"):
            self.revalidate(reviewed)
        self.i["coverage_complete"] = False
        self.assertFalse(self.plan()["candidates"])

    def test_protection_changed_after_plan(self):
        p = self.plan()
        self.i["items"][5]["protected_by"].append("new-release")
        with self.assertRaises(ContractError):
            self.revalidate(p)

    def test_native_binding_changed(self):
        p = self.plan()
        self.i["store_binding"] = "sha256:" + "b" * 64
        with self.assertRaises(ContractError):
            self.revalidate(p)

    def test_expired_plan(self):
        with self.assertRaises(ContractError):
            self.revalidate(self.plan(), now="2026-10-19T12:05:01Z")

    def test_full_id_no_cascading_image_remove(self):
        self.assertEqual(
            podman_delete_argv(self.i["items"][5])[:3], ["podman", "rmi", "--no-prune"]
        )

    def test_container_no_force_or_volumes(self):
        self.assertEqual(
            podman_delete_argv(self.i["items"][4]),
            ["podman", "rm", self.i["items"][4]["native_id"]],
        )

    def test_mutable_image_name_rejected(self):
        item = deepcopy(self.i["items"][5])
        item["native_id"] = "example:latest"
        with self.assertRaises(ContractError):
            podman_delete_argv(item)

    def test_no_arbitrary_path_command(self):
        with self.assertRaises(ContractError):
            podman_delete_argv(self.i["items"][6])

    def test_native_child_becomes_eligible_only_later(self):
        self.i["items"] = [x for x in self.i["items"] if x["kind"] != "container"]
        self.i["generation"] += 1
        self.assertIn(f"{3:064x}", [x["native_id"] for x in self.plan()["candidates"]])


class Pressure(unittest.TestCase):
    def test_normal(self):
        self.assertEqual(pressure(30, 100, 70, 10), "normal")

    def test_warning(self):
        self.assertEqual(pressure(85, 100, 15, 10), "warning")

    def test_critical_percentage(self):
        self.assertEqual(pressure(90, 100, 100, 1), "critical")

    def test_absolute_headroom(self):
        self.assertEqual(pressure(10, 100, 2, 3), "critical")

    def test_hard(self):
        self.assertEqual(pressure(101, 100, 20, 1), "hard")

    def test_hysteresis(self):
        self.assertEqual(pressure(77, 100, 23, 5, previous="critical"), "warning")

    def test_clear(self):
        self.assertEqual(pressure(74, 100, 26, 5, previous="critical"), "normal")

    def test_bool_rejected(self):
        with self.assertRaises(ContractError):
            pressure(True, 100, 20, 5)


class Retention(unittest.TestCase):
    def setUp(self):
        self.i = load("examples/resources/retention-inventory.json")
        self.policy = load("examples/resources/accepted-retention-policy.json")
        self.old = self.i["releases"][2]

    def result(self):
        return retained_runtime_handles(self.i, accepted_policy=self.policy, now=NOW)

    def approve_archive(self):
        # Owner-supplied receipt for the exact changed evidence in each synthetic case.
        self.old["cold_demotion_receipt"]["archive_digest"] = digest(self.old["archive"])

    def old_kept(self):
        self.assertIn(self.old["runtime_handles"][0], self.result()["protected_roots"])

    def test_fixture(self):
        self.assertEqual(self.result(), load("examples/resources/retention-decision.json"))

    def test_accepted_always_kept(self):
        self.assertIn(self.i["releases"][0]["runtime_handles"][0], self.result()["protected_roots"])

    def test_hot_previous_count(self):
        self.assertIn(self.i["releases"][1]["runtime_handles"][0], self.result()["protected_roots"])

    def test_age_extends_count(self):
        self.old["verified_at"] = "2026-10-18T00:00:00Z"
        self.old_kept()

    def test_hold_outweighs_archive(self):
        self.old["blocking_refs"] = ["relocation-hold"]
        self.old_kept()

    def test_missing_archive_kept(self):
        self.old["archive"] = None
        self.old["cold_demotion_receipt"] = None
        self.old_kept()

    def test_no_demotion_receipt_kept(self):
        self.old["cold_demotion_receipt"] = None
        self.old_kept()

    def test_unavailable_archive_kept(self):
        self.old["archive"]["retrievable"] = False
        self.approve_archive()
        self.old_kept()

    def test_registry_only_not_independent(self):
        self.old["archive"]["independent"] = False
        self.approve_archive()
        self.old_kept()

    def test_native_restore_missing(self):
        self.old["archive"]["native_restore_verified"] = False
        self.approve_archive()
        self.old_kept()

    def test_secret_closure_missing(self):
        self.old["archive"]["includes_secret_generations"] = False
        self.approve_archive()
        self.old_kept()

    def test_source_closure_missing(self):
        self.old["archive"]["includes_source"] = False
        self.approve_archive()
        self.old_kept()

    def test_image_closure_missing(self):
        self.old["archive"]["includes_images"] = False
        self.approve_archive()
        self.old_kept()

    def test_expired_verification(self):
        self.old["archive"]["valid_until"] = "2026-10-18T11:00:00Z"
        self.approve_archive()
        self.old_kept()

    def test_future_verification(self):
        self.old["archive"]["verified_at"] = "2026-10-20T11:00:00Z"
        self.approve_archive()
        self.old_kept()

    def test_wrong_closure(self):
        self.old["archive"]["closure_digest"] = "sha256:" + "0" * 64
        self.approve_archive()
        self.old_kept()

    def test_more_predecessors(self):
        self.policy["policy"]["prior_releases"] = 2
        self.policy["generation"] += 1
        self.i["policy_digest"] = digest(self.policy)
        self.old_kept()

    def test_incomplete_inventory_blocks(self):
        self.i["complete"] = False
        with self.assertRaises(ContractError):
            self.result()

    def test_duplicate_release(self):
        self.i["releases"].append(deepcopy(self.old))
        with self.assertRaises(ContractError):
            self.result()

    def test_ambiguous_accepted(self):
        self.old["accepted"] = True
        with self.assertRaises(ContractError):
            self.result()

    def test_invalid_evidence_not_boolean_receipt(self):
        self.old["cold_demotion_receipt"] = True
        with self.assertRaises(ContractError):
            self.result()

    def test_no_checkpoint_requirement_old_image_unpinned(self):
        self.old["recovery_required"] = False
        self.old["archive"] = None
        self.assertNotIn(self.old["runtime_handles"][0], self.result()["protected_roots"])


def test_complete_resource_report_has_no_account_or_blocker_prefix():
    report = load("examples/resources/report.json")
    account = report["accounts"][0]
    report["accounts"] = [{**deepcopy(account), "account": f"app-{i}"} for i in range(65)]
    report["accounts"][-1]["blockers"] = [f"blocked-{i}" for i in range(257)]
    validate("resource-records.schema.json", report, "ResourceReport")
    report["accounts"][-1]["coverage"] = "invalid"
    with unittest.TestCase().assertRaises(ContractError):
        validate("resource-records.schema.json", report, "ResourceReport")
