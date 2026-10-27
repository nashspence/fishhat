"""Pure resource-contract models. No cgroup, quota, Podman or filesystem mutation.

Native accounting, authenticated owner records and atomic reservation transactions
must be implemented independently. These functions do not establish enforcement.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath
from typing import Any

from fishhat_contracts.bounds import Bounds, bounds
from fishhat_contracts.json_work import lexical as _lexical
from fishhat_contracts.validation import ContractError, digest, validate

BUCKETS = ("runtime", "state", "scratch", "logs")
_VERIFIED_CLEANUP = object()


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ContractError(message)


def instant(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ContractError("invalid resource timestamp") from exc
    require(dt.tzinfo is not None, "resource timestamp lacks timezone")
    return dt


def normal_root(value: str) -> PurePosixPath:
    root = PurePosixPath(value)
    require(
        value.startswith("/")
        and str(root) == value
        and ".." not in root.parts
        and root != PurePosixPath("/"),
        "noncanonical resource root",
    )
    return root


@bounds(
    Bounds(
        id="resources.host",
        work="complete account, grant and quota-root bytes; indexed overlap detection",
        extent="all resource accounts, adapter grants and quota roots, without a count ceiling",
        limits=(),
        capacity=("receiving owner memory",),
        proofs=("tests/test_resources.py::HostEnvelopes::test_complete_host",),
        linear_proofs=("tests/test_resource_growth.py::test_host_resources_linear_work",),
    )
)
def validate_host_resources(host: dict[str, Any]) -> None:
    resources = host["resources"]
    if resources is None:
        require(not host["app_accounts"], "managed app lacks enforced resource profile")
        return
    validate("resources.schema.json", resources, "HostResources")
    pools, accounts = resources["pools"], resources["accounts"]

    allocation_grants: dict[str, set[str]] = {}

    def selection(instance_id: str, role: str, handle: str) -> None:
        instance = host["adapter_instances"].get(instance_id)
        require(
            instance is not None and instance["id"] == instance_id and instance["role"] == role,
            "unknown or mismatched resource adapter instance",
        )
        assert instance is not None
        if instance_id not in allocation_grants:
            allocation_grants[instance_id] = {
                grant["scope"]["handle"]
                for grant in instance["grants"]
                if grant["scope"]["kind"] == "allocation"
            }
        require(
            handle in allocation_grants[instance_id],
            "resource adapter lacks allocation scope",
        )

    for pool in pools.values():
        selection(pool["instance"], "storage", pool["pool"])
    control = resources["control"]
    selection(control["instance"], "storage", control["pool"])
    pool_selections = {(p["instance"], p["pool"]) for p in pools.values()}
    require(
        len(pool_selections) == len(pools),
        "duplicate pool selection",
    )
    require(
        (control["instance"], control["pool"]) not in pool_selections,
        "control and workload pool overlap",
    )
    require(
        resources["control"]["emergency_file_bytes"] < resources["control"]["reserve_bytes"],
        "emergency file consumes control reserve",
    )
    roots: dict[str, Any] = {}
    totals = {k: [0, 0] for k in pools}
    logins: set[str] = set()
    allocations: set[tuple[str, str, str]] = set()
    compute_allocations: set[tuple[str, str]] = set()
    for aid, account in accounts.items():
        require(account["login"] != "root", "root is not a managed account envelope")
        require(account["login"] not in logins, "duplicate account login")
        logins.add(account["login"])
        if account["subject_kind"] == "app":
            app_id = account["subject"]
            require(account["login"] == "app-" + app_id, "wrong app account identity")
            require(
                app_id in host["app_accounts"]
                and host["app_accounts"][app_id]["resource_account"] == aid,
                "app resource binding mismatch",
            )
        else:
            require(not account["login"].startswith("app-"), "non-app uses reserved app login")
        require(
            account["subject_kind"] != "user" or not account["automatic_gc"],
            "user store automatic cleanup prohibited",
        )
        c = account["compute"]
        selection(c["instance"], "compute", c["allocation"])
        compute_key = (c["instance"], c["allocation"])
        require(compute_key not in compute_allocations, "duplicate compute allocation")
        compute_allocations.add(compute_key)
        require(c["memory_high_bytes"] <= c["memory_max_bytes"], "memory high exceeds max")
        require(c["tmpfs_max_bytes"] < c["memory_max_bytes"], "tmpfs leaves no process memory")
        require(
            len({x["device_id"] for x in c["io_limits"]}) == len(c["io_limits"]),
            "duplicate IO device",
        )
        for bucket in BUCKETS:
            q = account["storage"][bucket]
            require(q["pool"] in pools, "unknown quota pool")
            pool = pools[q["pool"]]
            allocation = (pool["instance"], pool["pool"], q["allocation"])
            require(allocation not in allocations, "duplicate storage allocation")
            allocations.add(allocation)
            require(
                q["headroom_bytes"] < q["max_bytes"] and q["headroom_inodes"] < q["max_inodes"],
                "quota leaves no usable headroom",
            )
            path, parent = normal_root(q["root"]), normal_root(pools[q["pool"]]["mount"])
            require(
                len(path.parts) > len(parent.parts)
                and path.parts[: len(parent.parts)] == parent.parts,
                "quota root outside pool",
            )
            branch = roots
            for part in path.parts:
                require("" not in branch, "nested or duplicate quota roots")
                branch = branch.setdefault(part, {})
            require(not branch, "nested or duplicate quota roots")
            branch[""] = True
            totals[q["pool"]][0] += q["max_bytes"]
            totals[q["pool"]][1] += q["max_inodes"]
    for app_id, account in host["app_accounts"].items():
        key = account["resource_account"]
        require(
            key in accounts
            and accounts[key]["subject_kind"] == "app"
            and accounts[key]["subject"] == app_id,
            "unknown/mismatched app resource account",
        )
    for pid, pool in pools.items():
        normal_root(pool["mount"])
        for ix, unit in enumerate(("bytes", "inodes")):
            require(
                totals[pid][ix] + pool["host_reserve_" + unit] + pool["other_writers_max_" + unit]
                <= pool["allocation_budget_" + unit],
                "pool hard limits overcommitted",
            )
    p = resources["policy"]
    require(
        p["clear_percent"] < p["warning_percent"] < p["critical_percent"],
        "invalid pressure hysteresis",
    )
    require(p["gc_jitter_seconds"] < p["gc_interval_seconds"], "GC jitter exceeds interval")


def validate_requirements(
    requirements: dict[str, Any],
    *,
    app: dict[str, Any] | None = None,
    account: dict[str, Any] | None = None,
) -> None:
    validate("resources.schema.json", requirements, "AppRequirements")
    if account is not None:
        c = account["compute"]
        for need, cap in [
            ("minimum_memory_bytes", "memory_high_bytes"),
            ("minimum_cpu_millis", "cpu_millis"),
            ("minimum_tasks", "tasks_max"),
        ]:
            require(requirements[need] <= c[cap], "app minimum exceeds approved envelope")
        for key in BUCKETS:
            q, n = account["storage"][key], requirements["storage_minimum"][key]
            require(
                n["bytes"] <= q["max_bytes"] - q["headroom_bytes"]
                and n["inodes"] <= q["max_inodes"] - q["headroom_inodes"],
                "app storage minimum exceeds grant",
            )
        require(
            not requirements["automatic_gc"] or account["automatic_gc"],
            "app requests unapproved automatic cleanup",
        )
        if app is not None:
            files = max(1, len(app["components"]))
            require(
                requirements["logs"]["max_file_bytes"] * files
                < account["storage"]["logs"]["max_bytes"],
                "active logs exceed log quota",
            )


def validate_snapshot(snapshot: dict[str, Any]) -> None:
    validate("resource-records.schema.json", snapshot, "CapacitySnapshot")
    buckets = [quota["bucket"] for quota in snapshot["quotas"]]
    require(
        len(buckets) == len(BUCKETS) and set(buckets) == set(BUCKETS),
        "quota buckets must occur exactly once",
    )
    pools = {p["pool"]: p for p in snapshot["pools"]}
    require(len(pools) == len(snapshot["pools"]), "duplicate pool observation")
    domains = {p["storage"]["capacity_domain"] for p in pools.values()}
    require(len(domains) == len(pools), "duplicate pool capacity domain")
    require(
        snapshot["control_pool"]["capacity_domain"] not in domains,
        "control and workload capacity domain overlap",
    )
    allocations: set[tuple[str, str]] = set()
    for q in snapshot["quotas"]:
        require(q["pool"] in pools, "quota observation missing pool")
        p = pools[q["pool"]]
        require(
            q["storage"]["pool"] == p["storage"],
            "quota pool binding mismatch",
        )
        key = (p["storage"]["capacity_domain"], q["storage"]["handle"])
        require(key not in allocations, "duplicate allocation identity")
        allocations.add(key)
        normal_root(q["root"])


def resource_bindings_digest(snapshot: dict[str, Any]) -> str:
    """Canonical binding identity; callers must independently establish its authority."""
    validate_snapshot(snapshot)
    return digest(
        {
            "owner": snapshot["owner"],
            "account": snapshot["account"],
            "resource_generation": snapshot["resource_generation"],
            "control_pool": snapshot["control_pool"],
            "pools": _lexical(
                (
                    {key: p[key] for key in ("pool", "storage", "reserve_bytes", "reserve_inodes")}
                    for p in snapshot["pools"]
                ),
                key=lambda p: p["pool"],
            ),
            "quotas": _lexical(
                (
                    {
                        key: q[key]
                        for key in (
                            "bucket",
                            "pool",
                            "storage",
                            "root",
                            "max_bytes",
                            "max_inodes",
                            "headroom_bytes",
                            "headroom_inodes",
                        )
                    }
                    for q in snapshot["quotas"]
                ),
                key=lambda q: q["bucket"],
            ),
        }
    )


def check_capacity(
    snapshot: dict[str, Any],
    request: dict[str, Any],
    *,
    approved_bindings_digest: str,
    now: str,
    max_age_seconds: int = 30,
) -> dict[str, Any]:
    """Join counters to independent owner-approved bindings; no native guarantee."""
    validate_snapshot(snapshot)
    validate("resource-records.schema.json", request, "CapacityRequest")
    require(
        request["account"] == snapshot["account"]
        and request["resource_generation"] == snapshot["resource_generation"],
        "stale resource binding",
    )
    require(
        request["bindings_digest"]
        == approved_bindings_digest
        == resource_bindings_digest(snapshot),
        "capacity snapshot differs from approved resource bindings",
    )
    require(
        len({x["bucket"] for x in request["growth"]}) == len(request["growth"]),
        "duplicate growth bucket",
    )
    age = (instant(now) - instant(snapshot["observed_at"])).total_seconds()
    blockers: list[str] = []
    if not 0 <= age <= max_age_seconds:
        blockers.append("STALE_OR_FUTURE_ACCOUNTING")
    if not snapshot["coverage_complete"] or not snapshot["control_writable"]:
        blockers.append("ACCOUNTING_OR_CONTROL_UNAVAILABLE")
    if request["estimate"] == "unknown":
        blockers.append("UNBOUNDED_GROWTH")
    if request["estimate"] == "bounded-preparation" and request["stage"] not in (
        "prepare",
        "build",
    ):
        blockers.append("PREPARATION_IS_NOT_ACTIVATION_ESTIMATE")
    quotas = {x["bucket"]: x for x in snapshot["quotas"]}
    pools = {x["pool"]: x for x in snapshot["pools"]}
    pool_growth: dict[str, list[int]] = {}
    deficits: list[dict[str, Any]] = []
    for growth in request["growth"]:
        q = quotas[growth["bucket"]]
        if not q["enforced"]:
            blockers.append("QUOTA_ENFORCEMENT_LOST:" + growth["bucket"])
        new = pool_growth.setdefault(q["pool"], [0, 0])
        for ix, unit in enumerate(("bytes", "inodes")):
            available = (
                q["max_" + unit]
                - q["used_" + unit]
                - q["headroom_" + unit]
                - q["reserved_remaining_" + unit]
            )
            missing = max(0, growth[unit] - available)
            new[ix] += growth[unit]
            if missing:
                deficits.append(
                    {"scope": "quota", "id": growth["bucket"], "unit": unit, "shortfall": missing}
                )
    for pid, new in pool_growth.items():
        p = pools[pid]
        if not p["qualified"]:
            blockers.append("POOL_NOT_QUALIFIED:" + pid)
        for ix, unit in enumerate(("bytes", "inodes")):
            available = (
                p["available_" + unit] - p["reserve_" + unit] - p["reserved_remaining_" + unit]
            )
            missing = max(0, new[ix] - available)
            if missing:
                deficits.append({"scope": "pool", "id": pid, "unit": unit, "shortfall": missing})
    if deficits:
        blockers.append("CAPACITY_BLOCKED")
    return {
        "admissible": not blockers,
        "blockers": blockers,
        "deficits": deficits,
        "snapshot_digest": digest(snapshot),
        "request_digest": digest(request),
    }


class ReservationModel:
    """In-memory transaction model, not a durable scheduler or implementation."""

    def __init__(self, snapshot: dict[str, Any], *, approved_bindings_digest: str):
        validate_snapshot(snapshot)
        require(
            resource_bindings_digest(snapshot) == approved_bindings_digest,
            "reservation model differs from approved resource bindings",
        )
        self.snapshot = deepcopy(snapshot)
        self.approved_bindings_digest = approved_bindings_digest
        self.requests: dict[str, dict[str, Any]] = {}

    @bounds(
        Bounds(
            id="resources.reservation.reserve",
            work="complete current snapshot and request with per-call quota/pool indexes; replay in retained request bytes",
            extent="all observed pools and the four semantic quota buckets; no pool-count ceiling",
            limits=(),
            capacity=("receiving owner memory",),
            proofs=("tests/test_resource_growth.py::test_reservation_request_linear_work",),
            linear_proofs=("tests/test_resource_growth.py::test_reservation_request_linear_work",),
        )
    )
    def reserve(self, request: dict[str, Any], *, now: str) -> dict[str, Any]:
        key = request["operation_id"]
        if key in self.requests:
            require(self.requests[key]["digest"] == digest(request), "reservation replay conflict")
            return deepcopy(self.requests[key])
        decision = check_capacity(
            self.snapshot, request, approved_bindings_digest=self.approved_bindings_digest, now=now
        )
        require(decision["admissible"], "capacity reservation blocked")
        quotas = {quota["bucket"]: quota for quota in self.snapshot["quotas"]}
        pools = {pool["pool"]: pool for pool in self.snapshot["pools"]}
        for g in request["growth"]:
            q = quotas[g["bucket"]]
            p = pools[q["pool"]]
            for unit in ("bytes", "inodes"):
                q["reserved_remaining_" + unit] += g[unit]
                p["reserved_remaining_" + unit] += g[unit]
        self.requests[key] = {
            "digest": digest(request),
            "request": deepcopy(request),
            "phase": "active",
        }
        return deepcopy(self.requests[key])

    def timeout(self, key: str) -> None:
        # Timeout does not prove that a pull, capture, or native writer stopped.
        require(key in self.requests, "unknown reservation")
        if self.requests[key]["phase"] != "released":
            self.requests[key]["phase"] = "reconciling"

    @bounds(
        Bounds(
            id="resources.reservation.release",
            work="complete current bindings and retained request with fresh per-call quota/pool indexes; released replay is constant",
            extent="all observed pools and the four semantic quota buckets; exact current binding validation precedes subtraction",
            limits=(),
            capacity=("receiving owner memory",),
            proofs=("tests/test_resource_growth.py::test_reservation_request_linear_work",),
            linear_proofs=("tests/test_resource_growth.py::test_reservation_request_linear_work",),
        )
    )
    def release(self, key: str, *, writer_stopped: bool) -> None:
        require(key in self.requests, "unknown reservation")
        if self.requests[key]["phase"] == "released":
            return
        require(writer_stopped is True, "reservation release needs cessation evidence")
        require(
            resource_bindings_digest(self.snapshot)
            == self.approved_bindings_digest
            == self.requests[key]["request"]["bindings_digest"],
            "reservation release differs from approved resource bindings",
        )
        quotas = {quota["bucket"]: quota for quota in self.snapshot["quotas"]}
        pools = {pool["pool"]: pool for pool in self.snapshot["pools"]}
        for g in self.requests[key]["request"]["growth"]:
            q = quotas[g["bucket"]]
            p = pools[q["pool"]]
            for unit in ("bytes", "inodes"):
                q["reserved_remaining_" + unit] -= g[unit]
                p["reserved_remaining_" + unit] -= g[unit]
        # Production must replace the counters with fresh post-effect measurements.
        self.requests[key]["phase"] = "released"


def pressure(
    used: int,
    maximum: int,
    available: int,
    headroom: int,
    *,
    previous: str = "normal",
    warn: int = 80,
    critical: int = 90,
    clear: int = 75,
) -> str:
    for value in (used, maximum, available, headroom, warn, critical, clear):
        require(type(value) is int and value >= 0, "invalid pressure counter")
    require(maximum > 0 and clear < warn < critical < 100, "invalid pressure thresholds")
    if used >= maximum:
        return "hard"
    if available <= headroom or used * 100 >= maximum * critical:
        return "critical"
    if used * 100 >= maximum * warn:
        return "warning"
    if previous in ("warning", "critical", "hard") and used * 100 > maximum * clear:
        return "warning"
    return "normal"


@bounds(
    Bounds(
        id="resources.inventory",
        work="one complete native-object index and all reference edges",
        extent="all native inventory objects, references and protection labels",
        limits=(),
        capacity=("receiving owner memory",),
        proofs=("tests/test_resources.py::Cleanup::test_missing_graph_node_blocks",),
        linear_proofs=("tests/test_resource_growth.py::test_inventory_linear_work",),
    )
)
def validate_inventory(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    validate("resource-records.schema.json", value, "CleanupInventory")
    items = {i["handle"]: i for i in value["items"]}
    require(len(items) == len(value["items"]), "duplicate native object handle")
    require(
        len({(i["kind"], i["native_id"]) for i in value["items"]}) == len(items),
        "duplicate native object identity",
    )
    require(all(root in items for root in value["protected_roots"]), "missing protected object")
    require(
        all(reference in items for item in items.values() for reference in item["references"]),
        "incomplete reference graph",
    )
    return items


@bounds(
    Bounds(
        id="resources.cleanup-plan",
        work="complete native graph and retained-release closure, including radix ordering",
        extent="complete inventory, retention input and reviewed candidate extent across every dispatch batch",
        limits=(),
        capacity=("receiving owner memory",),
        proofs=("tests/test_resources.py::Cleanup::test_expected_candidates",),
        linear_proofs=(
            "tests/test_resource_growth.py::test_cleanup_complete_traversal_linear_work",
        ),
    )
)
def plan_cleanup(
    inventory: dict[str, Any],
    *,
    accepted_policy: dict[str, Any],
    retention_inventory: dict[str, Any],
    now: str,
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    """Derive protection from current owner inputs, then add native protections.

    The caller obtains accepted_policy and retention_inventory independently from
    the receiving owner's current state. A requester or adapter cannot supply
    replacement policy or remove retained roots through the native inventory.
    """
    items = validate_inventory(inventory)
    retention = retained_runtime_handles(
        retention_inventory,
        accepted_policy=accepted_policy,
        now=now,
    )
    require(
        inventory["owner"] == accepted_policy["owner"]
        and inventory["account"] == accepted_policy["account"]
        and inventory["policy_digest"] == retention["policy_digest"]
        and inventory["retention_inventory_digest"] == retention["inventory_digest"]
        and inventory["protection_generation"] == retention["protection_generation"],
        "cleanup retention authority changed",
    )
    require(
        all(root in items for root in retention["protected_roots"]),
        "missing retained native object",
    )
    when = instant(now)
    age = (when - instant(inventory["observed_at"])).total_seconds()
    blockers: list[str] = []
    if not 0 <= age <= accepted_policy["max_observation_age_seconds"]:
        blockers.append("STALE_INVENTORY")
    if inventory["account_kind"] == "user":
        blockers.append("USER_STORE_REPORT_ONLY")
    if not inventory["coverage_complete"] or not inventory["exclusive_control"]:
        blockers.append("INCOMPLETE_OR_SHARED_CONTROL")
    if inventory["busy"]:
        blockers.append("STORE_BUSY")
    if not inventory["control_writable"]:
        blockers.append("CONTROL_NOT_DURABLE")
    if any(not x["managed"] or x["kind"] == "unknown" for x in items.values()):
        blockers.append("UNOWNED_OR_UNKNOWN_CONTENT")
    roots = set(inventory["protected_roots"]) | set(retention["protected_roots"])
    roots |= {
        k for k, v in items.items() if v["running"] or v["protected_by"] or v["kind"] == "volume"
    }
    protected = set(roots)
    stack = list(roots)
    while stack:
        for child in items[stack.pop()]["references"]:
            if child not in protected:
                protected.add(child)
                stack.append(child)
    # Keep ancestors until the referencing native object has actually been removed.
    referenced = {r for item in items.values() for r in item["references"]}
    eligible = []
    for handle, item in items.items():
        age_item = (when - instant(item["last_used_at"])).total_seconds()
        if (
            handle in protected
            or handle in referenced
            or age_item
            < max(
                inventory["minimum_age_seconds"],
                accepted_policy["policy"]["unused_candidate_grace_seconds"],
            )
            or item["producer_operation"] is None
            or item["producer_state"] != "terminal"
            or item["kind"] in ("volume", "unknown")
        ):
            continue
        eligible.append({"handle": handle, "kind": item["kind"], "native_id": item["native_id"]})
    order = {"container": 0, "build-cache": 1, "scratch": 2, "closed-log": 3, "image": 4}
    eligible = _lexical(
        eligible,
        key=lambda item: (
            str(order[item["kind"]]) + items[item["handle"]]["last_used_at"] + "\0" + item["handle"]
        ),
    )
    result = {
        "format": "deployment-ops/resources/v1",
        "kind": "CleanupPlan",
        "owner": inventory["owner"],
        "account": inventory["account"],
        "store_binding": inventory["store_binding"],
        "inventory_digest": digest(inventory),
        "policy_digest": retention["policy_digest"],
        "retention_inventory_digest": retention["inventory_digest"],
        "retention_custody_digest": retention["custody_digest"],
        "protection_generation": retention["protection_generation"],
        "protection_digest": digest(
            {
                "policy_digest": retention["policy_digest"],
                "retention_custody_digest": retention["custody_digest"],
                "protection_generation": retention["protection_generation"],
                "protected_roots": _lexical(protected),
            }
        ),
        "generation": inventory["generation"],
        "created_at": now,
        "expires_at": (when + timedelta(seconds=ttl_seconds))
        .astimezone(UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        "max_objects": inventory["max_objects"],
        "candidates": [] if blockers else eligible,
        "blocked": blockers,
    }
    validate("resource-records.schema.json", result, "CleanupPlan")
    return result


@dataclass(frozen=True)
class CleanupCustody:
    """Current owner facts under one continuously held exclusion.

    The native owner supplies these fields independently for each attempted
    deletion and its outcome. A requester/adapter cannot mint this context.
    ``exclusion`` represents the caller's actual guard, not an authenticated
    token or a lock implemented by this pure model. Every external native,
    reference, protection, policy or durability change invalidates that guard.
    """

    owner: tuple[str, ...]
    account: str
    store_binding: str
    generation: int
    policy_digest: str
    retention_custody_digest: str
    protection_generation: int
    native_observed_at: str
    retention_observed_at: str
    exclusion: object | None
    coverage_complete: bool = True
    exclusive_control: bool = True
    busy: bool = False
    control_writable: bool = True


class CleanupTraversal:
    """Indexed reference traversal, created only by complete revalidation.

    The index is retained for the entire reviewed extent, including batches and
    retries. Current scalar custody and the exact native identity are checked
    before every attempt; a confirmed own removal advances the expected native
    generation without rescanning the graph. Unknown outcomes, lost exclusion
    and externally changed state stop this traversal. Native implementations
    must provide the actual exclusion, authenticated journal and observations.
    """

    def __init__(
        self,
        plan: dict[str, Any],
        inventory: dict[str, Any],
        retention_inventory: dict[str, Any],
        accepted_policy: dict[str, Any],
        removed: set[str],
        exclusion: object | None,
        *,
        _verified: object | None = None,
    ) -> None:
        require(_verified is _VERIFIED_CLEANUP, "cleanup traversal requires complete revalidation")
        self._custody = CleanupCustody(
            owner=tuple(inventory["owner"][key] for key in ("tool", "id", "epoch")),
            account=inventory["account"],
            store_binding=inventory["store_binding"],
            generation=inventory["generation"],
            policy_digest=plan["policy_digest"],
            retention_custody_digest=plan["retention_custody_digest"],
            protection_generation=plan["protection_generation"],
            native_observed_at=inventory["observed_at"],
            retention_observed_at=retention_inventory["observed_at"],
            exclusion=exclusion,
        )
        self._generation = inventory["generation"]
        self._candidates = {
            item["handle"]: (item["kind"], item["native_id"]) for item in plan["candidates"]
        }
        self._handles = iter(self._candidates)
        self._removed = set(removed)
        self._pending: str | None = None
        self._valid = True
        self._max_objects = min(plan["max_objects"], inventory["max_objects"])
        self._max_age = accepted_policy["max_observation_age_seconds"]
        self._expires = instant(plan["expires_at"])
        # A time-dependent cold-copy protection can expire without a generation
        # change. Conservatively stop at any retained archive validity boundary.
        for release in retention_inventory["releases"]:
            if release["archive"] is not None:
                expiry = instant(release["archive"]["valid_until"])
                if expiry > instant(plan["created_at"]):
                    self._expires = min(self._expires, expiry)

    @property
    def custody(self) -> CleanupCustody:
        """Expose the immutable verified baseline; current owner facts are separate."""
        return self._custody

    def next_batch(self) -> list[dict[str, str]]:
        """Visit each reviewed candidate once; a dispatch bound never cuts extent."""
        require(self._valid, "cleanup traversal invalidated")
        result = []
        for handle in self._handles:
            if handle in self._removed:
                continue
            kind, native_id = self._candidates[handle]
            result.append({"handle": handle, "kind": kind, "native_id": native_id})
            if len(result) == self._max_objects:
                break
        return result

    def _check(self, current: CleanupCustody, now: str, generation: int) -> None:
        expected = self.custody
        require(self._valid, "cleanup traversal invalidated")
        try:
            require(
                expected.exclusion is not None and current.exclusion is expected.exclusion,
                "cleanup exclusion lost",
            )
            require(
                current.owner == expected.owner
                and current.account == expected.account
                and current.store_binding == expected.store_binding
                and type(current.generation) is int
                and 0 <= current.generation <= 9_007_199_254_740_991
                and current.generation == generation,
                "cleanup native generation or binding changed",
            )
            require(
                current.policy_digest == expected.policy_digest
                and current.retention_custody_digest == expected.retention_custody_digest
                and current.protection_generation == expected.protection_generation,
                "cleanup owner protection changed",
            )
            require(
                current.coverage_complete
                and current.exclusive_control
                and not current.busy
                and current.control_writable,
                "cleanup now blocked",
            )
            when = instant(now)
            require(when < self._expires, "cleanup plan or archive validity expired")
            require(
                all(
                    0 <= (when - instant(observed)).total_seconds() <= self._max_age
                    for observed in (current.native_observed_at, current.retention_observed_at)
                ),
                "cleanup observation stale",
            )
        except ContractError:
            self._valid = False
            raise

    def before_delete(
        self, candidate: dict[str, str], *, current: CleanupCustody, now: str
    ) -> None:
        """Check one exact observed candidate under current independently held custody."""
        self._check(current, now, self._generation)
        require(self._generation < 9_007_199_254_740_991, "cleanup native generation exhausted")
        require(self._pending is None, "cleanup outcome unresolved")
        handle = candidate["handle"]
        if handle in self._removed or self._candidates.get(handle) != (
            candidate["kind"],
            candidate["native_id"],
        ):
            self._valid = False
            raise ContractError("cleanup candidate no longer safe")
        self._pending = handle

    def record_outcome(
        self, handle: str, outcome: str, *, current: CleanupCustody, now: str
    ) -> None:
        """Consume owner-authenticated outcome evidence; uncertainty ends permission."""
        require(self._pending == handle, "unknown cleanup outcome")
        require(outcome in {"removed", "not-removed", "unknown"}, "invalid cleanup outcome")
        if outcome == "unknown":
            self._valid = False
            return
        generation = self._generation + int(outcome == "removed")
        self._check(current, now, generation)
        self._generation = generation
        if outcome == "removed":
            self._removed.add(handle)
        self._pending = None


@bounds(
    Bounds(
        id="resources.cleanup-traversal",
        work="one complete verification plus indexed candidates, batches, retries and confirmed outcomes; external invalidation stops the run",
        extent="complete native graph and retention closure plus every attempt; unchanged input is never rescanned per candidate or batch",
        limits=(),
        capacity=("receiving owner memory",),
        proofs=(
            "tests/test_cleanup_traversal.py::test_exact_custody_and_candidate_identity_are_required",
        ),
        linear_proofs=(
            "tests/test_resource_growth.py::test_cleanup_complete_traversal_linear_work",
        ),
    )
)
def revalidate_cleanup(
    plan: dict[str, Any],
    inventory: dict[str, Any],
    *,
    accepted_policy: dict[str, Any],
    retention_inventory: dict[str, Any],
    now: str,
    confirmed_removed: set[str] | None = None,
    exclusion: object | None = None,
) -> CleanupTraversal:
    """Check current bindings while the owner excludes protection changes.

    The native executor serializes this final check and each deletion with
    accepted policy, hold and recovery-reference changes. It retains that
    exclusion until the native outcome is known; otherwise it must stop and
    reconcile. Returning from this pure helper creates no concurrency guard.
    The owner supplies its actual held exclusion and independently current
    CleanupCustody for each use of the returned indexed traversal. Without that
    exclusion, this helper verifies a snapshot but cannot authorize an attempt.
    """
    validate("resource-records.schema.json", plan, "CleanupPlan")
    require(instant(now) < instant(plan["expires_at"]), "cleanup plan expired")
    require(
        plan["owner"] == inventory["owner"]
        and plan["store_binding"] == inventory["store_binding"]
        and plan["account"] == inventory["account"]
        and plan["generation"] <= inventory["generation"],
        "cleanup native binding changed",
    )
    # `confirmed_removed` is owner-authenticated journal evidence supplied by the
    # native caller, never a client claim. Original reviewed identity remains in
    # the plan; refreshed observation timestamps and known own deletions must not
    # invalidate every later candidate in the same plan.
    removed = set() if confirmed_removed is None else confirmed_removed
    candidates = {item["handle"]: item for item in plan["candidates"]}
    require(removed <= candidates.keys(), "unknown cleanup progress")
    present = {item["handle"] for item in inventory["items"]}
    require(not (removed & present), "completed cleanup object reappeared")
    require(
        all(handle in present or handle in removed for handle in candidates),
        "cleanup object vanished without confirmed outcome",
    )
    # This entry check consumes the complete graph once. Dispatch batches and
    # retries use its retained index, never a copy/rescan of the same snapshot.
    current = plan_cleanup(
        inventory,
        accepted_policy=accepted_policy,
        retention_inventory=retention_inventory,
        now=now,
    )
    require(not current["blocked"], "cleanup now blocked")
    require(
        all(
            plan[key] == current[key]
            for key in ("policy_digest", "retention_custody_digest", "protection_generation")
        ),
        "cleanup owner protection changed",
    )
    require(plan["protection_digest"] == current["protection_digest"], "cleanup protection changed")
    require(
        len({x["handle"] for x in plan["candidates"]}) == len(plan["candidates"]),
        "duplicate cleanup candidate handle",
    )
    require(
        {
            (x["handle"], x["kind"], x["native_id"])
            for x in plan["candidates"]
            if x["handle"] not in removed
        }
        <= {(x["handle"], x["kind"], x["native_id"]) for x in current["candidates"]},
        "cleanup candidate no longer safe",
    )
    return CleanupTraversal(
        plan,
        inventory,
        retention_inventory,
        accepted_policy,
        removed,
        exclusion,
        _verified=_VERIFIED_CLEANUP,
    )


@bounds(
    Bounds(
        id="resources.retention",
        work="complete release and runtime-handle custody; radix ordering in key bytes",
        extent="every retained release, blocking reference, runtime handle and archive receipt",
        limits=(),
        capacity=("receiving owner memory",),
        proofs=(
            "tests/test_retention_authority.py::test_keep_local_policy_cannot_be_overridden_by_demotion_receipt",
        ),
        linear_proofs=("tests/test_resource_growth.py::test_retention_linear_work",),
    )
)
def retained_runtime_handles(
    inventory: dict[str, Any],
    *,
    accepted_policy: dict[str, Any],
    now: str,
) -> dict[str, Any]:
    """Derive retention under current owner policy, never policy from a scan.

    Native owners independently load accepted_policy and authenticate custody
    evidence and cold-demotion receipts. This pure model checks their exact
    bindings; it does not authorize policy changes or authenticate provenance.
    Each release's complete reasons appear once in release_reasons, while
    handle_releases joins protected handles to those exact release identities.
    This preserves every hold without expanding handles times blocking reasons.
    """
    validate("resource-records.schema.json", accepted_policy, "AcceptedRetentionPolicy")
    validate("resource-records.schema.json", inventory, "RetentionInventory")
    policy_digest = digest(accepted_policy)
    require(
        inventory["owner"] == accepted_policy["owner"]
        and inventory["account"] == accepted_policy["account"]
        and inventory["policy_digest"] == policy_digest,
        "retention policy authority changed",
    )
    policy = accepted_policy["policy"]
    require(inventory["complete"], "incomplete retention closure")
    when = instant(now)
    require(
        0
        <= (when - instant(inventory["observed_at"])).total_seconds()
        <= accepted_policy["max_observation_age_seconds"],
        "stale retention accounting",
    )
    releases = inventory["releases"]
    require(
        len({r["release_digest"] for r in releases}) == len(releases), "duplicate release identity"
    )
    require(sum(bool(r["accepted"]) for r in releases) == 1, "one accepted release required")
    require(
        next(r["release_digest"] for r in releases if r["accepted"])
        == accepted_policy["release_digest"],
        "accepted retention release changed",
    )
    require(all(instant(r["verified_at"]) <= when for r in releases), "future release observation")
    prior = _lexical(
        (r for r in releases if not r["accepted"]),
        key=lambda r: (
            instant(r["verified_at"]).astimezone(UTC).isoformat(timespec="microseconds")
            + r["release_digest"]
        ),
    )
    prior.reverse()
    newest = {r["release_digest"] for r in prior[: policy["prior_releases"]]}
    protected: dict[str, set[str]] = {}
    release_reasons: dict[str, list[str]] = {}
    demoted: list[str] = []
    for r in releases:
        reasons = list(r["blocking_refs"])
        if r["accepted"]:
            reasons.append("accepted-target-active-or-inactive")
        if r["release_digest"] in newest:
            reasons.append("hot-predecessor-count")
        if (when - instant(r["verified_at"])).total_seconds() < policy["minimum_prior_age_seconds"]:
            reasons.append("minimum-retention-age")
        if r["recovery_required"] and not reasons:
            a = r["archive"]
            receipt = r["cold_demotion_receipt"]
            if receipt is not None:
                require(
                    receipt["owner"] == inventory["owner"]
                    and receipt["account"] == inventory["account"]
                    and receipt["policy_digest"] == policy_digest
                    and receipt["release_digest"] == r["release_digest"]
                    and receipt["archive_digest"] == digest(a)
                    and receipt["protection_generation"] == inventory["protection_generation"],
                    "cold demotion receipt binding changed",
                )
            cold = bool(
                policy["cold_archive"] == "verified-independent-archive"
                and a
                and receipt
                and a["independent"]
                and a["retrievable"]
                and a["includes_images"]
                and a["includes_source"]
                and a["includes_secret_generations"]
                and a["native_restore_verified"]
                and a["closure_digest"] == r["release_digest"]
                and instant(a["verified_at"]) <= when < instant(a["valid_until"])
            )
            if not cold:
                reasons.append("recovery-copy-still-required-locally")
            else:
                demoted.append(r["release_digest"])
        if reasons:
            release_reasons[r["release_digest"]] = _lexical(set(reasons))
            for handle in r["runtime_handles"]:
                protected.setdefault(handle, set()).add(r["release_digest"])
    return {
        "protected_roots": _lexical(protected),
        "release_reasons": release_reasons,
        "handle_releases": {key: _lexical(protected[key]) for key in _lexical(protected)},
        "cold_demoted_releases": _lexical(demoted),
        "policy_digest": policy_digest,
        "protection_generation": inventory["protection_generation"],
        "inventory_digest": digest(inventory),
        # Only the scan timestamp is observational metadata. Release ordering,
        # archive validity/evidence, holds and every authority field remain pinned.
        "custody_digest": digest(
            {key: value for key, value in inventory.items() if key != "observed_at"}
        ),
    }
