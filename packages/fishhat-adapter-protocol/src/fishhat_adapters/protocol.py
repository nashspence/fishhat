"""Bounded data validation, with installation trust supplied by the receiving owner."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

from fishhat_contracts.publication import validate_publication_intent
from fishhat_contracts.validation import ContractError, canonical, digest, validate
from referencing.exceptions import Unresolvable

from .dns import validate_changes, validate_rrsets
from .schemas import check_closed_schema, validate_configuration
from .targets import check_target_request, check_target_response

ROLES: dict[str, dict[str, dict[str, Any]]] = json.loads(
    Path(__file__).with_name("roles.json").read_text(encoding="utf-8")
)


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ContractError(code)


def runtime_binding_digest(binding: dict[str, Any]) -> str:
    """Identify an accepted runtime binding independently of its current admission fence."""
    validate("adapter.schema.json", binding, "RuntimeBinding")
    return digest({key: value for key, value in binding.items() if key != "admission_generation"})


def check_schema(schema: dict[str, Any]) -> None:
    """Reject open value boundaries and unsafe references in provider-owned schemas."""
    check_closed_schema(schema)


def check_descriptor(value: dict[str, Any]) -> None:
    validate("adapter.schema.json", value)
    check_schema(value["configuration_schema"])
    check_schema(value["component_schema"])
    check_schema(value["source_schema"])
    allowed = {role + "." + method for role in value["roles"] for method in ROLES[role]}
    require(set(value["implemented"]) <= allowed, "UNKNOWN_OPERATION")


def check_configuration(schema: dict[str, Any], value: Any, expected_digest: str) -> None:
    check_schema(schema)
    require(digest(schema) == expected_digest, "SCHEMA_IDENTITY")
    require(len(canonical(value)) <= 1048576, "CONFIGURATION_CAPACITY")
    try:
        require(validate_configuration(schema, value), "CONFIGURATION_REJECTED")
    except (RecursionError, Unresolvable):
        raise ContractError("CONFIGURATION_REJECTED") from None


def check_request(role: str, value: dict[str, Any]) -> None:
    """Check a typed payload; mutation execution additionally requires an Invocation."""
    require(role in ROLES, "UNKNOWN_CONTRACT")
    validate(role + "-adapter.schema.json", value)
    method, inputs = value["method"], value["input"]
    if method == "reconcile":
        invocation = inputs["invocation"]
        check_invocation(role, invocation)
        original = invocation["attempt"]
        require(
            original["contract"] == value["contract"]
            and original["scope"] == inputs["scope"]
            and original["method"] in ROLES[role]
            and ROLES[role][original["method"]]["effect"],
            "RECONCILIATION_IDENTITY",
        )
        return
    check_target_request(role, value)
    if role == "compute" and method in {"plan", "set-limits"}:
        _check_limits(inputs["limits"])
    if role == "dns" and method in {"plan", "publish"}:
        validate_changes(inputs["change"])
        require(inputs["scope"] == inputs["change"]["scope"], "DNS_SCOPE_IDENTITY")
    binding = _handoff_binding(role, value)
    if binding is not None:
        require(
            binding["role"] == role and binding["scope"] == inputs["scope"],
            "HANDOFF_BINDING_SCOPE",
        )
    if role == "capture" and method in {"restore", "verify"}:
        snapshot = inputs["snapshot"]
        require(
            snapshot["dataset"] == inputs["dataset"] and snapshot["producer"]["role"] == "capture",
            "SNAPSHOT_INPUT_IDENTITY",
        )
    if role == "secret-source" and method == "publish":
        validate_publication_intent(
            source=inputs["binding"],
            entry=inputs["entry"],
            version=inputs["version"],
            expected_previous=inputs["expected_previous"],
        )
    if role == "repository" and method == "publish":
        require(
            inputs["candidate"]["repository"] == inputs["repository"],
            "REPOSITORY_CANDIDATE_IDENTITY",
        )
    if role == "runtime" and method in {"observe", "inventory"}:
        barrier = inputs["barrier"]
        if barrier is not None:
            require(
                barrier["scope"] == inputs["scope"]
                and barrier["owner"]["id"] == inputs["scope"]["authority"],
                "OBSERVATION_BARRIER_SCOPE",
            )


def instance_reference(instance: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
    """Project exact enrollment identity, without granting permission or native capability."""
    validate("adapter.schema.json", instance, "Instance")
    validate("adapter.schema.json", scope, "Scope")
    return {
        "instance": instance["id"],
        "role": instance["role"],
        "installation_digest": instance["installation_digest"],
        "configuration_digest": digest(instance["configuration"]),
        "instance_generation": instance["generation"],
        "instance_digest": digest(instance),
        "scope": copy.deepcopy(scope),
    }


def check_invocation(role: str, value: dict[str, Any]) -> None:
    """Verify the owner-retained mutation closure, not authorization to dispatch it."""
    validate("adapter.schema.json", value, "Invocation")
    request, attempt = value["request"], value["attempt"]
    check_request(role, request)
    executor = attempt["executor"]
    require(
        ROLES[role][request["method"]]["effect"]
        and attempt["contract"] == request["contract"]
        and attempt["method"] == request["method"]
        and attempt["scope"] == request["input"]["scope"] == executor["scope"]
        and executor["role"] == role
        and attempt["input_digest"] == digest(request),
        "INVOCATION_IDENTITY",
    )
    binding = _handoff_binding(role, request)
    require(binding is None or binding == executor, "INVOCATION_EXECUTOR_IDENTITY")


def _handoff_binding(role: str, request: dict[str, Any]) -> dict[str, Any] | None:
    method, inputs = request["method"], request["input"]
    if role in {"service", "software"} and method != "reconcile":
        return cast(
            dict[str, Any],
            inputs["binding"] if method == "observe" else inputs["target"]["executor"],
        )
    if (role == "capture" and method in {"assess", "capture", "restore", "verify"}) or (
        role == "secret-source" and method in {"resolve", "publish"}
    ):
        return cast(dict[str, Any], inputs["binding"])
    if role == "credential-issuer":
        if method == "issue":
            return cast(dict[str, Any], inputs["issuer"])
        if method in {"renew", "revoke"}:
            return cast(dict[str, Any], inputs["lease"]["issuer"])
    if role == "repository":
        if method in {"resolve", "fetch", "publish"}:
            return cast(dict[str, Any], inputs["repository"]["binding"])
        if method == "observe":
            return cast(dict[str, Any], inputs["binding"])
    return None


def _attempt_identity(attempt: dict[str, Any]) -> dict[str, Any]:
    mutable = {"state", "certainty", "outcome", "native_task"}
    return {key: value for key, value in attempt.items() if key not in mutable}


def check_response(
    role: str,
    request: dict[str, Any],
    response: dict[str, Any],
    *,
    invocation: dict[str, Any] | None = None,
) -> None:
    check_request(role, request)
    validate(role + "-adapter.schema.json", response, "Response")
    require(
        response["contract"] == request["contract"]
        and response["method"] == request["method"]
        and response["request_digest"] == digest(request)
        and response["scope"] == request["input"]["scope"],
        "RESPONSE_IDENTITY",
    )
    require(
        response["coverage"] != "complete" or response["continuation"] is None,
        "INCOMPLETE_RESPONSE_COVERAGE",
    )
    if request["method"] == "reconcile":
        require(invocation is not None, "EFFECT_INVOCATION_REQUIRED")
        assert invocation is not None
        check_invocation(role, invocation)
        original = request["input"]["invocation"]
        require(
            _attempt_identity(invocation["attempt"]) == _attempt_identity(original["attempt"])
            and invocation["request"] == original["request"],
            "RECONCILIATION_IDENTITY",
        )
        check_result(invocation["attempt"], response["effect"])
        request = invocation["request"]
        # Recovery has the same output obligations as the original method.
        validate(
            role + "-adapter.schema.json",
            {**response, "method": request["method"], "request_digest": digest(request)},
            "Response",
        )
    elif ROLES[role][request["method"]]["effect"]:
        require(invocation is not None, "EFFECT_INVOCATION_REQUIRED")
        assert invocation is not None
        check_invocation(role, invocation)
        require(
            invocation["request"] == request,
            "RESPONSE_EFFECT_IDENTITY",
        )
        check_result(invocation["attempt"], response["effect"])
    _check_handoff_response(role, request, response)
    _check_observed_quantities(role, response["output"])
    check_target_response(role, request, response, invocation["attempt"] if invocation else None)
    if "effect" in response and _succeeded(response["effect"]):
        assert invocation is not None
        _check_success_output(role, request, response["output"], invocation["attempt"]["executor"])
        if role == "credential-issuer" and request["method"] in {"issue", "renew"}:
            _check_issued_lifetime(request, response["output"])


def _succeeded(effect: dict[str, Any]) -> bool:
    return bool(
        effect["task_state"] == "terminal"
        and effect["effect_certainty"] == "known"
        and effect["postcondition"] == "satisfied"
    )


def _check_handoff_response(role: str, request: dict[str, Any], response: dict[str, Any]) -> None:
    method, inputs, output = request["method"], request["input"], response["output"]
    if role == "secret-source" and method == "resolve":
        version = output["version"]
        require(
            response["coverage"] == ("unknown" if output["state"] == "unknown" else "complete")
            and response["continuation"] is None,
            "SECRET_RESOLUTION_COVERAGE",
        )
        require(
            version is None
            or (
                version["source"] == inputs["binding"]["instance"]
                and version["entry"] == inputs["entry"]
                and version["version"] == inputs["version"]
            ),
            "SECRET_RESOLUTION_IDENTITY",
        )
    if role == "capture" and method in {"assess", "capture", "restore", "verify"}:
        for snapshot in output["snapshots"]:
            require(snapshot["dataset"] == inputs["dataset"], "SNAPSHOT_OUTPUT_IDENTITY")
            if method in {"restore", "verify"}:
                require(snapshot == inputs["snapshot"], "SNAPSHOT_OUTPUT_IDENTITY")
            else:
                require(snapshot["producer"] == inputs["binding"], "SNAPSHOT_OUTPUT_IDENTITY")
    if role == "credential-issuer" and method in {"issue", "renew", "revoke"}:
        target = inputs if method == "issue" else inputs["lease"]
        for lease in output["leases"]:
            require(
                all(lease[key] == target[key] for key in ("issuer", "identity", "consumer"))
                and (method == "issue" or lease["lease"] == target["lease"]),
                "LEASE_RESULT_IDENTITY",
            )
    if role == "secret-source" and method == "publish":
        require(
            all(
                version["source"] == inputs["binding"]["instance"]
                and version["entry"] == inputs["entry"]
                and version["version"] == inputs["version"]
                for version in output["versions"]
            ),
            "PUBLICATION_RESULT_IDENTITY",
        )
    if role == "repository":
        _check_repository_response(request, response)
    if role == "runtime" and method in {"observe", "inventory"}:
        observation = output["observation"]
        if observation is not None:
            require(
                observation["scope"] == inputs["scope"]
                and observation["barrier"] == inputs["barrier"],
                "OBSERVATION_BARRIER_IDENTITY",
            )
            if inputs["barrier"] is not None:
                require(
                    observation["admission_generation"]
                    == inputs["barrier"]["admission_generation"],
                    "OBSERVATION_BARRIER_GENERATION",
                )


def _check_repository_response(request: dict[str, Any], response: dict[str, Any]) -> None:
    """Correlate repository observations and immutable custody with the exact request."""
    method, inputs, output = request["method"], request["input"], response["output"]
    if method == "resolve":
        resolution = output["resolution"]
        require(
            resolution["repository"] == inputs["repository"] and resolution["ref"] == inputs["ref"],
            "REPOSITORY_RESOLUTION_IDENTITY",
        )
        require(
            response["coverage"] == ("unknown" if resolution["state"] == "unknown" else "complete")
            and response["continuation"] is None,
            "REPOSITORY_RESOLUTION_COVERAGE",
        )
    elif method == "fetch":
        snapshot = output["snapshot"]
        require(
            snapshot is None
            or (
                snapshot["repository"] == inputs["repository"]
                and snapshot["commit"] == inputs["commit"]
            ),
            "REPOSITORY_FETCH_IDENTITY",
        )
    elif method == "publish":
        publication = output["publication"]
        require(
            publication is None
            or (
                publication["repository"] == inputs["repository"]
                and publication["ref"] == inputs["ref"]
                and publication["object_id"] == inputs["candidate"]["commit"]
                and publication["previous"] == inputs["expected_previous"]
                and publication["snapshot"] == inputs["candidate"]
            ),
            "REPOSITORY_PUBLICATION_IDENTITY",
        )
    elif method == "observe":
        identities: set[bytes] = set()
        for resolution in output["refs"]:
            require(
                resolution["repository"]["binding"] == inputs["binding"],
                "REPOSITORY_OBSERVATION_EXECUTOR",
            )
            identity = canonical([resolution["repository"]["canonical"], resolution["ref"]])
            require(identity not in identities, "DUPLICATE_REPOSITORY_REF")
            identities.add(identity)


def _same_set(a: list[Any], b: list[Any]) -> bool:
    return len(a) == len(b) and {canonical(item) for item in a} == {canonical(item) for item in b}


def _check_issued_lifetime(request: dict[str, Any], output: dict[str, Any]) -> None:
    """An approved lifetime is a maximum measured from native issuance/renewal.

    Historical expiry, revocation and unknown observations may have null times;
    they cannot be presented as successful bounded issuance or renewal.
    """
    leases = output["leases"]
    require(len(leases) == 1, "LEASE_RESULT_CARDINALITY")
    lease = leases[0]
    start, end = lease["valid_from"], lease["expires_at"]
    require(
        lease["validity"] == "valid" and start is not None and end is not None,
        "LEASE_LIFETIME_UNVERIFIED",
    )
    if start is None or end is None:
        return
    begin = datetime.fromisoformat(start.replace("Z", "+00:00"))
    finish = datetime.fromisoformat(end.replace("Z", "+00:00"))
    require(
        begin < finish
        and finish - begin <= timedelta(seconds=request["input"]["lifetime_seconds"]),
        "LEASE_LIFETIME_EXCEEDED",
    )


def _check_success_output(
    role: str, request: dict[str, Any], output: dict[str, Any], executor: dict[str, Any]
) -> None:
    """Bind complete, method-specific result custody to its original requested identities."""
    inputs = request["input"]
    checks: dict[str, Callable[[], bool]] = {
        "runtime": lambda: output["deployment"] == inputs["deployment"],
        "compute": lambda: (
            output["allocation"] == inputs["allocation"]
            and _same_set(output["limits"], inputs["limits"])
        ),
        "storage": lambda: (
            output["allocations"][0]["handle"] == inputs["allocation"]
            and _same_set(output["allocations"][0]["purposes"], inputs["purposes"])
            and (not inputs["hard_isolation"] or output["allocations"][0]["hard_isolation"])
            and output["allocations"][0]["capacity_bytes"] == inputs["capacity_bytes"]
            and output["allocations"][0]["capacity_inodes"] == inputs["capacity_inodes"]
        ),
        "backup": lambda: (
            output["objects"][0]["handle"] == inputs["object"]
            and output["objects"][0]["repository"] == inputs["repository"]
            and _same_set(output["objects"][0]["artifacts"], inputs["artifacts"])
        ),
        "ingress": lambda: output["serving_generation"] == inputs["generation_digest"],
        "network": lambda: output["policy_generation"] == inputs["policy_digest"],
        "dns": lambda: _same_set(
            output["rrsets"],
            [
                change["after"]
                for change in inputs["change"]["changes"]
                if change["after"] is not None
            ],
        ),
        "secret-source": lambda: all(
            item["source"] == executor["instance"]
            and item["entry"] == inputs["entry"]
            and item["version"] == inputs["version"]
            for item in output["versions"]
        ),
        "bootstrap-source": lambda: (
            output["receipt"] is not None
            and output["receipt"]["selection_digest"] == digest(inputs["selection"])
            and output["receipt"]["domain_id"] == inputs["selection"]["domain_id"]
            and output["receipt"]["source_id"] == inputs["selection"]["source_id"]
            and output["receipt"]["ref"] == inputs["selection"]["ref"]
            and output["receipt"]["commit"] == inputs["selection"]["expected_commit"]
            and output["receipt"]["destination"].startswith(
                inputs["selection"]["recovery_root"].rstrip("/") + "/"
            )
            and (
                request["method"] != "verify"
                or output["receipt"]["output_digest"] == inputs["output"]["digest"]
            )
        ),
    }
    check = checks.get(role)
    require(check is None or check(), "SUCCESS_OUTPUT_IDENTITY")


def _check_limits(limits: list[dict[str, Any]]) -> None:
    keys = [(limit["quantity"], limit["target"]) for limit in limits]
    require(len(keys) == len(set(keys)), "DUPLICATE_LIMIT")
    values = {limit["quantity"]: limit["value"] for limit in limits if limit["target"] is None}
    require(
        "memory-high" not in values
        or "memory-max" not in values
        or values["memory-high"] <= values["memory-max"],
        "INCONSISTENT_MEMORY_LIMITS",
    )


def _check_counters(counters: list[dict[str, Any]], allocation: str | None) -> None:
    keys = [(item["allocation"], item["metric"], item["target"]) for item in counters]
    require(len(keys) == len(set(keys)), "DUPLICATE_COUNTER")
    for item in counters:
        require(item["allocation"] == allocation, "COUNTER_ALLOCATION_IDENTITY")
        require(
            item["coverage"] not in {"unsupported", "unknown"} or item["value"] is None,
            "UNKNOWN_COUNTER_VALUE",
        )
        start = item["interval_start"]
        require(
            start is None
            or datetime.fromisoformat(start) < datetime.fromisoformat(item["observed_at"]),
            "COUNTER_INTERVAL",
        )


def _check_observed_quantities(role: str, output: dict[str, Any]) -> None:
    if role == "compute":
        _check_limits(output["limits"])
        _check_counters(output["counters"], output["allocation"])
        require(
            output["allocation"] is not None or not (output["counters"] or output["limits"]),
            "UNKNOWN_ALLOCATION_QUANTITIES",
        )
    if role == "storage":
        for allocation in output["allocations"]:
            _check_counters(allocation["counters"], allocation["handle"])
    if role == "dns":
        validate_rrsets(output["rrsets"])


def check_result(attempt: dict[str, Any], result: dict[str, Any]) -> None:
    validate("adapter.schema.json", attempt, "EffectAttempt")
    validate("adapter.schema.json", result, "EffectResult")
    require(
        result["attempt_id"] == attempt["attempt_id"]
        and result["input_digest"] == attempt["input_digest"],
        "RESULT_IDENTITY",
    )
    if result["acknowledgment"] == "rejected":
        require(
            result["effect_certainty"] == "none" and result["task_state"] == "terminal",
            "CONTRADICTORY_REJECTION",
        )
    if result["postcondition"] == "satisfied":
        require(result["effect_certainty"] == "known", "UNKNOWN_EFFECT_CANNOT_SUCCEED")
    if result["task_state"] == "running":
        require(result["native_task"] is not None, "MISSING_NATIVE_TASK")


class Registry:
    """A receiving owner's pinned data registry, never a package loader or permission engine."""

    def __init__(self) -> None:
        self._installations: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        self._instances: dict[str, dict[str, Any]] = {}
        self._repositories: dict[bytes, dict[str, Any]] = {}
        self._repository_targets: dict[bytes, bytes] = {}
        self._source_targets: dict[bytes, dict[str, Any]] = {}

    def install(
        self, installation: dict[str, Any], descriptor: dict[str, Any], *, owner_approved: bool
    ) -> None:
        require(owner_approved, "INSTALLATION_NOT_AUTHORIZED")
        validate("adapter.schema.json", installation, "Installation")
        check_descriptor(descriptor)
        require(
            installation["implementation"] == descriptor["id"]
            and installation["descriptor_digest"] == digest(descriptor),
            "INSTALLATION_IDENTITY",
        )
        key = installation["artifact"]["digest"]
        pair = (copy.deepcopy(installation), copy.deepcopy(descriptor))
        require(
            key not in self._installations or self._installations[key] == pair,
            "IMMUTABLE_INSTALLATION_CONFLICT",
        )
        self._installations[key] = pair

    def enroll(self, instance: dict[str, Any], *, owner_approved: bool) -> None:
        require(owner_approved, "INSTANCE_NOT_AUTHORIZED")
        validate("adapter.schema.json", instance, "Instance")
        pair = self._installations.get(instance["installation_digest"])
        require(pair is not None, "UNINSTALLED_ADAPTER")
        assert pair is not None
        installation, descriptor = pair
        require(
            installation["enabled"]
            and instance["implementation"] == descriptor["id"]
            and instance["role"] in descriptor["roles"],
            "INSTANCE_BINDING",
        )
        check_configuration(
            descriptor["configuration_schema"], instance["configuration"], instance["schema_digest"]
        )
        scopes = [digest(x["scope"]) for x in instance["grants"]]
        require(len(scopes) == len(set(scopes)), "DUPLICATE_SCOPE")
        previous = self._instances.get(instance["id"])
        require(previous is None or previous == instance, "EXPLICIT_REBIND_REQUIRED")
        self._check_mutation_authority(instance)
        self._instances[instance["id"]] = copy.deepcopy(instance)

    @staticmethod
    def _repository_key(reference: dict[str, Any]) -> bytes:
        repository = reference["canonical"]
        return canonical(
            [reference["binding"]["scope"], repository["instance"], repository["repository_id"]]
        )

    def enroll_repository(self, reference: dict[str, Any], *, owner_approved: bool) -> None:
        """Retain an independently approved provider mapping; no native lookup is performed."""
        require(owner_approved, "REPOSITORY_MAPPING_NOT_AUTHORIZED")
        validate("repository-adapter.schema.json", reference, "RepositoryReference")
        binding = reference["binding"]
        instance = self.inspect_instance(binding["instance"])
        self._grant(instance, binding["scope"], "observe")
        require(
            binding == instance_reference(instance, binding["scope"]),
            "HANDOFF_INSTANCE_IDENTITY",
        )
        key = self._repository_key(reference)
        previous = self._repositories.get(key)
        require(previous is None or previous == reference, "EXPLICIT_REPOSITORY_REBIND_REQUIRED")
        target = canonical([binding, reference["provider_handle"]])
        require(
            target not in self._repository_targets or self._repository_targets[target] == key,
            "REPOSITORY_MAPPING_ALIAS",
        )
        self._repositories[key] = copy.deepcopy(reference)
        self._repository_targets[target] = key

    def _check_repository_mapping(self, reference: dict[str, Any]) -> None:
        require(
            self._repositories.get(self._repository_key(reference)) == reference,
            "UNAPPROVED_REPOSITORY_MAPPING",
        )

    @staticmethod
    def _source_target_key(selection: dict[str, Any], role: str, scope: dict[str, Any]) -> bytes:
        return canonical([selection, role, scope])

    def enroll_source_target(self, target: dict[str, Any], *, owner_approved: bool) -> None:
        """Retain an independently verified native target mapping, not source authority."""
        require(owner_approved, "SOURCE_TARGET_MAPPING_NOT_AUTHORIZED")
        validate("adapter.schema.json", target, "SourceTargetBinding")
        selection, executor = target["selection"], target["executor"]
        role, scope = executor["role"], executor["scope"]
        require(role in {"service", "software"}, "SOURCE_TARGET_ROLE")
        instance = self.resolve_source(selection, role, scope)
        require(executor == instance_reference(instance, scope), "HANDOFF_INSTANCE_IDENTITY")
        grant = self._grant(instance, scope, "change")
        require(target["namespace"] in grant["mutation"]["namespaces"], "SOURCE_TARGET_NAMESPACE")
        key = self._source_target_key(selection, role, scope)
        previous = self._source_targets.get(key)
        require(previous is None or previous == target, "EXPLICIT_SOURCE_TARGET_REBIND_REQUIRED")
        self._source_targets[key] = copy.deepcopy(target)

    def source_target(
        self, selection: dict[str, Any], role: str, scope: dict[str, Any]
    ) -> dict[str, Any]:
        """Read the independently approved exact target; this does not authorize dispatch."""
        self.resolve_source(selection, role, scope)
        target = self._source_targets.get(self._source_target_key(selection, role, scope))
        require(target is not None, "UNAPPROVED_SOURCE_TARGET_MAPPING")
        assert target is not None
        return copy.deepcopy(target)

    def _check_source_target_mapping(self, role: str, request: dict[str, Any]) -> None:
        inputs = request["input"]
        if role in {"service", "software"} and "target" in inputs:
            target = inputs["target"]
            require(
                self.source_target(target["selection"], role, inputs["scope"]) == target,
                "SOURCE_TARGET_MAPPING_IDENTITY",
            )

    def resolve_host_targets(self, host: dict[str, Any]) -> list[dict[str, Any]]:
        """Join host declarations to approved selectors and reject aliased native writers.

        This read-only resolution grants no native dispatch permission. The owner
        separately validates the complete source and rechecks current permissions,
        target identity, side effects and exclusion at mutation or notification.
        """
        validate("source.schema.json", host, "Host")
        resolved: list[dict[str, Any]] = []
        namespaces: set[bytes] = set()
        for concern in host["concerns"].values():
            for kind, role in (("services", "service"), ("packages", "software")):
                for declaration in concern[kind].values():
                    selection, scope = declaration["adapter"], declaration["scope"]
                    instance = self.resolve_source(selection, role, scope)
                    require(
                        host["adapter_instances"].get(instance["id"]) == instance,
                        "SOURCE_INSTANCE_REBIND_REQUIRED",
                    )
                    key = self._source_target_key(selection, role, scope)
                    target = self._source_targets.get(key)
                    require(target is not None, "UNAPPROVED_SOURCE_TARGET_MAPPING")
                    assert target is not None
                    require(
                        target["executor"] == instance_reference(instance, scope),
                        "HANDOFF_INSTANCE_IDENTITY",
                    )
                    namespace = canonical(target["namespace"])
                    require(namespace not in namespaces, "DUPLICATE_NATIVE_SOURCE_TARGET")
                    namespaces.add(namespace)
                    resolved.append(copy.deepcopy(target))
        return resolved

    def _check_mutation_authority(self, instance: dict[str, Any]) -> None:
        """Scan local enrolled facts; native admission still owns alias resolution/exclusion."""
        claims = {
            digest(namespace): (grant["scope"], grant["mutation"]["controller"])
            for old in self._instances.values()
            if old["id"] != instance["id"]
            for grant in old["grants"]
            if grant["mutation"] is not None
            for namespace in grant["mutation"]["namespaces"]
        }
        for grant in instance["grants"]:
            mutation = grant["mutation"]
            if mutation is None:
                continue
            namespaces = {digest(value) for value in mutation["namespaces"]}
            controller = mutation["controller"]
            if controller != instance["id"]:
                controlling = self._instances.get(controller)
                require(controlling is not None, "UNKNOWN_MUTATION_CONTROLLER")
                assert controlling is not None
                controlling_grant = self._grant(controlling, grant["scope"], "change")
                controlling_mutation = controlling_grant["mutation"]
                require(
                    controlling_mutation["controller"] == controller
                    and namespaces <= {digest(n) for n in controlling_mutation["namespaces"]},
                    "MUTATION_DELEGATION_SCOPE",
                )
            identity = (grant["scope"], controller)
            for namespace in namespaces:
                require(
                    namespace not in claims or claims[namespace] == identity,
                    "NATIVE_MUTATION_AUTHORITY_CONFLICT",
                )
                claims[namespace] = identity

    @staticmethod
    def _grant(instance: dict[str, Any], scope: dict[str, Any], access: str) -> dict[str, Any]:
        grant = next(
            (g for g in instance["grants"] if g["scope"] == scope and access in g["access"]),
            None,
        )
        require(grant is not None, "SCOPE_NOT_GRANTED")
        assert grant is not None
        return cast(dict[str, Any], grant)

    def inspect_instance(self, instance_id: str) -> dict[str, Any]:
        instance = self._instances.get(instance_id)
        require(instance is not None, "UNENROLLED_ADAPTER")
        assert instance is not None
        return copy.deepcopy(instance)

    def resolve(self, selection: dict[str, Any], components: dict[str, Any]) -> dict[str, Any]:
        validate("adapter.schema.json", selection, "Selection")
        instance = self._instances.get(selection["instance"])
        require(instance is not None, "UNENROLLED_ADAPTER")
        assert instance is not None
        _, descriptor = self._installations[instance["installation_digest"]]
        require(instance["role"] == "runtime", "INSTANCE_ROLE")
        check_configuration(
            descriptor["source_schema"], selection["source"], selection["source_schema_digest"]
        )
        for component in components.values():
            check_configuration(
                descriptor["component_schema"],
                component["native"],
                digest(descriptor["component_schema"]),
            )
        selectors = [canonical(x["native"]) for x in components.values()]
        require(len(set(selectors)) == len(selectors), "DUPLICATE_COMPONENT")
        return copy.deepcopy(instance)

    def resolve_source(
        self, selection: dict[str, Any], role: str, scope: dict[str, Any]
    ) -> dict[str, Any]:
        """Resolve approved source selection without enrollment, reconfiguration or execution."""
        validate("adapter.schema.json", selection, "Selection")
        validate("adapter.schema.json", scope, "Scope")
        require(role in ROLES, "UNKNOWN_CONTRACT")
        instance = self._instances.get(selection["instance"])
        require(instance is not None and instance["role"] == role, "INSTANCE_ROLE")
        assert instance is not None
        self._grant(instance, scope, "observe")
        _, descriptor = self._installations[instance["installation_digest"]]
        check_configuration(
            descriptor["source_schema"], selection["source"], selection["source_schema_digest"]
        )
        return copy.deepcopy(instance)

    def authorize_request(
        self,
        instance_id: str,
        role: str,
        request: dict[str, Any],
        *,
        owner_approved: bool,
        invocation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Authorize observation; reconciliation also needs independently retained invocation data."""
        check_request(role, request)
        require(not ROLES[role][request["method"]]["effect"], "EFFECT_INVOCATION_REQUIRED")
        instance = self.authorize(
            instance_id,
            role,
            request["method"],
            request["input"]["scope"],
            owner_approved=owner_approved,
        )
        if request["method"] == "reconcile":
            require(invocation is not None, "EFFECT_INVOCATION_REQUIRED")
            assert invocation is not None
            check_invocation(role, invocation)
            original = request["input"]["invocation"]
            require(
                _attempt_identity(original["attempt"]) == _attempt_identity(invocation["attempt"])
                and original["request"] == invocation["request"],
                "RECONCILIATION_IDENTITY",
            )
            require(
                invocation["attempt"]["executor"]
                == instance_reference(instance, request["input"]["scope"]),
                "RECONCILIATION_INSTANCE_IDENTITY",
            )
        binding = _handoff_binding(role, request)
        if binding is not None:
            require(
                binding == instance_reference(instance, request["input"]["scope"]),
                "HANDOFF_INSTANCE_IDENTITY",
            )
        if role == "repository":
            original = (
                request["input"]["invocation"]["request"]
                if request["method"] == "reconcile"
                else request
            )
            if original["method"] in {"resolve", "fetch", "publish"}:
                self._check_repository_mapping(original["input"]["repository"])
        original = (
            request["input"]["invocation"]["request"]
            if request["method"] == "reconcile"
            else request
        )
        self._check_source_target_mapping(role, original)
        return instance

    def authorize_invocation(
        self,
        role: str,
        invocation: dict[str, Any],
        *,
        owner_approved: bool,
    ) -> dict[str, Any]:
        """Check an owner-authored mutation closure; native dispatch remains owner-controlled."""
        check_invocation(role, invocation)
        request, attempt = invocation["request"], invocation["attempt"]
        require(
            attempt["state"] == "dispatched"
            and attempt["certainty"] == "unknown"
            and attempt["outcome"] == "pending",
            "INVOCATION_NOT_DISPATCHABLE",
        )
        instance = self.authorize(
            attempt["executor"]["instance"],
            role,
            request["method"],
            request["input"]["scope"],
            owner_approved=owner_approved,
        )
        require(
            attempt["executor"] == instance_reference(instance, request["input"]["scope"]),
            "HANDOFF_INSTANCE_IDENTITY",
        )
        if role == "repository":
            self._check_repository_mapping(request["input"]["repository"])
        self._check_source_target_mapping(role, request)
        return instance

    def authorize(
        self,
        instance_id: str,
        role: str,
        method: str,
        scope: dict[str, Any],
        *,
        owner_approved: bool,
    ) -> dict[str, Any]:
        """Check current enrollment permissions only, never release executable input bytes."""
        require(owner_approved, "OPERATION_NOT_AUTHORIZED")
        instance = self._operation(instance_id, role, method, scope)
        if ROLES[role][method]["effect"]:
            require(
                self._grant(instance, scope, "change")["mutation"]["controller"] == instance_id,
                "MUTATION_OWNER_REQUIRED",
            )
        return copy.deepcopy(instance)

    def inspect_delegation(
        self, controller: str, instance_id: str, role: str, method: str, scope: dict[str, Any]
    ) -> dict[str, Any]:
        """Resolve enrollment data for an owning coordinator; this does not authorize dispatch."""
        instance = self._operation(instance_id, role, method, scope)
        require(ROLES[role][method]["effect"], "REQUEST_IS_NOT_EFFECT")
        mutation = self._grant(instance, scope, "change")["mutation"]
        require(
            controller != instance_id and mutation["controller"] == controller,
            "MUTATION_DELEGATION_SCOPE",
        )
        return copy.deepcopy(instance)

    def _operation(
        self, instance_id: str, role: str, method: str, scope: dict[str, Any]
    ) -> dict[str, Any]:
        require(role in ROLES and method in ROLES[role], "UNKNOWN_OPERATION")
        instance = self._instances.get(instance_id)
        require(instance is not None and instance["role"] == role, "INSTANCE_ROLE")
        assert instance is not None
        access = "change" if ROLES[role][method]["effect"] else "observe"
        self._grant(instance, scope, access)
        _, descriptor = self._installations[instance["installation_digest"]]
        require(role + "." + method in descriptor["implemented"], "NATIVE_EXECUTOR_UNIMPLEMENTED")
        return instance


def require_qualification(
    value: dict[str, Any],
    *,
    expected: dict[str, str],
    required_cases: set[str],
    trusted_runner: str,
) -> None:
    """Validate evidence already authenticated by the owner; data cannot authenticate itself."""
    validate("adapter.schema.json", value, "Qualification")
    require(
        set(expected)
        == {"installation_digest", "contract_digest", "configuration_digest", "environment_digest"},
        "QUALIFICATION_BINDING",
    )
    require(
        all(value[k] == v for k, v in expected.items()) and value["runner"] == trusted_runner,
        "QUALIFICATION_IDENTITY",
    )
    cases = {case["id"]: case["outcome"] for case in value["cases"]}
    require(len(cases) == len(value["cases"]), "DUPLICATE_QUALIFICATION_CASE")
    require(bool(required_cases) and required_cases <= cases.keys(), "MISSING_QUALIFICATION_CASE")
    require(all(cases[k] == "passed" for k in required_cases), "UNQUALIFIED_NATIVE_BEHAVIOR")
