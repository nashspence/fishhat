"""Bounded data validation, with installation trust supplied by the receiving owner."""

from __future__ import annotations

import copy
from typing import Any, cast

from fishhat_contracts.adapter_semantics import (
    ROLES,
    _attempt_identity,
    _handoff_binding,
    check_invocation,
    check_request,
)
from fishhat_contracts.bounds import Bounds, bounds
from fishhat_contracts.validation import ContractError, canonical, digest, validate
from referencing.exceptions import Unresolvable

from .schemas import check_closed_schema, validate_configuration


def _api_bounds(name: str, *, registry: bool = False) -> Bounds:
    proof = "tests/test_export_growth.py::test_" + (
        "registry_exports_linear_work" if registry else "adapter_exports_linear_work"
    )
    return Bounds(
        id="adapters." + name,
        work="O(B + R) current complete input bytes and selected retained registry records",
        extent="Whole configuration, grants, selections and evidence; no list truncation",
        limits=(),
        capacity=(
            "Existing provider schema and configuration byte/work capacities reject explicitly",
        ),
        proofs=(proof,),
        linear_proofs=(proof,),
    )


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ContractError(code)


@bounds(_api_bounds("runtime_binding_digest"))
def runtime_binding_digest(binding: dict[str, Any]) -> str:
    """Identify an accepted runtime binding independently of its current admission fence."""
    validate("adapter.schema.json", binding, "RuntimeBinding")
    return digest({key: value for key, value in binding.items() if key != "admission_generation"})


@bounds(_api_bounds("check_schema"))
def check_schema(schema: dict[str, Any]) -> None:
    """Reject open value boundaries and unsafe references in provider-owned schemas."""
    check_closed_schema(schema)


@bounds(_api_bounds("check_descriptor"))
def check_descriptor(value: dict[str, Any]) -> None:
    validate("adapter.schema.json", value)
    check_schema(value["configuration_schema"])
    check_schema(value["component_schema"])
    check_schema(value["source_schema"])
    allowed = {role + "." + method for role in value["roles"] for method in ROLES[role]}
    require(set(value["implemented"]) <= allowed, "UNKNOWN_OPERATION")
    for role in value["roles"]:
        if any(
            ROLES[role][method]["effect"] and role + "." + method in value["implemented"]
            for method in ROLES[role]
        ):
            require(role + ".reconcile" in value["implemented"], "MISSING_RECONCILIATION_METHOD")


@bounds(_api_bounds("check_configuration"))
def check_configuration(schema: dict[str, Any], value: Any, expected_digest: str) -> None:
    check_schema(schema)
    require(digest(schema) == expected_digest, "SCHEMA_IDENTITY")
    require(len(canonical(value)) <= 1048576, "CONFIGURATION_CAPACITY")
    try:
        require(validate_configuration(schema, value), "CONFIGURATION_REJECTED")
    except (RecursionError, Unresolvable):
        raise ContractError("CONFIGURATION_REJECTED") from None


@bounds(_api_bounds("instance_reference"))
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


class Registry:
    """A receiving owner's pinned data registry, never a package loader or permission engine."""

    def __init__(self) -> None:
        self._installations: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        self._instances: dict[str, dict[str, Any]] = {}
        self._repositories: dict[bytes, dict[str, Any]] = {}
        self._repository_targets: dict[bytes, bytes] = {}
        self._source_targets: dict[bytes, dict[str, Any]] = {}

    @bounds(_api_bounds("Registry.install", registry=True))
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

    @bounds(_api_bounds("Registry.enroll", registry=True))
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

    @bounds(_api_bounds("Registry.enroll_repository", registry=True))
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

    def _check_bootstrap_binding(
        self, role: str, request: dict[str, Any], instance: dict[str, Any]
    ) -> None:
        """Join pinned recovery selection to independently loaded installation records."""
        if role != "bootstrap-source":
            return
        selected = request["input"]["selection"]["adapter"]
        installation, descriptor = self._installations[instance["installation_digest"]]
        require(
            descriptor["id"] == selected["implementation"]
            and installation["artifact"]["digest"] == selected["installation_digest"]
            and installation["descriptor_digest"] == selected["descriptor_digest"]
            and digest(instance["configuration"]) == selected["configuration_digest"]
            and digest(descriptor["source_schema"]) == selected["source_schema_digest"],
            "BOOTSTRAP_BINDING_IDENTITY",
        )

    @staticmethod
    def _source_target_key(selection: dict[str, Any], role: str, scope: dict[str, Any]) -> bytes:
        return canonical([selection, role, scope])

    @bounds(_api_bounds("Registry.enroll_source_target", registry=True))
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

    @bounds(_api_bounds("Registry.source_target", registry=True))
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

    @bounds(_api_bounds("Registry.resolve_host_targets", registry=True))
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

    @bounds(_api_bounds("Registry.inspect_instance", registry=True))
    def inspect_instance(self, instance_id: str) -> dict[str, Any]:
        instance = self._instances.get(instance_id)
        require(instance is not None, "UNENROLLED_ADAPTER")
        assert instance is not None
        return copy.deepcopy(instance)

    @bounds(_api_bounds("Registry.resolve", registry=True))
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

    @bounds(_api_bounds("Registry.resolve_source", registry=True))
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

    @bounds(_api_bounds("Registry.authorize_request", registry=True))
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
        self._check_bootstrap_binding(role, original, instance)
        return instance

    @bounds(_api_bounds("Registry.authorize_invocation", registry=True))
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
        self._check_bootstrap_binding(role, request, instance)
        return instance

    @bounds(_api_bounds("Registry.authorize", registry=True))
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

    @bounds(_api_bounds("Registry.inspect_delegation", registry=True))
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
        if ROLES[role][method]["effect"]:
            # The accepted instance identity includes grants. Admit a mutation
            # only when this same executor can inspect its uncertain outcome.
            require(
                role + ".reconcile" in descriptor["implemented"], "MISSING_RECONCILIATION_METHOD"
            )
            self._grant(instance, scope, "observe")
        return instance


@bounds(_api_bounds("require_qualification"))
def require_qualification(
    value: dict[str, Any],
    *,
    expected: dict[str, str],
    implemented: set[str],
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
    require(bool(required_cases), "MISSING_QUALIFICATION_CASE")
    methods = {
        role + "." + method: (role, method, semantics)
        for role, role_methods in ROLES.items()
        for method, semantics in role_methods.items()
    }
    require(implemented <= methods.keys(), "UNKNOWN_OPERATION")
    reconciliation = set()
    for name in implemented:
        role, method, semantics = methods[name]
        if semantics["effect"]:
            require(role + ".reconcile" in implemented, "MISSING_RECONCILIATION_METHOD")
            reconciliation.add("reconcile-" + role + "-" + method)
    required_cases = required_cases | {"linear-growth", "complete-extent"} | reconciliation
    cases = {case["id"]: case["outcome"] for case in value["cases"]}
    require(len(cases) == len(value["cases"]), "DUPLICATE_QUALIFICATION_CASE")
    require(bool(required_cases) and required_cases <= cases.keys(), "MISSING_QUALIFICATION_CASE")
    require(all(cases[k] == "passed" for k in required_cases), "UNQUALIFIED_NATIVE_BEHAVIOR")
