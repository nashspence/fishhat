"""Owner dispatch reference with an injected authoritative commit boundary.

This models persistence ordering, not native supervision or a separate journal.
Native observations must be authenticated and qualified by the installed owner.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any, cast
from uuid import uuid4

from fishhat_adapters import (
    ROLES,
    Registry,
    check_invocation,
    check_request,
    check_response,
    instance_reference,
    runtime_binding_digest,
)
from fishhat_contracts.validation import ContractError, canonical, digest, validate


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ContractError(code)


class AdapterCoordinator:
    def __init__(
        self,
        owner: dict[str, Any],
        registry: Registry,
        commit: Callable[[dict[str, Any]], None],
        *,
        native_exclusion: Callable[[dict[str, Any]], str | None] | None = None,
    ) -> None:
        validate("common.schema.json", owner, "Owner")
        self.registry = registry
        self.commit = commit
        # This callback is trusted supervisor context, never a request field. Its
        # identity covers one continuously held exclusion of all native writers;
        # releasing and reacquiring that exclusion must return a new identity.
        self.native_exclusion = native_exclusion
        self._poisoned = False
        self._observation_barriers: dict[str, dict[str, Any]] = {}
        self._quiescence_proofs: dict[str, dict[str, Any]] = {}
        self.state: dict[str, Any] = {
            "owner": copy.deepcopy(owner),
            "bindings": {},
            "admission": {},
            "attempts": {},
            "requests": {},
            "results": {},
            "quiescent": {},
        }

    def _publish(self, candidate: dict[str, Any]) -> None:
        require(not self._poisoned, "OWNER_COMMIT_UNCERTAIN")
        self._invalidate_observations(candidate)
        canonical(candidate)
        try:
            self.commit(copy.deepcopy(candidate))
        except Exception:
            # A failed acknowledgment can follow a successful commit. Stop all dispatch.
            self._poisoned = True
            raise
        self.state = candidate

    def _invalidate_observations(self, candidate: dict[str, Any]) -> None:
        """A changed local execution boundary invalidates its scans and clearance."""
        bindings = {**self.state["bindings"], **candidate["bindings"]}
        changed = {
            subject
            for subject in bindings
            if self.state["owner"] != candidate["owner"]
            or self.state["bindings"].get(subject) != candidate["bindings"].get(subject)
            or self.state["admission"].get(subject) != candidate["admission"].get(subject)
        }
        scopes = {canonical(binding["scope"]): subject for subject, binding in bindings.items()}
        for attempt_id in self.state["attempts"].keys() | candidate["attempts"].keys():
            if all(
                self.state[key].get(attempt_id) == candidate[key].get(attempt_id)
                for key in ("attempts", "requests", "results")
            ):
                continue
            for state in (self.state, candidate):
                attempt = state["attempts"].get(attempt_id)
                if attempt is not None and canonical(attempt["scope"]) in scopes:
                    changed.add(scopes[canonical(attempt["scope"])])
        for subject in changed:
            self._observation_barriers.pop(subject, None)
            self._quiescence_proofs.pop(subject, None)
            if subject in candidate["quiescent"]:
                candidate["quiescent"][subject] = False

    def _exclusion_identity(self, scope: dict[str, Any]) -> str:
        require(self.native_exclusion is not None, "NATIVE_EXCLUSION_REQUIRED")
        assert self.native_exclusion is not None
        identity = self.native_exclusion(copy.deepcopy(scope))
        require(identity is not None, "NATIVE_EXCLUSION_REQUIRED")
        assert identity is not None
        validate("common.schema.json", identity, "UUID")
        return identity

    def _require_drained(self, scope: dict[str, Any]) -> None:
        require(
            not any(
                attempt["scope"] == scope and attempt["state"] != "resolved"
                for attempt in self.state["attempts"].values()
            ),
            "PENDING_NATIVE_WORK",
        )

    def bind(
        self,
        binding: dict[str, Any],
        *,
        host: dict[str, Any],
        app: dict[str, Any],
        owner_approved: bool,
    ) -> None:
        require(owner_approved, "BINDING_NOT_AUTHORIZED")
        validate("adapter.schema.json", binding, "RuntimeBinding")
        subject = binding["subject"]
        require(
            binding["scope"]["kind"] == "application"
            and binding["scope"]["handle"] == subject
            and binding["scope"]["authority"] == self.state["owner"]["id"],
            "SUBJECT_SCOPE",
        )
        require(subject not in self.state["bindings"], "EXPLICIT_REBIND_REQUIRED")
        self._instance_matches(binding)
        self._source_matches(binding, host, app)
        candidate = copy.deepcopy(self.state)
        candidate["bindings"][subject] = copy.deepcopy(binding)
        candidate["admission"][subject] = False
        candidate["quiescent"][subject] = False
        self._publish(candidate)

    def _source_matches(
        self, binding: dict[str, Any], host: dict[str, Any], app: dict[str, Any]
    ) -> None:
        """Join already owner-selected sources to enrollment before accepting new work."""
        validate("source.schema.json", host, "Host")
        validate("source.schema.json", app, "App")
        assignment = host["app_accounts"].get(binding["subject"])
        require(
            app["id"] == binding["subject"]
            and assignment is not None
            and assignment["runtime_instance"] == app["runtime"]["instance"] == binding["instance"],
            "RUNTIME_SELECTION_MISMATCH",
        )
        instance = self.registry.resolve(app["runtime"], app["components"])
        require(
            host["adapter_instances"].get(binding["instance"]) == instance,
            "SOURCE_INSTANCE_REBIND_REQUIRED",
        )

    def _instance_matches(self, binding: dict[str, Any]) -> None:
        require("instance_digest" in binding, "BINDING_AUTHORITY_UNPINNED")
        instance = self.registry.inspect_instance(binding["instance"])
        require(
            instance["role"] == "runtime"
            and instance["installation_digest"] == binding["installation_digest"]
            and instance["generation"] == binding["instance_generation"]
            and digest(instance["configuration"]) == binding["configuration_digest"],
            "STALE_BINDING",
        )
        require(
            any(
                g["scope"] == binding["scope"]
                and "change" in g["access"]
                and g["mutation"]["controller"] == binding["instance"]
                for g in instance["grants"]
            ),
            "RUNTIME_MUTATION_AUTHORITY",
        )
        require(digest(instance) == binding["instance_digest"], "STALE_BINDING_AUTHORITY")

    def open_admission(self, subject: str, *, owner_approved: bool) -> None:
        require(owner_approved, "ADMISSION_NOT_AUTHORIZED")
        require(self.state["quiescent"].get(subject) is True, "QUIESCENCE_REQUIRED")
        binding = self.state["bindings"][subject]
        self._instance_matches(binding)
        self._require_drained(binding["scope"])
        proof = self._quiescence_proofs.get(subject)
        require(proof is not None, "QUIESCENCE_PROOF_REQUIRED")
        assert proof is not None
        require(
            proof["owner"] == self.state["owner"]
            and proof["scope"] == binding["scope"]
            and proof["binding_digest"] == runtime_binding_digest(binding)
            and proof["admission_generation"] == binding["admission_generation"]
            and proof["exclusion_id"] == self._exclusion_identity(binding["scope"]),
            "STALE_QUIESCENCE_PROOF",
        )
        candidate = copy.deepcopy(self.state)
        candidate["admission"][subject] = True
        candidate["quiescent"][subject] = False
        self._publish(candidate)

    def close_admission(self, subject: str) -> None:
        require(subject in self.state["bindings"], "UNKNOWN_BINDING")
        candidate = copy.deepcopy(self.state)
        candidate["admission"][subject] = False
        candidate["quiescent"][subject] = False
        candidate["bindings"][subject]["admission_generation"] += 1
        validate("adapter.schema.json", candidate["bindings"][subject], "RuntimeBinding")
        self._publish(candidate)

    def prepare(
        self,
        subject: str,
        request: dict[str, Any],
        *,
        host: dict[str, Any],
        app: dict[str, Any],
        operation_id: str,
        effect_id: str,
        attempt_id: str,
        owner_approved: bool,
    ) -> dict[str, Any]:
        require(not self._poisoned, "OWNER_COMMIT_UNCERTAIN")
        check_request("runtime", request)
        binding = self.state["bindings"].get(subject)
        require(binding is not None, "UNKNOWN_BINDING")
        assert binding is not None
        require(ROLES["runtime"][request["method"]]["effect"], "REQUEST_IS_NOT_EFFECT")
        require(request["method"] != "reconcile", "RECONCILE_ORIGINAL_ATTEMPT")
        require(request["input"].get("scope") == binding["scope"], "REQUEST_SCOPE")
        require(
            request["input"]["deployment"]["binding_digest"] == runtime_binding_digest(binding),
            "DEPLOYMENT_BINDING_IDENTITY",
        )
        self._instance_matches(binding)
        self._source_matches(binding, host, app)
        instance = self.registry.authorize(
            binding["instance"],
            "runtime",
            request["method"],
            binding["scope"],
            owner_approved=owner_approved,
        )
        return self._prepare(
            binding,
            instance,
            request,
            operation_id=operation_id,
            effect_id=effect_id,
            attempt_id=attempt_id,
        )

    def _service_instance(
        self, binding: dict[str, Any], instance_id: str, service: str
    ) -> dict[str, Any]:
        instance = self.registry.inspect_delegation(
            binding["instance"], instance_id, "service", "set-activity", binding["scope"]
        )
        grant = next(g for g in instance["grants"] if g["scope"] == binding["scope"])
        require(
            any(
                n["resource"] == service and n["facet"] == "lifecycle"
                for n in grant["mutation"]["namespaces"]
            ),
            "SERVICE_OUTSIDE_MUTATION_NAMESPACE",
        )
        return instance

    def prepare_service(
        self,
        subject: str,
        instance_id: str,
        request: dict[str, Any],
        *,
        host: dict[str, Any],
        app: dict[str, Any],
        operation_id: str,
        effect_id: str,
        attempt_id: str,
        owner_approved: bool,
    ) -> dict[str, Any]:
        """Accept a subordinate service lifecycle effect at the runtime owner's boundary."""
        require(not self._poisoned, "OWNER_COMMIT_UNCERTAIN")
        require(owner_approved, "OPERATION_NOT_AUTHORIZED")
        check_request("service", request)
        require(request["method"] == "set-activity", "UNSUPPORTED_DELEGATED_EFFECT")
        binding = self.state["bindings"].get(subject)
        require(binding is not None, "UNKNOWN_BINDING")
        assert binding is not None
        require(request["input"]["scope"] == binding["scope"], "REQUEST_SCOPE")
        self._instance_matches(binding)
        self._source_matches(binding, host, app)
        instance = self._service_instance(binding, instance_id, request["input"]["service"])
        return self._prepare(
            binding,
            instance,
            request,
            operation_id=operation_id,
            effect_id=effect_id,
            attempt_id=attempt_id,
            runtime_control={
                "binding_digest": runtime_binding_digest(binding),
                "service": request["input"]["service"],
                "activity": request["input"]["activity"],
            },
        )

    def _prepare(
        self,
        binding: dict[str, Any],
        instance: dict[str, Any],
        request: dict[str, Any],
        *,
        operation_id: str,
        effect_id: str,
        attempt_id: str,
        runtime_control: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        attempt = {
            "owner": copy.deepcopy(self.state["owner"]),
            "operation_id": operation_id,
            "effect_id": effect_id,
            "attempt_id": attempt_id,
            "executor": instance_reference(instance, binding["scope"]),
            "binding_generation": binding["generation"],
            "native_incarnation": binding["native_incarnation"],
            "contract": request["contract"],
            "method": request["method"],
            "scope": copy.deepcopy(binding["scope"]),
            "input_digest": digest(request),
            "state": "prepared",
            "certainty": "none",
            "outcome": "pending",
            "native_task": None,
        }
        if runtime_control is not None:
            attempt["runtime_control"] = runtime_control
        validate("adapter.schema.json", attempt, "EffectAttempt")
        previous = self.state["attempts"].get(attempt_id)
        if previous is not None:
            mutable = {"state", "certainty", "outcome", "native_task"}
            require(
                {key: value for key, value in previous.items() if key not in mutable}
                == {key: value for key, value in attempt.items() if key not in mutable},
                "ATTEMPT_IDENTITY_CONFLICT",
            )
            return cast(dict[str, Any], copy.deepcopy(previous))
        for old in self.state["attempts"].values():
            if old["effect_id"] == effect_id and old["operation_id"] == operation_id:
                require(old["state"] == "resolved", "UNCERTAIN_EFFECT_RETRY")
                raise ContractError("EFFECT_RETRY_REQUIRES_NEW_PLAN")
        candidate = copy.deepcopy(self.state)
        candidate["attempts"][attempt_id] = attempt
        candidate["requests"][attempt_id] = copy.deepcopy(request)
        check_invocation(instance["role"], {"attempt": attempt, "request": request})
        self._publish(candidate)
        return copy.deepcopy(attempt)

    def cancel_prepared(self, attempt_id: str, *, owner_approved: bool) -> None:
        require(owner_approved, "CANCELLATION_NOT_AUTHORIZED")
        attempt = self.state["attempts"].get(attempt_id)
        require(attempt is not None, "UNKNOWN_ATTEMPT")
        assert attempt is not None
        require(attempt["state"] == "prepared", "CANNOT_CANCEL_DISPATCHED_EFFECT")
        candidate = copy.deepcopy(self.state)
        candidate["attempts"][attempt_id].update(state="resolved", outcome="cancelled")
        self._publish(candidate)

    def dispatch(self, subject: str, attempt_id: str) -> dict[str, Any]:
        require(not self._poisoned, "OWNER_COMMIT_UNCERTAIN")
        binding = self.state["bindings"].get(subject)
        attempt = self.state["attempts"].get(attempt_id)
        require(binding is not None and attempt is not None, "UNKNOWN_ATTEMPT")
        assert binding is not None and attempt is not None
        instance, gate = self._dispatch_control(binding, attempt)
        if gate == "open":
            require(self.state["admission"][subject], "ADMISSION_CLOSED")
        elif gate == "closed":
            require(not self.state["admission"][subject], "ADMISSION_NOT_CLOSED")
        self._instance_matches(binding)
        require(
            attempt["scope"] == binding["scope"]
            and attempt["executor"] == instance_reference(instance, binding["scope"])
            and attempt["binding_generation"] == binding["generation"]
            and attempt["native_incarnation"] == binding["native_incarnation"],
            "STALE_DISPATCH",
        )
        require(attempt["state"] == "prepared", "RECONCILE_REQUIRED")
        candidate = copy.deepcopy(self.state)
        candidate["attempts"][attempt_id].update(state="dispatched", certainty="unknown")
        candidate["quiescent"][subject] = False
        self._publish(candidate)
        # Release the exact executable closure only after the owner commit has returned.
        invocation = {
            "attempt": copy.deepcopy(self.state["attempts"][attempt_id]),
            "request": copy.deepcopy(self.state["requests"][attempt_id]),
        }
        check_invocation(instance["role"], invocation)
        return invocation

    def _dispatch_control(
        self, binding: dict[str, Any], attempt: dict[str, Any]
    ) -> tuple[dict[str, Any], str]:
        if attempt["contract"] == "fishhat.runtime":
            require(
                attempt["method"] in ROLES["runtime"]
                and ROLES["runtime"][attempt["method"]]["effect"]
                and attempt["method"] != "reconcile"
                and "runtime_control" not in attempt,
                "INVALID_RUNTIME_EFFECT",
            )
            return (
                self.registry.inspect_instance(binding["instance"]),
                ROLES["runtime"][attempt["method"]]["admission"],
            )
        control = self._service_control(binding, attempt)
        instance = self._service_instance(
            binding, attempt["executor"]["instance"], control["service"]
        )
        require(
            attempt["executor"] == instance_reference(instance, binding["scope"]),
            "STALE_EXECUTOR_INSTANCE",
        )
        return (
            instance,
            "closed" if control["activity"] == "stopped" else "open",
        )

    @staticmethod
    def _service_control(binding: dict[str, Any], attempt: dict[str, Any]) -> dict[str, Any]:
        """Check retained input identity without requiring a currently available executor."""
        require(
            attempt["contract"] == "fishhat.service"
            and attempt["method"] == "set-activity"
            and "runtime_control" in attempt,
            "RUNTIME_CONTROL_REQUIRED",
        )
        control = attempt["runtime_control"]
        require(control["binding_digest"] == runtime_binding_digest(binding), "STALE_DISPATCH")
        request = {
            "contract": "fishhat.service",
            "method": "set-activity",
            "input": {
                "scope": binding["scope"],
                "service": control["service"],
                "activity": control["activity"],
            },
        }
        require(digest(request) == attempt["input_digest"], "DELEGATED_INPUT_IDENTITY")
        return cast(dict[str, Any], control)

    def settle(self, attempt_id: str, request: dict[str, Any], response: dict[str, Any]) -> None:
        """Retain complete typed response custody before resolving the original attempt."""
        attempt = self.state["attempts"].get(attempt_id)
        require(attempt is not None, "UNKNOWN_ATTEMPT")
        assert attempt is not None
        require(attempt["state"] in {"dispatched", "reconciling"}, "INVALID_SETTLEMENT")
        check_response(
            attempt["executor"]["role"],
            request,
            response,
            invocation={"attempt": attempt, "request": self.state["requests"][attempt_id]},
        )
        candidate = copy.deepcopy(self.state)
        candidate["attempts"][attempt_id].update(self._settlement(response["effect"]))
        retained = {
            "request": copy.deepcopy(request),
            "response": copy.deepcopy(response),
        }
        identity = digest(retained)
        evidence = candidate["results"].setdefault(attempt_id, {"latest": identity, "records": {}})
        evidence["records"][identity] = retained
        evidence["latest"] = identity
        self._publish(candidate)

    @staticmethod
    def _settlement(result: dict[str, Any]) -> dict[str, Any]:
        known_terminal = (
            result["task_state"] == "terminal" and result["effect_certainty"] != "unknown"
        )
        outcome = "pending"
        if known_terminal and result["postcondition"] != "unknown":
            outcome = "succeeded" if result["postcondition"] == "satisfied" else "failed"
        return {
            "state": "resolved" if outcome != "pending" else "reconciling",
            "certainty": result["effect_certainty"],
            "native_task": result["native_task"],
            "outcome": outcome,
        }

    def _check_retained_results(self, snapshot: dict[str, Any]) -> None:
        require(set(snapshot["results"]) <= set(snapshot["attempts"]), "RESTORE_RESULT_CUSTODY")
        for key, attempt in snapshot["attempts"].items():
            evidence = snapshot["results"].get(key)
            require(
                evidence is not None or attempt["outcome"] not in {"succeeded", "failed"},
                "RESTORE_RESULT_CUSTODY",
            )
            if evidence is None:
                continue
            require(
                set(evidence) == {"latest", "records"}
                and evidence["latest"] in evidence["records"],
                "RESTORE_RESULT_CUSTODY",
            )
            for identity, retained in evidence["records"].items():
                require(
                    set(retained) == {"request", "response"} and digest(retained) == identity,
                    "RESTORE_RESULT_CUSTODY",
                )
                check_response(
                    attempt["executor"]["role"],
                    retained["request"],
                    retained["response"],
                    invocation={"attempt": attempt, "request": snapshot["requests"][key]},
                )
            latest = evidence["records"][evidence["latest"]]
            require(
                all(
                    attempt[field] == value
                    for field, value in self._settlement(latest["response"]["effect"]).items()
                ),
                "RESTORE_RESULT_STATE",
            )

    def observation_request(
        self,
        subject: str,
        *,
        owner_approved: bool,
        method: str = "observe",
        limit: int = 256,
    ) -> dict[str, Any]:
        """Issue a fresh scan after draining, under independently held native exclusion.

        The nonce and resulting clearance are transient evidence, not accepted
        work. A process restart or restored state always requires a fresh scan.
        """
        require(not self._poisoned, "OWNER_COMMIT_UNCERTAIN")
        require(owner_approved, "OBSERVATION_NOT_AUTHORIZED")
        require(method in {"observe", "inventory"}, "INVALID_OBSERVATION_METHOD")
        binding = self.state["bindings"].get(subject)
        require(
            binding is not None and not self.state["admission"][subject], "ADMISSION_NOT_CLOSED"
        )
        assert binding is not None
        self._instance_matches(binding)
        self._require_drained(binding["scope"])
        barrier = {
            "id": str(uuid4()),
            "owner": copy.deepcopy(self.state["owner"]),
            "scope": copy.deepcopy(binding["scope"]),
            "binding_digest": runtime_binding_digest(binding),
            "admission_generation": binding["admission_generation"],
            "exclusion_id": self._exclusion_identity(binding["scope"]),
        }
        query = {
            "contract": "fishhat.runtime",
            "method": method,
            "input": {
                "scope": copy.deepcopy(binding["scope"]),
                "cursor": None,
                "limit": limit,
                "barrier": barrier,
            },
        }
        self.registry.authorize_request(
            binding["instance"], "runtime", query, owner_approved=owner_approved
        )
        if self.state["quiescent"][subject]:
            candidate = copy.deepcopy(self.state)
            candidate["quiescent"][subject] = False
            self._publish(candidate)
        self._quiescence_proofs.pop(subject, None)
        self._observation_barriers[subject] = copy.deepcopy(barrier)
        return query

    def prove_quiescent(
        self, subject: str, observation: dict[str, Any], *, owner_approved: bool
    ) -> None:
        """Consume one authenticated post-drain result while its exclusion remains held."""
        require(not self._poisoned, "OWNER_COMMIT_UNCERTAIN")
        require(owner_approved, "OBSERVATION_NOT_AUTHORIZED")
        validate("adapter.schema.json", observation, "Observation")
        binding = self.state["bindings"].get(subject)
        require(
            binding is not None and not self.state["admission"][subject], "ADMISSION_NOT_CLOSED"
        )
        assert binding is not None
        self._instance_matches(binding)
        self._require_drained(binding["scope"])
        require(
            observation["scope"] == binding["scope"]
            and observation["generation"] == binding["generation"]
            and observation["instance"] == binding["instance"]
            and observation["installation_digest"] == binding["installation_digest"]
            and observation["native_incarnation"] == binding["native_incarnation"]
            and observation["admission_generation"] == binding["admission_generation"],
            "OBSERVATION_IDENTITY",
        )
        barrier = self._observation_barriers.get(subject)
        require(barrier is not None, "OBSERVATION_BARRIER_REQUIRED")
        assert barrier is not None
        require(
            observation["barrier"] == barrier
            and barrier["owner"] == self.state["owner"]
            and barrier["scope"] == binding["scope"]
            and barrier["binding_digest"] == runtime_binding_digest(binding)
            and barrier["admission_generation"] == binding["admission_generation"]
            and barrier["exclusion_id"] == self._exclusion_identity(binding["scope"]),
            "STALE_OBSERVATION_BARRIER",
        )
        require(
            observation["coverage"] == "complete"
            and observation["continuation"] is None
            and observation["activity"] == "inactive"
            and observation["quiescence"] == "verified",
            "INCOMPLETE_QUIESCENCE",
        )
        candidate = copy.deepcopy(self.state)
        candidate["quiescent"][subject] = True
        self._publish(candidate)
        self._observation_barriers.pop(subject, None)
        self._quiescence_proofs[subject] = copy.deepcopy(barrier)

    def snapshot(self) -> dict[str, Any]:
        require(not self._poisoned, "OWNER_COMMIT_UNCERTAIN")
        return copy.deepcopy(self.state)

    def restore(self, snapshot: dict[str, Any]) -> None:
        """Load owner-verified state; cached observations never restore start authority."""
        self._observation_barriers.clear()
        self._quiescence_proofs.clear()
        canonical(snapshot)
        require(
            set(snapshot) == set(self.state) and snapshot["owner"] == self.state["owner"],
            "RESTORE_OWNER_IDENTITY",
        )
        scopes = {}
        for key, binding in snapshot["bindings"].items():
            validate("adapter.schema.json", binding, "RuntimeBinding")
            require(
                key == binding["subject"]
                and binding["scope"]["kind"] == "application"
                and binding["scope"]["handle"] == key
                and binding["scope"]["authority"] == snapshot["owner"]["id"],
                "RESTORE_BINDING_IDENTITY",
            )
            scopes[digest(binding["scope"])] = binding
        for key, attempt in snapshot["attempts"].items():
            validate("adapter.schema.json", attempt, "EffectAttempt")
            require(
                key == attempt["attempt_id"]
                and attempt["owner"] == snapshot["owner"]
                and digest(attempt["scope"]) in scopes,
                "RESTORE_ATTEMPT_IDENTITY",
            )
            if attempt["contract"] == "fishhat.service":
                self._service_control(scopes[digest(attempt["scope"])], attempt)
        require(
            set(snapshot["requests"]) == set(snapshot["attempts"]), "RESTORE_INVOCATION_CUSTODY"
        )
        for key, attempt in snapshot["attempts"].items():
            check_invocation(
                attempt["executor"]["role"],
                {"attempt": attempt, "request": snapshot["requests"][key]},
            )
        self._check_retained_results(snapshot)
        candidate = copy.deepcopy(snapshot)
        candidate["admission"] = {subject: False for subject in candidate["bindings"]}
        candidate["quiescent"] = {subject: False for subject in candidate["bindings"]}
        for binding in candidate["bindings"].values():
            binding["admission_generation"] += 1
            validate("adapter.schema.json", binding, "RuntimeBinding")
        self._publish(candidate)
