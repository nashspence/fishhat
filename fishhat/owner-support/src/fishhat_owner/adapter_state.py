"""Owner dispatch reference with atomic bounded commits and explicit checkpoints.

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
from fishhat_contracts.adapter_semantics import accumulate_result
from fishhat_contracts.bounds import Bounds, bounds
from fishhat_contracts.validation import ContractError, canonical, digest, validate


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ContractError(code)


class AdapterCoordinator:
    """Retain accepted work through an independently supplied atomic commit receiver.

    commit_delta receives a closed fishhat.adapter-commit/v1 envelope, never a
    replacement snapshot for ordinary work. Its exact fields are format, kind
    (delta), owner, expected_revision, revision and updates. Updates contain only
    changed entries in bindings, admission, quiescent, attempts, requests and
    results, keyed by subject or attempt ID as in the checkpoint. A result update
    contains latest, knowledge and records, with only newly appended digest-keyed
    request/response records. The receiver atomically checks its exact owner and
    expected revision, appends new requests and result records, updates only the
    selected binding/admission/attempt/result heads, and advances revision before
    acknowledging. Existing request and result bytes are immutable; result records
    merge by their digest, while latest and knowledge replace their selected head.
    Updates omit unchanged entries and never mean deletion. Native receivers must
    enforce these preconditions in the same durable transaction as the writes.

    Only explicit restore emits kind checkpoint with a complete checkpoint instead
    of updates. Its expected revision is the independently verified restored store
    head in the supplied snapshot, not permission to overwrite a newer store.
    Receivers must reject a stale revision or changed owner. Snapshot and restore
    may traverse complete retained state; ordinary work never rewrites that history.
    A failed commit acknowledgment poisons the coordinator because commit may have
    succeeded; a fresh coordinator must load independently verified durable state.
    """

    def __init__(
        self,
        owner: dict[str, Any],
        registry: Registry,
        commit_delta: Callable[[dict[str, Any]], None],
        *,
        native_exclusion: Callable[[dict[str, Any]], str | None] | None = None,
    ) -> None:
        validate("common.schema.json", owner, "Owner")
        self.registry = registry
        self.commit_delta = commit_delta
        # This callback is trusted supervisor context, never a request field. Its
        # identity covers one continuously held exclusion of all native writers;
        # releasing and reacquiring that exclusion must return a new identity.
        self.native_exclusion = native_exclusion
        self._poisoned = False
        self._observation_barriers: dict[str, dict[str, Any]] = {}
        self._quiescence_proofs: dict[str, dict[str, Any]] = {}
        self._effect_attempts: dict[tuple[str, str], str] = {}
        self._scope_subjects: dict[bytes, str] = {}
        self._pending_by_scope: dict[bytes, int] = {}
        self.state: dict[str, Any] = {
            "owner": copy.deepcopy(owner),
            "revision": 0,
            "bindings": {},
            "admission": {},
            "attempts": {},
            "requests": {},
            "results": {},
            "quiescent": {},
        }

    @bounds(
        Bounds(
            id="owner.adapter-commits",
            work=(
                "O(B) changed records and affected scope identities per atomic delta; "
                "O(sum(B)) across complete prepare/dispatch/observation/retry histories"
            ),
            extent="All exact requests and response records remain retained without history caps",
            limits=(),
            capacity=("Explicit owner storage failure poisons dispatch; no history is discarded",),
            proofs=(
                "tests/test_adapter_commit_growth.py::test_adapter_commit_history_linear_work",
            ),
            linear_proofs=(
                "tests/test_adapter_commit_growth.py::test_adapter_commit_history_linear_work",
            ),
        )
    )
    def _publish(self, updates: dict[str, Any], *, invalidate: tuple[str, ...] = ()) -> None:
        """Commit only this transition and invalidate only independently indexed scopes."""
        require(not self._poisoned, "OWNER_COMMIT_UNCERTAIN")
        changed = copy.deepcopy(updates)
        for subject in invalidate:
            self._observation_barriers.pop(subject, None)
            self._quiescence_proofs.pop(subject, None)
            changed.setdefault("quiescent", {})[subject] = False
        previous = self.state["revision"]
        validate("adapter.schema.json", previous + 1, "Generation")
        envelope = {
            "format": "fishhat.adapter-commit/v1",
            "kind": "delta",
            "owner": copy.deepcopy(self.state["owner"]),
            "expected_revision": previous,
            "revision": previous + 1,
            "updates": changed,
        }
        canonical(envelope)
        try:
            self.commit_delta(copy.deepcopy(envelope))
            self._apply_updates(changed)
            self.state["revision"] = previous + 1
        except BaseException:
            # A failed acknowledgment or local application may follow a durable commit.
            self._poisoned = True
            raise

    def _apply_updates(self, updates: dict[str, Any]) -> None:
        for subject, binding in updates.get("bindings", {}).items():
            self._scope_subjects[canonical(binding["scope"])] = subject
        for attempt_id, attempt in updates.get("attempts", {}).items():
            previous = self.state["attempts"].get(attempt_id)
            scope = canonical(attempt["scope"])
            pending = self._pending_by_scope.get(scope, 0)
            if previous is not None and previous["state"] != "resolved":
                pending -= 1
            if attempt["state"] != "resolved":
                pending += 1
            self._pending_by_scope[scope] = pending
            self._effect_attempts[(attempt["operation_id"], attempt["effect_id"])] = attempt_id
        for key, records in updates.items():
            if key != "results":
                self.state[key].update(records)
                continue
            for attempt_id, added in records.items():
                evidence = self.state["results"].setdefault(attempt_id, {"records": {}})
                evidence["records"].update(added["records"])
                evidence["latest"] = added["latest"]
                evidence["knowledge"] = added["knowledge"]

    @staticmethod
    def _checkpoint_indexes(
        snapshot: dict[str, Any],
    ) -> tuple[dict[tuple[str, str], str], dict[bytes, str], dict[bytes, int]]:
        subjects = {
            canonical(binding["scope"]): subject
            for subject, binding in snapshot["bindings"].items()
        }
        effects: dict[tuple[str, str], str] = {}
        pending: dict[bytes, int] = {}
        for attempt_id, attempt in snapshot["attempts"].items():
            key = (attempt["operation_id"], attempt["effect_id"])
            require(key not in effects, "RESTORE_EFFECT_IDENTITY")
            effects[key] = attempt_id
            if attempt["state"] != "resolved":
                scope = canonical(attempt["scope"])
                pending[scope] = pending.get(scope, 0) + 1
        return effects, subjects, pending

    def _checkpoint(self, candidate: dict[str, Any]) -> None:
        require(not self._poisoned, "OWNER_COMMIT_UNCERTAIN")
        previous = candidate["revision"]
        validate("adapter.schema.json", previous + 1, "Generation")
        candidate["revision"] = previous + 1
        indexes = self._checkpoint_indexes(candidate)
        envelope = {
            "format": "fishhat.adapter-commit/v1",
            "kind": "checkpoint",
            "owner": copy.deepcopy(candidate["owner"]),
            "expected_revision": previous,
            "revision": previous + 1,
            "checkpoint": candidate,
        }
        canonical(envelope)
        try:
            self.commit_delta(copy.deepcopy(envelope))
            self.state = candidate
            self._effect_attempts, self._scope_subjects, self._pending_by_scope = indexes
        except BaseException:
            self._poisoned = True
            raise

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
            self._pending_by_scope.get(canonical(scope), 0) == 0,
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
        self._publish(
            {"bindings": {subject: binding}, "admission": {subject: False}},
            invalidate=(subject,),
        )

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
        self._publish({"admission": {subject: True}}, invalidate=(subject,))

    def close_admission(self, subject: str) -> None:
        require(subject in self.state["bindings"], "UNKNOWN_BINDING")
        binding = copy.deepcopy(self.state["bindings"][subject])
        binding["admission_generation"] += 1
        validate("adapter.schema.json", binding, "RuntimeBinding")
        self._publish(
            {"bindings": {subject: binding}, "admission": {subject: False}},
            invalidate=(subject,),
        )

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
        private_inputs_digest: str | None = None,
    ) -> dict[str, Any]:
        """Retain the approved request and private operation-value commitment.

        The owner independently derives private_inputs_digest from the complete
        approved ordered metadata closure and retains its private byte custody.
        None means that closure is empty; provider-access credentials are separate.
        """
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
            private_inputs_digest=private_inputs_digest,
        )

    def _service_instance(
        self, binding: dict[str, Any], instance_id: str, target: dict[str, Any]
    ) -> dict[str, Any]:
        instance = self.registry.inspect_delegation(
            binding["instance"], instance_id, "service", "apply", binding["scope"]
        )
        grant = next(g for g in instance["grants"] if g["scope"] == binding["scope"])
        require(
            target["namespace"] in grant["mutation"]["namespaces"]
            and target["namespace"]["facet"] == "lifecycle",
            "SERVICE_OUTSIDE_MUTATION_NAMESPACE",
        )
        require(
            target["executor"] == instance_reference(instance, binding["scope"]),
            "STALE_EXECUTOR_INSTANCE",
        )
        require(
            self.registry.source_target(target["selection"], "service", binding["scope"]) == target,
            "SOURCE_TARGET_MAPPING_IDENTITY",
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
        private_inputs_digest: str | None = None,
    ) -> dict[str, Any]:
        """Accept a subordinate lifecycle effect with its private-value commitment.

        private_inputs_digest has the same owner-verified closure and custody
        requirements as prepare; None commits to an empty operation-value set.
        """
        require(not self._poisoned, "OWNER_COMMIT_UNCERTAIN")
        require(owner_approved, "OPERATION_NOT_AUTHORIZED")
        check_request("service", request)
        require(request["method"] == "apply", "UNSUPPORTED_DELEGATED_EFFECT")
        binding = self.state["bindings"].get(subject)
        require(binding is not None, "UNKNOWN_BINDING")
        assert binding is not None
        require(request["input"]["scope"] == binding["scope"], "REQUEST_SCOPE")
        self._instance_matches(binding)
        self._source_matches(binding, host, app)
        instance = self._service_instance(binding, instance_id, request["input"]["target"])
        return self._prepare(
            binding,
            instance,
            request,
            operation_id=operation_id,
            effect_id=effect_id,
            attempt_id=attempt_id,
            private_inputs_digest=private_inputs_digest,
            runtime_control={
                "binding_digest": runtime_binding_digest(binding),
                "target": copy.deepcopy(request["input"]["target"]),
                "intent": copy.deepcopy(request["input"]["intent"]),
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
        private_inputs_digest: str | None,
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
        if private_inputs_digest is not None:
            attempt["private_inputs_digest"] = private_inputs_digest
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
        earlier = self._effect_attempts.get((operation_id, effect_id))
        if earlier is not None:
            old = self.state["attempts"][earlier]
            require(old["state"] == "resolved", "UNCERTAIN_EFFECT_RETRY")
            raise ContractError("EFFECT_RETRY_REQUIRES_NEW_PLAN")
        check_invocation(instance["role"], {"attempt": attempt, "request": request})
        self._publish(
            {"attempts": {attempt_id: attempt}, "requests": {attempt_id: request}},
            invalidate=(binding["subject"],),
        )
        return copy.deepcopy(attempt)

    def cancel_prepared(self, attempt_id: str, *, owner_approved: bool) -> None:
        require(owner_approved, "CANCELLATION_NOT_AUTHORIZED")
        attempt = self.state["attempts"].get(attempt_id)
        require(attempt is not None, "UNKNOWN_ATTEMPT")
        assert attempt is not None
        require(attempt["state"] == "prepared", "CANNOT_CANCEL_DISPATCHED_EFFECT")
        changed = {**attempt, "state": "resolved", "outcome": "cancelled"}
        subject = self._scope_subjects[canonical(attempt["scope"])]
        self._publish({"attempts": {attempt_id: changed}}, invalidate=(subject,))

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
        changed = {**attempt, "state": "dispatched", "certainty": "unknown"}
        self._publish({"attempts": {attempt_id: changed}}, invalidate=(subject,))
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
            binding, attempt["executor"]["instance"], control["target"]
        )
        require(
            attempt["executor"] == instance_reference(instance, binding["scope"]),
            "STALE_EXECUTOR_INSTANCE",
        )
        return (
            instance,
            "closed" if control["intent"]["activity"] == "stopped" else "open",
        )

    @staticmethod
    def _service_control(binding: dict[str, Any], attempt: dict[str, Any]) -> dict[str, Any]:
        """Check retained input identity without requiring a currently available executor."""
        require(
            attempt["contract"] == "fishhat.service"
            and attempt["method"] == "apply"
            and "runtime_control" in attempt,
            "RUNTIME_CONTROL_REQUIRED",
        )
        control = attempt["runtime_control"]
        require(control["binding_digest"] == runtime_binding_digest(binding), "STALE_DISPATCH")
        request = {
            "contract": "fishhat.service",
            "method": "apply",
            "input": {
                "scope": binding["scope"],
                "target": control["target"],
                "intent": control["intent"],
            },
        }
        require(digest(request) == attempt["input_digest"], "DELEGATED_INPUT_IDENTITY")
        return cast(dict[str, Any], control)

    def settle(self, attempt_id: str, request: dict[str, Any], response: dict[str, Any]) -> None:
        """Retain complete typed response custody before resolving the original attempt."""
        require(not self._poisoned, "OWNER_COMMIT_UNCERTAIN")
        attempt = self.state["attempts"].get(attempt_id)
        require(attempt is not None, "UNKNOWN_ATTEMPT")
        assert attempt is not None
        check_response(
            attempt["executor"]["role"],
            request,
            response,
            invocation={"attempt": attempt, "request": self.state["requests"][attempt_id]},
        )
        retained = {
            "request": copy.deepcopy(request),
            "response": copy.deepcopy(response),
        }
        identity = digest(retained)
        previous = self.state["results"].get(attempt_id)
        if previous is not None and identity in previous["records"]:
            require(previous["records"][identity] == retained, "RESULT_IDENTITY_CONFLICT")
            return
        require(attempt["state"] in {"dispatched", "reconciling"}, "INVALID_SETTLEMENT")
        knowledge = accumulate_result(
            attempt,
            response["effect"],
            previous=None if previous is None else previous["knowledge"],
        )
        changed = {**attempt, **self._settlement(knowledge)}
        evidence = {"latest": identity, "records": {identity: retained}, "knowledge": knowledge}
        subject = self._scope_subjects[canonical(attempt["scope"])]
        self._publish(
            {"attempts": {attempt_id: changed}, "results": {attempt_id: evidence}},
            invalidate=(subject,),
        )

    @staticmethod
    def _settlement(knowledge: dict[str, Any]) -> dict[str, Any]:
        completion = knowledge["completion"]
        outcome = "pending"
        if (
            completion is not None
            and completion["effect_certainty"] == knowledge["effect_certainty"]
        ):
            outcome = "succeeded" if completion["postcondition"] == "satisfied" else "failed"
        return {
            "state": "resolved" if outcome != "pending" else "reconciling",
            "certainty": knowledge["effect_certainty"],
            "native_task": knowledge["native_task"],
            "outcome": outcome,
        }

    def _check_retained_results(self, snapshot: dict[str, Any]) -> None:
        require(set(snapshot["results"]) <= set(snapshot["attempts"]), "RESTORE_RESULT_CUSTODY")
        for key, attempt in snapshot["attempts"].items():
            evidence = snapshot["results"].get(key)
            if evidence is None:
                require(
                    (
                        attempt["state"],
                        attempt["certainty"],
                        attempt["outcome"],
                        attempt["native_task"],
                    )
                    in {
                        ("prepared", "none", "pending", None),
                        ("dispatched", "unknown", "pending", None),
                        ("resolved", "none", "cancelled", None),
                    },
                    "RESTORE_RESULT_CUSTODY",
                )
                continue
            require(
                set(evidence) == {"latest", "records", "knowledge"}
                and evidence["latest"] in evidence["records"],
                "RESTORE_RESULT_CUSTODY",
            )
            knowledge = None
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
                knowledge = accumulate_result(
                    attempt, retained["response"]["effect"], previous=knowledge
                )
            require(knowledge == evidence["knowledge"], "RESTORE_RESULT_KNOWLEDGE")
            assert knowledge is not None
            require(
                all(
                    attempt[field] == value for field, value in self._settlement(knowledge).items()
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
                "binding": instance_reference(
                    self.registry.inspect_instance(binding["instance"]), binding["scope"]
                ),
                "target": copy.deepcopy(binding),
            },
        }
        self.registry.authorize_request(
            binding["instance"],
            "runtime",
            query,
            owner_approved=owner_approved,
            expected_runtime_binding=binding,
        )
        if self.state["quiescent"][subject]:
            self._publish({"quiescent": {subject: False}})
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
        self._publish({"quiescent": {subject: True}})
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
        validate("adapter.schema.json", snapshot["revision"], "Generation")
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
        self._checkpoint(candidate)
