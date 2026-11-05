"""Standalone submit/withdraw arbitration model for a complete original owner epoch.

The native receiver must serialize both methods on its one durable acceptance index.
This in-memory model starts with a known empty epoch. It does not establish absence
after storage loss, authenticate a principal, start a worker, or commit native effects.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from threading import Lock
from typing import Any

from .operations import (
    operation_matches_delivery,
    submission_replay_identity,
    validate_operation,
    validate_submission_refusal,
)
from .validation import ContractError, digest, validate, validate_plan

JSON = dict[str, Any]


class StandaloneDecisions:
    def __init__(self, owner: JSON) -> None:
        validate("common.schema.json", owner, "Owner")
        self._owner = copy.deepcopy(owner)
        self._decisions: dict[str, tuple[bytes, JSON, JSON, str]] = {}
        self._lock = Lock()

    def decide(
        self,
        method: str,
        params: JSON,
        *,
        principal: str,
        can_read: Callable[[str, JSON], bool],
        can_close: Callable[[str, JSON], bool],
        reviewed_plan: Callable[[], JSON],
        admit: Callable[[], JSON],
    ) -> JSON:
        """Select exact replay, fresh native admission, or closure under shared exclusion.

        Authorization facts are independent, resource-scoped receiver decisions.
        reviewed_plan resolves authenticated custody and admit checks all current
        admission conditions and supplies the verified initial accepted Operation or
        original durable refusal. Ordinary errors must raise without storing a decision.
        A native transaction commits its decision and attribution before acknowledgment.
        """
        if method not in ("operation.submit", "operation.close"):
            raise ContractError("unsupported standalone decision")
        validate(
            "ssh-request.schema.json",
            {
                "format": "deployment-ops/owner/v1",
                "method": method,
                "message_id": params.get("request_id"),
                "params": params,
            },
        )
        if params["owner"] != self._owner:
            raise ContractError("current owner epoch required")
        validate("common.schema.json", principal, "Id")
        closing = method == "operation.close"
        if closing:
            submission = {k: v for k, v in params.items() if k not in ("resource", "confirm_close")}
            submission.update(confirmed=True, workflow_id=None, driver_term=None)
        else:
            if params["workflow_id"] is not None:
                raise ContractError("standalone submission required")
            submission = params
        identity = submission_replay_identity(submission)
        with self._lock:
            previous = self._decisions.get(params["request_id"])
            if previous is not None:
                if can_read(principal, copy.deepcopy(previous[1])) is not True:
                    raise ContractError("current scoped read permission required")
                if previous[0] != identity or (closing and params["resource"] != previous[1]):
                    raise ContractError("submission identity conflict")
                return copy.deepcopy(previous[2])
            plan = reviewed_plan()
            validate_plan(plan)
            resource = plan["subject"]["resource"]
            if can_read(principal, copy.deepcopy(resource)) is not True:
                raise ContractError("current scoped read permission required")
            if closing and can_close(principal, copy.deepcopy(resource)) is not True:
                raise ContractError("current scoped cancellation permission required")
            if not (
                plan["owner"] == self._owner
                and plan["id"] == params["plan_id"]
                and plan["digest"] == params["plan_digest"]
                and digest(plan["subject"]) == params["subject_digest"]
                and (not closing or resource == params["resource"])
            ):
                raise ContractError("original protected Plan identity changed")
            result: JSON
            if closing:
                refusal = {
                    k: v for k, v in submission.items() if k not in ("driver_term", "confirmed")
                }
                refusal.update(resource=resource, kind="SubmissionRefusal", reason="CANCELLED")
                result = {
                    "nonacceptance": refusal,
                    "problem": {
                        "owner": self._owner,
                        "resource": resource,
                        "code": "CANCELLED",
                        "summary": "The standalone request was withdrawn before acceptance.",
                        "retry": "none",
                        "evidence": [],
                    },
                }
            else:
                result = admit()
            delivery = {**submission, "resource": resource, "action": plan["subject"]["action"]}
            if set(result) == {"nonacceptance", "problem"}:
                validate_submission_refusal(result["nonacceptance"], result["problem"], delivery)
                if not closing and result["nonacceptance"]["reason"] == "CANCELLED":
                    raise ContractError("only explicit withdrawal can create a CANCELLED refusal")
            else:
                validate_operation(result)
                if (
                    result["state"] != "accepted"
                    or result["authenticated_principal"] != principal
                    or not operation_matches_delivery(result, delivery)
                ):
                    raise ContractError("native acceptance changed the original submission")
            self._decisions[params["request_id"]] = (
                identity,
                copy.deepcopy(resource),
                copy.deepcopy(result),
                principal,
            )
            return copy.deepcopy(result)
