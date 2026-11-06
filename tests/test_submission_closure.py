"""An explicitly authorized withdrawal competes with the original submission."""

import json
from unittest.mock import Mock

import pytest
from fishhat_client.submission import close_if_unaccepted, submit_once
from fishhat_contracts.discovery import admission_contract, owner_contract_schemas
from fishhat_contracts.submission_decisions import StandaloneDecisions
from fishhat_contracts.validation import ContractError, validate
from fishhat_owner.commands import close_request_params, parse_command

from tests.test_operation_semantics import delivery
from tests.test_owner_handoffs import FIXTURES, operation

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/SubmissionClose",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-cli.json",
    ],
    "scope": "standalone withdrawal and submission arbitration under common epoch custody",
    "relationship": "candidate",
    "reason": "Both serialized race orders preserve one decision under synthetic scoped authority. Native authorization, durability and execution remain independent responsibilities.",
    "claims": [],
}


def test_submit_and_close_share_one_exact_decision():
    op = operation()
    prepared = delivery(op)
    uncertain = {**prepared, "state": "acceptance_unknown"}
    original = Mock()
    submit_once(prepared, original, confirmed=True)
    submit = original.call_args.args[0]
    transport = Mock()
    close_if_unaccepted(uncertain, transport, confirmed=True)
    close = transport.call_args.args[0]
    assert (
        parse_command("app-ops op close-if-unaccepted --request-stdin --confirm --json", "app-ops")[
            "use_case"
        ]
        == "operation.close"
    )
    wire = json.dumps(
        {
            "format": "deployment-ops/owner/v1",
            "method": "operation.close",
            "message_id": op["request_id"],
            "params": close,
        }
    ).encode()
    assert close_request_params(wire, op["owner"]) == close
    with pytest.raises(ContractError):
        close_request_params(wire, {**op["owner"], "epoch": op["id"]})
    workflow_delivery = {**uncertain, "workflow_id": op["id"]}
    for invalid, confirmed in ((prepared, True), (uncertain, False), (workflow_delivery, True)):
        with pytest.raises(ContractError):
            close_if_unaccepted(invalid, transport, confirmed=confirmed)
    assert transport.call_count == 1
    for first in ("operation.submit", "operation.close"):
        index = StandaloneDecisions(op["owner"])
        context = {
            "principal": op["authenticated_principal"],
            "can_read": Mock(return_value=True),
            "admission_pin": admission_contract(owner_contract_schemas()),
            "can_close": Mock(return_value=True),
            "admit": Mock(return_value=op),
            "reviewed_plan": Mock(return_value=json.loads((FIXTURES / "plan.json").read_text())),
        }
        with pytest.raises(ContractError):
            index.decide(
                "operation.close", close, **{**context, "can_close": Mock(return_value=False)}
            )
        with pytest.raises(ContractError):
            wrong_scope = {**close, "resource": {"kind": "app", "id": "other"}}
            index.decide("operation.close", wrong_scope, **context)
        with pytest.raises(ContractError):
            unavailable = Mock(side_effect=ContractError("custody unavailable"))
            index.decide("operation.close", close, **{**context, "reviewed_plan": unavailable})
        another_resource = {"kind": "app", "id": "elsewhere"}
        scoped_read = Mock(
            side_effect=lambda principal, resource, allowed=another_resource: resource == allowed
        )
        probe = {**close, "resource": another_resource}
        with pytest.raises(ContractError, match="scoped read permission"):
            index.decide("operation.close", probe, **{**context, "can_read": scoped_read})
        scoped_read.assert_called_once_with(
            op["authenticated_principal"], op["subject"]["resource"]
        )
        scoped_close = Mock(
            side_effect=lambda principal, resource, allowed=another_resource: resource == allowed
        )
        with pytest.raises(ContractError, match="scoped cancellation permission"):
            index.decide("operation.close", probe, **{**context, "can_close": scoped_close})
        scoped_close.assert_called_once_with(
            op["authenticated_principal"], op["subject"]["resource"]
        )
        result = index.decide(first, submit if first == "operation.submit" else close, **context)
        scoped_read.reset_mock()
        with pytest.raises(ContractError, match="scoped read permission"):
            index.decide("operation.close", probe, **{**context, "can_read": scoped_read})
        scoped_read.assert_called_once_with(
            op["authenticated_principal"], op["subject"]["resource"]
        )

        replay = {
            **context,
            "can_close": Mock(return_value=False),
            "principal": "reader",
            "admission_pin": None,
            "reviewed_plan": unavailable,
        }
        assert index.decide("operation.submit", submit, **replay) == result
        assert index.decide("operation.close", close, **replay) == result
        with pytest.raises(ContractError):
            index.decide(
                "operation.close", close, **{**replay, "can_read": Mock(return_value=False)}
            )
        for params in ({**close, "claimed_actor": "another"}, {**close, "plan_id": op["id"]}):
            with pytest.raises(ContractError):
                index.decide("operation.close", params, **context)
        if first == "operation.submit":
            assert result == op
            context["admit"].assert_called_once()
            resolved = close_if_unaccepted(uncertain, Mock(return_value=result), confirmed=True)
            assert resolved["delivery"]["state"] == "accepted"
        else:
            context["admit"].assert_not_called()
            assert result["nonacceptance"]["reason"] == result["problem"]["code"] == "CANCELLED"
            response = {
                "format": "deployment-ops/owner/v1",
                "method": "operation.close",
                "message_id": op["request_id"],
                "ok": False,
                **result,
            }
            validate("ssh-response.schema.json", response)
            resolved = close_if_unaccepted(uncertain, Mock(return_value=response), confirmed=True)
            assert resolved["delivery"]["state"] == "rejected"
            delayed = Mock(return_value={**response, "method": "operation.submit"})
            assert submit_once(prepared, delayed, confirmed=True)["delivery"]["state"] == "rejected"

            # A new close cannot replace a prior native refusal with operator withdrawal.
            expired = {
                "nonacceptance": {**result["nonacceptance"], "reason": "PLAN_EXPIRED"},
                "problem": {
                    **result["problem"],
                    "code": "PLAN_EXPIRED",
                    "summary": "Plan expired.",
                },
            }
            prior = StandaloneDecisions(op["owner"])
            with pytest.raises(ContractError, match="explicit withdrawal"):
                prior.decide(
                    "operation.submit", submit, **{**context, "admit": Mock(return_value=result)}
                )
            prior.decide(
                "operation.submit", submit, **{**context, "admit": Mock(return_value=expired)}
            )
            assert prior.decide("operation.close", close, **replay) == expired
    lost = close_if_unaccepted(uncertain, Mock(side_effect=TimeoutError()), confirmed=True)
    assert lost["delivery"] == uncertain
