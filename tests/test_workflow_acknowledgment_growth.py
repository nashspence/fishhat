"""Executed reply work across all individual acknowledgments and exact retries."""

from __future__ import annotations

import copy

from fishhat_client.wire import frame
from fishhat_contracts.validation import digest
from fishhat_contracts.workflow_acknowledgments import (
    validate_workflow_mutation_acknowledgment,
    workflow_mutation_acknowledgment,
)

from tests.linear_support import assert_linear, measure
from tests.test_contracts import uid
from tests.test_owner_handoffs import wire
from tests.test_workflow_acknowledgments import accepted, expected

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_acknowledgments.py#workflow_mutation_acknowledgment",
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_acknowledgments.py#validate_workflow_mutation_acknowledgment",
        "release.toml#/engineering",
    ],
    "scope": "complete reply construction, correlation, framing and exact-retry work across increasing individual receipt counts",
    "relationship": "scoped-witness",
    "reason": "Executed Python, container and serialized-byte work covers each original reply and one lost-response replay over sixteenfold extent. Individual receipt setup is outside measurement. This proves only acknowledgment production/correlation growth, not workflow admission, complete-history validation, storage, authentication or native execution.",
    "claims": [
        "engineering:workflow.mutation-acknowledgment",
        "engineering:workflow.mutation-acknowledgment-validation",
    ],
}


def test_complete_reply_sequence_and_retries_have_linear_work():
    _, template = accepted("workflow.bind")
    samples = []
    for count in (4, 16, 64):
        receipts = []
        for index in range(count):
            receipt = copy.deepcopy(template)
            request = receipt["request"]
            request["bind_id"] = uid("ack-bind-" + str(index))
            request["child"]["request_id"] = uid("ack-child-" + str(index))
            request["binding"]["request_id"] = request["child"]["request_id"]
            request["expected_generation"] = index
            receipt.update(generation=index + 1, request_digest=digest(request))
            receipts.append((receipt, expected("workflow.bind", receipt)))

        def all_replies(receipts=receipts):
            replies = []
            for receipt, context in receipts:
                for _ in range(2):
                    result = workflow_mutation_acknowledgment("workflow.bind", receipt)
                    validate_workflow_mutation_acknowledgment(result, **context)
                    replies.append(frame(wire("workflow.bind", result)))
            return replies

        replies, work = measure(all_replies)
        assert len(replies) == 2 * count
        assert all(replies[index] == replies[index + 1] for index in range(0, len(replies), 2))
        assert max(map(len, replies)) < 4096
        samples.append((count, work))
    assert_linear(samples)
