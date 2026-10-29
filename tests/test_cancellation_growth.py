"""Complete cancellation journal work across admission, restart, pages and retries."""

from fishhat_client.wire import frame
from fishhat_contracts.cancellation import CancellationJournal
from fishhat_contracts.validation import canonical, strict_json

from tests.linear_support import assert_linear, measure
from tests.test_cancellation import (
    OWNER,
    REQUEST_ID,
    context,
    get_request,
    list_request,
    read_context,
    request,
    restored_custody,
    wire,
)

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/cancellation.py#validate_cancellation_receipt",
        "packages/fishhat-contracts/src/fishhat_contracts/cancellation.py#CancellationJournal.__init__",
        "packages/fishhat-contracts/src/fishhat_contracts/cancellation.py#CancellationJournal.cancel",
        "packages/fishhat-contracts/src/fishhat_contracts/cancellation.py#CancellationJournal.get",
        "packages/fishhat-contracts/src/fishhat_contracts/cancellation.py#CancellationJournal.page",
        "packages/fishhat-contracts/src/fishhat_contracts/cancellation.py#CancellationJournal.snapshot",
        "release.toml#/engineering",
    ],
    "scope": "all accepted cancellation identities, finite original replay, same-epoch restart and restored-epoch complete paged discovery",
    "relationship": "scoped-witness",
    "reason": "Executed work counts include every admission and exact replay, whole protected-state serialization/restoration, indexed lookup and complete page traversal with retries across sixteenfold extent. This establishes reference growth only; native storage, authorization and cancellation execution remain unqualified.",
    "claims": [
        "engineering:cancellation.validate",
        "engineering:cancellation.restore",
        "engineering:cancellation.admit",
        "engineering:cancellation.lookup",
        "engineering:cancellation.list",
        "engineering:cancellation.snapshot",
    ],
}


def test_complete_admission_restart_listing_and_retries_are_linear():
    samples = []
    for count in (16, 64, 256):
        requests = [request(index) for index in range(count)]

        def complete(requests=requests):
            journal = CancellationJournal(OWNER)
            for value in requests:
                original = journal.cancel(value, **context())
                replay = journal.cancel(value, **context(cancel_authorized=False, target=None))
                assert original == replay
                frame(wire("operation.cancel", replay, response=True))
            data = canonical(journal.snapshot())
            retained = strict_json(data, max_bytes=len(data))
            selections = []
            for custody in (None, restored_custody()):
                custodian = OWNER if custody is None else custody["custodian"]
                restored = CancellationJournal(
                    OWNER, retained=retained, custodian=custodian, verified_custody=custody
                )
                assert restored.stop_requested(REQUEST_ID) == (custody is None)
                receiving = read_context(expected_owner=custodian, verified_custody=custody)
                scope = {
                    "custodian": custodian,
                    "custody_id": None if custody is None else custody["id"],
                }
                for index, value in enumerate(requests):
                    assert (
                        restored.get({**get_request(index), **scope}, **receiving)[
                            "cancellation_id"
                        ]
                        == value["cancellation_id"]
                    )
                selected = []
                query = {**list_request(limit=7), **scope}
                while True:
                    page = restored.page(query, **receiving)
                    frame(wire("operation.cancellation.list", page, response=True))
                    if query["cursor"] is not None:
                        assert restored.page(query, **receiving) == page
                    selected.extend(item["cancellation_id"] for item in page["items"])
                    if page["next_cursor"] is None:
                        break
                    query["cursor"] = page["next_cursor"]
                selections.append(selected)
            return selections

        selected, work = measure(complete)
        assert selected == [[value["cancellation_id"] for value in requests]] * 2
        samples.append((count, work))
    assert_linear(samples)
