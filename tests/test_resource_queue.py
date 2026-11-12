"""Public host queue custody and record joins, without a native admission ledger."""

from __future__ import annotations

import io
from copy import deepcopy
from functools import partial

import pytest
from fishhat_client.wire import frame, read_frame
from fishhat_contracts import resource_queue as queue
from fishhat_contracts.discovery import (
    FRESH_ADMISSION_METHODS,
    admission_contract,
    owner_contract_schemas,
)
from fishhat_contracts.record_delivery import RecordSnapshot, validate_record_payload
from fishhat_contracts.validation import (
    MAX_BYTES,
    SCHEMAS,
    ContractError,
    canonical,
    digest,
    validate,
)
from fishhat_owner.commands import admission_params, direct_admission_contract, parse_command

from tests.linear_support import assert_linear, measure
from tests.test_owner_handoffs import committed, wire
from tests.test_owner_handoffs import request as ssh_request
from tests.test_resource_admission import (
    DIGEST,
    LATER,
    NOW,
    records,
    response_for,
    role_request,
    uid,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-queue.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/resource-admission.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-cli.json",
    ],
    "scope": "host queue staged input, immutable public record references and closed owner routes",
    "relationship": "candidate",
    "reason": "Independent owner, context, payload and page substitutions challenge the public queue boundary. Synthetic custody and reference checks provide no native authentication, durable queue, reservation or execution authority.",
    "claims": [],
}

API_NAMES = (
    "decode_admission_input",
    "validate_admission_input_custody",
    "validate_admission_record",
    "validate_admission_page",
    "validate_admission_response",
)

CHECK_OVERRIDES = {
    name: {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/resource_queue.py#" + symbol
            for symbol in API_NAMES
        ]
        + ["release.toml#/engineering"],
        "scope": "each queue boundary over complete inputs or pages spanning sixteenfold extent",
        "relationship": "scoped-witness",
        "reason": "The boundary case exercises every declared helper; the growth witness counts each helper's complete work independently over sixteenfold extent. Neither establishes native persistence, authorization, queue traversal or unmeasured input families.",
        "claims": ["engineering:resource_queue." + symbol for symbol in API_NAMES],
    }
    for name in ("test_resource_queue_boundaries", "test_resource_queue_linear_work")
}


def staged(count=0, *, value=None):
    value = records() if value is None else value
    payload = value["request"]
    payload["storage_requests"] = [
        {"operation_id": uid(1000 + index), "request_digest": DIGEST} for index in range(count)
    ]
    owner = value["policy"]["domain"]["owner"]
    data = canonical(payload)
    staging = committed()
    staging.update(
        owner=deepcopy(owner),
        resource={"kind": "host", "id": payload["domain"]["host"]},
        purpose="resource-admission",
        digest=digest(payload),
        size=len(data),
        offset=len(data),
        created_at=NOW,
        expires_at=LATER,
    )
    staging["handle"].update(
        owner=deepcopy(owner),
        purpose="resource-admission",
        digest=digest(payload),
        size=len(data),
    )
    reference = {"owner": owner, "request_id": payload["id"], "input": staging["handle"]}
    return value, reference, data, staging


def input_context(value):
    return {
        "expected_owner": value["policy"]["domain"]["owner"],
        "policy": value["policy"],
        "context": value["context"],
    }


def admission_record(payload=None):
    payload = deepcopy(payload or records()["request"])
    return {
        "format": "fishhat.resource-queue/v1",
        "kind": "ResourceAdmission",
        "id": payload["id"],
        "owner": deepcopy(payload["domain"]["owner"]),
        "resource": {"kind": "host", "id": payload["domain"]["host"]},
        "generation": 0,
        "request": payload,
        "eligibility": "pending",
        "last_known": None,
        "observation": None,
    }


def cancellation():
    retained = admission_record()
    command = {
        "owner": deepcopy(retained["owner"]),
        "cancellation_id": uid(700),
        "request_id": retained["id"],
        "request_digest": digest(retained["request"]),
        "confirmed": True,
    }
    receipt = {
        "format": "fishhat.resource-queue/v1",
        "kind": "ResourceAdmissionCancellation",
        "id": command["cancellation_id"],
        "owner": deepcopy(command["owner"]),
        "resource": retained["resource"],
        "request_id": command["request_id"],
        "request_digest": command["request_digest"],
        "observed_generation": retained["generation"],
        "disposition": "stop-requested",
        "recorded_at": NOW,
    }
    return command, receipt


def admission_page(count=1, *, offset=0, cursor=None, more=False):
    items = []
    for index in range(offset, offset + count):
        record = admission_record()
        record["id"] = record["request"]["id"] = uid(10_000 + index)
        items.append(RecordSnapshot(record, uid(100_000 + index)).reference)
    owner = records()["policy"]["domain"]["owner"]
    selection = {
        "owner": owner,
        "record_kind": "ResourceAdmission",
        "resource": {"kind": "host", "id": "node-a"},
        "active_only": False,
        "cursor": cursor,
        "limit": 64,
    }
    return {
        "format": "fishhat.resource-queue-page/v1",
        "kind": "ResourceAdmissionPage",
        "request": selection,
        "items": items,
        "next_cursor": "next_" + str(offset + count) if more else None,
        "history_complete": True,
    }


def test_staged_admission_preserves_complete_request_larger_than_the_wire_frame():
    value, reference, data, staging = staged(10_000)
    assert len(data) > MAX_BYTES
    payload = queue.decode_admission_input(reference, data, **input_context(value))
    assert payload == value["request"]
    assert len(payload["storage_requests"]) == 10_000
    queue.validate_admission_input_custody(
        reference,
        payload,
        staging,
        **input_context(value),
        principal="ops-app-operate",
        now=NOW,
    )
    envelope = ssh_request("resources.admission.submit", reference)
    validate("ssh-request.schema.json", envelope)
    assert read_frame(io.BytesIO(frame(envelope))) == envelope
    with pytest.raises(ContractError):
        validate("ssh-request.schema.json", ssh_request("resources.admission.submit", payload))
    with pytest.raises(ContractError):
        queue.decode_admission_input(
            reference, data, **input_context(value), capacity_bytes=len(data) - 1
        )


@pytest.mark.parametrize("change", ["owner", "epoch", "context", "policy", "request", "digest"])
def test_staged_admission_requires_independently_current_authority_and_exact_bytes(change):
    value, reference, data, _ = staged()
    context = deepcopy(input_context(value))
    reference = deepcopy(reference)
    if change == "owner":
        context["expected_owner"]["id"] = uid(99)
    elif change == "epoch":
        context["expected_owner"]["epoch"] = uid(99)
    elif change == "context":
        context["context"]["stage_id"] = uid(99)
    elif change == "policy":
        context["policy"]["domain"]["host"] = "node-b"
    elif change == "request":
        reference["request_id"] = uid(99)
    else:
        reference["input"]["digest"] = "sha256:" + "f" * 64
    with pytest.raises(ContractError):
        queue.decode_admission_input(reference, data, **context)


@pytest.mark.parametrize("replace_context", [False, True])
def test_staged_account_substitution_cannot_reuse_independently_approved_work(replace_context):
    value = records()
    value["policy"]["accounts"]["other-app"] = deepcopy(value["policy"]["accounts"]["demo-app"])
    expected = deepcopy(input_context(value))
    value["request"]["account"] = "other-app"
    if replace_context:
        value["request"]["context"]["account"] = "other-app"
    value, reference, data, staging = staged(value=value)
    error = "ADMISSION_CURRENT_CONTEXT" if replace_context else "ADMISSION_WORK_ACCOUNT"
    with pytest.raises(ContractError, match=error):
        queue.decode_admission_input(reference, data, **expected)
    with pytest.raises(ContractError, match=error):
        queue.validate_admission_input_custody(
            reference,
            value["request"],
            staging,
            **expected,
            principal="ops-app-operate",
            now=NOW,
        )


def test_staged_account_change_accepts_a_new_independently_approved_request():
    original = records()
    value = deepcopy(original)
    value["policy"]["accounts"]["other-app"] = deepcopy(value["policy"]["accounts"]["demo-app"])
    expected = deepcopy(input_context(value))
    expected["context"]["account"] = "other-app"
    expected["context"]["authorization"]["digest"] = "sha256:" + "b" * 64
    value["request"].update(id=uid(99), account="other-app", context=deepcopy(expected["context"]))
    value, reference, data, staging = staged(value=value)
    payload = queue.decode_admission_input(reference, data, **expected)
    queue.validate_admission_input_custody(
        reference,
        payload,
        staging,
        **expected,
        principal="ops-app-operate",
        now=NOW,
    )
    assert payload == value["request"]
    assert payload["id"] != original["request"]["id"]
    assert payload["context"] == expected["context"]
    assert original["request"]["context"]["account"] == "demo-app"


@pytest.mark.parametrize("change", ["principal", "resource", "expired", "uncommitted", "handle"])
def test_resource_admission_staging_custody_cannot_be_rebound(change):
    value, reference, _, staging = staged()
    principal, now = "ops-app-operate", NOW
    if change == "principal":
        principal = "other-principal"
    elif change == "resource":
        staging["resource"] = {"kind": "host", "id": "node-b"}
    elif change == "expired":
        now = "2026-11-11T12:00:00Z"
    elif change == "uncommitted":
        staging["state"] = "uploading"
    else:
        staging["handle"]["id"] = uid(99)
        reference["input"] = deepcopy(reference["input"])
        reference["input"]["id"] = uid(100)
    with pytest.raises(ContractError):
        queue.validate_admission_input_custody(
            reference,
            value["request"],
            staging,
            **input_context(value),
            principal=principal,
            now=now,
        )


@pytest.mark.parametrize("verb", ["submit", "get", "list", "cancel"])
def test_resource_admission_cli_is_closed_host_only_stdin(verb):
    confirm = " --confirm" if verb in {"submit", "cancel"} else ""
    command = f"host-ops resources admission {verb} --request-stdin{confirm} --json"
    parsed = parse_command(command, "host-ops")
    assert parsed["use_case"] == "resources.admission." + verb
    with pytest.raises(ContractError):
        parse_command(command.replace("host-ops", "app-ops"), "app-ops")
    with pytest.raises(ContractError):
        parse_command(command.replace(" --request-stdin", ""), "host-ops")
    with pytest.raises(ContractError):
        parse_command(command + " --native-option", "host-ops")
    if confirm:
        with pytest.raises(ContractError):
            parse_command(command.replace(confirm, ""), "host-ops")


def test_admission_submit_stdin_keeps_the_exact_host_receiver_epoch():
    value, reference, _, _ = staged()
    method = "resources.admission.submit"
    envelope = ssh_request(method, reference)
    owner = input_context(value)["expected_owner"]
    assert admission_params(canonical(envelope), method, owner) == reference
    for changed in [{**owner, "epoch": uid(99)}, {**owner, "tool": "app-ops"}]:
        with pytest.raises(ContractError):
            admission_params(canonical(envelope), method, changed)
    with pytest.raises(ContractError):
        admission_params(canonical(reference), method, owner)


def test_new_queue_writes_require_fresh_contract_pins_without_granting_execution(monkeypatch):
    _, reference, _, _ = staged()
    writes = {"resources.admission.submit", "resources.admission.cancel"}
    assert writes <= FRESH_ADMISSION_METHODS
    assert not {"resources.admission.get", "resources.admission.list"} & FRESH_ADMISSION_METHODS
    original_pin = admission_contract(owner_contract_schemas())
    envelope = ssh_request("resources.admission.submit", reference)
    pinned = read_frame(io.BytesIO(frame(envelope, admission_contract=original_pin)))
    assert pinned["admission_contract"] == original_pin
    parsed = parse_command(
        f"host-ops --admission-contract {original_pin} resources admission submit"
        " --request-stdin --confirm --json",
        "host-ops",
    )
    assert direct_admission_contract(parsed, pinned) == original_pin
    changed = deepcopy(SCHEMAS["resource-queue.schema.json"])
    changed["description"] = changed.get("description", "") + " Changed independent queue contract."
    monkeypatch.setitem(SCHEMAS, "resource-queue.schema.json", changed)
    assert admission_contract(owner_contract_schemas()) != original_pin
    pinned["admission_contract"] = "sha256:" + "f" * 64
    with pytest.raises(ContractError):
        direct_admission_contract(parsed, pinned)


def test_queue_record_round_trip_keeps_complete_request_and_typed_owner_identity():
    value, _, _, _ = staged(80)
    retained = admission_record(value["request"])
    snapshot = RecordSnapshot(retained, uid(88))
    reference = snapshot.reference
    assert reference["record"] == {
        "kind": "ResourceAdmission",
        "id": retained["id"],
        "generation": 0,
        "resource": retained["resource"],
    }
    restored = validate_record_payload(
        reference,
        canonical(retained),
        expected_owner=retained["owner"],
        expected_resource=retained["resource"],
    )
    assert restored == retained
    queue.validate_admission_record(restored, expected_request=value["request"])


@pytest.mark.parametrize("change", ["request", "owner", "host", "generation"])
def test_queue_record_cannot_change_retained_work_or_owner_generation(change):
    original = admission_record()
    changed = deepcopy(original)
    changed["generation"] += 1
    if change == "request":
        changed["request"]["queue"]["deadline"] = None
    elif change == "owner":
        changed["owner"]["epoch"] = uid(99)
    elif change == "host":
        changed["resource"]["id"] = "node-b"
    else:
        changed["generation"] = 0
        changed["eligibility"] = "closed"
    with pytest.raises(ContractError):
        queue.validate_admission_record(changed, previous=original)


@pytest.mark.parametrize("eligibility", ["closed", "review-required"])
def test_queue_eligibility_cannot_silently_reopen_original_work(eligibility):
    original = admission_record()
    original["eligibility"] = eligibility
    changed = {**deepcopy(original), "generation": 1, "eligibility": "eligible"}
    with pytest.raises(ContractError):
        queue.validate_admission_record(changed, previous=original)


@pytest.mark.parametrize("retain_submission", [False, True])
def test_rejection_cannot_erase_a_queued_records_accepted_submission(retain_submission):
    value = records()
    original = admission_record(value["request"])
    queued = response_for(value, role_request(value, "observe"))["output"]["observation"]
    original.update(eligibility="eligible", last_known=queued, observation=queued)
    queue.validate_admission_record(original)
    rejected = response_for(value, role_request(value, "observe"), state="rejected")["output"][
        "observation"
    ]
    if not retain_submission:
        rejected["submission"] = None
    changed = {
        **deepcopy(original),
        "generation": 1,
        "eligibility": "closed",
        "last_known": rejected,
        "observation": rejected,
    }
    with pytest.raises(ContractError, match="SCHEDULER_ACCEPTED_SUBMISSION_REJECTED"):
        queue.validate_admission_record(changed, previous=original)
    assert original["last_known"]["submission"] == value["submission"]


def test_initial_queue_rejection_has_no_accepted_submission_or_allocation():
    value = records()
    original = admission_record(value["request"])
    rejected = response_for(value, role_request(value, "observe"), state="rejected")["output"][
        "observation"
    ]
    rejected["submission"] = None
    changed = {
        **deepcopy(original),
        "generation": 1,
        "eligibility": "closed",
        "last_known": rejected,
        "observation": rejected,
    }
    queue.validate_admission_record(changed, previous=original)
    assert all(rejected[field] is None for field in ("submission", "grant", "release", "closure"))


@pytest.mark.parametrize("known_grant", [False, True])
def test_unknown_scheduler_observation_preserves_last_known_submission_and_grant(known_grant):
    value = records()
    original = admission_record(value["request"])
    observed = response_for(
        value,
        role_request(value, "observe"),
        state="allocated" if known_grant else "queued",
        grant=value["grant"] if known_grant else None,
    )["output"]["observation"]
    original.update(eligibility="eligible", last_known=observed, observation=observed)
    queue.validate_admission_record(original)
    changed = deepcopy(original)
    changed["generation"] += 1
    changed["observation"] = response_for(value, role_request(value, "observe"), state="unknown")[
        "output"
    ]["observation"]
    changed["observation"]["submission"] = None
    queue.validate_admission_record(changed, previous=original)
    assert changed["last_known"] == observed
    assert changed["last_known"]["submission"] == value["submission"]
    erasures = [None]
    if known_grant:
        assert changed["last_known"]["grant"] == value["grant"]
        erasures.append({**observed, "state": "queued", "grant": None})
    for erase in erasures:
        bad = {**deepcopy(changed), "last_known": erase}
        with pytest.raises(ContractError):
            queue.validate_admission_record(bad, previous=original)


def test_cancellation_receipt_keeps_its_own_identity_and_does_not_release_a_grant():
    command, receipt = cancellation()
    expected = {"expected_request": command, "expected_target": records()["request"]}
    queue.validate_admission_record(receipt, **expected)
    snapshot = RecordSnapshot(receipt, uid(88))
    assert snapshot.reference["record"]["kind"] == "ResourceAdmissionCancellation"
    assert snapshot.reference["record"]["generation"] is None
    assert receipt["id"] != receipt["request_id"]
    assert receipt["disposition"] == "stop-requested"
    changed = {**receipt, "request_digest": "sha256:" + "f" * 64}
    with pytest.raises(ContractError):
        queue.validate_admission_record(changed, **expected)
    with pytest.raises(ContractError):
        queue.validate_admission_record(receipt, expected_request=command)
    with pytest.raises(ContractError):
        queue.validate_admission_record(
            {**receipt, "resource": {"kind": "host", "id": "node-b"}}, **expected
        )
    with pytest.raises(ContractError):
        queue.validate_admission_record(
            {**receipt, "disposition": "already-closed"}, previous=receipt
        )
    with pytest.raises(ContractError):
        validate("resource-queue.schema.json", {**command, "native_job": "job-9"}, "CancelRequest")


@pytest.mark.parametrize(
    "change", ["owner", "kind", "resource", "schema", "duplicate", "selection"]
)
def test_queue_page_joins_reject_substituted_owner_kind_scope_or_record(change):
    page = admission_page(2)
    expected = deepcopy(page["request"])
    if change == "owner":
        page["items"][0]["owner"]["epoch"] = uid(99)
    elif change == "kind":
        page["request"]["record_kind"] = "ResourceAdmissionCancellation"
        expected["record_kind"] = "ResourceAdmissionCancellation"
    elif change == "resource":
        page["items"][0]["record"]["resource"]["id"] = "node-b"
    elif change == "schema":
        page["items"][0]["schema"]["digest"] = "sha256:" + "f" * 64
    elif change == "duplicate":
        page["items"][1] = deepcopy(page["items"][0])
    else:
        expected["active_only"] = True
    with pytest.raises(ContractError):
        queue.validate_admission_page(page, request=expected)


def test_queue_pages_bound_only_one_page_and_preserve_complete_history_extent():
    references = []
    cursor = None
    for offset, count, more in [(0, 64, True), (64, 64, True), (128, 1, False)]:
        page = admission_page(count, offset=offset, cursor=cursor, more=more)
        queue.validate_admission_page(page, request=page["request"])
        references.extend(page["items"])
        cursor = page["next_cursor"]
    assert cursor is None
    assert len({item["record"]["id"] for item in references}) == 129
    empty = admission_page(0, more=True)
    empty["history_complete"] = False
    queue.validate_admission_page(empty)
    assert empty["next_cursor"] is not None
    excessive = admission_page(2)
    excessive["request"]["limit"] = 1
    with pytest.raises(ContractError):
        queue.validate_admission_page(excessive)


@pytest.mark.parametrize("verb", ["submit", "get", "list", "cancel"])
def test_queue_wire_response_keeps_exact_request_and_typed_record_identity(verb):
    value, reference, _, _ = staged()
    owner = input_context(value)["expected_owner"]
    if verb == "submit":
        params = reference
        result = RecordSnapshot(admission_record(value["request"]), uid(88)).reference
    elif verb == "get":
        retained = admission_record()
        params = {"owner": owner, "record_kind": "ResourceAdmission", "id": retained["id"]}
        result = RecordSnapshot(retained, uid(88)).reference
    elif verb == "list":
        result = admission_page(2)
        params = result["request"]
    else:
        params, receipt = cancellation()
        result = RecordSnapshot(receipt, uid(88)).reference
    method = "resources.admission." + verb
    request = ssh_request(method, params)
    response = wire(method, result)
    queue.validate_admission_response(request, response, expected_owner=owner)
    assert admission_params(canonical(request), method, owner) == params
    assert read_frame(io.BytesIO(frame(response))) == response
    bad = {**response, "message_id": uid(99)}
    with pytest.raises(ContractError):
        queue.validate_admission_response(request, bad, expected_owner=owner)
    bad = deepcopy(response)
    if verb == "list":
        bad["result"]["request"]["cursor"] = "different"
    else:
        bad["result"]["record"]["id"] = uid(99)
    with pytest.raises(ContractError):
        queue.validate_admission_response(request, bad, expected_owner=owner)


def boundary_calls(count):
    value, reference, data, staging = staged(count)
    context = input_context(value)
    retained = admission_record(value["request"])
    page = admission_page(count)
    request = ssh_request("resources.admission.list", page["request"])
    response = wire("resources.admission.list", page)
    return {
        "decode_admission_input": partial(queue.decode_admission_input, reference, data, **context),
        "validate_admission_input_custody": partial(
            queue.validate_admission_input_custody,
            reference,
            value["request"],
            staging,
            **context,
            principal="ops-app-operate",
            now=NOW,
        ),
        "validate_admission_record": partial(
            queue.validate_admission_record, retained, expected_request=value["request"]
        ),
        "validate_admission_page": partial(
            queue.validate_admission_page, page, request=page["request"]
        ),
        "validate_admission_response": partial(
            queue.validate_admission_response,
            request,
            response,
            expected_owner=context["expected_owner"],
        ),
    }


def test_resource_queue_boundaries():
    calls = boundary_calls(4)
    for name, call in calls.items():
        result = call()
        if name == "decode_admission_input":
            assert len(result["storage_requests"]) == 4
        else:
            assert result is None


def test_resource_queue_linear_work():
    for api in API_NAMES:
        samples = []
        for count in (4, 16, 64):
            call = boundary_calls(count)[api]
            _, work = measure(call, modules=(queue,))
            samples.append((count, work))
        assert_linear(samples)
