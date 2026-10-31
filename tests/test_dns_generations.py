"""One authoritative DNS revision identity from observation through reconciliation."""

from __future__ import annotations

import copy

import pytest
from fishhat_adapters import check_response
from fishhat_contracts import adapter_observations, dns
from fishhat_contracts.adapter_observations import ObservationSequence
from fishhat_contracts.dns import validate_publication_precondition
from fishhat_contracts.validation import ContractError, canonical, digest

from tests.adapter_support import OWNER, identifier
from tests.linear_support import assert_linear, measure
from tests.test_adapter_dns import change, generation, rrset
from tests.test_adapter_handoffs import installed, invocation_for, response_for
from tests.test_adapter_invocations import recovered
from tests.test_adapter_observation_pages import page

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/dns-changes.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/dns-adapter.schema.json",
    ],
    "scope": "exact DNS revision namespace, complete stable observation, before-state prerequisites and newer direct/reconciled results",
    "relationship": "candidate",
    "reason": "Synthetic independent native views exercise stale, restored and substituted identities, complete traversal and measured reference growth without qualifying live DNS exclusion or publication.",
    "claims": [],
}
CHECK_OVERRIDES = {
    "test_dns_precondition_linear_work": {
        "purpose": "implementation",
        "authority": [
            "release.toml#/engineering",
            "packages/fishhat-contracts/src/fishhat_contracts/dns.py#validate_publication_precondition",
        ],
        "scope": "complete authoritative DNS state and changeset comparison over sixteenfold extent",
        "relationship": "scoped-witness",
        "reason": "Measured complete indexed joins and final RRset validation establish reference growth; native observation and exclusion remain outside this measurement.",
        "claims": ["engineering:dns.publication-precondition"],
    },
    "test_dns_observation_sequence_linear_work": {
        "purpose": "implementation",
        "authority": [
            "release.toml#/engineering",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_observations.py#ObservationSequence.__init__",
            "packages/fishhat-contracts/src/fishhat_contracts/adapter_observations.py#ObservationSequence.accept",
        ],
        "scope": "complete stable DNS observation traversals and exact retries over sixteenfold extent",
        "relationship": "scoped-witness",
        "reason": "Measured initialization and every page/retry include revision and cross-page identity indexes; no native snapshot, durability or authority is qualified.",
        "claims": [
            "engineering:adapters.observation-sequence.start",
            "engineering:adapters.observation-sequence.accept",
        ],
    },
}


def observed():
    query, reply = page("dns")
    query["input"]["cursor"] = None
    reply["request_digest"] = digest(query)
    reply["output"] = {"rrsets": [rrset()], "served_generation": generation(revision=7)}
    return query, reply


def publication():
    before, after = rrset(), rrset()
    after["ttl"]["seconds"] = 60
    value = change(before, after)
    value["expected_generation"] = generation(revision=7)
    query = {
        "contract": "fishhat.dns",
        "method": "publish",
        "input": {"scope": value["scope"], "change": value},
    }
    invocation = invocation_for(query)
    reply = response_for(
        query,
        invocation["attempt"],
        {"rrsets": [after], "served_generation": generation(revision=8)},
    )
    return query, invocation, reply


def sequence(query):
    return ObservationSequence(
        "dns", query, approved_binding=query["input"]["binding"], approved_owner=OWNER
    )


def test_observe_publish_and_lost_reply_use_the_same_exact_generation_identity():
    query, observed_reply = observed()
    traversal = sequence(query)
    assert traversal.accept(query, observed_reply) and traversal.complete
    publication_query, invocation, reply = publication()
    change = publication_query["input"]["change"]
    assert change["expected_generation"] == observed_reply["output"]["served_generation"]
    before = canonical(invocation)
    validate_publication_precondition(
        change,
        current_generation=observed_reply["output"]["served_generation"],
        current_rrsets=observed_reply["output"]["rrsets"],
    )
    check_response("dns", publication_query, reply, invocation=invocation)
    recovery_query = recovered(invocation)
    recovery_reply = response_for(recovery_query, invocation["attempt"], reply["output"])
    check_response("dns", recovery_query, recovery_reply, invocation=invocation)
    assert canonical(invocation) == before


@pytest.mark.parametrize("field", ["owner", "binding", "native_incarnation", "generation"])
def test_native_precondition_rejects_every_changed_revision_namespace_field(field):
    query, _, _ = publication()
    change = query["input"]["change"]
    current = copy.deepcopy(change["expected_generation"])
    if field == "owner":
        current[field]["epoch"] = identifier(90)
    elif field == "binding":
        current[field]["instance_generation"] += 1
    elif field == "native_incarnation":
        current[field] = identifier(91)
    else:
        current[field] += 1
    original = canonical(change)
    with pytest.raises(ContractError):
        validate_publication_precondition(
            change, current_generation=current, current_rrsets=[rrset()]
        )
    assert canonical(change) == original


@pytest.mark.parametrize("field", ["ttl", "rdata", "missing"])
def test_native_before_state_is_required_even_with_an_equal_generation(field):
    query, _, _ = publication()
    change = query["input"]["change"]
    current = [rrset()]
    if field == "missing":
        current.clear()
    elif field == "ttl":
        current[0]["ttl"]["seconds"] = 30
    else:
        current[0]["rdata"].append({"address": "192.0.2.20"})
    with pytest.raises(ContractError, match="DNS_BEFORE_STATE_CHANGED"):
        validate_publication_precondition(
            change, current_generation=change["expected_generation"], current_rrsets=current
        )


@pytest.mark.parametrize("reconciliation", [False, True])
@pytest.mark.parametrize(
    "field", ["owner", "binding", "native_incarnation", "generation", "null", "digest"]
)
def test_success_cannot_substitute_or_reuse_a_served_generation(field, reconciliation):
    query, invocation, reply = publication()
    if reconciliation:
        query = recovered(invocation)
        reply = response_for(query, invocation["attempt"], reply["output"])
    value = reply["output"]["served_generation"]
    if field == "owner":
        value[field]["epoch"] = identifier(90)
    elif field == "binding":
        value[field]["instance_generation"] += 1
    elif field == "native_incarnation":
        value[field] = identifier(91)
    elif field == "generation":
        value[field] = 7
    else:
        reply["output"]["served_generation"] = None if field == "null" else "sha256:" + "a" * 64
    with pytest.raises(ContractError):
        check_response("dns", query, reply, invocation=invocation)


def test_integer_precondition_and_counter_wrap_are_not_accepted():
    query, _, _ = publication()
    change = query["input"]["change"]
    original = copy.deepcopy(change["expected_generation"])
    change["expected_generation"] = 7
    with pytest.raises(ContractError):
        dns.validate_changes(change)
    original["generation"] = 9007199254740991
    change["expected_generation"] = original
    with pytest.raises(ContractError, match="DNS_GENERATION_EXHAUSTED"):
        validate_publication_precondition(
            change, current_generation=original, current_rrsets=[rrset()]
        )


def test_observation_traversal_rejects_mixed_generations_and_requires_independent_owner():
    query, reply = observed()
    with pytest.raises(ContractError, match="DNS_OBSERVATION_APPROVED_OWNER"):
        ObservationSequence("dns", query, approved_binding=query["input"]["binding"])
    traversal = sequence(query)
    reply.update(coverage="incomplete", continuation="page:next")
    assert traversal.accept(query, reply) and not traversal.complete
    assert not traversal.accept(query, copy.deepcopy(reply))
    query["input"]["cursor"] = reply["continuation"]
    reply.update(coverage="complete", continuation=None, request_digest=digest(query))
    reply["output"]["rrsets"] = []
    reply["output"]["served_generation"]["generation"] += 1
    with pytest.raises(ContractError, match="DNS_OBSERVATION_GENERATION_CHANGED"):
        traversal.accept(query, reply)
    assert not traversal.complete
    reply["output"]["served_generation"]["generation"] -= 1
    assert traversal.accept(query, reply) and traversal.complete


def test_unknown_observation_never_completes_a_traversal():
    query, reply = observed()
    reply.update(coverage="unknown")
    reply["output"]["served_generation"] = None
    traversal = sequence(query)
    assert traversal.accept(query, reply) and not traversal.complete
    reply.update(coverage="complete")
    with pytest.raises(ContractError):
        check_response("dns", query, reply)


def test_dns_snapshot_rejects_cross_page_cname_collision_without_consuming_the_page():
    query, reply = observed()
    cname = rrset()
    cname.update(type="CNAME", rdata=[{"target": "alias.example.test."}])
    reply["output"]["rrsets"] = [cname]
    reply.update(coverage="incomplete", continuation="page:next")
    traversal = sequence(query)
    assert traversal.accept(query, reply)
    query["input"]["cursor"] = reply["continuation"]
    reply.update(coverage="complete", continuation=None, request_digest=digest(query))
    reply["output"]["rrsets"] = [rrset()]
    with pytest.raises(ContractError, match="CNAME_COLLISION"):
        traversal.accept(query, reply)
    assert not traversal.complete
    reply["output"]["rrsets"] = [rrset(name="other.example.test.")]
    assert traversal.accept(query, reply) and traversal.complete


def test_invalidated_dns_snapshot_closes_unknown_without_a_replacement_generation():
    query, reply = observed()
    traversal = sequence(query)
    reply.update(coverage="incomplete", continuation="page:next")
    assert traversal.accept(query, reply)
    query["input"]["cursor"] = reply["continuation"]
    reply.update(coverage="unknown", continuation=None, request_digest=digest(query))
    reply["output"]["rrsets"] = []
    reply["output"]["served_generation"]["native_incarnation"] = identifier(91)
    with pytest.raises(ContractError, match="DNS_OBSERVATION_GENERATION_CHANGED"):
        traversal.accept(query, reply)
    reply["output"]["served_generation"] = None
    assert traversal.accept(query, reply) and not traversal.complete


def test_dns_precondition_linear_work():
    samples = []
    for count in (8, 32, 128):
        value = change(after=rrset())
        current, changes = [], []
        for index in range(count):
            before = rrset(name=f"host-{index:04d}.example.test.")
            after = copy.deepcopy(before)
            after["ttl"]["seconds"] = 60
            current.append(before)
            changes.append({"before": before, "after": after})
        value["changes"] = changes
        _, work = measure(
            lambda value=value, current=current: validate_publication_precondition(
                value, current_generation=value["expected_generation"], current_rrsets=current
            ),
            modules=(dns,),
        )
        samples.append((count, work))
    assert_linear(samples)


def test_dns_observation_sequence_linear_work():
    samples = []
    for count in (8, 32, 128):
        initial, _ = observed()
        _, executor = installed("dns")
        pages = []
        query = copy.deepcopy(initial)
        for index in range(count):
            last = index == count - 1
            _, reply = observed()
            reply.update(
                request_digest=digest(query),
                coverage="complete" if last else "incomplete",
                continuation=None if last else f"page:{index + 1}",
            )
            reply["output"]["rrsets"] = [rrset(name=f"host-{index:04d}.example.test.")]
            pages.append((copy.deepcopy(query), reply))
            query["input"]["cursor"] = reply["continuation"]

        def run(initial=initial, executor=executor, pages=pages):
            traversal = ObservationSequence(
                "dns", initial, approved_binding=executor, approved_owner=OWNER
            )
            for query, reply in pages:
                assert traversal.accept(query, reply)
                assert not traversal.accept(query, reply)
            assert traversal.complete

        _, work = measure(run, modules=(adapter_observations,))
        samples.append((count, work))
    assert_linear(samples)
