from __future__ import annotations

import copy

import pytest
from fishhat_adapters import check_request, check_response
from fishhat_contracts.validation import ContractError, digest

from tests.adapter_support import identifier
from tests.test_adapter_handoffs import artifact, installed, invocation_for, response_for

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/repository-adapter.schema.json"
    ],
    "scope": "literal repository refs and raw object identities, approved provider mappings, exact fetch custody and publication compare-and-swap receipts",
    "relationship": "candidate",
    "reason": "Synthetic independent request, predecessor, executor and artifact substitutions exercise typed handoffs without claiming native Git or provider atomicity.",
    "claims": [],
}

OLD = "a" * 40
NEW = "b" * 40
REF = "refs/heads/main"


def repository(*, approved=True):
    registry, binding = installed("repository")
    reference = {
        "canonical": {"instance": identifier(51), "repository_id": 7, "name": "source/demo"},
        "provider_handle": "repository:demo",
        "binding": binding,
    }
    if approved:
        registry.enroll_repository(reference, owner_approved=True)
    return registry, reference


def query(method, reference):
    inputs = {"scope": copy.deepcopy(reference["binding"]["scope"])}
    if method == "observe":
        inputs.update(binding=copy.deepcopy(reference["binding"]), cursor=None, limit=10)
    else:
        inputs["repository"] = copy.deepcopy(reference)
    if method in {"resolve", "publish"}:
        inputs["ref"] = REF
    if method == "fetch":
        inputs["commit"] = NEW
    if method == "publish":
        inputs.update(
            expected_previous={"state": "present", "object_id": OLD},
            candidate={
                "repository": copy.deepcopy(reference),
                "commit": NEW,
                "artifacts": [artifact("c")],
            },
        )
    return {"contract": "fishhat.repository", "method": method, "input": inputs}


def resolution(reference, state="present"):
    return {
        "repository": copy.deepcopy(reference),
        "ref": REF,
        "state": state,
        "object_id": NEW if state in {"present", "non-commit"} else None,
        "commit": NEW if state == "present" else None,
        "observed_at": "2026-10-24T00:00:00Z",
    }


def read_response(request, output, *, coverage="complete"):
    return {
        "contract": request["contract"],
        "method": request["method"],
        "request_digest": digest(request),
        "scope": request["input"]["scope"],
        "coverage": coverage,
        "continuation": None,
        "proposal": None,
        "output": output,
    }


def mutation_response(request):
    invocation = invocation_for(request)
    inputs = request["input"]
    if request["method"] == "fetch":
        output = {
            "snapshot": {
                "repository": copy.deepcopy(inputs["repository"]),
                "commit": NEW,
                "artifacts": [artifact("c")],
            }
        }
    else:
        output = {
            "publication": {
                "repository": copy.deepcopy(inputs["repository"]),
                "ref": inputs["ref"],
                "object_id": inputs["candidate"]["commit"],
                "previous": copy.deepcopy(inputs["expected_previous"]),
                "snapshot": copy.deepcopy(inputs["candidate"]),
            }
        }
    return invocation, response_for(request, invocation["attempt"], output)


@pytest.mark.parametrize("method", ["resolve", "fetch", "publish"])
def test_repository_requests_distinguish_observation_from_immutable_fetch_and_cas(method):
    registry, reference = repository()
    request = query(method, reference)
    check_request("repository", request)
    if method == "resolve":
        registry.authorize_request("selected", "repository", request, owner_approved=True)
        request["input"]["commit"] = NEW
    else:
        registry.authorize_invocation("repository", invocation_for(request), owner_approved=True)
        request["input"]["expected_commit"] = OLD
    with pytest.raises(ContractError):
        check_request("repository", request)


@pytest.mark.parametrize("state", ["present", "non-commit", "absent", "unknown"])
def test_resolve_does_not_require_an_invented_current_commit(state):
    _, reference = repository()
    request = query("resolve", reference)
    reply = read_response(
        request,
        {"resolution": resolution(reference, state)},
        coverage="unknown" if state == "unknown" else "complete",
    )
    check_response("repository", request, reply)
    changed = copy.deepcopy(reply)
    changed["output"]["resolution"]["ref"] = "refs/heads/other"
    with pytest.raises(ContractError, match="REPOSITORY_RESOLUTION_IDENTITY"):
        check_response("repository", request, changed)
    for member in ("object_id", "commit"):
        changed = copy.deepcopy(reply)
        observed = changed["output"]["resolution"]
        observed[member] = NEW if observed[member] is None else None
        with pytest.raises(ContractError):
            check_response("repository", request, changed)
    if state == "unknown":
        reply["coverage"] = "complete"
        with pytest.raises(ContractError, match="REPOSITORY_RESOLUTION_COVERAGE"):
            check_response("repository", request, reply)


@pytest.mark.parametrize(
    "ref",
    ["HEAD", "main", "refs/heads/main~1", "refs/heads/main\n"],
    ids=["symbolic-head", "short-name", "revision-expression", "trailing-newline"],
)
def test_repository_selection_and_publication_use_only_literal_git_refs(ref):
    _, reference = repository()
    for method in ("resolve", "publish"):
        request = query(method, reference)
        request["input"]["ref"] = ref
        with pytest.raises(ContractError):
            check_request("repository", request)


def test_publication_requires_explicit_predecessor_or_absence_and_retained_candidate():
    _, reference = repository()
    request = query("publish", reference)
    previous_digest = digest(request)
    request["input"]["expected_previous"] = {"state": "absent"}
    check_request("repository", request)
    assert digest(request) != previous_digest
    for previous in (
        None,
        {},
        {"state": "unknown"},
        {"state": "absent", "object_id": OLD},
        {"state": "present", "commit": OLD},
    ):
        changed = copy.deepcopy(request)
        changed["input"]["expected_previous"] = previous
        with pytest.raises(ContractError):
            check_request("repository", changed)
    request["input"]["candidate"]["artifacts"] = []
    with pytest.raises(ContractError):
        check_request("repository", request)


def test_annotated_tag_publication_compares_the_raw_tag_object_and_writes_a_direct_commit():
    _, reference = repository()
    tag_object = "c" * 40
    request = query("resolve", reference)
    request["input"]["ref"] = "refs/tags/release"
    observed = resolution(reference)
    observed.update(ref=request["input"]["ref"], object_id=tag_object, commit=OLD)
    check_response("repository", request, read_response(request, {"resolution": observed}))

    publication = query("publish", reference)
    publication["input"].update(
        ref=observed["ref"],
        expected_previous={"state": "present", "object_id": observed["object_id"]},
    )
    invocation, reply = mutation_response(publication)
    check_response("repository", publication, reply, invocation=invocation)
    changed = copy.deepcopy(reply)
    changed["output"]["publication"]["previous"]["object_id"] = observed["commit"]
    with pytest.raises(ContractError, match="REPOSITORY_PUBLICATION_IDENTITY"):
        check_response("repository", publication, changed, invocation=invocation)
    changed = copy.deepcopy(reply)
    changed["output"]["publication"]["object_id"] = tag_object
    with pytest.raises(ContractError, match="REPOSITORY_PUBLICATION_IDENTITY"):
        check_response("repository", publication, changed, invocation=invocation)


@pytest.mark.parametrize(
    "substitution", ["repository", "executor", "commit", "missing-artifacts", "missing-snapshot"]
)
def test_successful_fetch_requires_exact_repository_commit_and_immutable_custody(substitution):
    _, reference = repository()
    request = query("fetch", reference)
    invocation, reply = mutation_response(request)
    check_response("repository", request, reply, invocation=invocation)
    snapshot = reply["output"]["snapshot"]
    if substitution == "repository":
        snapshot["repository"]["provider_handle"] = "repository:other"
    elif substitution == "executor":
        snapshot["repository"]["binding"]["configuration_digest"] = artifact("d")["digest"]
    elif substitution == "commit":
        snapshot["commit"] = OLD
    elif substitution == "missing-artifacts":
        snapshot["artifacts"] = []
    else:
        reply["output"]["snapshot"] = None
    with pytest.raises(ContractError):
        check_response("repository", request, reply, invocation=invocation)


@pytest.mark.parametrize("reconcile", [False, True], ids=["direct", "lost-reply"])
@pytest.mark.parametrize("substitution", ["ref", "repository", "predecessor", "commit", "artifact"])
def test_publication_and_reconciliation_keep_the_original_cas_and_candidate(
    reconcile, substitution
):
    _, reference = repository()
    request = query("publish", reference)
    invocation, reply = mutation_response(request)
    if reconcile:
        request = {
            "contract": request["contract"],
            "method": "reconcile",
            "input": {"scope": request["input"]["scope"], "invocation": copy.deepcopy(invocation)},
        }
        reply = response_for(request, invocation["attempt"], reply["output"])
    check_response("repository", request, reply, invocation=invocation)
    publication = reply["output"]["publication"]
    if substitution == "ref":
        publication["ref"] = "refs/heads/other"
    elif substitution == "repository":
        publication["repository"]["provider_handle"] = "repository:other"
    elif substitution == "predecessor":
        publication["previous"] = {"state": "absent"}
    elif substitution == "commit":
        publication["snapshot"]["commit"] = OLD
    else:
        publication["snapshot"]["artifacts"] = [artifact("d")]
    with pytest.raises(ContractError, match="REPOSITORY_PUBLICATION_IDENTITY"):
        check_response("repository", request, reply, invocation=invocation)


def test_repository_mapping_requires_independent_owner_approval_and_cannot_rebind():
    registry, reference = repository(approved=False)
    request = query("fetch", reference)
    with pytest.raises(ContractError, match="UNAPPROVED_REPOSITORY_MAPPING"):
        registry.authorize_invocation("repository", invocation_for(request), owner_approved=True)
    with pytest.raises(ContractError, match="REPOSITORY_MAPPING_NOT_AUTHORIZED"):
        registry.enroll_repository(reference, owner_approved=False)
    registry.enroll_repository(reference, owner_approved=True)
    registry.authorize_invocation("repository", invocation_for(request), owner_approved=True)
    changed = copy.deepcopy(reference)
    changed["provider_handle"] = "repository:other"
    with pytest.raises(ContractError, match="EXPLICIT_REPOSITORY_REBIND_REQUIRED"):
        registry.enroll_repository(changed, owner_approved=True)
    with pytest.raises(ContractError, match="UNAPPROVED_REPOSITORY_MAPPING"):
        registry.authorize_invocation(
            "repository", invocation_for(query("fetch", changed)), owner_approved=True
        )
    changed = copy.deepcopy(reference)
    changed["canonical"]["repository_id"] = 8
    with pytest.raises(ContractError, match="REPOSITORY_MAPPING_ALIAS"):
        registry.enroll_repository(changed, owner_approved=True)


def test_repository_mapping_cannot_replace_accepted_executor_configuration():
    registry, reference = repository()
    changed = copy.deepcopy(reference)
    changed["binding"]["configuration_digest"] = artifact("d")["digest"]
    with pytest.raises(ContractError, match="HANDOFF_INSTANCE_IDENTITY"):
        registry.enroll_repository(changed, owner_approved=True)
    request = query("resolve", changed)
    with pytest.raises(ContractError, match="HANDOFF_INSTANCE_IDENTITY"):
        registry.authorize_request("selected", "repository", request, owner_approved=True)


def test_repository_observation_keeps_exact_executor_and_ref_identity():
    _, reference = repository()
    request = query("observe", reference)
    reply = read_response(request, {"refs": [resolution(reference)]})
    check_response("repository", request, reply)
    reply["output"]["refs"].append(copy.deepcopy(reply["output"]["refs"][0]))
    with pytest.raises(ContractError, match="DUPLICATE_REPOSITORY_REF"):
        check_response("repository", request, reply)
