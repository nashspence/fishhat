"""A restored gate needs complete original custody and each owner's fresh delegation."""

from copy import deepcopy
from types import SimpleNamespace

import pytest
from fishhat_contracts.handoffs import schema_identity
from fishhat_contracts.validation import ContractError, canonical, digest
from fishhat_contracts.workflow_gate_recovery import (
    GateJournalSource,
    GateRecoveryEnrollment,
    OriginGateRecoveryContext,
    WorkflowRecoveryGate,
    retain_recovery_gate,
)
from fishhat_contracts.workflow_journal import initialize_workflow_journal
from fishhat_contracts.workflow_journal_recovery import (
    JournalRecovery,
    OriginRecoveryContext,
    WorkflowRecoveryMember,
)
from fishhat_owner.workflow_journal import WorkflowJournal

from tests.test_contracts import uid
from tests.test_workflow_journal_epoch import CurrentNative
from tests.workflow_journal_support import (
    DRIVER,
    KEY_ID,
    NEXT_DRIVER,
    NOW,
    Endpoint,
    LogicalWorkload,
    MeteredPrivateKey,
    WorkflowRun,
    WorkMeter,
    require,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_gate_recovery.py",
    ],
    "scope": "current-epoch recovery-only gate, complete source custody, exact local reapproval, retained successor reservation and bounded aggregate recovery",
    "relationship": "candidate",
    "reason": "Independent synthetic native approval and real journal persistence challenge forged, incomplete and stale gate replacement. These reference checks do not qualify native anti-rollback or fencing.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_gate_epoch_recovery_requires_every_local_approval_and_preserves_custody": {
        **CHECK_PURPOSE,
        "purpose": "implementation",
        "relationship": "scoped-witness",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_gate_recovery.py#WorkflowRecoveryGate.__init__",
        ],
        "claims": ["engineering:workflow.journal.gate-recover"],
    },
    "test_gate_recovery_growth_counts_complete_owner_closure": {
        **CHECK_PURPOSE,
        "purpose": "implementation",
        "relationship": "scoped-witness",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_gate_recovery.py#WorkflowRecoveryGate.__init__",
        ],
        "claims": ["engineering:workflow.journal.gate-recover"],
    },
}


def recovered_gate(run, *, predecessor=None, sources=(), label="first", restore=False):
    old = run.gate.target if predecessor is None else predecessor.target
    owner = {**old.owner, "epoch": uid("gate-recovery-epoch-" + label)}
    key = MeteredPrivateKey(owner, run.meter.values)
    source = GateJournalSource(old.journal, old.journal.schema, old.journal.head, old.extension)
    lineage = (*sources, source)
    custody = {
        "format": "deployment-ops/owner-history/v1",
        "kind": "OwnerCustody",
        "id": uid("gate-custody-" + label),
        "custodian": owner,
        "origin": old.owner,
        "manifest": {
            "schema": schema_identity("https://fishhat.invalid/contracts/recovery-set.schema.json"),
            "digest": digest(
                [
                    {"owner": item.journal.owner, "head": item.head, "schema": item.schema}
                    for item in lineage
                ]
            ),
        },
        "created_at": NOW,
    }
    custody["digest"] = digest(custody)
    source_keys = {
        (canonical(item.journal.owner), KEY_ID): old.keys[(canonical(item.journal.owner), KEY_ID)]
        for item in lineage
    }
    origin = OriginGateRecoveryContext(run.manifest, lineage, custody, source_keys)
    path = run.root / ("gate-recovered-" + label + ".journal")
    store = (
        WorkflowJournal.open(
            path, expected_owner=owner, expected_schema=run.schema, metrics=run.meter.values
        )
        if restore
        else WorkflowJournal.create(path, owner=owner, schema=run.schema, metrics=run.meter.values)
    )
    native_fence = {"retired": True, "head": old.journal.head, "custody": custody}

    def authorize(principal, action, context):
        run.meter.values["restored_gate_authorization_visits"] += 1
        require(
            principal in {DRIVER, NEXT_DRIVER} and context["owner"] == owner,
            "restored gate current permission denied",
        )

    def verify_restore(context):
        run.meter.values["gate_native_restoration_visits"] += 1
        require(
            native_fence["retired"] and native_fence["head"] == source.head,
            "previous native gate authority is not fenced",
        )
        require(
            context["custody"] == native_fence["custody"]
            and context["authority"]["source_head"] == source.head,
            "native complete gate custody changed",
        )
        require(
            context["sources"]
            == [
                {"owner": item.journal.owner, "head": item.head, "schema": item.schema}
                for item in lineage
            ],
            "native gate lineage omitted custody",
        )

    def old_authorize(principal, action, context):
        require(action == "read", "original gate execution authority is fenced")

    old.authorize = old_authorize
    context = {
        "origin": origin,
        "owner": owner,
        "key_id": KEY_ID,
        "private_key": key,
        "member_keys": {
            (canonical(actor.owner), KEY_ID): actor.key.public_key() for actor in run.native
        },
        "authorize": authorize,
        "restore_gate": verify_restore,
        "journal": store,
        "principal": DRIVER,
        "extension": JournalRecovery(),
        "clock": lambda: NOW,
    }
    try:
        target = WorkflowRecoveryGate(**context)
    except BaseException:
        store.close()
        raise
    endpoint = Endpoint(target, run.root / ("gate-recovered-inputs-" + label), run.meter)
    return SimpleNamespace(
        target=target,
        endpoint=endpoint,
        context=context,
        origin=origin,
        lineage=lineage,
        native_fence=native_fence,
    )


def enroll_and_approve(run, recovered, index):
    member, actor = run.members[index], run.native[index]
    authority = deepcopy(recovered.target.authority)
    grant_id = uid("gate-reapproval-" + authority["owner"]["epoch"] + actor.owner["id"])
    previous = getattr(member.target, "_recovery_gate_authority", None)
    previous_digest = None if previous is None else digest(previous)
    grant = GateRecoveryEnrollment(
        authority,
        recovered.target.private_key.public_key(),
        grant_id,
        previous_digest,
    )
    extension = member.target.extension
    installed = dict(extension.gate_recovery_enrollments)
    installed[digest(authority)] = grant
    extension.gate_recovery_enrollments = installed
    actor.gate_recovery_enrollments[digest(authority)] = {
        "owner": actor.owner,
        "workflow_id": member.target.workflow_id,
        "authority": authority,
        "grant_id": grant_id,
        "previous_authority_digest": previous_digest,
    }
    return member.call(
        "recover.gate_approve",
        {"initialization": recovered.target._gate_recovery_initialized},
        lost_reply=True,
    )


def approve_all(run, recovered):
    for index in range(run.workload.owners):
        approval = enroll_and_approve(run, recovered, index)
        recovered.endpoint.call("recover.gate_collect", {"approval": approval})
    return recovered.endpoint.call("recover.gate_commit")


def recover_successor(run, recovered):
    successor, mapping = run.successor()
    gate = recovered.endpoint
    gate.call("recover.propose", {"successor": successor, "mapping": mapping})
    for member in run.members:
        projection = gate.call("recover.projection", {"owner": member.target.owner})
        disposition = member.call("recover.inspect", {"projection": projection})
        gate.call("recover.collect", {"disposition": disposition})
    certificate = gate.call("recover.commit")
    for member in run.members:
        member.call("recover.install", {"certificate": certificate})
    return successor, certificate


def test_gate_epoch_recovery_requires_every_local_approval_and_preserves_custody(tmp_path):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(children=1), meter)
        recovered = None
        try:
            run.prepare()
            original_head = run.gate.target.journal.head
            original_bytes = list(run.gate.target.journal.iter_events(read_authorized=True))
            recovered = recovered_gate(run)
            gate = recovered.endpoint
            with pytest.raises(ContractError, match="complete independent local reapproval"):
                gate.call("recover.gate_commit")
            successor, mapping = run.successor()
            with pytest.raises(ContractError, match="complete independent local reapproval"):
                gate.call("recover.propose", {"successor": successor, "mapping": mapping})
            first = enroll_and_approve(run, recovered, 0)
            gate.call("recover.gate_collect", {"approval": first})
            with pytest.raises(ContractError, match="duplicated"):
                gate.call("recover.gate_collect", {"approval": first})
            with pytest.raises(ContractError, match="complete independent local reapproval"):
                gate.call("recover.gate_commit")
            second = enroll_and_approve(run, recovered, 1)
            gate.call("recover.gate_collect", {"approval": second})
            gate.call("recover.gate_commit")
            with pytest.raises(ContractError, match="recovery only"):
                gate.call("round", {"to_phase": "draining"}, fresh=True)
            with pytest.raises(ContractError, match="fenced"):
                run.gate.call("round", {"to_phase": "draining"}, fresh=True)
            recovered.context["extension"].current_owners[canonical(run.native[0].owner)] = {
                **run.native[0].owner,
                "epoch": uid("unapproved-live-mapping-change"),
            }
            _, certificate = recover_successor(run, recovered)
            assert certificate["owner"] == recovered.target.owner
            assert certificate["body"]["supersedes"] is None
            assert run.gate.target.journal.head == original_head
            assert list(run.gate.target.journal.iter_events(read_authorized=True)) == original_bytes
            for actor in run.native:
                assert actor.retired and actor.successor is not None
                assert not actor.admissions
        finally:
            if recovered is not None:
                recovered.endpoint.close()
            run.close()


@pytest.mark.parametrize(
    "tamper",
    ["head", "custody", "enrollment"],
    ids=["changed-head", "changed-custody", "missing-enrollment"],
)
def test_gate_recovery_rejects_substituted_or_unapproved_authority(tmp_path, tamper):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(children=1), meter)
        recovered = None
        try:
            run.prepare()
            recovered = recovered_gate(run)
            if tamper == "enrollment":
                with pytest.raises(ContractError, match="independently enrolled"):
                    run.members[0].call(
                        "recover.gate_approve",
                        {
                            "initialization": recovered.target._gate_recovery_initialized,
                        },
                    )
                assert not run.native[0].gate_reapprovals
            else:
                command = deepcopy(
                    recovered.target.journal.lookup(
                        recovered.target._gate_recovery_initialized["id"], read_authorized=True
                    )["request"]
                )
                field = "source_head" if tamper == "head" else "custody_digest"
                command["payload"][field] = "sha256:" + "0" * 64
                context = dict(recovered.context)
                context.pop("principal")
                with pytest.raises(ContractError, match="custody commitment"):
                    initialize_workflow_journal(command, principal=DRIVER, context=context)
        finally:
            if recovered is not None:
                recovered.endpoint.close()
            run.close()


def test_gate_recovery_preserves_and_recertifies_an_existing_successor(tmp_path):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(children=1), meter)
        recovered = None
        try:
            run.prepare()
            successor = run.recover()
            original = run.gate.target._recovery_state["recovery"]["certificate"]
            recovered = recovered_gate(run)
            approve_all(run, recovered)
            with pytest.raises(ContractError, match="already reserved"):
                recovered.endpoint.call(
                    "recover.propose",
                    {
                        "successor": successor,
                        "mapping": run.successor()[1],
                    },
                )
            replacement = recovered.endpoint.call("recover.commit")
            assert replacement["body"]["recovery"] == original["body"]["recovery"]
            assert replacement["body"]["supersedes"] == {
                "id": original["id"],
                "digest": digest(original),
            }
            for member in run.members:
                member.call("recover.install", {"certificate": replacement})
                context = member.target.extension.context(member.target, principal=DRIVER)
                assert context.certificate == replacement
                assert context.projection["owner"] == original["owner"]
            assert run.gate.read(original["id"]) == original
            assert all(actor.successor == successor["workflow_id"] for actor in run.native)
        finally:
            if recovered is not None:
                recovered.endpoint.close()
            run.close()


def test_repeated_gate_epoch_recovery_preserves_every_source_segment(tmp_path):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(children=1), meter)
        first = second = None
        try:
            run.prepare()
            first = recovered_gate(run)
            approve_all(run, first)
            _, original = recover_successor(run, first)
            second = recovered_gate(
                run, predecessor=first.endpoint, sources=first.origin.sources, label="second"
            )
            approve_all(run, second)
            replacement = second.endpoint.call("recover.commit")
            assert replacement["body"]["supersedes"]["digest"] == digest(original)
            assert second.target.header == run.gate.target.header
            assert second.target.owner["epoch"] != first.target.owner["epoch"]
            assert (
                second.target._recovery_state["recovery"]["recovery"]
                == original["body"]["recovery"]
            )
            reused = dict(second.context)
            old_gate = run.gate.target
            custody = deepcopy(second.origin.custody)
            custody["custodian"] = old_gate.owner
            custody["digest"] = digest(
                {name: value for name, value in custody.items() if name != "digest"}
            )
            reused.update(
                origin=OriginGateRecoveryContext(
                    second.origin.proposal,
                    second.origin.sources,
                    custody,
                    second.origin.source_keys,
                ),
                owner=old_gate.owner,
                private_key=old_gate.private_key,
                journal=old_gate.journal,
            )
            with pytest.raises(ContractError, match="reuse an earlier owner epoch"):
                WorkflowRecoveryGate(**reused)
        finally:
            if second is not None:
                second.endpoint.close()
            if first is not None:
                first.endpoint.close()
            run.close()


def test_member_catches_up_after_missing_intermediate_recertification(tmp_path):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(children=1), meter)
        first = second = None
        try:
            run.prepare()
            run.recover()
            original = run.gate.target._recovery_state["recovery"]["certificate"]
            first = recovered_gate(run)
            approve_all(run, first)
            missed = first.endpoint.call("recover.commit")
            second = recovered_gate(
                run,
                predecessor=first.endpoint,
                sources=first.origin.sources,
                label="second",
            )
            approve_all(run, second)
            latest = second.endpoint.call("recover.commit")
            assert latest["body"]["supersedes"]["digest"] == digest(missed)
            for member in run.members:
                assert member.target._recovery_state["recovery"]["certificate"] == original
                changed = deepcopy(latest["body"])
                changed["disposition_closure_digest"] = digest("different closure")
                forged = second.target._sign(changed, uid("changed-recovery-closure"))
                with pytest.raises(ContractError, match="reservation or closure"):
                    member.call("recover.install", {"certificate": forged})
                installed = member.call("recover.install", {"certificate": latest}, lost_reply=True)
                assert installed["body"]["recovery"] == original["body"]["recovery"]
                assert member.target._recovery_state["recovery"]["certificate"] == latest
            assert run.gate.read(original["id"]) == original
            assert first.endpoint.read(missed["id"]) == missed
        finally:
            if second is not None:
                second.endpoint.close()
            if first is not None:
                first.endpoint.close()
            run.close()


def test_member_skips_unapproved_gate_epoch_with_exact_local_predecessor(tmp_path):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(owners=1, children=1), meter)
        first = second = None
        try:
            run.prepare()
            first = recovered_gate(run)
            assert first.target._gate_recovery_certificate is None
            second = recovered_gate(
                run,
                predecessor=first.endpoint,
                sources=first.origin.sources,
                label="second",
            )
            member = run.members[0]
            authority = second.target.authority
            member.target.extension.gate_recovery_enrollments = {
                digest(authority): GateRecoveryEnrollment(
                    authority,
                    second.target.private_key.public_key(),
                    uid("incorrect-local-predecessor-grant"),
                    digest(first.target.authority),
                ),
            }
            before = meter.values["native_gate_reapproval_visits"]
            with pytest.raises(ContractError, match="exact retained authority predecessor"):
                member.call(
                    "recover.gate_approve",
                    {
                        "initialization": second.target._gate_recovery_initialized,
                    },
                )
            assert meter.values["native_gate_reapproval_visits"] == before
            assert getattr(member.target, "_recovery_gate_authority", None) is None
            approval = enroll_and_approve(run, second, 0)
            assert approval["body"]["native"]["previous_authority_digest"] is None
            assert approval["body"]["authority"]["predecessor"] == first.target.owner
            second.endpoint.call("recover.gate_collect", {"approval": approval})
            second.endpoint.call("recover.gate_commit")
            _, certificate = recover_successor(run, second)
            assert certificate["owner"] == second.target.owner
        finally:
            if second is not None:
                second.endpoint.close()
            if first is not None:
                first.endpoint.close()
            run.close()


def test_gate_recovery_recertifies_missed_terminal_abandonment(tmp_path):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(owners=2, children=1), meter)
        recovered = None
        try:
            run.prepare()
            successor = run.recover(commit=False)
            proposal = run.gate.call("recover.abandon_start")
            for member in run.members:
                result = member.call("recover.abandon", {"proposal": proposal})
                run.gate.call("recover.collect_abandon", {"abandonment": result})
            original = run.gate.call("recover.abandon_commit")
            assert original["body"]["supersedes"] is None
            run.members[0].call("recover.observe_abandon", {"certificate": original})
            recovered = recovered_gate(run)
            approve_all(run, recovered)
            with pytest.raises(ContractError, match="missing or already current"):
                recovered.endpoint.call(
                    "recover.abandon_recertify",
                    {
                        "successor_workflow_id": uid("unrelated-abandonment"),
                    },
                )
            latest = recovered.endpoint.call(
                "recover.abandon_recertify",
                {
                    "successor_workflow_id": successor["workflow_id"],
                },
                lost_reply=True,
            )
            for name in ("recovery", "abandon_id", "owner_count", "closure_digest"):
                assert latest["body"][name] == original["body"][name]
            assert latest["body"]["supersedes"] == {
                "id": original["id"],
                "digest": digest(original),
            }
            assert recovered.target._recovery_state["recovery"] is None
            run.members[1].call("recover.observe_abandon", {"certificate": latest})
            assert all(actor.successor is None for actor in run.native)
            assert all(successor["workflow_id"] in actor.abandoned for actor in run.native)
            with pytest.raises(ContractError, match="successor workflow"):
                recovered.endpoint.call(
                    "recover.propose",
                    {
                        "successor": successor,
                        "mapping": run.successor()[1],
                    },
                )
            replacement, mapping = run.successor()
            replacement["workflow_id"] = uid("replacement-after-abandonment")
            recovered.endpoint.call(
                "recover.propose",
                {
                    "successor": replacement,
                    "mapping": mapping,
                },
            )
            for member in run.members:
                projection = recovered.endpoint.call(
                    "recover.projection",
                    {
                        "owner": member.target.owner,
                    },
                )
                disposition = member.call("recover.inspect", {"projection": projection})
                recovered.endpoint.call("recover.collect", {"disposition": disposition})
            certificate = recovered.endpoint.call("recover.commit")
            assert (
                certificate["body"]["recovery"]["successor_workflow_id"]
                == replacement["workflow_id"]
            )
            assert run.gate.read(original["id"]) == original
        finally:
            if recovered is not None:
                recovered.endpoint.close()
            run.close()


def test_gate_recovery_growth_counts_complete_owner_closure(tmp_path):
    samples = []
    for owners in (1, 4, 12):
        meter = WorkMeter()
        with meter.account():
            run = WorkflowRun(
                tmp_path / str(owners), LogicalWorkload(owners=owners, children=1), meter
            )
            recovered = None
            try:
                run.prepare()
                before = meter.values.copy()
                recovered = recovered_gate(run)
                approve_all(run, recovered)
                recover_successor(run, recovered)
                difference = meter.values - before
                assert difference["native_gate_reapproval_visits"] == owners
                samples.append((owners, difference))
            finally:
                if recovered is not None:
                    recovered.endpoint.close()
                run.close()
    for metric in (
        "canonical_bytes",
        "hash_bytes",
        "wire_bytes",
        "bytes_written",
        "signature_verifications",
        "reference_python_steps",
    ):
        first_count, first = samples[0]
        assert first[metric] > 0
        for count, values in samples[1:]:
            assert values[metric] * first_count <= first[metric] * count * 1.5, (metric, samples)


def test_member_epoch_restore_preserves_a_prior_gate_reapproval(tmp_path):
    class ReapprovingNative(CurrentNative):
        def _apply(self, request, outcome):
            if request["action"] == "gate-reapproval":
                self.approval = outcome
            else:
                super()._apply(request, outcome)

        def approve_gate_recovery(self, context):
            require(context == self.enrolled_gate_context, "current gate grant not installed")
            result = {
                "owner": self.owner,
                "workflow_id": context["workflow_id"],
                "authority_digest": digest(context["authority"]),
                "grant_id": context["grant_id"],
                "previous_authority_digest": context["previous_authority_digest"],
                "native_generation": 1,
                "original_admission_closed": True,
                "custody_preserved": True,
            }
            self._append("gate-reapproval", result)
            return deepcopy(result)

    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(children=1), meter)
        recovered = current_native = current_journal = None
        try:
            run.prepare()
            recovered = recovered_gate(run)
            approve_all(run, recovered)
            original = run.members[0].target
            old_approval = deepcopy(original._recovery_gate_approval)
            current = {**original.owner, "epoch": uid("member-after-gate-reapproval")}
            custody = {
                "format": "deployment-ops/owner-history/v1",
                "kind": "OwnerCustody",
                "id": uid("member-after-gate-custody"),
                "custodian": current,
                "origin": original.owner,
                "manifest": {
                    "schema": schema_identity(
                        "https://fishhat.invalid/contracts/recovery-set.schema.json"
                    ),
                    "digest": digest(
                        {"journal": original.journal.head, "native": run.native[0].store.head}
                    ),
                },
                "created_at": NOW,
            }
            custody["digest"] = digest(custody)
            current_native = ReapprovingNative(
                run.native[0],
                current,
                custody,
                original.journal,
                tmp_path / "current-native-after-reapproval.journal",
                meter,
            )
            key = MeteredPrivateKey(current, meter.values)
            current_journal = WorkflowJournal.create(
                tmp_path / "current-member-after-reapproval.journal",
                owner=current,
                schema=run.schema,
                metrics=meter.values,
            )
            extension = JournalRecovery(
                current_owners={canonical(original.owner): current},
                verified_custody={canonical(original.owner): custody},
            )
            target = WorkflowRecoveryMember(
                OriginRecoveryContext(
                    original.journal,
                    original.journal.schema,
                    original.signed_projection,
                    original.enrollment,
                    custody,
                    original.keys,
                ),
                owner=current,
                key_id=KEY_ID,
                private_key=key,
                native=current_native,
                operation_keys={(canonical(current), KEY_ID): key.public_key()},
                journal=current_journal,
                principal=DRIVER,
                extension=extension,
                clock=lambda: NOW,
            )
            assert target._recovery_gate_approval == old_approval
            assert target._recovery_gate_authority == recovered.target.authority
            assert target.header == original.header
            assert original.record(old_approval["id"], principal=DRIVER) == old_approval
            grant = GateRecoveryEnrollment(
                recovered.target.authority,
                recovered.target.private_key.public_key(),
                uid("current-member-gate-reapproval-grant"),
                digest(old_approval["body"]["authority"]),
            )
            extension.gate_recovery_enrollments = {digest(grant.authority): grant}
            current_native.enrolled_gate_context = {
                "owner": current,
                "workflow_id": target.workflow_id,
                "authority": grant.authority,
                "grant_id": grant.grant_id,
                "previous_authority_digest": grant.previous_authority_digest,
            }
            command = {
                "id": uid("current-member-gate-reapproval"),
                "workflow_id": target.workflow_id,
                "action": "recover.gate_approve",
                "payload": {"initialization": recovered.target._gate_recovery_initialized},
            }
            new_approval = target._run(command, DRIVER)
            assert new_approval["owner"] == current
            assert new_approval["body"]["authority"] == old_approval["body"]["authority"]
            assert target._recovery_gate_approval == new_approval
            assert current_native.approval == new_approval["body"]["native"]
            assert target._run(command, DRIVER) == new_approval
            with pytest.raises(ContractError, match="already approved"):
                target._run({**command, "id": uid("duplicate-current-member-approval")}, DRIVER)
            with pytest.raises(ContractError, match="recovery only"):
                target._run(
                    {
                        "id": uid("forbidden-restored-member-round"),
                        "workflow_id": target.workflow_id,
                        "action": "round",
                        "payload": {
                            "expected_generation": target.generation,
                            "driver_term": target.driver_term,
                            "to_phase": "draining",
                        },
                    },
                    DRIVER,
                )
        finally:
            if current_journal is not None:
                current_journal.close()
            if current_native is not None:
                current_native.store.close()
            if recovered is not None:
                recovered.endpoint.close()
            run.close()


def test_gate_recovery_cold_reopen_preserves_current_epoch_outcomes(tmp_path):
    meter = WorkMeter()
    with meter.account():
        run = WorkflowRun(tmp_path, LogicalWorkload(children=1), meter)
        recovered = reopened = None
        try:
            run.prepare()
            recovered = recovered_gate(run)
            approve_all(run, recovered)
            _, certificate = recover_successor(run, recovered)
            original = list(recovered.target.journal.iter_events(read_authorized=True))
            recovered.endpoint.close()
            context = dict(recovered.context)
            reopened = WorkflowJournal.open(
                tmp_path / "gate-recovered-first.journal",
                expected_owner=recovered.target.owner,
                expected_schema=run.schema,
                metrics=meter.values,
            )
            context["journal"] = reopened
            target = WorkflowRecoveryGate(**context)
            assert target.record(certificate["id"], principal=DRIVER) == certificate
            assert list(reopened.iter_events(read_authorized=True)) == original
            assert target._gate_recovery_certificate == recovered.target._gate_recovery_certificate
            changed = dict(context)
            origin_owner = run.native[0].owner
            current_owner = {**origin_owner, "epoch": uid("changed-current-member-after-approval")}
            custody = {
                "format": "deployment-ops/owner-history/v1",
                "kind": "OwnerCustody",
                "id": uid("changed-member-custody"),
                "custodian": current_owner,
                "origin": origin_owner,
                "manifest": {
                    "schema": schema_identity(
                        "https://fishhat.invalid/contracts/recovery-set.schema.json"
                    ),
                    "digest": digest("changed exact member custody"),
                },
                "created_at": NOW,
            }
            custody["digest"] = digest(custody)
            changed["extension"] = JournalRecovery(
                current_owners={canonical(origin_owner): current_owner},
                verified_custody={canonical(origin_owner): custody},
            )
            with pytest.raises(
                ContractError, match="independently approved initialization changed"
            ):
                WorkflowRecoveryGate(**changed)
        finally:
            if reopened is not None:
                reopened.close()
            if recovered is not None:
                recovered.endpoint.close()
            run.close()


def test_reapproval_history_uses_one_index_without_recursive_key_layers():
    class InstalledKeys(dict):
        def __iter__(self):
            raise AssertionError("unrelated installed trust was enumerated")

    for count in (1, 16, 128):
        target = SimpleNamespace(keys=InstalledKeys({("original", "key"): "original-key"}))
        index = None
        for number in range(count):
            authority = {
                "owner": {
                    "tool": "host-ops",
                    "id": uid("gate"),
                    "epoch": uid("history-epoch-" + str(number)),
                },
                "key_id": KEY_ID,
            }
            previous = getattr(target, "_recovery_gate_authority", None)
            previous_digest = None if previous is None else digest(previous)
            grant = GateRecoveryEnrollment(
                authority,
                "synthetic-key",
                uid("grant-" + str(number)),
                previous_digest,
            )
            record = {
                "body": {
                    "authority": authority,
                    "native": {
                        "grant_id": grant.grant_id,
                        "previous_authority_digest": previous_digest,
                    },
                }
            }
            retain_recovery_gate(target, record, grant)
            if index is None:
                index = target.keys
            assert target.keys is index
            assert target.keys[(canonical(authority["owner"]), KEY_ID)] == "synthetic-key"
            assert target.keys[("original", "key")] == "original-key"
        assert len(target._recovery_gate_key_index) == count
