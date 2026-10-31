"""Original journal bytes survive independently approved current-epoch recovery."""

from copy import deepcopy
from dataclasses import replace

import pytest
from fishhat_contracts.handoffs import PHASES, schema_identity
from fishhat_contracts.record_delivery import RecordSnapshot
from fishhat_contracts.validation import ContractError, canonical, digest
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_journal import GateEnrollment, WorkflowGate, WorkflowMember
from fishhat_contracts.workflow_journal_recovery import (
    JournalRecovery,
    OriginRecoveryContext,
    WorkflowRecoveryMember,
)
from fishhat_owner.workflow_journal import WorkflowJournal

from tests.test_contracts import uid
from tests.test_owner_history import seal_custody
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
    child_key,
    require,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-history.schema.json",
    ],
    "scope": "exact original epoch custody, qualified historical readers, exclusive successor retirement and preserved completed Operations",
    "relationship": "candidate",
    "reason": "Real source and current-owner file journals are closed and reopened using only paths and independently enrolled keys; synthetic protected native custody does not qualify production restoration.",
    "claims": [],
}

CHECK_OVERRIDES = {
    name: {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_journal_recovery.py#WorkflowRecoveryMember.__init__",
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json",
            "release.toml#/engineering",
        ],
        "scope": "one complete authenticated replay of original local custody and current recovery events with unchanged original bytes",
        "relationship": "scoped-witness",
        "reason": "Reference execution exercises the exact restored-member boundary and measures all preparation, native files, cryptographic input, cold reads, and successor work at increasing local history extent.",
        "claims": ["engineering:workflow.journal-recovery.member-restore"],
    }
    for name in (
        "test_restored_epoch_requires_exact_custody_and_preserves_original_bytes",
        "test_restored_epoch_recovery_is_linear",
    )
}


class CurrentNative:
    """Independent synthetic current owner with retained native restoration facts."""

    def __init__(self, original, owner, custody, source, path, meter, *, restore=False):
        self.original, self.owner, self.custody = original, owner, custody
        self.source_head, self.source_schema = source.head, source.schema
        self.meter = meter
        self.store = (
            WorkflowJournal.open(
                path, expected_owner=owner, expected_schema=source.schema, metrics=meter.values
            )
            if restore
            else WorkflowJournal.create(
                path, owner=owner, schema=source.schema, metrics=meter.values
            )
        )
        self.successor = None
        self.facts = {}
        self.abandonments = {}
        self.abandoned = set()
        self.used = set()
        for event in self.store.iter_events(read_authorized=True):
            self._apply(event["request"], event["outcome"])
        if not restore:
            self._append(
                "adopt",
                {"custody": custody, "source_head": source.head, "source_schema": source.schema},
            )

    def _append(self, action, outcome):
        identifier = action + "-" + str(len(self.store._index))
        self.store.append(identifier, {"action": action}, outcome, expected_head=self.store.head)
        self._apply({"action": action}, outcome)

    def _apply(self, request, outcome):
        action = request["action"]
        if action == "adopt":
            self.adoption = outcome
        elif action == "retire":
            self.successor = outcome["successor_workflow_id"]
            self.facts[self.successor] = outcome
        elif action == "abandon":
            self.abandonments[outcome["successor_workflow_id"]] = outcome
        elif action == "observe-abandon":
            self.abandoned.add(outcome["successor_workflow_id"])
            self.successor = None
        elif action == "used":
            self.used.add(outcome["successor_workflow_id"])
        else:
            raise AssertionError(action)

    def authorize(self, principal, action, context):
        require(principal in {DRIVER, NEXT_DRIVER}, "current native permission denied")
        require(context["owner"] == self.owner, "current native owner scope changed")

    def restore_recovery(self, context):
        require(
            context["owner"] == self.owner
            and context["origin"] == self.original.owner
            and context["custody"] == self.custody == self.adoption["custody"]
            and context["source_head"] == self.adoption["source_head"] == self.source_head
            and context["source_schema"] == self.adoption["source_schema"] == self.source_schema,
            "native independently approved restoration custody changed",
        )
        require(
            self.original.prepared is not None, "native positive original preparation unavailable"
        )
        self.meter.values["native_restoration_checks"] += 1

    def result_payload(self, operation):
        return self.original.result_payload(operation)

    def recovery_disposition(self, projection):
        recovery = projection["recovery"]
        successor = recovery["successor_workflow_id"]
        require(
            successor not in self.abandoned and self.successor in {None, successor},
            "native successor is abandoned or another candidate is reserved",
        )
        if successor in self.facts:
            return deepcopy(self.facts[successor])
        require(
            projection["owner"] == self.owner
            and projection["origin_owner"] == self.original.owner
            and projection["custody"] == self.custody,
            "native recovery owner mapping changed",
        )
        children = []
        for pair in projection["mapping"]:
            key = child_key(pair["origin"])
            self.meter.values["native_recovery_slot_visits"] += 1
            require(key in self.original._allowed_children, "native original slot not retained")
            operation = self.original.operations.get(key)
            require(
                operation is not None and operation["state"] == "succeeded",
                "native completed outcome unavailable",
            )
            children.append(
                {
                    "origin": pair["origin"],
                    "kind": "completed",
                    "operation": operation,
                    "operation_reference": RecordSnapshot(
                        operation, uid("historical-operation-" + operation["id"])
                    ).reference,
                    "recovery": None,
                    "native_stopped": True,
                }
            )
        self._material()
        facts = {
            **{
                name: recovery[name]
                for name in (
                    "origin_workflow_id",
                    "origin_proposal_digest",
                    "successor_workflow_id",
                    "successor_proposal_digest",
                )
            },
            "origin_projection_digest": projection["origin_projection_digest"],
            "preparation": "prepared",
            "admission_retired": True,
            "successor_reserved": True,
            "custody_digest": self.store.head,
            "children": children,
        }
        self._append("retire", facts)
        return deepcopy(facts)

    def _material(self):
        require(
            self.meter.read_material(self.original.root / "source.material")
            == self.original.workload.material(self.original.index),
            "original material custody changed",
        )

    def check_recovery(self, projection, facts, certificate):
        successor = projection["recovery"]["successor_workflow_id"]
        require(
            self.successor == successor
            and self.facts.get(successor) == facts
            and certificate["body"]["recovery"] == projection["recovery"],
            "native exact successor reservation unavailable",
        )
        self._material()

    def abandon_recovery(self, projection, proposal):
        recovery = projection["recovery"]
        successor = recovery["successor_workflow_id"]
        require(
            self.successor == successor and successor not in self.used,
            "native successor was used or is not reserved",
        )
        require(proposal["recovery"] == recovery, "native abandonment candidate changed")
        facts = {
            **{
                name: recovery[name]
                for name in (
                    "origin_workflow_id",
                    "successor_workflow_id",
                    "successor_proposal_digest",
                )
            },
            "unused": True,
            "successor_admission_closed": True,
            "native_stopped": True,
            "custody_digest": self.store.head,
        }
        self._append("abandon", facts)
        return deepcopy(facts)

    def observe_abandonment(self, projection, facts, certificate):
        successor = projection["recovery"]["successor_workflow_id"]
        require(
            self.abandonments.get(successor) == facts
            and certificate["body"]["recovery"] == projection["recovery"],
            "native abandonment closure changed",
        )
        self._append("observe-abandon", {"successor_workflow_id": successor})


def original_run(root, workload, meter):
    run = WorkflowRun(root, workload, meter)
    try:
        run.prepare()
        for phase in PHASES["host-drain"][1:]:
            run.round(phase)
            if phase == "host-effect":
                run.children()
        run.assert_complete()
    finally:
        run.close()


class EpochRun:
    def __init__(self, root, workload, meter, *, restore=False):
        self.original = WorkflowRun(root, workload, meter, restore=True)
        self.root, self.workload, self.meter = root, workload, meter
        self.members, self.native, self.contexts, self.keys, self.custody = [], [], [], [], {}
        self.owners = {}
        recovery_schema = schema_identity(
            "https://fishhat.invalid/contracts/recovery-set.schema.json"
        )
        for index, old in enumerate(self.original.members):
            origin = old.target.owner
            current = {**origin, "epoch": uid("restored-journal-" + origin["id"])}
            custody = seal_custody(
                {
                    "format": "deployment-ops/owner-history/v1",
                    "kind": "OwnerCustody",
                    "id": uid("journal-custody-" + origin["id"]),
                    "custodian": current,
                    "origin": origin,
                    "manifest": {
                        "schema": recovery_schema,
                        "digest": digest(
                            {
                                "source_head": old.target.journal.head,
                                "native_head": self.original.native[index].store.head,
                            }
                        ),
                    },
                    "created_at": NOW,
                    "digest": "sha256:" + "0" * 64,
                }
            )
            self.owners[canonical(origin)], self.custody[canonical(origin)] = current, custody
        self.extension = JournalRecovery(current_owners=self.owners, verified_custody=self.custody)
        self.original.gate.target.extension = self.extension
        self.original.gate.target.keys = dict(self.original.gate.target.keys)
        for index, old in enumerate(self.original.members):
            origin = old.target.owner
            current, custody = self.owners[canonical(origin)], self.custody[canonical(origin)]
            key = MeteredPrivateKey(current, meter.values)
            self.keys.append(key)
            actor = CurrentNative(
                self.original.native[index],
                current,
                custody,
                old.target.journal,
                root / f"current-native-{index}.journal",
                meter,
                restore=restore,
            )
            self.native.append(actor)
            context = OriginRecoveryContext(
                old.target.journal,
                old.target.journal.schema,
                old.target.signed_projection,
                old.target.enrollment,
                custody,
                {(canonical(origin), KEY_ID): self.original.keys[index].public_key()},
            )
            self.contexts.append(context)
            store = (
                WorkflowJournal.open(
                    root / f"current-{index}.journal",
                    expected_owner=current,
                    expected_schema=self.original.schema,
                    metrics=meter.values,
                )
                if restore
                else WorkflowJournal.create(
                    root / f"current-{index}.journal",
                    owner=current,
                    schema=self.original.schema,
                    metrics=meter.values,
                )
            )
            target = WorkflowRecoveryMember(
                context,
                owner=current,
                key_id=KEY_ID,
                private_key=key,
                native=actor,
                operation_keys={(canonical(current), KEY_ID): key.public_key()},
                journal=store,
                principal=DRIVER,
                extension=self.extension,
                clock=lambda: NOW,
            )
            self.members.append(Endpoint(target, root / f"current-inputs-{index}", meter))
            self.original.gate.target.keys[(canonical(current), KEY_ID)] = key.public_key()
        self.successors = []

    def proposal(self, label="one"):
        proposal, mapping = self.original.successor()
        proposal["workflow_id"] = uid("epoch-successor-" + label)
        for participant in proposal["participants"]:
            participant["owner"] = self.owners[canonical(participant["owner"])]
        for pair in mapping:
            pair["successor"]["owner"] = self.owners[canonical(pair["origin"]["owner"])]
        proposal["target"] = {"host_change": mapping[0]["successor"]}
        return proposal, mapping

    def inspect(self, label="one"):
        proposal, mapping = self.proposal(label)
        gate = self.original.gate
        gate.call("recover.propose", {"successor": proposal, "mapping": mapping})
        for member in self.members:
            projection = gate.call("recover.projection", {"owner": member.target.owner})
            disposition = member.call("recover.inspect", {"projection": projection})
            gate.call("recover.collect", {"disposition": disposition})
        return proposal

    def finish(self, proposal):
        gate = self.original.gate
        certificate = gate.call("recover.commit")
        for member in self.members:
            member.call("recover.install", {"certificate": certificate})
        gate_store = WorkflowJournal.create(
            self.root / "epoch-successor-gate.journal",
            owner=gate.target.owner,
            schema=self.original.schema,
            metrics=self.meter.values,
        )
        successor_gate = WorkflowGate(
            proposal,
            owner=gate.target.owner,
            key_id=KEY_ID,
            private_key=self.original.gate_key,
            member_keys=gate.target.keys,
            authorize=self.original.authorize_gate,
            check_reservation=self.original.check_reservation,
            journal=gate_store,
            principal=NEXT_DRIVER,
            extension=self.extension,
            recovery_context=self.extension.context(gate.target, principal=DRIVER),
            clock=lambda: NOW,
        )
        self.successors.append(successor_gate)
        for index, (member, actor) in enumerate(zip(self.members, self.native, strict=True)):
            signed = successor_gate.projection(member.target.owner, principal=NEXT_DRIVER)
            body = {key: value for key, value in signed["body"].items() if key != "command_digest"}
            grant = GateEnrollment(
                successor_gate.workflow_id,
                successor_gate.header["proposal_digest"],
                gate.target.owner,
                KEY_ID,
                self.original.gate_key.public_key(),
                member.target.owner,
                digest(body),
                uid("new-epoch-grant-" + str(index)),
            )
            store = WorkflowJournal.create(
                self.root / f"epoch-successor-member-{index}.journal",
                owner=member.target.owner,
                schema=self.original.schema,
                metrics=self.meter.values,
            )
            target = WorkflowMember(
                signed,
                owner=member.target.owner,
                key_id=KEY_ID,
                private_key=self.keys[index],
                enrollment=grant,
                operation_keys=member.target.keys,
                native=actor,
                journal=store,
                principal=NEXT_DRIVER,
                extension=self.extension,
                recovery_context=self.extension.context(member.target, principal=DRIVER),
                clock=lambda: NOW,
            )
            self.successors.append(target)
            for key, (_, binding) in target.children.items():
                assert target.outcomes[key] == binding["completed"]["operation"]
                assert target.outcomes[key]["owner"] == self.contexts[index].enrollment.member_owner
                with pytest.raises(ContractError, match="completed"):
                    target.admit(
                        uid("reject-completed-" + binding["request_id"]),
                        {"owner": target.owner, "request_id": binding["request_id"]},
                        principal=NEXT_DRIVER,
                    )

    def close(self):
        for target in self.successors:
            target.journal.close()
        for member in self.members:
            member.close()
        for actor in self.native:
            actor.store.close()
        self.original.close()


def exercise_epoch(root, workload, meter):
    original_run(root, workload, meter)
    # Store filenames are selected by the native fixture; exact originals remain
    # available only from disk after both generations of live objects are closed.
    first = EpochRun(root, workload, meter)
    original_paths = [member.target.journal._path for member in first.original.members]
    before = [path.read_bytes() for path in original_paths]
    expected = [dict(member.target.outcomes) for member in first.members]
    first.close()
    del first
    restored = EpochRun(root, workload, meter, restore=True)
    try:
        assert [member.target.outcomes for member in restored.members] == expected
        proposal = restored.inspect()
        restored.finish(proposal)
    finally:
        restored.close()
    assert [path.read_bytes() for path in original_paths] == before
    meter.retained(root)
    return meter.values


def test_restored_epoch_requires_exact_custody_and_preserves_original_bytes(tmp_path):
    meter, workload = WorkMeter(), LogicalWorkload(owners=2, children=2)
    exercise_epoch(tmp_path / "complete", workload, meter)
    root = tmp_path / "adverse"
    original_run(root, LogicalWorkload(owners=1, children=1), meter)
    run = EpochRun(root, LogicalWorkload(owners=1, children=1), meter)
    try:
        context, member = run.contexts[0], run.members[0].target
        wrong = deepcopy(context.custody)
        wrong["manifest"]["digest"] = digest("unapproved-restoration")
        seal_custody(wrong)
        store = WorkflowJournal.create(
            root / "unapproved.journal", owner=member.owner, schema=run.original.schema
        )
        try:
            with pytest.raises(ContractError, match="approved"):
                WorkflowRecoveryMember(
                    replace(context, custody=wrong),
                    owner=member.owner,
                    key_id=KEY_ID,
                    private_key=run.keys[0],
                    native=run.native[0],
                    operation_keys=member.keys,
                    journal=store,
                    principal=DRIVER,
                    extension=run.extension,
                )
        finally:
            store.close()
        old_schema = {**run.original.schema, "digest": digest("exact-approved-historical-profile")}
        historical = WorkflowJournal.create(
            root / "historical.journal", owner=context.source.owner, schema=old_schema
        )
        historical_projection = run.original.gate.target._sign(
            {**context.signed_projection["body"], "historical_note": "exact-old-v1"},
            context.signed_projection["id"],
        )
        historical_projection_digest = digest(
            {
                key: value
                for key, value in historical_projection["body"].items()
                if key != "command_digest"
            }
        )
        historical_origin = replace(
            context,
            signed_projection=historical_projection,
            enrollment=replace(context.enrollment, projection_digest=historical_projection_digest),
        )
        for event in context.source.iter_events(read_authorized=True):
            request, outcome = event["request"], event["outcome"]
            if request["action"] == "member.join":
                request = {**request, "payload": {"projection": historical_projection}}
                body = {
                    **outcome["body"],
                    "projection_digest": historical_projection_digest,
                    "command_digest": digest(request),
                }
                outcome = run.original.members[0].target._sign(body, outcome["id"])
            elif request["action"] == "complete":
                body = {**outcome["body"], "historical_note": "exact-old-v1"}
                outcome = run.original.members[0].target._sign(body, outcome["id"])
            historical.append(event["event_id"], request, outcome, expected_head=historical.head)
        store = WorkflowJournal.create(
            root / "missing-reader.journal", owner=member.owner, schema=run.original.schema
        )
        try:
            with pytest.raises(ContractError, match="qualified recovery reader"):
                WorkflowRecoveryMember(
                    replace(historical_origin, source=historical, source_schema=old_schema),
                    owner=member.owner,
                    key_id=KEY_ID,
                    private_key=run.keys[0],
                    native=run.native[0],
                    operation_keys=member.keys,
                    journal=store,
                    principal=DRIVER,
                    extension=run.extension,
                )
        finally:
            store.close()
        accepted_custody = deepcopy(context.custody)
        accepted_custody["id"] = uid("qualified-historical-custody")
        accepted_custody["manifest"]["digest"] = digest(
            {"source_head": historical.head, "native_head": run.original.native[0].store.head}
        )
        seal_custody(accepted_custody)
        profile = (old_schema["uri"], old_schema["digest"])
        reads = []

        def qualified_reader(record):
            require(
                record["body"].get("historical_note", "exact-old-v1") == "exact-old-v1",
                "historical semantic profile changed",
            )
            reads.append(record["id"])

        approved = JournalRecovery(
            current_owners=run.owners,
            verified_custody={canonical(context.enrollment.member_owner): accepted_custody},
            retained_readers={profile: qualified_reader},
            recovery_readers={profile: qualified_reader},
        )
        native = CurrentNative(
            run.original.native[0],
            member.owner,
            accepted_custody,
            historical,
            root / "qualified-native.journal",
            meter,
        )
        store = WorkflowJournal.create(
            root / "qualified-current.journal", owner=member.owner, schema=run.original.schema
        )
        historical_bytes = historical._path.read_bytes()
        try:
            protected = {
                "origin": replace(
                    historical_origin,
                    source=historical,
                    source_schema=old_schema,
                    custody=accepted_custody,
                ),
                "owner": member.owner,
                "key_id": KEY_ID,
                "private_key": run.keys[0],
                "native": native,
                "operation_keys": member.keys,
                "journal": store,
                "extension": approved,
            }
            command = {
                "id": uid("qualified-historical-initialize"),
                "workflow_id": member.workflow_id,
                "action": "member.recover",
                "payload": {"projection_digest": digest(historical_projection)},
            }
            wrong_digest = {
                **command,
                "id": uid("wrong-historical-initialize"),
                "payload": {"projection_digest": digest("another-original-record")},
            }
            before = store.head, native.store.head
            with pytest.raises(ContractError, match="independently restored custody"):
                run.original.initialize(
                    wrong_digest, protected, root / "wrong-recovery-initialize.input"
                )
            assert (store.head, native.store.head) == before
            restored = run.original.initialize(
                command, protected, root / "qualified-recovery-initialize.input"
            )
            assert restored.outcomes == member.outcomes and reads
            assert historical_projection["id"] in reads
            assert historical._path.read_bytes() == historical_bytes
        finally:
            store.close()
            native.store.close()
            historical.close()
        with pytest.raises(ContractError, match="recovery only"):
            member._run(
                member._command(
                    "prepare",
                    uid("forbidden-original"),
                    {"expected_generation": member.generation, "driver_term": member.driver_term},
                ),
                DRIVER,
            )
    finally:
        run.close()


def test_restored_epoch_recovery_is_linear(tmp_path):
    samples = []
    for children in (1, 4, 16):
        meter = WorkMeter()
        workload = LogicalWorkload(owners=2, children=children, evidence_bytes=128)
        continuation_edges = workload.extent()["continuation_edges"]
        with meter.account():
            counts = exercise_epoch(tmp_path / str(children), workload, meter)
        # The initial Plan is already bound. Every causal successor is bound
        # exactly once; cold replay and preserved completed recovery add none.
        assert counts["native_bind_visits"] == continuation_edges
        samples.append((children, counts))
    baseline_extent, baseline = samples[0]
    for extent, counts in samples[1:]:
        for metric in baseline.keys() | counts.keys():
            if metric == "native_bind_visits":
                # Exact logical-edge equality above also checks the zero-edge
                # baseline, which cannot calibrate a proportional cost bound.
                continue
            assert counts[metric] * baseline_extent <= 1.25 * baseline[metric] * extent, (
                metric,
                samples,
            )


def test_unused_successor_requires_complete_positive_abandonment(tmp_path):
    meter, workload = WorkMeter(), LogicalWorkload(owners=2, children=1)
    used_root = tmp_path / "used"
    original_run(used_root, workload, meter)
    used = EpochRun(used_root, workload, meter)
    try:
        used.inspect()
        successor = used.native[0].successor
        used.native[0]._append("used", {"successor_workflow_id": successor})
        proposal = used.original.gate.call("recover.abandon_start")
        with pytest.raises(ContractError, match="used"):
            used.members[0].call("recover.abandon", {"proposal": proposal})
        with pytest.raises(ContractError, match="closure"):
            used.original.gate.call("recover.abandon_commit")
    finally:
        used.close()
    complete_root = tmp_path / "unused"
    original_run(complete_root, workload, meter)
    run = EpochRun(complete_root, workload, meter)
    try:
        run.inspect()
        gate = run.original.gate
        proposal = gate.call("recover.abandon_start")
        with pytest.raises(ContractError, match=r"incomplete|committed"):
            gate.call("recover.commit")
        one = run.members[0].call("recover.abandon", {"proposal": proposal})
        gate.call("recover.collect_abandon", {"abandonment": one})
        with pytest.raises(ContractError, match="closure"):
            gate.call("recover.abandon_commit")
        with pytest.raises(ContractError, match="duplicated"):
            gate.call("recover.collect_abandon", {"abandonment": one})
        second = run.members[1].call("recover.abandon", {"proposal": proposal})
        gate.call("recover.collect_abandon", {"abandonment": second})
        certificate = gate.call("recover.abandon_commit")
        for member in run.members:
            member.call("recover.observe_abandon", {"certificate": certificate})
            assert run.extension.blocks_work(member.target)
        replacement = run.inspect("two")
        run.finish(replacement)
    finally:
        run.close()


def test_unknown_disposition_advances_only_with_exact_successful_native_recovery(tmp_path):
    meter = WorkMeter()
    run = WorkflowRun(tmp_path, LogicalWorkload(owners=1, children=1), meter)
    try:
        run.prepare()
        for phase in PHASES["host-drain"][1:]:
            run.round(phase)
            if phase == "host-effect":
                run.children(unknown_at=(0, 0))
                break
        run.recover(commit=False)
        member, actor, gate = run.members[0], run.native[0], run.gate
        state = member.target._recovery_state["recovery"]
        previous = state["disposition"]
        origin = run.workload.child(0, 0)
        original_bytes = canonical(actor.operations[child_key(origin)])
        with pytest.raises(ContractError, match="unknown"):
            gate.call("recover.commit")

        def invalid(context):
            return {
                **context["previous"],
                "kind": "unaccepted",
                "operation": None,
                "operation_reference": None,
                "native_stopped": True,
            }

        actor.reconcile_recovery = invalid
        query = {"origin": origin, "previous_disposition_id": previous["id"]}
        with pytest.raises(ContractError, match="preserve exact original"):
            member.call("recover.reconcile", query)

        def reconcile(context):
            plan = deepcopy(context["original_binding"]["plan"])
            plan["id"] = uid("positive-native-recovery-plan")
            plan["subject"] = {
                "action": "operation.recover",
                "resource": plan["subject"]["resource"],
                "arguments": {
                    "operation_id": context["previous"]["operation"]["id"],
                    "disposition": "native-reconcile",
                    "origin": None,
                },
            }
            plan["digest"] = digest(
                {key: value for key, value in plan.items() if key not in {"digest", "witness"}}
            )
            witness = {key: value for key, value in plan["witness"].items() if key != "signature"}
            witness.update(
                id=uid("positive-native-recovery-plan-witness"), subject_digest=plan["digest"]
            )
            plan["witness"] = sign(witness, actor.key)
            operation = deepcopy(context["previous"]["operation"])
            operation.update(
                id=uid("positive-native-recovery-operation"),
                request_id=uid("positive-native-recovery-request"),
                subject=plan["subject"],
                plan_digest=plan["digest"],
                state="succeeded",
                effect_certainty="known",
            )
            witness = {
                key: value for key, value in operation["witness"].items() if key != "signature"
            }
            witness.update(
                id=uid("positive-native-recovery-witness"),
                workflow_id=None,
                state="succeeded",
                subject_digest=digest(
                    {key: value for key, value in operation.items() if key != "witness"}
                ),
            )
            operation["witness"] = sign(witness, actor.key)
            fact = {
                **context["previous"],
                "kind": "recovered",
                "native_stopped": True,
                "recovery": {
                    "reference": RecordSnapshot(
                        operation, uid("positive-native-recovery-snapshot")
                    ).reference,
                    "operation": operation,
                    "plan": plan,
                },
            }
            facts = {**actor.dispositions[actor.successor], "children": [fact]}
            actor._append("positive-native-recovery", "recover", facts)
            return fact

        actor.reconcile_recovery = reconcile
        update = member.call("recover.reconcile", query)
        gate.call("recover.collect_update", {"update": update})
        with pytest.raises(ContractError, match="predecessor"):
            gate.call("recover.collect_update", {"update": update})
        certificate = gate.call("recover.commit")
        member.call("recover.install", {"certificate": certificate})
        context = JournalRecovery().context(member.target, principal=DRIVER)
        assert context.disposition["body"]["facts"]["children"][0]["kind"] == "recovered"
        assert canonical(actor.operations[child_key(origin)]) == original_bytes
        assert (
            context.disposition["body"]["facts"]["children"][0]["operation"]
            == actor.operations[child_key(origin)]
        )
    finally:
        run.close()
