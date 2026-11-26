# Fishhat: hard-cut the common recovery policy and adopt contractual CI performance

## Status and first action

This is a researched reference handoff for the Fishhat integration agent, prepared under the maintainer's explicit request to remove the policy/contract/design introduced by the supplied durability delivery and replace its direction with [nashspence/all #64](https://github.com/nashspence/all/issues/64).

The hard-cut direction is decided. Begin the coordinated policy deletion and shared-runner integration; do not build further machinery merely to satisfy the retired recovery model. A short table of independently approved numerical limits is still required before activating performance acceptance. That review does not require design to implement fixtures, a calibrator or another algorithm.

The owning GitHub issue controls the task. This reference branch is research input under [Proffer](https://github.com/nashspence/proffer/blob/2ce5e15c3191fcdc2be70213c0170f57c852a883/README.md), not a product implementation or automatic authority to merge. Do not merge these planning/history files into Fishhat main. Publish the consumer's disposition in the owning issue.

## 1. Inspected sources and attachment lineage

| Item | Inspected identity |
|---|---|
| Fishhat current main | [f96b83dc20f059d62a4363a63c37bb0ef8c642e5](https://github.com/nashspence/fishhat/commit/f96b83dc20f059d62a4363a63c37bb0ef8c642e5) |
| Uploaded file | `fishhat-durability-delivery(1).zip`; SHA-256 `4ac4bf68abe9fbdd37a86656d5b33d90b5918a9418c6401480b9f613375d8bff` |
| Archive base / prepared commit | `930ee3301648b6c0f13c751a2ac8f42990abeaff` / `fbf0f0d7747a8e201818fbf0afb957b6820baa8c` |
| Actual integration | [PR #418](https://github.com/nashspence/fishhat/pull/418), merge [e46bad60c32422f07a0a376615a5a92f2f7e3323](https://github.com/nashspence/fishhat/commit/e46bad60c32422f07a0a376615a5a92f2f7e3323) |
| Shared implementation | [all 29d2af516a91d762094da1da55c71d07d79e095c](https://github.com/nashspence/all/commit/29d2af516a91d762094da1da55c71d07d79e095c), merged through [all PR #65](https://github.com/nashspence/all/pull/65) |
| Storage approval | [all #66](https://github.com/nashspence/all/issues/66), [versioned enrollment](https://github.com/nashspence/all/blob/29d2af516a91d762094da1da55c71d07d79e095c/docs/storage-profile-enrollment.md) |
| Handoff protocol | [Proffer 2ce5e15c3191fcdc2be70213c0170f57c852a883](https://github.com/nashspence/proffer/tree/2ce5e15c3191fcdc2be70213c0170f57c852a883) |

The ZIP manifest's tar, bundle and patch hashes and byte lengths were verified. No attachment program was executed. The archive changed 20 files; the integrated PR changed **57 files, including 37 supplied-adapter descriptors**. Consequently, deleting only the three new durability files or reversing only the archive patch is incomplete.

The current blanket ban on numerical performance gates predates #418. This handoff coordinates two changes: remove the attachment's universal recovery economics, and explicitly supersede the older advisory-only rule for approved production-operation budgets. Do not misattribute all old timing policy to the attachment.

The accompanying [source-evidence-inventory.json](source-evidence-inventory.json) records all 57 paths, all 37 descriptors, the eight schema roots, and the current issue-body audit. It is a dated-by-source research snapshot, not another normative registry.

## 2. Delete the common machinery completely

Implement a pre-v1 hard cut. Do not retain the old model as disabled-by-default configuration, an alias, a compatibility reader, an alternate executor or a renamed common accounting framework.

| Maintained surface | Required disposition |
|---|---|
| [`durability.schema.json`](https://github.com/nashspence/fishhat/blob/f96b83dc20f059d62a4363a63c37bb0ef8c642e5/packages/fishhat-contracts/src/fishhat_contracts/contracts/durability.schema.json) | Remove the repository-wide `RecoveryPolicy` and `Rules` mandate. Remove the file after any independently justified product promises have an appropriate owning contract. |
| [`durability.py`](https://github.com/nashspence/fishhat/blob/f96b83dc20f059d62a4363a63c37bb0ef8c642e5/packages/fishhat-contracts/src/fishhat_contracts/durability.py) | Remove `RecoveryPolicy`, `RecoveryBudget`, `CheckpointCandidate`, `CheckpointDecision`, `recovery_policy`, `checkpoint_decision` and their active consumers/exports/declarations. |
| [`tests/test_durability.py`](https://github.com/nashspence/fishhat/blob/f96b83dc20f059d62a4363a63c37bb0ef8c642e5/tests/test_durability.py) | Remove tests whose sole promise is the retired economic policy or its installed identity. Preserve or move independently justified owner correctness assertions. Do not retain obsolete policy merely to keep test counts unchanged. |
| Eight installed schema roots | Remove the durability-policy closure from `source`, `records`, `adapter`, `workflow`, `workflow-journal`, `ssh-request`, `ssh-response` and `cli-output` schemas. Recompute their current complete identities. |
| 37 `some-implementations/**/descriptor.json` files | Regenerate affected installed schema identities through the maintained tooling. Do not paste pre-#418 digests over later independent contract changes. |
| Owner and contract source | Reconcile policy-dependent comments/declarations in owner `adapter_state.py`, owner `workflow_journal.py` and contracts `workflow_journal.py`, plus any later consumers found by a current-tree search. |
| Generated inventories | Review source-owned declarations, then regenerate `policy/{checks,engineering,interfaces,operations}.json` and `tests/fixtures/index.json` as applicable. Generated agreement does not authorize a semantic change. |
| [`AGENTS.md`](https://github.com/nashspence/fishhat/blob/f96b83dc20f059d62a4363a63c37bb0ef8c642e5/AGENTS.md) | Replace the common durability mandate and every categorical prohibition on performance gates, including the growth, evidence and delivery sections; changing one heading is insufficient. |

Remove these obligations wherever active: the universal adaptive/restart mode, 120-second replay target, one-eighth optional-overhead fraction, the `7*C <= S` and `7*(O+C) <= U` rules, once-credited composed workflow budgets, disjoint optional-spending reservations, overrun debt, restored-credit accounting, policy attempt caps/defaults, mandatory optional-generation counts and matched adaptive-versus-restart measurement requirements.

Durability design returns to the relevant Fishhat owner and operation. Owners may choose efficient persistence, batching, optional recovery or recomputation to meet their actual result/failure promises and raw budgets. There is no obligation to replace the removed framework with another common recovery framework.

**Do not blindly revert PR #418.** Its bounded-work clarification removed an implication that every yield requires durable resumability. Preserve the freedom to fuse internal phases, group safe commits and recompute derived work. A successful hard cut must not recreate per-item/per-yield persistence pressure.

Useful current-tree search terms include `durability.schema`, `fishhat_contracts.durability`, `RecoveryPolicy`, `RecoveryBudget`, `CheckpointCandidate`, `checkpoint_decision`, `replay_target_seconds`, `max_optional_overhead_fraction` and `retained_checkpoint_generations`. Resolve every active reference by meaning; an unrelated occurrence of the number 120 is not evidence of this policy.

## 3. Preserve product promises for independent reasons

The request removes a universal mechanism prescription. It does not authorize silent loss of accepted data, current authorization, effect identity, or an owner's already-promised recovery result.

There is concrete pre-attachment authority for this distinction: the [pre-change owner workflow journal](https://github.com/nashspence/fishhat/blob/930ee3301648b6c0f13c751a2ac8f42990abeaff/fishhat/owner-support/src/fishhat_owner/workflow_journal.py) and [pre-change workflow-journal contract](https://github.com/nashspence/fishhat/blob/930ee3301648b6c0f13c751a2ac8f42990abeaff/packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json) already required journal/HEAD commitment, independent checkpoint continuity, real writer exclusion and acknowledgement after commitment.

In particular:

- The current `CheckpointStore` protects authoritative continuity. It is not the optional computational checkpoint policy being removed. Preserve its required result while allowing reviewed implementation changes.
- Preserve exact accepted bytes and stable request/effect identities; unknown effects require reconciliation, not a new identity and blind replay.
- Preserve current permission, positive exclusion, the declared failure scope, and required acknowledgement/effect ordering.
- Preserve protected state, introduced migrations/fixtures, retained readers, complete result extent and existing growth obligations.
- Keep actual native fault/custody evidence distinct from CI timing evidence.

Do not use “preserve all current durability rules” as a blanket exemption that retains the unwanted framework. For a disputed retained requirement, identify its operation, independently owned result/failure promise and source. If changing that public promise is necessary, make the concrete owning-contract decision explicitly; do not preserve arbitrary internal phase boundaries solely because tests describe them.

## 4. Replace advisory-only authority with small absolute contracts

Adopt [all #64](https://github.com/nashspence/all/issues/64) in Fishhat's maintained policy and executable acceptance path. The shared proposal and implementation exist; Fishhat's consumer adoption is the work here.

The operative rule should be:

> An approved performance contract names a real operation, a shared execution profile and a fixed maximum raw wall-clock duration. A correct, complete execution on an admitted profile that exceeds that limit fails the operation's performance acceptance. Correctness, authorization, custody and extent remain independently required. Missing, unqualified or invalid evidence cannot supply a performance pass.

Use the existing shared formats:

- `.all/performance/limits.json`: operation IDs, profile IDs and actual positive integer `max_wall_ns` values.
- `.all/performance/bindings.json`: separately reviewed bindings to actual operations, timed boundaries, fixture/verifier hashes, commands/adapters and full-process counterparts.

Design/maintainer authority supplies and approves the small numerical table and intended product scope. Integration prepares the real bindings and implementation. The trusted acceptance path selects approved authority independently of the candidate. An integration-proposed budget, easier fixture or narrower completion boundary cannot activate itself merely by appearing in the candidate diff.

**Do not put placeholder numbers into an activated contract or close adoption without concrete approved values.** The remaining authority request is a short ordinary review of those numbers and scope, not a designer-written benchmark, reference program, calibration system or another global architecture pause. Work on the hard cut and bindings can proceed now.

Use only the cases needed for material operation costs. Collection operations normally use 16 real members at supported parallelism 1, 2 and 4 with separate limits. Non-list operations use a meaningful bounded unit. Do not add fake concurrency to a serial authority or hold its required per-request lock outside the measured unit. No mandatory layer matrix, no-durability executor or matched-reference comparison is required.

### Keep suite telemetry useful

The current [`policy/performance.toml`](https://github.com/nashspence/fishhat/blob/f96b83dc20f059d62a4363a63c37bb0ef8c642e5/policy/performance.toml) contains report-only **pytest process** targets, including 30-second/5-second goals. [`scripts/run_stats.py`](https://github.com/nashspence/fishhat/blob/f96b83dc20f059d62a4363a63c37bb0ef8c642e5/scripts/run_stats.py) and [measurement tests](https://github.com/nashspence/fishhat/blob/f96b83dc20f059d62a4363a63c37bb0ef8c642e5/tests/test_performance_measurement.py) enforce that scope.

Do not simply flip `report_only` or convert CPU/memory/test-suite statistics into product contracts. Keep honest validation telemetry and diagnostic profiling while removing the blanket prohibition on independently approved production timing gates. Watchdog/validation timeout scaling never scales a product budget.

## 5. First operation coverage and completion

Start with an available real operation, then attach performance acceptance to the existing implementation packets as other operations become real. This cutover must not wait for every unfinished native owner.

| First coverage | Measurement boundary and next action |
|---|---|
| 16 new-head `CheckpointStore.compare_and_swap` publications, serial | Use the actual guarded installed code, a real fresh head on every call, recurring lock acquisition/release, required file/directory synchronization and publication before returning. Approve its warm maximum and verify all 16 outcomes. |
| Full-process counterpart for the same 16-publication operation | Include launch, imports, initialization attributable to the product, operation completion and foreground process exit. Approve a separate raw maximum. A fast warm result cannot hide startup. |
| Complete journal acknowledgement | Route to [#187](https://github.com/nashspence/fishhat/issues/187) and [#166](https://github.com/nashspence/fishhat/issues/166). When available, measure exact accepted work through its whole promised acknowledgement; the checkpoint primitive alone does not qualify it. |
| Authenticated checkpoint inspection | Route to [#450](https://github.com/nashspence/fishhat/issues/450). Measure the real complete supported exchange as it lands, without expanding that issue into writable authority. |
| Real collection/owner workflows | Attach 16-member supported-concurrency budgets and relevant complete-command/early integrated coverage to their existing owning packets. Preserve complete extent and growth evidence. |

The first pair uses `public-linux-x64-4cpu-prepared-ext4-v2`. Design chooses the actual warm/cold numbers; this handoff invents no approved values.

Existing evidence is informative and deliberately uncomfortable: all #66 measured 36 Fishhat 16-CAS windows, median 13.826 ms, range 9.414–605.141 ms. Two exceeded its separate 320 ms engineering comparison: **473.010732 ms and 605.141475 ms**. That comparison is neither an approved Fishhat budget nor a suggested default. Preserve the misses and investigate their cause; do not fit a larger budget to the slowest observation or select the fastest repeat. The [enrollment record](https://github.com/nashspence/all/blob/29d2af516a91d762094da1da55c71d07d79e095c/docs/storage-profile-enrollment.md) gives the source and limits of that evidence.

Before accepting an architecture on which broad implementation depends, obtain one small complete user workflow within its own approved budget. Before release, require separate non-CI large end-to-end qualification with representative extent, backend/history, completion/drain and appropriate interruption/recovery, under its own raw maximum. Tiny CI fixtures and the 256 MiB prepared resource do not establish a large-backend release claim.

## 6. Install the shared runner as an actual candidate acceptance path

Use the pinned [common performance contract](https://github.com/nashspence/all/blob/29d2af516a91d762094da1da55c71d07d79e095c/docs/performance.md) and [prepared-storage recipe](https://github.com/nashspence/all/blob/29d2af516a91d762094da1da55c71d07d79e095c/docs/prepared-storage.md). Reuse the implementation; do not fork its timer, storage admission or acceptance rule.

1. Select **three independent revisions** in trusted workflow configuration: approved shared package, approved limits/bindings, and exact candidate. Record all three.
2. Install the shared package and actual candidate with their required runtime/provenance outside a clean candidate source tree. Prepared v2 requires **Python 3.12.16**, public Ubuntu 24.04 x64, four available CPUs and at least 14 GiB memory.
3. Use shared `prepared_storage` setup once for a bounded cohort. Admit both actual protected ext4 resources through the shared path. Keep control reports and installed tooling outside the tested mounts.
4. Invoke the installed isolated parent, `python -I -B -m all_policy performance`, with approved authority/revision, `--repository nashspence/fishhat`, exact candidate and the admitted storage root.
5. Make each `run` do fresh useful work and complete recurring locks, synchronization, acknowledgement, joins and drain. Fixture setup cannot precompute the result. Verification checks completion; it cannot supply omitted work. Teardown cannot defer the real publication.
6. Retain exactly three complete observations. Every value must be within the unchanged approved maximum. Keep pass, miss, unqualified and failed outcomes distinct; only pass succeeds.
7. Always verify/clean up owned resources and preserve the gate's original nonzero status. Retain raw timing, setup/postflight/cleanup, correctness, source and installation evidence, including failures.
8. Install this outcome in the protected **exact-candidate** acceptance path and demonstrate that a failed/missing result cannot be treated as success.

### Critical GitHub Actions wiring

Prepared v2 accepts actual trusted `push`, `workflow_dispatch` and `schedule` contexts on explicitly allowlisted `refs/heads/main`. It is not automatically a `pull_request` job.

Use a reviewed trusted-dispatch arrangement that selects the reviewed candidate independently, executes against that exact source, and associates the required result with that exact candidate SHA. Verify the protected review/required-check wiring. A main-only report after merge or a scheduled run does not establish PR acceptance. Never falsify `GITHUB_EVENT_NAME`/`GITHUB_REF`, bypass guards, import approval from candidate code, or automatically execute an unreviewed privileged candidate.

If the required-check association or trusted dispatch cannot be completed with available permissions, record that exact infrastructure blocker; do not claim that an advisory job installed the required gate. Do not add unrelated workflow permissions or weaken the existing protected merge path.

### What the profile does and does not promise

The shared owner supplies a verified storage configuration and generic correct bounded probes. It does **not** supply a ±percentage precision guarantee, fixed CPU-speed envelope or operation-specific noise correction. Raw time remains raw time; diagnostic probes and later reruns cannot erase an admitted miss.

The two filesystems share a backing host/failure domain. Their timing approval is not a power-loss certificate and does not replace [#435](https://github.com/nashspence/fishhat/issues/435)/[#439](https://github.com/nashspence/fishhat/issues/439)'s actual installed custody evidence or [#165](https://github.com/nashspence/fishhat/issues/165)'s separate qualification. Do not time a host temporary directory and call it guest-store qualification.

The weekly twelve-worker campaign remains centrally owned by `all`. Fishhat runs ordinary per-cohort admission and its own operation budgets, not a copied research matrix. Follow the active shared approval/suspension decision. No automatic remote revocation or hardware-error allowance is implied.

## 7. Reconcile the entire issue surface

The paginated audit found **169 open Fishhat issues**, excluding four open PRs. **151 issue bodies** contain advisory/no-gate language; **126** contain the exact “Numerical performance misses” boilerplate. The companion inventory lists every matching issue and its observed clause. This is a body-only snapshot; inspect current comments and native relations before changing disposition.

Follow current Fishhat issue governance: preserve historical bodies, record superseding decisions in comments, link/pin the current decision where it changes the next step, use native sub-issues/dependencies, and keep completion histories intact. Do not rewrite or reopen completed issues merely to alter old language.

| Surface | Required update |
|---|---|
| [#137](https://github.com/nashspence/fishhat/issues/137), [#48](https://github.com/nashspence/fishhat/issues/48) | Publish the controlling cutover decision and update navigation/acceptance interpretation. Remove the universal advisory exemption for approved product contracts while retaining correctness, extent, growth and native-evidence ownership. |
| [#84](https://github.com/nashspence/fishhat/issues/84) | Preserve profiling history and useful suite-cost investigation. Supersede its categorical ban on numerical product gates; suite telemetry itself remains observational. |
| [#162](https://github.com/nashspence/fishhat/issues/162), [#166](https://github.com/nashspence/fishhat/issues/166), [#165](https://github.com/nashspence/fishhat/issues/165), [#187](https://github.com/nashspence/fishhat/issues/187) | Route concrete raw operation-budget/binding acceptance to the appropriate remaining work; preserve their unfinished authority, effects, migration and failure promises. |
| [#450](https://github.com/nashspence/fishhat/issues/450) | Replace the advisory exemption for its future approved operation contract. Preserve its authenticated non-mutating inspection scope; no writable admission is implied. |
| All other matched active issues | Add a concise linked supersession/disposition tailored to their scope. Product budget misses block affected acceptance once the approved contract applies. Non-applicable validation/infrastructure metrics remain identified as such. Inspect later comments; do not assume every old sentence is still controlling. |
| [#144](https://github.com/nashspence/fishhat/issues/144), #435, #439, merged PR #418 | Preserve completed history and evidence. Add a linked supersession note for retired common-policy references where needed; use follow-ups for new work. |

A suitable decision comment distinguishes “ordinary run statistics remain observations” from “a miss of an approved production-operation maximum prevents acceptance.” Link the owning operation/contract and this cutover issue, and name any genuine missing capability. Do not imply that the issue's old text has become fresh approval for a timing exemption.

Retire open tasks whose **sole** purpose is implementing removed recovery economics, after recording the exact replacement and transferring any independent outcome obligation. Do not mass-close useful implementation issues because they contain obsolete boilerplate. Reconcile references to all #35 and #64, implementation dependencies, and active PRs before declaring the issue surface complete. Report audit coverage and unresolved exceptions in the owning issue, not a new main-branch tracking file.

## 8. Execution sequence and acceptance

Keep the work in a few reviewable packets under this owning issue using native dependencies. The maintainer has already authorized the direction; the sequence must not preserve old machinery until every future product operation is implemented.

1. Resolve current-source drift and publish the controlling issue decisions. Identify the small available-operation numerical table for ordinary independent approval.
2. Remove the common policy/module/sole-purpose tests and installed closure; replace contradictory developer policy; regenerate affected identities and projections together. Preserve independent promises and legitimate implementation freedom.
3. Complete the approved first warm/full-process operation pair and trusted exact-candidate CI acceptance, retaining real observed outcomes.
4. Reconcile the active issue surface, attach future operation requirements to existing owner packets, and record adoption evidence and Proffer disposition.

Acceptance for this cutover:

- The retired common framework has no active schema/API/configuration/closure/test mandate or compatibility path.
- Current contract identities and all affected adapter descriptors/projections are consistent; protected state/history is preserved.
- Fishhat's maintained policy states raw production-operation acceptance without contradicting advisory-only clauses elsewhere.
- The initial available operation and its cold counterpart have **concrete independently approved numbers**, reviewed bindings and actual admitted exact-candidate CI results. Missing/unqualified/failed evidence or a budget miss is not called acceptance.
- The protected required path demonstrably reports and enforces candidate results; it is not merely a post-merge or periodic dashboard.
- The issue audit has a recorded disposition for every still-relevant conflicting active instruction, with current relationships and honest blockers.
- Future complete-journal/inspection/owner and pre-release large-work requirements are assigned to their real existing owners, without claiming unfinished capabilities are implemented.
- Required local/PR/native checks applicable to the changed claims are reported for the delivered implementation. Proffer record validation and this research are not those checks.
- The consumer posts a Proffer disposition naming adopted/adapted/rejected parts, actual integration commit(s), checks and remaining limitations.

Do not require completion of all Fishhat native implementation issues to close this bounded policy/shared-runner cutover. Conversely, deleting documents alone is insufficient: the available-operation contract and required measurement path must actually work.

## 9. Validation performed for this reference

Performed: attachment checksum/byte-length verification; current-source and integrated-diff review; complete pagination/body scan of open issues; independent reviews of lineage, Proffer protocol and acceptance semantics; validation of the Proffer records against the pinned protocol; publication identity/content verification.

Not performed: implementation of the Fishhat cutover, new product timing runs, product `make check`/native/release qualification, approval of Fishhat numerical budgets, or activation of required consumer checks. No speedup, precision bound, native authority or release claim follows from this reference.

The published checks and exact handoff commit are recorded in the owning issue. Re-read live issue decisions and rebase the research on actual current source before integration.
