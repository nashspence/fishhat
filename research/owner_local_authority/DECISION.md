# Host-local owner authority: contract-boundary research

This is **non-normative research about the contracts on `main`**. It does not
introduce an owner, journal, target database, fence, IPC protocol, executor,
recovery method, or replacement implementation. The installed receiving owner
and its existing owned state remain the *only* management authority for its
accepted host-local work. Tests here call the maintained reference `Journal`;
that reference itself is **not** an installed, native-qualified owner.

## Authoritative boundaries already on `main`

| Question | Existing owner of the answer |
| --- | --- |
| Host-local acceptance and independent recovery | `AGENTS.md` (preserve custody and independent recovery); `fishhat/owner-support/src/fishhat_owner/journal.py`; `tests/test_engineering.py` |
| Exactly one durable owner of each store; forward-only changes | `state/inventory.toml`; `AGENTS.md` (change durable state deliberately); maintained migrations and `tests/test_migrations.py` |
| Current uncertainty, cumulative effects, cessation and holds | `packages/fishhat-contracts/src/fishhat_contracts/contracts/states.json`; `tests/test_owner_effect_history.py` |
| Retained old epochs, read-only custody and authoritative historical snapshots | `packages/fishhat-contracts/src/fishhat_contracts/contracts/owner-history.schema.json`; `tests/test_owner_history.py` |
| Recovery of original work | `packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json` (`operation.recover`); `packages/fishhat-contracts/src/fishhat_contracts/history.py`; `tests/test_historical_recovery_qualification.py` |
| Receiver-owned adapter binding, dispatch and exclusion | `fishhat/owner-support/src/fishhat_owner/adapter_state.py`; `packages/fishhat-contracts/src/fishhat_contracts/adapter_semantics.py`; `tests/test_adapter_effects.py` |
| Native qualification, platform and growth claims | `release.toml`; `scripts/operation_qualification.py`; `tests/test_linear_growth.py` |

The following conclusions clarify the **scope** of these rules; they do not
replace or extend the sources above:

- **Local authority does not require a remote decision service.** `host-ops` and
  `app-ops` independently authenticate, authorize, admit, retain, inspect and
  recover their own host-local work. A client, directory, reporter, external
  coordinator, witness or other host cannot become a prerequisite for those
  decisions. Cross-owner workflows may have their own explicit participant
  prerequisites; they cannot silently transfer management authority away from
  a receiving owner.
- **Effect enforcement is not another owner.** A selected, receiver-approved
  local adapter or native resource can reject stale execution and supply
  observations, but does not independently accept owner work or grant roles.
  No separate journal, target authority or remote service is defined here.
  Original accepted intent, binding, principal, grants, scope, epoch, generation,
  and effect identity remain subject to the existing receiver-owned contracts.
  The reference `Journal` accepts a test-injected `authorized` decision; native
  receiving-principal authentication and scoped authorization are separate
  qualifications, never fields trusted from source data or request JSON.
- **Per-host exclusion is not global exclusion.** Copying an entire host-local
  state to disconnected machines allows each copy to act on its *own* local
  resources. It cannot elect a unique physical writer for an external shared
  resource. Host-local management must not claim that guarantee or silently
  require a remote election service. A shared-resource operation needs its own
  independently qualified application/resource protocol or is unsupported.
- **History is custody, never revived execution.** A new epoch must preserve the
  exact original request, outcomes, cumulative facts, uncertainty, effects,
  holds, and qualified readers. Former execution or cancellation tokens do not
  become current capabilities. `operation.recover` is a separately reviewed,
  current-authority Plan with a *new* identity and native reconciliation;
  a read-only `OwnerCustody` descriptor cannot authorize it. In particular, a
  lost reply spanning restoration cannot be transformed into `none` merely
  because the historical owner or old executor is unavailable.
- **No-effect requires affirmative native evidence.** A missing response,
  missing target record, terminated process, stale lease, or SQLite transaction
  cannot by itself prove that every native effect path has ceased and remains
  excluded. Unknown work retains its uncertainty and holds until the current
  owner's existing recovery requirements are met. A simulated receiver-supplied
  verifier is not proof of native cessation.
- **Copyable local state cannot authenticate its own complete rollback.** A
  digest saved and rolled back with the data does not add an independent trusted
  observation. Nor do disconnected identical local copies know which machine is
  the sole global writer. Neither guarantee follows from the owner journal.

## Evidence and qualification boundary

`test_main_boundaries.py` demonstrates the local acceptance, retained
uncertainty, epoch identity, independent-clone and full-rollback limitations
**against the maintained mainline `Journal`**, not an alternate implementation.
Those are scoped reference behaviors, not native OS/IPC/storage guarantees.
The maintained history, recovery, effect and engineering test suites above own
normative contract evidence; this research must not be added as a second source
of validation truth or treated as replacement qualification. The current
`release.toml` explicitly has no native-qualified profiles. Linux, macOS,
Windows and appliance behavior require separate evidence for the *selected*
installed owner and native adapters, not an assumption derived from Python or
SQLite test execution.
