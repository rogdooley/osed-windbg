# `rop.prove()` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a debugger-backed, evidence-preserving x86 ROP proof workflow with guided and observe modes, deterministic replay tests, target fingerprinting, and an optional post-chain DEP postcondition.

**Architecture:** A proof-specific controller and state machine consume existing `ChainStep` and semantic data through a narrow `ProofDebuggerAdapter`. Production behavior uses a WinDbg adapter; automated acceptance uses a scripted replay adapter with the same contract. Gadget execution and post-chain objective verification remain separate phases and separate outcomes.

**Tech Stack:** TypeScript 5.9, WinDbg Preview JavaScript data model, existing semantic ROP pipeline, Vitest 3.2, esbuild, CMake/Visual Studio 2022 Win32 for manual validation.

**Spec:** `Documentation/ROP_PROVE_IMPLEMENTATION_SPEC.md`

## Global Constraints

- Support x86 only; reject non-PE32/four-byte-pointer sessions before arming.
- Never issue `g`, `gc`, `p`, `t`, or equivalent execution-control commands.
- Never write target registers or memory.
- Own at most one one-shot breakpoint and never modify an unrelated breakpoint.
- Reuse `ChainStep`, `CapabilityIndex`, and the existing semantic composition pipeline; do not create a second gadget interpreter.
- Preserve `executionStatus` and `objectiveStatus` as independent fields everywhere.
- A verified API entry is not a verified DEP bypass.
- Bare `rop.prove()` never starts a session.
- Automated acceptance uses replay fixtures; real x86 execution and protection checks remain documented manual gates.
- Run repository shell commands through `rtk`.

## Review Focus

- Software breakpoints replace the first instruction byte: fingerprint live gadget bytes before arming and test that the owned `INT 3` does not create `STALE_TARGET`.
- One-shot breakpoints disappear after a hit while IDs can be reused: test both expected absence and refusal to delete a reused ID.
- IAT slots and runtime frames can be partially unreadable: test exact four-byte reads and structured `UNVERIFIED` results without partial-value assembly.
- x86 ESP arithmetic wraps at 32 bits and pivots are not deltas: test wraparound, `ret N`, and an exact register-derived pivot.
- A module can unload/reload at the same base: test that changed live gadget bytes or target hash still produces `STALE_TARGET`.

---

## File structure

- Create `src/rop/proof/types.ts`: proof statuses, expressions, checkpoints, observations, sessions, fingerprints, and serialized record schema.
- Create `src/rop/proof/adapter.ts`: `ProofDebuggerAdapter` and adapter result contracts.
- Create `src/rop/proof/windbg_adapter.ts`: allowlisted WinDbg reads and owned-breakpoint operations.
- Create `src/rop/proof/predictor.ts`: chain normalization and checkpoint prediction using existing semantics.
- Create `src/rop/proof/comparator.ts`: expression evaluation and ordered checkpoint assertions.
- Create `src/rop/proof/fingerprint.ts`: capture scope, SHA-256, and stale/incomplete comparison.
- Create `src/rop/proof/postcondition.ts`: runtime stdcall-frame capture and supported API postconditions.
- Create `src/rop/proof/session.ts`: guided/observe state machine and breakpoint lifecycle.
- Create `src/rop/proof/store.ts`: append-only in-memory sessions, history, JSON, and Markdown serialization.
- Create `src/rop/proof/controller.ts`: public operation dispatch independent of rendering.
- Create `src/rop/proof/index.ts`: proof-module exports.
- Modify `src/rop/index.ts`: export proof contracts needed by tests and the public binding.
- Modify `src/index.ts`: bind and render `rop.prove()` while preserving `lastResult` chain inheritance.
- Modify `src/core/help_catalog.ts`: usage, examples, and evidence-boundary wording.
- Modify `src/types/windbg.d.ts`: only the host filesystem/debugger shapes required by the production adapter.
- Create `tests/helpers/replay_proof_adapter.ts`: scripted adapter and explicit stop-frame advancement.
- Create `tests/fixtures/proof/*.json`: deterministic recorded stop sequences.
- Create `tests/proof_adapter.test.ts`, `tests/proof_predictor.test.ts`, `tests/proof_comparator.test.ts`, `tests/proof_fingerprint.test.ts`, `tests/proof_session.test.ts`, `tests/proof_postcondition.test.ts`, `tests/proof_public_api.test.ts`, and `tests/proof_export.test.ts`.
- Create `tests/manual/rop_prove_target/CMakeLists.txt` and `tests/manual/rop_prove_target/rop_prove_target.c`: PE32 validation fixture.
- Create `Documentation/ROP_PROVE_WINDOWS_VALIDATION.md`: public-interface manual gates and evidence checklist.
- Modify `Documentation/ROP_API_REFERENCE.md`, `Documentation/ROP_WORKFLOW.md`, `Documentation/README.md`, `CHANGELOG.md`, and rebuilt `dist/osed.js`.

### Task 1: Proof contracts and replay adapter

**Files:**
- Create: `src/rop/proof/types.ts`
- Create: `src/rop/proof/adapter.ts`
- Create: `src/rop/proof/index.ts`
- Create: `tests/helpers/replay_proof_adapter.ts`
- Create: `tests/fixtures/proof/linear-good.json`
- Test: `tests/proof_adapter.test.ts`

**Interfaces:**
- Produces: `ProofDebuggerAdapter`, `AdapterResult`, `DeleteOwnedResult`, `ProofRegisterSnapshot`, `BreakpointSnapshot`, `OwnedBreakpoint`, `LiveDisassembly`, `MemoryProtectionRegion`, `FingerprintScope`, `TargetFingerprint`, `ProofCheckpoint`, `CheckpointObservation`, `ProofSession`, and `ProofRecordV1`.
- `ProofDebuggerAdapter` exposes synchronous `readRegisters`, `readMemory`, `listBreakpoints`, `setOneShot`, `deleteOwned`, `disassemble`, `getFingerprint`, and `queryProtection` methods. It exposes no execution-control method.

- [ ] **Step 1: Write failing replay-adapter contract tests**

  Assert that a fixture frame returns exact registers and bytes, `setOneShot` records one owned breakpoint, `deleteOwned` deletes only an exact tuple, ID reuse is refused, and explicit harness advancement—not an adapter method—changes the active stop.

- [ ] **Step 2: Run the focused test and confirm failure**

  Run: `rtk npm test -- tests/proof_adapter.test.ts`  
  Expected: FAIL because the proof contracts and replay adapter do not exist.

- [ ] **Step 3: Add the minimal contracts and replay implementation**

  Use discriminated unions for session state and assertion status. Store addresses as `bigint` in memory and lowercase fixed-width hex strings in serialized records. Make structured read failures explicit; never return zero for an unreadable address.

- [ ] **Step 4: Run the focused test and typecheck**

  Run: `rtk npm test -- tests/proof_adapter.test.ts`  
  Run: `rtk npm run typecheck`  
  Expected: PASS.

- [ ] **Step 5: Commit**

  `git add src/rop/proof/types.ts src/rop/proof/adapter.ts src/rop/proof/index.ts tests/helpers/replay_proof_adapter.ts tests/fixtures/proof/linear-good.json tests/proof_adapter.test.ts && git commit -m "test: add proof adapter replay contract"`

### Task 2: Semantic checkpoint prediction

**Files:**
- Create: `src/rop/proof/predictor.ts`
- Modify: `src/rop/proof/types.ts`
- Modify: `src/rop/proof/index.ts`
- Test: `tests/proof_predictor.test.ts`

**Interfaces:**
- Consumes: `ChainStep[]`, optional `CapabilityIndex`, live disassembly from `ProofDebuggerAdapter`, and existing `SemanticSummary` values.
- Produces: `buildProofPlan(input, adapter): ProofPlan` and target/ESP expressions consumed by the comparator and session machine.

- [ ] **Step 1: Write failing predictor tests**

  Pin checkpoint order and exact assertions for `pop eax ; ret`, `ret 8`, `xchg eax, esp ; ret`, an IAT dereference/dispatch pair, and an unknown instruction. Assert that `ret 8` includes its return pop; pivot and IAT targets remain deferred descriptors with explicit register/memory dependencies; 32-bit addition wraps; and unknown flow-affecting semantics halt prediction as `UNVERIFIED`. Pure predictor tests must not invent concrete runtime pivot or IAT addresses.

- [ ] **Step 2: Add manual-chain normalization tests**

  Assert that a generated `ChainStep[]` preserves gadget/value roles, a DWORD string resolves an unambiguous corpus address, and ambiguous or unresolved gadget boundaries cannot become a verified plan.

- [ ] **Step 3: Run the tests and confirm failure**

  Run: `rtk npm test -- tests/proof_predictor.test.ts`  
  Expected: FAIL because `buildProofPlan` does not exist.

- [ ] **Step 4: Implement prediction by composing existing semantics**

  Read exact stack deltas and register transforms from `SemanticSummary`. Send live instruction text through the existing live provider/canonicalization/composition path; do not add mnemonic-specific behavior to the predictor.

- [ ] **Step 5: Verify**

  Run: `rtk npm test -- tests/proof_predictor.test.ts tests/semantic_pipeline.test.ts tests/chain_verifier.test.ts`  
  Run: `rtk npm run typecheck:semantic-rop`  
  Expected: PASS with no change to `rop.verify()` behavior.

- [ ] **Step 6: Commit**

  `git add src/rop/proof/predictor.ts src/rop/proof/types.ts src/rop/proof/index.ts tests/proof_predictor.test.ts && git commit -m "feat: predict semantic ROP checkpoints"`

### Task 3: Ordered checkpoint comparison

**Files:**
- Create: `src/rop/proof/comparator.ts`
- Modify: `src/rop/proof/types.ts`
- Test: `tests/proof_comparator.test.ts`
- Create: `tests/fixtures/proof/esp-divergence.json`

**Interfaces:**
- Consumes: predicted checkpoint, prior observation, current adapter snapshot.
- Produces: `compareCheckpoint(input, adapter): CheckpointObservation` with ordered `VERIFIED`, `FAILED`, and `UNVERIFIED` assertions.

- [ ] **Step 1: Write the failing first-divergence test**

  Replay a matching EIP and an ESP four bytes above prediction. Assert EIP is recorded `VERIFIED`, ESP is the first `FAILED` assertion, `differenceBytes` is `+4`, later assertions are not evaluated, and the checkpoint does not advance.

- [ ] **Step 2: Write EIP-first and unknown-effect tests**

  Assert a wrong EIP returns `UNEXPECTED_STOP` before register/stack comparison. Assert unknown memory aliasing is `UNVERIFIED`, never a match, while an exact known-width write compares before/after bytes.

- [ ] **Step 3: Run and confirm failure**

  Run: `rtk npm test -- tests/proof_comparator.test.ts`  
  Expected: FAIL because the comparator does not exist.

- [ ] **Step 4: Implement expression evaluation and ordered comparison**

  Evaluate all arithmetic as unsigned x86 DWORD arithmetic. Compare absolute observed ESP with the evaluated expression; do not derive it from checkpoint index or a running accumulator.

- [ ] **Step 5: Verify and commit**

  Run: `rtk npm test -- tests/proof_comparator.test.ts tests/proof_predictor.test.ts`  
  Run: `rtk npm run typecheck`  
  Expected: PASS.

  `git add src/rop/proof/comparator.ts src/rop/proof/types.ts tests/proof_comparator.test.ts tests/fixtures/proof/esp-divergence.json && git commit -m "feat: compare proof checkpoints in assertion order"`

### Task 4: Fingerprint capture and stale-target enforcement

**Files:**
- Create: `src/rop/proof/fingerprint.ts`
- Modify: `src/rop/proof/types.ts`
- Test: `tests/proof_fingerprint.test.ts`
- Create: `tests/fixtures/proof/fingerprint-mutation.json`

**Interfaces:**
- Produces: `sha256(bytes): string`, `captureProofFingerprint(scope, adapter): TargetFingerprint`, and `compareProofFingerprint(baseline, current): FingerprintComparison`.
- The comparison distinguishes `CURRENT`, `INCOMPLETE`, and `STALE_TARGET`.

- [ ] **Step 1: Write failing SHA-256 and completeness tests**

  Use standard empty-string and `abc` SHA-256 vectors. Assert an unreadable local, remote, or unusual-path target image marks the fingerprint incomplete and cannot yield a verified session even when checkpoint observations match; the reason must identify target identity as incomplete rather than report a comparator failure.

- [ ] **Step 2: Write failing mutation tests**

  Replay module-base change, same-base gadget-byte change, target-hash change, and irrelevant-module addition. Assert the first three are stale and the last does not invalidate a chain that never uses that module.

- [ ] **Step 3: Write the owned-breakpoint byte test**

  Assert baseline gadget bytes are captured before `setOneShot`; the adapter's simulated `0xCC` at the owned breakpoint does not self-invalidate, while an unrelated byte change does.

- [ ] **Step 4: Implement hashing and scoped comparison**

  Keep the hash implementation dependency-free for the WinDbg bundle. Full file hash is required at start and before final verification; checkpoint revalidation uses process/thread, module bases, live relevant bytes, and protections.

- [ ] **Step 5: Verify and commit**

  Run: `rtk npm test -- tests/proof_fingerprint.test.ts`  
  Run: `rtk npm run typecheck`  
  Expected: PASS.

  `git add src/rop/proof/fingerprint.ts src/rop/proof/types.ts tests/proof_fingerprint.test.ts tests/fixtures/proof/fingerprint-mutation.json && git commit -m "feat: fingerprint proof targets"`

### Task 5: Guided and observe session state machine

**Files:**
- Create: `src/rop/proof/session.ts`
- Create: `src/rop/proof/store.ts`
- Modify: `src/rop/proof/types.ts`
- Test: `tests/proof_session.test.ts`
- Create: `tests/fixtures/proof/unexpected-stop.json`

**Interfaces:**
- Produces: `ProofSessionMachine.start`, `observeAndAdvance`, `status`, and `cancel`; `ProofSessionStore.add`, `active`, `history`, and `appendEvent`.
- Consumes: proof plan, comparator, fingerprint comparison, and `ProofDebuggerAdapter`.

- [ ] **Step 1: Write failing guided-mode tests**

  Assert only one breakpoint is armed, no adapter resume method is called, a matching stop consumes exactly one checkpoint, a failed assertion halts, and `cancel` deletes only an exact owned tuple.

- [ ] **Step 2: Write failing unexpected-stop ownership tests**

  Replay an unrelated breakpoint and an exception before the owned checkpoint. Assert `UNEXPECTED_STOP`, unchanged checkpoint index, retained owned breakpoint, and preserved stop details. Assert a fired one-shot may be absent after a matching stop without being treated as an ownership error.

- [ ] **Step 3: Write failing orphan-reclamation tests**

  Simulate extension reload by discarding the session store while retaining a breakpoint with a versioned proof marker. Assert session start reports the orphan and makes no state change. Assert `cancel` with `orphans:true` deletes an exactly revalidated ID/address/full-marker/enabled/one-shot tuple, but refuses ID reuse, address mutation, marker mutation, prefix-only matches, and unsupported marker versions.

- [ ] **Step 4: Write failing observe-mode tests**

  Assert no breakpoint calls occur. Match only the next unconsumed checkpoint; a later checkpoint address is still `UNEXPECTED_STOP` and does not skip ahead.

- [ ] **Step 5: Write failing incremental pivot-resolution tests**

  Replay a stop at `xchg eax,esp ; ret` with an observed EAX and controlled bytes at `[EAX]`. Assert the session resolves next EIP from those little-endian bytes, derives absolute next ESP from the observed EAX plus the composed return delta, records both inputs, and only then arms the resolved target. An unreadable pivot stack must become `UNVERIFIED` and arm nothing.

- [ ] **Step 6: Implement the state machine and append-only store**

  Keep `CHECKPOINT_REACHED` as a recorded transition. Permit continued execution after an `UNVERIFIED` assertion only when next EIP and ESP remain exact and independent of the unknown assertion.

- [ ] **Step 7: Verify and commit**

  Run: `rtk npm test -- tests/proof_session.test.ts tests/proof_comparator.test.ts tests/proof_fingerprint.test.ts`  
  Run: `rtk npm run typecheck`  
  Expected: PASS.

  `git add src/rop/proof/session.ts src/rop/proof/store.ts src/rop/proof/types.ts tests/proof_session.test.ts tests/fixtures/proof/unexpected-stop.json && git commit -m "feat: add guided ROP proof sessions"`

### Task 6: IAT two-phase dispatch and postcondition phase

**Files:**
- Create: `src/rop/proof/postcondition.ts`
- Modify: `src/rop/proof/predictor.ts`
- Modify: `src/rop/proof/session.ts`
- Modify: `src/rop/proof/types.ts`
- Test: `tests/proof_postcondition.test.ts`
- Create: `tests/fixtures/proof/slot-call-virtualprotect.json`

**Interfaces:**
- Produces: `resolveDynamicDispatch(checkpoint, observation, adapter): DynamicDispatchResult`, `captureStdcallFrame(api, esp, adapter): RuntimeApiFrame`, and `evaluatePostcondition(request, frame, returnObservation, adapter): ObjectiveObservation`.

- [ ] **Step 1: Write failing little-endian IAT tests**

  At the dereference-gadget entry, set EAX to the slot address and return bytes `78 56 34 12`. Assert the next target is `0x12345678`, not the EAX slot value, guided mode arms the API-entry breakpoint there, and no intermediate breakpoint is armed at the adjacent `jmp eax` gadget. Assert the compound transition retains both gadgets' provenance and predicts API-entry ESP as `uint32(esp0 + 4)` from the dereference gadget's exact `+4` and dispatch gadget's exact zero delta. A non-exact component must make the ESP assertion `UNVERIFIED`. Assert a three-byte/failed slot read is `UNVERIFIED` and arms nothing.

- [ ] **Step 2: Write failing API-entry frame-capture tests**

  Replay API entry with a static `SHELLCODE` placeholder but concrete stack DWORDs. Assert `[ESP]` supplies the return address and actual `[ESP+4]`/`[ESP+8]` supply the `VirtualProtect` range carried into `POSTCONDITION_ARMED`.

- [ ] **Step 3: Write failing postcondition-state tests**

  Assert system-code execution creates no gadget checkpoints. After manual replay advancement, require EIP at the captured return address, API success, and executable protections across the captured runtime range. For `VirtualProtect`, assert the range begins at runtime `lpAddress`. For `VirtualAlloc`, assert a nonzero EAX return is the authoritative range base even when requested `lpAddress` is null or a different non-null value; zero EAX fails before protection checks. Test region walking without a fixed page-size assumption, zero/overflowing ranges, partial readability, unsupported API, and unexpected return stop separately.

- [ ] **Step 4: Implement dispatch resolution and postconditions**

  Support current-process `VirtualProtect` and `VirtualAlloc`. Mark other APIs `objectiveStatus: UNVERIFIED` with an explicit reason. Keep gadget-loop `executionStatus` unchanged by a later objective failure.

- [ ] **Step 5: Verify and commit**

  Run: `rtk npm test -- tests/proof_postcondition.test.ts tests/proof_session.test.ts`  
  Run: `rtk npm run typecheck:semantic-rop`  
  Expected: PASS.

  `git add src/rop/proof/postcondition.ts src/rop/proof/predictor.ts src/rop/proof/session.ts src/rop/proof/types.ts tests/proof_postcondition.test.ts tests/fixtures/proof/slot-call-virtualprotect.json && git commit -m "feat: verify IAT dispatch and DEP postconditions"`

### Task 7: Production WinDbg adapter and public API

**Files:**
- Create: `src/rop/proof/windbg_adapter.ts`
- Create: `src/rop/proof/controller.ts`
- Modify: `src/rop/proof/index.ts`
- Modify: `src/rop/index.ts`
- Modify: `src/index.ts`
- Modify: `src/core/help_catalog.ts`
- Modify: `src/types/windbg.d.ts`
- Test: `tests/proof_public_api.test.ts`

**Interfaces:**
- Produces: `ProofController.execute(options): ProofCommandOutcome` and the public `api.rop.prove` binding.
- The controller accepts injected adapter/store/corpus/last-generated-chain dependencies so public behavior remains replay-testable without global `host` stubs.

- [ ] **Step 1: Write failing public API tests**

  Assert `rop.prove` is exposed. A bare call with no active session returns the specified no-op error and changes nothing. An options object defaults to guided mode; no argument means advance. Starting guided/observe modes uses the last generated chain or explicit chain. Starting while active is rejected without replacing the session. If current EIP is checkpoint zero, start consumes that entry and arms checkpoint one; otherwise guided start arms checkpoint zero. Assert a start-time orphan report points to `{action:"cancel", orphans:true}` and that default cancel does not broaden its scope. `status`, `history`, and `cancel` dispatch correctly.

- [ ] **Step 2: Write failing adapter allowlist tests**

  Assert only inspection, `bp /1`, breakpoint listing, and exact owned deletion commands are accepted. Reject caller-controlled command strings and every execution-control or target-write command.

- [ ] **Step 3: Implement the production adapter and binding**

  Reuse existing register, memory, module, protection, and output helpers where possible. Keep proof state independent of `lastResult`; use `lastResult` only to inherit the last generated chain, resolved API, and relevant options.

- [ ] **Step 4: Verify and commit**

  Run: `rtk npm test -- tests/proof_public_api.test.ts tests/rop_command.test.ts tests/generate_verify_fixes.test.ts`  
  Run: `rtk npm run typecheck`  
  Expected: PASS.

  `git add src/rop/proof/windbg_adapter.ts src/rop/proof/controller.ts src/rop/proof/index.ts src/rop/index.ts src/index.ts src/core/help_catalog.ts src/types/windbg.d.ts tests/proof_public_api.test.ts && git commit -m "feat: expose rop prove in WinDbg"`

### Task 8: Persistence, export, and reporting

**Files:**
- Modify: `src/rop/proof/store.ts`
- Modify: `src/rop/proof/controller.ts`
- Modify: `src/index.ts`
- Test: `tests/proof_export.test.ts`

**Interfaces:**
- Produces: `serializeProofRecord(session): ProofRecordV1`, `renderProofMarkdown(record): string`, and explicit-path export through the host filesystem.

- [ ] **Step 1: Write failing outcome-separation tests**

  Assert exports always contain both outcomes. When chain execution is verified but no postcondition was requested, assert `executionStatus` is `VERIFIED`, `objectiveStatus` is `UNVERIFIED` with reason `not requested`, and `CommandResult.success` is false.

- [ ] **Step 2: Write failing evidence-retention tests**

  Assert failed, unverified, unexpected-stop, stale, cancellation, and breakpoint ownership events survive history and JSON/Markdown export in order. Assert export does not mutate session status.

- [ ] **Step 3: Implement canonical JSON and deterministic Markdown**

  Require an explicit path for filesystem export. Preserve raw and formatted addresses, schema version, target hash status, all assertions, and signed ESP differences.

- [ ] **Step 4: Verify and commit**

  Run: `rtk npm test -- tests/proof_export.test.ts tests/proof_public_api.test.ts`  
  Run: `rtk npm run typecheck`  
  Expected: PASS.

  `git add src/rop/proof/store.ts src/rop/proof/controller.ts src/index.ts tests/proof_export.test.ts && git commit -m "feat: persist and export ROP proof evidence"`

### Task 9: Windows x86 manual validation fixture and documentation

**Files:**
- Create: `tests/manual/rop_prove_target/CMakeLists.txt`
- Create: `tests/manual/rop_prove_target/rop_prove_target.c`
- Create: `Documentation/ROP_PROVE_WINDOWS_VALIDATION.md`
- Modify: `Documentation/ROP_API_REFERENCE.md`
- Modify: `Documentation/ROP_WORKFLOW.md`
- Modify: `Documentation/README.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Produces: a standalone PE32 target and two evidence checklists using only public `dx @$osed()` proof calls; the operator runs all `g` commands manually.

- [ ] **Step 1: Add the Win32 fixture**

  Provide deterministic exported x86 sequences covering a normal pop/return path, `ret N`, a stack pivot, IAT-backed `VirtualProtect`, and a page whose protection change is observable. Fail the build/runtime guard when pointer size is not four bytes.

- [ ] **Step 2: Document manual gate A**

  Build with `cmake -A Win32`, load the extension, create/load the corpus, start proof through `dx @$osed().rop.prove({mode:"guided"})`, issue each `g` manually, and capture evidence that the IAT dispatch target came from the slot contents.

- [ ] **Step 3: Document manual gate B**

  Request the postcondition, capture the actual API-entry stack range, manually continue to the captured return address, and record the observed executable protection. Include explicit failure and cleanup steps.

- [ ] **Step 4: Update user documentation**

  Document guided/observe rules, status/cancel/history/export, stale fingerprints, replay-versus-live validation, and the two independent outcomes. State that macOS/replay success is not target verification.

- [ ] **Step 5: Review the fixture and commit**

  Run on macOS: `rtk npm test` and `rtk npm run typecheck`  
  On Windows: run both documented manual gates and retain their transcripts.  
  Expected: automated suite passes; manual evidence is required before the exam-ready claim.

  `git add tests/manual Documentation CHANGELOG.md && git commit -m "docs: add ROP proof Windows validation gates"`

### Task 10: Full regression and distributable build

**Files:**
- Modify: `dist/osed.js`

**Interfaces:**
- Consumes all prior tasks.
- Produces the bundled extension and final verification evidence.

- [ ] **Step 1: Run the complete automated suite**

  Run: `rtk npm test`  
  Run: `rtk npm run typecheck`  
  Run: `rtk npm run typecheck:semantics`  
  Run: `rtk npm run typecheck:semantic-rop`  
  Expected: all commands exit zero.

- [ ] **Step 2: Build and inspect the bundle**

  Run: `rtk npm run build`  
  Confirm `dist/osed.js` contains the `rop.prove` binding and no execution-control command path.

- [ ] **Step 3: Re-run focused proof tests against the built source state**

  Run: `rtk npm test -- tests/proof_adapter.test.ts tests/proof_predictor.test.ts tests/proof_comparator.test.ts tests/proof_fingerprint.test.ts tests/proof_session.test.ts tests/proof_postcondition.test.ts tests/proof_public_api.test.ts tests/proof_export.test.ts`  
  Expected: PASS.

- [ ] **Step 4: Commit the distributable**

  `git add dist/osed.js && git commit -m "build: bundle rop proof workflow"`

## Completion boundary

Implementation is code-complete when all automated checks pass and the bundle is rebuilt. It is target-validated and suitable for an exam-readiness claim only after both Windows x86 manual gates have been run against the final bundle and their evidence has been reviewed. Until then, report the feature as replay-verified but Windows validation pending.
