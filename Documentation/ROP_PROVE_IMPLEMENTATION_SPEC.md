# `rop.prove()` Implementation Specification

Status: approved design, ready for implementation planning  
Scope: WinDbg Preview JavaScript extension, x86 proof workflow, guided execution only

## 1. Objective

`rop.prove()` verifies a ROP chain against debugger observations. It predicts each meaningful transition from the existing chain and semantic models, compares those predictions with the stopped target, records the evidence, and halts at the first failed assertion.

The feature has two independent outcomes:

- `executionStatus`: whether the chain's gadget transitions and API dispatch were observed as predicted.
- `objectiveStatus`: whether an optional post-chain objective was observed after the dispatched API returned.

These fields are load-bearing. They must remain separate in types, stored records, rendered output, exports, and tests. The UI must never turn a verified API dispatch into the claim that a DEP bypass was verified.

## 2. Scope and non-goals

Version 1 shall:

- support x86 targets only;
- consume the `ChainStep[]` representation produced by `rop.generate()` and the existing semantic corpus;
- accept an explicitly supplied manual chain when its gadget boundaries can be resolved through the corpus or the existing live semantic pipeline;
- provide guided and observation-only modes;
- install at most one owned, one-shot breakpoint;
- require the user to issue every execution command manually;
- persist observations for the debugger-session lifetime and support explicit JSON or Markdown export;
- support an optional, separate postcondition phase for current-process `VirtualProtect` and `VirtualAlloc` calls.

Version 1 shall not:

- issue `g`, `gc`, `p`, `t`, or any equivalent resume/step command;
- write target registers or memory;
- interpret execution inside system APIs as corpus-backed gadget execution;
- claim a DEP bypass from static prediction, gadget execution, or API entry alone;
- prove cross-process `VirtualProtectEx`, `VirtualAllocEx`, or `WriteProcessMemory` postconditions;
- silently start a session from a bare `rop.prove()` call.

## 3. Public API

The namespace additions are:

- `rop.prove({mode:"guided", chain?, postcondition?})`
- `rop.prove({mode:"observe", chain?, postcondition?})`
- `rop.prove()`
- `rop.prove({action:"status", sessionId?})`
- `rop.prove({action:"cancel"})`
- `rop.prove({action:"cancel", orphans:true})`
- `rop.prove({action:"history", sessionId?})`
- `rop.prove({action:"export", sessionId?, path, format:"json"|"markdown"})`

Start options are `{mode?:"guided"|"observe", chain?:string|ChainStep[], api?:string, postcondition?:{kind:"dep"}}`. Passing an options object without `action` starts a session and defaults `mode` to `guided`; passing no argument advances an existing session. `api` inherits the last generated chain's `resolvedApi` when available and is otherwise required for an API-specific postcondition. Action objects are disjoint from start options. Export defaults to JSON when `format` is omitted.

Starting a session uses the supplied chain or, when omitted, the last successful `rop.generate()` chain. A manual chain may be supplied as `ChainStep[]` or as the existing DWORD string form. A string is eligible for proof only when each executed gadget address resolves unambiguously through the loaded corpus or live disassembly processed by the existing semantics pipeline. Unresolved placeholders are preserved as evidence and prevent a complete verification when they affect flow, ESP, or required assertions.

A bare `rop.prove()` means only "examine the current stop and advance the active session." It requires an active `ARMED`, `CHECKPOINT_REACHED`, or `POSTCONDITION_ARMED` session. With no such session it returns a no-op error that directs the user to `rop.prove({mode:"guided"})` or `rop.prove({mode:"observe"})`. It never creates a session implicitly.

Starting while another session is active is also a no-op error; the caller must finish or cancel the active session. At start, if current EIP already equals checkpoint zero, that entry is observed immediately and guided mode arms checkpoint one. Otherwise guided mode arms checkpoint zero. Observe mode records no unexpected stop during creation; its first bare call applies the matching rule in section 7.

`status` and `history` are read-only. Default `cancel` removes only a breakpoint whose current ID, address, and ownership marker still match the active session. `cancel` with `orphans:true` additionally performs the orphan-reclamation procedure in section 7. `export` is the only operation that writes proof records to disk.

## 4. Proof adapter boundary

All debugger-dependent operations shall be behind a `ProofDebuggerAdapter` interface. The state machine, predictor, comparator, fingerprint comparison, and postcondition evaluator must depend on this interface rather than directly on global `host` objects or debugger commands.

Required operations:

- `readRegisters()` returns the current x86 register snapshot.
- `readMemory(address, length)` returns raw bytes or a structured read failure.
- `listBreakpoints()` returns ID, address, enabled/one-shot state, and command text.
- `setOneShot(address, marker)` creates one breakpoint and returns its captured identity.
- `deleteOwned(breakpoint)` removes it only after identity revalidation.
- `disassemble(address)` returns live instruction text and bytes for validation through the existing semantic pipeline.
- `getFingerprint(scope)` returns process, target, modules, live bytes, and requested protection observations.
- `queryProtection(address)` returns the page protection needed by postcondition evaluation.

The interface is synchronous to match the existing extension:

```typescript
interface ProofDebuggerAdapter {
  readRegisters(): ProofRegisterSnapshot;
  readMemory(address: bigint, length: number): AdapterResult<Uint8Array>;
  listBreakpoints(): AdapterResult<BreakpointSnapshot[]>;
  setOneShot(address: bigint, marker: string): AdapterResult<OwnedBreakpoint>;
  deleteOwned(breakpoint: OwnedBreakpoint): DeleteOwnedResult;
  disassemble(address: bigint, maxInstructions: number): AdapterResult<LiveDisassembly>;
  getFingerprint(scope: FingerprintScope): AdapterResult<TargetFingerprint>;
  queryProtection(address: bigint): AdapterResult<MemoryProtectionRegion>;
}
```

`AdapterResult<T>` is either `{ok:true,value:T}` or `{ok:false,error:AdapterError}`. `deleteOwned` distinguishes `deleted`, `already-fired`, `identity-mismatch`, and `not-found`; only `deleted` authorizes a `bc <id>` command. There is deliberately no generic command or execution-control method.

The production `WinDbgProofAdapter` may execute only the commands needed to inspect state and manage the owned breakpoint. Its command allowlist must reject execution control (`g`, `gc`, `p`, `t`), target memory/register writes, and arbitrary caller-supplied command strings.

The automated test harness shall provide a `ReplayProofAdapter`. A replay fixture contains ordered stop frames: registers, addressable memory bytes, breakpoints, disassembly, protections, and fingerprint data. Advancing between frames is a test-harness action representing the user's manual `g`; the adapter and proof state machine have no resume method. The replay adapter records breakpoint create/delete requests so ownership behavior can be asserted deterministically.

## 5. Chain normalization and prediction

The predictor shall not add a second gadget-semantics implementation. It uses `ChainStep`, `CapabilityIndex`, `SemanticSequence`, `SemanticSummary`, and the existing instruction semantics and composition pipeline.

Each predicted checkpoint represents a meaningful debugger stop, normally gadget entry. Checkpoint zero has entry assertions only. Checkpoint N normally contains the target for gadget N and the transition assertions produced by gadget N-1. The recognized IAT dereference/dispatch boundary is the deliberate exception: it becomes one compound transition from dereference-gadget entry to API entry, with no intermediate breakpoint at the `jmp` gadget.

Checkpoint targets are expressions, not only fixed corpus addresses:

- fixed gadget address;
- exact register-derived pivot destination;
- exact memory-derived dispatch destination;
- unresolved target.

Prediction is incremental. Session start builds the ordered checkpoint templates, fixed gadget addresses, semantic expressions, and dependencies that are knowable without execution. It does not require every checkpoint target to have a concrete address. Immediately before a dynamic transition executes, the session resolves its deferred target from the just-observed register and memory state, records the inputs and result, and only then arms the next breakpoint. No dynamic value may be inferred from the original payload when a debugger observation is available.

For a canonical `xchg eax,esp ; ret` pivot, the pivot checkpoint records EAX from the stopped target, reads the next EIP as a little-endian DWORD from `[EAX_before]`, and derives next ESP from the composed exact semantics (normally `EAX_before + 4`). For the IAT boundary, the dereference checkpoint reads the slot contents and resolves the API target as specified in section 6. Unreadable memory, an unknown source register, or a non-exact flow/ESP expression leaves the next target unresolved and prevents guided arming.

Each transition contains explicit expected expressions for:

- next EIP;
- next absolute ESP;
- register values whose effects are exact;
- stack operands consumed;
- memory reads and writes whose address and width are exact.

For ordinary gadgets and `ret N`, next ESP is derived from the semantic summary's exact stack delta, which already includes the return-address pop. For stack pivots, next ESP is derived from the composed exact ESP register transform, such as the entry value of EAX for `xchg eax, esp`. The comparator evaluates the expression against the saved prior observation and compares it with the new absolute ESP. It must not maintain an independent running stack accumulator.

Conservative or unknown semantics produce `UNVERIFIED` assertions. A checkpoint may advance after an `UNVERIFIED` assertion only when the next EIP and ESP remain exact and the unknown effect cannot influence a later required assertion. Otherwise the session halts as `UNVERIFIED`; it does not guess.

## 6. IAT dereference and API dispatch

The slot-call boundary is a dynamic transition from corpus gadgets into an API target. It is not a requirement that the final target be present in the gadget corpus.

When stopped at the entry of `mov eax,[eax]` (or the equivalent register pair selected by the generated chain), the predictor shall:

1. Treat the entry register value as the IAT slot address.
2. Read exactly four bytes from that address.
3. Assemble the bytes as an unsigned little-endian DWORD.
4. Store the result as `expectedApiEntry`, together with the slot address and raw bytes.
5. In guided mode, arm the next one-shot breakpoint at `expectedApiEntry`.

The adjacent `mov <value>,[<slot>] ; ret` and `jmp <value>` gadgets remain separately identified in provenance and are composed using their existing semantic summaries, but the session does not arm an intermediate breakpoint at the `jmp` address. If `esp0` is observed at dereference-gadget entry, expected API-entry ESP is `uint32(esp0 + dereferenceGadget.stackDelta + dispatchGadget.stackDelta)`. For the canonical `mov eax,[eax] ; ret` followed by `jmp eax`, the exact deltas are `+4` and `0`, so expected API-entry ESP is `uint32(esp0 + 4)`. If either component is non-exact, the ESP assertion is `UNVERIFIED`; it is never reconstructed from chain indexes. The API-entry observation evaluates this compound register and absolute-ESP state.

For the canonical EAX sequence, the operation is semantically `expectedApiEntry = uint32LE(readMemory(registers.eax, 4))`. Reading EAX itself is not resolution of the slot.

When the API-entry stop is examined, verification requires:

- observed EIP equals the captured `expectedApiEntry`;
- the dereference destination register equals `expectedApiEntry` when that effect is exact;
- observed ESP equals the predicted absolute ESP;
- the target lies in executable memory and its module identity is recorded.

A mismatch is `FAILED`. An unreadable slot, partial read, unresolved dispatch register, or incomplete target identity is `UNVERIFIED`.

## 7. Guided and observe modes

Guided mode owns at most one one-shot breakpoint. Creation snapshots the breakpoint list, uses a session-unique marker, creates the breakpoint, snapshots again, and records the unique new ID/address/marker tuple. Deletion first re-lists breakpoints and removes only an exact tuple match. A missing one-shot after a matching stop is expected. An ID reused for another address or marker must never be removed.

Markers use an extension-owned, versioned format containing a proof prefix, session ID, random nonce, and checkpoint ID; none of these fields come from user text. At every session start, the adapter scans `listBreakpoints()` for recognized proof markers not referenced by the active store. If any exist, start makes no state change and reports their IDs and addresses with the recovery command `rop.prove({action:"cancel", orphans:true})`. It never deletes them implicitly.

Orphan reclamation works after extension reload when the original `ProofSessionStore` no longer exists. It builds candidates only from successfully parsed proof markers, immediately re-lists each candidate, and issues `bc <id>` only when ID, address, complete marker, enabled state, and one-shot state still match. It returns per-breakpoint `deleted`, `identity-mismatch`, `not-found`, or `unsupported-marker-version` results. With an active session, `cancel` first follows normal active ownership cleanup, then `orphans:true` scans for remaining marker-owned breakpoints. No prefix-only or ID-only match authorizes deletion.

The extension never resumes execution. The user issues `g` manually and invokes bare `rop.prove()` after the debugger stops.

In observe mode, no breakpoint is created or removed. The current EIP is matched only against the next unconsumed checkpoint in order. If it does not equal that checkpoint's evaluated target, the session records `UNEXPECTED_STOP` and does not advance. It must not search ahead, skip checkpoints, or infer that an earlier gadget executed.

In guided mode, a stop is expected when EIP matches the armed checkpoint. If EIP differs while the owned breakpoint remains armed, record `UNEXPECTED_STOP` and retain both the checkpoint and ownership. Exceptions and unrelated breakpoint hits are preserved in the observation record. They do not consume the checkpoint.

## 8. Session state machine

Stable states are:

- `IDLE`
- `ARMED`
- `CHECKPOINT_REACHED`
- `FAILED`
- `UNVERIFIED`
- `STALE_TARGET`
- `EXECUTION_COMPLETE`
- `POSTCONDITION_ARMED`
- `POSTCONDITION_OBSERVED`
- `POSTCONDITION_FAILED`
- `CANCELLED`

`CHECKPOINT_REACHED` records the evaluated stop before either the next checkpoint is armed or execution completes. `UNEXPECTED_STOP` is an observation outcome while the session remains armed; it is not a checkpoint advance.

Any failed exact assertion halts the gadget loop. A stale fingerprint halts it before comparison. Cancellation is explicit and preserves the event log.

## 9. Fingerprint

The initial fingerprint records:

- process and thread identity;
- x86 architecture and four-byte pointer size;
- target executable name, canonical path, and on-disk SHA-256;
- target and chain-relevant modules: name, path, base, preferred base, image size, PE timestamp, and checksum when available;
- chain hash and semantic schema/corpus provenance;
- each gadget's module, RVA, live bytes, and decoded instructions;
- the IAT slot, resolved API target, stack/pivot destinations, and declared payload regions with current protections.

The target SHA-256 shall be computed by streaming the on-disk file through the WinDbg host filesystem and a deterministic SHA-256 implementation covered by standard test vectors. Failure to read or hash the file does not abort diagnostic use, but marks the fingerprint incomplete and caps the session at `UNVERIFIED`. This coupling is intentional for version 1: remote debugging, deleted images, device paths, inaccessible shares, or other targets without a readable local image may produce matching checkpoint observations but cannot reach `VERIFIED`. That result is a designed identity limitation, not a comparator failure.

Before each checkpoint comparison and each arm operation, a quick fingerprint revalidates process/thread identity, architecture, relevant module bases, gadget bytes, dynamic target bytes where applicable, and requested protections. The full target file hash is repeated before either outcome can become `VERIFIED`. Live gadget bytes are sampled before installing a software breakpoint so the extension's own `INT 3` cannot create a false stale result.

A changed process, architecture, target hash, relevant module base, gadget byte sequence, or required protection produces `STALE_TARGET`. Historical observations remain readable but are not current proof.

## 10. Comparison and observation records

Every assertion has:

- subject (`EIP`, `ESP`, register, stack operand, memory effect, fingerprint, or protection);
- expected expression and evaluated value;
- observed value or read error;
- evidence source and semantic confidence;
- status: `VERIFIED`, `FAILED`, or `UNVERIFIED`;
- reason and signed byte difference where meaningful.

The comparator evaluates EIP before registers, ESP, stack operands, or memory effects. A wrong stop location therefore becomes `UNEXPECTED_STOP`, not a misleading register failure. For an expected stop, the first failed exact assertion stops evaluation and is reported as the divergence reason; already evaluated assertions remain in the record.

Memory effects are compared only when the effective address, width, and before-value are known. Unknown aliasing or partial reads are `UNVERIFIED`, never matches.

## 11. Post-chain verification

API dispatch completes the gadget loop. An optional postcondition begins a separate phase and never applies gadget-loop stack or corpus invariants inside system code.

At the API-entry checkpoint, the extension captures the actual runtime stdcall frame from observed ESP:

- `[ESP]`: actual return address;
- `[ESP+4]` onward: actual arguments according to the resolved API signature.

All DWORDs are assembled little-endian from memory bytes. The postcondition inputs come from this captured runtime frame, not the static chain. `VirtualProtect` verifies `[lpAddress_runtime, lpAddress_runtime + dwSize_runtime)`. `VirtualAlloc` records the runtime-requested `lpAddress`, `dwSize`, allocation type, and protection, but verifies `[EAX_return, EAX_return + dwSize_runtime)` because the nonzero return value is the authoritative allocated base; requested `lpAddress` is evidence only and may be null or rounded by the API. A zero return value fails the `VirtualAlloc` objective before protection checks. A static `SHELLCODE` or other placeholder has no authority in this phase.

If requested and supported, guided mode arms the captured return address and enters `POSTCONDITION_ARMED`. The user issues `g`. On the next bare `rop.prove()`, EIP must first equal that return address. The evaluator then checks the API success value and protections across the actual runtime range. `queryProtection` returns region base and size as well as protection flags, so the evaluator walks complete regions until the requested range is covered without assuming a page size. Zero-sized, overflowing, partially unreadable, or partially non-executable ranges are not accepted. Unsupported APIs or unreadable frames yield `objectiveStatus: UNVERIFIED`, not a guessed result.

## 12. Persistence and reporting

A module-level `ProofSessionStore`, separate from `lastResult`, retains active, completed, failed, stale, and cancelled sessions for the lifetime of the loaded extension. Records are append-only event logs with a schema version, session ID, timestamps, source chain, predictions, fingerprints, breakpoint ownership events, observations, and both outcome fields.

The store is intentionally not treated as durable breakpoint ownership across script reload. Durable recovery authority is the fully parsed marker plus immediate breakpoint identity revalidation described in section 7.

JSON is the canonical export. Markdown is a deterministic rendering intended for exam notes. Neither export may omit failed or unverified assertions. Export never changes proof status.

`CommandResult.success` is true only when both `executionStatus` and `objectiveStatus` are `VERIFIED`. When no postcondition was requested, `objectiveStatus` remains `UNVERIFIED` with reason `not requested`, so command success remains false even if chain execution was verified. Rendered output must lead with the two explicit outcomes rather than a generic pass/fail label.

## 13. Test tiers and acceptance gates

### Tier 1: automated Vitest tests

Pure predictor tests cover exact register transforms, `ret N`, deferred pivot/IAT descriptors, unknown semantics, and manual-chain normalization. They verify the dependency expressions, not runtime values.

Replay-adapter state-machine tests cover:

- a known-good recorded gadget sequence;
- an intentionally wrong predicted ESP detected at the first divergence with the signed byte difference;
- an unexpected breakpoint and an exception that do not advance or surrender ownership;
- breakpoint ID reuse that `cancel` refuses to delete;
- extension reload with an orphaned proof marker, start-time refusal/warning, successful exact orphan reclamation, and refusal on marker/address mutation;
- observe-mode matching only the next unconsumed checkpoint;
- runtime resolution of a pivot target and absolute ESP from the immediately preceding observed register/memory state;
- fingerprint mutation producing `STALE_TARGET` before state comparison;
- incomplete hashing capping the session at `UNVERIFIED`;
- little-endian IAT resolution from four recorded bytes;
- runtime stack argument capture overriding a static placeholder;
- bare `rop.prove()` without an active session returning a no-op error;
- exports preserving separate execution and objective outcomes.

These tests are deterministic and CI-runnable. They are integration tests of the predictor, comparator, and full state machine through the adapter contract, not isolated helper tests.

### Tier 2: manual Windows x86 integration gates

A dedicated PE32 fixture built with Visual Studio 2022 and CMake `-A Win32` provides known gadget sequences, a `ret N`, a pivot, an imported `VirtualProtect`, and a controlled writable test page. The validation guide must include a PE32/pointer-size guard and use only the public `dx @$osed().rop.prove(...)` interface for proof operations.

Manual gate A verifies the known-good gadget path and IAT dispatch. Manual gate B performs a real current-process `VirtualProtect` transition, stops at the captured return address, and verifies protection across the runtime-captured range. The operator issues every `g` command.

Automated tests are required for every change. Both manual gates are required before declaring `rop.prove()` exam-ready or releasing it as target-verified functionality. A macOS build, Vitest run, or replay trace alone is insufficient for that claim.

## 14. Required documentation language

Documentation and command output shall use these terms consistently:

- `VERIFIED`: an asserted fact was compared with a debugger observation and matched under a complete, current fingerprint.
- `FAILED`: an exact asserted fact was compared and mismatched.
- `UNVERIFIED`: the fact was not safely comparable, the fingerprint was incomplete, or the requested postcondition was not observed.
- `UNEXPECTED_STOP`: the debugger stopped somewhere other than the next checkpoint; session position did not advance.
- `STALE_TARGET`: target identity or relevant runtime evidence changed after session creation.

The phrase "DEP bypass verified" may appear only when `objectiveStatus` is `VERIFIED` by the separate postcondition phase. It must never be inferred from `executionStatus` alone.
