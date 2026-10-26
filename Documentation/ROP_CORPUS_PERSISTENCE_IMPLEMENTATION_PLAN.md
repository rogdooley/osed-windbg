# ROP Corpus Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make live ROP discovery accurate and preserve a complete, validated corpus across debugger sessions.

**Architecture:** Keep scanner decoding, semantic classification, and corpus persistence separated. The index owns corpus lifecycle and access guards; a new pure persistence module serializes, deserializes, fingerprints, and compares the catalog.

**Tech Stack:** TypeScript 5.9, Vitest 3.2, WinDbg JavaScript host APIs.

**Spec:** `Documentation/ROP_CORPUS_PERSISTENCE_DESIGN.md`

## Global Constraints

- Preserve the read-only debugger interaction model.
- Treat imported corpora as unusable until explicit successful validation.
- Preserve unknown facts instead of inferring gadget safety.
- Store JSON as the canonical interchange artifact; no new dependencies.

## Review Focus

- Imported JSON with an unsupported schema must not load a usable corpus.
- A missing, rebased, or changed module must keep an imported corpus stale.
- A changed sampled gadget byte must keep an imported corpus stale.
- Memory `xchg` must be discoverable but never appear as a register exchange.
- `pop esp` must remain discoverable without becoming a general load candidate.

---

### Task 1: Correct scanner boundaries and memory-operand decoding

**Files:**
- Modify: `src/core/backward_scanner.ts`
- Modify: `src/analysis/live_gadgets.ts`
- Test: `tests/backward_scanner.test.ts`

**Interfaces:**
- Produces decoded four-instruction gadgets and `mod=00` base-register memory operands.
- Preserves `scanBackward()` return shape and `LiveDiscoveryResult.stats.rejected` semantics.

- [ ] Write failing decoder tests for `xchg dword [ecx], eax` and a four-instruction `push ebp ; xchg dword [ecx], eax ; pop ebp ; ret` sequence.
- [ ] Run `npm test -- tests/backward_scanner.test.ts` and confirm the new assertions fail.
- [ ] Implement bounded base-register memory decoding and raise live backward scanning to four pre-terminator instructions.
- [ ] Write a failing regression test proving rejected count is never inferred from discovered gadgets.
- [ ] Replace summary arithmetic with the explicit rejected statistic.
- [ ] Run the focused tests and confirm they pass.

### Task 2: Correct semantic capabilities and dispatch labels

**Files:**
- Modify: `src/rop/types.ts`
- Modify: `src/rop/capabilities.ts`
- Test: `tests/semantic_pipeline.test.ts`
- Test: `tests/architecture_integration.test.ts`

**Interfaces:**
- Adds `DISPATCH_JMP_MEMORY` to `CapabilityKind`.
- Makes non-ESP `pop` the only `LOAD_REGISTER`/stack-value source.
- Models memory `xchg` as memory read/write effects rather than register exchange.

- [ ] Write failing capability assertions for `pop esp`, `jmp dword [eax]`, and `xchg dword [ecx], eax`.
- [ ] Run the focused semantic tests and confirm expected failures.
- [ ] Implement the minimal capability and semantic rules.
- [ ] Run the focused tests and confirm they pass.

### Task 3: Add versioned corpus serialization and validation

**Files:**
- Create: `src/rop/corpus_store.ts`
- Modify: `src/rop/types.ts`
- Modify: `src/index.ts`
- Modify: `src/core/help_catalog.ts`
- Test: `tests/corpus_store.test.ts`

**Interfaces:**
- `exportCorpus(index, context) -> string` emits versioned JSON.
- `importCorpus(text) -> ImportedCorpus` rejects malformed or incompatible JSON.
- `validateCorpus(imported, liveModules, readMemory) -> ValidationResult` compares module identity/base/size and sampled bytes.
- Publishes `rop.corpus.export(path)`, `rop.corpus.import(path)`, and `rop.corpus.validate()`.

- [ ] Write failing pure-module tests for round-trip, incompatible schema, matching validation, changed module mapping, and changed sampled byte.
- [ ] Run `npm test -- tests/corpus_store.test.ts` and confirm the expected failures.
- [ ] Implement serialization, strict deserialization, and bounded fingerprint capture/comparison without target mutation.
- [ ] Write failing API-level tests showing imported corpora are guarded before validation and enabled after validation.
- [ ] Wire the corpus namespace, filesystem I/O, command help, and corpus-operation guard.
- [ ] Run corpus tests and confirm they pass.

### Task 4: Document and verify the public workflow

**Files:**
- Modify: `README.md`
- Modify: `Documentation/COMMANDS.md`
- Modify: `Documentation/GADGET_DISCOVERY.md`
- Modify: `Documentation/SEMANTIC_ROP_DESIGN.md`

- [ ] Document corpus export/import/validate, validation limitations for RP++ provenance, and capability-count semantics.
- [ ] Run `npm test`, `npm run typecheck`, and `npm run build`.
- [ ] Inspect `git diff --check` and review the public command examples against the implementation.
