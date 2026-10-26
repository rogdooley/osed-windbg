# ROP Corpus Persistence Design

## Intent

Preserve a complete semantic ROP gadget catalog across a debugger restart
without allowing stale addresses to be used accidentally. Correct capability
labels so the catalog describes usable gadget effects rather than incidental
instructions.

## Goals

- Report live scan accepted and rejected counts accurately.
- Do not label `pop esp` as a general register or constant load.
- Represent both register and memory-indirect dispatch explicitly.
- Discover bounded memory-operand gadgets used for data movement, including
  the supplied `push ebp ; xchg dword [ecx], eax ; pop ebp ; ret` sequence.
- Export/import the full corpus as versioned JSON.
- Require explicit live validation before an imported corpus may be queried,
  planned, emitted, synthesized, or exported as a chain.

## Non-goals

- Persist exploit state, plans, or generated chains.
- Prove that a gadget is exploitable or that its stack source is controlled.
- Reconstruct RP++ provenance that was not supplied at scan time.

## Approaches

1. Evidence-only export: safest but cannot satisfy restart reuse.
2. Validated reuse: import as stale, then compare module identity/base and
   sampled instruction bytes before enabling corpus operations. **Selected.**
3. Immediate reuse: convenient but unsafe when a binary changes or relocates.

## Design

`rop.corpus.export(path)` writes canonical JSON containing corpus schema
version, gadgets, locations, semantic summaries, capabilities, scan metadata,
and a validation fingerprint. Each fingerprint records every resolvable module
that backs a gadget (name, path, base, size) and a bounded sample of gadget
address/instruction bytes.

`rop.corpus.import(path)` accepts only the export schema, restores the catalog
in a `stale-imported` state, and makes the status visible to the user.
`rop.corpus.validate()` rebuilds the fingerprint from the live target. It
enables the corpus only when module identity/base/size and every sampled byte
match; otherwise it leaves the corpus unavailable and reports the mismatch.

Existing live and RP++ scans create an active corpus immediately. For RP++
input without module provenance, export records byte samples but no module
identity mapping. Such an import can be validated only by those exact live
bytes, not by image identity, so users should prefer a live scan when module
identity is required.

Capability derivation will only label a general register load for non-ESP
`pop`. `pop esp` is represented as a stack-control effect and remains visible
through semantic writes/transforms. `jmp [memory]` receives a distinct
`DISPATCH_JMP_MEMORY` capability. Capability summaries will state that counts
are deduplicated semantic gadgets, not raw address occurrences.

The live backward scanner will raise its pre-terminator instruction bound from
three to four and decode the safe, unambiguous base-register ModRM memory form
(`mod=00`, no SIB or displacement) for supported `mov` and `xchg` opcodes.
This is sufficient for `xchg dword [ecx], eax` while keeping the initial parser
bounded; displacement and SIB forms remain explicit future work rather than
silently guessed. Memory `xchg` will be modeled as a memory read and write,
not as an `EXCHANGE_REGISTER` capability.

## Verification

Regression tests cover the negative-rejection case, ESP capability labels,
memory-indirect jump dispatch, the four-instruction memory-exchange gadget,
export/import round-trip, successful validation, mismatched module/bytes, and
guard behavior before validation.
The complete Vitest suite, TypeScript typecheck, and production bundle build
must pass.
