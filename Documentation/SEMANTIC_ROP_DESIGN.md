# Semantic ROP Design

This subsystem is library-first. It separates parsing, semantics, and ROP policy so future providers can reuse the same analysis core.

## Contracts

### Source adapters

Adapters convert external instruction listings into `InstructionSequence` objects.

Allowed:
- source-specific parsing
- provenance capture
- normalized instruction text

Forbidden:
- semantic interpretation
- ROP classification
- scoring

### Semantic engine

The semantic engine consumes `InstructionSequence` and emits `SemanticSequence`.

Allowed:
- register reads and writes
- stack effects
- memory effects
- flow effects
- confidence tracking
- bounded affine register net-effects

Forbidden:
- exploit policy
- gadget scoring
- chain planning
- symbolic execution

Invariant:
- Each instruction derives post-state register values and memory-address expressions from the entry-relative pre-instruction state, then commits all register updates atomically.
- This keeps multi-output instructions (`xchg`) and stack consumers (`pop reg ; pop reg`) correct: later stack reads are rebased to `ESP_entry + offset`, not repeatedly reported as raw `[esp]`.

### ROP policy

The ROP policy layer consumes `SemanticSequence` and produces `RopGadget`.

Allowed:
- classification
- scoring
- canonicalization
- capability indexing
- explanations

Forbidden:
- source parsing
- reinterpreting raw RP++ text

### Query semantics

`RopQuery` filters gadgets against the aggregated net-effects. Register preservation has two distinct, non-interchangeable meanings:

- `preserves`: the register's net transform at gadget exit is exactly identity (`reg_entry + 0`). Admits gadgets that clobber and restore, e.g. `xchg esi, eax ; add eax, 4 ; xchg esi, eax`. This is the default an exploit developer usually means.
- `preservesThroughout`: the register is never written by any instruction in the gadget. Strict; use when a live value must survive at every intermediate step, not only at exit.

`transforms` asserts a net `RegisterExpr` per register (`base` + `offset`, `offsetRegister`, `constant`, or `fromMemory`). Only the provided fields are checked. Consistent with the confidence discipline everywhere else, an `unknown` net transform satisfies no positive assertion, so an unproven gadget is never returned.

## Non-goals

Version 1 does not attempt:
- symbolic execution
- general value tracking
- flag propagation
- memory alias analysis
- branch feasibility
- chain synthesis
- graph search
- automatic ROP chain generation

Version 1 does allow bounded register net-effect tracking. The supported shape is intentionally small:
- unchanged register: `reg_entry + 0`
- register plus constant: `reg_entry + k`
- copied register plus constant: `other_reg_entry + k`
- constant value
- memory load from an affine address
- unknown

Closure boundary:
- One base register plus one constant is supported.
- One base register plus one register offset is supported only while no constant offset is also required.
- Multiple register offsets, scaled register terms, register-offset plus constant-offset combinations, and opaque arithmetic degrade to `unknown` by design.
- Controllability is not a semantic-layer fact. A transform such as `esi = esi + ecx` records a register-dependent expression; a later query or planner decides whether `ecx` is controlled in context.

## Supported instruction subset

The semantic engine starts with a narrow x86 subset:
- `pop reg`
- `push reg`
- `ret`
- `retn imm`
- `mov reg, reg`
- `mov reg, [reg]`
- `mov [reg], reg`
- `xor reg, reg`
- `add reg, reg`
- `add reg, imm`
- `sub reg, reg`
- `sub reg, imm`
- `neg reg`
- `inc reg`
- `dec reg`
- `xchg reg, reg`
- `leave`
- `call target`
- `jmp target`
- `nop`

Unsupported instructions are preserved but marked with unknown semantics.

## Confidence model

Each semantic field carries:
- exact values
- conservative values
- unknown flag

Confidence is one of:
- `EXACT`
- `CONSERVATIVE`
- `UNKNOWN`

## Adding a new semantic rule

1. Add a rule to `src/semantics/instruction-semantics.ts`.
2. Encode the minimum safe facts only.
3. Add a fixture snippet and a unit test.
4. If the rule affects ROP policy, update `src/rop/classifier.ts` or `src/rop/scoring.ts`.
