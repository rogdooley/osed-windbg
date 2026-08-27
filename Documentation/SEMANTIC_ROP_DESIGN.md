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

The semantic engine covers the x86 instructions relevant to ROP gadgets:

### Core
- `pop reg`, `push reg`, `pushad`
- `ret`, `retn imm`
- `mov reg, reg`, `mov reg, [reg]`, `mov [reg], reg`
- `xchg reg, reg`
- `leave`, `nop`
- `call target`, `jmp target`

### Arithmetic (affine-modeled)
- `add reg, reg`, `add reg, imm`
- `sub reg, reg`, `sub reg, imm`
- `neg reg`, `inc reg`, `dec reg`
- `xor reg, reg` (zero idiom tracked exactly)

### Arithmetic (unknown-expression — no affine model)
- `or reg, reg`, `or reg, imm`
- `and reg, reg`, `and reg, imm`
- `not reg`
- `adc reg, reg`, `adc reg, imm` (CF-dependent)
- `sbb reg, reg`, `sbb reg, imm` (CF-dependent)

These instructions record correct register reads, writes, and capability tags but degrade the net register transform to `unknown` because bitwise and carry-dependent operations do not fit the affine model.

Unsupported instructions are preserved but marked with unknown semantics.

## Capability kinds

The capability index tags each gadget with one or more `CapabilityKind` values:

### Data movement
- `LOAD_REGISTER`, `LOAD_CONSTANT`, `STACK_READ`, `STACK_WRITE`
- `MOVE_REGISTER`, `REGISTER_TRANSFER`, `EXCHANGE_REGISTER`, `REGISTER_SWAP`
- `ZERO_REGISTER`, `REGISTER_ZERO`
- `MEMORY_READ`, `LOAD_MEMORY`, `MEMORY_WRITE`, `STORE_MEMORY`
- `STACK_COPY`

### Arithmetic
- `REGISTER_ADD`, `REGISTER_SUB`, `REGISTER_XOR`
- `REGISTER_ADC`, `REGISTER_SBB`
- `REGISTER_OR`, `REGISTER_AND`, `REGISTER_NOT`
- `REGISTER_NEGATE`, `REGISTER_INCREMENT`, `REGISTER_DECREMENT`

### Control flow
- `DISPATCH_RET`, `DISPATCH_PUSHAD`
- `DISPATCH_CALL_REGISTER`, `DISPATCH_CALL_MEMORY`
- `DISPATCH_JMP_REGISTER`
- `STACK_PIVOT`, `STACK_ADJUST`

The `ARITHMETIC` query alias expands to all arithmetic capability kinds.

## Backward scanner

`scan_live` includes a backward scanner that discovers gadgets the pattern scanner misses. Where the pattern scanner matches fixed byte sequences ending in `C3`, the backward scanner:

1. Scans executable memory for `ret` (`C3`) and `ret N` (`C2 xx xx`) terminators
2. Decodes backward from each terminator using a lookup-table x86 mini-decoder (up to 12 bytes, 3 instructions)
3. Only decodes `mod=11` (register-register) ModRM to avoid variable-length memory operand ambiguity
4. Covers: inc/dec/push/pop, all ALU reg-reg (`add`/`or`/`adc`/`sbb`/`and`/`sub`/`xor`/`cmp`/`test`/`xchg`/`mov`), `neg`/`not`, group-1 imm8 (`83`), ALU eax-imm32 short forms, `call`/`jmp` reg, FPU D9 ops
5. Skips single-instruction gadgets already covered by the pattern scanner

The backward scanner is x86-only (0x40–0x4F are REX prefixes in x64) and runs in O(memory) time.

## Value construction solver

`solveValue()` in `src/rop/value_solver.ts` addresses the common DEP-bypass problem where a target register value contains badchar bytes (e.g. `0x00001000` for `dwSize` or `0x40` for `PAGE_EXECUTE_READWRITE`). It searches the capability index for arithmetic gadgets and constructs the value using a short gadget chain where all stack-placed immediates are badchar-free.

Seven fixed-shape recipes are tried in preference order (shortest chain first):

1. **direct** — `pop dst ; ret` with the raw value (when it happens to be clean)
2. **negate** — `pop dst ; ret` with −V, then `neg dst ; ret`
3. **complement** — `pop dst ; ret` with ~V, then `not dst ; ret`
4. **two-add** — `pop dst` A + `pop scratch` B + `add dst, scratch` where A + B = V
5. **two-sub** — same shape with `sub` where A − B = V
6. **zero-add** — `xor dst, dst` + `pop scratch` V + `add dst, scratch` (when `pop dst` is unavailable)
7. **zero-sub-neg** — `xor dst, dst` + `pop scratch` V + `sub dst, scratch` + `neg dst`

Two-value decomposition (recipes 4–5) probes ~25 uniform-byte candidates then falls back to a single-byte exhaustive sweep — O(256) worst case, instant in practice.

The solver accounts for `ret N` padding and side-effect pops from multi-instruction gadgets. Output is a `ChainStep[]` array compatible with `formatChainPython()` and the synthesis pipeline.

Exposed to WinDbg as `rop.construct(register, value, badchars?)`. Also available as a callback parameter to `planRegisterSetup()` for automatic fallback when a register cannot be satisfied by direct pop.

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
