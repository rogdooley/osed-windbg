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

Forbidden:
- exploit policy
- gadget scoring
- chain planning
- symbolic execution

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

## Non-goals

Version 1 does not attempt:
- symbolic execution
- value tracking
- flag propagation
- memory alias analysis
- branch feasibility
- chain synthesis
- graph search
- automatic ROP chain generation

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

