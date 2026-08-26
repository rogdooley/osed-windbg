# Changelog

This changelog reconstructs the functional history of `osed-windbg` from Git.
Development began inside the `OSED-Toolkit` repository and moved to this
standalone repository on 2026-07-09. Dates below describe when functionality
first appeared or materially changed; they are not package release dates.

## Timeline

### 2026-08-26 - Backward scanner and arithmetic pipeline

- Added backward scanner to `scan_live` that discovers multi-instruction gadgets,
  `ret N` terminators, and register-register arithmetic the pattern scanner misses.
  Scans executable memory for `C3`/`C2` terminators and decodes backward using a
  lookup-table x86 mini-decoder (mod=11 register-register only). Covers ALU ops
  (`add`/`sub`/`or`/`and`/`adc`/`sbb`/`xor`/`neg`/`not`/`inc`/`dec`), mov/xchg/test,
  call/jmp reg, group-1 imm8, ALU eax-imm32 short forms, and FPU D9 ops.
- Extended the semantic engine with rules for `or`, `and`, `not`, `adc`, and `sbb`
  (register-register and register-immediate forms). These degrade to unknown net
  transforms since bitwise and carry-dependent operations do not fit the affine model.
- Added five new `CapabilityKind` values: `REGISTER_ADC`, `REGISTER_SBB`,
  `REGISTER_OR`, `REGISTER_AND`, `REGISTER_NOT`.
- Added `ARITHMETIC` query alias so `rop.query("capability", "ARITHMETIC")` matches
  all eleven arithmetic capability kinds in a single query.
- Backward scanner stats (terminators found, new gadgets) are now reported in the
  `scan_live` corpus summary.

### 2026-08-24 - Semantic ROP pipeline completion and exploit state

- Added `rop.plan()` to analyze semantic capabilities and produce feasible
  exploit strategies with feasibility levels, preconditions, and ranked
  recommendations for VirtualProtect, VirtualAlloc, and WriteProcessMemory.
- Added `rop.emit()` to select and rank concrete gadgets for a planned strategy,
  producing a gadget assignment with scores and side-effect counts.
- Added `rop.synthesize()` to combine a plan with exploit state and produce a
  concrete stack layout. Evaluates three entry paths (RET_TO_FRAME, DIRECT_API,
  PIVOT_TO_FRAME) and reports status as complete, complete-with-violations, or
  blocked.
- Added `rop.export()` to write emitted gadgets and synthesized layouts as
  Python exploit stubs with `struct.pack` lines. Supports console output or
  file write via WinDbg `.logopen`/`.logclose`.
- Added `rop.pivots()` to find, classify, and rank stack pivot gadgets from the
  corpus. Classifies pivots as register (xchg/mov esp), esp-adjust (add/sub
  esp), or memory (indirect). Supports filtering by source register or minimum
  ESP delta.
- Added `exploit.state()` and `exploit.clear()` to view, set, and manage the
  cached exploit state used by the synthesizer. State is populated automatically
  by `triage()` and individual fields can be overridden manually.
- Added badchar address filtering to `rop.scan()` for RP++ text input, matching
  the filtering already available in `rop.scan_live()`.

### 2026-07-22 - Live ROP indexing and native chain construction

- Added `rop.scan_live()` to discover known gadget patterns directly from live
  executable target memory, apply bad-character address filtering, and feed the
  surviving hits into the semantic capability index without RP++.
- Added `rop.chain()` to emit paste-ready register-setup chains from the loaded
  corpus using real gadget addresses, with support for xor-zero targets, pure
  multi-pop co-satisfaction, and single-pop fallback.
- Added PUSHAD goal planners for DEP-bypass workflows. `rop.chain_vp()` now
  defaults to the RET-slide VirtualProtect layout, while constrained
  `rop.chain_wpm()` and `rop.chain_va()` report their saved-ESP argument
  assumptions instead of presenting them as unconstrained complete chains.
- Added flat stdcall frame emitters (`rop.frame_vp()`, `rop.frame_wpm()`, and
  `rop.frame_va()`) for the no-gadget case. They require no loaded ROP corpus,
  emit the API return target plus arguments as data words, and check every
  concrete dword against the caller's bad-character set.

### 2026-03-24 - Initial WinDbg exploit-development toolkit

The first implementation appeared in `OSED-Toolkit` as a TypeScript/JavaScript
extension for WinDbg Preview. It already provided the core classic stack-
exploitation workflow:

- Cyclic-pattern creation and offset lookup.
- Bad-character comparison.
- Module enumeration with exploit-mitigation inspection.
- SEH-chain walking.
- ROP, stack-pivot, and raw-byte scanning.
- Egghunter generation.
- Shared memory, output, command-registry, scan-engine, and validation layers.

The remainder of the day was spent making that first command surface work in
the actual WinDbg JavaScript host. The bundle changed from CommonJS-style
output to a global `initializeScript` entry point, gained `dx` positional-
argument support and an `@$osed()` alias, and hardened module/address parsing.
SEH handling evolved to discover the 32-bit TEB under WoW64 and tolerate
WinDbg model pointer objects instead of assuming ordinary JavaScript numbers.

### 2026-03-29 - Ranked SEH gadget discovery

- Added validated `pop reg; pop reg; ret` instruction patterns.
- Added `seh_ppr()` to find and rank POP/POP/RET candidates.
- Expanded recognition from a narrow pattern to the full supported register
  combinations.

This was the first move from raw gadget searching toward exploit-specific
validation and ranking.

### 2026-04-12 - Egghunter workflow

- Added WinDbg-facing exploit/egghunter helpers, extending the toolkit beyond
  crash inspection and gadget discovery into payload construction.

### 2026-05-01 to 2026-05-12 - Shellcode and PE analysis

- Added the `sc` shellcode namespace: module and PE inspection, export walking,
  API hashing and resolution, and shellcode-oriented helpers.
- Added IAT discovery and inspection.
- Adapted nested results into objects WinDbg's `dx` evaluator could expand.
- Added shellcode analysis features developed alongside Shellforge.
- Added `triage()`, combining control-state, SEH, stack context, and gadget
  observations into a first-response command.

At this point the project had changed from a collection of independent
commands into a debugger-resident workflow assistant.

### 2026-06-22 - Payload and ROP workflow expansion

- Added XOR payload encoding with bad-character-aware key selection.
- Added NOP generation.
- Expanded ROP instruction validation and gadget suggestions.
- Added PUSHAD-oriented ROP templates.
- Hardened pattern, SEH, memory, and scan behavior with focused tests.

### 2026-07-05 - Semantic ROP engine

- Introduced a semantic intermediate representation for instructions and
  instruction sequences.
- Added canonicalization, effect composition, gadget classification,
  capability derivation, and scoring.
- Added an RP++ text provider and semantic-pipeline fixtures.
- Extended `rop_suggest()` with selectable `fast` and `semantic` engines.
- Added WinDbg alias fallback for hosts that could not publish the preferred
  namespace form.

This was the largest architectural change: gadgets could now be selected by
what they do, rather than only by matching byte or instruction patterns.

### 2026-07-08 to 2026-07-09 - Query surface and format strings

- Added page-protection summaries to the shellcode/PE inspection surface.
- Added `rop.scan()`, `rop.query()`, and `rop.capabilities()` over RP++ output.
- Added pivot queries backed by the same semantic machinery.
- Made negative memory constraints fail safely when semantics are unknown.
- Added `fmt.offset()` and `fmt.build()` for format-string argument discovery
  and `%n`-family write payload construction.

### 2026-07-09 - Standalone initial release

The complete extension was copied from `OSED-Toolkit/osed-windbg` into this
repository as commit `9db6bfb`. The snapshot contained the established command
surface, semantic ROP subsystem, tests, documentation, and a self-contained
`dist/osed.js` bundle. This is a repository migration boundary, not the true
beginning of the project.

The first standalone fix corrected `triage()` so instruction-pointer control
is reported only when the value actually contains recognizable user-controlled
evidence, rather than merely being nonzero.

### 2026-07-16 - Evidence-first analysis layer

- Added normalized `memory()` evidence with tri-state permission fields.
- Added `landing()` analysis for stack/address bytes, memory permissions,
  patterns, markers, NOP runs, and disassembly observations.
- Changed `triage()` to consume shared landing evidence instead of duplicating
  reads and interpretation.
- Added an explicit analysis-architecture contract separating evidence
  collection from user-facing conclusions.
- Fixed `dx` expansion by returning debugger-safe data shapes.

### 2026-07-19 - x64, math, help, and richer semantic queries

- Extended applicable commands to x64 register names, pointer widths,
  `JMP/CALL RSP`, and RSP pivot patterns.
- Added `math()` for signed, unsigned, hexadecimal, little-endian, and two's-
  complement views.
- Expanded semantic ROP queries with chain-oriented effects and constraints.
- Added IAT documentation and related semantic coverage.
- Rebuilt help around a centralized catalog with per-command schemas and
  executable examples.
- Published `rop` as a plain namespace object for more predictable `dx` use.

### 2026-07-20 to 2026-07-21 - WinDbg output and IAT hardening

- Added examples directly to help results.
- Introduced debugger markup/link result handling.
- Made IAT inspection tolerate unreadable thunks and improved thunk reading.
- Added build-derived version metadata and a `version()` command.
- Corrected table padding around DML links, then simplified markup where it
  impaired readability.

## Functional arc

In short, the project evolved through these stages:

1. Mechanical exploit primitives: patterns, bad characters, modules, SEH, and
   raw gadget scanning.
2. Workflow commands: ranked PPR discovery, shellcode/PE inspection, IAT
   resolution, and integrated crash triage.
3. Payload assistance: encoders, egghunters, NOPs, and ROP templates.
4. Semantic analysis: effect-based gadget classification, scoring, and query.
5. Evidence-first diagnostics: normalized memory and landing observations
   shared by commands.
6. Product hardening: x64 coverage, structured help, debugger-safe results,
   IAT resilience, versioning, and readable WinDbg output.

## History sources

- Pre-migration history: `OSED-Toolkit`, path `osed-windbg/`, commits
  `9eb9764` through `ad5b08d`.
- Standalone history: this repository, beginning with `9db6bfb`.
