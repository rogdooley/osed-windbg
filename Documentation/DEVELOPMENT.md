# Development Guide

## Registry Pattern

- Each command is a `Command` object registered centrally.
- `initializeScript()` builds registry, publishes `osed`, and tries to register an alias so calls use `@$osed().<command>(...)`.
- If alias registration is rejected by the host, the script still loads and exposes the fallback global object.
- `@$osed().<command>(...)` dispatches through `registry.execute`.
- Shared `validation.ts` enforces schema and unknown-key rejection.

## Add a New Command (<=10 steps)

1. Create `src/commands/<name>.ts`.
2. Export `create<Name>Command(): Command`.
3. Define `name`, `description`, `usage`, `examples`, `schema`.
4. Put input checks in shared schema where possible.
5. Keep host interaction minimal in command file.
6. Move pure algorithms to `src/logic/`.
7. Return structured `CommandResult`.
8. Add deterministic output table/section text.
9. Register command in `src/index.ts`.
10. Document it in `Documentation/COMMANDS.md`.

## Analysis Layer

Read `Documentation/ANALYSIS_ARCHITECTURE.md` before adding or changing code under `src/analysis/`.

The analysis layer owns debugger evidence collection and normalization. Commands consume and render that evidence. If a command needs evidence that is not available, extend the analysis contract and its tests instead of querying WinDbg or duplicating classification logic in the command.

Current analysis modules:

- `analysis/memory.ts`: normalizes region protection, state, and type while preserving raw numeric values.
- `analysis/landing.ts`: samples landing bytes and emits atomic, range-backed observations.

Tests for analysis code must cover unknown separately from confirmed false. Confidence tests must also verify bounds and order independence when aggregation is involved.

## Rebuild and Reload During Live Debugging

1. `npm run build`
2. In WinDbg: `.scriptload <path>\\dist\\osed.js`
3. Rebind in-session: `dx @$osed().reload()`
4. Verify command surface: `dx @$osed().help()`

## host.* Typing Notes

This project intentionally limits declarations to:

- `host.diagnostics.debugLog`
- `host.memory.readMemoryValues`
- `host.currentProcess`
- `host.currentThread`

Reason: avoid relying on undocumented APIs and reduce runtime mismatch risk across WinDbg builds.
