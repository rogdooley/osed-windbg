# `rop.prove()` Windows x86 validation

Automated replay tests validate prediction, comparison, ownership, fingerprint, and postcondition state transitions. They do not prove that the WinDbg host adapter works against a real process. Run both gates below against the final `dist/osed.js` before treating the feature as exam-ready.

## Build and preflight

From a VS 2022 Developer Command Prompt:

```text
cmake -S tests\manual\rop_prove_target -B build\rop-prove -A Win32
cmake --build build\rop-prove --config Release
dumpbin /headers build\rop-prove\Release\rop_prove_target.exe
```

Confirm `machine (x86)` and a PE32 optional header. The CMake pointer-size guard intentionally rejects x64 builds. Start the target, attach WinDbg Preview, and load the final bundle:

```text
.scriptload C:\path\to\osed-windbg\dist\osed.js
dx @$osed().version()
dx @$osed().rop.scan_live("rop_prove_target")
dx @$osed().sc.iat_find("VirtualProtect")
```

Record the executable SHA-256, module base, gadget addresses, IAT slot, and `!vprot` output with the transcript.

## Gate A: guided gadget and IAT proof

1. Generate or supply a chain containing the exported dereference and dispatch sequence.
2. Start through `dx @$osed().rop.prove({mode:"guided"})`.
3. Confirm exactly one proof-marked one-shot breakpoint appears in `bl`.
4. Issue `g` yourself. After each stop run bare `dx @$osed().rop.prove()`.
5. At the dereference boundary, record EAX as the slot address, `dd eax L1` as the little-endian API target, and the next proof breakpoint. It must be at the slot contents, not the slot address or adjacent `jmp eax` gadget.
6. Confirm each checkpoint lists the EIP and absolute ESP assertions it evaluated. Introduce a controlled wrong stack transition once and confirm the first divergence halts without arming another checkpoint.
7. Cancel with `dx @$osed().rop.prove({action:"cancel"})`; verify unrelated breakpoints remain.

Gate A passes only when real stop states match, the dynamic target came from `[EAX]`, and no extension command resumed execution.

## Gate B: runtime DEP postcondition

1. Start a supported `VirtualProtect` or `VirtualAlloc` proof with `postcondition:true`.
2. At API entry, record the actual stack DWORDs. `VirtualProtect` uses runtime `lpAddress` and `dwSize`; `VirtualAlloc` uses returned EAX as the checked base.
3. Confirm `executionStatus` can be `VERIFIED` while `objectiveStatus` remains `UNVERIFIED` in `POSTCONDITION_ARMED`.
4. Issue `g` yourself, then call bare `rop.prove()` at the captured return address.
5. Compare the reported regions with `!vprot` across the complete runtime range.
6. Export the record with `{action:"export", path:"C:\\exam-notes\\proof.json"}` and optionally `format:"markdown"`.

Gate B passes only when API success and executable protection are observed after return. Reaching the API is not a verified DEP bypass.

## Failure and reload cleanup

- Unexpected stops do not consume a checkpoint.
- `STALE_TARGET` requires a new session; do not reuse old observations after a target or module change.
- After script reload, inspect `bl`, then use `{action:"cancel", orphans:true}`. Full marker and breakpoint identity are revalidated before deletion.
- An unreadable on-disk image intentionally caps execution at `UNVERIFIED` because target identity is incomplete.
