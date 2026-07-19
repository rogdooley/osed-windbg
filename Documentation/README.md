# OSED WinDbg Toolkit

TypeScript-based WinDbg Preview data-model script for exploit-development helpers.

## Try It

If you only want to see the built JavaScript do something useful, use this path:

1. Load the bundle in WinDbg Preview:
   - `.scriptload <full path>\\osed-windbg\\dist\\osed.js`
2. Confirm the command surface:
   - `dx @$osed().help()`
3. Pick a loaded module and inspect its mitigation state:
   - `dx @$osed().modules("kernel32")`
4. Find a classic import target:
   - `dx @$osed().sc.iat_find("VirtualProtect")`
5. Print a ready-made exploit skeleton:
   - `dx @$osed().rop_template("VirtualProtect", "essfunc")`
6. Load RP++ output into the semantic ROP index:
   - `dx @$osed().rop.scan("0x1000: pop eax ; ret ;")`
7. Inspect the semantic capability catalog:
   - `dx @$osed().rop.capabilities()`
8. Query the loaded corpus:
   - `dx @$osed().rop.query({ writes: ["eax"], capability: "LOAD_REGISTER" })`

That sequence shows the script’s value without requiring any prior setup beyond a live debug target.

## Prerequisites

- WinDbg Preview (modern JavaScript provider)
- Node.js 20+
- x86 for the full classic OSED workflow; x64 for memory, landing, PE/import/export, math, triage context, and RSP gadget evidence.

## Install and Build

1. Clone this repository.
2. Change into the project directory:
   - `cd osed-windbg`
3. Install dev dependencies:
   - `npm install`
4. Build bundle:
   - `npm run build`
5. In WinDbg Preview:
   - `.scriptload <full path>\\osed-windbg\\dist\\osed.js`

## Quickstart

- `dx @$osed().help()`
- `dx @$osed().pattern_create(300, "msf")`
- `dx @$osed().pattern.create(300, "msf")`
- `dx @$osed().exploit("offset")`
- `dx @$osed().seh()`
- `dx @$osed().seh.visualize()`
- `dx @$osed().triage()`
- `dx @$osed().memory(0x0012F800)`
- `dx @$osed().can_execute(0x0012F800)`
- `dx @$osed().landing()`
- `dx @$osed().math(0xFFFFFFD6, 32)`
- `dx @$osed().rop_suggest({ module: "essfunc", engine: "semantic" })`
- `dx @$osed().rop.scan("0x1000: pop eax ; ret ;")`
- `dx @$osed().rop.query({ capability: "STACK_PIVOT", executableOnly: true })`
- `dx @$osed().rop.capabilities()`
- `dx @$osed().sc.peb()`
- `dx @$osed().sc.modules()`
- `dx @$osed().sc.module_pages("kernel32")`
- `dx @$osed().sc.page_summary("kernel32")`
- `dx @$osed().sc.base("kernel")`
- `dx @$osed().sc.pe("kernel32")`
- `dx @$osed().sc.hashes("kernel32", "crc32")`
- `dx @$osed().sc.hash("WinExec", "ROR13")`
- `dx @$osed().sc.hashresolve("kernel32", 0x7c0dfcaa, "ROR13")`
- `dx @$osed().sc.algorithms()`
- `dx @$osed().sc.exportdir("kernel32")`
- `dx @$osed().sc.export("kernel32", "GetProcAddress")`
- `dx @$osed().sc.exportat("kernel32", 842)`
- `dx @$osed().sc.exportwalk("kernel32", "GetProcAddress")`
- `dx @$osed().sc.iat()`
- `dx @$osed().sc.iat("app.exe")`
- `dx @$osed().sc.iat("app.exe", "Virtual")`
- `dx @$osed().sc.iat_find("VirtualAlloc")`
- `dx @$osed().sc.iat_ptr("app.exe", "VirtualAlloc")`

For the full command matrix, see `Documentation/COMMANDS.md`.

For the normative dependency and evidence rules governing `src/analysis/`, see `Documentation/ANALYSIS_ARCHITECTURE.md`.

## Troubleshooting

- Script fails to load:
  - Confirm `dist/osed.js` exists and path is correct.
- `@$osed` is missing:
  - Re-run `.scriptload` and confirm `initializeScript()` executed.
  - If the script reports `functionAlias` registration failure, use the fallback global object directly: `dx osed.help()` or `dx osed.reload()`.
- Command returns validation errors:
  - Use `dx @$osed().help("<name>")` and match schema exactly.
- Memory read failures:
  - Ensure target process is active and addresses are valid in current context.
- `dx` result output is noisy:
  - Command calls return `true/false`; inspect full structured output with `dx @$osed().last_result()`.
