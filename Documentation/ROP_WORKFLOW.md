# ROP Chain Construction Workflow

This guide walks through the end-to-end process of discovering ROP gadgets,
planning a DEP bypass strategy, and constructing an exploit chain using the
`osed-windbg` toolkit. Each step builds on the previous one.

## Prerequisites

- WinDbg Preview with `osed.js` loaded
- A debugged process stopped at or near a crash (e.g. an access violation
  from a buffer overflow)
- A non-ASLR module in the target process to source gadgets from

## Step 1: Triage the crash

```js
dx @$osed().triage()
```

Captures the full crash state: EIP control evidence, stack layout, SEH chain,
register values, and bad characters. This populates the internal exploit state
used later by the synthesizer.

Review the output for:
- **EIP controlled** — confirms you have instruction pointer control
- **Control mechanism** — `saved-ret` or `seh` determines your chain shape
- **Stack bytes after ESP** — how much contiguous controlled space you have
- **Bad characters** — bytes that get mangled in transit (null, newline, etc.)

## Step 2: Identify gadget source modules

```js
dx @$osed().modules()
```

Look for modules where:
- **ASLR = false** — addresses won't change between runs
- **Rebase = false** — preferred base address is used
- **SafeSEH = false** — required if exploiting via SEH

These modules provide stable gadget addresses for your chain.

## Step 3: Scan for gadgets

```js
dx @$osed().rop.scan_live("modulename.dll", "00 0A 0D")
```

Replace `modulename.dll` with your target module and `"00 0A 0D"` with
your actual bad characters (space-delimited hex bytes). Add `true` as the
third argument to restrict to executable sections only:

```js
dx @$osed().rop.scan_live("modulename.dll", "00 0A 0D", true)
```

This runs two scanners:
- **Pattern scanner** — matches known byte sequences ending in `ret` (`C3`)
- **Backward scanner** — walks backward from `ret`/`ret N` terminators to
  discover multi-instruction gadgets, arithmetic operations (`add`, `sub`,
  `neg`, `not`, `xor`, etc.), and `ret N` variants the pattern scanner misses

All discovered gadgets pass through the semantic pipeline (instruction
parsing, effect composition, capability derivation, scoring) and addresses
containing bad-character bytes are filtered out.

You can scan multiple modules — results accumulate into a single corpus:

```js
dx @$osed().rop.scan_live("module1.dll", "00 0A 0D", true)
dx @$osed().rop.scan_live("module2.dll", "00 0A 0D", true)
```

## Step 4: Survey available capabilities

```js
dx @$osed().rop.capabilities()
```

Shows the full capability inventory: how many gadgets provide each type of
operation (register loads, zero, move, exchange, arithmetic, memory access,
stack pivots, dispatch).

To inspect specific capability categories:

```js
dx @$osed().rop.query("capability", "LOAD_REGISTER")
dx @$osed().rop.query("capability", "ARITHMETIC")
dx @$osed().rop.query("capability", "REGISTER_ADD")
dx @$osed().rop.query("capability", "STACK_PIVOT")
```

The `ARITHMETIC` alias expands to all eleven arithmetic capability kinds,
useful for surveying value-construction gadgets.

To find gadgets that write or preserve specific registers:

```js
dx @$osed().rop.query("writes", "eax")
dx @$osed().rop.query("preserves", "ebx")
```

## Step 5: Plan the exploit strategy

```js
dx @$osed().rop.plan("VirtualProtect")
```

Also available: `"VirtualAlloc"` and `"WriteProcessMemory"`.

The planner evaluates six chain shapes against the loaded corpus and reports
which are feasible, their complexity, required capabilities, and
preconditions. The recommended shape is marked.

Common shapes in order of complexity:
- **SYNTHETIC_STDCALL_FRAME** — lay the API call frame directly on the stack
- **STACK_PIVOT_FRAME** — pivot ESP to a controlled region holding the frame
- **RET_DISPATCH** — return into the API address already on the stack
- **PUSHAD_DISPATCH** — load registers then `pushad` to build the frame
- **CALL_REGISTER / JMP_REGISTER** — load API into a register and dispatch

## Step 6: Synthesize the stack layout

```js
dx @$osed().rop.synthesize(1, "SYNTHETIC_STDCALL_FRAME")
```

Pass the plan ID (from step 5) and the chosen shape. The synthesizer
produces a concrete stack layout showing each word's offset, role, and value.

Review the status:
- **complete** — all values resolved and badchar-clean
- **complete-with-violations** — layout produced but some values contain
  bad-character bytes (see step 7)
- **blocked** — missing required capabilities

Placeholders like `VIRTUALPROTECT`, `RETURN_ADDR`, and `LP_ADDRESS` must be
resolved with actual addresses before use.

## Step 7: Construct badchar-tainted values

When the synthesizer flags violations (e.g. `dwSize = 0x00000201` contains
null bytes), use the value solver to construct those values arithmetically:

```js
dx @$osed().rop.construct("ebx", 0x201, "00 0A 0D")
dx @$osed().rop.construct("edx", 0x40, "00 0A 0D")
```

The solver tries seven recipes in preference order:

| Recipe | Method | When it works |
|--------|--------|---------------|
| direct | `pop reg` | Value has no bad bytes |
| negate | `pop reg` + `neg reg` | −V has no bad bytes |
| complement | `pop reg` + `not reg` | ~V has no bad bytes |
| two-add | `pop reg` + `pop scratch` + `add reg, scratch` | A + B = V, both clean |
| two-sub | `pop reg` + `pop scratch` + `sub reg, scratch` | A − B = V, both clean |
| zero-add | `xor reg, reg` + `pop scratch` + `add reg, scratch` | No `pop reg` available |
| zero-sub-neg | `xor reg, reg` + `pop scratch` + `sub reg, scratch` + `neg reg` | Last resort |

Output includes paste-ready Python `pack()` lines and accounts for `ret N`
padding and side-effect pops automatically.

## Step 8: Export to Python

```js
dx @$osed().rop.export(1)
```

Writes the emitted gadgets or synthesized layout as a Python exploit stub
with `struct.pack` lines.

## Alternative paths

### PUSHAD chains (legacy)

If using the PUSHAD dispatch shape, the legacy chain builders provide a
more direct path:

```js
dx @$osed().rop.chain_vp(0x7C801AD0)
dx @$osed().rop.chain_wpm(0x7C802213)
dx @$osed().rop.chain_va(0x7C809AE1)
```

Pass the API address as the first argument. These builders use `pop`/`xor`
gadgets from the loaded corpus to set up registers for the PUSHAD frame.

For a generic register-setup chain without a specific API layout:

```js
dx @$osed().rop.chain("eax", 0xDEADBEEF, "ebx", 0x1000)
```

### Flat stdcall frames (no gadgets needed)

When you already have the API address and just need the call frame laid out
as data words:

```js
dx @$osed().rop.frame_vp(vpAddr, retAddr, lpAddr, dwSize, flProtect, writable, "00 0A 0D")
dx @$osed().rop.frame_wpm(wpmAddr, retAddr, hProcess, lpBase, lpBuf, nSize, writable, "00 0A 0D")
dx @$osed().rop.frame_va(vaAddr, retAddr, lpAddr, dwSize, allocType, flProtect, "00 0A 0D")
```

These require no loaded corpus. Every concrete value is checked against the
badchar set and violations are reported.

### Stack pivots

For SEH or heap-spray exploits where you need to redirect ESP to a
controlled region:

```js
dx @$osed().rop.pivots()
dx @$osed().rop.pivots("eax")
```

Finds, classifies, and ranks pivot gadgets. Filter by source register to
find pivots that use a register you control.

## Typical flow

For most saved-return-address DEP bypasses, the workflow is:

1. `triage()` — understand the crash
2. `modules()` — pick a gadget source
3. `rop.scan_live(module, badchars)` — build the corpus
4. `rop.capabilities()` — confirm you have what you need
5. `rop.plan("VirtualProtect")` — choose a strategy
6. `rop.synthesize(planId, shape)` — get the stack layout
7. `rop.construct(reg, value, badchars)` — solve any badchar violations
8. Paste the Python output into your exploit

For SEH exploits, add `rop.pivots()` after step 3 to find a pivot gadget
for the SEH handler, and use the `seh_ppr()` command to find POP/POP/RET
candidates.
