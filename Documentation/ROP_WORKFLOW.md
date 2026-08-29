# ROP Chain Construction Workflow

This guide walks through the end-to-end process of discovering ROP gadgets,
planning a DEP bypass strategy, and constructing an exploit chain using the
`osed-windbg` toolkit. Each step builds on the previous one.

Companion references: [GADGET_DISCOVERY.md](GADGET_DISCOVERY.md) for finding
specific gadgets, and [ROP_API_REFERENCE.md](ROP_API_REFERENCE.md) for API
prototypes, constant values, and the PUSHAD register maps.

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
- **ASLR = disabled** — the module loads at its preferred base, so addresses
  won't change between runs (this is also the rebase signal: ASLR disabled means
  `DYNAMIC_BASE` is not set, so the loader uses the preferred base)
- **NX_COMPAT = disabled** — the module opts out of DEP
- **SafeSEH = disabled** — required if exploiting via SEH

Columns report `enabled`/`disabled`/`unknown`, not true/false. The
`triage()` MODULE SCORE table already ranks these for you and lists every
ASLR-disabled (attacker-controlled) module; `modules()` shows the full set.
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

To hunt for a *specific* gadget in the corpus (e.g. a clean `pop eax ; ret`)
with `rop.query`, see [GADGET_DISCOVERY.md](GADGET_DISCOVERY.md).

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

Also available: `"VirtualAlloc"`, `"WriteProcessMemory"`, `"VirtualProtectEx"`,
`"VirtualAllocEx"`, and `"WinExec"`. The `Ex` variants take a leading
`hProcess` handle (`GetCurrentProcess()` = `0xFFFFFFFF`) and are drop-in
substitutes when only the `Ex` form is importable. `"WinExec"` is a
command-execution payload (a two-argument `stdcall` frame), not a DEP bypass:
use it when the goal is running a command rather than running shellcode.

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

## Reference: `RET` vs `RET N` and stack alignment

In a ROP chain, `ESP` is your instruction pointer: after every gadget's `RET`
the CPU fetches the next gadget address from `[ESP]`. Controlling where `ESP`
lands next is the whole game, and the two return forms are how you do it.

**`RET`** (opcode `C3`) pops one slot and advances:

```
EIP = [ESP]        ; next gadget address
ESP = ESP + 4      ; advance one slot (pointer size on x86)
```

**`RET N`** (opcode `C2 iw`, e.g. `RET 8` = `C2 08 00`) does the same, then
adds a fixed constant to `ESP`:

```
EIP = [ESP]        ; next gadget address
ESP = ESP + 4 + N  ; advance one slot, then skip N MORE bytes
```

Two properties matter when you pick one from your corpus:

- **`N` is a constant baked into the instruction.** You match a gadget to the
  skip you need; you do not parameterize it at exploit time.
- **The skipped bytes are read as data, never executed.** The CPU does not
  decode them, it only moves `ESP` past them. That is what makes `RET N` safe
  for stepping over addresses, padding, or badchar-laden literals sitting in
  the chain.

`RET N` is the callee-cleanup convention (`stdcall`, most of the Win32 API),
so the compiler emits these everywhere and they are plentiful as gadgets.

Use `RET N` to:

1. **Step over junk or non-address data** embedded between gadget addresses,
   so those words are never interpreted as gadgets.
2. **Re-align `ESP`** by an exact delta when a preceding gadget or API call
   left the chain off by some slots, without a register-clobbering pile of
   throwaway `POP r32` gadgets.
3. **Account for `stdcall` API returns inside the chain.** A `stdcall`
   function ends in its own `RET N` that cleans up its arguments, so you know
   exactly where `ESP` lands when control returns to your chain.

### Worked example: `VirtualProtect` cleanup is load-bearing

`VirtualProtect` is `stdcall` with four 4-byte arguments, so its epilogue is
`RET 10h` (skip 4 x 4 = 16 bytes). Lay the call frame out as data words:

```
[ &VirtualProtect ]  <- chain RETs here; this becomes the new EIP
[ return address  ]  <- where VirtualProtect returns (back into your chain)
[ lpAddress       ]  <- arg1  (page to make executable)
[ dwSize          ]  <- arg2
[ flNewProtect    ]  <- arg3  (0x40 = PAGE_EXECUTE_READWRITE)
[ &lpflOldProtect ]  <- arg4  (writable scratch pointer)
[ ... shellcode / next gadget ... ]
```

When `VirtualProtect` finishes, its own `RET 10h` pops the return address into
`EIP` **and** adds `0x10` to `ESP`, skipping all four argument words in one
step. `ESP` therefore lands on the word immediately after `&lpflOldProtect`,
which is exactly where execution should continue. You do **not** add any
cleanup gadget for those four args, because the callee already did it. If you
mistakenly treated `VirtualProtect` as `cdecl` (caller cleanup) and inserted
your own `ADD ESP, 10h` gadget afterward, `ESP` would overshoot by `0x10` and
the chain would resume in the wrong place.

The flat frame builders emit this layout for you with every value badchar-checked:

```js
dx @$osed().rop.frame_vp(vpAddr, retAddr, lpAddr, dwSize, flProtect, writable, "00 0A 0D")
```

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
