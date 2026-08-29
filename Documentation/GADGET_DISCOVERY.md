# Finding ROP Gadgets

A practical guide to locating specific gadgets (like `pop eax ; ret`) with the
semantic ROP corpus, and to telling a clean gadget from one that will desync or
clobber your chain.

For the end-to-end chain-building flow, see [ROP_WORKFLOW.md](ROP_WORKFLOW.md).
For the mechanics of `RET` vs `RET N`, see the reference section in that file.
For API prototypes, constant values, and the PUSHAD register maps, see
[ROP_API_REFERENCE.md](ROP_API_REFERENCE.md).

## The mental model

Gadget discovery in this tool is a two-step loop:

1. **Load a corpus.** Gadgets are discovered from a module (or pasted RP++
   output) into an in-memory *semantic corpus*. Every gadget is decoded and
   annotated with what it reads, writes, preserves, and does to ESP.
2. **Query the corpus.** `rop.query` filters that annotated set by those
   semantic properties, so you ask for *what a gadget does*, not just for a
   byte pattern.

This is why you can ask for "something that loads EAX and leaves every other
register alone" instead of grepping disassembly by hand.

## Step 1: Load a corpus

Discover live gadgets from a loaded module (badchars are filtered out of gadget
addresses):

```js
dx @$osed().rop.scan_live("MSA2Mfilter03", "00 0A 0D")
```

Multiple modules at once:

```js
dx @$osed().rop.scan_live(["MSA2Mfilter03", "MSA2Mcodec00"], "00 0A 0D")
```

Or paste RP++ / rp++ output directly:

```js
dx @$osed().rop.scan("0x10031659: pop ebx ; pop eax ; ret ;", "00 0A 0D")
```

Confirm what the corpus can do:

```js
dx @$osed().rop.capabilities()
```

## Step 2: Query for a gadget

`rop.query` takes either a single `(field, value)` pair or an object with
several constraints ANDed together.

### Single field

```js
dx @$osed().rop.query("writes", "eax")
```

Returns every gadget that writes EAX — `pop eax`, `mov eax, ...`, `add eax, ...`,
`xor eax, eax`, and so on. Useful to survey the inventory, too broad to pick from.

### Object form (multiple constraints)

```js
dx @$osed().rop.query({capability: "LOAD_REGISTER", writes: ["eax"]})
```

`LOAD_REGISTER` is the pop-into-register capability, so this narrows to
pop-style loads that land in EAX.

## Finding a *clean* `pop eax ; ret`

The important refinement after learning that `pop eax ; pop ebx ; ret` and
`pop eax ; mov ecx, edx ; ret` both "write eax." To demand a gadget that
touches nothing else, constrain what it must preserve:

```js
dx @$osed().rop.query({
  capability: "LOAD_REGISTER",
  writes: ["eax"],
  preservesThroughout: ["ebx","ecx","edx","esi","edi","ebp"],
  memoryWrites: false
})
```

- **`preservesThroughout`** keeps only gadgets that leave those registers as
  identity (unchanged from start to end). A `pop eax ; pop ebx ; ret` is
  rejected because it does not preserve EBX; a gadget with an incidental
  `mov ecx, ...` is rejected because it does not preserve ECX.
- **`memoryWrites: false`** drops gadgets with `mov [reg], ...` side effects.

The result set is effectively "clean `pop eax ; ret`."

> Preservation is proven, not assumed. A gadget whose net effect on a register
> cannot be established does **not** count as preserving it, so this filter errs
> toward excluding anything unproven — exactly what you want when hunting a
> side-effect-free gadget.

## Query field reference

| Field | Type | Meaning |
|---|---|---|
| `capability` | kind or list | What the gadget does (see kinds below); `ARITHMETIC` is an alias covering all the register-arithmetic kinds |
| `reads` / `writes` | register list | Registers the gadget reads / writes |
| `preserves` / `preservesThroughout` | register list | Registers left unchanged (net identity) |
| `stackDelta` | number or list | Net ESP change the gadget produces — pin a gadget's stack footprint |
| `terminator` | `RETURN` / `CALL` / `JUMP` | How the gadget ends |
| `memoryReads` / `memoryWrites` | boolean | Include (`true`) or exclude (`false`) gadgets with memory side effects |
| `executableOnly` | boolean | Restrict to executable sections (also the optional 3rd positional arg) |

Common `capability` kinds: `LOAD_REGISTER`, `ZERO_REGISTER`, `MOVE_REGISTER`,
`EXCHANGE_REGISTER`, `REGISTER_ADD`, `REGISTER_SUB`, `REGISTER_XOR`,
`REGISTER_NEGATE`, `REGISTER_NOT`, `STACK_PIVOT`, `MEMORY_READ`, `MEMORY_WRITE`,
and the dispatch kinds (`DISPATCH_RET`, `DISPATCH_JMP_REGISTER`, …).

## Recipe book

**A clean register load into EDX**
```js
dx @$osed().rop.query({capability: "LOAD_REGISTER", writes: ["edx"], preservesThroughout: ["eax","ebx","ecx","esi","edi","ebp"]})
```

**An `add eax, ebx` (or any arithmetic that combines two registers)**
```js
dx @$osed().rop.query({capability: "REGISTER_ADD", writes: ["eax"], reads: ["ebx"]})
```

**Zero a register (`xor eax, eax ; ret`)**
```js
dx @$osed().rop.query({capability: "ZERO_REGISTER", writes: ["eax"]})
```

**A stack pivot that lands from a register you control**
```js
dx @$osed().rop.query({capability: "STACK_PIVOT", reads: ["eax"]})
```
(or use the ranked, classified view: `rop.pivots("eax")`.)

**A gadget that writes memory (for building a decoder or writing an arg)**
```js
dx @$osed().rop.query({capability: "MEMORY_WRITE", writes: ["edi"]})
```

**Avoid `ret N` when you need a plain `ret`**
`terminator` distinguishes `RETURN` / `CALL` / `JUMP`, not plain-`ret` vs
`ret N`. To separate them, filter on `stackDelta`: read the delta of a known
plain-`ret` gadget from the query output, then reuse that number to pin others.
A `ret N` gadget reports a larger delta because it skips N extra bytes.

## Gadgets triage finds for you

Some classes are surfaced directly by `triage()` (and `rop.find`) without a
query, because they are the usual entry points:

- **JMP ESP / CALL ESP** — return into shellcode already at ESP
- **POP POP RET** — SEH overwrite handler gadgets
- **Stack pivots** — redirect ESP into a controlled region

```js
dx @$osed().triage()
```

Use `rop.query` for everything else — the specific register/arithmetic/memory
gadgets that make up the body of a chain.

## From gadget to chain: let the tools pick

If your goal is "load this value into this register," you usually do not need to
pick the gadget by hand. `rop.construct` finds one, **prefers the clean
gadget**, pads any side effects so the chain stays aligned, and reports what it
clobbers:

```js
dx @$osed().rop.construct("eax", 0x201, "00 0A 0D")
```

Protect a register that must stay live (e.g. one already staged for a stdcall
frame) with a preserve list:

```js
dx @$osed().rop.construct("ebx", 0x201, "00 0A 0D", "eax")
```

Use `rop.query` to *see the inventory*; use `rop.construct` to *pick and lay out
the recipe*.

## Always verify the gadget live

A query result is a claim about decoded instructions. Before trusting a gadget,
disassemble it in WinDbg and read past the mnemonic you asked for:

```
u 0x10031659
```

```
10031659 5b              pop     ebx
1003165a 58              pop     eax     <- extra pop: consumes a stack slot AND clobbers eax
1003165b c3              ret
```

The two things to catch by eye:

- **Extra stack consumers** — a second `pop`, an `add esp, N`, a `ret N`. Each
  needs a filler slot in your chain, or the next gadget address is misinterpreted.
- **Incidental writes** — a `mov`/`xor`/`lea` into a register you rely on.

`rop.construct` already models both of these (it pads fillers and reports
clobbers), which is why letting it lay out the recipe is safer than hand-picking
from raw query output. But when you do hand-pick, `u` is the check that saves the
chain.
