# Chain commands: which one, when, and why

This is the canonical guide to the ROP dispatch builders (`slot_call`,
`chain_*`, `frame_*`, `frame_write`). If you only read one section, read
[Decision table](#decision-table). If you're new to the *why*, start at
[Theory](#theory-the-mental-model).

- [Theory: the mental model](#theory-the-mental-model)
- [Slot vs target](#slot-vs-target-read-this-first)
- [Decision table](#decision-table)
- [The dispatch spectrum](#the-dispatch-spectrum)
- [Addresses: nulls vs volatility](#addresses-nulls-vs-volatility)
- [Filling in BUF and SHELLCODE](#filling-in-buf-and-shellcode)
- [Command reference](#command-reference)
- [Common mistakes](#common-mistakes)

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

- **`slot_call`** — `pop eax=<slot> ; mov eax,[eax] ; jmp eax`. Dereferences the
  slot at runtime, so the ASLR'd target is fetched on the box and never appears
  in the payload. Null/badchar words are synthesised in a register and stored.
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
fragile. The robust fix is to **derive it from a register at runtime** so it
tracks wherever the stack actually is:

```
mov reg, esp ; add reg, <calibrated offset>     ; reg = shellcode address, this run
```

The offset (distance from the captured `ESP` to the shellcode) is constant even
under ASLR, because the whole payload shifts together — you calibrate it once.
This is what **`rop.slot_call_rel`** (planned — see the command reference) is
meant to provide. It is a *separate* function from `slot_call` because it needs
an ESP-capture primitive and changes the preamble; whether your corpus has that
primitive is corpus-specific.

**Rule of thumb:** ASLR off / stable lab stack → construct the fixed address
with `slot_call`. Stack ASLR on → `slot_call_rel` (register-relative).

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

Find one live:

```
!address 0x10000000
```

Pick a `MEM_COMMIT` / `PAGE_READWRITE` region in filter03 and use an address well
inside it.

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

### `rop.slot_call_rel(buf, iatSlot, "…", badchars?)` — ASLR-proof + stack-relative *(planned)*

Like `slot_call`, but frame words may be **register-relative** (e.g. an
ESP-derived, once-calibrated offset) so you never hardcode a volatile stack
address. Intended for full-ASLR targets. It needs an ESP-capture primitive in
the corpus; the design is being finalized against what filter03 actually
exposes, and the command reports honestly when the primitive is absent. **Not
yet implemented** — use `slot_call` with a constructed fixed address until this
ships.

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

## See also

- [ROP_WORKFLOW.md](ROP_WORKFLOW.md) — end-to-end chain construction.
- [ROP_API_REFERENCE.md](ROP_API_REFERENCE.md) — stdcall, PUSHAD, per-API
  register maps, constants.
- [GADGET_DISCOVERY.md](GADGET_DISCOVERY.md) — finding and verifying gadgets.
