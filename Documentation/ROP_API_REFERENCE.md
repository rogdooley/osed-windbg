# ROP API & Register Reference

A one-stop reference for the DEP-bypass / payload APIs, their C prototypes, the
constant values you plug in, and the PUSHAD register mappings — so you do not
have to leave the debugger to dig through notes.

The PUSHAD tables here mirror the tool's own templates in
[`src/rop/chain.ts`](../src/rop/chain.ts) (`planVirtualProtect`,
`planVirtualAlloc`, `planWriteProcessMemory`), so what you read here is what the
tool emits. See also [ROP_WORKFLOW.md](ROP_WORKFLOW.md) and
[GADGET_DISCOVERY.md](GADGET_DISCOVERY.md).

## x86 (32-bit) register set

| Register | Role |
|---|---|
| `EAX` | accumulator / return value |
| `EBX` | general |
| `ECX` | counter |
| `EDX` | general / I/O |
| `ESI` | source index |
| `EDI` | destination index |
| `EBP` | frame (base) pointer |
| `ESP` | stack pointer — the ROP "instruction pointer" |

## stdcall in one paragraph

Arguments are pushed **right to left**, then the call pushes the return address.
The **callee** cleans its own arguments (`ret N`). So a live call frame on the
stack is:

```
[ &Function ]   <- CALL/RET transfers here; becomes EIP
[ retaddr   ]   <- where the API returns
[ arg1      ]
[ arg2      ]
...           <- the API's own `ret N` pops these on the way out
```

(For why the callee's `ret N` is load-bearing, see the RET vs RET N section in
[ROP_WORKFLOW.md](ROP_WORKFLOW.md).)

## Constants cheat sheet

| Symbol | Value | Used for |
|---|---|---|
| `PAGE_EXECUTE_READWRITE` | `0x40` | flNewProtect / flProtect (make executable) |
| `PAGE_EXECUTE_READ` | `0x20` | flProtect |
| `PAGE_READWRITE` | `0x04` | non-exec scratch |
| `MEM_COMMIT` | `0x1000` | VirtualAlloc flAllocationType |
| `MEM_RESERVE` | `0x2000` | VirtualAlloc flAllocationType |
| `MEM_COMMIT \| MEM_RESERVE` | `0x3000` | VirtualAlloc flAllocationType |
| `GetCurrentProcess()` pseudo-handle | `0xFFFFFFFF` | hProcess (current process) |
| `SW_HIDE` | `0x0` | WinExec uCmdShow |
| `SW_SHOWNORMAL` | `0x1` | WinExec uCmdShow |
| Typical `dwSize` | `0x201` | rounded up to a page by the API anyway |
| ROP NOP / junk filler | `0x90909090` | unused register slots |

## C prototypes (with the values you actually use)

```c
// Flip an existing page (usually the stack) to executable, then return into it.
BOOL VirtualProtect(
    LPVOID lpAddress,        // page to change  (shellcode start)
    SIZE_T dwSize,           // 0x201
    DWORD  flNewProtect,     // 0x40  PAGE_EXECUTE_READWRITE
    PDWORD lpflOldProtect    // out: any writable dword
);

// Allocate a fresh RWX region (lpAddress = NULL lets the OS choose).
LPVOID VirtualAlloc(
    LPVOID lpAddress,        // NULL or specific
    SIZE_T dwSize,           // 0x201
    DWORD  flAllocationType, // 0x1000  MEM_COMMIT
    DWORD  flProtect         // 0x40    PAGE_EXECUTE_READWRITE
);

// Copy shellcode into an already-executable destination.
BOOL WriteProcessMemory(
    HANDLE  hProcess,               // 0xFFFFFFFF  GetCurrentProcess()
    LPVOID  lpBaseAddress,          // dest (executable)
    LPCVOID lpBuffer,               // src (shellcode)
    SIZE_T  nSize,                  // shellcode byte count
    SIZE_T* lpNumberOfBytesWritten  // out: any writable dword
);

// Ex variants: identical, plus a leading hProcess handle.
BOOL   VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
                        DWORD flNewProtect, PDWORD lpflOldProtect);
LPVOID VirtualAllocEx (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
                        DWORD flAllocationType, DWORD flProtect);

// Command execution payload (not a DEP bypass).
UINT WinExec(
    LPCSTR lpCmdLine,        // pointer to "calc" / "cmd /c ..."
    UINT   uCmdShow          // 0x1  SW_SHOWNORMAL
);
```

## PUSHAD: the CPU fact

`pushad` pushes the registers in this order (each push decrements ESP):

```
EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
```

Because the stack grows down, the resulting memory layout from **low address
(ESP) to high** is the reverse:

```
ESP -> [EDI] [ESI] [EBP] [ESP] [EBX] [EDX] [ECX] [EAX]
```

That fixed ordering is why `pushad ; ret` can *become* a stdcall frame: you load
each register so that, after the push, the stack already reads as
`[&API][retaddr][arg1]...`.

## PUSHAD dispatch: two modes

**Direct mode** — the `ret` after `pushad` pops **EDI** into EIP, so `EDI` is the
API. The remaining words become the frame:

```
EDI = &API           ESI = retaddr        EBP = param1
ESP = param2 (saved) EBX = param3         EDX = param4
ECX = param5         EAX = unused
```

**RET-slide mode** — `EDI` is a plain `ret` gadget, which slides one more hop so
**ESI** is the API. This shifts every role down by one, and is the common
VirtualProtect layout because the saved `ESP` conveniently becomes `lpAddress`:

```
EDI = &ret (slide)   ESI = &API           EBP = retaddr
ESP = param1 (saved) EBX = param2         EDX = param3
ECX = param4         EAX = param5
```

> `ESP` is the **saved** stack pointer — you cannot `pop` it to an arbitrary
> value, so the argument that lands on `ESP` (dwSize in direct VirtualProtect,
> lpAddress in RET-slide) is "whatever ESP happens to be." Verify it is
> acceptable, or pick the mode that puts a settable register on the argument you
> care about.

## Per-API PUSHAD register maps

These are exactly what the tool's templates emit. `WRITABLE` = any writable
address (dummy out-param), `0x90909090` = junk filler.

### VirtualProtect — RET-slide (default)

| Reg | Value | Role |
|---|---|---|
| `EDI` | &`ret` gadget | RET-slide (first ret pops ESI into EIP) |
| `ESI` | &VirtualProtect | the API |
| `EBP` | retaddr | return after VP (e.g. `jmp esp`) |
| `ESP` | *(saved)* | lpAddress — must point into shellcode/NOP sled |
| `EBX` | `0x201` | dwSize |
| `EDX` | `0x40` | flNewProtect = PAGE_EXECUTE_READWRITE |
| `ECX` | `WRITABLE` | lpflOldProtect |
| `EAX` | `0x90909090` | unused |

### VirtualProtect — direct

| Reg | Value | Role |
|---|---|---|
| `EDI` | &VirtualProtect | RET dispatches here |
| `ESI` | retaddr | return after VP (e.g. `jmp esp`) |
| `EBP` | lpAddress | shellcode start |
| `ESP` | *(saved)* | dwSize — verify the saved SP is an acceptable size |
| `EBX` | `0x40` | flNewProtect = PAGE_EXECUTE_READWRITE |
| `EDX` | `WRITABLE` | lpflOldProtect |
| `ECX` | `WRITABLE` | unused |
| `EAX` | `0x90909090` | unused |

### VirtualAlloc — direct

| Reg | Value | Role |
|---|---|---|
| `EDI` | &VirtualAlloc | RET dispatches here |
| `ESI` | retaddr | return after VA (e.g. `push esp ; ret`) |
| `EBP` | lpAddress | NULL = OS chooses, or specific |
| `ESP` | *(saved)* | dwSize |
| `EBX` | `0x1000` | flAllocationType = MEM_COMMIT |
| `EDX` | `0x40` | flProtect = PAGE_EXECUTE_READWRITE |
| `ECX` | `0x90909090` | unused |
| `EAX` | `0x90909090` | unused |

### WriteProcessMemory — direct

| Reg | Value | Role |
|---|---|---|
| `EDI` | &WriteProcessMemory | RET dispatches here |
| `ESI` | retaddr | return after WPM |
| `EBP` | `0xFFFFFFFF` | hProcess = GetCurrentProcess() |
| `ESP` | *(saved)* | lpBaseAddress — only a bypass if saved SP is executable |
| `EBX` | lpBuffer | source (shellcode on stack) |
| `EDX` | nSize | shellcode byte count |
| `ECX` | `WRITABLE` | lpNumberOfBytesWritten |
| `EAX` | `0x90909090` | unused |

## When PUSHAD is not available

A `pushad ; ret` gadget is convenient enough that it is often absent. The
fallbacks build the same stdcall frame without it:

- **Synthetic stdcall frame** — lay `[&API][retaddr][args...]` directly on the
  stack as data words. No PUSHAD, no register juggling. See `rop.frame_vp` /
  `rop.plan("VirtualProtect")` and the `SYNTHETIC_STDCALL_FRAME` shape.
- **Per-register construction** — when an argument value contains badchars, build
  it in a register with `rop.construct(reg, value, badchars, preserve?)`, which
  also reports what each step clobbers so you can order the setup safely.

For picking individual gadgets to do any of the above, see
[GADGET_DISCOVERY.md](GADGET_DISCOVERY.md).
