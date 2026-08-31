export type HelpEntry = {
  name: string;
  description: string;
  usage: string;
  examples: string[];
};

export const NAMESPACE_HELP_ENTRIES: HelpEntry[] = [
  {
    name: "pattern.create",
    description: "Generates cyclic pattern text.",
    usage: "dx @$osed().pattern.create(length, type?)",
    examples: ["dx @$osed().pattern.create(300, \"msf\")"],
  },
  {
    name: "pattern.offset",
    description: "Finds an offset in the selected pattern family.",
    usage: "dx @$osed().pattern.offset(value, type?)",
    examples: ["dx @$osed().pattern.offset(0x39654138, \"msf\")"],
  },
  {
    name: "seh.visualize",
    description: "Walks the current thread SEH chain.",
    usage: "dx @$osed().seh.visualize()",
    examples: ["dx @$osed().seh.visualize()"],
  },
  {
    name: "fmt.build",
    description: "Builds a format-string write payload.",
    usage: "dx @$osed().fmt.build(addr, value, argIndex, width?, exclude?)",
    examples: ["dx @$osed().fmt.build(0x00402118, 0x625011AF, 6)"],
  },
  {
    name: "fmt.offset",
    description: "Finds the controlled format-string parameter index.",
    usage: "dx @$osed().fmt.offset(marker?, count?, firstArg?)",
    examples: ["dx @$osed().fmt.offset(0x41414141, 40)"],
  },
  {
    name: "str.read",
    description: "Reads a null-terminated ASCII or UTF-16LE string from memory.",
    usage: "dx @$osed().str.read(address, max?, encoding?)",
    examples: ["dx @$osed().str.read(0x0019F920)", "dx @$osed().str.read(0x0019F920, 128, \"utf16le\")"],
  },
  {
    name: "str.find",
    description: "Finds ASCII and/or UTF-16LE string bytes in loaded module sections.",
    usage: "dx @$osed().str.find(text, module?, encoding?, maxResults?)",
    examples: ["dx @$osed().str.find(\"VirtualProtect\")", "dx @$osed().str.find(\"cmd.exe\", \"target\", \"ascii\", 25)"],
  },
  {
    name: "str.refs",
    description: "Finds executable absolute-pointer references to a string address or literal.",
    usage: "dx @$osed().str.refs(target, module?, encoding?, maxResults?)",
    examples: ["dx @$osed().str.refs(\"VirtualProtect\")", "dx @$osed().str.refs(0x00403080, \"target\", \"ascii\", 25)"],
  },
  {
    name: "str.bytes",
    description: "Encodes text as payload bytes and reports bad-character hits.",
    usage: "dx @$osed().str.bytes(text, encoding?, terminator?, exclude?)",
    examples: ["dx @$osed().str.bytes(\"cmd.exe\")", "dx @$osed().str.bytes(\"W00T\", \"ascii\", true, \"00 0A 0D\")"],
  },
  {
    name: "rop_find",
    description: "Flat alias for legacy ROP helper/module triage.",
    usage: "dx @$osed().rop_find(module?, maxResults?, executableOnly?, mode?)",
    examples: ["dx @$osed().rop_find(\"essfunc\")"],
  },
  {
    name: "rop.find",
    description: "Runs the legacy ROP helper/module triage from the ROP namespace.",
    usage: "dx @$osed().rop.find(module?, maxResults?, executableOnly?, mode?)",
    examples: ["dx @$osed().rop.find(\"essfunc\")"],
  },
  {
    name: "rop.scan",
    description: "Loads pasted RP++ output into the semantic ROP corpus. Optionally filters gadgets whose addresses contain bad characters.",
    usage: "dx @$osed().rop.scan(text, badchars?)",
    examples: [
      "dx @$osed().rop.scan(\"0x1000: pop eax ; ret ;\")",
      'dx @$osed().rop.scan(rpOutput, "00 0A 0D")',
    ],
  },
  {
    name: "rop.scan_live",
    description: "Discovers live gadgets across one or more modules and replaces or appends to the semantic corpus.",
    usage: "dx @$osed().rop.scan_live(moduleOrModules?, badchars?, append?, maxPerPattern?)",
    examples: [
      'dx @$osed().rop.scan_live("compression", "00 0A 0D")',
      'dx @$osed().rop.scan_live("crypto", "00 0A 0D", true)',
      'dx @$osed().rop.scan_live(["compression", "crypto", "network"])',
      'dx @$osed().rop.scan_live({module:"crypto", append:true})',
    ],
  },
  {
    name: "rop.query",
    description: "Filters the loaded semantic ROP corpus.",
    usage: "dx @$osed().rop.query(field, value, executableOnly?)",
    examples: ['dx @$osed().rop.query("capability", "LOAD_REGISTER")', 'dx @$osed().rop.query("writes", "eax")'],
  },
  {
    name: "rop.capabilities",
    description: "Summarizes capabilities in the loaded semantic ROP corpus.",
    usage: "dx @$osed().rop.capabilities()",
    examples: ["dx @$osed().rop.capabilities()"],
  },
  {
    name: "rop.plan",
    description: "Plans feasible exploit strategies from semantic capabilities without selecting gadget addresses. Strategies: VirtualProtect, VirtualAlloc, WriteProcessMemory, VirtualProtectEx, VirtualAllocEx, WinExec, Stack Pivot.",
    usage: "dx @$osed().rop.plan(strategy, apiResolution?)",
    examples: ['dx @$osed().rop.plan("VirtualAlloc")', 'dx @$osed().rop.plan("VirtualProtect", "iat")', 'dx @$osed().rop.plan("WinExec")'],
  },
  {
    name: "rop.emit",
    description: "Selects and ranks concrete gadgets for a plan strategy. Produces a gadget assignment, not an executable chain.",
    usage: "dx @$osed().rop.emit(planId, strategyId?)",
    examples: ["dx @$osed().rop.emit(1)", "dx @$osed().rop.emit(1, 3)"],
  },
  {
    name: "rop.synthesize",
    description: "Synthesizes a concrete stack layout from a plan and the current exploit state. Uses cached state from triage(); accepts optional overrides.",
    usage: "dx @$osed().rop.synthesize(planId, overrides?)",
    examples: [
      "dx @$osed().rop.synthesize(1)",
      'dx @$osed().rop.synthesize(1, {controlledBytesAfterEsp: 128})',
      'dx @$osed().rop.synthesize(1, {badchars: "00 0A 0D"})',
    ],
  },
  {
    name: "rop.construct",
    description: "Builds a badchar-safe ROP recipe that loads a value into a register using pop/arithmetic gadgets. Models each gadget's full side effects: emits filler slots for extra pops and `add esp` skips so the chain stays aligned, reports every register the recipe clobbers (including non-pop writes like `mov eax, ...`), and excludes gadgets whose ESP shift cannot be padded (push, sub esp). Pass a preserve list to exclude gadgets that would overwrite registers you need to keep live (e.g. eax already staged for a stdcall frame).",
    usage: "dx @$osed().rop.construct(register, value, badchars?, preserve?)",
    examples: [
      'dx @$osed().rop.construct("ebx", 0x201, "00 0A 0D")',
      'dx @$osed().rop.construct("ebx", 0x201, "00 0A 0D", "eax")',
      'dx @$osed().rop.construct("edx", 0x1000, "00 0A 0D", "eax ecx")',
    ],
  },
  {
    name: "rop.setup",
    description: "Packs a whole set of target registers into a clobber-safe load sequence — the tool for staging a PUSHAD or stdcall frame. Exploits multi-pop gadgets to set several registers per gadget and orders gadgets so none overwrites an already-finalized register; reports honest conflicts when no ordering works. Values must be badchar-free (build tainted values with rop.construct first). Unlike rop.construct, it reasons about all target registers at once.",
    usage: 'dx @$osed().rop.setup("reg=value reg=value ...", badchars?)',
    examples: [
      'dx @$osed().rop.setup("edi=0x10001000 ebx=0x40", "00 0A 0D")',
      'dx @$osed().rop.setup("edi=0x10030000 esi=0x10040000 ebp=0x10050000 ebx=0x201 edx=0x40", "00 0A 0D")',
    ],
  },
  {
    name: "rop.frame_write",
    description: "Builds a stdcall call frame WITHOUT pushad: assembles it word-by-word in a writable buffer via a canonical `mov [eax], ecx ; ret` store (eax=pointer, ecx=value), then `xchg eax, esp` pivots ESP onto the frame so the trailing ret dispatches into the API. Null/badchar-heavy words are synthesised in ecx (preserving the eax pointer) instead of placed in the payload. Words are ordered: word0 = API address (ret enters it), word1 = post-call target (must be executable), then the stdcall args. BUF must be a writable, stable, badchar-free address.",
    usage: 'dx @$osed().rop.frame_write(buf, "word0 word1 arg1 arg2 ...", badchars?)',
    examples: [
      'dx @$osed().rop.frame_write("BUF", "VIRTUALALLOC POST_CALL 0x0 0x1000 0x3000 0x40", "00 0A 0D")',
      'dx @$osed().rop.frame_write("0x00420000", "0x10030000 0x10017260 0x0 0x1000 0x3000 0x40", "00 0A 0D")',
    ],
  },
  {
    name: "rop.export",
    description: "Exports emitted gadgets (and optionally the synthesized stack layout) as a Python exploit stub. If a file path is given, writes to disk; otherwise prints to console.",
    usage: "dx @$osed().rop.export(planId, path?)",
    examples: [
      "dx @$osed().rop.export(1)",
      'dx @$osed().rop.export(1, "C:\\\\exploit\\\\rop.py")',
    ],
  },
  {
    name: "rop.pivots",
    description: "Finds, classifies, and ranks stack pivot gadgets from the semantic corpus. Optionally filters by source register or minimum ESP adjustment.",
    usage: "dx @$osed().rop.pivots(register?, minDelta?)",
    examples: [
      "dx @$osed().rop.pivots()",
      'dx @$osed().rop.pivots("eax")',
      "dx @$osed().rop.pivots(undefined, 0x100)",
    ],
  },
  {
    name: "rop.chain",
    description: "Builds a register-setup chain from the loaded ROP corpus.",
    usage: "dx @$osed().rop.chain(register, value, register2?, value2?, ...)",
    examples: ['dx @$osed().rop.chain("eax", 0xDEADBEEF, "ebx", 0x1000)'],
  },
  {
    name: "rop.chain_vp",
    description: "Builds a VirtualProtect PUSHAD chain from the loaded ROP corpus.",
    usage: "dx @$osed().rop.chain_vp(virtualProtect?, retGadget?, returnAddress?, lpAddress?, dwSize?, writable?, flNewProtect?, mode?)",
    examples: ["dx @$osed().rop.chain_vp(0x7C801AD0, 0x62501010, 0x625011AF)"],
  },
  {
    name: "rop.chain_wpm",
    description: "Builds a constrained WriteProcessMemory PUSHAD chain from the loaded ROP corpus.",
    usage: "dx @$osed().rop.chain_wpm(writeProcessMemory?, returnAddress?, lpBuffer?, nSize?, writable?)",
    examples: ["dx @$osed().rop.chain_wpm(0x7C802213, 0x625011AF, 0x0012F800, 0x200)"],
  },
  {
    name: "rop.chain_va",
    description: "Builds a constrained VirtualAlloc PUSHAD chain from the loaded ROP corpus.",
    usage: "dx @$osed().rop.chain_va(virtualAlloc?, returnAddress?, lpAddress?, flAllocationType?, flProtect?)",
    examples: ["dx @$osed().rop.chain_va(0x7C809AE1)"],
  },
  {
    name: "rop.frame_vp",
    description: "Builds a flat VirtualProtect stdcall frame without requiring ROP gadgets.",
    usage: "dx @$osed().rop.frame_vp(virtualProtect?, returnAddress?, lpAddress?, dwSize?, flNewProtect?, writable?, badchars?)",
    examples: ['dx @$osed().rop.frame_vp(0x7C801AD0, 0x625011AF, 0x0012F800, 0x201, 0x40, 0x62506000, "00 0A 0D")'],
  },
  {
    name: "rop.frame_wpm",
    description: "Builds a flat WriteProcessMemory stdcall frame without requiring ROP gadgets.",
    usage: "dx @$osed().rop.frame_wpm(writeProcessMemory?, returnAddress?, hProcess?, lpBaseAddress?, lpBuffer?, nSize?, writable?, badchars?)",
    examples: ['dx @$osed().rop.frame_wpm(0x7C802213, 0x625011AF, 0xFFFFFFFF, 0x62502000, 0x0012F800, 0x200, 0x62506000, "00")'],
  },
  {
    name: "rop.frame_va",
    description: "Builds a flat VirtualAlloc stdcall frame without requiring ROP gadgets.",
    usage: "dx @$osed().rop.frame_va(virtualAlloc?, returnAddress?, lpAddress?, dwSize?, flAllocationType?, flProtect?, badchars?)",
    examples: ['dx @$osed().rop.frame_va(0x7C809AE1, 0x625011AF, 0, 0x201, 0x1000, 0x40, "00 0A 0D")'],
  },
  {
    name: "code_caves",
    description: "Finds contiguous null/int3/nop padding regions in PE sections suitable for shellcode placement. Detection heuristics inspired by nop-tech/codecaver (https://github.com/nop-tech/codecaver).",
    usage: "dx @$osed().code_caves(module?, minSize?, maxResults?)",
    examples: [
      "dx @$osed().code_caves()",
      'dx @$osed().code_caves("essfunc")',
      'dx @$osed().code_caves("essfunc", 100)',
    ],
  },
  {
    name: "sc.iat",
    description: "Enumerates imported addresses for a module, optionally filtered by DLL or symbol substring.",
    usage: "dx @$osed().sc.iat(module?, filter?)",
    examples: ["dx @$osed().sc.iat()", "dx @$osed().sc.iat(\"app.exe\", \"Virtual\")"],
  },
  {
    name: "sc.iat_find",
    description: "Searches all loaded modules for matching IAT entries.",
    usage: "dx @$osed().sc.iat_find(symbol)",
    examples: ["dx @$osed().sc.iat_find(\"VirtualAlloc\")"],
  },
  {
    name: "sc.iat_ptr",
    description: "Resolves one imported symbol to its IAT slot and current target pointer.",
    usage: "dx @$osed().sc.iat_ptr(module, symbol)",
    examples: ["dx @$osed().sc.iat_ptr(\"app.exe\", \"VirtualProtect\")"],
  },
  {
    name: "sc.exportdir",
    description: "Shows PE export directory addresses and table metadata.",
    usage: "dx @$osed().sc.exportdir(module)",
    examples: ["dx @$osed().sc.exportdir(\"kernel32\")"],
  },
  {
    name: "sc.export",
    description: "Resolves an export by name and reports ordinal, RVA, VA, and forwarder data.",
    usage: "dx @$osed().sc.export(module, symbol)",
    examples: ["dx @$osed().sc.export(\"kernel32\", \"GetProcAddress\")"],
  },
  {
    name: "sc.exportwalk",
    description: "Walks PE export resolution checkpoints.",
    usage: "dx @$osed().sc.exportwalk(module, symbol?, verbose?)",
    examples: ["dx @$osed().sc.exportwalk(\"kernel32\", \"GetProcAddress\")"],
  },
  {
    name: "sc.exportat",
    description: "Resolves an export by ordinal index.",
    usage: "dx @$osed().sc.exportat(module, ordinalIndex)",
    examples: ["dx @$osed().sc.exportat(\"kernel32\", 842)"],
  },
  {
    name: "sc.hashresolve",
    description: "Resolves an API hash against module exports.",
    usage: "dx @$osed().sc.hashresolve(module, hashValue, algorithm?)",
    examples: ["dx @$osed().sc.hashresolve(\"kernel32\", 0x7c0dfcaa, \"ROR13\")"],
  },
  {
    name: "sc.exports",
    description: "Enumerates exported symbols, optionally filtered by substring.",
    usage: "dx @$osed().sc.exports(module, filter?)",
    examples: ["dx @$osed().sc.exports(\"kernel32\", \"Virtual\")"],
  },
  {
    name: "sc.resolve",
    description: "Resolves one export to an address.",
    usage: "dx @$osed().sc.resolve(module, symbol)",
    examples: ["dx @$osed().sc.resolve(\"kernel32\", \"WinExec\")"],
  },
  {
    name: "sc.hashes",
    description: "Hashes named exports with the selected shellforge-compatible algorithm.",
    usage: "dx @$osed().sc.hashes(module, algorithm?)",
    examples: ["dx @$osed().sc.hashes(\"kernel32\", \"crc32\")"],
  },
  {
    name: "sc.hash",
    description: "Hashes one API name.",
    usage: "dx @$osed().sc.hash(name, algorithm?)",
    examples: ["dx @$osed().sc.hash(\"WinExec\", \"ROR13\")"],
  },
  {
    name: "sc.algorithms",
    description: "Lists supported API hash algorithms.",
    usage: "dx @$osed().sc.algorithms()",
    examples: ["dx @$osed().sc.algorithms()"],
  },
  {
    name: "sc.pe",
    description: "Prints PE header fields for a module.",
    usage: "dx @$osed().sc.pe(module)",
    examples: ["dx @$osed().sc.pe(\"kernel32\")"],
  },
  {
    name: "sc.base",
    description: "Resolves a module base address.",
    usage: "dx @$osed().sc.base(module)",
    examples: ["dx @$osed().sc.base(\"kernel32\")"],
  },
  {
    name: "sc.modules",
    description: "Lists loaded modules.",
    usage: "dx @$osed().sc.modules()",
    examples: ["dx @$osed().sc.modules()"],
  },
  {
    name: "sc.peb",
    description: "Dumps current PEB-oriented module evidence.",
    usage: "dx @$osed().sc.peb()",
    examples: ["dx @$osed().sc.peb()"],
  },
  {
    name: "sc.module_pages",
    description: "Reports module size and estimated page count.",
    usage: "dx @$osed().sc.module_pages(module)",
    examples: ["dx @$osed().sc.module_pages(\"kernel32\")"],
  },
  {
    name: "sc.page_summary",
    description: "Buckets module pages by protection value.",
    usage: "dx @$osed().sc.page_summary(module)",
    examples: ["dx @$osed().sc.page_summary(\"kernel32\")"],
  },
  {
    name: "stackmap",
    description: "Maps the call stack at crash time, classifying each slot as pattern bytes (PATTERN), verified return address (RET), saved frame pointer (SAVED_EBP), stale module pointer (STALE_PTR), null (NULL), or data (DATA). Reports controlled slot count, ROP room, and chain entry point.",
    usage: "dx @$osed().stackmap(depth?, patternLength?)",
    examples: [
      "dx @$osed().stackmap()",
      "dx @$osed().stackmap(128)",
      "dx @$osed().stackmap(64, 20000)",
    ],
  },
  {
    name: "exploit.state",
    description: "Views or updates the cached exploit state used by rop.synthesize(). Populated automatically by triage(); individual fields can be set or overridden manually.",
    usage: "dx @$osed().exploit.state(overrides?)",
    examples: [
      "dx @$osed().exploit.state()",
      'dx @$osed().exploit.state({mechanism: "saved-ret", controlledBytesAfterEsp: 512})',
      'dx @$osed().exploit.state({badchars: "00 0A 0D", apiResolution: "iat"})',
    ],
  },
  {
    name: "exploit.clear",
    description: "Clears the cached exploit state.",
    usage: "dx @$osed().exploit.clear()",
    examples: ["dx @$osed().exploit.clear()"],
  },
];

export function findHelpEntry(name: string): HelpEntry | undefined {
  const normalized = name.trim().toLowerCase();
  return NAMESPACE_HELP_ENTRIES.find((entry) => entry.name.toLowerCase() === normalized);
}

export function helpRows(entry: HelpEntry): Array<Record<string, string>> {
  return [
    {
      Helper: entry.name,
      Usage: entry.usage,
      Description: entry.description,
    },
    ...entry.examples.map((example) => ({
      Helper: "example",
      Usage: example,
      Description: "",
    })),
  ];
}
