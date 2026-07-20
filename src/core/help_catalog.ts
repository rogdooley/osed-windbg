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
    name: "rop.scan",
    description: "Loads pasted RP++ output into the semantic ROP corpus.",
    usage: "dx @$osed().rop.scan(text, options?)",
    examples: ["dx @$osed().rop.scan(\"0x1000: pop eax ; ret ;\")"],
  },
  {
    name: "rop.query",
    description: "Filters the loaded semantic ROP corpus.",
    usage: "dx @$osed().rop.query(query)",
    examples: ["dx @$osed().rop.query({ transforms: [{ register: \"esi\", base: \"esi\", offset: 4 }] })"],
  },
  {
    name: "rop.capabilities",
    description: "Summarizes capabilities in the loaded semantic ROP corpus.",
    usage: "dx @$osed().rop.capabilities()",
    examples: ["dx @$osed().rop.capabilities()"],
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
