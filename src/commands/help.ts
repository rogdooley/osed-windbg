import { Command, CommandRegistry, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { findHelpEntry, helpRows, NAMESPACE_HELP_ENTRIES, HelpEntry } from "../core/help_catalog";
import { HelpDocument, renderAll, renderCandidates, renderCompactDetail, renderFullDetail, renderNamespace, renderOverview, renderSearch } from "../core/help_render";

const categoryForName = (name: string): string => {
  if (name.startsWith("rop") || name === "retn" || name === "add_esp" || name === "pivots") return "rop";
  if (name === "seh" || name === "seh_ppr" || name.startsWith("seh.")) return "seh";
  if (name.startsWith("sc.")) return "pe-api";
  if (name.startsWith("str.")) return "strings";
  if (name.startsWith("fmt.") || name === "fmt_build" || name === "fmt_offset") return "format";
  if (name.startsWith("pattern") || ["badchars", "badchar_array", "badchar_find"].includes(name)) return "payload";
  if (["triage", "landing", "stackmap", "findmsp"].includes(name)) return "crash";
  if (["modules", "memory", "code_caves", "find_mem_bytes", "find_ptr", "find_stack_bytes", "find_bytes"].includes(name)) return "target";
  if (["egghunter", "encode", "nop"].includes(name)) return "shellcode";
  return "tools";
};

const LISTING_SUMMARIES: Record<string, string> = {
  triage: "Crash and mitigation summary",
  findmsp: "Find cyclic offsets in registers and memory",
  landing: "Analyze execution landing and protections",
  stackmap: "Identify controlled stack regions",
  modules: "Modules, bases, and mitigations",
  memory: "Inspect memory region and protections",
  code_caves: "Find candidate staging regions",
  pattern_create: "Generate a cyclic pattern",
  pattern_offset: "Resolve a cyclic offset",
  badchars: "Compare candidate bytes with memory",
  badchar_array: "Generate a bad-character test array",
  badchar_find: "Locate a sent bad-character array in memory",
  find_bytes: "Find byte sequence in PE sections",
  find_mem_bytes: "Find byte sequence in a memory range",
  find_stack_bytes: "Find byte sequence on the stack",
  find_ptr: "Search executable memory for instruction bytes",
  "rop.scan": "Load gadgets into the semantic corpus",
  "rop.scan_live": "Discover gadgets in loaded modules",
  "rop.query": "Search gadgets by capability or instruction",
  "rop.capabilities": "Summarize available ROP primitives",
  "rop.plan": "Compare API-call construction strategies",
  "rop.emit": "Select gadgets for a strategy",
  "rop.synthesize": "Build a concrete stack layout",
  "rop.construct": "Build register-load ROP recipes",
  "rop.setup": "Stage registers for a call frame",
  "rop.frame_write": "Construct stdcall frames in memory",
  "rop.slot_call": "Call APIs through stable IAT slots",
  "rop.generate": "Generate an API-call chain",
  "rop.verify": "Verify chain structure and side effects",
  "rop.prove": "Trace chain execution in WinDbg",
  "rop.pivots": "Find and rank stack pivot gadgets",
  "rop.corpus.export": "Save the semantic corpus to disk",
  "rop.corpus.import": "Load a corpus as inactive evidence",
  "rop.corpus.validate": "Validate corpus against live memory",
  "rop.corpus.report": "Print a human-readable gadget inventory",
  "rop.frame_va": "Build a VirtualAlloc stdcall frame",
  "rop.frame_vp": "Build a VirtualProtect stdcall frame",
  "rop.frame_wpm": "Build a WriteProcessMemory stdcall frame",
  "rop.chain": "Build a register-setup chain",
  "rop.chain_va": "Build a VirtualAlloc PUSHAD chain",
  "rop.chain_vp": "Build a VirtualProtect PUSHAD chain",
  "rop.chain_wpm": "Build a WriteProcessMemory PUSHAD chain",
  "rop.export": "Export gadgets and chain as Python",
  "rop.find": "Legacy ROP helper and module triage",
  rop_find: "Flat alias for legacy ROP helper triage",
  rop_suggest: "Suggest exploit-friendly gadget patterns",
  rop_template: "Print a commented ROP chain skeleton",
  pivots: "Scan for stack pivot candidates",
  retn: "Scan for retn N gadgets",
  add_esp: "Scan for add esp, N gadgets",
  seh: "Walk current thread SEH chain",
  seh_ppr: "Find POP-POP-RET candidates",
  "seh.visualize": "Inspect the exception-handler chain",
  encode: "Encode shellcode around forbidden bytes",
  egghunter: "Generate an egghunter stub",
  nop: "Generate a NOP sled",
  "sc.iat": "Inspect imported APIs and IAT entries",
  "sc.iat_find": "Search all modules for matching IAT entries",
  "sc.iat_ptr": "Resolve an import to its IAT slot",
  "sc.resolve": "Resolve API exports",
  "sc.export": "Resolve an export by name",
  "sc.exportat": "Resolve an export by ordinal",
  "sc.exportdir": "Show PE export directory metadata",
  "sc.exportwalk": "Walk PE export resolution checkpoints",
  "sc.exports": "Enumerate exported symbols",
  "sc.hash": "Hash one API name",
  "sc.hashes": "Hash named exports with a given algorithm",
  "sc.hashresolve": "Resolve an API hash against exports",
  "sc.algorithms": "List supported API hash algorithms",
  "sc.pe": "Print PE header fields",
  "sc.base": "Resolve a module base address",
  "sc.modules": "List loaded modules",
  "sc.peb": "Dump PEB-oriented module evidence",
  "sc.module_pages": "Report module size and page count",
  "sc.page_summary": "Bucket module pages by protection",
  "str.find": "Search process memory for strings",
  "str.read": "Read a string from memory",
  "str.refs": "Find executable pointers to a string",
  "str.bytes": "Encode text as payload bytes",
  "leak.classify": "Classify a pointer without dereferencing",
  "pattern.create": "Generate cyclic pattern text",
  "pattern.offset": "Find an offset in a pattern family",
  fmt_build: "Construct format-string payload components",
  fmt_offset: "Find the controlled parameter index",
  "fmt.build": "Construct format-string payload components",
  "fmt.offset": "Find the controlled parameter index",
  exploit: "Emit exploit-development command workflows",
  "exploit.state": "View or update cached exploit state",
  "exploit.clear": "Clear the cached exploit state",
  math: "Format an integer as hex, signed, unsigned, LE",
  leak_classify: "Classify a pointer without dereferencing",
  help: "List commands or show detailed help",
  reload: "Clear and re-register command registry",
  version: "Show loaded build identity",
};

function shortSummary(name: string, description: string, supplied?: string): string {
  return LISTING_SUMMARIES[name] ?? supplied ?? description.split(/(?<=[.!?])\s/)[0] ?? description;
}

const toDocument = (entry: HelpEntry): HelpDocument => ({ ...entry, summary: shortSummary(entry.name, entry.description, entry.summary) });

function registryDocument(command: Command): HelpDocument {
  return { name: command.name, description: command.description, summary: shortSummary(command.name, command.description), usage: command.usage, examples: command.examples, category: categoryForName(command.name) };
}

function groupedDocuments(registry: CommandRegistry): Map<string, HelpDocument[]> {
  const documents = new Map<string, HelpDocument>();
  for (const command of registry.getAll()) documents.set(command.name, registryDocument(command));
  for (const entry of NAMESPACE_HELP_ENTRIES) documents.set(entry.name, toDocument(entry));
  documents.delete("rop");
  const groups = new Map<string, HelpDocument[]>();
  for (const entry of [...documents.values()].sort((a, b) => a.name.localeCompare(b.name))) {
    const category = entry.category ?? categoryForName(entry.name);
    groups.set(category, [...(groups.get(category) ?? []), entry]);
  }
  return groups;
}

const OVERVIEW_WORKFLOW: Array<[string, string[]]> = [
  ["crash", ["triage", "findmsp", "stackmap", "landing"]],
  ["target", ["modules", "memory", "code_caves"]],
  ["payload", ["pattern_create", "pattern_offset", "badchars"]],
  ["rop", ["rop.scan_live", "rop.query", "rop.capabilities", "rop.plan", "rop.generate", "rop.verify", "rop.prove"]],
  ["pe-api", ["sc.iat", "sc.resolve"]],
  ["shellcode", ["encode", "egghunter"]],
  ["seh", ["seh", "seh_ppr"]],
  ["strings", ["str.find"]],
  ["format", ["fmt_build"]],
];

function overviewGroups(all: HelpDocument[]): Map<string, HelpDocument[]> {
  const index = new Map(all.map((entry) => [entry.name, entry]));
  const groups = new Map<string, HelpDocument[]>();
  for (const [category, names] of OVERVIEW_WORKFLOW) {
    const entries = names.map((name) => index.get(name)).filter((entry): entry is HelpDocument => !!entry);
    if (entries.length > 0) groups.set(category, entries);
  }
  return groups;
}

function documents(registry: CommandRegistry): HelpDocument[] {
  return [...groupedDocuments(registry).values()].flat().sort((a, b) => a.name.localeCompare(b.name));
}

function namespaceTask(name: string, entry: HelpDocument): string {
  if (name === "rop") {
    if (["rop.scan", "rop.scan_live", "rop.query", "rop.capabilities", "rop.pivots", "rop.find", "rop_find"].includes(entry.name)) return "discovery";
    if (["rop.plan", "rop.emit", "rop.synthesize"].includes(entry.name)) return "planning";
    if (["rop.verify", "rop.prove"].includes(entry.name)) return "validation";
    if (entry.name.startsWith("rop.corpus.")) return "persistence";
    if (entry.name === "rop.export") return "export";
    if (["retn", "add_esp"].includes(entry.name)) return "control flow";
    return "construction";
  }
  if (name === "sc") {
    if (entry.name.startsWith("sc.iat")) return "imports";
    if (["sc.exports", "sc.export", "sc.exportat", "sc.exportdir", "sc.exportwalk", "sc.resolve", "sc.hash", "sc.hashes", "sc.hashresolve", "sc.algorithms"].includes(entry.name)) return "api resolution";
    return "pe and modules";
  }
  return "commands";
}

function namespaceDocuments(name: string, all: HelpDocument[]): Map<string, HelpDocument[]> | undefined {
  const normalized = name.toLowerCase();
  const matches = all.filter((entry) => {
    if (normalized === "rop") return (entry.category ?? categoryForName(entry.name)) === "rop";
    if (normalized === "seh") return (entry.category ?? categoryForName(entry.name)) === "seh";
    if (["crash", "payload", "target", "shellcode", "pe-api", "strings", "format", "tools"].includes(normalized)) {
      return (entry.category ?? categoryForName(entry.name)) === normalized;
    }
    return entry.name.startsWith(`${normalized}.`);
  });
  if (matches.length === 0) return undefined;
  const groups = new Map<string, HelpDocument[]>();
  for (const entry of matches) {
    const task = namespaceTask(normalized, entry);
    groups.set(task, [...(groups.get(task) ?? []), entry]);
  }
  return groups;
}

function searchDocuments(query: string, all: HelpDocument[]): HelpDocument[] {
  const needle = query.toLowerCase();
  return all.filter((entry) => [entry.name, entry.summary, entry.description, ...(entry.keywords ?? [])]
    .filter((value): value is string => Boolean(value))
    .some((value) => value.toLowerCase().includes(needle)))
    .sort((a, b) => {
      const score = (entry: HelpDocument) => entry.name.toLowerCase().includes(needle) ? 0 : 1;
      return score(a) - score(b) || a.name.localeCompare(b.name);
    });
}

function groupByCategory(entries: HelpDocument[]): Map<string, HelpDocument[]> {
  const groups = new Map<string, HelpDocument[]>();
  for (const entry of entries) {
    const category = entry.category ?? categoryForName(entry.name);
    groups.set(category, [...(groups.get(category) ?? []), entry]);
  }
  return groups;
}

function print(lines: string[]): void {
  for (const line of lines) out.print(line);
}

export function createHelpCommand(registry: CommandRegistry): Command {
  return {
    name: "help",
    description: "List commands or show detailed command help.",
    usage: "dx @$osed().help(command?, mode?)",
    examples: ["dx @$osed().help()", "dx @$osed().help(\"all\")", "dx @$osed().help(\"sc.iat\", \"full\")"],
    schema: { command: { type: "string" }, mode: { type: "string" } },
    execute(options: Record<string, unknown>): CommandResult {
      const commandName = options.command as string | undefined;
      const mode = options.mode as string | undefined;
      if (!commandName) {
        const groups = overviewGroups(documents(registry));
        print(renderOverview(groups));
        return { command: "help", args: options, success: true, findings: [...groups.values()].flat(), warnings: [], errors: [], schema: { command: { type: "string", optional: true }, mode: { type: "string", optional: true } } };
      }
      if (commandName.toLowerCase() === "all") {
        const groups = groupedDocuments(registry);
        print(renderAll(groups));
        return { command: "help", args: options, success: true, findings: [...groups.values()].flat(), warnings: [], errors: [] };
      }
      if (mode && mode.toLowerCase() !== "full") return { command: "help", args: options, success: false, findings: [], warnings: [], errors: [`Unknown help mode '${mode}'. Use 'full'.`] };
      const all = documents(registry);
      if (commandName.startsWith("?")) {
        const query = commandName.slice(1).trim();
        if (!query) return { command: "help", args: options, success: false, findings: [], warnings: [], errors: ["Search query cannot be empty."] };
        const matches = searchDocuments(query, all);
        print(renderSearch(query, groupByCategory(matches), matches.length));
        return { command: "help", args: options, success: true, findings: matches, warnings: [], errors: [] };
      }
      const namespace = namespaceDocuments(commandName, all);
      if (namespace) {
        print(renderNamespace(commandName, namespace));
        return { command: "help", args: options, success: true, findings: [...namespace.values()].flat(), warnings: [], errors: [] };
      }
      const command = registry.get(commandName);
      const helper = findHelpEntry(commandName === "rop" ? "rop.find" : commandName);
      if (!command && !helper) {
        const suffix = commandName.toLowerCase();
        const matches = all.filter((entry) => entry.name.toLowerCase().endsWith(`.${suffix}`));
        if (matches.length === 1) {
          const resolved = matches[0];
          const resolvedHelper = findHelpEntry(resolved.name);
          const resolvedCommand = registry.get(resolved.name);
          print(mode?.toLowerCase() === "full" ? renderFullDetail(resolved) : renderCompactDetail(resolved));
          return resolvedHelper
            ? { command: "help", args: options, success: true, findings: helpRows(resolvedHelper), warnings: [], errors: [] }
            : { command: "help", args: options, success: true, findings: [{ name: resolvedCommand!.name, description: resolvedCommand!.description, usage: resolvedCommand!.usage, examples: resolvedCommand!.examples, schema: resolvedCommand!.schema }], warnings: [], errors: [], schema: resolvedCommand!.schema as Record<string, unknown> };
        }
        if (matches.length > 1) {
          print(renderCandidates(commandName, matches));
          return { command: "help", args: options, success: false, findings: matches, warnings: [], errors: [`'${commandName}' matches multiple commands.`] };
        }
        return { command: "help", args: options, success: false, findings: [], warnings: [], errors: [`Unknown command '${commandName}'.`] };
      }
      const document = helper ? toDocument(helper) : registryDocument(command!);
      print(mode?.toLowerCase() === "full" ? renderFullDetail(document) : renderCompactDetail(document));
      if (helper) return { command: "help", args: options, success: true, findings: helpRows(helper), warnings: [], errors: [] };
      return { command: "help", args: options, success: true, findings: [{ name: command!.name, description: command!.description, usage: command!.usage, examples: command!.examples, schema: command!.schema }], warnings: [], errors: [], schema: command!.schema as Record<string, unknown> };
    },
  };
}
