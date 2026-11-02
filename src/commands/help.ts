import { Command, CommandRegistry, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { findHelpEntry, helpRows, NAMESPACE_HELP_ENTRIES, HelpEntry } from "../core/help_catalog";
import { HelpDocument, renderAll, renderCandidates, renderCompactDetail, renderFullDetail, renderNamespace, renderOverview, renderSearch } from "../core/help_render";

const SEARCH_LIMIT = 15;

const categoryForName = (name: string): string => {
  if (name.startsWith("rop") || name === "retn" || name === "add_esp") return "rop";
  if (name === "seh" || name === "seh_ppr" || name.startsWith("seh.")) return "seh";
  if (name.startsWith("sc.")) return "pe-api";
  if (name.startsWith("str.")) return "strings";
  if (name.startsWith("fmt.")) return "format";
  if (name.startsWith("pattern") || ["badchars", "badchar_array", "badchar_find"].includes(name)) return "payload";
  if (["triage", "landing", "stackmap", "findmsp"].includes(name)) return "crash";
  if (["modules", "memory", "code_caves", "find_mem_bytes", "find_ptr", "find_stack_bytes", "find_bytes"].includes(name)) return "target";
  if (["egghunter", "encode", "nop"].includes(name)) return "shellcode";
  return "tools";
};

const toDocument = (entry: HelpEntry): HelpDocument => entry;

function registryDocument(command: Command): HelpDocument {
  return { name: command.name, description: command.description, usage: command.usage, examples: command.examples, category: categoryForName(command.name) };
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
    .some((value) => value.toLowerCase().includes(needle)));
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
        const groups = groupedDocuments(registry);
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
        const limited = matches.slice(0, SEARCH_LIMIT);
        print(renderSearch(query, limited, matches.length));
        return { command: "help", args: options, success: true, findings: limited, warnings: matches.length > limited.length ? [`Showing ${limited.length} of ${matches.length} matches.`] : [], errors: [] };
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
