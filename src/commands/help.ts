import { Command, CommandRegistry, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { findHelpEntry, helpRows, NAMESPACE_HELP_ENTRIES, HelpEntry } from "../core/help_catalog";
import { HelpDocument, renderAll, renderCompactDetail, renderFullDetail, renderOverview } from "../core/help_render";

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
      const command = registry.get(commandName);
      const helper = findHelpEntry(commandName === "rop" ? "rop.find" : commandName);
      if (!command && !helper) return { command: "help", args: options, success: false, findings: [], warnings: [], errors: [`Unknown command '${commandName}'.`] };
      const document = helper ? toDocument(helper) : registryDocument(command!);
      print(mode?.toLowerCase() === "full" ? renderFullDetail(document) : renderCompactDetail(document));
      if (helper) return { command: "help", args: options, success: true, findings: helpRows(helper), warnings: [], errors: [] };
      return { command: "help", args: options, success: true, findings: [{ name: command!.name, description: command!.description, usage: command!.usage, examples: command!.examples, schema: command!.schema }], warnings: [], errors: [], schema: command!.schema as Record<string, unknown> };
    },
  };
}
