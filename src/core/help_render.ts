import { HelpEntry, normalizeHelpExamples } from "./help_catalog";

export const HELP_WIDTH = 80;
const NAME_WIDTH = 23;
const DESC_WIDTH = 36;
const EXAMPLE_PREFIX = "dx @$osed().";
const ROOT_CATEGORY_ORDER = ["crash", "payload", "target", "rop", "seh", "shellcode", "pe-api", "strings", "format", "tools"];
const ROP_TASK_ORDER = ["discovery", "planning", "construction", "control flow", "validation", "persistence", "export"];

export type HelpDocument = Pick<HelpEntry, "name" | "description" | "usage" | "examples" | "details" | "summary" | "category" | "arguments" | "prerequisites" | "limitations" | "seeAlso" | "keywords">;

function words(text: string): string[] {
  return text.trim().split(/\s+/).filter(Boolean);
}

/** Wrap prose only. Callers render debugger commands as indivisible lines. */
export function wrapText(text: string, width = HELP_WIDTH, indent = ""): string[] {
  const available = Math.max(1, width - indent.length);
  const lines: string[] = [];
  let line = "";
  for (const word of words(text)) {
    if (!line) {
      line = word;
    } else if (line.length + 1 + word.length <= available) {
      line += ` ${word}`;
    } else {
      lines.push(`${indent}${line}`);
      line = word;
    }
  }
  if (line) lines.push(`${indent}${line}`);
  return lines.length > 0 ? lines : [indent];
}

function heading(title: string): string[] {
  return ["", `=== ${title} ===`];
}

function labelled(label: string, value: string): string[] {
  return wrapText(value, HELP_WIDTH, " ".repeat(label.length)).map((line, index) => index === 0 ? `${label}${line.trimStart()}` : line);
}

function exampleLines(examples: HelpDocument["examples"]): string[] {
  return normalizeHelpExamples(examples).flatMap((example) => {
    const [command, note] = example.command.split(/\s+\/\/\s+/, 2);
    return [
      ...(example.label ? wrapText(`${example.label}:`, HELP_WIDTH, "  ") : []),
      `  ${command}`,
      ...(note ? wrapText(note, HELP_WIDTH, "  ") : []),
    ];
  });
}

function orderedGroups(groups: Map<string, HelpDocument[]>, order: string[] = ROOT_CATEGORY_ORDER): Array<[string, HelpDocument[]]> {
  const rank = (name: string): number => {
    const found = order.indexOf(name);
    return found === -1 ? order.length : found;
  };
  return [...groups.entries()].sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b));
}

function shortExample(entry: HelpDocument): string {
  const examples = normalizeHelpExamples(entry.examples);
  if (examples.length === 0) return "";
  const command = examples[0].command.split(/\s+\/\/\s+/)[0];
  return command.startsWith(EXAMPLE_PREFIX) ? command.slice(EXAMPLE_PREFIX.length) : command;
}

function truncate(text: string, width: number): string {
  if (text.length <= width) return text;
  const cut = text.lastIndexOf(" ", width - 1);
  return `${text.slice(0, cut > 0 ? cut : width - 1).trimEnd()}…`;
}

export function renderListing(entries: HelpDocument[]): string[] {
  const nameWidth = Math.max(...entries.map((e) => e.name.length)) + 2;
  return entries.map((entry) => {
    const summary = truncate(entry.summary ?? entry.description, DESC_WIDTH);
    const example = shortExample(entry);
    return `${entry.name.padEnd(nameWidth)}${summary}${example ? `  ${example}` : ""}`;
  });
}

export function renderOverview(groups: Map<string, HelpDocument[]>): string[] {
  const lines = heading("OSED Help");
  lines.push(...wrapText("Choose a task area, then use help(\"name\") for a quick command reference.", HELP_WIDTH));
  lines.push("", "QUICK START", "  dx @$osed().triage()", "", "DISCOVER", "  help(\"crash\")     Crash analysis commands", "  help(\"rop\")       ROP discovery and construction", "  help(\"?pivot\")    Search commands", "  help(\"all\")       Complete inventory");
  for (const [category, entries] of orderedGroups(groups)) {
    lines.push("", category.toUpperCase());
    lines.push(...renderListing(entries));
  }
  lines.push("", "MORE", "  help(\"rop\")      All ROP commands", "  help(\"all\")      Complete inventory", "  help(\"?pivot\")   Search commands");
  return lines;
}

export function renderAll(groups: Map<string, HelpDocument[]>): string[] {
  const lines = heading("All OSED Commands");
  for (const [category, entries] of orderedGroups(groups)) {
    lines.push("", category.toUpperCase());
    lines.push(...renderListing(entries));
  }
  return lines;
}

export function renderNamespace(name: string, groups: Map<string, HelpDocument[]>): string[] {
  const lines = heading(`Help: ${name}`);
  for (const [task, entries] of orderedGroups(groups, name.toLowerCase() === "rop" ? ROP_TASK_ORDER : [])) {
    lines.push("", task.toUpperCase());
    lines.push(...renderListing(entries));
  }
  lines.push("", ...wrapText("Use help(\"name\") for RUN-first help or help(\"name\", \"full\") for all details.", HELP_WIDTH));
  return lines;
}

export function renderSearch(query: string, groups: Map<string, HelpDocument[]>, total: number): string[] {
  const lines = heading(`Search: ${query} (${total} ${total === 1 ? "match" : "matches"})`);
  if (total === 0) return [...lines, "No matching commands."];
  for (const [category, entries] of orderedGroups(groups)) {
    lines.push("", category.toUpperCase());
    lines.push(...renderListing(entries));
  }
  return lines;
}

export function renderCandidates(suffix: string, entries: HelpDocument[]): string[] {
  const lines = heading(`Ambiguous help: ${suffix}`);
  lines.push("Multiple commands match this suffix:", ...renderListing(entries));
  return lines;
}

export function renderCompactDetail(entry: HelpDocument): string[] {
  const examples = normalizeHelpExamples(entry.examples);
  const lines = heading(`Help: ${entry.name}`);
  lines.push(...wrapText(entry.summary ?? entry.description, HELP_WIDTH));
  if (examples[0]) {
    const [command, note] = examples[0].command.split(/\s+\/\/\s+/, 2);
    lines.push("", "RUN", `  ${command}`, ...(note ? wrapText(note, HELP_WIDTH, "  ") : []));
  }
  if (entry.prerequisites?.length) lines.push("", "REQUIRES", ...entry.prerequisites.flatMap((value) => wrapText(value, HELP_WIDTH, "  ")));
  if (entry.seeAlso?.length) lines.push("", "NEXT", ...wrapText(entry.seeAlso.join(", "), HELP_WIDTH, "  "));
  lines.push("", `MORE → help(\"${entry.name}\", \"full\")`);
  return lines;
}

export function renderFullDetail(entry: HelpDocument): string[] {
  const lines = heading(`Help: ${entry.name}`);
  lines.push("PURPOSE", ...wrapText(entry.description, HELP_WIDTH, "  "), "", "USAGE", `  ${entry.usage}`);
  if (entry.details) lines.push("", "DETAILS", ...wrapText(entry.details, HELP_WIDTH, "  "));
  if (entry.arguments?.length) lines.push("", "ARGUMENTS", ...entry.arguments.flatMap((argument) => labelled(`  ${argument.name}${argument.required ? "" : "?"}: `, argument.description)));
  if (entry.prerequisites?.length) lines.push("", "REQUIRES", ...entry.prerequisites.flatMap((value) => wrapText(value, HELP_WIDTH, "  ")));
  if (entry.limitations?.length) lines.push("", "LIMITATIONS", ...entry.limitations.flatMap((value) => wrapText(value, HELP_WIDTH, "  ")));
  if (entry.examples.length) lines.push("", "EXAMPLES", ...exampleLines(entry.examples));
  if (entry.seeAlso?.length) lines.push("", "SEE ALSO", ...wrapText(entry.seeAlso.join(", "), HELP_WIDTH, "  "));
  return lines;
}
