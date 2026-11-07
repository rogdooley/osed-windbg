import { HelpEntry, normalizeHelpExamples } from "./help_catalog";
import { getVersionInfo } from "./version";

export const HELP_WIDTH = 68;
const INDEX_NAME_WIDTH = 24;
const DETAIL_NAME_WIDTH = 23;
const ROOT_CATEGORY_ORDER = ["crash", "target", "payload", "rop", "seh", "shellcode", "pe-api", "strings", "format", "tools"];
const ROP_TASK_ORDER = ["discovery", "planning", "construction", "control flow", "validation", "persistence", "export"];

const CATEGORY_LABELS: Record<string, string> = {
  "pe-api": "PE / API",
};

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

function ruler(): string {
  return "─".repeat(HELP_WIDTH);
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

function categoryLabel(key: string): string {
  return CATEGORY_LABELS[key] ?? key.toUpperCase();
}

/** Index listing: command(...) + summary, two columns, no examples. */
export function renderListing(entries: HelpDocument[]): string[] {
  return entries.map((entry) => {
    const label = `  ${entry.name}(...)`;
    const summary = entry.summary ?? entry.description;
    if (label.length >= INDEX_NAME_WIDTH) {
      return `${label}  ${summary}`;
    }
    return `${label.padEnd(INDEX_NAME_WIDTH)}${summary}`;
  });
}

/** Detail listing: command + full summary, used by namespace/all views. */
function renderDetailListing(entries: HelpDocument[]): string[] {
  const nameWidth = Math.max(DETAIL_NAME_WIDTH, ...entries.map((e) => e.name.length + 2));
  return entries.flatMap((entry) => {
    const summary = entry.summary ?? entry.description;
    if (entry.name.length + 2 > nameWidth) {
      return [entry.name, ...wrapText(summary, HELP_WIDTH, "  ")];
    }
    const descWidth = HELP_WIDTH - nameWidth;
    const wrapped = wrapText(summary, descWidth);
    return wrapped.map((line, i) =>
      `${i === 0 ? entry.name.padEnd(nameWidth) : " ".repeat(nameWidth)}${line}`);
  });
}

export function renderOverview(groups: Map<string, HelpDocument[]>): string[] {
  const info = getVersionInfo();
  const banner = `OSED-WINDBG ${info.version}`;
  const lines: string[] = [
    "",
    `╭─ ${banner} ${ "─".repeat(Math.max(0, HELP_WIDTH - banner.length - 4))}╮`,
    `│ Exploit development · x86 · WinDbg JavaScript extension${" ".repeat(Math.max(0, HELP_WIDTH - 57))}│`,
    `╰${"─".repeat(HELP_WIDTH - 1)}╯`,
  ];
  lines.push(
    "",
    "QUICK START",
    `  ${"triage()".padEnd(INDEX_NAME_WIDTH - 2)}Analyze current crash and exploitability`,
    `  ${"help(\"rop\")".padEnd(INDEX_NAME_WIDTH - 2)}ROP discovery, planning, and construction`,
    `  ${"help(\"all\")".padEnd(INDEX_NAME_WIDTH - 2)}Complete command reference`,
    `  ${"help(\"?pivot\")".padEnd(INDEX_NAME_WIDTH - 2)}Search commands by keyword`,
  );
  for (const [category, entries] of orderedGroups(groups)) {
    lines.push("", categoryLabel(category));
    lines.push(...renderListing(entries));
  }
  lines.push(
    "",
    ruler(),
    `  ${"help(\"<command>\")".padEnd(INDEX_NAME_WIDTH - 2)}Command details`,
    `  ${"help(\"<category>\")".padEnd(INDEX_NAME_WIDTH - 2)}Category reference`,
    `  ${"help(\"?term\")".padEnd(INDEX_NAME_WIDTH - 2)}Search commands`,
  );
  return lines;
}

export function renderAll(groups: Map<string, HelpDocument[]>): string[] {
  const lines = ["", `=== All OSED Commands ===`];
  for (const [category, entries] of orderedGroups(groups)) {
    lines.push("", categoryLabel(category));
    lines.push(...renderDetailListing(entries));
  }
  return lines;
}

export function renderNamespace(name: string, groups: Map<string, HelpDocument[]>): string[] {
  const label = categoryLabel(name.toLowerCase());
  const lines = ["", `${label} — COMMAND REFERENCE`, ruler()];
  for (const [task, entries] of orderedGroups(groups, name.toLowerCase() === "rop" ? ROP_TASK_ORDER : [])) {
    lines.push("", task.toUpperCase());
    for (const entry of entries) {
      const summary = entry.summary ?? entry.description;
      lines.push(`  ${entry.usage.replace(/^dx @\$osed\(\)\./, "")}`);
      lines.push(...wrapText(summary, HELP_WIDTH, "      "));
      lines.push("");
    }
  }
  lines.push(
    ruler(),
    `  help(\"<command>\")  Command details    help(\"?term\")  Search`,
  );
  return lines;
}

export function renderSearch(query: string, groups: Map<string, HelpDocument[]>, total: number): string[] {
  const lines = ["", `=== Search: ${query} (${total} ${total === 1 ? "match" : "matches"}) ===`];
  if (total === 0) return [...lines, "No matching commands."];
  for (const [category, entries] of orderedGroups(groups)) {
    lines.push("", categoryLabel(category));
    lines.push(...renderListing(entries));
  }
  return lines;
}

export function renderCandidates(suffix: string, entries: HelpDocument[]): string[] {
  const lines = ["", `=== Ambiguous help: ${suffix} ===`];
  lines.push("Multiple commands match this suffix:", ...renderListing(entries));
  return lines;
}

export function renderCompactDetail(entry: HelpDocument): string[] {
  const examples = normalizeHelpExamples(entry.examples);
  const lines = ["", `=== Help: ${entry.name} ===`];
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
  const lines = ["", `=== Help: ${entry.name} ===`];
  lines.push("PURPOSE", ...wrapText(entry.description, HELP_WIDTH, "  "), "", "USAGE", `  ${entry.usage}`);
  if (entry.details) lines.push("", "DETAILS", ...wrapText(entry.details, HELP_WIDTH, "  "));
  if (entry.arguments?.length) lines.push("", "ARGUMENTS", ...entry.arguments.flatMap((argument) => labelled(`  ${argument.name}${argument.required ? "" : "?"}: `, argument.description)));
  if (entry.prerequisites?.length) lines.push("", "REQUIRES", ...entry.prerequisites.flatMap((value) => wrapText(value, HELP_WIDTH, "  ")));
  if (entry.limitations?.length) lines.push("", "LIMITATIONS", ...entry.limitations.flatMap((value) => wrapText(value, HELP_WIDTH, "  ")));
  if (entry.examples.length) lines.push("", "EXAMPLES", ...exampleLines(entry.examples));
  if (entry.seeAlso?.length) lines.push("", "SEE ALSO", ...wrapText(entry.seeAlso.join(", "), HELP_WIDTH, "  "));
  return lines;
}
