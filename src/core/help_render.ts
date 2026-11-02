import { HelpEntry, normalizeHelpExamples } from "./help_catalog";

export const HELP_WIDTH = 80;
const NAME_WIDTH = 23;

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
  return normalizeHelpExamples(examples).flatMap((example) => [
    ...(example.label ? wrapText(`${example.label}:`, HELP_WIDTH, "  ") : []),
    `  ${example.command}`,
  ]);
}

export function renderListing(entries: HelpDocument[]): string[] {
  return entries.flatMap((entry) => {
    const summary = entry.summary ?? entry.description;
    if (entry.name.length > NAME_WIDTH) {
      return [entry.name, ...wrapText(summary, HELP_WIDTH, "  ")];
    }
    const descriptionWidth = HELP_WIDTH - NAME_WIDTH - 2;
    const description = wrapText(summary, descriptionWidth);
    return description.map((line, index) => `${index === 0 ? entry.name.padEnd(NAME_WIDTH) : " ".repeat(NAME_WIDTH)}  ${line}`);
  });
}

export function renderOverview(groups: Map<string, HelpDocument[]>): string[] {
  const lines = heading("OSED Help");
  lines.push(...wrapText("Choose a task area, then use help(\"name\") for a quick command reference.", HELP_WIDTH));
  lines.push("", "QUICK START", "  help(\"triage\")  help(\"pattern_create\")  help(\"rop.scan_live\")");
  for (const [category, entries] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    lines.push("", category.toUpperCase());
    lines.push(...renderListing(entries));
  }
  lines.push("", "ALL COMMANDS → help(\"all\")");
  return lines;
}

export function renderAll(groups: Map<string, HelpDocument[]>): string[] {
  const lines = heading("All OSED Commands");
  for (const [category, entries] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    lines.push("", category.toUpperCase());
    lines.push(...renderListing(entries));
  }
  return lines;
}

export function renderNamespace(name: string, groups: Map<string, HelpDocument[]>): string[] {
  const lines = heading(`Help: ${name}`);
  for (const [task, entries] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    lines.push("", task.toUpperCase());
    lines.push(...renderListing(entries));
  }
  lines.push("", ...wrapText("Use help(\"name\") for RUN-first help or help(\"name\", \"full\") for all details.", HELP_WIDTH));
  return lines;
}

export function renderSearch(query: string, groups: Map<string, HelpDocument[]>, total: number): string[] {
  const lines = heading(`Search: ${query} (${total} ${total === 1 ? "match" : "matches"})`);
  if (total === 0) return [...lines, "No matching commands."];
  for (const [category, entries] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
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
  if (examples[0]) lines.push("", "RUN", `  ${examples[0].command}`);
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
