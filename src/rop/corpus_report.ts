import type { CapabilityIndex } from "./capabilities";
import type { RopCapability, RopGadget } from "./types";

export type CorpusReportOrigin = "live" | "rpplus" | "imported";
export type CorpusReportValidation = "sampled" | "unverified" | "unknown";

export interface CorpusReportModule {
  name: string;
  base?: bigint;
  aslr?: "enabled" | "disabled" | "unknown";
}

export interface CorpusReportOptions {
  pointerSize: 4 | 8;
  origin: CorpusReportOrigin;
  validation: CorpusReportValidation;
  modules?: CorpusReportModule[];
  badchars?: number[];
}

type ReportRow = { va: bigint | undefined; rva: bigint | undefined; instructions: string; capability: string; esp: string };

function normalizedIdentity(value: string | undefined): string {
  return (value ?? "?").replace(/\\/g, "/").split("/").pop()!.toLowerCase();
}

function capabilityLabel(capabilities: RopCapability[]): string {
  const loads = [...new Set(capabilities.filter((cap) => cap.kind === "LOAD_REGISTER" && cap.register).map((cap) => cap.register!.toUpperCase()))];
  if (loads.length > 0) return "LOAD(" + loads.join(",") + ")";
  const pivot = capabilities.find((cap) => cap.kind === "STACK_PIVOT");
  if (pivot) {
    const register = pivot.evidence.join(" ").match(/\b(?:xchg|mov)\s+esp\s*,\s*([a-z]{3})\b/i)?.[1];
    return "PIVOT(" + (register?.toUpperCase() ?? "?") + ")";
  }
  const jump = capabilities.find((cap) => cap.kind === "DISPATCH_JMP_REGISTER");
  if (jump) return "JMP(" + (jump.register?.toUpperCase() ?? "?") + ")";
  const write = capabilities.find((cap) => cap.kind === "MEMORY_WRITE");
  if (write) return "WRITE(" + (write.register?.toUpperCase() ?? "?") + ")";
  if (capabilities.some((cap) => cap.kind === "STACK_ADJUST")) return "ADJUST(ESP)";
  return capabilities[0]?.kind ?? "?";
}

function espDelta(gadget: RopGadget): string {
  if (gadget.categories.includes("STACK_PIVOT")) return "DYN";
  const field = gadget.semanticSummary.summary.stackDelta;
  if (field.values.unknown || field.values.conservative.size > 0 || field.values.exact.size !== 1) return "?";
  const value = [...field.values.exact][0];
  return value > 0 ? "+" + value : String(value);
}

function hex(value: bigint, width: number): string {
  return "0x" + value.toString(16).toUpperCase().padStart(width, "0");
}

function pad(value: string, width: number): string {
  return value + " ".repeat(Math.max(0, width - value.length));
}

function validationLabel(validation: CorpusReportValidation): string {
  return validation === "sampled" ? "SAMPLED" : validation === "unverified" ? "UNVERIFIED" : "?";
}

function originLabel(origin: CorpusReportOrigin): string {
  return origin === "live" ? "LIVE" : origin === "imported" ? "IMPORTED" : "RP++";
}

export function formatCorpusReport(index: CapabilityIndex, options: CorpusReportOptions): string {
  const addressWidth = options.pointerSize * 2;
  const moduleMetadata = new Map((options.modules ?? []).map((module) => [normalizedIdentity(module.name), module]));
  const groups = new Map<string, Array<{ gadget: RopGadget; locationIndex: number }>>();
  for (const gadget of index.gadgets) {
    gadget.locations.forEach((location, locationIndex) => {
      const key = normalizedIdentity(location.module);
      const group = groups.get(key) ?? [];
      group.push({ gadget, locationIndex });
      groups.set(key, group);
    });
  }

  const badchars = options.badchars === undefined ? "?" : options.badchars.length === 0 ? "none" : options.badchars.map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ");
  const lines = [
    "=== OSED ROP CORPUS ===",
    "Architecture: " + (options.pointerSize === 4 ? "x86" : "x64"),
    "Corpus: " + originLabel(options.origin) + " | Validation: " + validationLabel(options.validation),
    "Gadgets: " + [...groups.values()].reduce((total, group) => total + group.length, 0) + " | Modules: " + groups.size,
    "Badchars: " + badchars,
  ];
  if (groups.size === 0) {
    lines.push("", "No gadgets in corpus.");
    return lines.join("\n");
  }

  for (const [identity, entries] of [...groups.entries()].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)) {
    const metadata = moduleMetadata.get(identity);
    const moduleName = metadata?.name ?? entries[0].gadget.locations[entries[0].locationIndex].module ?? "?";
    const rows: ReportRow[] = entries.map(({ gadget, locationIndex }) => {
      const location = gadget.locations[locationIndex];
      const va = location.virtualAddress === undefined ? undefined : BigInt(location.virtualAddress);
      return {
        va,
        rva: va === undefined || metadata?.base === undefined ? undefined : va - metadata.base,
        instructions: gadget.instructions.map((instruction) => instruction.normalizedText || instruction.originalText).join(" ; "),
        capability: capabilityLabel(gadget.capabilities),
        esp: espDelta(gadget),
      };
    }).sort((left, right) =>
      (left.rva ?? left.va ?? BigInt(-1)) < (right.rva ?? right.va ?? BigInt(-1)) ? -1
        : (left.rva ?? left.va ?? BigInt(-1)) > (right.rva ?? right.va ?? BigInt(-1)) ? 1
          : left.instructions < right.instructions ? -1 : left.instructions > right.instructions ? 1 : 0);
    const rendered = rows.map((row) => ({
      va: row.va === undefined ? "?" : hex(row.va, addressWidth),
      rva: row.rva === undefined ? "?" : "+" + row.rva.toString(16).toUpperCase().padStart(Math.max(1, addressWidth - 2), "0"),
      instructions: row.instructions,
      capability: row.capability,
      esp: row.esp,
    }));
    const widths = {
      va: Math.max(2, ...rendered.map((row) => row.va.length)),
      rva: Math.max(3, ...rendered.map((row) => row.rva.length)),
      instructions: Math.max(12, ...rendered.map((row) => row.instructions.length)),
      capability: Math.max(10, ...rendered.map((row) => row.capability.length)),
      esp: Math.max(3, ...rendered.map((row) => row.esp.length)),
    };
    lines.push(
      "",
      "MODULE: " + moduleName,
      "Base: " + (metadata?.base === undefined ? "?" : hex(metadata.base, addressWidth)) + " | ASLR: " + (metadata?.aslr === "enabled" ? "ON" : metadata?.aslr === "disabled" ? "OFF" : "?") + " | Gadgets: " + rendered.length,
      "",
      pad("VA", widths.va) + "  " + pad("RVA", widths.rva) + "  " + pad("INSTRUCTIONS", widths.instructions) + "  " + pad("CAPABILITY", widths.capability) + "  ESP",
      "-".repeat(widths.va) + "  " + "-".repeat(widths.rva) + "  " + "-".repeat(widths.instructions) + "  " + "-".repeat(widths.capability) + "  " + "-".repeat(widths.esp),
      ...rendered.map((row) => pad(row.va, widths.va) + "  " + pad(row.rva, widths.rva) + "  " + pad(row.instructions, widths.instructions) + "  " + pad(row.capability, widths.capability) + "  " + row.esp),
    );
  }
  return lines.join("\n");
}
