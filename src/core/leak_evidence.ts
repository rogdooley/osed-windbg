import { MemoryRegionEvidence } from "../analysis/memory";
import { ModuleMitigation } from "../commands/modules";

export type EvidenceProvenance = "debugger_observed" | "leak_derived" | "exploit_usable";

export type PointerClassification = {
  value: bigint;
  pointerSize: 4 | 8;
  provenance: EvidenceProvenance;
  kind: "null" | "module_pointer" | "memory_pointer" | "reserved" | "unmapped" | "unknown";
  module?: { name: string; rva: bigint; aslr: ModuleMitigation["aslr"] };
  memory?: MemoryRegionEvidence;
};

export type DerivedModuleBase = {
  pointer: bigint;
  rva: bigint;
  base?: bigint;
  pointerSize: 4 | 8;
  alignmentPlausible: boolean;
  moduleMatched: boolean;
  module?: { name: string; base: bigint; aslr: ModuleMitigation["aslr"] };
  provenance: "leak_derived";
  reason?: string;
};

export function classifyPointer(value: bigint, pointerSize: 4 | 8, findModule: (address: bigint) => ModuleMitigation | undefined, inspectMemory: (address: bigint) => MemoryRegionEvidence): PointerClassification {
  if (value === BigInt(0)) return { value, pointerSize, provenance: "debugger_observed", kind: "null" };
  const module = findModule(value);
  const memory = inspectMemory(value);
  if (module) return { value, pointerSize, provenance: "debugger_observed", kind: "module_pointer", module: { name: module.name, rva: value - module.base, aslr: module.aslr }, memory };
  const kind = memory.source === "unavailable" || memory.state === "unknown"
    ? "unknown"
    : memory.state === "free"
      ? "unmapped"
      : memory.state === "reserve"
        ? "reserved"
        : "memory_pointer";
  return { value, pointerSize, provenance: "debugger_observed", kind, memory };
}

/** Extract pointer-shaped hexadecimal tokens from explicitly supplied text.
 * This is evidence parsing only: it neither observes a network response nor
 * establishes that an attacker can receive the text. */
export function extractHexPointers(text: string, pointerSize: 4 | 8): bigint[] {
  const minimumDigits = pointerSize === 8 ? 8 : 6;
  const maximumDigits = pointerSize * 2;
  const expression = new RegExp(`(?:0x)?[0-9a-fA-F]{${minimumDigits},${maximumDigits}}`, "g");
  const values: bigint[] = [];
  const seen = new Set<string>();
  for (const match of text.matchAll(expression)) {
    const token = match[0];
    const value = BigInt(token.startsWith("0x") || token.startsWith("0X") ? token : `0x${token}`);
    const key = value.toString();
    if (!seen.has(key)) {
      seen.add(key);
      values.push(value);
    }
  }
  return values;
}

/** Derive a candidate image base and bind it back to the current target's
 * loaded-module map. Arithmetic alone is never reported as a valid base. */
export function deriveModuleBase(
  pointer: bigint,
  rva: bigint,
  pointerSize: 4 | 8,
  findModule: (address: bigint) => ModuleMitigation | undefined,
): DerivedModuleBase {
  if (rva > pointer) {
    return {
      pointer, rva, pointerSize, alignmentPlausible: false, moduleMatched: false,
      provenance: "leak_derived", reason: "RVA exceeds the observed pointer.",
    };
  }
  const base = pointer - rva;
  const module = findModule(pointer);
  const moduleMatched = module !== undefined && module.base === base && pointer - module.base === rva;
  return {
    pointer,
    rva,
    base,
    pointerSize,
    alignmentPlausible: (base & BigInt(0xfff)) === BigInt(0),
    moduleMatched,
    module: moduleMatched && module ? { name: module.name, base: module.base, aslr: module.aslr } : undefined,
    provenance: "leak_derived",
    reason: moduleMatched ? undefined : "Calculated base does not match a loaded module in the current target.",
  };
}
