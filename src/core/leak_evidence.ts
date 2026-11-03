import { MemoryRegionEvidence } from "../analysis/memory";
import { ModuleMitigation } from "../commands/modules";

export type EvidenceProvenance = "debugger_observed" | "leak_derived" | "exploit_usable";

export type PointerClassification = {
  value: bigint;
  pointerSize: 4 | 8;
  provenance: EvidenceProvenance;
  kind: "null" | "module_pointer" | "memory_pointer" | "unmapped";
  module?: { name: string; rva: bigint; aslr: ModuleMitigation["aslr"] };
  memory?: MemoryRegionEvidence;
};

export function classifyPointer(value: bigint, pointerSize: 4 | 8, findModule: (address: bigint) => ModuleMitigation | undefined, inspectMemory: (address: bigint) => MemoryRegionEvidence): PointerClassification {
  if (value === BigInt(0)) return { value, pointerSize, provenance: "debugger_observed", kind: "null" };
  const module = findModule(value);
  const memory = inspectMemory(value);
  if (module) return { value, pointerSize, provenance: "debugger_observed", kind: "module_pointer", module: { name: module.name, rva: value - module.base, aslr: module.aslr }, memory };
  return { value, pointerSize, provenance: "debugger_observed", kind: memory.source === "unavailable" ? "unmapped" : "memory_pointer", memory };
}
