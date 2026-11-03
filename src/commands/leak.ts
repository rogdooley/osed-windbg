import { memoryRegion } from "../analysis/memory";
import { classifyPointer } from "../core/leak_evidence";
import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { normalizeAddress } from "../core/validation";
import { findModuleByAddress } from "./modules";
import { decodeProtectValue, getPointerSize } from "../core/memory";

export function createLeakClassifyCommand(): Command {
  return {
    name: "leak_classify",
    description: "Classify a pointer value without dereferencing it.",
    usage: "dx @$osed().leak_classify(value)",
    examples: ["dx @$osed().leak_classify(0x76A31240)"],
    schema: { value: { type: ["number", "string"], required: true } },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const value = normalizeAddress(options.value);
      const result = classifyPointer(value, pointerSize, findModuleByAddress, memoryRegion);
      out.section("POINTER CLASSIFICATION");
      out.print("VALUE");
      out.print("  Address: " + out.formatAddress(value, pointerSize));
      out.print("  Architecture: " + (pointerSize === 4 ? "x86" : "x64"));
      out.print("  Pointer width: " + String(pointerSize * 8) + " bits");
      if (result.module || result.memory) out.print("TARGET");
      out.print("  Classification: " + (result.kind === "module_pointer" ? "Loaded module" : result.kind === "memory_pointer" ? "Mapped memory" : result.kind === "reserved" ? "Reserved memory" : result.kind === "unmapped" ? "Unmapped" : result.kind === "null" ? "Null pointer" : "Unknown"));
      if (result.module) {
        out.print("  Module: " + (result.module.name.split(/[\\\\/]/).pop() ?? result.module.name));
        out.print("  Module RVA: 0x" + result.module.rva.toString(16).toUpperCase().padStart(pointerSize * 2, "0"));
        out.print("  ASLR: " + result.module.aslr);
      }
      if (result.memory) {
        out.print("  State: " + (result.memory.state === "commit" ? "MEM_COMMIT" : result.memory.state === "reserve" ? "MEM_RESERVE" : result.memory.state === "free" ? "MEM_FREE" : "unknown"));
        out.print("  Type: " + (result.memory.regionType === "unknown" ? "unknown" : "MEM_" + result.memory.regionType.toUpperCase()));
        out.print("  Protection: " + (result.memory.raw.protection === undefined ? "unknown" : decodeProtectValue(result.memory.raw.protection).name));
        out.print("  Executable: " + (result.memory.executable === true ? "Yes" : result.memory.executable === false ? "No" : "Unknown"));
      }
      out.print("PROVENANCE");
      out.print("  " + result.provenance);
      out.print("ASSESSMENT");
      out.print(result.kind === "module_pointer" ? "  Valid pointer into a loaded module." : result.kind === "null" ? "  Null pointer." : result.kind === "memory_pointer" ? "  Address resolves to committed memory." : result.kind === "reserved" ? "  Address is reserved but not committed." : result.kind === "unmapped" ? "  Address does not resolve to mapped memory." : "  Memory state could not be established.");
      out.print("  No information disclosure established.");
      return { command: "leak_classify", args: options, success: true, findings: [result], warnings: [], errors: [] };
    },
  };
}
