import { memoryRegion } from "../analysis/memory";
import { classifyPointer } from "../core/leak_evidence";
import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { normalizeAddress } from "../core/validation";
import { findModuleByAddress } from "./modules";
import { getPointerSize } from "../core/memory";

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
      out.print("  Architecture: x" + String(pointerSize * 8));
      if (result.module || result.memory) out.print("TARGET");
      if (result.module) {
        out.print("  Module: " + (result.module.name.split(/[\\\\/]/).pop() ?? result.module.name));
        out.print("  Module RVA: 0x" + result.module.rva.toString(16).toUpperCase().padStart(pointerSize * 2, "0"));
        out.print("  ASLR: " + result.module.aslr);
      }
      if (result.memory) {
        out.print("  Protection: " + (result.memory.executable === true ? "executable" : result.memory.executable === false ? "non-executable" : "unknown"));
        out.print("  Region: " + result.memory.regionType);
      }
      out.print("PROVENANCE");
      out.print("  " + result.provenance);
      out.print("ASSESSMENT");
      out.print(result.kind === "module_pointer" ? "  Valid pointer into a loaded module." : result.kind === "null" ? "  Null pointer." : result.kind === "memory_pointer" ? "  Pointer into a mapped memory region." : "  No mapped target established.");
      out.print("  No information disclosure established.");
      return { command: "leak_classify", args: options, success: true, findings: [result], warnings: [], errors: [] };
    },
  };
}
