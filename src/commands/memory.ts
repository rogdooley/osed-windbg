import { memoryRegion } from "../analysis/memory";
import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { normalizeAddress } from "../core/validation";

function flag(value: boolean | null): string {
  return value === null ? "unknown" : value ? "yes" : "no";
}

export function createMemoryCommand(): Command {
  return {
    name: "memory",
    description: "Inspect normalized memory-region evidence for an address.",
    usage: "dx @$osed().memory(0x41414141)",
    examples: ["dx @$osed().memory(0x41414141)", "dx @$osed().memory(\"0012F800\")"],
    schema: { address: { type: ["number", "string"], required: true } },
    execute(options: Record<string, unknown>): CommandResult {
      const address = normalizeAddress(options.address);
      const evidence = memoryRegion(address);
      out.section("Memory Evidence");
      out.info(`Address: ${out.formatAddress(address, 8)}`);
      out.table(
        [
          { key: "read", header: "Read" },
          { key: "write", header: "Write" },
          { key: "exec", header: "Exec" },
          { key: "guard", header: "Guard" },
          { key: "noAccess", header: "No access" },
          { key: "commit", header: "Committed" },
          { key: "type", header: "Type" },
        ],
        [{
          read: flag(evidence.readable),
          write: flag(evidence.writable),
          exec: flag(evidence.executable),
          guard: flag(evidence.guarded),
          noAccess: flag(evidence.noAccess),
          commit: flag(evidence.committed),
          type: evidence.regionType,
        }],
      );
      for (const warning of evidence.warnings) out.warn(warning);
      return { command: "memory", args: options, success: true, findings: [evidence], warnings: evidence.warnings, errors: [] };
    },
  };
}
