import { landing } from "../analysis/landing";
import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { normalizeAddress } from "../core/validation";

export function createLandingCommand(): Command {
  return {
    name: "landing",
    description: "Analyze exploit-relevant evidence at ESP/RSP or an explicit address.",
    usage: "dx @$osed().landing()",
    examples: ["dx @$osed().landing()", "dx @$osed().landing(0x0012F800)"],
    schema: { address: { type: ["number", "string"] } },
    execute(options: Record<string, unknown>): CommandResult {
      const address = options.address === undefined ? undefined : normalizeAddress(options.address);
      const evidence = landing(address);
      out.section("Landing Evidence");
      if (evidence.address !== undefined) out.info(`Address: ${out.formatAddress(evidence.address, 8)}`);
      out.table(
        [
          { key: "kind", header: "Observation" },
          { key: "address", header: "Address" },
          { key: "length", header: "Length" },
          { key: "confidence", header: "Confidence" },
        ],
        evidence.observations.map((item) => ({
          kind: item.kind,
          address: item.address === undefined ? "" : out.formatAddress(item.address, 8),
          length: item.length?.toString() ?? "",
          confidence: item.confidence.toFixed(2),
        })),
      );
      out.info(evidence.recommendation);
      const available = evidence.address !== undefined;
      return {
        command: "landing",
        args: options,
        success: available,
        findings: [evidence],
        warnings: available ? [] : [evidence.recommendation],
        errors: [],
      };
    },
  };
}
