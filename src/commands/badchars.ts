import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readMemory } from "../core/memory";
import { normalizeAddress, normalizeByteArray } from "../core/validation";
import { compareBadchars, expectedBytes } from "../logic/badchars_logic";

function result(command: string, args: Record<string, unknown>, findings: unknown[], warnings: string[] = []): CommandResult {
  return { command, args, success: true, findings, warnings, errors: [] };
}

export function createBadcharsCommand(): Command {
  return {
    name: "badchars",
    description: "Identify bad characters from a memory byte sequence.",
    usage: "dx @$osed.badchars({ address: 0x41414141, exclude: [0, 10, 13] })",
    examples: [
      "dx @$osed.badchars({ address: 0x00B8F900 })",
      "dx @$osed.badchars({ address: '00B8F900', exclude: [0, 10, 13, 0] })",
    ],
    schema: {
      address: { type: ["number", "string"], required: true },
      exclude: { type: "array", elementType: "number", default: [] },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const address = normalizeAddress(options.address);
      const normalizedExclude = normalizeByteArray((options.exclude as number[]) ?? []);
      const expected = expectedBytes(normalizedExclude.values);
      const observed = readMemory(address, expected.length);
      const compared = compareBadchars(observed, expected);
      const pointerSize = getPointerSize();

      out.section("Bad Character Analysis");
      out.info(`Start address: ${out.formatAddress(address, pointerSize)}`);
      out.info(`Exclude count: ${normalizedExclude.values.length}`);

      if (compared.breakOffset !== undefined && compared.nextExpected !== undefined) {
        out.warn(`Sequence breaks at offset 0x${compared.breakOffset.toString(16).toUpperCase()}.`);
        out.warn(`Next expected byte: ${out.formatHexByte(compared.nextExpected)}`);
      } else {
        out.info("No sequence break detected in sampled byte range.");
      }

      out.table(
        [
          { key: "offset", header: "Offset", width: 8 },
          { key: "expected", header: "Expected", width: 10 },
          { key: "observed", header: "Observed", width: 10 },
        ],
        compared.mismatches.slice(0, 32).map((mismatch) => ({
          offset: `0x${mismatch.offset.toString(16).toUpperCase()}`,
          expected: out.formatHexByte(mismatch.expected),
          observed: out.formatHexByte(mismatch.observed),
        })),
      );

      const excludeList = normalizedExclude.values
        .map((value) => value.toString(16).toUpperCase().padStart(2, "0"))
        .join(" ");
      out.info(`Copy-ready exclude list: ${excludeList}`);
      out.whyItMatters("Accurate badchar profiling prevents payload corruption before shellcode staging.");

      const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];
      return result(
        "badchars",
        {
          ...options,
          exclude: normalizedExclude.values,
        },
        [
          {
            breakOffset: compared.breakOffset,
            nextExpected: compared.nextExpected,
            mismatches: compared.mismatches,
            exclude: normalizedExclude.values,
          },
        ],
        warnings,
      );
    },
  };
}
