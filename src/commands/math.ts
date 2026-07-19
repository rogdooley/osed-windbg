import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { analyzeMathValue } from "../logic/math_logic";

export function createMathCommand(): Command {
  return {
    name: "math",
    description: "Format an integer as hex, signed, unsigned, little-endian bytes, and two's complement.",
    usage: "dx @$osed().math(value, bits?)",
    examples: [
      "dx @$osed().math(0xFFFFFFD6)",
      "dx @$osed().math(-42, 32)",
      "dx @$osed().math(0x625011D3, 32)",
    ],
    schema: {
      value: { type: ["number", "string"], required: true },
      bits: { type: "number", default: 32 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const evidence = analyzeMathValue(options.value, options.bits);

      out.section("Math");
      out.table(
        [
          { key: "field", header: "Field", width: 18 },
          { key: "value", header: "Value", width: 24 },
        ],
        [
          { field: "Input", value: evidence.input },
          { field: "Bits", value: evidence.bits.toString() },
          { field: "Hex", value: evidence.hex },
          { field: "Unsigned", value: evidence.unsigned },
          { field: "Signed", value: evidence.signed },
          { field: "Little-endian", value: evidence.littleEndianBytes },
          { field: "Two's complement", value: evidence.twosComplement },
        ],
      );

      return {
        command: "math",
        args: options,
        success: true,
        findings: [evidence],
        warnings: [],
        errors: [],
      };
    },
  };
}
