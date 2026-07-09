import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { MSF_MAX_LENGTH, decodeOffsetNeedle, generateCyclicPattern, generateMsfPattern } from "../logic/pattern_logic";

function success(command: string, args: Record<string, unknown>, findings: unknown[]): CommandResult {
  return { command, args, success: true, findings, warnings: [], errors: [] };
}

export function createPatternCommands(): Command[] {
  const patternCreate: Command = {
    name: "pattern_create",
    description: "Generate cyclic pattern strings.",
    usage: "dx @$osed.pattern_create({ length: 300, type: 'msf' })",
    examples: [
      "dx @$osed.pattern_create({ length: 300, type: 'msf' })",
      "dx @$osed.pattern_create({ length: 800, type: 'cyclic' })",
    ],
    schema: {
      length: { type: "number", required: true, min: 1, max: 100000 },
      type: { type: "string", enum: ["msf", "cyclic"], default: "msf" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const length = options.length as number;
      const type = options.type as "msf" | "cyclic";

      if (type === "msf" && length > MSF_MAX_LENGTH) {
        throw new Error(`MSF pattern max length is ${MSF_MAX_LENGTH}.`);
      }

      const pattern = type === "msf" ? generateMsfPattern(length) : generateCyclicPattern(length);

      out.section("Pattern Create");
      out.info(`Format: ${type}`);
      out.info(`Length: ${length}`);
      out.print(pattern);
      out.whyItMatters("Reliable offset discovery is the foundation of controlled EIP/RIP overwrite.");

      return success("pattern_create", options, [{ type, length, pattern }]);
    },
  };

  const patternOffset: Command = {
    name: "pattern_offset",
    description: "Locate value offset inside a generated pattern.",
    usage: "dx @$osed.pattern_offset({ value: 0x39654138, type: 'msf' })",
    examples: [
      "dx @$osed.pattern_offset({ value: 0x39654138, type: 'msf' })",
      "dx @$osed.pattern_offset({ value: '41326341', type: 'cyclic' })",
    ],
    schema: {
      value: { type: ["number", "string"], required: true },
      type: { type: "string", enum: ["msf", "cyclic"], default: "msf" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const raw = options.value;
      if (typeof raw !== "number" && typeof raw !== "string") {
        throw new Error("pattern_offset.value must be number or hex string.");
      }

      const needle = decodeOffsetNeedle(raw);
      const type = options.type as "msf" | "cyclic";
      const pattern = type === "msf" ? generateMsfPattern(MSF_MAX_LENGTH) : generateCyclicPattern(100000);
      const offset = pattern.indexOf(needle);

      out.section("Pattern Offset");
      out.info(`Format: ${type}`);
      out.info(`Needle: ${needle}`);
      if (offset < 0) {
        out.error("Needle not found in selected pattern.");
      } else {
        out.info(`Offset: ${offset}`);
      }
      out.whyItMatters("Exact offset maps crash control to payload layout and exploit reliability.");

      return success("pattern_offset", options, [{ needle, offset }]);
    },
  };

  return [patternCreate, patternOffset];
}
