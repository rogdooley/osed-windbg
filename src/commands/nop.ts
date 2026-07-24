import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";

export function createNopCommand(): Command {
  return {
    name: "nop",
    description: "Generate a NOP sled of N bytes.",
    usage: "dx @$osed().nop(16)",
    examples: [
      "dx @$osed().nop(16)",
      "dx @$osed().nop(32)",
      "dx @$osed().nop(16, 0x90)",
    ],
    schema: {
      length: { type: "number", min: 1, max: 4096, required: true },
      byte: { type: "number", default: 0x90 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const length = options.length as number;
      const nopByte = ((options.byte as number | undefined) ?? 0x90) & 0xff;

      const sled = Array.from({ length }, () => nopByte);
      const hexStr = sled.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(" ");
      const python = `b"${sled.map((b) => `\\x${b.toString(16).padStart(2, "0")}`).join("")}"`;

      out.section("NOP Sled");
      out.info(`Length: ${length} bytes  Byte: 0x${nopByte.toString(16).toUpperCase().padStart(2, "0")}`);
      out.print(hexStr);
      out.print(python);
      out.whyItMatters("A NOP sled gives the exploit a landing zone — small ESP variations still slide into shellcode.");

      return {
        command: "nop",
        args: options,
        success: true,
        findings: [{ length, byte: nopByte, sled }],
        warnings: [],
        errors: [],
      };
    },
  };
}
