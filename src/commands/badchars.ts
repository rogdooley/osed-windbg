import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readMemory, tryReadMemory } from "../core/memory";
import { normalizeAddress, normalizeByteArray } from "../core/validation";
import { compareBadchars, expectedBytes, formatByteArray, locateExpectedArray } from "../logic/badchars_logic";
import { readRegisters } from "./triage";

function result(command: string, args: Record<string, unknown>, findings: unknown[], warnings: string[] = []): CommandResult {
  return { command, args, success: true, findings, warnings, errors: [] };
}

function readLargestWindow(start: bigint, maxLength: number): Uint8Array | undefined {
  let low = 1;
  let high = maxLength;
  let best: Uint8Array | undefined;

  while (low <= high) {
    const mid = low + Math.floor((high - low) / 2);
    const chunk = tryReadMemory(start, mid);
    if (chunk) {
      best = chunk;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  return best;
}

export function createBadcharsCommand(): Command {
  return {
    name: "badchars",
    description: "Identify bad characters from a memory byte sequence.",
    usage: "dx @$osed().badchars(address, exclude?)",
    examples: [
      "dx @$osed().badchars(0x00B8F900)",
      'dx @$osed().badchars("00B8F900", "00 0A 0D")',
    ],
    schema: {
      address: { type: ["number", "string"], required: true },
      exclude: { type: "array", elementType: "number", default: [] },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const address = normalizeAddress(options.address);
      const normalizedExclude = normalizeByteArray((options.exclude as number[]) ?? []);
      const expected = expectedBytes(normalizedExclude.values);
      const observed = readMemory(address, expected.length + 64);
      const compared = compareBadchars(observed, expected);
      const pointerSize = getPointerSize();

      out.section("Bad Character Analysis");
      out.info(`Start address: ${out.formatAddress(address, pointerSize)}`);
      if (normalizedExclude.values.length > 0) {
        out.info(`Known excludes: ${normalizedExclude.values.map((v) => out.formatHexByte(v)).join(" ")}`);
      }

      if (compared.badChars.length > 0) {
        out.warn(`Bad characters found: ${compared.badChars.map((v) => out.formatHexByte(v)).join(" ")}`);
      } else if (compared.expectedConsumed >= expected.length) {
        out.info("All expected bytes survived — no bad characters detected.");
      } else {
        out.info("No bad characters detected in the tested range.");
      }

      out.info(`Survivors: ${compared.survivorCount} of ${compared.expectedConsumed} tested bytes`);

      if (compared.expectedConsumed < expected.length) {
        const lastTested = expected[compared.expectedConsumed - 1];
        const firstUntested = expected[compared.expectedConsumed];
        out.warn(
          `Array truncated after ${out.formatHexByte(lastTested)}; bytes ${out.formatHexByte(firstUntested)}-0xFF not tested.`,
        );
      }

      const allExclude = [...new Set([...normalizedExclude.values, ...compared.badChars])].sort((a, b) => a - b);
      out.info(
        `Copy-ready exclude list: ${allExclude.map((v) => v.toString(16).toUpperCase().padStart(2, "0")).join(" ") || "(none)"}`,
      );
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
            badChars: compared.badChars,
            survivorCount: compared.survivorCount,
            expectedConsumed: compared.expectedConsumed,
            mismatches: compared.mismatches,
            exclude: normalizedExclude.values,
            allExclude,
          },
        ],
        warnings,
      );
    },
  };
}

export function createBadcharArrayCommand(): Command {
  return {
    name: "badchar_array",
    description: "Generate a bad-character test byte array (0x00-0xFF minus excludes) in paste-ready forms.",
    usage: "dx @$osed().badchar_array(exclude?)",
    examples: ["dx @$osed().badchar_array()", 'dx @$osed().badchar_array("00 0A 0D")'],
    schema: {
      exclude: { type: "array", elementType: "number", default: [] },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const normalizedExclude = normalizeByteArray((options.exclude as number[]) ?? []);
      const expected = expectedBytes(normalizedExclude.values);
      const python = formatByteArray(expected, "python");
      const c = formatByteArray(expected, "c");
      const hex = formatByteArray(expected, "hex");

      out.section("Bad Character Test Array");
      out.info(`Bytes: ${expected.length} (excluded ${normalizedExclude.values.length})`);
      out.print(`Python: ${python}`);
      out.print(`C:      ${c}`);
      out.print(`Hex:    ${hex}`);
      out.whyItMatters("Send this array to the target, then use badchar_find to locate it in memory and see which bytes were mangled.");

      const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];
      return result(
        "badchar_array",
        { ...options, exclude: normalizedExclude.values },
        [{ count: expected.length, exclude: normalizedExclude.values, bytes: expected, formats: { python, c, hex } }],
        warnings,
      );
    },
  };
}

export function createBadcharFindCommand(): Command {
  return {
    name: "badchar_find",
    description: "Locate a sent bad-character array in memory (near an address or the stack pointer) and report the first corrupted byte.",
    usage: "dx @$osed().badchar_find(address?, exclude?, windowBytes?, minRun?)",
    examples: ["dx @$osed().badchar_find()", 'dx @$osed().badchar_find("0012F800", "00 0A 0D")'],
    schema: {
      address: { type: ["number", "string"] },
      exclude: { type: "array", elementType: "number", default: [] },
      windowBytes: { type: "number", min: 256, max: 16384, default: 2048 },
      minRun: { type: "number", min: 4, max: 64, default: 8 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const normalizedExclude = normalizeByteArray((options.exclude as number[]) ?? []);
      const expected = expectedBytes(normalizedExclude.values);
      const windowBytes = options.windowBytes as number;
      const minRun = options.minRun as number;

      let anchor: bigint | undefined;
      let anchorLabel = "n/a";
      if (options.address !== undefined) {
        anchor = normalizeAddress(options.address);
        anchorLabel = out.formatAddress(anchor, pointerSize);
      } else {
        const regs = readRegisters(pointerSize);
        anchor = regs.sp;
        anchorLabel = regs.sp !== undefined ? `${regs.spName ?? "sp"} ${out.formatAddress(regs.sp, pointerSize)}` : "n/a";
      }

      out.section("Bad Character Locate");
      if (anchor === undefined) {
        out.warn("No anchor address available (stack pointer unreadable). Provide an explicit address.");
        return result("badchar_find", options, [{ located: false }], ["No anchor address available."]);
      }
      out.info(`Anchor: ${anchorLabel}`);
      out.info(`Window: ${windowBytes} bytes, expecting a ${expected.length}-byte array.`);

      let window = tryReadMemory(anchor, windowBytes);
      const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];
      if (!window) {
        window = readLargestWindow(anchor, windowBytes);
        if (window) {
          warnings.push(`Anchor range was only partially readable; scanned ${window.length} byte(s).`);
        }
      }
      if (!window) {
        out.warn("Anchor memory was not readable.");
        return result("badchar_find", options, [{ located: false }], ["Anchor memory was not readable."]);
      }
      if (window.length < windowBytes) {
        out.warn(`Anchor range was only partially readable; scanned ${window.length} byte(s).`);
      }

      const located = locateExpectedArray(window, expected, minRun);
      if (!located) {
        out.warn(`Test array not found within ${windowBytes} bytes of the anchor (min run ${minRun}).`);
        return result("badchar_find", options, [{ located: false }], warnings.length > 0 ? warnings : ["Test array not found near anchor."]);
      }

      const landing = anchor + BigInt(located.offset);
      const observed = window.slice(located.offset);
      const compared = compareBadchars(observed, expected);

      out.info(`Located at ${out.formatAddress(landing, pointerSize)} (anchor + 0x${located.offset.toString(16).toUpperCase()}).`);
      out.info(`Matched ${located.matchedRun} survivor bytes starting at expected index ${located.expectedStart}.`);

      if (compared.badChars.length > 0) {
        out.warn(`Bad characters found: ${compared.badChars.map((v) => out.formatHexByte(v)).join(" ")}`);
      } else if (compared.expectedConsumed >= expected.length) {
        out.info("All expected bytes survived — no bad characters detected.");
      } else {
        out.info("No bad characters detected in the tested range.");
      }

      out.info(`Survivors: ${compared.survivorCount} of ${compared.expectedConsumed} tested bytes`);

      if (compared.expectedConsumed < expected.length) {
        const lastTested = expected[compared.expectedConsumed - 1];
        const firstUntested = expected[compared.expectedConsumed];
        out.warn(
          `Array truncated after ${out.formatHexByte(lastTested)}; bytes ${out.formatHexByte(firstUntested)}-0xFF not tested.`,
        );
      }

      const allExclude = [...new Set([...normalizedExclude.values, ...compared.badChars])].sort((a, b) => a - b);
      out.info(
        `Copy-ready exclude list: ${allExclude.map((v) => v.toString(16).toUpperCase().padStart(2, "0")).join(" ") || "(none)"}`,
      );

      return result(
        "badchar_find",
        { ...options, exclude: normalizedExclude.values },
        [
          {
            located: true,
            landingAddress: landing,
            anchorOffset: located.offset,
            expectedStart: located.expectedStart,
            matchedRun: located.matchedRun,
            badChars: compared.badChars,
            survivorCount: compared.survivorCount,
            expectedConsumed: compared.expectedConsumed,
            mismatches: compared.mismatches,
            allExclude,
            exclude: normalizedExclude.values,
          },
        ],
        warnings,
      );
    },
  };
}
