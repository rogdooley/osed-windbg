import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readMemory, tryReadMemory } from "../core/memory";
import { normalizeAddress, normalizeByteArray } from "../core/validation";
import { compareBadchars, expectedBytes, formatByteArray, locateExpectedArray } from "../logic/badchars_logic";
import { readRegisters } from "./triage";

function result(command: string, args: Record<string, unknown>, findings: unknown[], warnings: string[] = []): CommandResult {
  return { command, args, success: true, findings, warnings, errors: [] };
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

      const window = tryReadMemory(anchor, windowBytes);
      if (!window) {
        out.warn("Anchor memory was not readable.");
        return result("badchar_find", options, [{ located: false }], ["Anchor memory was not readable."]);
      }

      const located = locateExpectedArray(window, expected, minRun);
      if (!located) {
        out.warn(`Test array not found within ${windowBytes} bytes of the anchor (min run ${minRun}).`);
        return result("badchar_find", options, [{ located: false }], ["Test array not found near anchor."]);
      }

      const landing = anchor + BigInt(located.offset);
      const observed = window.slice(located.offset);
      const compared = compareBadchars(observed, expected);

      out.info(`Located at ${out.formatAddress(landing, pointerSize)} (anchor + 0x${located.offset.toString(16).toUpperCase()}).`);
      out.info(`Clean run before first break: ${located.matchedRun} bytes.`);
      if (compared.breakOffset !== undefined && compared.nextExpected !== undefined) {
        out.warn(`First corruption at array offset 0x${compared.breakOffset.toString(16).toUpperCase()}: expected ${out.formatHexByte(compared.nextExpected)}, observed ${out.formatHexByte(observed[compared.breakOffset])}.`);
        out.info("The first break is the high-confidence bad byte; later mismatches may be shift artifacts.");
      } else {
        out.info("No corruption detected across the located array — no bad characters in this exclude set.");
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

      // Highest-confidence next step: exclude the first corrupted byte and re-test.
      const suggestedExclude = compared.nextExpected !== undefined
        ? [...new Set([...normalizedExclude.values, compared.nextExpected])].sort((a, b) => a - b)
        : normalizedExclude.values;
      out.info(`Suggested next exclude: ${suggestedExclude.map((value) => value.toString(16).toUpperCase().padStart(2, "0")).join(" ") || "(none)"}`);

      const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];
      return result(
        "badchar_find",
        { ...options, exclude: normalizedExclude.values },
        [
          {
            located: true,
            landingAddress: landing,
            anchorOffset: located.offset,
            cleanRun: located.matchedRun,
            breakOffset: compared.breakOffset,
            nextExpected: compared.nextExpected,
            mismatches: compared.mismatches,
            suggestedExclude,
            exclude: normalizedExclude.values,
          },
        ],
        warnings,
      );
    },
  };
}
