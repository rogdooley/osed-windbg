import { resolveTeb32Address } from "../analysis/seh";
import { getPointerSize, readMemory, readPointer } from "../core/memory";
import * as out from "../core/output";
import { Command, CommandResult } from "../core/registry";
import { readRegisters } from "./triage";

type StackBounds = {
  base?: bigint;
  limit?: bigint;
};

function stackBounds(pointerSize: 4 | 8): StackBounds {
  if (pointerSize !== 4) {
    return {};
  }
  const teb = resolveTeb32Address(host.currentThread as Record<string, unknown>);
  if (!teb) {
    return {};
  }
  try {
    return {
      base: readPointer(teb + BigInt(4), 4),
      limit: readPointer(teb + BigInt(8), 4),
    };
  } catch (_error) {
    return {};
  }
}

function findPattern(buffer: Uint8Array, pattern: Uint8Array, maxResults: number): number[] {
  const hits: number[] = [];
  if (pattern.length === 0 || buffer.length < pattern.length) {
    return hits;
  }
  const last = buffer.length - pattern.length;
  for (let i = 0; i <= last; i += 1) {
    let match = true;
    for (let j = 0; j < pattern.length; j += 1) {
      if (buffer[i + j] !== pattern[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      hits.push(i);
      if (hits.length >= maxResults) {
        break;
      }
    }
  }
  return hits;
}

export function createFindStackBytesCommand(): Command {
  return {
    name: "find_stack_bytes",
    description: "Find byte sequence hits in the current thread stack only.",
    usage: "dx @$osed().find_stack_bytes(bytes, maxResults?, stackBytes?)",
    examples: [
      'dx @$osed().find_stack_bytes("43 43 43 43")',
      'dx @$osed().find_stack_bytes("43 43 43 43", 20, 4096)',
    ],
    schema: {
      bytes: { type: "array", elementType: "number", required: true },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
      stackBytes: { type: "number", min: 16, max: 1048576 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const bytes = options.bytes as number[];
      if (bytes.length === 0 || bytes.some((value) => !Number.isInteger(value) || value < 0 || value > 0xff)) {
        throw new Error("bytes must contain 0x00..0xFF integers.");
      }

      const pointerSize = getPointerSize();
      const regs = readRegisters(pointerSize);
      if (regs.sp === undefined) {
        throw new Error("Stack pointer is unavailable.");
      }

      const bounds = stackBounds(pointerSize);
      let searchBytes = options.stackBytes as number | undefined;
      const warnings: string[] = [];
      if (searchBytes === undefined && bounds.base !== undefined && bounds.base > regs.sp) {
        searchBytes = Number(bounds.base - regs.sp);
      }
      if (searchBytes === undefined) {
        searchBytes = 4096;
        warnings.push("Stack bounds unavailable; defaulted to a 4096-byte search window from SP.");
      }
      if (bounds.base !== undefined && bounds.base > regs.sp) {
        const maxToBase = Number(bounds.base - regs.sp);
        if (searchBytes > maxToBase) {
          searchBytes = maxToBase;
          warnings.push("stackBytes exceeded StackBase and was clamped to the current thread stack range.");
        }
      }

      const buffer = readMemory(regs.sp, searchBytes);
      const pattern = Uint8Array.from(bytes);
      const offsets = findPattern(buffer, pattern, options.maxResults as number);

      out.section("Find Stack Bytes");
      out.info(`Start: ${out.formatAddress(regs.sp, pointerSize)} (${(regs.spName ?? "sp").toUpperCase()})`);
      if (bounds.base !== undefined) {
        out.info(`StackBase: ${out.formatAddress(bounds.base, pointerSize)}`);
      }
      if (bounds.limit !== undefined) {
        out.info(`StackLimit: ${out.formatAddress(bounds.limit, pointerSize)}`);
      }
      out.info(`Searched ${searchBytes} byte(s) in the current thread stack.`);
      out.table(
        [
          { key: "address", header: "Address", width: 18 },
          { key: "offset", header: "SP+Offset", width: 12 },
        ],
        offsets.map((offset) => ({
          address: out.formatAddress(regs.sp! + BigInt(offset), pointerSize),
          offset: `0x${offset.toString(16).toUpperCase()}`,
        })),
      );
      if (offsets.length === 0) {
        out.info("No byte matches found in the searched stack window.");
      }
      out.info("Scope: current thread stack only; this does not search heap, modules outside the stack window, or arbitrary process memory.");
      out.whyItMatters("Stack-local byte matches confirm whether your input landed near control data and help anchor overwrite offsets quickly.");

      return {
        command: "find_stack_bytes",
        args: options,
        success: true,
        findings: offsets.map((offset) => regs.sp! + BigInt(offset)),
        warnings,
        errors: [],
        stats: {
          searchedBytes: searchBytes,
          results: offsets.length,
        },
      };
    },
  };
}
