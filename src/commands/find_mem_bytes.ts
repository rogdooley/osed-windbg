import { getPointerSize, readMemory } from "../core/memory";
import * as out from "../core/output";
import { Command, CommandResult } from "../core/registry";
import { normalizeAddress } from "../core/validation";

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

export function createFindMemBytesCommand(): Command {
  return {
    name: "find_mem_bytes",
    description: "Find byte sequence hits in an explicit live-memory range.",
    usage: "dx @$osed().find_mem_bytes(address, length, bytes, maxResults?)",
    examples: [
      'dx @$osed().find_mem_bytes(0x14800000, 0x16000, "43 43 43 43")',
      'dx @$osed().find_mem_bytes("14800000", 4096, "FF E4", 20)',
    ],
    schema: {
      address: { type: ["number", "string"], required: true },
      length: { type: "number", min: 1, max: 16777216, required: true },
      bytes: { type: "array", elementType: "number", required: true },
      maxResults: { type: "number", min: 1, max: 200, default: 50 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const address = normalizeAddress(options.address);
      const length = options.length as number;
      const bytes = options.bytes as number[];
      if (bytes.length === 0 || bytes.some((value) => !Number.isInteger(value) || value < 0 || value > 0xff)) {
        throw new Error("bytes must contain 0x00..0xFF integers.");
      }

      const pointerSize = getPointerSize();
      const buffer = readMemory(address, length);
      const offsets = findPattern(buffer, Uint8Array.from(bytes), options.maxResults as number);

      out.section("Find Memory Bytes");
      out.info(`Start: ${out.formatAddress(address, pointerSize)}`);
      out.info(`Length: 0x${length.toString(16).toUpperCase()} (${length}) byte(s)`);
      out.table(
        [
          { key: "address", header: "Address", width: 18 },
          { key: "offset", header: "Base+Offset", width: 12 },
        ],
        offsets.map((offset) => ({
          address: out.formatAddress(address + BigInt(offset), pointerSize),
          offset: `0x${offset.toString(16).toUpperCase()}`,
        })),
      );
      if (offsets.length === 0) {
        out.info("No byte matches found in the searched memory range.");
      }
      out.info("Scope: explicit live-memory range only; this can search stack, heap, modules, or any readable region if you provide the correct address and length.");
      out.whyItMatters("Explicit live-memory searches let you confirm where controlled bytes landed without assuming they live in a module image or the current stack window.");

      return {
        command: "find_mem_bytes",
        args: options,
        success: true,
        findings: offsets.map((offset) => address + BigInt(offset)),
        warnings: [],
        errors: [],
        stats: {
          searchedBytes: length,
          results: offsets.length,
        },
      };
    },
  };
}
