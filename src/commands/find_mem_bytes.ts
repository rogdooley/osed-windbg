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

type ScanOutcome = {
  hits: bigint[];
  warnings: string[];
  scannedBytes: number;
};

function readLargestWindow(start: bigint, maxLength: number): Uint8Array | undefined {
  let low = 1;
  let high = maxLength;
  let best: Uint8Array | undefined;

  while (low <= high) {
    const mid = low + Math.floor((high - low) / 2);
    try {
      const chunk = readMemory(start, mid);
      best = chunk;
      low = mid + 1;
    } catch (_error) {
      high = mid - 1;
    }
  }

  return best;
}

function scanReadableRange(start: bigint, length: number, pattern: Uint8Array, maxResults: number): ScanOutcome {
  const hits: bigint[] = [];
  const warnings: string[] = [];
  const chunkSize = 0x1000;
  const skipSize = 0x1000;
  let offset = 0;
  let scannedBytes = 0;
  let previousTail = new Uint8Array(0);
  let previousTailStart = start;

  while (offset < length && hits.length < maxResults) {
    const current = start + BigInt(offset);
    const remaining = length - offset;
    const requested = Math.min(chunkSize, remaining);
    let chunk: Uint8Array | undefined;
    try {
      chunk = readMemory(current, requested);
    } catch (_error) {
      chunk = readLargestWindow(current, requested);
      if (!chunk) {
        warnings.push(`Skipped unreadable range at ${out.formatAddress(current, getPointerSize())}.`);
        previousTail = new Uint8Array(0);
        offset += Math.min(skipSize, remaining);
        continue;
      }
      warnings.push(
        `Range at ${out.formatAddress(current, getPointerSize())} was only partially readable; scanned ${chunk.length} byte(s).`,
      );
    }

    scannedBytes += chunk.length;
    const combined = new Uint8Array(previousTail.length + chunk.length);
    combined.set(previousTail, 0);
    combined.set(chunk, previousTail.length);
    const combinedBase = previousTailStart;
    const offsets = findPattern(combined, pattern, maxResults - hits.length);
    for (const matchOffset of offsets) {
      const address = combinedBase + BigInt(matchOffset);
      if (address >= current) {
        hits.push(address);
      }
    }

    const tailLength = Math.min(pattern.length - 1, chunk.length);
    previousTail = tailLength > 0 ? chunk.slice(chunk.length - tailLength) : new Uint8Array(0);
    previousTailStart = current + BigInt(chunk.length - tailLength);
    offset += chunk.length;
  }

  return { hits, warnings, scannedBytes };
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
      const pattern = Uint8Array.from(bytes);
      const scan = scanReadableRange(address, length, pattern, options.maxResults as number);

      out.section("Find Memory Bytes");
      out.info(`Start: ${out.formatAddress(address, pointerSize)}`);
      out.info(`Length: 0x${length.toString(16).toUpperCase()} (${length}) byte(s)`);
      out.table(
        [
          { key: "address", header: "Address", width: 18 },
          { key: "offset", header: "Base+Offset", width: 12 },
        ],
        scan.hits.map((hit) => ({
          address: out.formatAddress(hit, pointerSize),
          offset: `0x${(hit - address).toString(16).toUpperCase()}`,
        })),
      );
      out.info(`Scanned ${scan.scannedBytes} readable byte(s) in the requested range.`);
      for (const warning of scan.warnings) {
        out.warn(warning);
      }
      if (scan.hits.length === 0) {
        out.info("No byte matches found in the searched memory range.");
      }
      out.info("Scope: explicit live-memory range only; this can search stack, heap, modules, or any readable region if you provide the correct address and length.");
      out.whyItMatters("Explicit live-memory searches let you confirm where controlled bytes landed without assuming they live in a module image or the current stack window.");

      return {
        command: "find_mem_bytes",
        args: options,
        success: true,
        findings: scan.hits,
        warnings: scan.warnings,
        errors: [],
        stats: {
          searchedBytes: length,
          readableBytes: scan.scannedBytes,
          results: scan.hits.length,
        },
      };
    },
  };
}
