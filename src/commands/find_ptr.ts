import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize } from "../core/memory";
import { scanPattern } from "../core/scan_engine";
import { normalizeByteArray } from "../core/validation";
import { applyFilters, badcharAddressFilter, encodeInstructionSearch } from "../logic/pointer_filter_logic";
import { findModuleByAddress } from "./modules";

function annotate(address: bigint, pointerSize: 4 | 8): string {
  const module = findModuleByAddress(address);
  if (!module) {
    return out.formatAddress(address, pointerSize);
  }
  return `${module.name}+0x${(address - module.base).toString(16).toUpperCase()}`;
}

function resolvePattern(options: Record<string, unknown>): number[] {
  if (typeof options.instruction === "string" && options.instruction.trim().length > 0) {
    const encoded = encodeInstructionSearch(options.instruction);
    if (!encoded) {
      throw new Error(`Unrecognized instruction search '${options.instruction}'. Use e.g. 'jmp esp', 'call eax', 'pushret esp'.`);
    }
    return encoded;
  }
  const bytes = (options.bytes as number[]) ?? [];
  if (bytes.length === 0 || bytes.some((value) => !Number.isInteger(value) || value < 0 || value > 0xff)) {
    throw new Error("Provide an 'instruction' (e.g. 'jmp esp') or a non-empty 'bytes' array of 0x00..0xFF integers.");
  }
  return bytes;
}

export function createFindPtrCommand(): Command {
  return {
    name: "find_ptr",
    description: "Search executable memory for an instruction or byte pattern and filter surviving pointers by bad characters.",
    usage: "dx @$osed().find_ptr(instruction, module?, badchars?, maxResults?, executableOnly?)",
    examples: [
      'dx @$osed().find_ptr("jmp esp")',
      'dx @$osed().find_ptr("call eax", "essfunc", "00 0A 0D")',
    ],
    schema: {
      instruction: { type: "string" },
      bytes: { type: "array", elementType: "number", default: [] },
      module: { type: "string" },
      executableOnly: { type: "boolean", default: true },
      badchars: { type: "array", elementType: "number", default: [] },
      maxResults: { type: "number", min: 1, max: 200, default: 20 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const pattern = resolvePattern(options);
      const normalizedExclude = normalizeByteArray((options.badchars as number[]) ?? []);
      const maxResults = options.maxResults as number;
      const executableOnly = options.executableOnly !== false;

      // Over-scan so the bad-character filter still has enough survivors to return.
      const scanCap = Math.min(Math.max(maxResults * 5, maxResults), 200);
      const scan = scanPattern(
        {
          module: options.module as string | undefined,
          executableOnly,
          maxResults: scanCap,
          chunkSize: 0x4000,
        },
        Uint8Array.from(pattern),
      );

      const filters = [badcharAddressFilter(normalizedExclude.values, pointerSize)];
      const outcome = applyFilters(scan.hits, filters);
      const kept = outcome.kept.slice(0, maxResults);

      out.section("Pointer Search");
      out.info(`Pattern: ${pattern.map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ")}`);
      out.info(`Hits: ${scan.hits.length} scanned, ${outcome.rejected.length} rejected by bad chars, ${outcome.kept.length} surviving.`);

      if (kept.length === 0) {
        out.warn("No pointers survived the filter stack.");
      } else {
        out.table(
          [
            { key: "address", header: "Address", width: 18 },
            { key: "location", header: "Location", width: 24 },
            { key: "python", header: "Python", width: 14 },
          ],
          kept.map((hit) => ({
            address: out.formatAddress(hit, pointerSize),
            location: annotate(hit, pointerSize),
            python: `0x${hit.toString(16).toUpperCase()}`,
          })),
        );
      }
      out.whyItMatters("Filtering pointers by bad characters up front prevents choosing an address the target will corrupt.");

      const warnings = scan.warnings.map((warning) => `${warning.region}: ${warning.message}`);
      if (normalizedExclude.warning) {
        warnings.push(normalizedExclude.warning);
      }

      return {
        command: "find_ptr",
        args: { ...options, badchars: normalizedExclude.values },
        success: true,
        findings: [
          {
            pattern,
            badchars: normalizedExclude.values,
            filters: filters.map((filter) => filter.name),
            scanned: scan.hits.length,
            rejected: outcome.rejected.length,
            surviving: kept,
          },
        ],
        warnings,
        errors: [],
        stats: scan.stats,
      };
    },
  };
}
