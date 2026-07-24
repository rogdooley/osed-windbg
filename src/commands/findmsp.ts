import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, tryReadMemory } from "../core/memory";
import { readRegisters } from "./triage";
import {
  buildHaystacks,
  dwordAt,
  locatePatternInBuffer,
  matchRegisterValue,
} from "../logic/pattern_scan_logic";
import { readSehRecords, resolveTeb32Address } from "../analysis/seh";

type FindMatch = {
  source: string;
  type: "register" | "pointer" | "stack" | "seh";
  kind: "msf" | "cyclic";
  offset: number;
  confidence: "EXACT" | "CONSERVATIVE";
  detail: string;
};

// Registers whose value is too small to be a memory pointer are not dereferenced.
const MIN_POINTER = BigInt(0x10000);
const MAX_STACK_MATCHES = 100;

function low32(value: bigint): number {
  return Number(value & BigInt(0xffffffff)) >>> 0;
}

function scanRegisters(
  regs: ReturnType<typeof readRegisters>,
  haystacks: ReturnType<typeof buildHaystacks>,
  probeBytes: number,
): FindMatch[] {
  const matches: FindMatch[] = [];
  for (const register of regs.all) {
    const direct = matchRegisterValue(low32(register.value), haystacks);
    if (direct) {
      matches.push({
        source: register.name.toLowerCase(),
        type: "register",
        kind: direct.kind,
        offset: direct.offset,
        confidence: direct.confidence,
        detail: "register overwritten with pattern bytes",
      });
      continue;
    }
    if (register.value < MIN_POINTER) {
      continue;
    }
    const buffer = tryReadMemory(register.value, probeBytes);
    if (!buffer) {
      continue;
    }
    const located = locatePatternInBuffer(buffer, haystacks);
    if (located) {
      matches.push({
        source: register.name.toLowerCase(),
        type: "pointer",
        kind: located.kind,
        offset: located.offset,
        confidence: located.confidence,
        detail: `points into pattern (${located.length} contiguous bytes readable)`,
      });
    }
  }
  return matches;
}

function scanStack(
  regs: ReturnType<typeof readRegisters>,
  haystacks: ReturnType<typeof buildHaystacks>,
  stackBytes: number,
): { matches: FindMatch[]; truncated: boolean; readable: boolean } {
  if (regs.sp === undefined) {
    return { matches: [], truncated: false, readable: false };
  }
  const buffer = tryReadMemory(regs.sp, stackBytes);
  if (!buffer) {
    return { matches: [], truncated: false, readable: false };
  }
  const label = (regs.spName ?? "sp").toLowerCase();
  const matches: FindMatch[] = [];
  let truncated = false;
  // Stack slots are pointer-granular, so walk dword-aligned positions from SP.
  for (let index = 0; index + 4 <= buffer.length; index += 4) {
    const value = dwordAt(buffer, index);
    if (value === undefined) {
      continue;
    }
    const match = matchRegisterValue(value, haystacks);
    if (!match) {
      continue;
    }
    if (matches.length >= MAX_STACK_MATCHES) {
      truncated = true;
      break;
    }
    matches.push({
      source: `${label}+0x${index.toString(16)}`,
      type: "stack",
      kind: match.kind,
      offset: match.offset,
      confidence: match.confidence,
      detail: "stack slot holds pattern bytes",
    });
  }
  return { matches, truncated, readable: true };
}

function scanSeh(pointerSize: 4 | 8, haystacks: ReturnType<typeof buildHaystacks>): { matches: FindMatch[]; warning?: string } {
  if (pointerSize !== 4) {
    return { matches: [] };
  }
  const teb = resolveTeb32Address(host.currentThread as Record<string, unknown>);
  if (!teb) {
    return { matches: [], warning: "TEB unavailable for SEH walk." };
  }
  try {
    const records = readSehRecords(teb, 3);
    const matches: FindMatch[] = [];
    records.forEach((record, index) => {
      const fields: Array<{ name: "next" | "handler"; value: bigint }> = [
        { name: "next", value: record.next },
        { name: "handler", value: record.handler },
      ];
      for (const field of fields) {
        const match = matchRegisterValue(low32(field.value), haystacks);
        if (match) {
          matches.push({
            source: `seh[${index}].${field.name}`,
            type: "seh",
            kind: match.kind,
            offset: match.offset,
            confidence: match.confidence,
            detail: "SEH record field holds pattern bytes",
          });
        }
      }
    });
    return { matches };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { matches: [], warning: `SEH read failed: ${message}` };
  }
}

export function createFindMspCommand(): Command {
  return {
    name: "findmsp",
    description: "Comprehensive cyclic-pattern offset scan across registers, the stack, SEH, and pointer targets.",
    usage: "dx @$osed().findmsp(patternLength?, stackBytes?, probeBytes?)",
    examples: ["dx @$osed().findmsp()", "dx @$osed().findmsp(20000, 4096)"],
    schema: {
      patternLength: { type: "number", min: 256, max: 100000, default: 10000 },
      stackBytes: { type: "number", min: 128, max: 8192, default: 2048 },
      probeBytes: { type: "number", min: 8, max: 256, default: 32 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const patternLength = options.patternLength as number;
      const stackBytes = options.stackBytes as number;
      const probeBytes = options.probeBytes as number;

      const haystacks = buildHaystacks(patternLength);
      const regs = readRegisters(pointerSize);

      const registerMatches = scanRegisters(regs, haystacks, probeBytes);
      const stack = scanStack(regs, haystacks, stackBytes);
      const seh = scanSeh(pointerSize, haystacks);

      const matches = [...registerMatches, ...stack.matches, ...seh.matches];

      const ipName = (regs.ipName ?? (pointerSize === 8 ? "rip" : "eip")).toLowerCase();
      const ipMatch = registerMatches.find((match) => match.source === ipName && match.type === "register");

      out.section("INSTRUCTION POINTER");
      if (ipMatch) {
        out.print(`${ipName.toUpperCase()} overwritten at pattern offset ${ipMatch.offset} (${ipMatch.kind}, ${ipMatch.confidence}).`);
      } else {
        out.print(`${ipName.toUpperCase()} does not hold cyclic-pattern bytes.`);
      }

      out.section("PATTERN MATCHES");
      if (matches.length === 0) {
        out.print("No cyclic-pattern evidence found in registers, stack, SEH, or pointer targets.");
      } else {
        out.table(
          [
            { key: "source", header: "Source", width: 16 },
            { key: "type", header: "Where", width: 10 },
            { key: "offset", header: "Offset", width: 8 },
            { key: "kind", header: "Pattern", width: 8 },
            { key: "confidence", header: "Conf", width: 12 },
            { key: "detail", header: "Detail" },
          ],
          matches.map((match) => ({
            source: match.source,
            type: match.type,
            offset: `${match.offset}`,
            kind: match.kind,
            confidence: match.confidence,
            detail: match.detail,
          })),
        );
      }

      const warnings: string[] = [];
      if (!stack.readable) {
        warnings.push("Stack pointer memory was not readable; stack scan skipped.");
      } else if (stack.truncated) {
        warnings.push(`Stack scan stopped after ${MAX_STACK_MATCHES} matches; increase specificity or reduce stackBytes.`);
      }
      if (seh.warning) {
        warnings.push(seh.warning);
      }

      return {
        command: "findmsp",
        args: options,
        success: true,
        findings: [
          {
            pointerSize,
            instructionPointer: {
              register: ipName,
              value: regs.ip,
              matched: ipMatch !== undefined,
              offset: ipMatch?.offset,
              pattern: ipMatch?.kind,
              confidence: ipMatch?.confidence,
            },
            matches,
            counts: {
              register: registerMatches.filter((match) => match.type === "register").length,
              pointer: registerMatches.filter((match) => match.type === "pointer").length,
              stack: stack.matches.length,
              seh: seh.matches.length,
            },
          },
        ],
        warnings,
        errors: [],
      };
    },
  };
}
