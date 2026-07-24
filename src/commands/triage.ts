import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize } from "../core/memory";
import { scanPattern } from "../core/scan_engine";
import { decodeOffsetNeedle, generateCyclicPattern, generateMsfPattern } from "../logic/pattern_logic";
import { LandingEvidence, landing } from "../analysis/landing";
import { readSehRecords, resolveTeb32Address } from "../analysis/seh";
import { findModuleByAddress, listModulesWithMitigations, ModuleMitigation } from "./modules";

export type RegisterSnapshot = {
  ip?: bigint;
  ipName?: string;
  sp?: bigint;
  spName?: string;
  exceptionCode?: bigint;
  all: Array<{ name: string; value: bigint }>;
};

type TriState = "yes" | "no" | "unknown";

export type IpControlEvidence = {
  patternMatched: boolean;
  ip?: bigint;
  ipBackedByModule?: boolean;
  exceptionCode?: bigint;
};

function safeGet(value: unknown, key: string): unknown {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  try {
    return (value as Record<string, unknown>)[key];
  } catch (_error) {
    return undefined;
  }
}

function safeKeys(value: unknown): string[] {
  if (!value || typeof value !== "object") {
    return [];
  }
  try {
    return Object.keys(value as Record<string, unknown>);
  } catch (_error) {
    return [];
  }
}

function toBigInt(value: unknown): bigint | undefined {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) {
    return BigInt(Math.trunc(value));
  }
  if (typeof value === "string") {
    const text = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(text)) {
      return BigInt(text);
    }
    if (/^[0-9a-fA-F]+$/.test(text)) {
      return BigInt(`0x${text}`);
    }
    if (/^[0-9]+$/.test(text)) {
      return BigInt(text);
    }
  }
  if (value && typeof value === "object") {
    const nested = ["value", "Value", "address", "Address", "targetLocation"];
    for (const key of nested) {
      const parsed = toBigInt(safeGet(value, key));
      if (parsed !== undefined) {
        return parsed;
      }
    }
    try {
      const valueOf = safeGet(value, "valueOf");
      if (typeof valueOf === "function") {
        const resolved = (valueOf as () => unknown).call(value);
        if (resolved !== value) {
          const parsed = toBigInt(resolved);
          if (parsed !== undefined) {
            return parsed;
          }
        }
      }
    } catch (_error) {
      // ignore
    }
    try {
      const asString = safeGet(value, "toString");
      if (typeof asString === "function") {
        const str = (asString as () => unknown).call(value);
        if (typeof str === "string" && str !== "[object Object]") {
          return toBigInt(str);
        }
      }
    } catch (_error) {
      // ignore
    }
  }
  return undefined;
}

function toArray(value: unknown): unknown[] {
  if (Array.isArray(value)) {
    return value;
  }
  if (value && typeof (value as { [Symbol.iterator]?: unknown })[Symbol.iterator] === "function") {
    try {
      return Array.from(value as Iterable<unknown>);
    } catch (_error) {
      return [];
    }
  }
  return [];
}

export function readRegisters(pointerSize: 4 | 8): RegisterSnapshot {
  const thread = host.currentThread as Record<string, unknown>;
  const regsRoot = safeGet(thread, "Registers");
  const userRegs = safeGet(regsRoot, "User") ?? regsRoot;

  const all: Array<{ name: string; value: bigint }> = [];
  for (const key of safeKeys(userRegs)) {
    const parsed = toBigInt(safeGet(userRegs, key));
    if (parsed !== undefined) {
      all.push({ name: key, value: parsed });
    }
  }

  const pick = (...names: string[]): { name: string; value: bigint } | undefined => {
    for (const candidate of names) {
      const found = all.find((entry) => entry.name.toLowerCase() === candidate.toLowerCase());
      if (found) {
        return found;
      }
    }
    return undefined;
  };

  const ip = pointerSize === 8 ? pick("rip", "eip") : pick("eip", "rip");
  const sp = pointerSize === 8 ? pick("rsp", "esp") : pick("esp", "rsp");
  const ex = pick("exceptioncode", "exception", "lastExceptionCode");

  return {
    ip: ip?.value,
    ipName: ip?.name,
    sp: sp?.value,
    spName: sp?.name,
    exceptionCode: ex?.value,
    all,
  };
}

function findOffset(raw: bigint | undefined, maxLen: number): { kind: "msf" | "cyclic"; offset: number } | undefined {
  if (raw === undefined) {
    return undefined;
  }

  const low = Number(raw & BigInt(0xffffffff));
  const candidates = [
    { kind: "msf" as const, haystack: generateMsfPattern(Math.min(maxLen, 20280)) },
    { kind: "cyclic" as const, haystack: generateCyclicPattern(Math.max(maxLen, 20000)) },
  ];

  for (const candidate of candidates) {
    const needle = decodeOffsetNeedle(low);
    const offset = candidate.haystack.indexOf(needle);
    if (offset >= 0) {
      return { kind: candidate.kind, offset };
    }
  }

  return undefined;
}

export function isInstructionPointerControlled(evidence: IpControlEvidence): boolean {
  if (evidence.patternMatched) {
    return true;
  }

  if (evidence.ip === undefined) {
    return false;
  }

  if (evidence.exceptionCode === BigInt(0xc0000005)) {
    return true;
  }

  return evidence.ipBackedByModule === false;
}

export function landingCandidateAddresses(evidence: LandingEvidence): bigint[] {
  const candidateKinds = new Set(["nop_sled_detected", "payload_like_bytes"]);
  const addresses = evidence.observations
    .filter((item) => candidateKinds.has(item.kind) && item.address !== undefined)
    .map((item) => item.address!);
  return [...new Set(addresses.map(String))]
    .map(BigInt)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
    .slice(0, 5);
}

function scoreModule(module: ModuleMitigation): number {
  let score = 0;
  if (!module.system) score += 25;
  if (module.aslr === "disabled") score += 35;
  if (module.dep === "disabled") score += 10;
  if (module.safeseh === "disabled") score += 30;
  return score;
}

function scanGadgets(pointerSize: 4 | 8, moduleFilter?: string): { jmp: string[]; call: string[]; ppr: string[]; pivots: string[] } {
  const fmt = (address: bigint): string => {
    const mod = findModuleByAddress(address);
    if (!mod) {
      return out.formatAddress(address, getPointerSize());
    }
    const delta = address - mod.base;
    return `${mod.name}+0x${delta.toString(16).toUpperCase()}`;
  };

  const jmpHits = scanPattern({ module: moduleFilter, executableOnly: true, maxResults: 12, chunkSize: 0x4000 }, Uint8Array.from([0xff, 0xe4])).hits;
  const callHits = scanPattern({ module: moduleFilter, executableOnly: true, maxResults: 12, chunkSize: 0x4000 }, Uint8Array.from([0xff, 0xd4])).hits;

  const pprHits: bigint[] = [];
  if (pointerSize === 4) {
    for (let a = 0x58; a <= 0x5f && pprHits.length < 12; a += 1) {
      for (let b = 0x58; b <= 0x5f && pprHits.length < 12; b += 1) {
        const hits = scanPattern(
          { module: moduleFilter, executableOnly: true, maxResults: Math.max(0, 12 - pprHits.length), chunkSize: 0x4000 },
          Uint8Array.from([a, b, 0xc3]),
        ).hits;
        pprHits.push(...hits);
      }
    }
  }

  const pivotPatterns = pointerSize === 8
    ? [
        Uint8Array.from([0x48, 0x94, 0xc3]),
        Uint8Array.from([0x54, 0xc3]),
        Uint8Array.from([0x48, 0x89, 0xec, 0xc3]),
        Uint8Array.from([0x48, 0x89, 0xc4, 0xc3]),
      ]
    : [Uint8Array.from([0x94, 0xc3]), Uint8Array.from([0x54, 0xc3]), Uint8Array.from([0x8b, 0xe5, 0xc3])];
  const pivotHits: bigint[] = [];
  for (const pattern of pivotPatterns) {
    const hits = scanPattern(
      { module: moduleFilter, executableOnly: true, maxResults: Math.max(0, 12 - pivotHits.length), chunkSize: 0x4000 },
      pattern,
    ).hits;
    pivotHits.push(...hits);
    if (pivotHits.length >= 12) {
      break;
    }
  }

  const uniq = (values: bigint[]) => [...new Set(values.map((v) => v.toString()))].map((v) => BigInt(v));

  return {
    jmp: uniq(jmpHits).slice(0, 5).map(fmt),
    call: uniq(callHits).slice(0, 5).map(fmt),
    ppr: uniq(pprHits).slice(0, 5).map(fmt),
    pivots: uniq(pivotHits).slice(0, 5).map(fmt),
  };
}

function readSehPreview(pointerSize: 4 | 8): { overwritten: TriState; next?: bigint; handler?: bigint; warning?: string } {
  if (pointerSize !== 4) {
    return { overwritten: "unknown", warning: "SEH overwrite analysis is x86-only." };
  }

  const tebCandidate = resolveTeb32Address(host.currentThread as Record<string, unknown>);
  if (!tebCandidate) {
    return { overwritten: "unknown", warning: "TEB unavailable for SEH walk." };
  }

  try {
    const first = readSehRecords(tebCandidate, 1)[0];
    if (!first) {
      return { overwritten: "no", warning: "SEH chain is empty." };
    }
    const { next, handler } = first;
    const mod = findModuleByAddress(handler);
    const overwritten: TriState = mod ? "no" : "yes";
    return { overwritten, next, handler };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return { overwritten: "unknown", warning: `SEH read failed: ${msg}` };
  }
}

function quickBadcharScan(bytes: Uint8Array | undefined, badchars: number[]): Array<{ byte: number; count: number; first?: number }> {
  if (!bytes) {
    return [];
  }

  return badchars.map((byte) => {
    let count = 0;
    let first: number | undefined;
    for (let i = 0; i < bytes.length; i += 1) {
      if (bytes[i] === byte) {
        count += 1;
        if (first === undefined) {
          first = i;
        }
      }
    }
    return { byte, count, first };
  });
}

export function createTriageCommand(): Command {
  return {
    name: "triage",
    description: "Fast crash triage for exploit-development workflows.",
    usage: "dx @$osed().triage(patternLength?, badchars?, module?, stackBytes?)",
    examples: ["dx @$osed().triage()", 'dx @$osed().triage(10000, "00 0A 0D", "vulnserver")'],
    schema: {
      patternLength: { type: "number", min: 256, max: 100000, default: 10000 },
      badchars: { type: "array", elementType: "number", default: [0, 10, 13] },
      module: { type: "string" },
      stackBytes: { type: "number", min: 128, max: 4096, default: 1024 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const regs = readRegisters(pointerSize);
      const patternLength = options.patternLength as number;
      const stackBytesToRead = options.stackBytes as number;
      const badchars = ((options.badchars as number[]) ?? [0, 10, 13]).map((v) => v & 0xff);
      const moduleFilter = options.module as string | undefined;

      const patternOffset = findOffset(regs.ip, patternLength);
      const seh = readSehPreview(pointerSize);
      const landingEvidence = landing(regs.sp, stackBytesToRead);
      const stackBytes = landingEvidence.bytes.length > 0 ? Uint8Array.from(landingEvidence.bytes) : undefined;
      const shellcode = landingCandidateAddresses(landingEvidence);
      const badcharStats = quickBadcharScan(stackBytes, badchars);

      const modules = listModulesWithMitigations(moduleFilter)
        .map((module) => ({
          module: module.name,
          score: scoreModule(module),
          aslr: module.aslr,
          dep: module.dep,
          safeseh: module.safeseh,
          system: module.system,
        }))
        .sort((a, b) => b.score - a.score)
        .slice(0, 6);

      const gadgets = scanGadgets(pointerSize, moduleFilter);

      const ipBackedByModule = regs.ip !== undefined ? findModuleByAddress(regs.ip) !== undefined : undefined;
      const eipControlled = isInstructionPointerControlled({
        patternMatched: patternOffset !== undefined,
        ip: regs.ip,
        ipBackedByModule,
        exceptionCode: regs.exceptionCode,
      })
        ? "yes"
        : "no";
      const badSp = stackBytes ? "no" : "yes";

      out.section("CONTROL");
      out.print(`${pointerSize === 8 ? "RIP" : "EIP"} controlled: ${eipControlled}`);
      out.print(`Offset: ${patternOffset ? patternOffset.offset : "n/a"}`);
      out.print(`Pattern: ${patternOffset ? patternOffset.kind : "n/a"}`);

      out.section("SEH");
      if (pointerSize === 8) {
        out.print("Not applicable: classic SEH overwrite workflow is x86-only.");
      } else {
        out.print(`Overwritten: ${seh.overwritten}`);
        out.print(`Next SEH: ${seh.next !== undefined ? out.formatAddress(seh.next, 4) : "n/a"}`);
        out.print(`Handler: ${seh.handler !== undefined ? out.formatAddress(seh.handler, 4) : "n/a"}`);
        if (seh.warning) out.print(`Status: ${seh.warning}`);
      }

      out.section("STACK");
      out.print(`${regs.spName ?? "SP"}: ${regs.sp !== undefined ? out.formatAddress(regs.sp, pointerSize) : "n/a"}`);
      out.print(`Bad stack pointer: ${badSp}`);
      out.print(`SP points into cyclic pattern: ${stackBytes && regs.sp ? (findOffset(regs.sp, patternLength) ? "yes" : "no") : "unknown"}`);
      if (shellcode.length > 0) {
        out.print("Shellcode candidates:");
        for (const candidate of shellcode) {
          out.print(`  ${out.formatAddress(candidate, pointerSize)}`);
        }
      } else {
        out.print("Shellcode candidates: none");
      }

      out.section("GADGETS");
      out.print(pointerSize === 8 ? "JMP RSP:" : "JMP ESP:");
      for (const line of gadgets.jmp) out.print(`  ${line}`);
      out.print(pointerSize === 8 ? "CALL RSP:" : "CALL ESP:");
      for (const line of gadgets.call) out.print(`  ${line}`);
      if (pointerSize === 4) {
        out.print("POP POP RET:");
        for (const line of gadgets.ppr) out.print(`  ${line}`);
      }
      out.print("Stack pivots:");
      for (const line of gadgets.pivots) out.print(`  ${line}`);

      out.section("CONTEXT");
      out.print(`Exception code: ${regs.exceptionCode !== undefined ? out.formatAddress(regs.exceptionCode, 4) : "n/a"}`);
      out.print(`${regs.ipName ?? "IP"}: ${regs.ip !== undefined ? out.formatAddress(regs.ip, pointerSize) : "n/a"}`);

      out.section("MODULE SCORE");
      out.table(
        [
          { key: "module", header: "Module", width: 20 },
          { key: "score", header: "Score", width: 6 },
          { key: "aslr", header: "ASLR", width: 8 },
          { key: "dep", header: "DEP", width: 8 },
          { key: "safeseh", header: "SafeSEH", width: 8 },
          { key: "system", header: "System", width: 8 },
        ],
        modules.map((item) => ({
          module: item.module,
          score: `${item.score}`,
          aslr: item.aslr,
          dep: item.dep,
          safeseh: item.safeseh,
          system: item.system ? "yes" : "no",
        })),
      );

      out.section("BADCHAR QUICK SCAN");
      out.table(
        [
          { key: "byte", header: "Byte", width: 8 },
          { key: "count", header: "Count", width: 6 },
          { key: "first", header: "FirstOff", width: 8 },
        ],
        badcharStats.map((entry) => ({
          byte: out.formatHexByte(entry.byte),
          count: `${entry.count}`,
          first: entry.first !== undefined ? `${entry.first}` : "n/a",
        })),
      );

      const warnings: string[] = [];
      warnings.push(...(landingEvidence.memory?.warnings ?? []));
      if (landingEvidence.address === undefined) warnings.push(landingEvidence.recommendation);
      else if (landingEvidence.observations.some((item) => item.kind === "bytes_inaccessible")) warnings.push("Stack read failed: landing bytes are inaccessible.");
      else if (landingEvidence.observations.some((item) => item.kind === "bytes_truncated")) warnings.push("Stack read was truncated before the requested length.");
      if (seh.warning) warnings.push(seh.warning);

      const findings = [
        {
          control: {
            ipControlled: eipControlled === "yes",
            offset: patternOffset?.offset,
            pattern: patternOffset?.kind,
            ip: regs.ip,
            ipName: regs.ipName,
          },
          seh,
          stack: {
            sp: regs.sp,
            spName: regs.spName,
            badPointer: badSp === "yes",
            shellcodeCandidates: shellcode,
            landing: landingEvidence,
          },
          gadgets,
          modules,
          badchars: badcharStats,
          exception: regs.exceptionCode,
        },
      ];

      return {
        command: "triage",
        args: options,
        success: true,
        findings,
        warnings,
        errors: [],
      };
    },
  };
}
