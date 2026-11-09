// Cave-byte heuristics (0x00, 0xCC, 0x90) and section-alignment scanning
// inspired by nop-tech/codecaver: https://github.com/nop-tech/codecaver

import { Command, CommandResult } from "../core/registry";
import { forEachSection, ModuleSection } from "../core/scan_engine";
import { tryReadMemory, getPointerSize, readUint16LE, readUint32LE } from "../core/memory";
import { memoryRegion } from "../analysis/memory";
import * as out from "../core/output";

export type CavePattern = "NULL" | "INT3" | "NOP" | "PADDING";
export type CaveCapability = "EXEC" | "STAGING" | "ROP_WORKSPACE" | "RWX" | "READ_ONLY" | "UNUSABLE";

export type CodeCave = {
  address: bigint;
  size: number;
  pattern: CavePattern;
  module: string;
  modulePath: string;
  moduleBase: bigint;
  section: string;
  sectionExecutable: boolean;
  rva: number;
  aslr: "enabled" | "disabled" | "unknown";
  readable: boolean | null;
  writable: boolean | null;
  executable: boolean | null;
  capabilities: CaveCapability[];
  addrSafe: boolean | null;
  badBytes: number[];
  safeOffset: number | null;
  safeVa: bigint | null;
};

const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040;
const ROP_WORKSPACE_MIN_BYTES = 128;

function classifyRun(nullCount: number, int3Count: number, nopCount: number): CavePattern {
  const total = nullCount + int3Count + nopCount;
  if (total === nullCount) return "NULL";
  if (total === int3Count) return "INT3";
  if (total === nopCount) return "NOP";
  return "PADDING";
}

function isCaveByte(byte: number): boolean {
  return byte === 0x00 || byte === 0xcc || byte === 0x90;
}

function alignUp(value: number, alignment: number): number {
  if (alignment <= 0) return value;
  return Math.ceil(value / alignment) * alignment;
}

function readSectionAlignment(moduleBase: bigint): number {
  try {
    const mz = readUint16LE(moduleBase);
    if (mz !== 0x5a4d) return 0;
    const peOffset = readUint32LE(moduleBase + BigInt(0x3c));
    const pe = moduleBase + BigInt(peOffset);
    if (readUint32LE(pe) !== 0x4550) return 0;
    return readUint32LE(pe + BigInt(0x38));
  } catch {
    return 0;
  }
}

function readModuleAslr(moduleBase: bigint): "enabled" | "disabled" | "unknown" {
  try {
    const mz = readUint16LE(moduleBase);
    if (mz !== 0x5a4d) return "unknown";
    const peOffset = readUint32LE(moduleBase + BigInt(0x3c));
    const pe = moduleBase + BigInt(peOffset);
    if (readUint32LE(pe) !== 0x4550) return "unknown";
    const dllChars = readUint16LE(pe + BigInt(0x5e));
    return (dllChars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) !== 0 ? "enabled" : "disabled";
  } catch {
    return "unknown";
  }
}

function computeEffectiveSizes(sections: ModuleSection[]): number[] {
  if (sections.length === 0) return [];

  const grouped = new Map<string, ModuleSection[]>();
  for (const section of sections) {
    const key = `${section.module.base.toString(16)}`;
    const list = grouped.get(key) ?? [];
    list.push(section);
    grouped.set(key, list);
  }

  const effectiveSizes: number[] = new Array(sections.length);

  for (const moduleSections of grouped.values()) {
    const moduleBase = moduleSections[0].module.base;
    const moduleEnd = moduleBase + moduleSections[0].module.size;
    const sectionAlignment = readSectionAlignment(moduleBase);

    const sorted = [...moduleSections].sort((a, b) => (a.start < b.start ? -1 : 1));

    for (let i = 0; i < sorted.length; i++) {
      const section = sorted[i];
      const idx = sections.indexOf(section);

      if (sectionAlignment > 0) {
        const alignedSize = alignUp(section.size, sectionAlignment);
        const nextStart = i + 1 < sorted.length ? sorted[i + 1].start : moduleEnd;
        const maxSize = Number(nextStart - section.start);
        effectiveSizes[idx] = Math.min(alignedSize, maxSize > 0 ? maxSize : alignedSize);
      } else {
        effectiveSizes[idx] = section.size;
      }
    }
  }

  return effectiveSizes;
}

function scanForCaves(
  section: ModuleSection,
  scanSize: number,
  minSize: number,
  chunkSize: number,
): CodeCave[] {
  const caves: CodeCave[] = [];
  let runStart: bigint | undefined;
  let runLength = 0;
  let nullCount = 0;
  let int3Count = 0;
  let nopCount = 0;
  const moduleName = section.module.name.replace(/^.*[\\\/]/, "");

  const flush = (): void => {
    if (runStart !== undefined && runLength >= minSize) {
      caves.push({
        address: runStart,
        size: runLength,
        pattern: classifyRun(nullCount, int3Count, nopCount),
        module: moduleName,
        modulePath: section.module.path,
        moduleBase: section.module.base,
        section: section.name,
        sectionExecutable: section.executable,
        rva: Number(runStart - section.module.base),
        aslr: "unknown",
        readable: null,
        writable: null,
        executable: null,
        capabilities: [],
        addrSafe: null,
        badBytes: [],
        safeOffset: null,
        safeVa: null,
      });
    }
    runStart = undefined;
    runLength = 0;
    nullCount = 0;
    int3Count = 0;
    nopCount = 0;
  };

  for (let offset = 0; offset < scanSize; offset += chunkSize) {
    const chunkStart = section.start + BigInt(offset);
    const remaining = scanSize - offset;
    const size = Math.min(remaining, chunkSize);
    const bytes = tryReadMemory(chunkStart, size);
    if (!bytes) {
      flush();
      continue;
    }

    for (let i = 0; i < bytes.length; i++) {
      if (isCaveByte(bytes[i])) {
        if (runStart === undefined) {
          runStart = chunkStart + BigInt(i);
        }
        runLength++;
        if (bytes[i] === 0x00) nullCount++;
        else if (bytes[i] === 0xcc) int3Count++;
        else nopCount++;
      } else {
        flush();
      }
    }
  }

  flush();
  return caves;
}

export function classifyCapabilities(
  readable: boolean | null,
  writable: boolean | null,
  executable: boolean | null,
  size: number,
): CaveCapability[] {
  const r = readable === true;
  const w = writable === true;
  const x = executable === true;

  if (!r && !w && !x) return ["UNUSABLE"];

  const caps: CaveCapability[] = [];
  if (r && w && x) caps.push("RWX");
  if (x && !(r && w && x)) caps.push("EXEC");
  if (w) {
    caps.push("STAGING");
    if (size >= ROP_WORKSPACE_MIN_BYTES) caps.push("ROP_WORKSPACE");
  }
  if (r && !w && !x) caps.push("READ_ONLY");

  return caps.length > 0 ? caps : ["UNUSABLE"];
}

function displayCapabilities(caps: CaveCapability[]): string {
  if (caps.includes("RWX")) return "RWX";
  if (caps.includes("UNUSABLE")) return "UNUSABLE";
  if (caps.includes("READ_ONLY")) return "READ_ONLY";

  const parts: string[] = [];
  if (caps.includes("EXEC")) parts.push("EXEC");
  if (caps.includes("STAGING")) parts.push("STAGING");
  if (caps.includes("ROP_WORKSPACE")) parts.push("ROP");
  return parts.join(",");
}

function protectionLabel(r: boolean | null, w: boolean | null, x: boolean | null): string {
  if (r === null && w === null && x === null) return "?";
  const parts: string[] = [];
  if (r) parts.push("R");
  if (w) parts.push("W");
  if (x) parts.push("X");
  return parts.length > 0 ? parts.join("") : "-";
}

function enrichAndSplit(caves: CodeCave[], minSize: number): CodeCave[] {
  const result: CodeCave[] = [];

  for (const cave of caves) {
    let pos = cave.address;
    const end = cave.address + BigInt(cave.size);

    while (pos < end) {
      const region = memoryRegion(pos);
      let segEnd: bigint;

      if (region.baseAddress !== undefined && region.regionSize !== undefined && region.regionSize > BigInt(0)
          && region.baseAddress <= pos && (region.baseAddress + region.regionSize) > pos) {
        segEnd = region.baseAddress + region.regionSize;
        if (segEnd > end) segEnd = end;
      } else {
        segEnd = end;
      }

      const segSize = Number(segEnd - pos);
      if (segSize >= minSize) {
        let r = region.readable;
        let w = region.writable;
        let x = region.executable;
        if (region.guarded === true || region.noAccess === true || (region.committed !== null && !region.committed)) {
          r = false;
          w = false;
          x = false;
        }

        const offsetFromOriginal = Number(pos - cave.address);
        result.push({
          ...cave,
          address: pos,
          size: segSize,
          rva: cave.rva + offsetFromOriginal,
          readable: r,
          writable: w,
          executable: x,
          capabilities: classifyCapabilities(r, w, x, segSize),
        });
      }

      pos = segEnd;
    }
  }

  return result;
}

export function parseBadChars(input: string): Set<number> {
  const chars = new Set<number>();
  const tokens = input.trim().split(/[\s,]+/);
  for (const token of tokens) {
    if (token.length === 0) continue;
    const value = parseInt(token, 16);
    if (!isNaN(value) && value >= 0 && value <= 0xff) {
      chars.add(value);
    }
  }
  return chars;
}

export function addressBadBytes(address: bigint, pointerSize: number, badChars: Set<number>): number[] {
  const bad: number[] = [];
  let addr = address;
  for (let i = 0; i < pointerSize; i++) {
    const byte = Number(addr & BigInt(0xff));
    if (badChars.has(byte)) bad.push(byte);
    addr >>= BigInt(8);
  }
  return [...new Set(bad)];
}

export function findSafeOffset(
  caveAddress: bigint,
  caveSize: number,
  pointerSize: number,
  badChars: Set<number>,
): { offset: number; va: bigint } | null {
  for (let delta = 0; delta < caveSize; delta++) {
    const addr = caveAddress + BigInt(delta);
    if (addressBadBytes(addr, pointerSize, badChars).length === 0) {
      return { offset: delta, va: addr };
    }
  }
  return null;
}

function rankCaves(caves: CodeCave[]): CodeCave[] {
  return [...caves].sort((a, b) => {
    const aslrRank = (c: CodeCave): number =>
      c.aslr === "disabled" ? 0 : c.aslr === "unknown" ? 1 : 2;
    const aslrDiff = aslrRank(a) - aslrRank(b);
    if (aslrDiff !== 0) return aslrDiff;

    if (a.addrSafe !== null && b.addrSafe !== null) {
      const safeDiff = (a.addrSafe ? 0 : 1) - (b.addrSafe ? 0 : 1);
      if (safeDiff !== 0) return safeDiff;
    }

    const usability = (c: CodeCave): number => {
      if (c.capabilities.includes("UNUSABLE")) return 2;
      if (c.capabilities.includes("READ_ONLY")) return 1;
      return 0;
    };
    const useDiff = usability(a) - usability(b);
    if (useDiff !== 0) return useDiff;

    return b.size - a.size;
  });
}

export function findCodeCaves(
  module: string | undefined,
  minSize: number,
  maxResults: number,
  badChars?: string,
  capability?: string,
): { caves: CodeCave[]; warnings: string[] } {
  const scope = forEachSection({
    module,
    executableOnly: false,
    maxResults: 200,
    chunkSize: 0x1000,
  });

  const effectiveSizes = computeEffectiveSizes(scope.sections);

  let pointerSize: number;
  try {
    pointerSize = getPointerSize();
  } catch {
    pointerSize = 4;
  }

  const rawCaves: CodeCave[] = [];
  for (let s = 0; s < scope.sections.length; s++) {
    const section = scope.sections[s];
    const scanSize = effectiveSizes[s];
    const found = scanForCaves(section, scanSize, minSize, 0x1000);
    for (const cave of found) {
      rawCaves.push(cave);
    }
  }

  let caves = enrichAndSplit(rawCaves, minSize);

  const aslrCache = new Map<string, "enabled" | "disabled" | "unknown">();
  for (const cave of caves) {
    const key = cave.moduleBase.toString(16);
    let aslr = aslrCache.get(key);
    if (aslr === undefined) {
      aslr = readModuleAslr(cave.moduleBase);
      aslrCache.set(key, aslr);
    }
    cave.aslr = aslr;
  }

  if (capability) {
    const cap = capability.toUpperCase();
    caves = caves.filter((c) => c.capabilities.includes(cap as CaveCapability));
  }

  if (badChars && badChars.trim().length > 0) {
    const badSet = parseBadChars(badChars);
    if (badSet.size > 0) {
      for (const cave of caves) {
        const bad = addressBadBytes(cave.address, pointerSize, badSet);
        cave.addrSafe = bad.length === 0;
        cave.badBytes = bad;
        if (!cave.addrSafe) {
          const safe = findSafeOffset(cave.address, cave.size, pointerSize, badSet);
          if (safe) {
            cave.safeOffset = safe.offset;
            cave.safeVa = safe.va;
          }
        }
      }
    }
  }

  caves = rankCaves(caves);
  caves = caves.slice(0, maxResults);

  return { caves, warnings: scope.warnings };
}

export function createCodeCavesCommand(): Command {
  return {
    name: "code_caves",
    description:
      "Find contiguous null/int3/nop padding regions in PE sections suitable for shellcode placement. Inspired by nop-tech/codecaver (https://github.com/nop-tech/codecaver).",
    usage: "dx @$osed().code_caves(module?, minSize?, maxResults?, badChars?, capability?)",
    examples: [
      "dx @$osed().code_caves()",
      'dx @$osed().code_caves("vulnserver")',
      'dx @$osed().code_caves("essfunc", 100)',
      'dx @$osed().code_caves("essfunc", 50, 25, "00 0A 0D")',
      'dx @$osed().code_caves("", 50, 25, "", "EXEC")',
    ],
    schema: {
      module: { type: "string" },
      minSize: { type: "number", min: 1, default: 50 },
      maxResults: { type: "number", min: 1, max: 100, default: 25 },
      badChars: { type: "string" },
      capability: { type: "string" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const module = options.module as string | undefined;
      const minSize = (options.minSize as number | undefined) ?? 50;
      const maxResults = (options.maxResults as number | undefined) ?? 25;
      const badChars = options.badChars as string | undefined;
      const capability = options.capability as string | undefined;
      const pointerSize = getPointerSize();
      const hasBadChars = badChars !== undefined && badChars.trim().length > 0;

      const { caves, warnings } = findCodeCaves(module, minSize, maxResults, badChars, capability);

      out.section("Code Caves");

      if (caves.length === 0) {
        const parts = [`No caves >= ${minSize} bytes found`];
        if (module) parts.push(`in '${module}'`);
        if (capability) parts.push(`with capability ${capability}`);
        out.info(parts.join(" ") + ".");
      } else {
        const parts = [`Found ${caves.length} cave(s)`, `min ${minSize} bytes`];
        if (module) parts.push(`module: ${module}`);
        if (capability) parts.push(`filter: ${capability}`);
        if (hasBadChars) parts.push("bad chars applied");
        out.info(parts.join(", "));

        const columns: out.TableColumn[] = [
          { key: "va", header: "VA", width: pointerSize * 2 + 2 },
          { key: "rva", header: "RVA", width: pointerSize * 2 + 2 },
          { key: "size", header: "Size", width: 11 },
          { key: "pattern", header: "Pattern", width: 7 },
          { key: "module", header: "Module", width: 16 },
          { key: "section", header: "Section", width: 8 },
          { key: "aslr", header: "ASLR" },
          { key: "prot", header: "Prot" },
          { key: "capability", header: "Capability", width: 14 },
        ];

        if (hasBadChars) {
          columns.push({ key: "addrSafe", header: "AddrSafe" });
          columns.push({ key: "safeVa", header: "SafeVA", width: pointerSize * 2 + 2 });
        }

        out.table(
          columns,
          caves.map((cave) => {
            const row: Record<string, string> = {
              va: out.formatAddress(cave.address, pointerSize),
              rva: out.formatAddress(BigInt(cave.rva), pointerSize),
              size: `0x${cave.size.toString(16).toUpperCase()} (${cave.size})`,
              pattern: cave.pattern,
              module: cave.module,
              section: cave.section,
              aslr: cave.aslr === "enabled" ? "yes" : cave.aslr === "disabled" ? "no" : "?",
              prot: protectionLabel(cave.readable, cave.writable, cave.executable),
              capability: displayCapabilities(cave.capabilities),
            };
            if (hasBadChars) {
              row.addrSafe = cave.addrSafe ? "yes" : "no";
              row.safeVa =
                cave.addrSafe ? "-"
                : cave.safeVa !== null ? out.formatAddress(cave.safeVa, pointerSize)
                : "(none)";
            }
            return row;
          }),
        );

        if (hasBadChars) {
          const unsafeCount = caves.filter((c) => c.addrSafe === false).length;
          if (unsafeCount > 0) {
            const aslrNote = caves.some((c) => c.aslr === "enabled")
              ? " (ASLR addresses valid for current mapping only)"
              : "";
            out.info(`${unsafeCount} cave address(es) contain forbidden bytes${aslrNote}.`);
          }
        }
      }

      for (const warning of warnings) {
        out.warn(warning);
      }

      out.whyItMatters(
        "Code caves are unused regions within mapped images. Their suitability for execution, staging, or ROP workspaces depends on memory protection, address stability, and input constraints.",
      );

      return {
        command: "code_caves",
        args: options,
        success: true,
        findings: caves.map((cave) => ({
          address: out.formatAddress(cave.address, pointerSize),
          rva: cave.rva,
          size: cave.size,
          pattern: cave.pattern,
          module: cave.module,
          modulePath: cave.modulePath,
          moduleBase: out.formatAddress(cave.moduleBase, pointerSize),
          section: cave.section,
          sectionExecutable: cave.sectionExecutable,
          aslr: cave.aslr,
          readable: cave.readable,
          writable: cave.writable,
          executable: cave.executable,
          capabilities: cave.capabilities,
          addrSafe: cave.addrSafe,
          badBytes: cave.badBytes.map((b) => out.formatHexByte(b)),
          safeOffset: cave.safeOffset,
          safeVa: cave.safeVa !== null ? out.formatAddress(cave.safeVa, pointerSize) : null,
        })),
        warnings,
        errors: [],
      };
    },
  };
}
