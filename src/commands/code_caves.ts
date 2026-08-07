import { Command, CommandResult } from "../core/registry";
import { forEachSection, ModuleSection } from "../core/scan_engine";
import { tryReadMemory, getPointerSize, readUint16LE, readUint32LE } from "../core/memory";
import { memoryRegion } from "../analysis/memory";
import * as out from "../core/output";

export type CavePattern = "NULL" | "INT3" | "NOP" | "PADDING";

export type CodeCave = {
  address: bigint;
  size: number;
  pattern: CavePattern;
  module: string;
  section: string;
  sectionExecutable: boolean;
  readable: boolean | null;
  writable: boolean | null;
  executable: boolean | null;
};

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
        section: section.name,
        sectionExecutable: section.executable,
        readable: null,
        writable: null,
        executable: null,
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

function enrichProtection(caves: CodeCave[]): void {
  const checked = new Map<string, { readable: boolean | null; writable: boolean | null; executable: boolean | null }>();
  for (const cave of caves) {
    const key = cave.address.toString();
    let prot = checked.get(key);
    if (!prot) {
      const region = memoryRegion(cave.address);
      prot = { readable: region.readable, writable: region.writable, executable: region.executable };
      checked.set(key, prot);
    }
    cave.readable = prot.readable;
    cave.writable = prot.writable;
    cave.executable = prot.executable;
  }
}

function flag(value: boolean | null): string {
  return value === null ? "?" : value ? "yes" : "no";
}

export function findCodeCaves(
  module: string | undefined,
  minSize: number,
  maxResults: number,
): { caves: CodeCave[]; warnings: string[] } {
  const scope = forEachSection({
    module,
    executableOnly: false,
    maxResults: 200,
    chunkSize: 0x1000,
  });

  const effectiveSizes = computeEffectiveSizes(scope.sections);

  const caves: CodeCave[] = [];
  for (let s = 0; s < scope.sections.length; s++) {
    const section = scope.sections[s];
    const scanSize = effectiveSizes[s];
    const found = scanForCaves(section, scanSize, minSize, 0x1000);
    for (const cave of found) {
      caves.push(cave);
      if (caves.length >= maxResults) break;
    }
    if (caves.length >= maxResults) break;
  }

  caves.sort((a, b) => b.size - a.size);

  enrichProtection(caves);

  return { caves, warnings: scope.warnings };
}

export function createCodeCavesCommand(): Command {
  return {
    name: "code_caves",
    description: "Find contiguous null-byte and int3/nop-padding regions in PE sections suitable for shellcode placement.",
    usage: "dx @$osed().code_caves(module?, minSize?, maxResults?)",
    examples: [
      "dx @$osed().code_caves()",
      'dx @$osed().code_caves("vulnserver")',
      'dx @$osed().code_caves("essfunc", 100)',
      'dx @$osed().code_caves("essfunc", 50, 20)',
    ],
    schema: {
      module: { type: "string" },
      minSize: { type: "number", min: 1, default: 50 },
      maxResults: { type: "number", min: 1, max: 100, default: 25 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const module = options.module as string | undefined;
      const minSize = (options.minSize as number | undefined) ?? 50;
      const maxResults = (options.maxResults as number | undefined) ?? 25;
      const pointerSize = getPointerSize();

      const { caves, warnings } = findCodeCaves(module, minSize, maxResults);

      out.section("Code Caves");

      if (caves.length === 0) {
        out.info(`No caves >= ${minSize} bytes found${module ? ` in '${module}'` : ""}.`);
      } else {
        out.info(`Found ${caves.length} cave(s) (min ${minSize} bytes${module ? `, module: ${module}` : ""})`);
        out.table(
          [
            { key: "address", header: "Address", width: pointerSize * 2 + 2 },
            { key: "size", header: "Size", width: 11 },
            { key: "pattern", header: "Pattern", width: 7 },
            { key: "module", header: "Module", width: 16 },
            { key: "section", header: "Section", width: 8 },
            { key: "read", header: "R" },
            { key: "write", header: "W" },
            { key: "exec", header: "X" },
          ],
          caves.map((cave) => ({
            address: out.formatAddress(cave.address, pointerSize),
            size: `0x${cave.size.toString(16).toUpperCase()} (${cave.size})`,
            pattern: cave.pattern,
            module: cave.module,
            section: cave.section,
            read: flag(cave.readable),
            write: flag(cave.writable),
            exec: flag(cave.executable),
          })),
        );
      }

      for (const warning of warnings) {
        out.warn(warning);
      }

      out.whyItMatters("Code caves provide writable regions for shellcode or ROP stack pivots without allocating new memory.");

      return {
        command: "code_caves",
        args: options,
        success: true,
        findings: caves.map((cave) => ({
          address: out.formatAddress(cave.address, pointerSize),
          size: cave.size,
          pattern: cave.pattern,
          module: cave.module,
          section: cave.section,
          sectionExecutable: cave.sectionExecutable,
          readable: cave.readable,
          writable: cave.writable,
          executable: cave.executable,
        })),
        warnings,
        errors: [],
      };
    },
  };
}
