import { Command, CommandResult } from "../core/registry";
import { forEachSection, ModuleSection } from "../core/scan_engine";
import { tryReadMemory, getPointerSize } from "../core/memory";
import { memoryRegion } from "../analysis/memory";
import * as out from "../core/output";

export type CodeCave = {
  address: bigint;
  size: number;
  module: string;
  section: string;
  sectionExecutable: boolean;
  readable: boolean | null;
  writable: boolean | null;
  executable: boolean | null;
};

function scanSectionForCaves(
  section: ModuleSection,
  minSize: number,
  chunkSize: number,
): CodeCave[] {
  const caves: CodeCave[] = [];
  let runStart: bigint | undefined;
  let runLength = 0;

  const flush = (): void => {
    if (runStart !== undefined && runLength >= minSize) {
      caves.push({
        address: runStart,
        size: runLength,
        module: section.module.name.replace(/^.*[\\\/]/, ""),
        section: section.name,
        sectionExecutable: section.executable,
        readable: null,
        writable: null,
        executable: null,
      });
    }
    runStart = undefined;
    runLength = 0;
  };

  for (let offset = 0; offset < section.size; offset += chunkSize) {
    const chunkStart = section.start + BigInt(offset);
    const remaining = section.size - offset;
    const size = Math.min(remaining, chunkSize);
    const bytes = tryReadMemory(chunkStart, size);
    if (!bytes) {
      flush();
      continue;
    }

    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] === 0x00) {
        if (runStart === undefined) {
          runStart = chunkStart + BigInt(i);
          runLength = 1;
        } else {
          runLength++;
        }
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

  const caves: CodeCave[] = [];
  for (const section of scope.sections) {
    const found = scanSectionForCaves(section, minSize, 0x1000);
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
    description: "Find contiguous null-byte regions in PE sections suitable for shellcode placement.",
    usage: "dx @$osed().code_caves(module?, minSize?, maxResults?)",
    examples: [
      "dx @$osed().code_caves()",
      'dx @$osed().code_caves("essfunc")',
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
        out.info(`No null-byte regions >= ${minSize} bytes found.`);
      } else {
        out.info(`Found ${caves.length} cave(s) (min ${minSize} bytes)`);
        out.table(
          [
            { key: "address", header: "Address", width: pointerSize * 2 + 2 },
            { key: "size", header: "Size", width: 8 },
            { key: "module", header: "Module", width: 16 },
            { key: "section", header: "Section", width: 8 },
            { key: "read", header: "R" },
            { key: "write", header: "W" },
            { key: "exec", header: "X" },
          ],
          caves.map((cave) => ({
            address: out.formatAddress(cave.address, pointerSize),
            size: `0x${cave.size.toString(16).toUpperCase()} (${cave.size})`,
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
