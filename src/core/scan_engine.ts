import { tryReadMemory, readUint16LE, readUint32LE } from "./memory";

export type ScanOptions = {
  module?: string;
  executableOnly: boolean;
  maxResults: number;
  chunkSize: number;
};

export type ModuleInfo = {
  name: string;
  path: string;
  base: bigint;
  size: bigint;
};

export type ModuleSection = {
  module: ModuleInfo;
  name: string;
  start: bigint;
  size: number;
  executable: boolean;
};

export type ScanWarning = {
  region: string;
  message: string;
};

export type ScanResult = {
  hits: bigint[];
  warnings: ScanWarning[];
  stats: Record<string, number>;
};

const IMAGE_SCN_MEM_EXECUTE = 0x20000000;

function decodeAscii(bytes: Uint8Array): string {
  let result = "";
  for (const byte of bytes) {
    if (byte === 0) {
      break;
    }
    result += String.fromCharCode(byte);
  }
  return result;
}

function parseBigIntString(value: string): bigint {
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
  return BigInt(0);
}

function toBigInt(value: unknown): bigint {
  if (typeof value === "bigint") {
    return value;
  }

  if (typeof value === "number") {
    return BigInt(Math.max(0, Math.trunc(value)));
  }

  if (typeof value === "string") {
    return parseBigIntString(value);
  }

  if (value && typeof value === "object") {
    const valueOf = (value as { valueOf?: () => unknown }).valueOf;
    if (typeof valueOf === "function") {
      const resolved = valueOf.call(value);
      if (resolved !== value) {
        const parsed = toBigInt(resolved);
        if (parsed !== BigInt(0)) {
          return parsed;
        }
      }
    }

    const asString = (value as { toString?: () => string }).toString;
    if (typeof asString === "function") {
      return parseBigIntString(asString.call(value));
    }
  }

  return BigInt(0);
}

function asArray(value: unknown): unknown[] {
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

function getModules(): ModuleInfo[] {
  const process = host.currentProcess as unknown as { Modules?: unknown };
  const modules = asArray(process?.Modules);

  return modules
    .map((entry) => {
      const module = entry as {
        Name?: string;
        Path?: string;
        BaseAddress?: number | bigint;
        Base?: number | bigint | string;
        Address?: number | bigint | string;
        Size?: number | bigint;
        Length?: number | bigint | string;
        EndAddress?: number | bigint | string;
      };

      const base = toBigInt(module.BaseAddress ?? module.Base ?? module.Address);
      let size = toBigInt(module.Size ?? module.Length);
      const end = toBigInt(module.EndAddress);
      if (size === BigInt(0) && end > base) {
        size = end - base;
      }

      return {
        name: module.Name ?? "<unknown>",
        path: module.Path ?? module.Name ?? "<unknown>",
        base,
        size,
      };
    })
    .filter((module) => module.size > BigInt(0))
    .sort((a, b) => (a.base < b.base ? -1 : 1));
}

function parseSections(module: ModuleInfo): ModuleSection[] {
  const sections: ModuleSection[] = [];

  try {
    const mz = readUint16LE(module.base);
    if (mz !== 0x5a4d) {
      return sections;
    }

    const peOffset = readUint32LE(module.base + BigInt(0x3c));
    const pe = module.base + BigInt(peOffset);
    const sig = readUint32LE(pe);
    if (sig !== 0x4550) {
      return sections;
    }

    const sectionCount = readUint16LE(pe + BigInt(0x6));
    const optionalHeaderSize = readUint16LE(pe + BigInt(0x14));
    const sectionTable = pe + BigInt(0x18) + BigInt(optionalHeaderSize);

    for (let i = 0; i < sectionCount; i += 1) {
      const entry = sectionTable + BigInt(i * 40);
      const nameBytes = tryReadMemory(entry, 8) ?? new Uint8Array();
      const name = decodeAscii(nameBytes).replace(/\0+$/, "") || `.sec${i}`;
      const virtualSize = readUint32LE(entry + BigInt(0x8));
      const virtualAddress = readUint32LE(entry + BigInt(0xc));
      const characteristics = readUint32LE(entry + BigInt(0x24));
      const executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0;

      if (virtualSize > 0) {
        sections.push({
          module,
          name,
          start: module.base + BigInt(virtualAddress),
          size: virtualSize,
          executable,
        });
      }
    }
  } catch (_error) {
    return [];
  }

  return sections;
}

function matchesModuleFilter(module: ModuleInfo, filter?: string): boolean {
  if (!filter) {
    return true;
  }

  const needle = filter.toLowerCase();
  return module.name.toLowerCase().includes(needle) || module.path.toLowerCase().includes(needle);
}

export function forEachSection(options: ScanOptions): { sections: ModuleSection[]; warnings: string[] } {
  const warnings: string[] = [];
  const sections: ModuleSection[] = [];
  const matchingModules = getModules().filter((item) => matchesModuleFilter(item, options.module));

  if (matchingModules.length === 0) {
    warnings.push(
      options.module
        ? `No loaded modules matched '${options.module}'.`
        : "No loaded modules were available to scan.",
    );
  }

  for (const module of matchingModules) {
    const parsed = parseSections(module);
    if (parsed.length === 0) {
      warnings.push(`Could not parse PE sections for module ${module.name}.`);
      continue;
    }

    for (const section of parsed) {
      if (!options.executableOnly || section.executable) {
        sections.push(section);
      }
    }
  }

  if (matchingModules.length > 0 && sections.length === 0 && warnings.length === 0) {
    warnings.push(
      options.executableOnly
        ? "Matched modules contained no executable PE sections."
        : "Matched modules contained no scannable PE sections.",
    );
  }

  sections.sort((a, b) => (a.start < b.start ? -1 : 1));
  return { sections, warnings };
}

export function scanPattern(options: ScanOptions, pattern: Uint8Array): ScanResult {
  const hits: bigint[] = [];
  const seenHits = new Set<string>();
  const warnings: ScanWarning[] = [];

  const normalizedChunk = Math.max(0x1000, Math.min(0x4000, options.chunkSize));
  const normalizedMax = Math.min(options.maxResults, 200);

  const scope = forEachSection({
    ...options,
    chunkSize: normalizedChunk,
    maxResults: normalizedMax,
  });

  for (const warning of scope.warnings) {
    warnings.push({ region: "module", message: warning });
  }

  let chunksRead = 0;
  let chunksSkipped = 0;

  for (const section of scope.sections) {
    for (let offset = 0; offset < section.size; offset += normalizedChunk) {
      const chunkStart = section.start + BigInt(offset);
      const remaining = section.size - offset;
      const size = Math.max(0, Math.min(remaining, normalizedChunk + pattern.length - 1));

      if (size < pattern.length) {
        continue;
      }

      const bytes = tryReadMemory(chunkStart, size);
      if (!bytes) {
        chunksSkipped += 1;
        warnings.push({
          region: `${section.module.name}:${section.name}`,
          message: `Unreadable memory at chunk offset 0x${offset.toString(16).toUpperCase()}.`,
        });
        continue;
      }

      chunksRead += 1;

      const last = bytes.length - pattern.length;
      for (let i = 0; i <= last; i += 1) {
        let matched = true;
        for (let j = 0; j < pattern.length; j += 1) {
          if (bytes[i + j] !== pattern[j]) {
            matched = false;
            break;
          }
        }

        if (matched) {
          const hit = chunkStart + BigInt(i);
          const hitKey = hit.toString();
          if (seenHits.has(hitKey)) {
            continue;
          }

          seenHits.add(hitKey);
          hits.push(hit);
          if (hits.length >= normalizedMax) {
            return {
              hits: hits.sort((a, b) => (a < b ? -1 : 1)),
              warnings,
              stats: {
                sectionsScanned: scope.sections.length,
                chunksRead,
                chunksSkipped,
                results: hits.length,
                stoppedEarly: 1,
              },
            };
          }
        }
      }
    }
  }

  return {
    hits: hits.sort((a, b) => (a < b ? -1 : 1)),
    warnings,
    stats: {
      sectionsScanned: scope.sections.length,
      chunksRead,
      chunksSkipped,
      results: hits.length,
      stoppedEarly: 0,
    },
  };
}
