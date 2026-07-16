export type EvidenceFlag = boolean | null;

export type MemoryRegionType = "image" | "mapped" | "private" | "unknown";

export interface RawMemoryRegion {
  baseAddress?: bigint;
  allocationBase?: bigint;
  regionSize?: bigint;
  state?: number;
  protection?: number;
  allocationProtection?: number;
  type?: number;
}

export interface MemoryRegionEvidence {
  address: bigint;
  baseAddress?: bigint;
  allocationBase?: bigint;
  regionSize?: bigint;
  readable: EvidenceFlag;
  writable: EvidenceFlag;
  executable: EvidenceFlag;
  guarded: EvidenceFlag;
  noAccess: EvidenceFlag;
  committed: EvidenceFlag;
  regionType: MemoryRegionType;
  raw: {
    state?: number;
    protection?: number;
    allocationProtection?: number;
    type?: number;
  };
  source: "vprot" | "unavailable";
  warnings: string[];
}

export interface SerializedMemoryRegionEvidence {
  address: string;
  baseAddress?: string;
  allocationBase?: string;
  regionSize?: string;
  readable: EvidenceFlag;
  writable: EvidenceFlag;
  executable: EvidenceFlag;
  guarded: EvidenceFlag;
  noAccess: EvidenceFlag;
  committed: EvidenceFlag;
  regionType: MemoryRegionType;
  raw: {
    state?: number;
    protection?: number;
    allocationProtection?: number;
    type?: number;
  };
  source: "vprot" | "unavailable";
  warnings: string[];
}

const PAGE_NOACCESS = 0x01;
const PAGE_READONLY = 0x02;
const PAGE_READWRITE = 0x04;
const PAGE_WRITECOPY = 0x08;
const PAGE_EXECUTE = 0x10;
const PAGE_EXECUTE_READ = 0x20;
const PAGE_EXECUTE_READWRITE = 0x40;
const PAGE_EXECUTE_WRITECOPY = 0x80;
const PAGE_GUARD = 0x100;
const MEM_COMMIT = 0x1000;
const MEM_PRIVATE = 0x20000;
const MEM_MAPPED = 0x40000;
const MEM_IMAGE = 0x1000000;

function protectionBase(protection: number): number {
  return protection & 0xff;
}

function formatAddressValue(value: bigint): string {
  return `0x${value.toString(16).toUpperCase().padStart(16, "0")}`;
}

export function serializeMemoryRegionEvidence(evidence: MemoryRegionEvidence): SerializedMemoryRegionEvidence {
  return {
    address: formatAddressValue(evidence.address),
    baseAddress: evidence.baseAddress === undefined ? undefined : formatAddressValue(evidence.baseAddress),
    allocationBase: evidence.allocationBase === undefined ? undefined : formatAddressValue(evidence.allocationBase),
    regionSize: evidence.regionSize === undefined ? undefined : `0x${evidence.regionSize.toString(16).toUpperCase()}`,
    readable: evidence.readable,
    writable: evidence.writable,
    executable: evidence.executable,
    guarded: evidence.guarded,
    noAccess: evidence.noAccess,
    committed: evidence.committed,
    regionType: evidence.regionType,
    raw: { ...evidence.raw },
    source: evidence.source,
    warnings: [...evidence.warnings],
  };
}

export function normalizeMemoryRegion(address: bigint, raw: RawMemoryRegion, source: MemoryRegionEvidence["source"] = "vprot"): MemoryRegionEvidence {
  const protection = raw.protection;
  const base = protection === undefined ? undefined : protectionBase(protection);
  const knownProtection = base !== undefined && [
    PAGE_NOACCESS,
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
  ].includes(base);

  const readable = !knownProtection
    ? null
    : [PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY].includes(base!);
  const writable = !knownProtection
    ? null
    : [PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY].includes(base!);
  const executable = !knownProtection
    ? null
    : [PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY].includes(base!);

  let regionType: MemoryRegionType = "unknown";
  if (raw.type === MEM_IMAGE) regionType = "image";
  else if (raw.type === MEM_MAPPED) regionType = "mapped";
  else if (raw.type === MEM_PRIVATE) regionType = "private";

  return {
    address,
    baseAddress: raw.baseAddress,
    allocationBase: raw.allocationBase,
    regionSize: raw.regionSize,
    readable,
    writable,
    executable,
    guarded: protection === undefined ? null : (protection & PAGE_GUARD) !== 0,
    noAccess: !knownProtection ? null : base === PAGE_NOACCESS,
    committed: raw.state === undefined ? null : raw.state === MEM_COMMIT,
    regionType,
    raw: {
      state: raw.state,
      protection: raw.protection,
      allocationProtection: raw.allocationProtection,
      type: raw.type,
    },
    source,
    warnings: [],
  };
}

function toArray(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (value && typeof (value as { [Symbol.iterator]?: unknown })[Symbol.iterator] === "function") {
    try {
      return Array.from(value as Iterable<unknown>);
    } catch (_error) {
      return [];
    }
  }
  return [];
}

function parseHexValue(value: string): bigint | undefined {
  const cleaned = value.replace(/`/g, "");
  return /^[0-9a-f]+$/i.test(cleaned) ? BigInt(`0x${cleaned}`) : undefined;
}

export function parseVprot(lines: string[]): RawMemoryRegion {
  const fields = new Map<string, bigint>();
  for (const line of lines) {
    const match = line.match(/^\s*(BaseAddress|AllocationBase|RegionSize|State|Protect|AllocationProtect|Type):\s+([0-9a-f`]+)/i);
    if (!match) continue;
    const value = parseHexValue(match[2]);
    if (value !== undefined) fields.set(match[1].toLowerCase(), value);
  }

  const asNumber = (key: string): number | undefined => {
    const value = fields.get(key);
    return value === undefined ? undefined : Number(value & BigInt(0xffffffff));
  };

  return {
    baseAddress: fields.get("baseaddress"),
    allocationBase: fields.get("allocationbase"),
    regionSize: fields.get("regionsize"),
    state: asNumber("state"),
    protection: asNumber("protect"),
    allocationProtection: asNumber("allocationprotect"),
    type: asNumber("type"),
  };
}

export function memoryRegion(address: bigint): MemoryRegionEvidence {
  try {
    const hostAny = host as unknown as {
      namespace?: { Debugger?: { Utility?: { Control?: { ExecuteCommand?: (command: string) => unknown } } } };
    };
    const control = hostAny.namespace?.Debugger?.Utility?.Control;
    const execute = control?.ExecuteCommand;
    if (typeof execute !== "function") throw new Error("WinDbg command execution is unavailable.");
    const result = execute.call(control, `!vprot 0x${address.toString(16)}`);
    const raw = parseVprot(toArray(result).map(String));
    if (raw.protection === undefined && raw.state === undefined && raw.type === undefined) {
      throw new Error("WinDbg returned no recognizable memory metadata.");
    }
    return normalizeMemoryRegion(address, raw);
  } catch (error) {
    const evidence = normalizeMemoryRegion(address, {}, "unavailable");
    evidence.warnings.push(error instanceof Error ? error.message : String(error));
    return evidence;
  }
}

export function canExecute(address: bigint): EvidenceFlag {
  return memoryRegion(address).executable;
}
