import { readPointer } from "../core/memory";

type PointerReader = (address: bigint, pointerSize: 4 | 8) => bigint;

export interface SehRecordEvidence {
  node: bigint;
  next: bigint;
  handler: bigint;
}

function safeGet(value: unknown, key: string): unknown {
  if (!value || typeof value !== "object") return undefined;
  try {
    return (value as Record<string, unknown>)[key];
  } catch (_error) {
    return undefined;
  }
}

function safeKeys(value: unknown): string[] {
  if (!value || typeof value !== "object") return [];
  try {
    return Object.keys(value as Record<string, unknown>);
  } catch (_error) {
    return [];
  }
}

function toAddress(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isFinite(value)) return BigInt(Math.max(0, Math.trunc(value)));
  if (typeof value === "string") {
    const text = value.trim();
    const embeddedHex = text.match(/0x[0-9a-fA-F]+/);
    if (embeddedHex) return BigInt(embeddedHex[0]);
    if (/^[0-9a-fA-F]+$/.test(text)) return BigInt(`0x${text}`);
  }
  if (value && typeof value === "object") {
    for (const key of ["targetLocation", "address", "Address", "Value", "value"]) {
      const parsed = toAddress(safeGet(value, key));
      if (parsed !== BigInt(0)) return parsed;
    }
    try {
      const valueOf = safeGet(value, "valueOf");
      if (typeof valueOf === "function") {
        const resolved = (valueOf as () => unknown).call(value);
        if (resolved !== value) {
          const parsed = toAddress(resolved);
          if (parsed !== BigInt(0)) return parsed;
        }
      }
    } catch (_error) {
      // Continue with string conversion.
    }
    try {
      const toString = safeGet(value, "toString");
      if (typeof toString === "function") return toAddress((toString as () => unknown).call(value));
    } catch (_error) {
      // Unparseable host object.
    }
  }
  return BigInt(0);
}

function signedInteger(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return Math.trunc(value);
  if (typeof value === "bigint") return Number(value);
  const text = typeof value === "string" ? value : String(value ?? "");
  const match = text.match(/-?[0-9]+/);
  return match ? parseInt(match[0], 10) : 0;
}

function environmentTeb(thread: Record<string, unknown>): bigint {
  for (const environment of [safeGet(thread, "Environment"), safeGet(thread, "NativeEnvironment")]) {
    const block = safeGet(environment, "EnvironmentBlock");
    if (!block || typeof block !== "object") continue;
    const direct = toAddress(safeGet(block, "Self"));
    if (direct !== BigInt(0)) return direct;
    const ntTib = safeGet(block, "NtTib");
    const nativeSelf = toAddress(safeGet(ntTib, "Self"));
    const wowOffset = signedInteger(safeGet(block, "WowTebOffset"));
    if (nativeSelf !== BigInt(0) && wowOffset !== 0) return nativeSelf + BigInt(wowOffset);
    if (nativeSelf !== BigInt(0)) return nativeSelf;
  }
  return BigInt(0);
}

function candidates(value: unknown, depth = 0): bigint[] {
  if (depth > 2 || value === null || value === undefined) return [];
  const found = new Set<bigint>();
  const direct = toAddress(value);
  if (direct !== BigInt(0)) found.add(direct);
  if (typeof value === "object") {
    for (const key of safeKeys(value)) {
      for (const item of candidates(safeGet(value, key), depth + 1)) found.add(item);
    }
  }
  return [...found];
}

function looksLikeTeb32(address: bigint, reader: PointerReader): boolean {
  try {
    if (address < BigInt(0x1000) || reader(address + BigInt(0x18), 4) !== address) return false;
    const head = reader(address, 4);
    return head !== BigInt(0) && head !== BigInt(0xffffffff);
  } catch (_error) {
    return false;
  }
}

export function resolveTeb32Address(thread: Record<string, unknown>, reader: PointerReader = readPointer): bigint | undefined {
  const fromEnvironment = environmentTeb(thread);
  if (fromEnvironment !== BigInt(0)) return fromEnvironment;

  for (const key of ["Teb", "Teb32", "TebAddress", "Wow64Teb", "Wow64Teb32"]) {
    const parsed = toAddress(safeGet(thread, key));
    if (parsed !== BigInt(0)) return parsed;
  }
  for (const key of safeKeys(thread)) {
    if (/teb/i.test(key)) {
      const parsed = toAddress(safeGet(thread, key));
      if (parsed !== BigInt(0)) return parsed;
    }
  }
  return candidates(thread).find((candidate) => looksLikeTeb32(candidate, reader));
}

export function readSehRecords(teb: bigint, maxRecords = 64, reader: PointerReader = readPointer): SehRecordEvidence[] {
  const records: SehRecordEvidence[] = [];
  let node = reader(teb, 4);
  while (node !== BigInt(0xffffffff) && records.length < maxRecords) {
    const next = reader(node, 4);
    records.push({ node, next, handler: reader(node + BigInt(4), 4) });
    node = next;
  }
  return records;
}
