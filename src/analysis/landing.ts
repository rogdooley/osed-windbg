import { getPointerSize, tryReadMemory } from "../core/memory";
import { generateCyclicPattern, generateMsfPattern } from "../logic/pattern_logic";
import { MemoryRegionEvidence, SerializedMemoryRegionEvidence, memoryRegion, serializeMemoryRegionEvidence } from "./memory";

export interface Observation {
  kind: string;
  confidence: number;
  address?: bigint;
  length?: number;
  details: Record<string, unknown>;
}

export interface LandingEvidence {
  address?: bigint;
  memory?: MemoryRegionEvidence;
  bytes: number[];
  requestedBytes: number;
  observations: Observation[];
  confidence: number;
  recommendation: string;
}

export interface SerializedObservation {
  kind: string;
  confidence: number;
  address?: string;
  length?: number;
  details: Record<string, unknown>;
}

export interface SerializedLandingEvidence {
  address?: string;
  memory?: SerializedMemoryRegionEvidence;
  bytes: number[];
  requestedBytes: number;
  observations: SerializedObservation[];
  confidence: number;
  recommendation: string;
}

const POSITIVE_OBSERVATION_KINDS = new Set([
  "nop_sled_detected",
  "repeated_marker_bytes",
  "cyclic_pattern_match",
  "payload_like_bytes",
  "known_payload_prefix",
  "executable_region",
  "disassembly_succeeded",
]);

function stableDetails(value: unknown): string {
  if (typeof value === "bigint") return `bigint:${value.toString(16)}`;
  if (Array.isArray(value)) return `[${value.map(stableDetails).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${key}:${stableDetails(entry)}`)
      .join(",")}}`;
  }
  return `${typeof value}:${String(value)}`;
}

function formatAddressValue(value: bigint): string {
  return `0x${value.toString(16).toUpperCase().padStart(16, "0")}`;
}

function serializeUnknown(value: unknown): unknown {
  if (typeof value === "bigint") return formatAddressValue(value);
  if (Array.isArray(value)) return value.map(serializeUnknown);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      out[key] = serializeUnknown(entry);
    }
    return out;
  }
  return value;
}

export function serializeLandingEvidence(evidence: LandingEvidence): SerializedLandingEvidence {
  return {
    address: evidence.address === undefined ? undefined : formatAddressValue(evidence.address),
    memory: evidence.memory === undefined ? undefined : serializeMemoryRegionEvidence(evidence.memory),
    bytes: [...evidence.bytes],
    requestedBytes: evidence.requestedBytes,
    observations: evidence.observations.map((item) => ({
      kind: item.kind,
      confidence: item.confidence,
      address: item.address === undefined ? undefined : formatAddressValue(item.address),
      length: item.length,
      details: serializeUnknown(item.details) as Record<string, unknown>,
    })),
    confidence: evidence.confidence,
    recommendation: evidence.recommendation,
  };
}

/** Stable derived identity without adding mutable identity state to evidence. */
export function observationIdentity(value: Observation): string {
  return [
    value.kind,
    value.address === undefined ? "" : value.address.toString(16),
    value.length === undefined ? "" : value.length.toString(),
    stableDetails(value.details),
  ].join("|");
}

export function calculateLandingConfidence(observations: readonly Observation[]): number {
  const contributions = observations
    .filter((item) => POSITIVE_OBSERVATION_KINDS.has(item.kind))
    .map((item) => Math.max(0, Math.min(1, Number.isFinite(item.confidence) ? item.confidence : 0)))
    .sort((left, right) => left - right);
  if (contributions.length === 0) return 0;
  return Math.max(0, Math.min(1, contributions.reduce((sum, value) => sum + value, 0) / 2));
}

function observation(kind: string, confidence: number, address: bigint, offset: number, length: number, details: Record<string, unknown> = {}): Observation {
  return { kind, confidence, address: address + BigInt(offset), length, details: { offset, ...details } };
}

function repeatedRuns(bytes: Uint8Array, minimum = 4): Array<{ byte: number; offset: number; length: number }> {
  const runs: Array<{ byte: number; offset: number; length: number }> = [];
  for (let start = 0; start < bytes.length;) {
    let end = start + 1;
    while (end < bytes.length && bytes[end] === bytes[start]) end += 1;
    if (end - start >= minimum) runs.push({ byte: bytes[start], offset: start, length: end - start });
    start = end;
  }
  return runs;
}

function findPattern(bytes: Uint8Array): { kind: string; offset: number; length: number } | undefined {
  if (bytes.length < 8) return undefined;
  const text = String.fromCharCode(...bytes);
  const candidates = [
    { kind: "msf", value: generateMsfPattern(20280) },
    { kind: "cyclic", value: generateCyclicPattern(20000) },
  ];
  for (const candidate of candidates) {
    const length = Math.min(text.length, 32);
    for (let window = length; window >= 8; window -= 1) {
      for (let offset = 0; offset <= text.length - window; offset += 1) {
        if (candidate.value.includes(text.slice(offset, offset + window))) return { kind: candidate.kind, offset, length: window };
      }
    }
  }
  return undefined;
}

export function analyzeLandingBytes(address: bigint, bytes: Uint8Array, memory: MemoryRegionEvidence, requestedBytes = bytes.length, disassemblySucceeded: boolean | null = null): LandingEvidence {
  const observations: Observation[] = [];
  const runs = repeatedRuns(bytes);
  for (const run of runs) {
    if (run.byte === 0x90 && run.length >= 8) {
      observations.push(observation("nop_sled_detected", 0.95, address, run.offset, run.length, { byte: run.byte }));
    } else if ([0x41, 0x42, 0x43, 0x44].includes(run.byte)) {
      observations.push(observation("repeated_marker_bytes", 0.8, address, run.offset, run.length, { byte: run.byte }));
    } else {
      observations.push(observation("repeated_byte_run", 0.45, address, run.offset, run.length, { byte: run.byte }));
    }
  }

  const pattern = findPattern(bytes);
  if (pattern) observations.push(observation("cyclic_pattern_match", 0.9, address, pattern.offset, pattern.length, { pattern: pattern.kind }));

  // Preserve the legacy triage signal as normalized evidence. This is deliberately
  // observational: low-printability bytes are not classified as shellcode.
  for (let offset = 0; offset <= bytes.length - 32; offset += 4) {
    const window = bytes.slice(offset, offset + 32);
    let zeroes = 0;
    let printable = 0;
    for (const byte of window) {
      if (byte === 0x00) zeroes += 1;
      if (byte >= 0x20 && byte <= 0x7e) printable += 1;
    }
    if (zeroes <= 1 && printable <= 8) {
      observations.push(observation("payload_like_bytes", 0.4, address, offset, window.length, { zeroes, printable }));
    }
  }

  const prefixes: Array<{ name: string; bytes: number[] }> = [
    { name: "x86_cld_call", bytes: [0xfc, 0xe8] },
    { name: "x86_getpc_fnstenv", bytes: [0xd9, 0xee, 0xd9, 0x74, 0x24, 0xf4] },
  ];
  for (const prefix of prefixes) {
    if (prefix.bytes.every((value, index) => bytes[index] === value)) {
      observations.push(observation("known_payload_prefix", 0.65, address, 0, prefix.bytes.length, { prefix: prefix.name }));
    }
  }

  if (memory.readable !== null) observations.push(observation(memory.readable ? "readable_region" : "unreadable_region", 1, address, 0, bytes.length));
  if (memory.executable !== null) observations.push(observation(memory.executable ? "executable_region" : "non_executable_region", 1, address, 0, bytes.length));
  if (disassemblySucceeded !== null) observations.push(observation(disassemblySucceeded ? "disassembly_succeeded" : "disassembly_failed", 0.8, address, 0, Math.min(bytes.length, 16)));
  if (bytes.length < requestedBytes) observations.push(observation(bytes.length === 0 ? "bytes_inaccessible" : "bytes_truncated", 1, address, bytes.length, requestedBytes - bytes.length, { requestedBytes, actualBytes: bytes.length }));

  const positive = observations.filter((item) => POSITIVE_OBSERVATION_KINDS.has(item.kind));
  const confidence = calculateLandingConfidence(observations);
  const recommendation = memory.executable === false
    ? "Execution from this page will fault; redirect to executable memory or change the staging strategy."
    : bytes.length === 0
      ? "The landing bytes are inaccessible; verify the address and debugger context."
      : positive.length > 0
        ? "The address has payload-like evidence; validate control flow and the complete byte sequence."
        : "No strong landing signal was found in the sampled bytes.";

  return { address, memory, bytes: Array.from(bytes), requestedBytes, observations, confidence, recommendation };
}

function stackPointer(): bigint | undefined {
  const thread = host.currentThread as Record<string, unknown>;
  const registers = ((thread?.Registers as Record<string, unknown> | undefined)?.User ?? thread?.Registers) as Record<string, unknown> | undefined;
  const names = getPointerSize() === 8 ? ["rsp", "esp"] : ["esp", "rsp"];
  for (const name of names) {
    const value = registers?.[name] ?? registers?.[name.toUpperCase()];
    if (typeof value === "bigint") return value;
    if (typeof value === "number" && Number.isFinite(value)) return BigInt(Math.trunc(value));
    if (typeof value === "string" && /^(0x)?[0-9a-f`]+$/i.test(value)) return BigInt(`0x${value.replace(/^0x/i, "").replace(/`/g, "")}`);
    if (value && typeof value === "object") {
      try {
        const rendered = String(value);
        if (/^(0x)?[0-9a-f`]+$/i.test(rendered)) return BigInt(`0x${rendered.replace(/^0x/i, "").replace(/`/g, "")}`);
      } catch (_error) {
        // Keep searching aliases when a debugger value cannot be rendered.
      }
    }
  }
  return undefined;
}

function readAvailablePrefix(address: bigint, requestedBytes: number): Uint8Array {
  const complete = tryReadMemory(address, requestedBytes);
  if (complete) return complete;

  let low = 0;
  let high = requestedBytes - 1;
  let available: Uint8Array = new Uint8Array();
  while (low <= high) {
    const length = Math.floor((low + high) / 2);
    if (length === 0) {
      low = 1;
      continue;
    }
    const bytes = tryReadMemory(address, length);
    if (bytes) {
      available = bytes;
      low = length + 1;
    } else {
      high = length - 1;
    }
  }
  return available;
}

function canDisassemble(address: bigint): boolean | null {
  try {
    const hostAny = host as unknown as { namespace?: { Debugger?: { Utility?: { Control?: { ExecuteCommand?: (command: string) => unknown } } } } };
    const control = hostAny.namespace?.Debugger?.Utility?.Control;
    if (typeof control?.ExecuteCommand !== "function") return null;
    const lines = Array.from(control.ExecuteCommand.call(control, `u 0x${address.toString(16)} L1`) as Iterable<unknown>).map(String);
    return lines.some((line) => /\b[0-9a-f`]+\s+[0-9a-f]{2}/i.test(line)) && !lines.some((line) => /memory access error|could not be read|unable to/i.test(line));
  } catch (_error) {
    return null;
  }
}

export function landing(address?: bigint, requestedBytes = 64): LandingEvidence {
  const target = address ?? stackPointer();
  if (target === undefined) {
    return { bytes: [], requestedBytes, observations: [], confidence: 0, recommendation: "Stack pointer is unavailable; provide an explicit address." };
  }
  const memory = memoryRegion(target);
  const bytes = readAvailablePrefix(target, requestedBytes);
  return analyzeLandingBytes(target, bytes, memory, requestedBytes, canDisassemble(target));
}
