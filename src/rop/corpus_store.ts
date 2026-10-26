import { buildCapabilities, type CapabilityIndex } from "./capabilities";
import type { RopGadget } from "./types";

export const CORPUS_EXPORT_SCHEMA_VERSION = "v1" as const;

export interface CorpusModuleFingerprint {
  name: string;
  path: string;
  base: number;
  size: number;
}

export interface CorpusByteSample {
  address: number;
  bytes: number[];
}

export interface CorpusFingerprint {
  modules: CorpusModuleFingerprint[];
  samples: CorpusByteSample[];
}

export interface ImportedCorpus {
  schemaVersion: typeof CORPUS_EXPORT_SCHEMA_VERSION;
  index: CapabilityIndex;
  fingerprint: CorpusFingerprint;
}

export interface CorpusValidationResult {
  valid: boolean;
  reasons: string[];
}

type StoredCorpus = {
  schemaVersion: typeof CORPUS_EXPORT_SCHEMA_VERSION;
  gadgets: RopGadget[];
  fingerprint: CorpusFingerprint;
};

function isGadget(value: unknown): value is RopGadget {
  if (!value || typeof value !== "object") return false;
  const gadget = value as Partial<RopGadget>;
  return gadget.schemaVersion === "v1"
    && typeof gadget.canonicalId === "string"
    && Array.isArray(gadget.instructions)
    && Array.isArray(gadget.locations)
    && Array.isArray(gadget.categories)
    && !!gadget.semanticSummary
    && Array.isArray(gadget.capabilities);
}

function replacer(_key: string, value: unknown): unknown {
  if (value instanceof Set) return { $set: [...value] };
  return value;
}

function reviver(_key: string, value: unknown): unknown {
  if (value && typeof value === "object" && "$set" in value) {
    const encoded = value as { $set?: unknown };
    if (Array.isArray(encoded.$set)) return new Set(encoded.$set);
  }
  return value;
}

function isFingerprint(value: unknown): value is CorpusFingerprint {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<CorpusFingerprint>;
  return Array.isArray(candidate.modules) && Array.isArray(candidate.samples)
    && candidate.modules.every((module) => module && typeof module.name === "string" && typeof module.path === "string"
      && typeof module.base === "number" && typeof module.size === "number")
    && candidate.samples.every((sample) => sample && typeof sample.address === "number" && Array.isArray(sample.bytes)
      && sample.bytes.every((byte) => typeof byte === "number"));
}

export function exportCorpus(index: CapabilityIndex, fingerprint: CorpusFingerprint): string {
  const stored: StoredCorpus = {
    schemaVersion: CORPUS_EXPORT_SCHEMA_VERSION,
    gadgets: index.gadgets,
    fingerprint,
  };
  return JSON.stringify(stored, replacer, 2);
}

export function importCorpus(text: string): ImportedCorpus {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text, reviver);
  } catch (_error) {
    throw new Error("ROP corpus JSON is invalid.");
  }
  if (!parsed || typeof parsed !== "object") throw new Error("ROP corpus JSON must contain an object.");
  const stored = parsed as Partial<StoredCorpus>;
  if (stored.schemaVersion !== CORPUS_EXPORT_SCHEMA_VERSION) {
    throw new Error(`Unsupported ROP corpus schema '${String(stored.schemaVersion ?? "missing")}'.`);
  }
  if (!Array.isArray(stored.gadgets) || !stored.gadgets.every(isGadget) || !isFingerprint(stored.fingerprint)) {
    throw new Error("ROP corpus JSON is missing gadgets or fingerprint data.");
  }
  return {
    schemaVersion: CORPUS_EXPORT_SCHEMA_VERSION,
    index: buildCapabilities(stored.gadgets as RopGadget[]),
    fingerprint: stored.fingerprint,
  };
}

function sameBytes(left: number[], right: number[]): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

export function validateCorpus(imported: ImportedCorpus, live: CorpusFingerprint): CorpusValidationResult {
  const reasons: string[] = [];
  for (const expected of imported.fingerprint.modules) {
    const observed = live.modules.find((module) => module.name === expected.name && module.path === expected.path);
    if (!observed || observed.base !== expected.base || observed.size !== expected.size) {
      reasons.push(`module ${expected.name} mapping changed`);
    }
  }
  for (const expected of imported.fingerprint.samples) {
    const observed = live.samples.find((sample) => sample.address === expected.address);
    if (!observed || !sameBytes(expected.bytes, observed.bytes)) {
      reasons.push(`gadget bytes changed at 0x${expected.address.toString(16)}`);
    }
  }
  return { valid: reasons.length === 0, reasons };
}
