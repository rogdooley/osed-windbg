import { buildCapabilities, type CapabilityIndex } from "./capabilities";
import { canonicalizeSequenceForPolicy, composeSemanticSequence } from "../semantics/compose";
import { parseInstruction } from "../semantics/canonicalize";
import { SEMANTIC_SCHEMA_VERSION, type InstructionSequence } from "../semantics/types";
import { buildRopGadget } from "./classifier";
import { deriveCapabilities } from "./capabilities";
import { scoreSemanticSequence } from "./scoring";
import { ROP_SCHEMA_VERSION, type GadgetLocation, type RopGadget } from "./types";

export const CORPUS_EXPORT_SCHEMA_VERSION = "v2" as const;
const LEGACY_CORPUS_EXPORT_SCHEMA_VERSION = "v1" as const;

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
  schemaVersion: typeof LEGACY_CORPUS_EXPORT_SCHEMA_VERSION;
  gadgets: RopGadget[];
  fingerprint: CorpusFingerprint;
};

type CompactGadget = {
  instructions: string[];
  locations: GadgetLocation[];
};

type CompactStoredCorpus = {
  schemaVersion: typeof CORPUS_EXPORT_SCHEMA_VERSION;
  gadgets: CompactGadget[];
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

function isCompactGadget(value: unknown): value is CompactGadget {
  if (!value || typeof value !== "object") return false;
  const gadget = value as Partial<CompactGadget>;
  return Array.isArray(gadget.instructions)
    && gadget.instructions.length > 0
    && gadget.instructions.every((instruction) => typeof instruction === "string" && instruction.trim().length > 0)
    && Array.isArray(gadget.locations)
    && gadget.locations.every((location) => location && typeof location === "object");
}

function compactGadget(gadget: RopGadget): CompactGadget {
  return {
    // Semantic summaries, classifications, scores, and capabilities are all
    // deterministic products of these instructions. Persisting them made an
    // archive much larger without preserving any additional corpus input.
    instructions: gadget.instructions.map((instruction) => instruction.normalizedText || instruction.originalText),
    locations: gadget.locations,
  };
}

function rehydrateGadget(stored: CompactGadget): RopGadget {
  const instructions = stored.instructions.map((instruction) => parseInstruction(instruction));
  const firstLocation = stored.locations[0] ?? {};
  const sequence: InstructionSequence = {
    schemaVersion: SEMANTIC_SCHEMA_VERSION,
    id: `corpus:${stored.instructions.join(" ; ")}`,
    source: {
      kind: "corpus-import",
      name: firstLocation.source ?? "corpus-import",
      format: "corpus",
      version: "v2",
    },
    originalText: stored.instructions.join(" ; "),
    instructions,
    provenance: {
      module: firstLocation.module,
      section: firstLocation.section,
      virtualAddress: firstLocation.virtualAddress,
      fileOffset: firstLocation.fileOffset,
      executable: (firstLocation.executable as InstructionSequence["provenance"]["executable"]) ?? "UNKNOWN",
      writable: (firstLocation.writable as InstructionSequence["provenance"]["writable"]) ?? "UNKNOWN",
      aslr: (firstLocation.aslr as InstructionSequence["provenance"]["aslr"]) ?? "UNKNOWN",
      rebaseable: (firstLocation.rebaseable as InstructionSequence["provenance"]["rebaseable"]) ?? "UNKNOWN",
    },
  };
  const semanticSummary = composeSemanticSequence(sequence);
  const classification = buildRopGadget(semanticSummary);
  const scoring = scoreSemanticSequence(semanticSummary, classification.categories);
  return {
    schemaVersion: ROP_SCHEMA_VERSION,
    canonicalId: canonicalizeSequenceForPolicy(sequence),
    instructions,
    locations: stored.locations,
    semanticSummary,
    categories: classification.categories,
    score: scoring.score,
    scoreReasons: scoring.scoreReasons,
    classificationReasons: classification.classificationReasons,
    capabilities: deriveCapabilities(semanticSummary, classification.categories),
  };
}

export function exportCorpus(index: CapabilityIndex, fingerprint: CorpusFingerprint): string {
  const stored: CompactStoredCorpus = {
    schemaVersion: CORPUS_EXPORT_SCHEMA_VERSION,
    gadgets: index.gadgets.map(compactGadget),
    fingerprint,
  };
  return JSON.stringify(stored);
}

export function importCorpus(text: string): ImportedCorpus {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text, reviver);
  } catch (_error) {
    throw new Error("ROP corpus JSON is invalid.");
  }
  if (!parsed || typeof parsed !== "object") throw new Error("ROP corpus JSON must contain an object.");
  const stored = parsed as Partial<StoredCorpus | CompactStoredCorpus>;
  if (stored.schemaVersion !== CORPUS_EXPORT_SCHEMA_VERSION && stored.schemaVersion !== LEGACY_CORPUS_EXPORT_SCHEMA_VERSION) {
    throw new Error(`Unsupported ROP corpus schema '${String(stored.schemaVersion ?? "missing")}'.`);
  }
  if (!Array.isArray(stored.gadgets) || !isFingerprint(stored.fingerprint)) {
    throw new Error("ROP corpus JSON is missing gadgets or fingerprint data.");
  }
  const gadgets = stored.schemaVersion === CORPUS_EXPORT_SCHEMA_VERSION
    ? stored.gadgets.every(isCompactGadget) ? stored.gadgets.map(rehydrateGadget) : undefined
    : stored.gadgets.every(isGadget) ? stored.gadgets as RopGadget[] : undefined;
  if (!gadgets) throw new Error("ROP corpus JSON is missing gadgets or fingerprint data.");
  return {
    schemaVersion: CORPUS_EXPORT_SCHEMA_VERSION,
    index: buildCapabilities(gadgets),
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
