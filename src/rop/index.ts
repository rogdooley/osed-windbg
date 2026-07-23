export * from "./types";
export * from "./classifier";
export * from "./scoring";
export * from "./capabilities";
export * from "./query";
export * from "./chain";

import { canonicalizeSequenceForPolicy, composeSemanticSequence } from "../semantics/compose";
import { InstructionSequence, InstructionSequenceSource } from "../semantics/types";
import { InstructionSequenceProvider } from "../semantics/provider";
import { RPPlusProviderOptions, parseRpPlusSequences } from "../semantics/rpplus-provider";
import { AnalysisReason, RopGadget, RopIndex, ROP_SCHEMA_VERSION } from "./types";
import { buildRopGadget } from "./classifier";
import { scoreSemanticSequence } from "./scoring";
import { buildCapabilities, deriveCapabilities } from "./capabilities";

function locationFromSequence(sequence: InstructionSequence) {
  return {
    module: sequence.provenance.module,
    section: sequence.provenance.section,
    virtualAddress: sequence.provenance.virtualAddress,
    fileOffset: sequence.provenance.fileOffset,
    executable: sequence.provenance.executable,
    writable: sequence.provenance.writable,
    aslr: sequence.provenance.aslr,
    rebaseable: sequence.provenance.rebaseable,
    source: sequence.source.name,
  };
}

export function buildRopGadgetFromSequence(sequence: InstructionSequence): RopGadget {
  const semanticSummary = composeSemanticSequence(sequence);
  const classification = buildRopGadget(semanticSummary);
  const scoring = scoreSemanticSequence(semanticSummary, classification.categories);
  const capabilities = deriveCapabilities(semanticSummary, classification.categories);
  return {
    schemaVersion: ROP_SCHEMA_VERSION,
    canonicalId: canonicalizeSequenceForPolicy(sequence),
    instructions: sequence.instructions,
    locations: [locationFromSequence(sequence)],
    semanticSummary,
    categories: classification.categories,
    score: scoring.score,
    scoreReasons: scoring.scoreReasons,
    classificationReasons: classification.classificationReasons,
    capabilities,
  };
}

export function dedupeRopGadgets(gadgets: RopGadget[]): RopGadget[] {
  const byCanonicalId = new Map<string, RopGadget>();
  for (const gadget of gadgets) {
    const existing = byCanonicalId.get(gadget.canonicalId);
    if (!existing) {
      byCanonicalId.set(gadget.canonicalId, gadget);
      continue;
    }
    existing.locations.push(...gadget.locations);
  }
  return [...byCanonicalId.values()];
}

export function buildRopIndexFromSequences(sequences: Iterable<InstructionSequence>): RopIndex {
  const gadgets = dedupeRopGadgets([...sequences].map((sequence) => buildRopGadgetFromSequence(sequence)));
  const byCanonicalId = new Map<string, RopGadget>();
  for (const gadget of gadgets) {
    byCanonicalId.set(gadget.canonicalId, gadget);
  }
  return { gadgets, byCanonicalId };
}

export async function buildRopIndexFromProvider(provider: InstructionSequenceProvider): Promise<RopIndex> {
  const sequences: InstructionSequence[] = [];
  for await (const sequence of provider.load()) {
    sequences.push(sequence);
  }
  return buildRopIndexFromSequences(sequences);
}

export function buildRopIndexFromRpPlusText(text: string, options: RPPlusProviderOptions = {}): RopIndex {
  return buildRopIndexFromSequences(parseRpPlusSequences(text, options));
}

export function buildCapabilityIndexFromRpPlusText(text: string, options: RPPlusProviderOptions = {}) {
  return buildCapabilityIndex(buildRopIndexFromRpPlusText(text, options));
}

export function buildCapabilityIndex(index: RopIndex) {
  return buildCapabilities(index.gadgets);
}

export function buildCapabilityIndexFromSequences(sequences: Iterable<InstructionSequence>) {
  return buildCapabilities(buildRopIndexFromSequences(sequences).gadgets);
}
