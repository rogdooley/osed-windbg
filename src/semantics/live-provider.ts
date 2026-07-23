import { canonicalizeTextSequence, parseInstruction } from "./canonicalize";
import { InstructionSequence, SEMANTIC_SCHEMA_VERSION } from "./types";

// Bridges live gadget discoveries into the semantic pipeline. A LiveGadgetHit is
// a decoded gadget (mnemonic text, in the same form the RP++ adapter produces)
// found at a real address in target memory. Pure construction — no debugger reads
// here — so the whole live -> index -> query path is testable without a host.

export interface LiveGadgetHit {
  mnemonic: string;
  address: bigint;
  module?: string;
}

export function sequenceFromLiveHit(hit: LiveGadgetHit): InstructionSequence {
  const parts = hit.mnemonic
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  const instructions = parts.map((part) => parseInstruction(part));
  const canonical = canonicalizeTextSequence(parts.join(" ; "));
  const addressNumber = Number(hit.address);

  return {
    schemaVersion: SEMANTIC_SCHEMA_VERSION,
    id: `live:${hit.address.toString(16)}:${canonical}`,
    source: { kind: "source-adapter", name: "live", format: "windbg-memory", version: "v1" },
    originalText: `0x${hit.address.toString(16)}: ${parts.join(" ; ")} ;`,
    instructions,
    provenance: {
      module: hit.module,
      // The full address survives in id/originalText; the numeric field is exact
      // for realistic user-space addresses (< 2^53).
      virtualAddress: Number.isSafeInteger(addressNumber) ? addressNumber : undefined,
      // Discovered by scanning executable sections, so executability is proven.
      executable: "EXACT",
      writable: "UNKNOWN",
      aslr: "UNKNOWN",
      rebaseable: "UNKNOWN",
    },
  };
}

export function sequencesFromLiveHits(hits: Iterable<LiveGadgetHit>): InstructionSequence[] {
  return [...hits].map(sequenceFromLiveHit);
}
