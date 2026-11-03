import { generateCyclicPattern, generateMsfPattern } from "../logic/pattern_logic";

export interface PatternEvidence {
  address: bigint;
  patternFamily: "msf" | "cyclic" | null;
  matched: boolean;
  matchLength: number;
  patternOffset: number | null;
  confidence: number;
  source: "sampled-memory";
}

/** Observes a pattern in sampled bytes; it does not establish total controlled capacity. */
export function analyzePatternEvidence(address: bigint, bytes: Uint8Array, maxWindow = 32): PatternEvidence {
  const text = String.fromCharCode(...bytes);
  for (const candidate of [
    { family: "msf" as const, value: generateMsfPattern(20280) },
    { family: "cyclic" as const, value: generateCyclicPattern(20000) },
  ]) {
    for (let length = Math.min(bytes.length, maxWindow); length >= 8; length -= 1) {
      for (let offset = 0; offset <= text.length - length; offset += 1) {
        const patternOffset = candidate.value.indexOf(text.slice(offset, offset + length));
        if (patternOffset >= 0) return { address: address + BigInt(offset), patternFamily: candidate.family, matched: true, matchLength: length, patternOffset, confidence: 0.9, source: "sampled-memory" };
      }
    }
  }
  return { address, patternFamily: null, matched: false, matchLength: 0, patternOffset: null, confidence: 0, source: "sampled-memory" };
}
