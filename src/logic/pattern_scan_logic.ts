import { decodeOffsetNeedle, generateCyclicPattern, generateMsfPattern, MSF_MAX_LENGTH } from "./pattern_logic";

// Comprehensive cyclic-pattern offset scanning ("findmsp"-style). Pure logic: it
// takes already-read values/buffers and locates them inside the MSF and cyclic
// haystacks, carrying a confidence that reflects offset ambiguity within the
// pattern (EXACT = the match is unique, CONSERVATIVE = it repeats).

export type PatternKind = "msf" | "cyclic";
export type MatchConfidence = "EXACT" | "CONSERVATIVE";

// deBruijn(alphabet=62, order=3) length; the largest cyclic pattern we can build.
const CYCLIC_MAX_LENGTH = 62 * 62 * 62;

export interface PatternHaystacks {
  msf: string;
  cyclic: string;
}

export interface RegisterMatch {
  kind: PatternKind;
  offset: number;
  confidence: MatchConfidence;
}

export interface BufferMatch {
  kind: PatternKind;
  offset: number;
  length: number;
  confidence: MatchConfidence;
}

export function buildHaystacks(length: number): PatternHaystacks {
  const requested = Number.isFinite(length) ? Math.trunc(length) : 0;
  return {
    msf: generateMsfPattern(Math.max(4, Math.min(requested, MSF_MAX_LENGTH))),
    cyclic: generateCyclicPattern(Math.max(4, Math.min(Math.max(requested, 20000), CYCLIC_MAX_LENGTH))),
  };
}

function confidenceFor(haystack: string, needle: string, firstOffset: number): MatchConfidence {
  return haystack.indexOf(needle, firstOffset + 1) === -1 ? "EXACT" : "CONSERVATIVE";
}

// Interpret a 32-bit little-endian register value as four pattern characters and
// find where those characters sit in the pattern — i.e. the register was
// overwritten with pattern bytes at the returned offset.
export function matchRegisterValue(low32: number, haystacks: PatternHaystacks): RegisterMatch | undefined {
  const needle = decodeOffsetNeedle(low32 >>> 0);
  for (const kind of ["msf", "cyclic"] as const) {
    const offset = haystacks[kind].indexOf(needle);
    if (offset >= 0) {
      return { kind, offset, confidence: confidenceFor(haystacks[kind], needle, offset) };
    }
  }
  return undefined;
}

function bufferToLatin1(buffer: Uint8Array): string {
  let text = "";
  for (let index = 0; index < buffer.length; index += 1) {
    text += String.fromCharCode(buffer[index]);
  }
  return text;
}

// Locate a memory buffer inside the pattern by matching its leading bytes. Used
// for pointers: a register/SP whose target memory begins with pattern content is
// pointing into the cyclic buffer at the returned offset. Tries the longest
// leading run first (min 4 bytes) so the offset is as unambiguous as possible.
export function locatePatternInBuffer(buffer: Uint8Array, haystacks: PatternHaystacks, maxProbe = 64): BufferMatch | undefined {
  const text = bufferToLatin1(buffer);
  const cap = Math.min(text.length, maxProbe);
  for (const kind of ["msf", "cyclic"] as const) {
    const haystack = haystacks[kind];
    for (let length = cap; length >= 4; length -= 1) {
      const needle = text.slice(0, length);
      const offset = haystack.indexOf(needle);
      if (offset >= 0) {
        return { kind, offset, length, confidence: confidenceFor(haystack, needle, offset) };
      }
    }
  }
  return undefined;
}

// Little-endian 32-bit read from a byte buffer; undefined if out of range.
export function dwordAt(buffer: Uint8Array, index: number): number | undefined {
  if (index < 0 || index + 4 > buffer.length) {
    return undefined;
  }
  return (buffer[index] | (buffer[index + 1] << 8) | (buffer[index + 2] << 16) | (buffer[index + 3] << 24)) >>> 0;
}
