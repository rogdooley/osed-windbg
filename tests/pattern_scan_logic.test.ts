import { describe, expect, test } from "vitest";
import { generateMsfPattern } from "../src/logic/pattern_logic";
import { buildHaystacks, dwordAt, locatePatternInBuffer, matchRegisterValue } from "../src/logic/pattern_scan_logic";

const haystacks = buildHaystacks(20000);

function leDwordOf(text: string): number {
  return (text.charCodeAt(0) | (text.charCodeAt(1) << 8) | (text.charCodeAt(2) << 16) | (text.charCodeAt(3) << 24)) >>> 0;
}

function bytesOf(text: string): Uint8Array {
  return Uint8Array.from([...text].map((char) => char.charCodeAt(0)));
}

describe("pattern scan logic", () => {
  test("matchRegisterValue resolves an MSF offset exactly", () => {
    const msf = generateMsfPattern(1000);
    const at = 400;
    const value = leDwordOf(msf.slice(at, at + 4));
    expect(matchRegisterValue(value, haystacks)).toEqual({ kind: "msf", offset: at, confidence: "EXACT" });
  });

  test("matchRegisterValue returns undefined for a value not in any pattern", () => {
    // 0xFFFFFFFF -> four 0xFF bytes, which never appear in the ASCII patterns.
    expect(matchRegisterValue(0xffffffff, haystacks)).toBeUndefined();
  });

  test("matchRegisterValue falls back to the cyclic pattern", () => {
    // Find a 4-char cyclic window that does not occur in the MSF pattern.
    let at = -1;
    for (let index = 0; index + 4 <= 800; index += 1) {
      const window = haystacks.cyclic.slice(index, index + 4);
      if (haystacks.msf.indexOf(window) === -1) {
        at = index;
        break;
      }
    }
    expect(at).toBeGreaterThanOrEqual(0);
    const value = leDwordOf(haystacks.cyclic.slice(at, at + 4));
    const match = matchRegisterValue(value, haystacks);
    expect(match?.kind).toBe("cyclic");
    expect(match?.offset).toBe(at);
  });

  test("locatePatternInBuffer locates pointer targets that begin with pattern content", () => {
    const msf = generateMsfPattern(2000);
    const start = 256;
    const buffer = bytesOf(msf.slice(start, start + 16));
    expect(locatePatternInBuffer(buffer, haystacks)).toEqual({ kind: "msf", offset: start, length: 16, confidence: "EXACT" });
  });

  test("locatePatternInBuffer returns undefined when the buffer does not start with pattern bytes", () => {
    const buffer = Uint8Array.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    expect(locatePatternInBuffer(buffer, haystacks)).toBeUndefined();
  });

  test("dwordAt reads little-endian and bounds-checks", () => {
    const buffer = Uint8Array.from([0x41, 0x61, 0x30, 0x41, 0x62, 0x63]);
    expect(dwordAt(buffer, 0)).toBe(0x41306141);
    expect(dwordAt(buffer, 2)).toBe(0x63624130 >>> 0);
    expect(dwordAt(buffer, 3)).toBeUndefined();
    expect(dwordAt(buffer, -1)).toBeUndefined();
  });
});
