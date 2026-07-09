import { describe, expect, test } from "vitest";
import { MSF_MAX_LENGTH, decodeOffsetNeedle, generateCyclicPattern, generateMsfPattern } from "../src/logic/pattern_logic";

describe("pattern logic", () => {
  test("generates msf pattern with requested length", () => {
    const pattern = generateMsfPattern(30);
    expect(pattern.length).toBe(30);
    expect(pattern.startsWith("Aa0Aa1Aa2")).toBe(true);
  });

  test("respects msf max length constant", () => {
    const pattern = generateMsfPattern(MSF_MAX_LENGTH + 500);
    expect(pattern.length).toBe(MSF_MAX_LENGTH);
  });

  test("generates cyclic pattern deterministically", () => {
    const a = generateCyclicPattern(256);
    const b = generateCyclicPattern(256);
    expect(a).toBe(b);
    expect(a.length).toBe(256);
  });

  test("decodes little-endian numeric crash value", () => {
    expect(decodeOffsetNeedle(0x41326341)).toBe("Ac2A");
  });

  test("decodes raw hex string value", () => {
    expect(decodeOffsetNeedle("41326341")).toBe("Ac2A");
    expect(() => decodeOffsetNeedle("GARBAGE")).toThrow(/hex/i);
  });

  test("cyclic pattern throws when length exceeds De Bruijn sequence", () => {
    expect(generateCyclicPattern(10).length).toBe(10);
    expect(() => generateCyclicPattern(300000)).toThrow(/exceeds/i);
  });
});
