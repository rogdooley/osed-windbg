import { describe, expect, test } from "vitest";
import { compareBadchars, expectedBytes } from "../src/logic/badchars_logic";

describe("badchars logic", () => {
  test("builds expected bytes while excluding values", () => {
    const values = expectedBytes([0x00, 0x0a, 0x0d]);
    expect(values.includes(0x00)).toBe(false);
    expect(values.includes(0x0a)).toBe(false);
    expect(values.includes(0x0d)).toBe(false);
    expect(values.length).toBe(253);
  });

  test("finds first mismatch and expected next byte", () => {
    const expected = [0x01, 0x02, 0x03, 0x04];
    const observed = Uint8Array.from([0x01, 0x02, 0x41, 0x04]);
    const result = compareBadchars(observed, expected);
    expect(result.breakOffset).toBe(2);
    expect(result.nextExpected).toBe(0x03);
    expect(result.mismatches.length).toBe(1);
  });
});
