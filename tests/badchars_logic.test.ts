import { describe, expect, test } from "vitest";
import { compareBadchars, expectedBytes, summarizeBadcharTest } from "../src/logic/badchars_logic";

describe("badchars logic", () => {
  test("builds expected bytes while excluding values", () => {
    const values = expectedBytes([0x00, 0x0a, 0x0d]);
    expect(values.includes(0x00)).toBe(false);
    expect(values.includes(0x0a)).toBe(false);
    expect(values.includes(0x0d)).toBe(false);
    expect(values.length).toBe(253);
  });

  test("detects dropped bytes as bad characters", () => {
    const expected = [0x01, 0x02, 0x03, 0x04, 0x05];
    const observed = Uint8Array.from([0x01, 0x02, 0x04, 0x05]);
    const result = compareBadchars(observed, expected);
    expect(result.badChars).toEqual([0x03]);
    expect(result.survivorCount).toBe(4);
    expect(result.expectedConsumed).toBe(5);
  });

  test("detects multiple dropped bytes", () => {
    const expected = expectedBytes([]);
    const observed = Uint8Array.from([
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0b, 0x0c, 0x0e, 0x0f, 0x10,
    ]);
    const result = compareBadchars(observed, expected);
    expect(result.badChars).toContain(0x00);
    expect(result.badChars).toContain(0x0a);
    expect(result.badChars).toContain(0x0d);
    expect(result.survivorCount).toBe(14);
  });

  test("detects bytes rewritten to lower-valued replacements", () => {
    const expected = [0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81];
    const observed = Uint8Array.from([0x79, 0x7a, 0x7b, 0x2f, 0x7d, 0x7e, 0x7f, 0x3f, 0x81]);
    const result = compareBadchars(observed, expected);

    expect(result.badChars).toEqual([0x7c, 0x80]);
    expect(result.mismatches).toEqual([
      { offset: 3, expected: 0x7c, observed: 0x2f },
      { offset: 7, expected: 0x80, observed: 0x3f },
    ]);
    expect(result.survivorCount).toBe(7);
    expect(result.expectedConsumed).toBe(9);
  });

  test("reports no bad chars when all bytes survive", () => {
    const expected = [0x01, 0x02, 0x03, 0x04];
    const observed = Uint8Array.from([0x01, 0x02, 0x03, 0x04]);
    const result = compareBadchars(observed, expected);
    expect(result.badChars).toEqual([]);
    expect(result.survivorCount).toBe(4);
    expect(result.expectedConsumed).toBe(4);
  });

  test("handles truncated array with trailing junk", () => {
    const expected = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    const observed = Uint8Array.from([0x01, 0x02, 0x03, 0x00, 0x00]);
    const result = compareBadchars(observed, expected);
    expect(result.survivorCount).toBe(3);
    expect(result.expectedConsumed).toBe(3);
  });

  test("keeps caller exclusions separate from tested and untested bytes", () => {
    const expected = expectedBytes([0x00, 0xff]);
    const compared = compareBadchars(Uint8Array.from(expected.slice(0, 4)), expected);
    expect(summarizeBadcharTest([0x00, 0xff], expected, compared)).toMatchObject({
      candidateCount: 256,
      excluded: [0x00, 0xff],
      testedCount: 4,
      survivedCount: 4,
      corrupted: [],
    });
    expect(summarizeBadcharTest([0x00, 0xff], expected, compared).untestedInThisTest).not.toContain(0xff);
  });
});
