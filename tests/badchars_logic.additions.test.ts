import { describe, expect, test } from "vitest";
import { expectedBytes, formatByteArray, locateExpectedArray } from "../src/logic/badchars_logic";

describe("badchar array generation and location", () => {
  test("formatByteArray renders python, c, and hex forms", () => {
    const bytes = [0x01, 0x02, 0xff];
    expect(formatByteArray(bytes, "python")).toBe('b"\\x01\\x02\\xff"');
    expect(formatByteArray(bytes, "c")).toBe('"\\x01\\x02\\xff"');
    expect(formatByteArray(bytes, "hex")).toBe("01 02 ff");
  });

  test("formatByteArray tracks the excluded expected set", () => {
    const expected = expectedBytes([0x00, 0x0a, 0x0d]);
    expect(expected[0]).toBe(0x01);
    expect(expected).not.toContain(0x0a);
    expect(formatByteArray(expected, "hex").startsWith("01 02 03")).toBe(true);
  });

  test("locateExpectedArray finds the array embedded after junk", () => {
    const expected = expectedBytes([0x00]);
    const junk = [0xde, 0xad, 0xbe, 0xef, 0xca];
    const window = Uint8Array.from([...junk, ...expected]);
    const located = locateExpectedArray(window, expected);
    expect(located?.offset).toBe(junk.length);
    expect(located?.matchedRun).toBe(expected.length);
  });

  test("locateExpectedArray finds array with dropped bytes", () => {
    const expected = expectedBytes([]);
    const observed = [
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0b, 0x0c, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    ];
    const window = Uint8Array.from(observed);
    const located = locateExpectedArray(window, expected);
    expect(located).toBeDefined();
    expect(located!.offset).toBe(0);
    expect(located!.expectedStart).toBe(1);
    expect(located!.matchedRun).toBe(9);
  });

  test("locateExpectedArray reports the longest run and tolerates trailing corruption", () => {
    const expected = expectedBytes([0x00]);
    const corrupted = [...expected];
    corrupted[20] = 0xff;
    const window = Uint8Array.from([0x90, 0x90, ...corrupted]);
    const located = locateExpectedArray(window, expected);
    expect(located?.offset).toBe(2);
    expect(located?.matchedRun).toBeGreaterThanOrEqual(20);
  });

  test("locateExpectedArray returns undefined below the minimum run", () => {
    const expected = expectedBytes([0x00]);
    const window = Uint8Array.from([0x01, 0x02, 0x03, 0xff, 0xff, 0xff]);
    expect(locateExpectedArray(window, expected, 8)).toBeUndefined();
  });
});
