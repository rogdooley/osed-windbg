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
    const expected = expectedBytes([0x00]); // 0x01..0xff
    const junk = [0xde, 0xad, 0xbe, 0xef, 0xca];
    const window = Uint8Array.from([...junk, ...expected]);
    expect(locateExpectedArray(window, expected)).toEqual({ offset: junk.length, matchedRun: expected.length });
  });

  test("locateExpectedArray reports the longest run and tolerates trailing corruption", () => {
    const expected = expectedBytes([0x00]);
    const corrupted = [...expected];
    corrupted[20] = 0xff; // a badchar mangled the byte at offset 20
    const window = Uint8Array.from([0x90, 0x90, ...corrupted]);
    const located = locateExpectedArray(window, expected);
    expect(located?.offset).toBe(2);
    expect(located?.matchedRun).toBe(20); // clean run stops at the corrupted byte
  });

  test("locateExpectedArray returns undefined below the minimum run", () => {
    const expected = expectedBytes([0x00]);
    const window = Uint8Array.from([0x01, 0x02, 0x03, 0xff, 0xff, 0xff]); // only 3 clean bytes
    expect(locateExpectedArray(window, expected, 8)).toBeUndefined();
  });
});
