import { describe, expect, test } from "vitest";
import { findAllByteMatches } from "../src/logic/byte_matcher";

describe("byte matcher", () => {
  test("returns all matching offsets", () => {
    const buffer = Uint8Array.from([0x90, 0x58, 0xc3, 0x90, 0x58, 0xc3]);
    const pattern = Uint8Array.from([0x58, 0xc3]);
    expect(findAllByteMatches(buffer, pattern)).toEqual([1, 4]);
  });

  test("returns empty when pattern longer than buffer", () => {
    expect(findAllByteMatches(Uint8Array.from([0x01]), Uint8Array.from([0x01, 0x02]))).toEqual([]);
  });
});
