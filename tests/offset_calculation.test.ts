import { describe, expect, test } from "vitest";
import { generateMsfPattern, decodeOffsetNeedle } from "../src/logic/pattern_logic";

describe("offset calculation", () => {
  test("finds known msf offset from little-endian value", () => {
    const pattern = generateMsfPattern(5000);
    const target = pattern.slice(1200, 1204);
    const value =
      target.charCodeAt(0) |
      (target.charCodeAt(1) << 8) |
      (target.charCodeAt(2) << 16) |
      (target.charCodeAt(3) << 24);

    const needle = decodeOffsetNeedle(value >>> 0);
    const offset = pattern.indexOf(needle);
    expect(offset).toBe(1200);
  });
});
