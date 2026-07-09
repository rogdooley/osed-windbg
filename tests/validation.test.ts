import { describe, expect, test } from "vitest";
import { normalizeAddress, normalizeByteArray, validateOptions } from "../src/core/validation";

describe("option validation", () => {
  test("rejects unknown keys", () => {
    const result = validateOptions({ length: 10, junk: true }, { length: { type: "number", required: true } });
    expect(result.success).toBe(false);
    expect(result.errors.some((err) => err.path === "junk")).toBe(true);
  });

  test("supports union field types", () => {
    const result = validateOptions({ address: "0x41414141" }, { address: { type: ["number", "string"], required: true } });
    expect(result.success).toBe(true);
  });

  test("normalizes and validates addresses", () => {
    expect(normalizeAddress("0x41414141")).toBe(BigInt("0x41414141"));
    expect(() => normalizeAddress("12345")).toThrow(/Decimal/);
  });

  test("normalizes duplicate byte values with warning", () => {
    const normalized = normalizeByteArray([0x0d, 0x00, 0x0d, 0x0a]);
    expect(normalized.values).toEqual([0x00, 0x0a, 0x0d]);
    expect(normalized.warning).toMatch(/Duplicate/);
  });
});
