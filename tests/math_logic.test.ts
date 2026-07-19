import { describe, expect, test } from "vitest";
import { analyzeMathValue } from "../src/logic/math_logic";

describe("math logic", () => {
  test("formats negative values as 32-bit two's complement", () => {
    expect(analyzeMathValue(-42, 32)).toMatchObject({
      bits: 32,
      hex: "0xFFFFFFD6",
      unsigned: "4294967254",
      signed: "-42",
      littleEndianBytes: "D6 FF FF FF",
      twosComplement: "0xFFFFFFD6",
    });
  });

  test("interprets high-bit hex as signed within the selected width", () => {
    expect(analyzeMathValue("0xFFFFFFD6", 32)).toMatchObject({
      unsigned: "4294967254",
      signed: "-42",
      littleEndianBytes: "D6 FF FF FF",
    });
  });

  test("formats common x86 addresses as unsigned positive dwords", () => {
    expect(analyzeMathValue("0x625011D3", 32)).toMatchObject({
      hex: "0x625011D3",
      unsigned: "1649414611",
      signed: "1649414611",
      littleEndianBytes: "D3 11 50 62",
    });
  });

  test("supports 64-bit values and little-endian byte order", () => {
    expect(analyzeMathValue("0x1122334455667788", 64)).toMatchObject({
      hex: "0x1122334455667788",
      littleEndianBytes: "88 77 66 55 44 33 22 11",
      twosComplement: "0x1122334455667788",
    });
  });
});
