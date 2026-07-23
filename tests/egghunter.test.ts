import { describe, expect, test } from "vitest";
import { buildEgghunter } from "../src/commands/egghunter";

const NO_BADCHARS: number[] = [];

describe("NtAccess egghunter", () => {
  test("generates 32-byte stub with tag embedded", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: NO_BADCHARS });
    expect(result.size).toBe(32);
    expect(result.badcharHits).toEqual([]);
    // Tag "W00T" = [0x57, 0x30, 0x30, 0x54] at offset 18
    expect(result.bytes[18]).toBe(0x57); // W
    expect(result.bytes[19]).toBe(0x30); // 0
    expect(result.bytes[20]).toBe(0x30); // 0
    expect(result.bytes[21]).toBe(0x54); // T
  });

  test("embeds custom tag correctly", () => {
    const result = buildEgghunter({ tag: "B33F", mode: "ntaccess", wow64: false, badchars: NO_BADCHARS });
    expect(result.bytes[18]).toBe(0x42); // B
    expect(result.bytes[19]).toBe(0x33); // 3
    expect(result.bytes[20]).toBe(0x33); // 3
    expect(result.bytes[21]).toBe(0x46); // F
  });

  test("WoW64 variant uses inc ecx (0x41) instead of inc edx (0x42)", () => {
    const standard = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: NO_BADCHARS });
    const wow64 = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: true, badchars: NO_BADCHARS });
    expect(standard.bytes[5]).toBe(0x42); // inc edx
    expect(wow64.bytes[5]).toBe(0x41);    // inc ecx
  });

  test("reports badchar violations in stub bytes", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: [0x0f, 0xcd] });
    expect(result.badcharHits.length).toBeGreaterThan(0);
    expect(result.badcharHits.some((h) => h.includes("0x0F"))).toBe(true);
    expect(result.badcharHits.some((h) => h.includes("0xCD"))).toBe(true);
  });

  test("reports badchars in the tag itself", () => {
    // Tag "A\x00BC" — null byte in tag
    const result = buildEgghunter({ tag: "A\x00BC", mode: "ntaccess", wow64: false, badchars: [0] });
    expect(result.badcharHits.some((h) => h.includes("0x00"))).toBe(true);
  });
});

describe("SEH egghunter", () => {
  test("generates 70-byte stub with tag embedded", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "seh", wow64: false, badchars: NO_BADCHARS });
    expect(result.size).toBe(70);
    expect(result.badcharHits).toEqual([]);
    // Tag at offset 0x34
    expect(result.bytes[0x34]).toBe(0x57); // W
    expect(result.bytes[0x35]).toBe(0x30); // 0
    expect(result.bytes[0x36]).toBe(0x30); // 0
    expect(result.bytes[0x37]).toBe(0x54); // T
  });

  test("starts with jmp short past handler", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "seh", wow64: false, badchars: NO_BADCHARS });
    expect(result.bytes[0]).toBe(0xeb); // jmp short
    expect(result.bytes[1]).toBe(0x17); // skip 23 bytes of handler
  });

  test("ends with jmp edi (FF E7)", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "seh", wow64: false, badchars: NO_BADCHARS });
    expect(result.bytes[result.size - 2]).toBe(0xff);
    expect(result.bytes[result.size - 1]).toBe(0xe7);
  });

  test("contains null bytes and reports them as badchars", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "seh", wow64: false, badchars: [0] });
    expect(result.badcharHits.length).toBeGreaterThan(0);
    expect(result.badcharHits.some((h) => h.includes("0x00"))).toBe(true);
  });

  test("embeds custom tag at the correct offset", () => {
    const result = buildEgghunter({ tag: "HACK", mode: "seh", wow64: false, badchars: NO_BADCHARS });
    expect(result.bytes[0x34]).toBe(0x48); // H
    expect(result.bytes[0x35]).toBe(0x41); // A
    expect(result.bytes[0x36]).toBe(0x43); // C
    expect(result.bytes[0x37]).toBe(0x4b); // K
  });

  test("scan loop uses or di,0xfff for page alignment", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "seh", wow64: false, badchars: NO_BADCHARS });
    // or di, 0x0FFF at offset 0x2D
    expect(result.bytes[0x2d]).toBe(0x66);
    expect(result.bytes[0x2e]).toBe(0x81);
    expect(result.bytes[0x2f]).toBe(0xcf);
    expect(result.bytes[0x30]).toBe(0xff);
    expect(result.bytes[0x31]).toBe(0x0f);
  });
});

describe("egghunter tag padding", () => {
  test("pads short tags to 4 bytes with X", () => {
    const result = buildEgghunter({ tag: "AB", mode: "ntaccess", wow64: false, badchars: NO_BADCHARS });
    expect(result.bytes[18]).toBe(0x41); // A
    expect(result.bytes[19]).toBe(0x42); // B
    expect(result.bytes[20]).toBe(0x58); // X (padding)
    expect(result.bytes[21]).toBe(0x58); // X (padding)
  });

  test("truncates long tags to 4 bytes", () => {
    const result = buildEgghunter({ tag: "ABCDEF", mode: "ntaccess", wow64: false, badchars: NO_BADCHARS });
    expect(result.bytes[18]).toBe(0x41); // A
    expect(result.bytes[19]).toBe(0x42); // B
    expect(result.bytes[20]).toBe(0x43); // C
    expect(result.bytes[21]).toBe(0x44); // D
  });
});
