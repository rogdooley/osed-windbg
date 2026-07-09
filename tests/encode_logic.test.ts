import { describe, expect, test } from "vitest";
import {
  buildXorStub,
  findXorKey,
  parseShellcodeHex,
  xorEncode,
} from "../src/commands/encode";

describe("parseShellcodeHex", () => {
  test("parses space-separated hex string", () => {
    expect(parseShellcodeHex("fc e8 82 00")).toEqual([0xfc, 0xe8, 0x82, 0x00]);
  });

  test("parses hex string without separators", () => {
    expect(parseShellcodeHex("fce88200")).toEqual([0xfc, 0xe8, 0x82, 0x00]);
  });

  test("parses byte array input unchanged", () => {
    expect(parseShellcodeHex([0xfc, 0xe8])).toEqual([0xfc, 0xe8]);
  });

  test("masks array values to byte range", () => {
    expect(parseShellcodeHex([0x100, 0x1ff])).toEqual([0x00, 0xff]);
  });

  test("throws for empty string", () => {
    expect(() => parseShellcodeHex("")).toThrow(/non-empty/);
  });

  test("throws for odd-length hex string", () => {
    expect(() => parseShellcodeHex("abc")).toThrow(/even/);
  });
});

describe("xorEncode", () => {
  test("XOR encodes each byte with key", () => {
    expect(xorEncode([0x00, 0xff, 0xaa], 0xaa)).toEqual([0xaa, 0x55, 0x00]);
  });

  test("is its own inverse (decoding = re-encoding)", () => {
    const key = 0x41;
    const original = [0x01, 0x02, 0x03, 0x04];
    expect(xorEncode(xorEncode(original, key), key)).toEqual(original);
  });
});

describe("findXorKey", () => {
  test("auto-selects a key not in exclude and producing no excluded bytes", () => {
    const shellcode = [0x41, 0x42, 0x43];
    const exclude = new Set([0x00, 0x0a, 0x0d]);
    const key = findXorKey(shellcode, exclude);
    expect(key).toBeDefined();
    expect(exclude.has(key!)).toBe(false);
    for (const b of xorEncode(shellcode, key!)) {
      expect(exclude.has(b)).toBe(false);
    }
  });

  test("returns hint key when it produces no excluded bytes", () => {
    const shellcode = [0x01, 0x02];
    const exclude = new Set([0x00]);
    const key = findXorKey(shellcode, exclude, 0x10);
    expect(key).toBe(0x10);
  });

  test("returns undefined when hint key produces an excluded byte", () => {
    // XOR 0x01 with 0x01 = 0x00, which is excluded
    const key = findXorKey([0x01], new Set([0x00]), 0x01);
    expect(key).toBeUndefined();
  });

  test("returns undefined when no valid key exists", () => {
    // Shellcode byte 0x00: XOR with key K = K. If ALL keys are excluded, no solution.
    // Exclude all values 1-255 — impossible to find a non-zero non-excluded key.
    const allBytes = new Set(Array.from({ length: 256 }, (_, i) => i));
    expect(findXorKey([0x41], allBytes)).toBeUndefined();
  });

  test("skips key 0x00 (null)", () => {
    // Key 0 would XOR every byte with 0 (no-op), but key=0 is never a valid XOR key here.
    const shellcode = [0x41];
    const exclude = new Set([0x00]);
    const key = findXorKey(shellcode, exclude);
    expect(key).not.toBe(0);
  });
});

describe("buildXorStub", () => {
  test("short stub (len<=255) is 21 bytes", () => {
    expect(buildXorStub(0x41, 100)).toHaveLength(21);
    expect(buildXorStub(0x41, 255)).toHaveLength(21);
    expect(buildXorStub(0x41, 1)).toHaveLength(21);
  });

  test("long stub (len>255) is 23 bytes", () => {
    expect(buildXorStub(0x41, 256)).toHaveLength(23);
    expect(buildXorStub(0x41, 512)).toHaveLength(23);
    expect(buildXorStub(0x41, 65535)).toHaveLength(23);
  });

  test("short stub: key at stub[9], len at stub[6]", () => {
    const stub = buildXorStub(0xbb, 0x7f);
    expect(stub[6]).toBe(0x7f);  // MOV CL, len
    expect(stub[9]).toBe(0xbb);  // XOR [ESI], key
  });

  test("long stub: hi at stub[6], lo at stub[8], key at stub[11]", () => {
    // len = 0x0154 = 340 → hi=0x01, lo=0x54
    const stub = buildXorStub(0x41, 0x0154);
    expect(stub[6]).toBe(0x01);  // MOV CH, hi
    expect(stub[8]).toBe(0x54);  // MOV CL, lo
    expect(stub[11]).toBe(0x41); // XOR [ESI], key
  });

  test("short stub fixed bytes avoid 0x00, 0x0A, 0x0D", () => {
    const stub = buildXorStub(0x01, 0x01);
    const bad = new Set([0x00, 0x0a, 0x0d]);
    // Variable slots: stub[6]=len, stub[9]=key — skip those
    [0, 1, 2, 3, 4, 5, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20].forEach((i) => {
      expect(bad.has(stub[i])).toBe(false);
    });
  });

  test("long stub fixed bytes avoid 0x00, 0x0A, 0x0D", () => {
    // hi=0x01, lo=0x54, key=0x01 — none in {0,0x0a,0x0d}
    const stub = buildXorStub(0x01, 0x0154);
    const bad = new Set([0x00, 0x0a, 0x0d]);
    // Variable slots: stub[6]=hi, stub[8]=lo, stub[11]=key
    [0, 1, 2, 3, 4, 5, 7, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22].forEach((i) => {
      expect(bad.has(stub[i])).toBe(false);
    });
  });

  test("short stub starts EB 0E (JMP SHORT to CALL at offset 16)", () => {
    const stub = buildXorStub(0x41, 50);
    expect(stub[0]).toBe(0xeb);
    expect(stub[1]).toBe(0x0e);
  });

  test("long stub starts EB 10 (JMP SHORT to CALL at offset 18)", () => {
    const stub = buildXorStub(0x41, 300);
    expect(stub[0]).toBe(0xeb);
    expect(stub[1]).toBe(0x10);
  });
});
