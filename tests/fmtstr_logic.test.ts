import { describe, expect, test } from "vitest";
import { buildFormatString, parseU32, FmtWidth } from "../src/logic/fmtstr_logic";

const MOD: Record<FmtWidth, number> = { byte: 0x100, word: 0x10000, dword: 0x100000000 };

// Simulate a printf pass over the built payload and reconstruct the writes it performs.
// Proves the address-block accounting, padding math, and positional args are all correct.
function simulate(result: ReturnType<typeof buildFormatString>, argIndex: number, prefix: number, width: FmtWidth): Map<number, number> {
  const mod = MOD[width];
  const mem = new Map<number, number>();
  let count = prefix + result.addressBlock.length;

  const re = /%(\d+)c|%(\d+)\$(hhn|hn|n)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(result.formatString)) !== null) {
    if (match[1] !== undefined) {
      count += Number.parseInt(match[1], 10); // %<pad>c prints pad chars
    } else {
      const arg = Number.parseInt(match[2], 10);
      const slot = arg - argIndex;
      const targetAddr = result.addressDwords[slot];
      mem.set(targetAddr, count % mod);
    }
  }
  return mem;
}

describe("parseU32", () => {
  test("parses hex numbers, decimal strings, and JS numbers", () => {
    expect(parseU32(0x402118)).toBe(0x402118);
    expect(parseU32("0x625011AF")).toBe(0x625011af);
    expect(parseU32("100")).toBe(100); // digit-only string is decimal (matches toBigInt convention)
    expect(parseU32("deadbeef")).toBe(0xdeadbeef); // letters present → hex
  });

  test("masks to 32 bits", () => {
    expect(parseU32(0xffffffff)).toBe(0xffffffff);
  });
});

describe("buildFormatString — word mode", () => {
  test("classic single dword write accounts for the address block", () => {
    const result = buildFormatString({
      writes: [{ addr: 0x00402118, value: 0x625011af }],
      argIndex: 6,
      width: "word",
    });
    // Two 16-bit chunks: 0x11AF @ 0x402118 (arg 6), 0x6250 @ 0x40211A (arg 7).
    // Address block is 8 bytes, so the first pad is 0x11AF - 8 = 4519, NOT 4527.
    expect(result.formatString).toBe("%4519c%6$hn%20641c%7$hn");
    expect(result.addressDwords).toEqual([0x00402118, 0x0040211a]);
  });

  test("emitted payload reconstructs the requested write", () => {
    const writes = [{ addr: 0x00402118, value: 0x625011af }];
    const result = buildFormatString({ writes, argIndex: 6, width: "word" });
    const mem = simulate(result, 6, 0, "word");
    // low word to addr, high word to addr+2
    expect(mem.get(0x00402118)).toBe(0x11af);
    expect(mem.get(0x0040211a)).toBe(0x6250);
  });

  test("prefix bytes shift the padding", () => {
    const result = buildFormatString({
      writes: [{ addr: 0x00402118, value: 0x625011af }],
      argIndex: 6,
      width: "word",
      prefix: 4,
    });
    // start count = 4 (prefix) + 8 (address block) = 12; first pad = 0x11AF - 12 = 4515
    expect(result.rows[0].specifier.startsWith("%4515c")).toBe(true);
    const mem = simulate(result, 6, 4, "word");
    expect(mem.get(0x00402118)).toBe(0x11af);
    expect(mem.get(0x0040211a)).toBe(0x6250);
  });

  test("multiple writes reconstruct correctly", () => {
    const writes = [
      { addr: 0x00402118, value: 0x625011af },
      { addr: 0x00403000, value: 0x41424344 },
    ];
    const result = buildFormatString({ writes, argIndex: 10, width: "word" });
    const mem = simulate(result, 10, 0, "word");
    expect(mem.get(0x00402118)).toBe(0x11af);
    expect(mem.get(0x0040211a)).toBe(0x6250);
    expect(mem.get(0x00403000)).toBe(0x4344);
    expect(mem.get(0x00403002)).toBe(0x4142);
  });

  test("every row's cumulative count matches its target chunk value", () => {
    const result = buildFormatString({
      writes: [{ addr: 0x00402118, value: 0x625011af }],
      argIndex: 6,
      width: "word",
    });
    for (const row of result.rows) {
      expect(row.cumCount % MOD.word).toBe(row.value);
    }
  });

  test("formatString is the concatenation of row specifiers", () => {
    const result = buildFormatString({
      writes: [{ addr: 0x00402118, value: 0x625011af }],
      argIndex: 6,
      width: "word",
    });
    expect(result.rows.map((r) => r.specifier).join("")).toBe(result.formatString);
  });
});

describe("buildFormatString — byte and dword modes", () => {
  test("byte mode produces four %hhn writes and reconstructs", () => {
    const writes = [{ addr: 0x00402118, value: 0x04030201 }];
    const result = buildFormatString({ writes, argIndex: 6, width: "byte" });
    expect(result.addressDwords.length).toBe(4);
    expect(result.formatString).toContain("$hhn");
    const mem = simulate(result, 6, 0, "byte");
    expect(mem.get(0x00402118)).toBe(0x01);
    expect(mem.get(0x00402119)).toBe(0x02);
    expect(mem.get(0x0040211a)).toBe(0x03);
    expect(mem.get(0x0040211b)).toBe(0x04);
  });

  test("dword mode produces one %n write", () => {
    const result = buildFormatString({ writes: [{ addr: 0x00402118, value: 0x100 }], argIndex: 6, width: "dword" });
    expect(result.addressDwords).toEqual([0x00402118]);
    expect(result.formatString).toContain("$n");
    const mem = simulate(result, 6, 0, "dword");
    expect(mem.get(0x00402118)).toBe(0x100);
  });
});

describe("buildFormatString — validation and warnings", () => {
  test("rejects argIndex < 1", () => {
    expect(() => buildFormatString({ writes: [{ addr: 1, value: 2 }], argIndex: 0 })).toThrow(/argIndex/);
  });

  test("rejects empty writes", () => {
    expect(() => buildFormatString({ writes: [], argIndex: 6 })).toThrow(/at least one/);
  });

  test("warns when a target address contains a badchar", () => {
    const result = buildFormatString({
      writes: [{ addr: 0x00402100, value: 0x11111111 }], // low byte 0x00
      argIndex: 6,
      width: "word",
      exclude: [0x00],
    });
    expect(result.warnings.some((w) => /badchar 0x00/.test(w))).toBe(true);
  });

  test("warns on huge padding suggesting a narrower width", () => {
    // dword mode needs padding up to the full 32-bit value → enormous (> 0x10000 threshold).
    const result = buildFormatString({ writes: [{ addr: 0x00402118, value: 0x00020000 }], argIndex: 6, width: "dword" });
    expect(result.warnings.some((w) => /narrower width/.test(w))).toBe(true);
  });
});
