import { describe, expect, test, vi } from "vitest";
import { classifySlot, type StackSlot } from "../src/analysis/stackmap";
import { generateMsfPattern, generateCyclicPattern } from "../src/logic/pattern_logic";

vi.mock("../src/commands/modules", () => ({
  findModuleByAddress: (address: bigint) => {
    const vulnBase = BigInt("0x62500000");
    const vulnEnd = vulnBase + BigInt(0x10000);
    if (address >= vulnBase && address < vulnEnd) {
      return {
        name: "vulnserver",
        base: vulnBase,
        size: BigInt(0x10000),
        path: "vulnserver.exe",
        aslr: "disabled",
        nxcompat: "disabled",
        safeseh: "disabled",
        system: false,
      };
    }
    return undefined;
  },
  listModulesWithMitigations: () => [],
}));

vi.mock("../src/core/memory", () => ({
  getPointerSize: () => 4 as 4 | 8,
  readPointer: () => BigInt(0),
  tryReadMemory: (address: bigint, length: number) => {
    const callAddr = BigInt("0x625011FE");
    if (address === callAddr && length >= 5) {
      return Uint8Array.from([0xe8, 0x12, 0x34, 0x56, 0x78]);
    }
    const noCallAddr = BigInt("0x62501300");
    if (address >= noCallAddr && address < noCallAddr + BigInt(10)) {
      return Uint8Array.from([0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
    }
    return undefined;
  },
  readMemory: () => new Uint8Array(),
}));

const haystacks = {
  msf: generateMsfPattern(20280),
  cyclic: generateCyclicPattern(20000),
};

const sp = BigInt("0x0184FA30");
const stackEnd = sp + BigInt(0x2000);

function classify(offset: number, value: bigint): StackSlot {
  const address = sp + BigInt(offset);
  return classifySlot(offset, address, value, 4, sp, stackEnd, haystacks);
}

describe("stackmap slot classification", () => {
  test("classifies null as NULL", () => {
    const slot = classify(0, BigInt(0));
    expect(slot.classification).toBe("NULL");
    expect(slot.detail).toBe("frame boundary");
  });

  test("classifies MSF pattern bytes as PATTERN with offset", () => {
    const patternStr = haystacks.msf;
    const dword =
      patternStr.charCodeAt(100) |
      (patternStr.charCodeAt(101) << 8) |
      (patternStr.charCodeAt(102) << 16) |
      (patternStr.charCodeAt(103) << 24);
    const slot = classify(0, BigInt(dword >>> 0));
    expect(slot.classification).toBe("PATTERN");
    expect(slot.patternKind).toBe("msf");
    expect(slot.patternOffset).toBe(100);
  });

  test("classifies cyclic pattern bytes as PATTERN", () => {
    const patternStr = haystacks.cyclic;
    const dword =
      patternStr.charCodeAt(200) |
      (patternStr.charCodeAt(201) << 8) |
      (patternStr.charCodeAt(202) << 16) |
      (patternStr.charCodeAt(203) << 24);
    const slot = classify(0, BigInt(dword >>> 0));
    expect(slot.classification).toBe("PATTERN");
    expect(slot.patternKind).toBe("cyclic");
    expect(slot.patternOffset).toBe(200);
  });

  test("classifies value pointing into stack as SAVED_EBP", () => {
    const value = sp + BigInt(0x100);
    const slot = classify(0x40, value);
    expect(slot.classification).toBe("SAVED_EBP");
    expect(slot.detail).toBe("points into stack");
  });

  test("classifies module pointer with verified CALL as RET", () => {
    const returnAddr = BigInt("0x62501203");
    const slot = classify(0x58, returnAddr);
    expect(slot.classification).toBe("RET");
    expect(slot.callSiteVerified).toBe(true);
    expect(slot.module).toBe("vulnserver");
    expect(slot.detail).toContain("CALL verified");
  });

  test("classifies module pointer without CALL site as STALE_PTR", () => {
    const staleAddr = BigInt("0x62501305");
    const slot = classify(0x60, staleAddr);
    expect(slot.classification).toBe("STALE_PTR");
    expect(slot.callSiteVerified).toBe(false);
    expect(slot.module).toBe("vulnserver");
    expect(slot.detail).toContain("no CALL site");
  });

  test("classifies unknown non-zero value as DATA", () => {
    const slot = classify(0x10, BigInt(0x00000002));
    expect(slot.classification).toBe("DATA");
    expect(slot.detail).toBe("local / arg");
  });

  test("pattern classification takes priority over stack pointer range", () => {
    const patternStr = haystacks.msf;
    const offsetInStack = 0x50;
    const dword =
      patternStr.charCodeAt(0) |
      (patternStr.charCodeAt(1) << 8) |
      (patternStr.charCodeAt(2) << 16) |
      (patternStr.charCodeAt(3) << 24);
    const fakeValue = BigInt(dword >>> 0);
    const slot = classify(offsetInStack, fakeValue);
    expect(slot.classification).toBe("PATTERN");
  });
});
