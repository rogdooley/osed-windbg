import { describe, expect, test } from "vitest";
import { normalizeMemoryRegion, parseVprot, serializeMemoryRegionEvidence } from "../src/analysis/memory";

describe("memory analysis", () => {
  test("normalizes Win32 protection, state, and type flags", () => {
    const evidence = normalizeMemoryRegion(BigInt("0x401000"), {
      state: 0x1000,
      protection: 0x140,
      type: 0x1000000,
    });

    expect(evidence).toMatchObject({
      readable: true,
      writable: true,
      executable: true,
      guarded: true,
      noAccess: false,
      committed: true,
      regionType: "image",
    });
  });

  test("preserves unavailable metadata as unknown", () => {
    const evidence = normalizeMemoryRegion(BigInt("0x41414141"), {}, "unavailable");
    expect(evidence.readable).toBeNull();
    expect(evidence.writable).toBeNull();
    expect(evidence.executable).toBeNull();
    expect(evidence.guarded).toBeNull();
    expect(evidence.noAccess).toBeNull();
    expect(evidence.committed).toBeNull();
    expect(evidence.regionType).toBe("unknown");
  });

  test("parses standard vprot fields including backtick addresses", () => {
    expect(parseVprot([
      "BaseAddress:       00000000`00401000",
      "AllocationBase:   00000000`00400000",
      "RegionSize:       00000000`00002000",
      "State:            00001000 MEM_COMMIT",
      "Protect:          00000020 PAGE_EXECUTE_READ",
      "Type:             01000000 MEM_IMAGE",
    ])).toEqual({
      baseAddress: BigInt("0x401000"),
      allocationBase: BigInt("0x400000"),
      regionSize: BigInt("0x2000"),
      state: 0x1000,
      protection: 0x20,
      allocationProtection: undefined,
      type: 0x1000000,
    });
  });

  test("preserves raw values even when their semantics are unknown", () => {
    const evidence = normalizeMemoryRegion(BigInt("0x401000"), {
      state: 0x2000,
      protection: 0x200,
      allocationProtection: 0x80,
      type: 0x80000,
    });

    expect(evidence.raw).toEqual({
      state: 0x2000,
      protection: 0x200,
      allocationProtection: 0x80,
      type: 0x80000,
    });
    expect(evidence).toMatchObject({
      readable: null,
      writable: null,
      executable: null,
      noAccess: null,
      committed: false,
      regionType: "unknown",
    });
  });

  test("serializes address fields into dx-safe strings", () => {
    const evidence = normalizeMemoryRegion(BigInt("0x625011d3"), {
      baseAddress: BigInt("0x62501000"),
      allocationBase: BigInt("0x62500000"),
      regionSize: BigInt("0x1000"),
      state: 0x1000,
      protection: 0x20,
      type: 0x1000000,
    });

    expect(serializeMemoryRegionEvidence(evidence)).toMatchObject({
      address: "0x00000000625011D3",
      baseAddress: "0x0000000062501000",
      allocationBase: "0x0000000062500000",
      regionSize: "0x1000",
      executable: true,
      regionType: "image",
    });
  });
});
