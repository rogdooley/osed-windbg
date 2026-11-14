import { describe, expect, test } from "vitest";
import { planApiResolution } from "../src/rop/api_plan";

const target = {
  module: "KERNEL32.DLL",
  symbol: "WriteProcessMemory",
  address: BigInt(0x765861c0),
  exportRva: 0x361c0,
};

const common = {
  ownerModule: "libspp.dll",
  ownerBase: BigInt(0x10000000),
  ownerImageBase: BigInt(0x10000000),
  actualModule: "KERNEL32.DLL",
  actualModuleBase: BigInt(0x76550000),
};

describe("planApiResolution", () => {
  test("prefers a byte-safe validated direct slot", () => {
    const candidates = planApiResolution(target, [{
      ...common,
      slot: BigInt(0x101680ac), pointer: target.address, importedSymbol: "WriteProcessMemory",
    }], [0x00, 0x0a]);
    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({ strategy: "direct-slot", state: "ENCODABLE", exportRvaVerified: true, slotPayloadSafe: true });
  });

  test("keeps a validated direct slot when its payload word contains a badchar", () => {
    const candidates = planApiResolution(target, [{
      ...common,
      slot: BigInt(0x10008000), pointer: target.address, importedSymbol: "WriteProcessMemory",
    }], [0x00]);
    expect(candidates[0]).toMatchObject({ strategy: "direct-slot", state: "ADDRESS_VALIDATED", slotPayloadSafe: false });
    expect(candidates[0].recommendation).toContain("requires address construction");
  });

  test("only accepts an exact same-image export as a derived anchor", () => {
    const candidates = planApiResolution(target, [{
      ...common,
      slot: BigInt(0x101680ac), pointer: BigInt(0x76573f30), importedSymbol: "ReadFile",
      nearestSymbol: "ReadFile", nearestOffset: BigInt(0),
    }, {
      ...common,
      slot: BigInt(0x101680b0), pointer: BigInt(0x76573f31), importedSymbol: "ReadFile",
      nearestSymbol: "ReadFile", nearestOffset: BigInt(1),
    }], [0x00]);
    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({ strategy: "derived-address", state: "ENCODABLE" });
    expect(candidates[0].anchor?.delta).toBe(BigInt(0x12290));
  });

  test("does not treat a forwarded/outside-module import as a same-image anchor", () => {
    const candidates = planApiResolution(target, [{
      ...common,
      actualModule: "ntdll.dll", actualModuleBase: BigInt(0x77c00000),
      slot: BigInt(0x10168078), pointer: BigInt(0x77c61f00), importedSymbol: "HeapAlloc",
      nearestSymbol: "RtlAllocateHeap", nearestOffset: BigInt(0),
    }]);
    expect(candidates).toEqual([]);
  });
});
