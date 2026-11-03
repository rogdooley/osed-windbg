import { describe, expect, test } from "vitest";
import { classifyPointer } from "../src/core/leak_evidence";
import type { MemoryRegionEvidence } from "../src/analysis/memory";
import type { ModuleMitigation } from "../src/commands/modules";

const module: ModuleMitigation = { name: "C:\\lab\\test.dll", path: "C:\\lab\\test.dll", base: BigInt(0x1000), size: BigInt(0x100), characteristics: 0, dllCharacteristics: 0, aslr: "enabled", nxcompat: "enabled", safeseh: "unknown", system: false, preferredBase: BigInt(0x1000) };
const mapped = (address: bigint): MemoryRegionEvidence => ({ address, readable: true, writable: true, executable: false, guarded: false, noAccess: false, committed: true, regionType: "private", raw: {}, source: "vprot", warnings: [] });
const unavailable = (address: bigint): MemoryRegionEvidence => ({ ...mapped(address), source: "unavailable", warnings: ["unavailable"] });
const finder = (address: bigint) => address >= module.base && address < module.base + module.size ? module : undefined;

describe("pointer classification", () => {
  test("classifies module pointers and preserves the RVA at boundaries", () => {
    expect(classifyPointer(BigInt(0x1000), 4, finder, mapped)).toMatchObject({ kind: "module_pointer", module: { rva: BigInt(0), aslr: "enabled" }, provenance: "debugger_observed" });
    expect(classifyPointer(BigInt(0x10ff), 4, finder, mapped).module?.rva).toBe(BigInt(0xff));
    expect(classifyPointer(BigInt(0x1100), 4, finder, mapped).kind).toBe("memory_pointer");
  });

  test("distinguishes null, private mapped memory, unmapped memory, and x64 width", () => {
    expect(classifyPointer(BigInt(0), 4, finder, mapped)).toMatchObject({ kind: "null", pointerSize: 4 });
    expect(classifyPointer(BigInt(0x2000), 4, finder, mapped)).toMatchObject({ kind: "memory_pointer", pointerSize: 4 });
    expect(classifyPointer(BigInt(0x3000), 8, finder, unavailable)).toMatchObject({ kind: "unmapped", pointerSize: 8 });
  });
});
