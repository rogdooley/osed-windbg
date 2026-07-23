import { describe, expect, test } from "vitest";
import { listModulesWithMitigations } from "../src/commands/modules";

function writeUint16(memory: Map<number, number>, address: number, value: number): void {
  memory.set(address, value & 0xff);
  memory.set(address + 1, (value >>> 8) & 0xff);
}

function writeUint32(memory: Map<number, number>, address: number, value: number): void {
  for (let index = 0; index < 4; index += 1) memory.set(address + index, (value >>> (index * 8)) & 0xff);
}

describe("module mitigation parsing", () => {
  test("classifies a valid PE32 image without a load-config directory as SafeSEH disabled", () => {
    const base = 0x400000;
    const pe = base + 0x100;
    const memory = new Map<number, number>();
    writeUint16(memory, base, 0x5a4d);
    writeUint32(memory, base + 0x3c, 0x100);
    writeUint32(memory, pe, 0x4550);
    writeUint16(memory, pe + 0x18, 0x10b);
    writeUint16(memory, pe + 0x5e, 0);

    (globalThis as unknown as { host: unknown }).host = {
      currentProcess: {
        Modules: [{ Name: "vulnserver.exe", Path: "C:\\labs\\vulnserver.exe", BaseAddress: base, Size: 0x20000 }],
      },
      memory: {
        readMemoryValues: (address: number | bigint, length: number) => {
          const start = Number(address);
          return Array.from({ length }, (_, index) => memory.get(start + index) ?? 0);
        },
      },
    };

    expect(listModulesWithMitigations()[0]).toMatchObject({
      name: "vulnserver.exe",
      aslr: "disabled",
      dep: "disabled",
      safeseh: "disabled",
    });
  });
});
