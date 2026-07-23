import { describe, expect, test } from "vitest";
import { readSehRecords, resolveTeb32Address } from "../src/analysis/seh";

describe("x86 SEH analysis", () => {
  test("resolves the TEB from the WinDbg environment block shape", () => {
    const thread = {
      Environment: {
        EnvironmentBlock: { NtTib: { Self: "0x7ffde000" } },
      },
    };

    expect(resolveTeb32Address(thread, () => BigInt(0))).toBe(BigInt("0x7ffde000"));
  });

  test("derives the WOW64 TEB when WinDbg supplies a native TEB and offset", () => {
    const thread = {
      NativeEnvironment: {
        EnvironmentBlock: {
          NtTib: { Self: BigInt("0x000000007ffde000") },
          WowTebOffset: "-8192",
        },
      },
    };

    expect(resolveTeb32Address(thread, () => BigInt(0))).toBe(BigInt("0x7ffdc000"));
  });

  test("reads the active record and preserves attacker-controlled values", () => {
    const memory = new Map<string, bigint>([
      ["0x7ffde000", BigInt("0x9fec80")],
      ["0x9fec80", BigInt("0x42424242")],
      ["0x9fec84", BigInt("0x43434343")],
    ]);
    const reader = (address: bigint): bigint => {
      const value = memory.get(`0x${address.toString(16)}`);
      if (value === undefined) throw new Error("unmapped");
      return value;
    };

    expect(readSehRecords(BigInt("0x7ffde000"), 1, reader)).toEqual([
      {
        node: BigInt("0x9fec80"),
        next: BigInt("0x42424242"),
        handler: BigInt("0x43434343"),
      },
    ]);
  });
});
