import { describe, expect, test } from "vitest";
import { isInstructionPointerControlled, landingCandidateAddresses } from "../src/commands/triage";
import { normalizeMemoryRegion } from "../src/analysis/memory";

describe("triage control detection", () => {
  test("reports control when a pattern offset is matched", () => {
    expect(
      isInstructionPointerControlled({
        patternMatched: true,
        ip: BigInt("0x41414141"),
        ipBackedByModule: false,
      }),
    ).toBe(true);
  });

  test("reports control when ip is outside loaded modules", () => {
    expect(
      isInstructionPointerControlled({
        patternMatched: false,
        ip: BigInt("0x41414141"),
        ipBackedByModule: false,
      }),
    ).toBe(true);
  });

  test("reports control on access violations even when the ip is module-backed", () => {
    expect(
      isInstructionPointerControlled({
        patternMatched: false,
        ip: BigInt("0x10001000"),
        ipBackedByModule: true,
        exceptionCode: BigInt("0xc0000005"),
      }),
    ).toBe(true);
  });

  test("does not report control when ip is in a loaded module", () => {
    expect(
      isInstructionPointerControlled({
        patternMatched: false,
        ip: BigInt("0x10001000"),
        ipBackedByModule: true,
      }),
    ).toBe(false);
  });

  test("does not report control when ip is unavailable", () => {
    expect(
      isInstructionPointerControlled({
        patternMatched: false,
        ipBackedByModule: false,
      }),
    ).toBe(false);
  });
});

describe("triage landing projection", () => {
  test("renders candidates from shared landing observations without rescanning bytes", () => {
    const base = BigInt("0x12f800");
    const memory = normalizeMemoryRegion(base, { protection: 0x04 });
    expect(landingCandidateAddresses({
      address: base,
      memory,
      bytes: [],
      requestedBytes: 64,
      confidence: 0,
      recommendation: "",
      observations: [
        { kind: "readable_region", confidence: 1, address: base, length: 64, details: {} },
        { kind: "payload_like_bytes", confidence: 0.4, address: base + BigInt(8), length: 32, details: {} },
        { kind: "nop_sled_detected", confidence: 0.95, address: base, length: 12, details: {} },
      ],
    })).toEqual([base, base + BigInt(8)]);
  });
});
