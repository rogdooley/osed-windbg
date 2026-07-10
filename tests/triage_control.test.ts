import { describe, expect, test } from "vitest";
import { isInstructionPointerControlled } from "../src/commands/triage";

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
