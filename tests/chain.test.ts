import { describe, expect, test } from "vitest";
import { sequencesFromLiveHits } from "../src/semantics/live-provider";
import { buildCapabilityIndexFromSequences, formatChainPython, planRegisterSetup } from "../src/rop";

// Chain construction over an index built from (synthetic) live gadget hits, so it
// exercises the full live -> index -> plan path.
const index = buildCapabilityIndexFromSequences(
  sequencesFromLiveHits([
    { mnemonic: "pop eax ; ret", address: BigInt(0x00401000), module: "vuln" },
    { mnemonic: "pop ebx ; ret", address: BigInt(0x00401010), module: "vuln" },
    { mnemonic: "pop ecx ; pop edx ; ret", address: BigInt(0x00401020), module: "vuln" },
  ]),
);

describe("register-setup chain construction", () => {
  test("emits gadget/value pairs at real addresses for satisfiable registers", () => {
    const plan = planRegisterSetup(index, [
      { register: "eax", value: 0xdeadbeef },
      { register: "ebx", value: 0x00001000 },
    ]);
    expect(plan.satisfied).toEqual(["eax", "ebx"]);
    expect(plan.unsatisfied).toEqual([]);
    expect(plan.stackBytes).toBe(16);
    expect(plan.steps).toEqual([
      { kind: "gadget", address: BigInt(0x00401000), comment: "pop eax ; ret" },
      { kind: "value", value: 0xdeadbeef, comment: "eax = 0xDEADBEEF" },
      { kind: "gadget", address: BigInt(0x00401010), comment: "pop ebx ; ret" },
      { kind: "value", value: 0x00001000, comment: "ebx = 0x00001000" },
    ]);
  });

  test("reports registers with only multi-pop gadgets as unsatisfied, with reason", () => {
    const plan = planRegisterSetup(index, [{ register: "ecx", value: 0x41414141 }]);
    expect(plan.satisfied).toEqual([]);
    expect(plan.unsatisfied).toEqual([
      { register: "ecx", reason: "only multi-pop or address-less load gadgets available" },
    ]);
  });

  test("reports registers with no load gadget at all", () => {
    const plan = planRegisterSetup(index, [{ register: "edi", value: 0 }]);
    expect(plan.unsatisfied).toEqual([{ register: "edi", reason: "no pop gadget found for register" }]);
  });

  test("formatChainPython renders paste-ready pack() lines", () => {
    const plan = planRegisterSetup(index, [{ register: "eax", value: 0xdeadbeef }]);
    expect(formatChainPython(plan)).toEqual([
      "from struct import pack",
      'rop = b""',
      'rop += pack("<I", 0x00401000)  # pop eax ; ret',
      'rop += pack("<I", 0xDEADBEEF)  # eax = 0xDEADBEEF',
    ]);
  });
});
