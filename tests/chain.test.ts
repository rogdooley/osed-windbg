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

describe("smarter chain construction: multi-pop and zeroing", () => {
  test("co-satisfies two registers with a single multi-pop gadget", () => {
    const multi = buildCapabilityIndexFromSequences(
      sequencesFromLiveHits([
        { mnemonic: "pop eax ; pop ebx ; ret", address: BigInt(0x00402000), module: "vuln" },
        { mnemonic: "pop eax ; ret", address: BigInt(0x00402100), module: "vuln" },
        { mnemonic: "pop ebx ; ret", address: BigInt(0x00402110), module: "vuln" },
      ]),
    );
    const plan = planRegisterSetup(multi, [
      { register: "eax", value: 0x11111111 },
      { register: "ebx", value: 0x22222222 },
    ]);
    expect(plan.satisfied).toEqual(["eax", "ebx"]);
    expect(plan.stackBytes).toBe(12); // one gadget slot + two value slots
    expect(plan.steps).toEqual([
      { kind: "gadget", address: BigInt(0x00402000), comment: "pop eax ; pop ebx ; ret" },
      { kind: "value", value: 0x11111111, comment: "eax = 0x11111111" },
      { kind: "value", value: 0x22222222, comment: "ebx = 0x22222222" },
    ]);
  });

  test("zeroes a value-0 target with xor, preferring it over a pop", () => {
    const both = buildCapabilityIndexFromSequences(
      sequencesFromLiveHits([
        { mnemonic: "xor eax, eax ; ret", address: BigInt(0x00404000), module: "vuln" },
        { mnemonic: "pop eax ; ret", address: BigInt(0x00404010), module: "vuln" },
      ]),
    );
    const plan = planRegisterSetup(both, [{ register: "eax", value: 0 }]);
    expect(plan.satisfied).toEqual(["eax"]);
    expect(plan.stackBytes).toBe(4); // xor gadget only, no value slot
    expect(plan.steps).toEqual([
      { kind: "gadget", address: BigInt(0x00404000), comment: "xor eax, eax ; ret (eax = 0)" },
    ]);
  });

  test("mixes zeroing and pop across targets", () => {
    const mixed = buildCapabilityIndexFromSequences(
      sequencesFromLiveHits([
        { mnemonic: "xor eax, eax ; ret", address: BigInt(0x00405000), module: "vuln" },
        { mnemonic: "pop ebx ; ret", address: BigInt(0x00405010), module: "vuln" },
      ]),
    );
    const plan = planRegisterSetup(mixed, [
      { register: "eax", value: 0 },
      { register: "ebx", value: 0x5 },
    ]);
    expect(plan.satisfied).toEqual(["eax", "ebx"]);
    expect(plan.steps).toEqual([
      { kind: "gadget", address: BigInt(0x00405000), comment: "xor eax, eax ; ret (eax = 0)" },
      { kind: "gadget", address: BigInt(0x00405010), comment: "pop ebx ; ret" },
      { kind: "value", value: 0x5, comment: "ebx = 0x00000005" },
    ]);
  });
});
