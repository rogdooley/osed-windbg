import { describe, expect, test } from "vitest";
import { buildApiResolution, type ApiPlanCandidate, type CapabilityIndex, type RopGadget } from "../src/rop";

function gadget(address: number, text: string): RopGadget {
  const instructions = text.split(";").map((part) => {
    const trimmed = part.trim();
    const space = trimmed.indexOf(" ");
    const mnemonic = space < 0 ? trimmed : trimmed.slice(0, space);
    const operands = space < 0 ? "" : trimmed.slice(space + 1);
    return { mnemonic, operands: operands ? operands.split(",").map((value) => value.trim()) : [], originalText: part.trim() };
  });
  return {
    schemaVersion: "v1", canonicalId: `${address}:${text}`, instructions, locations: [{ virtualAddress: address, executable: "EXACT", writable: "CONSERVATIVE", aslr: "CONSERVATIVE", rebaseable: "CONSERVATIVE" }],
    semanticSummary: { instructions: [], effects: [], unknowns: [], netTransform: {} } as never,
    categories: [], score: 10, scoreReasons: [], classificationReasons: [], capabilities: [],
  };
}

const corpus = (gadgets: RopGadget[]): CapabilityIndex => ({ gadgets, byCapability: new Map(), byRegister: new Map(), byCategory: new Map() } as never);
const target = { module: "KERNEL32.DLL", symbol: "WriteProcessMemory", address: BigInt(0x765861c0), exportRva: 0x361c0 };
const base: Omit<ApiPlanCandidate, "strategy" | "anchor"> = {
  state: "ENCODABLE", target, ownerModule: "libspp.dll", ownerBase: BigInt(0x10000000), ownerImageBase: BigInt(0x10000000), slot: BigInt(0x101680ac), pointer: target.address,
  slotPayloadSafe: true, pointerResolved: true, targetModuleVerified: true, exportRvaVerified: true, recommendation: "test",
};

describe("buildApiResolution", () => {
  test("constructs a direct IAT dereference with an explicit continuation", () => {
    const plan = buildApiResolution(corpus([gadget(0x11111111, "pop eax; ret"), gadget(0x22222222, "mov eax, [eax]; ret")]), { ...base, strategy: "direct-slot" }, { continuation: 0x33333333 });
    expect(plan.state).toBe("CHAIN_CONSTRUCTED");
    expect(plan.steps.map((step) => step.value ?? Number(step.address))).toEqual([0x11111111, 0x101680ac, 0x22222222, 0x33333333]);
  });

  test("places ret-N padding after the next return address", () => {
    const plan = buildApiResolution(corpus([gadget(0x11111111, "pop eax; ret 4"), gadget(0x22222222, "mov eax, [eax]; ret")]), { ...base, strategy: "direct-slot" }, { continuation: 0x33333333 });
    expect(plan.state).toBe("CHAIN_CONSTRUCTED");
    expect(plan.steps.map((step) => step.value ?? Number(step.address))).toEqual([0x11111111, 0x101680ac, 0x22222222, 0x41414141, 0x33333333]);
  });

  test("rejects a derived add gadget that clobbers a preserved register", () => {
    const candidate: ApiPlanCandidate = { ...base, strategy: "derived-address", anchor: { symbol: "ReadFile", pointer: BigInt(0x76573f30), delta: BigInt(0x12290) } };
    const plan = buildApiResolution(corpus([
      gadget(0x11111111, "pop eax; ret"), gadget(0x22222222, "mov eax, [eax]; ret"), gadget(0x33333333, "pop ebp; ret"), gadget(0x44444444, "add eax, ebp; dec ecx; ret"),
    ]), candidate, { continuation: 0x55555555, preserve: ["ecx"] });
    expect(plan.state).toBe("UNSATISFIED");
    expect(plan.unsatisfied.join(" ")).toContain("add eax, ebp");
  });
});
