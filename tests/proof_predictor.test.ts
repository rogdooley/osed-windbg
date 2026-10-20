import { describe, expect, test } from "vitest";
import { buildCapabilityIndexFromRpPlusText } from "../src/rop";
import type { ChainStep } from "../src/rop/chain";
import { buildProofPlan, uint32Add } from "../src/rop/proof";
import fixture from "./fixtures/proof/linear-good.json";
import { ReplayProofAdapter, type ReplayFixture } from "./helpers/replay_proof_adapter";

const provenance = {
  module: "proof.dll",
  executable: "EXACT" as const,
  writable: "CONSERVATIVE" as const,
  aslr: "CONSERVATIVE" as const,
  rebaseable: "CONSERVATIVE" as const,
};

function corpus(text: string) {
  return buildCapabilityIndexFromRpPlusText(text, { provenance });
}

function gadget(address: number, comment: string): ChainStep {
  return { kind: "gadget", address: BigInt(address), comment };
}

function value(value: number, comment: string): ChainStep {
  return { kind: "value", value, comment };
}

function replay(): ReplayProofAdapter {
  return new ReplayProofAdapter(fixture as ReplayFixture);
}

describe("buildProofPlan", () => {
  test("uses composed pop and ret semantics for the following checkpoint", () => {
    const index = corpus([
      "0x10001000: pop eax ; ret ;",
      "0x10002000: ret ;",
    ].join("\n"));
    const plan = buildProofPlan({
      chain: [gadget(0x10001000, "load eax"), value(0x41414141, "eax"), gadget(0x10002000, "next")],
      corpus: index,
    }, replay());

    expect(plan.checkpoints.map((checkpoint) => checkpoint.stepIndex)).toEqual([0, 2]);
    expect(plan.checkpoints[1].target).toEqual({ kind: "constant", value: 0x10002000n });
    expect(plan.checkpoints[1].assertions).toEqual(expect.arrayContaining([
      expect.objectContaining({
        subject: "ESP",
        expected: { kind: "register-offset", register: "esp", checkpoint: "before", offset: 8 },
        confidence: "EXACT",
      }),
      expect.objectContaining({
        subject: "EAX",
        expected: {
          kind: "memory-dword",
          address: { kind: "register", register: "esp", checkpoint: "before" },
        },
        confidence: "EXACT",
      }),
    ]));
  });

  test("includes the ret immediate in the absolute ESP expression", () => {
    const index = corpus([
      "0x10003000: ret 8 ;",
      "0x10004000: ret ;",
    ].join("\n"));
    const plan = buildProofPlan({
      chain: [
        gadget(0x10003000, "ret 8"),
        gadget(0x10004000, "next"),
        value(0x41414141, "padding"),
        value(0x41414141, "padding"),
      ],
      corpus: index,
    }, replay());

    expect(plan.checkpoints[1].assertions).toContainEqual(expect.objectContaining({
      subject: "ESP",
      expected: { kind: "register-offset", register: "esp", checkpoint: "before", offset: 12 },
    }));
  });

  test("leaves a pivot target deferred with observed register and memory dependencies", () => {
    const index = corpus("0x10005000: xchg eax, esp ; ret ;");
    const plan = buildProofPlan({ chain: [gadget(0x10005000, "pivot")], corpus: index }, replay());

    expect(plan.checkpoints).toHaveLength(2);
    expect(plan.checkpoints[1]).toMatchObject({ label: "pivot target", dynamic: true });
    expect(plan.checkpoints[1].target).toEqual({
      kind: "memory-dword",
      address: { kind: "register", register: "eax", checkpoint: "before" },
    });
    expect(plan.checkpoints[1].assertions).toContainEqual(expect.objectContaining({
      subject: "ESP",
      expected: { kind: "register-offset", register: "eax", checkpoint: "before", offset: 4 },
    }));
  });

  test("coalesces a dereference and register dispatch into a deferred API checkpoint", () => {
    const index = corpus([
      "0x10006000: mov eax, [eax] ; ret ;",
      "0x10007000: jmp eax ;",
    ].join("\n"));
    const plan = buildProofPlan({
      chain: [gadget(0x10006000, "deref IAT"), gadget(0x10007000, "dispatch")],
      corpus: index,
      api: "VirtualProtect",
    }, replay());

    expect(plan.checkpoints).toHaveLength(2);
    expect(plan.checkpoints[1]).toMatchObject({ label: "VirtualProtect API entry", dynamic: true });
    expect(plan.checkpoints.some((checkpoint) => checkpoint.target.kind === "constant" && checkpoint.target.value === 0x10007000n)).toBe(false);
    expect(plan.checkpoints[1].target).toEqual({
      kind: "memory-dword",
      address: { kind: "register", register: "eax", checkpoint: "before" },
    });
    expect(plan.checkpoints[1].assertions).toContainEqual(expect.objectContaining({
      subject: "ESP",
      expected: { kind: "register-offset", register: "esp", checkpoint: "before", offset: 4 },
    }));
    expect(plan.checkpoints[1].provenance).toHaveLength(2);
  });

  test("marks unknown flow-affecting semantics incomplete", () => {
    const index = corpus("0x10008000: mystery eax ; ret ;");
    const plan = buildProofPlan({ chain: [gadget(0x10008000, "unknown")], corpus: index }, replay());

    expect(plan.incompleteReasons.join(" ")).toContain("unknown semantics");
    expect(plan.checkpoints[0].assertions).toEqual([]);
  });

  test("wraps address arithmetic as an unsigned x86 DWORD", () => {
    expect(uint32Add(0xfffffffcn, 8)).toBe(4n);
  });

  test("normalizes unambiguous manual gadget addresses without changing data words", () => {
    const index = corpus([
      "0x10001000: pop eax ; ret ;",
      "0x10002000: ret ;",
    ].join("\n"));
    const plan = buildProofPlan({ chain: "10001000 41414141 10002000", corpus: index }, replay());

    expect(plan.steps.map((step) => step.kind)).toEqual(["gadget", "value", "gadget"]);
    expect(plan.steps[1].value).toBe(0x41414141);
  });

  test("does not guess when one manual address maps to multiple corpus gadgets", () => {
    const index = corpus([
      "0x10009000: pop eax ; ret ;",
      "0x10009000: pop ebx ; ret ;",
    ].join("\n"));
    const plan = buildProofPlan({ chain: "10009000", corpus: index }, replay());

    expect(plan.steps[0].kind).toBe("value");
    expect(plan.incompleteReasons.join(" ")).toContain("ambiguous");
  });
});
