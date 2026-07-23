import { CapabilityIndex } from "./capabilities";
import { RopGadget } from "./types";

// Native ROP chain construction over the semantic capability index. v1 covers the
// bread-and-butter case: loading registers with constant values (API argument
// setup) using single `pop reg ; ret` gadgets. Those write only their target
// register, so the resulting chain is clobber-free and order-independent. It is a
// pure evidence emitter — it produces a chain layout as text, it does not write
// target memory. Multi-pop co-satisfaction is a deliberate future enhancement.

export interface ChainTarget {
  register: string;
  value: number;
}

export interface ChainStep {
  kind: "gadget" | "value";
  address?: bigint;
  value?: number;
  comment: string;
}

export interface ChainPlan {
  steps: ChainStep[];
  satisfied: string[];
  unsatisfied: Array<{ register: string; reason: string }>;
  stackBytes: number;
}

function firstKnownAddress(gadget: RopGadget): bigint | undefined {
  const location = gadget.locations.find((entry) => entry.virtualAddress !== undefined);
  return location?.virtualAddress !== undefined ? BigInt(location.virtualAddress) : undefined;
}

function isSinglePopRet(gadget: RopGadget, register: string): boolean {
  if (gadget.instructions.length !== 2) {
    return false;
  }
  const [pop, ret] = gadget.instructions;
  return (
    pop.mnemonic === "pop" &&
    pop.operands.length === 1 &&
    pop.operands[0].trim().toLowerCase() === register &&
    ret.mnemonic === "ret" &&
    ret.operands.length === 0
  );
}

// Pick the best clean single pop gadget for a register: a `pop reg ; ret` with a
// known address, highest-scoring first (scoring already favors short, exact gadgets).
function selectPopGadget(index: CapabilityIndex, register: string): RopGadget | undefined {
  return index
    .loadRegister(register)
    .filter((gadget) => isSinglePopRet(gadget, register) && firstKnownAddress(gadget) !== undefined)
    .sort((a, b) => b.score - a.score)[0];
}

export function planRegisterSetup(index: CapabilityIndex, targets: ChainTarget[]): ChainPlan {
  const steps: ChainStep[] = [];
  const satisfied: string[] = [];
  const unsatisfied: Array<{ register: string; reason: string }> = [];

  for (const target of targets) {
    const register = target.register.trim().toLowerCase();
    const gadget = selectPopGadget(index, register);
    if (!gadget) {
      const reason = index.loadRegister(register).length > 0
        ? "only multi-pop or address-less load gadgets available"
        : "no pop gadget found for register";
      unsatisfied.push({ register, reason });
      continue;
    }

    const address = firstKnownAddress(gadget)!;
    const value = target.value >>> 0;
    steps.push({ kind: "gadget", address, comment: `pop ${register} ; ret` });
    steps.push({ kind: "value", value, comment: `${register} = 0x${value.toString(16).toUpperCase().padStart(8, "0")}` });
    satisfied.push(register);
  }

  return { steps, satisfied, unsatisfied, stackBytes: steps.length * 4 };
}

function hex32(value: bigint | number): string {
  const asBig = typeof value === "bigint" ? value : BigInt(value >>> 0);
  return `0x${asBig.toString(16).toUpperCase().padStart(8, "0")}`;
}

export function formatChainPython(plan: ChainPlan): string[] {
  const lines = ["from struct import pack", 'rop = b""'];
  for (const step of plan.steps) {
    const word = step.kind === "gadget" ? step.address! : step.value!;
    lines.push(`rop += pack("<I", ${hex32(word)})  # ${step.comment}`);
  }
  return lines;
}
