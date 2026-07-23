import { CapabilityIndex } from "./capabilities";
import { RopGadget } from "./types";

// Native ROP chain construction over the semantic capability index. Covers the
// bread-and-butter case: loading registers with constant values (API argument
// setup). Each target register is written exactly once — via a single-slot xor
// zero, a shared multi-pop, or a single pop — so the chain is clobber-free and
// order-independent. It is a pure evidence emitter: it produces a chain layout as
// text, it does not write target memory.

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

// A `xor reg, reg ; ret` gadget — zeroes reg in a single stack slot with no value.
function isZeroRet(gadget: RopGadget, register: string): boolean {
  if (gadget.instructions.length !== 2) {
    return false;
  }
  const [xor, ret] = gadget.instructions;
  return (
    xor.mnemonic === "xor" &&
    xor.operands.length === 2 &&
    xor.operands[0].trim().toLowerCase() === register &&
    xor.operands[1].trim().toLowerCase() === register &&
    ret.mnemonic === "ret" &&
    ret.operands.length === 0
  );
}

function selectZeroGadget(index: CapabilityIndex, register: string): RopGadget | undefined {
  return index
    .zeroRegister(register)
    .filter((gadget) => isZeroRet(gadget, register) && firstKnownAddress(gadget) !== undefined)
    .sort((a, b) => b.score - a.score)[0];
}

// The register pop order of a `pop R1 ; ... ; pop Rn ; ret` gadget, or undefined
// if the gadget is not a pure pop-sequence terminated by a plain ret.
function popSequenceRegisters(gadget: RopGadget): string[] | undefined {
  const instructions = gadget.instructions;
  if (instructions.length < 2) {
    return undefined;
  }
  const ret = instructions[instructions.length - 1];
  if (ret.mnemonic !== "ret" || ret.operands.length !== 0) {
    return undefined;
  }
  const registers: string[] = [];
  for (let index = 0; index < instructions.length - 1; index += 1) {
    const step = instructions[index];
    if (step.mnemonic !== "pop" || step.operands.length !== 1) {
      return undefined;
    }
    registers.push(step.operands[0].trim().toLowerCase());
  }
  return registers;
}

function valueComment(register: string, value: number): string {
  return `${register} = 0x${(value >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
}

// Plan a register-setup chain. Each target register is written exactly once, so
// the chain is clobber-free regardless of gadget order. Three passes, cheapest
// first: zero via `xor reg, reg ; ret`; co-satisfy several registers with one
// multi-pop gadget; then a single `pop reg ; ret` per remaining register.
export function planRegisterSetup(index: CapabilityIndex, targets: ChainTarget[]): ChainPlan {
  const steps: ChainStep[] = [];
  const satisfied: string[] = [];
  const unsatisfied: Array<{ register: string; reason: string }> = [];

  const remaining = new Map<string, number>();
  const order: string[] = [];
  for (const target of targets) {
    const register = target.register.trim().toLowerCase();
    if (!remaining.has(register)) {
      order.push(register);
    }
    remaining.set(register, target.value >>> 0);
  }

  // Pass 0: zero registers whose target value is 0 with a single-slot xor gadget.
  for (const register of order) {
    if (remaining.get(register) !== 0) {
      continue;
    }
    const gadget = selectZeroGadget(index, register);
    if (gadget) {
      steps.push({ kind: "gadget", address: firstKnownAddress(gadget)!, comment: `xor ${register}, ${register} ; ret (${register} = 0)` });
      satisfied.push(register);
      remaining.delete(register);
    }
  }

  // Pass 1: co-satisfy with multi-pop gadgets whose popped registers are all
  // distinct and all still-remaining targets (so nothing else is clobbered).
  const popSequences = index.gadgets
    .map((gadget) => ({ gadget, registers: popSequenceRegisters(gadget) }))
    .filter((entry): entry is { gadget: RopGadget; registers: string[] } =>
      entry.registers !== undefined && entry.registers.length >= 2 && firstKnownAddress(entry.gadget) !== undefined);

  let progressed = true;
  while (progressed) {
    progressed = false;
    let best: { gadget: RopGadget; registers: string[] } | undefined;
    for (const candidate of popSequences) {
      const { registers } = candidate;
      const distinct = new Set(registers).size === registers.length;
      if (!distinct || !registers.every((register) => remaining.has(register))) {
        continue;
      }
      if (!best || registers.length > best.registers.length || (registers.length === best.registers.length && candidate.gadget.score > best.gadget.score)) {
        best = candidate;
      }
    }
    if (best) {
      steps.push({ kind: "gadget", address: firstKnownAddress(best.gadget)!, comment: `${best.registers.map((register) => `pop ${register}`).join(" ; ")} ; ret` });
      for (const register of best.registers) {
        const value = remaining.get(register)! >>> 0;
        steps.push({ kind: "value", value, comment: valueComment(register, value) });
        satisfied.push(register);
        remaining.delete(register);
      }
      progressed = true;
    }
  }

  // Pass 2: a single pop ; ret for each register still remaining.
  for (const register of order) {
    if (!remaining.has(register)) {
      continue;
    }
    const gadget = selectPopGadget(index, register);
    if (!gadget) {
      const reason = index.loadRegister(register).length > 0
        ? "only multi-pop or address-less load gadgets available"
        : "no pop gadget found for register";
      unsatisfied.push({ register, reason });
      remaining.delete(register);
      continue;
    }
    const value = remaining.get(register)! >>> 0;
    steps.push({ kind: "gadget", address: firstKnownAddress(gadget)!, comment: `pop ${register} ; ret` });
    steps.push({ kind: "value", value, comment: valueComment(register, value) });
    satisfied.push(register);
    remaining.delete(register);
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
