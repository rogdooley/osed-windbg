import { type ApiPlanCandidate, dwordIsByteSafe } from "./api_plan";
import { type CapabilityIndex } from "./capabilities";
import { type ChainStep, firstKnownAddress, retImmBytes } from "./chain";
import { type RopGadget } from "./types";

export type ApiBuildState = "UNSATISFIED" | "CHAIN_CONSTRUCTED" | "CHAIN_SIMULATED";

export interface ApiBuildOptions {
  output?: string;
  preserve?: string[];
  maxGadgets?: number;
  badchars?: number[];
  /** Address to receive the final RET. Required for a constructible chain. */
  continuation?: number;
}

export interface ApiBuildPlan {
  state: ApiBuildState;
  strategy: ApiPlanCandidate["strategy"];
  steps: ChainStep[];
  gadgetCount: number;
  stackBytes: number;
  clobbers: string[];
  expectedOutput?: bigint;
  unsatisfied: string[];
  notes: string[];
}

function op(gadget: RopGadget, instruction: number, operand: number): string {
  return (gadget.instructions[instruction]?.operands[operand] ?? "").trim().toLowerCase();
}

function isRetTerminated(gadget: RopGadget): boolean {
  return retImmBytes(gadget) >= 0 && firstKnownAddress(gadget) !== undefined;
}

function writes(gadget: RopGadget): string[] {
  const result = new Set<string>();
  for (const instruction of gadget.instructions) {
    const mnemonic = instruction.mnemonic.toLowerCase();
    const destination = op(gadget, gadget.instructions.indexOf(instruction), 0);
    if (["pop", "mov", "add", "sub", "adc", "sbb", "xor", "or", "and", "not", "neg", "inc", "dec", "xchg"].includes(mnemonic)
      && /^[a-z]{2,3}$/.test(destination)) result.add(destination);
    if (mnemonic === "xchg" && /^[a-z]{2,3}$/.test(op(gadget, gadget.instructions.indexOf(instruction), 1))) {
      result.add(op(gadget, gadget.instructions.indexOf(instruction), 1));
    }
  }
  return [...result];
}

function pick(index: CapabilityIndex, predicate: (gadget: RopGadget) => boolean, preserve: Set<string>, output: string): RopGadget | undefined {
  return index.gadgets
    .filter((gadget) => isRetTerminated(gadget) && predicate(gadget))
    .filter((gadget) => writes(gadget).every((reg) => reg === output || !preserve.has(reg)))
    .sort((left, right) => retImmBytes(left) - retImmBytes(right) || left.instructions.length - right.instructions.length || right.score - left.score)[0];
}

function pickPop(index: CapabilityIndex, register: string, preserve: Set<string>, output: string): RopGadget | undefined {
  return pick(index, (gadget) => gadget.instructions.length === 2 && gadget.instructions[0].mnemonic === "pop" && op(gadget, 0, 0) === register, preserve, output);
}

function pickLoad(index: CapabilityIndex, output: string, preserve: Set<string>): RopGadget | undefined {
  return pick(index, (gadget) => gadget.instructions.length === 2
    && gadget.instructions[0].mnemonic === "mov"
    && op(gadget, 0, 0) === output
    && op(gadget, 0, 1) === `[${output}]`, preserve, output);
}

function pickAdd(index: CapabilityIndex, output: string, source: string, preserve: Set<string>): RopGadget | undefined {
  return pick(index, (gadget) => gadget.instructions.length >= 2
    && gadget.instructions[0].mnemonic === "add"
    && op(gadget, 0, 0) === output
    && op(gadget, 0, 1) === source, preserve, output);
}

function addends(delta: bigint, badchars: number[]): number[] | undefined {
  const word = Number(delta & BigInt(0xffffffff)) >>> 0;
  if (dwordIsByteSafe(BigInt(word), badchars)) return [word];
  for (let byte = 1; byte < 256; byte += 1) {
    const component = ((byte << 24) | (byte << 16) | (byte << 8) | byte) >>> 0;
    const second = (word - component) >>> 0;
    if (dwordIsByteSafe(BigInt(component), badchars) && dwordIsByteSafe(BigInt(second), badchars)) return [component, second];
  }
  return undefined;
}

/**
 * Small, explicit Phase-2 composer. It intentionally supports only
 * pop/mov-[reg]/add/ret shapes; unsupported gadget semantics fail closed.
 */
export function buildApiResolution(index: CapabilityIndex, candidate: ApiPlanCandidate, options: ApiBuildOptions = {}): ApiBuildPlan {
  const output = (options.output ?? "eax").toLowerCase();
  const preserve = new Set((options.preserve ?? []).map((reg) => reg.toLowerCase()));
  const badchars = options.badchars ?? [];
  const maxGadgets = options.maxGadgets ?? 12;
  const unsatisfied: string[] = [];
  const notes: string[] = [];
  if (output !== "eax") return { state: "UNSATISFIED", strategy: candidate.strategy, steps: [], gadgetCount: 0, stackBytes: 0, clobbers: [], unsatisfied: ["Phase 2 currently supports EAX output only."], notes };
  if (!candidate.exportRvaVerified || !candidate.pointerResolved || !candidate.targetModuleVerified) {
    return { state: "UNSATISFIED", strategy: candidate.strategy, steps: [], gadgetCount: 0, stackBytes: 0, clobbers: [], unsatisfied: ["Phase 1 address evidence is incomplete; rebuild from a validated candidate."], notes };
  }
  if (options.continuation === undefined) unsatisfied.push("A concrete continuation address is required after the final RET.");
  if (options.continuation !== undefined && !dwordIsByteSafe(BigInt(options.continuation), badchars)) unsatisfied.push("Continuation address contains a forbidden byte.");

  const popEax = pickPop(index, "eax", preserve, output);
  const loadEax = pickLoad(index, output, preserve);
  if (!popEax) unsatisfied.push("No exact `pop eax ; ret` gadget satisfies preservation constraints.");
  if (!loadEax) unsatisfied.push("No exact `mov eax, [eax] ; ret` gadget satisfies preservation constraints.");
  const operations: Array<{ gadget: RopGadget; operand?: number; comment: string }> = [];
  if (popEax && loadEax) {
    if (!candidate.slotPayloadSafe) unsatisfied.push("IAT slot contains a forbidden byte; dynamic slot-address construction is not implemented in this milestone.");
    else {
      operations.push({ gadget: popEax, operand: Number(candidate.slot), comment: `pop eax = IAT slot 0x${candidate.slot.toString(16).toUpperCase()}` });
      operations.push({ gadget: loadEax, comment: "mov eax, [eax] (live IAT target)" });
    }
  }
  if (candidate.strategy === "derived-address") {
    const components = candidate.anchor ? addends(candidate.anchor.delta, badchars) : undefined;
    if (!components) unsatisfied.push("No one- or two-addend byte-safe displacement decomposition was found.");
    const popEbp = pickPop(index, "ebp", preserve, output);
    const addEaxEbp = pickAdd(index, output, "ebp", preserve);
    if (!popEbp) unsatisfied.push("No exact `pop ebp ; ret` gadget satisfies preservation constraints.");
    if (!addEaxEbp) unsatisfied.push("No `add eax, ebp ; ... ; ret` gadget satisfies preservation constraints.");
    if (components && popEbp && addEaxEbp) {
      for (const component of components) {
        operations.push({ gadget: popEbp, operand: component, comment: `pop ebp = 0x${component.toString(16).toUpperCase().padStart(8, "0")}` });
        operations.push({ gadget: addEaxEbp, comment: "add eax, ebp" });
      }
      notes.push(`Displacement encoded as ${components.map((value) => `0x${value.toString(16).toUpperCase().padStart(8, "0")}`).join(" + ")}.`);
    }
  }
  if (operations.length > maxGadgets) unsatisfied.push(`Construction needs ${operations.length} gadgets; maxGadgets is ${maxGadgets}.`);
  for (const operation of operations) {
    const address = firstKnownAddress(operation.gadget)!;
    if (!dwordIsByteSafe(address, badchars)) unsatisfied.push(`Gadget address 0x${address.toString(16).toUpperCase()} contains a forbidden byte.`);
    if (operation.operand !== undefined && !dwordIsByteSafe(BigInt(operation.operand), badchars)) {
      unsatisfied.push(`Operand 0x${operation.operand.toString(16).toUpperCase()} contains a forbidden byte.`);
    }
  }
  if (unsatisfied.length > 0) return { state: "UNSATISFIED", strategy: candidate.strategy, steps: [], gadgetCount: operations.length, stackBytes: 0, clobbers: [], unsatisfied, notes };

  const steps: ChainStep[] = [];
  const clobbers = new Set<string>();
  let pendingPadding = 0;
  for (const operation of operations) {
    steps.push({ kind: "gadget", address: firstKnownAddress(operation.gadget)!, comment: operation.comment });
    for (let word = 0; word < pendingPadding; word += 1) steps.push({ kind: "value", value: 0x41414141, comment: "ret immediate padding" });
    pendingPadding = retImmBytes(operation.gadget) / 4;
    if (operation.operand !== undefined) steps.push({ kind: "value", value: operation.operand, comment: operation.comment });
    for (const reg of writes(operation.gadget)) if (reg !== output) clobbers.add(reg);
  }
  steps.push({ kind: "value", value: options.continuation!, comment: "required continuation after API resolution" });
  for (let word = 0; word < pendingPadding; word += 1) steps.push({ kind: "value", value: 0x41414141, comment: "ret immediate padding" });
  return {
    state: "CHAIN_CONSTRUCTED",
    strategy: candidate.strategy,
    steps,
    gadgetCount: operations.length,
    stackBytes: steps.length * 4,
    clobbers: [...clobbers].sort(),
    expectedOutput: candidate.target.address,
    unsatisfied: [],
    notes,
  };
}
