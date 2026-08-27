import { CapabilityIndex } from "./capabilities";
import { ChainStep, GadgetSelection, firstKnownAddress, hex32, retImmBytes, retImmPadding } from "./chain";
import { RopGadget } from "./types";

export type RecipeKind = "direct" | "negate" | "complement" | "two-add" | "two-sub" | "zero-add" | "zero-sub-neg";

export interface ValueRecipe {
  steps: ChainStep[];
  recipe: RecipeKind;
  scratchRegister?: string;
  stackBytes: number;
}

const SCRATCH_CANDIDATES = ["eax", "ecx", "edx", "ebx", "esi", "edi"];

function isBadcharFree(value: number, badchars: Set<number>): boolean {
  if (badchars.size === 0) return true;
  const w = value >>> 0;
  for (let i = 0; i < 4; i++) {
    if (badchars.has((w >>> (i * 8)) & 0xff)) return false;
  }
  return true;
}

function selectBest(candidates: RopGadget[]): GadgetSelection | undefined {
  const withAddr = candidates
    .map((g) => ({ gadget: g, retImm: retImmBytes(g) }))
    .filter((s) => s.retImm >= 0 && firstKnownAddress(s.gadget) !== undefined);
  if (withAddr.length === 0) return undefined;
  withAddr.sort((a, b) => {
    if (a.retImm !== b.retImm) return a.retImm - b.retImm;
    return b.gadget.score - a.gadget.score;
  });
  return withAddr[0];
}

function gadgetStep(sel: GadgetSelection, comment: string): ChainStep {
  return { kind: "gadget", address: firstKnownAddress(sel.gadget)!, comment };
}

function valueStep(value: number, comment: string): ChainStep {
  return { kind: "value", value: value >>> 0, comment };
}

function extraPopSteps(gadget: RopGadget): ChainStep[] {
  const steps: ChainStep[] = [];
  const insns = gadget.instructions;
  for (let i = 0; i < insns.length; i++) {
    const insn = insns[i];
    if (insn.mnemonic === "pop" && i > 0 && insns[i - 1].mnemonic !== "ret") {
      // This is a side-effect pop that's not the primary operation
    }
  }
  // Count pops after the first non-pop instruction (side-effect pops)
  let foundPrimary = false;
  for (const insn of insns) {
    if (insn.mnemonic === "ret") break;
    if (!foundPrimary && insn.mnemonic !== "pop") {
      foundPrimary = true;
      continue;
    }
    if (foundPrimary && insn.mnemonic === "pop") {
      const reg = insn.operands[0]?.trim().toLowerCase() ?? "?";
      steps.push({ kind: "value", value: 0x41414141, comment: `junk (${reg} side effect)` });
    }
  }
  return steps;
}

function capKey(kind: string, register?: string, targetRegister?: string): string {
  return [kind, register ?? "", targetRegister ?? ""].join(":");
}

function findPopGadget(index: CapabilityIndex, reg: string): GadgetSelection | undefined {
  const candidates = index.capabilityMap.get(capKey("LOAD_REGISTER", reg)) ?? [];
  const purePopRet = candidates.filter((g) => {
    if (g.instructions.length < 2) return false;
    const last = g.instructions[g.instructions.length - 1];
    if (last.mnemonic !== "ret") return false;
    return g.instructions[0].mnemonic === "pop" &&
      g.instructions[0].operands[0]?.trim().toLowerCase() === reg;
  });
  return selectBest(purePopRet);
}

function findZeroGadget(index: CapabilityIndex, reg: string): GadgetSelection | undefined {
  const candidates = index.capabilityMap.get(capKey("ZERO_REGISTER", reg)) ?? [];
  const pureXorRet = candidates.filter((g) => {
    if (g.instructions.length !== 2) return false;
    const [xor, ret] = g.instructions;
    return xor.mnemonic === "xor" &&
      xor.operands[0]?.trim().toLowerCase() === reg &&
      xor.operands[1]?.trim().toLowerCase() === reg &&
      ret.mnemonic === "ret";
  });
  return selectBest(pureXorRet);
}

function findUnaryGadget(index: CapabilityIndex, kind: string, reg: string): GadgetSelection | undefined {
  const candidates = index.capabilityMap.get(capKey(kind, reg)) ?? [];
  const valid = candidates.filter((g) => {
    const last = g.instructions[g.instructions.length - 1];
    return last?.mnemonic === "ret";
  });
  return selectBest(valid);
}

function findBinaryGadget(index: CapabilityIndex, kind: string, dst: string, src: string): GadgetSelection | undefined {
  const candidates = index.capabilityMap.get(capKey(kind, dst, src)) ?? [];
  const valid = candidates.filter((g) => {
    const last = g.instructions[g.instructions.length - 1];
    return last?.mnemonic === "ret";
  });
  return selectBest(valid);
}

function emitGadgetWithSideEffects(sel: GadgetSelection, comment: string): ChainStep[] {
  const steps: ChainStep[] = [gadgetStep(sel, comment)];
  steps.push(...extraPopSteps(sel.gadget));
  steps.push(...retImmPadding(sel.retImm));
  return steps;
}

function findTwoValueDecomposition(target: number, badchars: Set<number>, mode: "add" | "sub"): { a: number; b: number } | undefined {
  const t = target >>> 0;
  const probes = [
    0x01010101, 0x02020202, 0x03030303, 0x04040404, 0x05050505,
    0x06060606, 0x07070707, 0x08080808, 0x09090909, 0x0B0B0B0B,
    0x0C0C0C0C, 0x0E0E0E0E, 0x0F0F0F0F, 0x10101010, 0x11111111,
    0x20202020, 0x30303030, 0x40404040, 0x50505050, 0x7F7F7F7F,
    0x80808080, 0xFEFEFEFE, 0x12345678, 0x55555555, 0xAAAAAAAA,
  ];
  for (const a of probes) {
    if (!isBadcharFree(a, badchars)) continue;
    const b = mode === "add" ? ((t - a) >>> 0) : ((a - t) >>> 0);
    if (isBadcharFree(b, badchars)) return { a, b };
  }
  // Exhaustive single-byte sweep: pick byte 0 of A, derive rest
  for (let ab0 = 1; ab0 < 256; ab0++) {
    if (badchars.has(ab0)) continue;
    const a = ab0 | (ab0 << 8) | (ab0 << 16) | (ab0 << 24);
    const b = mode === "add" ? ((t - a) >>> 0) : ((a - t) >>> 0);
    if (isBadcharFree(b, badchars)) return { a, b };
  }
  return undefined;
}

function valueComment(reg: string, value: number): string {
  return `${reg} = ${hex32(value >>> 0)}`;
}

function tryDirect(
  index: CapabilityIndex, reg: string, value: number, badchars: Set<number>,
): ValueRecipe | undefined {
  if (!isBadcharFree(value, badchars)) return undefined;
  const pop = findPopGadget(index, reg);
  if (!pop) return undefined;
  const steps: ChainStep[] = [
    ...emitGadgetWithSideEffects(pop, `pop ${reg}`),
  ];
  // Insert the value right after the gadget address (before any side-effect junk)
  steps.splice(1, 0, valueStep(value, valueComment(reg, value)));
  return { steps, recipe: "direct", stackBytes: steps.length * 4 };
}

function tryNegate(
  index: CapabilityIndex, reg: string, value: number, badchars: Set<number>,
): ValueRecipe | undefined {
  const negValue = ((-value) >>> 0);
  if (!isBadcharFree(negValue, badchars)) return undefined;
  const pop = findPopGadget(index, reg);
  const neg = findUnaryGadget(index, "REGISTER_NEGATE", reg);
  if (!pop || !neg) return undefined;
  const steps: ChainStep[] = [
    ...emitGadgetWithSideEffects(pop, `pop ${reg}`),
  ];
  steps.splice(1, 0, valueStep(negValue, `${reg} = neg(${hex32(value >>> 0)}) = ${hex32(negValue)}`));
  steps.push(...emitGadgetWithSideEffects(neg, `neg ${reg} -> ${hex32(value >>> 0)}`));
  return { steps, recipe: "negate", stackBytes: steps.length * 4 };
}

function tryComplement(
  index: CapabilityIndex, reg: string, value: number, badchars: Set<number>,
): ValueRecipe | undefined {
  const notValue = (~value) >>> 0;
  if (!isBadcharFree(notValue, badchars)) return undefined;
  const pop = findPopGadget(index, reg);
  const not = findUnaryGadget(index, "REGISTER_NOT", reg);
  if (!pop || !not) return undefined;
  const steps: ChainStep[] = [
    ...emitGadgetWithSideEffects(pop, `pop ${reg}`),
  ];
  steps.splice(1, 0, valueStep(notValue, `${reg} = not(${hex32(value >>> 0)}) = ${hex32(notValue)}`));
  steps.push(...emitGadgetWithSideEffects(not, `not ${reg} -> ${hex32(value >>> 0)}`));
  return { steps, recipe: "complement", stackBytes: steps.length * 4 };
}

function tryTwoOp(
  index: CapabilityIndex, reg: string, value: number, badchars: Set<number>,
  mode: "add" | "sub",
): ValueRecipe | undefined {
  const decomp = findTwoValueDecomposition(value, badchars, mode);
  if (!decomp) return undefined;
  const capKind = mode === "add" ? "REGISTER_ADD" : "REGISTER_SUB";
  const pop = findPopGadget(index, reg);
  if (!pop) return undefined;

  for (const scratch of SCRATCH_CANDIDATES) {
    if (scratch === reg) continue;
    const binGadget = findBinaryGadget(index, capKind, reg, scratch);
    if (!binGadget) continue;
    const scratchPop = findPopGadget(index, scratch);
    if (!scratchPop) continue;

    const steps: ChainStep[] = [];
    // Step 1: pop dst, A
    const popSteps = emitGadgetWithSideEffects(pop, `pop ${reg}`);
    popSteps.splice(1, 0, valueStep(decomp.a, `${reg} = ${hex32(decomp.a)}`));
    steps.push(...popSteps);
    // Step 2: pop scratch, B
    const scratchSteps = emitGadgetWithSideEffects(scratchPop, `pop ${scratch}`);
    scratchSteps.splice(1, 0, valueStep(decomp.b, `${scratch} = ${hex32(decomp.b)}`));
    steps.push(...scratchSteps);
    // Step 3: add/sub dst, scratch
    const op = mode === "add" ? "add" : "sub";
    steps.push(...emitGadgetWithSideEffects(binGadget, `${op} ${reg}, ${scratch} -> ${hex32(value >>> 0)}`));

    return { steps, recipe: mode === "add" ? "two-add" : "two-sub", scratchRegister: scratch, stackBytes: steps.length * 4 };
  }
  return undefined;
}

function tryZeroAdd(
  index: CapabilityIndex, reg: string, value: number, badchars: Set<number>,
): ValueRecipe | undefined {
  if (!isBadcharFree(value, badchars)) return undefined;
  const zero = findZeroGadget(index, reg);
  if (!zero) return undefined;

  for (const scratch of SCRATCH_CANDIDATES) {
    if (scratch === reg) continue;
    const addGadget = findBinaryGadget(index, "REGISTER_ADD", reg, scratch);
    if (!addGadget) continue;
    const scratchPop = findPopGadget(index, scratch);
    if (!scratchPop) continue;

    const steps: ChainStep[] = [];
    steps.push(...emitGadgetWithSideEffects(zero, `xor ${reg}, ${reg}`));
    const scratchSteps = emitGadgetWithSideEffects(scratchPop, `pop ${scratch}`);
    scratchSteps.splice(1, 0, valueStep(value, `${scratch} = ${hex32(value >>> 0)}`));
    steps.push(...scratchSteps);
    steps.push(...emitGadgetWithSideEffects(addGadget, `add ${reg}, ${scratch} -> ${hex32(value >>> 0)}`));

    return { steps, recipe: "zero-add", scratchRegister: scratch, stackBytes: steps.length * 4 };
  }
  return undefined;
}

function tryZeroSubNeg(
  index: CapabilityIndex, reg: string, value: number, badchars: Set<number>,
): ValueRecipe | undefined {
  if (!isBadcharFree(value, badchars)) return undefined;
  const zero = findZeroGadget(index, reg);
  const neg = findUnaryGadget(index, "REGISTER_NEGATE", reg);
  if (!zero || !neg) return undefined;

  for (const scratch of SCRATCH_CANDIDATES) {
    if (scratch === reg) continue;
    const subGadget = findBinaryGadget(index, "REGISTER_SUB", reg, scratch);
    if (!subGadget) continue;
    const scratchPop = findPopGadget(index, scratch);
    if (!scratchPop) continue;

    const steps: ChainStep[] = [];
    steps.push(...emitGadgetWithSideEffects(zero, `xor ${reg}, ${reg}`));
    const scratchSteps = emitGadgetWithSideEffects(scratchPop, `pop ${scratch}`);
    scratchSteps.splice(1, 0, valueStep(value, `${scratch} = ${hex32(value >>> 0)}`));
    steps.push(...scratchSteps);
    steps.push(...emitGadgetWithSideEffects(subGadget, `sub ${reg}, ${scratch} -> neg(${hex32(value >>> 0)})`));
    steps.push(...emitGadgetWithSideEffects(neg, `neg ${reg} -> ${hex32(value >>> 0)}`));

    return { steps, recipe: "zero-sub-neg", scratchRegister: scratch, stackBytes: steps.length * 4 };
  }
  return undefined;
}

export function solveValue(
  index: CapabilityIndex,
  register: string,
  value: number,
  badchars: number[],
): ValueRecipe | undefined {
  const reg = register.trim().toLowerCase();
  const v = value >>> 0;
  const bc = new Set(badchars.map((b) => b & 0xff));

  return tryDirect(index, reg, v, bc)
    ?? tryNegate(index, reg, v, bc)
    ?? tryComplement(index, reg, v, bc)
    ?? tryTwoOp(index, reg, v, bc, "add")
    ?? tryTwoOp(index, reg, v, bc, "sub")
    ?? tryZeroAdd(index, reg, v, bc)
    ?? tryZeroSubNeg(index, reg, v, bc);
}
