import { CapabilityIndex } from "./capabilities";
import { ChainStep, GadgetSelection, firstKnownAddress, hex32, retImmBytes, retImmPadding } from "./chain";
import { RopGadget } from "./types";

export type RecipeKind = "direct" | "negate" | "complement" | "two-add" | "two-sub" | "zero-add" | "zero-sub-neg";

export interface ValueRecipe {
  steps: ChainStep[];
  recipe: RecipeKind;
  scratchRegister?: string;
  stackBytes: number;
  /** Registers this recipe overwrites: the target, any scratch, and every side-effect pop. */
  clobbers: string[];
}

const SCRATCH_CANDIDATES = ["eax", "ecx", "edx", "ebx", "esi", "edi"];

const SUBREGISTER_PARENT: Record<string, string> = {
  ax: "eax", al: "eax", ah: "eax",
  bx: "ebx", bl: "ebx", bh: "ebx",
  cx: "ecx", cl: "ecx", ch: "ecx",
  dx: "edx", dl: "edx", dh: "edx",
  si: "esi", di: "edi", bp: "ebp", sp: "esp",
};

const X86_REGISTERS = new Set<string>([
  "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
  ...Object.keys(SUBREGISTER_PARENT),
]);

// Mnemonics whose first operand is the written destination register.
const WRITE_DEST_MNEMONICS = new Set<string>([
  "mov", "movzx", "movsx", "lea", "xor", "or", "and", "add", "sub", "adc",
  "sbb", "inc", "dec", "neg", "not", "imul", "shl", "shr", "sar", "sal",
  "rol", "ror", "bswap", "xadd", "cmovz", "cmovnz", "cmove", "cmovne",
]);

// Instructions that read/write ESP in a way we cannot cleanly turn into filler.
const STACK_UNSAFE_MNEMONICS = new Set<string>(["push", "pusha", "pushad", "leave", "enter", "call", "jmp", "int", "iret"]);

function normalizeRegister(operand: string | undefined): string | undefined {
  const reg = operand?.trim().toLowerCase();
  if (!reg || !X86_REGISTERS.has(reg)) return undefined;
  return SUBREGISTER_PARENT[reg] ?? reg;
}

function parseImmediate(operand: string | undefined): number | undefined {
  if (operand === undefined) return undefined;
  const t = operand.trim().toLowerCase();
  if (/^0x[0-9a-f]+$/.test(t)) return parseInt(t, 16);
  if (/^[0-9]+$/.test(t)) return parseInt(t, 10);
  if (/^[0-9a-f]+h$/.test(t)) return parseInt(t.slice(0, -1), 16);
  return undefined;
}

interface GadgetEffects {
  /** 32-bit registers written as a side effect (excludes the primary instruction's target). */
  clobbers: string[];
  /** Filler words for every extra stack slot the gadget consumes past its primary op, in stack order. */
  fillers: ChainStep[];
  /** False when the gadget shifts ESP in a way we cannot pad (push, sub esp, misaligned add esp, esp writes). */
  safe: boolean;
  reason?: string;
}

/**
 * Full side-effect model for a gadget used in value construction. The first
 * instruction is the primary operation (a value-consuming `pop reg` or an ALU
 * op); every later instruction before the terminating `ret` is a side effect.
 * We track which registers those side effects clobber and how many extra stack
 * slots they consume, so the chain can be padded and the caller can preserve
 * live registers. Gadgets whose ESP movement cannot be cleanly padded are
 * marked unsafe and excluded from selection.
 */
function gadgetEffects(gadget: RopGadget): GadgetEffects {
  const insns = gadget.instructions;
  const clobbers = new Set<string>();
  const fillers: ChainStep[] = [];
  let safe = true;
  let reason: string | undefined;
  const markUnsafe = (why: string): void => {
    if (safe) { safe = false; reason = why; }
  };

  for (let i = 1; i < insns.length; i++) {
    const insn = insns[i];
    const mnemonic = insn.mnemonic.trim().toLowerCase();
    if (mnemonic === "ret" || mnemonic === "retn") break; // terminator; ret N handled via retImmPadding
    const rawDst = insn.operands[0]?.trim().toLowerCase();
    const dst = normalizeRegister(insn.operands[0]);

    if (mnemonic === "pop") {
      clobbers.add(dst ?? rawDst ?? "?");
      fillers.push({ kind: "value", value: 0x41414141, comment: `junk (${rawDst ?? "?"} side effect)` });
      continue;
    }
    if ((mnemonic === "add" || mnemonic === "sub") && rawDst === "esp") {
      const imm = parseImmediate(insn.operands[1]);
      if (imm === undefined || imm % 4 !== 0) { markUnsafe(`${mnemonic} esp, ${insn.operands[1] ?? "?"} is not a paddable 4-byte multiple`); continue; }
      if (mnemonic === "sub") { markUnsafe(`sub esp, 0x${imm.toString(16)} shifts ESP back into consumed stack`); continue; }
      for (let k = 0; k < imm / 4; k++) {
        fillers.push({ kind: "value", value: 0x41414141, comment: `junk (add esp, 0x${imm.toString(16)})` });
      }
      continue;
    }
    if (STACK_UNSAFE_MNEMONICS.has(mnemonic)) { markUnsafe(`${mnemonic} alters ESP/control unpredictably`); continue; }
    if (dst === "esp") { markUnsafe(`${mnemonic} writes ESP directly`); continue; }
    if (mnemonic === "xchg") {
      const a = normalizeRegister(insn.operands[0]);
      const b = normalizeRegister(insn.operands[1]);
      if (a === "esp" || b === "esp") { markUnsafe("xchg with ESP"); continue; }
      if (a) clobbers.add(a);
      if (b) clobbers.add(b);
      continue;
    }
    if (mnemonic === "cmp" || mnemonic === "test" || mnemonic === "nop") continue;
    if (dst) {
      // Known writer, or an unrecognized mnemonic with a register destination:
      // assume it clobbers rather than risk a silent overwrite.
      clobbers.add(dst);
    }
  }
  return { clobbers: [...clobbers], fillers, safe, reason };
}

// True if the register is written again after its initial pop (by a later pop,
// an ALU write, or an xchg), so the popped value does NOT survive to the ret.
// Such a gadget cannot be used to load that register to a chosen value.
function poppedRegisterSurvives(gadget: RopGadget, reg: string): boolean {
  const insns = gadget.instructions;
  const target = SUBREGISTER_PARENT[reg] ?? reg;
  for (let i = 1; i < insns.length; i++) {
    const insn = insns[i];
    const mnemonic = insn.mnemonic.trim().toLowerCase();
    if (mnemonic === "ret" || mnemonic === "retn") break;
    const dst = normalizeRegister(insn.operands[0]);
    if (mnemonic === "pop" && dst === target) return false;
    if (mnemonic === "xchg") {
      const a = normalizeRegister(insn.operands[0]);
      const b = normalizeRegister(insn.operands[1]);
      if (a === target || b === target) return false;
      continue;
    }
    if (WRITE_DEST_MNEMONICS.has(mnemonic) && dst === target) return false;
  }
  return true;
}

// Mnemonic of the last instruction (before the ret) that writes `reg`, or
// undefined if none does. Used to confirm the intended operation is the final
// thing that touches the register — e.g. `neg ecx ; sbb ecx, ecx ; ret` writes
// ecx last with sbb, so it is NOT a usable negate gadget for ecx.
function registerFinalWriteMnemonic(gadget: RopGadget, reg: string): string | undefined {
  const target = SUBREGISTER_PARENT[reg] ?? reg;
  let last: string | undefined;
  const insns = gadget.instructions;
  for (let i = 0; i < insns.length; i++) {
    const insn = insns[i];
    const mnemonic = insn.mnemonic.trim().toLowerCase();
    if (mnemonic === "ret" || mnemonic === "retn") break;
    const dst = normalizeRegister(insn.operands[0]);
    if (mnemonic === "pop" && dst === target) { last = "pop"; continue; }
    if (mnemonic === "xchg") {
      const a = normalizeRegister(insn.operands[0]);
      const b = normalizeRegister(insn.operands[1]);
      if (a === target || b === target) last = "xchg";
      continue;
    }
    if (WRITE_DEST_MNEMONICS.has(mnemonic) && dst === target) last = mnemonic;
  }
  return last;
}

const OPERATION_MNEMONIC: Record<string, string> = {
  REGISTER_NEGATE: "neg",
  REGISTER_NOT: "not",
  REGISTER_ADD: "add",
  REGISTER_SUB: "sub",
};

function collectClobbers(primaryReg: string, gadgets: RopGadget[], scratch?: string): string[] {
  const set = new Set<string>([primaryReg]);
  if (scratch) set.add(scratch);
  for (const gadget of gadgets) {
    for (const reg of gadgetEffects(gadget).clobbers) set.add(reg);
  }
  return [...set];
}

function isBadcharFree(value: number, badchars: Set<number>): boolean {
  if (badchars.size === 0) return true;
  const w = value >>> 0;
  for (let i = 0; i < 4; i++) {
    if (badchars.has((w >>> (i * 8)) & 0xff)) return false;
  }
  return true;
}

// A gadget ending in `ret N` costs N/4 filler words in the chain and shifts ESP
// forward by N. Beyond this cap the padding is impractical (and demands that
// much extra controlled stack), so such gadgets — e.g. a function epilogue with
// `ret 0x1010` — are excluded rather than compensated with hundreds of words.
const MAX_RET_IMM = 0x40;

// Optional reliability hint: returns false for addresses in a module that is
// currently relocated off its preferred base (its address will differ next run).
// Set for the duration of solveValue so selectBest can prefer stable gadgets.
let stableAddressHint: ((address: bigint) => boolean) | undefined;

function gadgetIsStable(gadget: RopGadget): boolean {
  if (!stableAddressHint) return true;
  const addr = firstKnownAddress(gadget);
  return addr === undefined ? true : stableAddressHint(addr);
}

function selectBest(candidates: RopGadget[], preserve?: Set<string>): GadgetSelection | undefined {
  const withAddr = candidates
    .map((g) => ({ gadget: g, retImm: retImmBytes(g), effects: gadgetEffects(g) }))
    .filter((s) => s.retImm >= 0 && s.retImm <= MAX_RET_IMM && firstKnownAddress(s.gadget) !== undefined)
    // Drop gadgets whose ESP movement cannot be cleanly padded — they would
    // desync the chain no matter how the values are laid out.
    .filter((s) => s.effects.safe)
    // Exclude gadgets whose side effects would clobber a register the caller
    // asked to keep live (e.g. eax already loaded for a stdcall frame). This
    // covers register writes of any kind, not just pops.
    .filter((s) => !preserve || !s.effects.clobbers.some((r) => preserve.has(r)));
  if (withAddr.length === 0) return undefined;
  withAddr.sort((a, b) => {
    // Reliability first: a gadget from a module loaded at its preferred base
    // keeps its address next run; one from a relocated module does not.
    const aStable = gadgetIsStable(a.gadget) ? 0 : 1;
    const bStable = gadgetIsStable(b.gadget) ? 0 : 1;
    if (aStable !== bStable) return aStable - bStable;
    if (a.retImm !== b.retImm) return a.retImm - b.retImm;
    // Prefer gadgets with the smallest side-effect footprint: a clean
    // `pop reg ; ret` beats one that also pops, writes, or skips stack.
    const aCost = a.effects.clobbers.length + a.effects.fillers.length;
    const bCost = b.effects.clobbers.length + b.effects.fillers.length;
    if (aCost !== bCost) return aCost - bCost;
    return b.gadget.score - a.gadget.score;
  });
  return { gadget: withAddr[0].gadget, retImm: withAddr[0].retImm };
}

function gadgetStep(sel: GadgetSelection, comment: string): ChainStep {
  return { kind: "gadget", address: firstKnownAddress(sel.gadget)!, comment };
}

function valueStep(value: number, comment: string): ChainStep {
  return { kind: "value", value: value >>> 0, comment };
}

function extraPopSteps(gadget: RopGadget): ChainStep[] {
  return gadgetEffects(gadget).fillers;
}

function capKey(kind: string, register?: string, targetRegister?: string): string {
  return [kind, register ?? "", targetRegister ?? ""].join(":");
}

function findPopGadget(index: CapabilityIndex, reg: string, preserve?: Set<string>): GadgetSelection | undefined {
  const candidates = index.capabilityMap.get(capKey("LOAD_REGISTER", reg)) ?? [];
  const purePopRet = candidates.filter((g) => {
    if (g.instructions.length < 2) return false;
    const last = g.instructions[g.instructions.length - 1];
    if (last.mnemonic !== "ret") return false;
    return g.instructions[0].mnemonic === "pop" &&
      g.instructions[0].operands[0]?.trim().toLowerCase() === reg &&
      poppedRegisterSurvives(g, reg);
  });
  return selectBest(purePopRet, preserve);
}

function findZeroGadget(index: CapabilityIndex, reg: string, preserve?: Set<string>): GadgetSelection | undefined {
  const candidates = index.capabilityMap.get(capKey("ZERO_REGISTER", reg)) ?? [];
  const pureXorRet = candidates.filter((g) => {
    if (g.instructions.length !== 2) return false;
    const [xor, ret] = g.instructions;
    return xor.mnemonic === "xor" &&
      xor.operands[0]?.trim().toLowerCase() === reg &&
      xor.operands[1]?.trim().toLowerCase() === reg &&
      ret.mnemonic === "ret";
  });
  return selectBest(pureXorRet, preserve);
}

function findUnaryGadget(index: CapabilityIndex, kind: string, reg: string, preserve?: Set<string>): GadgetSelection | undefined {
  const candidates = index.capabilityMap.get(capKey(kind, reg)) ?? [];
  const expected = OPERATION_MNEMONIC[kind];
  const valid = candidates.filter((g) => {
    const last = g.instructions[g.instructions.length - 1];
    if (last?.mnemonic !== "ret") return false;
    // The operation must be the final write to reg, so its result survives the ret.
    return expected === undefined || registerFinalWriteMnemonic(g, reg) === expected;
  });
  return selectBest(valid, preserve);
}

function findBinaryGadget(index: CapabilityIndex, kind: string, dst: string, src: string, preserve?: Set<string>): GadgetSelection | undefined {
  const candidates = index.capabilityMap.get(capKey(kind, dst, src)) ?? [];
  const expected = OPERATION_MNEMONIC[kind];
  const valid = candidates.filter((g) => {
    const last = g.instructions[g.instructions.length - 1];
    if (last?.mnemonic !== "ret") return false;
    return expected === undefined || registerFinalWriteMnemonic(g, dst) === expected;
  });
  return selectBest(valid, preserve);
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
  index: CapabilityIndex, reg: string, value: number, badchars: Set<number>, preserve: Set<string>,
): ValueRecipe | undefined {
  if (!isBadcharFree(value, badchars)) return undefined;
  const pop = findPopGadget(index, reg, preserve);
  if (!pop) return undefined;
  const steps: ChainStep[] = [
    ...emitGadgetWithSideEffects(pop, `pop ${reg}`),
  ];
  // Insert the value right after the gadget address (before any side-effect junk)
  steps.splice(1, 0, valueStep(value, valueComment(reg, value)));
  return { steps, recipe: "direct", stackBytes: steps.length * 4, clobbers: collectClobbers(reg, [pop.gadget]) };
}

function tryNegate(
  index: CapabilityIndex, reg: string, value: number, badchars: Set<number>, preserve: Set<string>,
): ValueRecipe | undefined {
  const negValue = ((-value) >>> 0);
  if (!isBadcharFree(negValue, badchars)) return undefined;
  const pop = findPopGadget(index, reg, preserve);
  const neg = findUnaryGadget(index, "REGISTER_NEGATE", reg, preserve);
  if (!pop || !neg) return undefined;
  const steps: ChainStep[] = [
    ...emitGadgetWithSideEffects(pop, `pop ${reg}`),
  ];
  steps.splice(1, 0, valueStep(negValue, `${reg} = neg(${hex32(value >>> 0)}) = ${hex32(negValue)}`));
  steps.push(...emitGadgetWithSideEffects(neg, `neg ${reg} -> ${hex32(value >>> 0)}`));
  return { steps, recipe: "negate", stackBytes: steps.length * 4, clobbers: collectClobbers(reg, [pop.gadget, neg.gadget]) };
}

function tryComplement(
  index: CapabilityIndex, reg: string, value: number, badchars: Set<number>, preserve: Set<string>,
): ValueRecipe | undefined {
  const notValue = (~value) >>> 0;
  if (!isBadcharFree(notValue, badchars)) return undefined;
  const pop = findPopGadget(index, reg, preserve);
  const not = findUnaryGadget(index, "REGISTER_NOT", reg, preserve);
  if (!pop || !not) return undefined;
  const steps: ChainStep[] = [
    ...emitGadgetWithSideEffects(pop, `pop ${reg}`),
  ];
  steps.splice(1, 0, valueStep(notValue, `${reg} = not(${hex32(value >>> 0)}) = ${hex32(notValue)}`));
  steps.push(...emitGadgetWithSideEffects(not, `not ${reg} -> ${hex32(value >>> 0)}`));
  return { steps, recipe: "complement", stackBytes: steps.length * 4, clobbers: collectClobbers(reg, [pop.gadget, not.gadget]) };
}

function tryTwoOp(
  index: CapabilityIndex, reg: string, value: number, badchars: Set<number>, preserve: Set<string>,
  mode: "add" | "sub",
): ValueRecipe | undefined {
  const decomp = findTwoValueDecomposition(value, badchars, mode);
  if (!decomp) return undefined;
  const capKind = mode === "add" ? "REGISTER_ADD" : "REGISTER_SUB";
  const pop = findPopGadget(index, reg, preserve);
  if (!pop) return undefined;

  // Evaluate every scratch register and keep the cheapest chain (fewest words),
  // so a clean `add reg, edx ; ret` beats an `add reg, ecx ; ret N` that would
  // drag in filler words.
  let best: ValueRecipe | undefined;
  for (const scratch of SCRATCH_CANDIDATES) {
    if (scratch === reg || preserve.has(scratch)) continue;
    const binGadget = findBinaryGadget(index, capKind, reg, scratch, preserve);
    if (!binGadget) continue;
    const scratchPop = findPopGadget(index, scratch, preserve);
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

    const recipe: ValueRecipe = {
      steps,
      recipe: mode === "add" ? "two-add" : "two-sub",
      scratchRegister: scratch,
      stackBytes: steps.length * 4,
      clobbers: collectClobbers(reg, [pop.gadget, scratchPop.gadget, binGadget.gadget], scratch),
    };
    if (!best || recipe.stackBytes < best.stackBytes) best = recipe;
  }
  return best;
}

function tryZeroAdd(
  index: CapabilityIndex, reg: string, value: number, badchars: Set<number>, preserve: Set<string>,
): ValueRecipe | undefined {
  if (!isBadcharFree(value, badchars)) return undefined;
  const zero = findZeroGadget(index, reg, preserve);
  if (!zero) return undefined;

  for (const scratch of SCRATCH_CANDIDATES) {
    if (scratch === reg || preserve.has(scratch)) continue;
    const addGadget = findBinaryGadget(index, "REGISTER_ADD", reg, scratch, preserve);
    if (!addGadget) continue;
    const scratchPop = findPopGadget(index, scratch, preserve);
    if (!scratchPop) continue;

    const steps: ChainStep[] = [];
    steps.push(...emitGadgetWithSideEffects(zero, `xor ${reg}, ${reg}`));
    const scratchSteps = emitGadgetWithSideEffects(scratchPop, `pop ${scratch}`);
    scratchSteps.splice(1, 0, valueStep(value, `${scratch} = ${hex32(value >>> 0)}`));
    steps.push(...scratchSteps);
    steps.push(...emitGadgetWithSideEffects(addGadget, `add ${reg}, ${scratch} -> ${hex32(value >>> 0)}`));

    return {
      steps,
      recipe: "zero-add",
      scratchRegister: scratch,
      stackBytes: steps.length * 4,
      clobbers: collectClobbers(reg, [zero.gadget, scratchPop.gadget, addGadget.gadget], scratch),
    };
  }
  return undefined;
}

function tryZeroSubNeg(
  index: CapabilityIndex, reg: string, value: number, badchars: Set<number>, preserve: Set<string>,
): ValueRecipe | undefined {
  if (!isBadcharFree(value, badchars)) return undefined;
  const zero = findZeroGadget(index, reg, preserve);
  const neg = findUnaryGadget(index, "REGISTER_NEGATE", reg, preserve);
  if (!zero || !neg) return undefined;

  for (const scratch of SCRATCH_CANDIDATES) {
    if (scratch === reg || preserve.has(scratch)) continue;
    const subGadget = findBinaryGadget(index, "REGISTER_SUB", reg, scratch, preserve);
    if (!subGadget) continue;
    const scratchPop = findPopGadget(index, scratch, preserve);
    if (!scratchPop) continue;

    const steps: ChainStep[] = [];
    steps.push(...emitGadgetWithSideEffects(zero, `xor ${reg}, ${reg}`));
    const scratchSteps = emitGadgetWithSideEffects(scratchPop, `pop ${scratch}`);
    scratchSteps.splice(1, 0, valueStep(value, `${scratch} = ${hex32(value >>> 0)}`));
    steps.push(...scratchSteps);
    steps.push(...emitGadgetWithSideEffects(subGadget, `sub ${reg}, ${scratch} -> neg(${hex32(value >>> 0)})`));
    steps.push(...emitGadgetWithSideEffects(neg, `neg ${reg} -> ${hex32(value >>> 0)}`));

    return {
      steps,
      recipe: "zero-sub-neg",
      scratchRegister: scratch,
      stackBytes: steps.length * 4,
      clobbers: collectClobbers(reg, [zero.gadget, scratchPop.gadget, subGadget.gadget, neg.gadget], scratch),
    };
  }
  return undefined;
}

export function solveValue(
  index: CapabilityIndex,
  register: string,
  value: number,
  badchars: number[],
  preserveRegisters: string[] = [],
  preferStable?: (address: bigint) => boolean,
): ValueRecipe | undefined {
  const reg = register.trim().toLowerCase();
  const v = value >>> 0;
  const bc = new Set(badchars.map((b) => b & 0xff));
  // The target register is clobbered by definition; drop it from the preserve
  // set so it can never exclude its own construction.
  const preserve = new Set(preserveRegisters.map((r) => r.trim().toLowerCase()));
  preserve.delete(reg);

  stableAddressHint = preferStable;
  try {
    return tryDirect(index, reg, v, bc, preserve)
      ?? tryNegate(index, reg, v, bc, preserve)
      ?? tryComplement(index, reg, v, bc, preserve)
      ?? tryTwoOp(index, reg, v, bc, preserve, "add")
      ?? tryTwoOp(index, reg, v, bc, preserve, "sub")
      ?? tryZeroAdd(index, reg, v, bc, preserve)
      ?? tryZeroSubNeg(index, reg, v, bc, preserve);
  } finally {
    stableAddressHint = undefined;
  }
}
