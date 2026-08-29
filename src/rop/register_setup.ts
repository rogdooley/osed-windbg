import { buildCapabilities, CapabilityIndex } from "./capabilities";
import { ChainStep, firstKnownAddress, hex32, retImmBytes, retImmPadding } from "./chain";
import { RopGadget } from "./types";
import { solveValue } from "./value_solver";

// Register-packing setup planner. Unlike solveValue (one register at a time),
// this loads a whole set of target registers at once — the case you hit when
// staging a PUSHAD or stdcall frame, where every register is live and no
// collateral write can be tolerated. It exploits multi-pop gadgets to cover
// several targets per gadget and schedules the gadget order so that a gadget
// never overwrites a register that is already final. When no ordering works it
// reports the conflict honestly instead of emitting a corrupt chain.

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

const WRITE_DEST_MNEMONICS = new Set<string>([
  "mov", "movzx", "movsx", "lea", "xor", "or", "and", "add", "sub", "adc",
  "sbb", "inc", "dec", "neg", "not", "imul", "shl", "shr", "sar", "sal",
  "rol", "ror", "bswap", "xadd",
]);

const STACK_UNSAFE_MNEMONICS = new Set<string>(["push", "pusha", "pushad", "leave", "enter", "call", "jmp", "int", "iret"]);

function parent(reg: string): string {
  return SUBREGISTER_PARENT[reg] ?? reg;
}

function normalizeRegister(operand: string | undefined): string | undefined {
  const reg = operand?.trim().toLowerCase();
  if (!reg || !X86_REGISTERS.has(reg)) return undefined;
  return parent(reg);
}

function parseImmediate(operand: string | undefined): number | undefined {
  if (operand === undefined) return undefined;
  const t = operand.trim().toLowerCase();
  if (/^0x[0-9a-f]+$/.test(t)) return parseInt(t, 16);
  if (/^[0-9]+$/.test(t)) return parseInt(t, 10);
  if (/^[0-9a-f]+h$/.test(t)) return parseInt(t.slice(0, -1), 16);
  return undefined;
}

interface GadgetShape {
  /** Registers popped, in stack order (parent-normalized). Determines the slot layout. */
  popRegs: string[];
  /** Registers whose final in-gadget write is a pop, so they can be set to an arbitrary value. */
  cleanPops: Set<string>;
  /** Every register the gadget writes (pops + non-pop writes) — anything here corrupts a finalized target. */
  writes: Set<string>;
  /** Filler words for `add esp` skips, in order. */
  espFillers: ChainStep[];
  /** False when the gadget shifts ESP in a way we cannot pad. */
  safe: boolean;
}

function analyzeGadget(gadget: RopGadget): GadgetShape {
  const popRegs: string[] = [];
  const writes = new Set<string>();
  const espFillers: ChainStep[] = [];
  const lastWriteWasPop = new Map<string, boolean>();
  let safe = true;

  const insns = gadget.instructions;
  for (let i = 0; i < insns.length; i++) {
    const insn = insns[i];
    const mnemonic = insn.mnemonic.trim().toLowerCase();
    if (mnemonic === "ret" || mnemonic === "retn") break;
    const rawDst = insn.operands[0]?.trim().toLowerCase();
    const dst = normalizeRegister(insn.operands[0]);

    if (mnemonic === "pop") {
      const reg = dst ?? rawDst ?? "?";
      popRegs.push(reg);
      writes.add(reg);
      lastWriteWasPop.set(reg, true);
      continue;
    }
    if ((mnemonic === "add" || mnemonic === "sub") && rawDst === "esp") {
      const imm = parseImmediate(insn.operands[1]);
      if (imm === undefined || imm % 4 !== 0 || mnemonic === "sub") { safe = false; continue; }
      for (let k = 0; k < imm / 4; k++) {
        espFillers.push({ kind: "value", value: 0x41414141, comment: `junk (add esp, 0x${imm.toString(16)})` });
      }
      continue;
    }
    if (STACK_UNSAFE_MNEMONICS.has(mnemonic)) { safe = false; continue; }
    if (dst === "esp") { safe = false; continue; }
    if (mnemonic === "xchg") {
      const a = normalizeRegister(insn.operands[0]);
      const b = normalizeRegister(insn.operands[1]);
      if (a === "esp" || b === "esp") { safe = false; continue; }
      if (a) { writes.add(a); lastWriteWasPop.set(a, false); }
      if (b) { writes.add(b); lastWriteWasPop.set(b, false); }
      continue;
    }
    if (mnemonic === "cmp" || mnemonic === "test" || mnemonic === "nop") continue;
    if (dst) { writes.add(dst); lastWriteWasPop.set(dst, false); }
  }

  const cleanPops = new Set<string>();
  for (const [reg, wasPop] of lastWriteWasPop) {
    if (wasPop) cleanPops.add(reg);
  }
  return { popRegs, cleanPops, writes, espFillers, safe };
}

function describeGadget(gadget: RopGadget): string {
  return gadget.instructions
    .map((insn) => (insn.operands.length > 0 ? `${insn.mnemonic} ${insn.operands.join(", ")}` : insn.mnemonic))
    .join(" ; ");
}

function isBadcharFree(value: number, badchars: Set<number>): boolean {
  if (badchars.size === 0) return true;
  const w = value >>> 0;
  for (let i = 0; i < 4; i++) {
    if (badchars.has((w >>> (i * 8)) & 0xff)) return false;
  }
  return true;
}

function addressBadcharFree(address: bigint, badchars: Set<number>): boolean {
  return isBadcharFree(Number(address & BigInt(0xffffffff)), badchars);
}

export interface RegisterSetupPlan {
  steps: ChainStep[];
  /** Registers in the order they were finalized. */
  ordered: string[];
  /** Targets that could not be set, with a reason. */
  unresolved: Array<{ register: string; reason: string }>;
  stackBytes: number;
  success: boolean;
}

interface Candidate {
  gadget: RopGadget;
  shape: GadgetShape;
  address: bigint;
  retImm: number;
  score: number;
}

/**
 * Plan a chain that loads every target register, packing targets into multi-pop
 * gadgets and ordering gadgets so none overwrites an already-finalized target.
 * Values must be directly poppable (badchar-free); build badchar-tainted values
 * with rop.construct first, or set that register separately.
 */
export function planRegisterSetupPacking(
  index: CapabilityIndex,
  targets: Record<string, number>,
  badchars: number[] = [],
): RegisterSetupPlan {
  const bc = new Set(badchars.map((b) => b & 0xff));
  const targetValues = new Map<string, number>();
  for (const [reg, value] of Object.entries(targets)) {
    targetValues.set(parent(reg.trim().toLowerCase()), value >>> 0);
  }

  // Both the packing path and the arithmetic path (solveValue) must see the same
  // badchar-clean corpus, so a gadget whose address contains a badchar is never
  // selected by either. Rebuild a filtered index once and use it throughout.
  const workingIndex = bc.size === 0
    ? index
    : buildCapabilities(index.gadgets.filter((g) => {
        const addr = firstKnownAddress(g);
        return addr === undefined || addressBadcharFree(addr, bc);
      }));

  const candidates: Candidate[] = workingIndex.gadgets
    .map((gadget) => ({ gadget, shape: analyzeGadget(gadget), address: firstKnownAddress(gadget), retImm: retImmBytes(gadget) }))
    .filter((c): c is Candidate & { address: bigint } =>
      c.address !== undefined && c.retImm >= 0 && c.shape.safe && c.shape.popRegs.length > 0)
    .map((c) => ({ gadget: c.gadget, shape: c.shape, address: c.address, retImm: c.retImm, score: c.gadget.score }));

  // How often each register appears as a write across candidates. Registers that
  // are frequently clobbered (e.g. eax on compiler-heavy corpora) get deferred to
  // the end so earlier gadgets don't need to avoid them.
  const clobberFrequency = new Map<string, number>();
  for (const c of candidates) {
    for (const reg of c.shape.writes) clobberFrequency.set(reg, (clobberFrequency.get(reg) ?? 0) + 1);
  }

  const pending = new Set(targetValues.keys());
  const done = new Set<string>();
  const steps: ChainStep[] = [];
  const ordered: string[] = [];

  const keyGreater = (a: number[], b: number[] | undefined): boolean => {
    if (!b) return true;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return a[i] > b[i];
    }
    return false;
  };

  while (pending.size > 0) {
    let best: { candidate: Candidate; cover: Set<string> } | undefined;
    let bestKey: number[] | undefined;

    for (const candidate of candidates) {
      if (!addressBadcharFree(candidate.address, bc)) continue;
      // A gadget must not write any already-finalized target.
      let corrupts = false;
      for (const reg of candidate.shape.writes) {
        if (done.has(reg)) { corrupts = true; break; }
      }
      if (corrupts) continue;

      // Cover = pending targets this gadget can cleanly set to their (badchar-free) value.
      const cover = new Set<string>();
      for (const reg of candidate.shape.cleanPops) {
        if (!pending.has(reg)) continue;
        if (!isBadcharFree(targetValues.get(reg)!, bc)) continue;
        cover.add(reg);
      }
      if (cover.size === 0) continue;

      const waste = candidate.shape.writes.size - cover.size + candidate.shape.espFillers.length;
      let deferSum = 0;
      for (const reg of cover) deferSum += clobberFrequency.get(reg) ?? 0;
      // Lexicographic, all maximized: cover the most; then prefer covering
      // low-collateral-frequency registers (defer eax-like registers that other
      // gadgets clobber, so they get set last); then least waste; then score.
      const key = [cover.size, -deferSum, -waste, candidate.score, -candidate.retImm];
      if (keyGreater(key, bestKey)) { bestKey = key; best = { candidate, cover }; }
    }

    if (best) {
      // Direct multi-pop packing for badchar-free values.
      const { candidate, cover } = best;
      steps.push({ kind: "gadget", address: candidate.address, comment: describeGadget(candidate.gadget) });
      // Assign each target its value at the LAST slot that pops it; junk elsewhere.
      const lastIndexOf = new Map<string, number>();
      candidate.shape.popRegs.forEach((reg, idx) => lastIndexOf.set(reg, idx));
      candidate.shape.popRegs.forEach((reg, idx) => {
        if (cover.has(reg) && lastIndexOf.get(reg) === idx) {
          steps.push({ kind: "value", value: targetValues.get(reg)! >>> 0, comment: `${reg} = ${hex32(targetValues.get(reg)!)}` });
        } else {
          steps.push({ kind: "value", value: 0x41414141, comment: `junk (${reg})` });
        }
      });
      steps.push(...candidate.shape.espFillers);
      steps.push(...retImmPadding(candidate.retImm));
      for (const reg of cover) { pending.delete(reg); done.add(reg); ordered.push(reg); }
      continue;
    }

    // No direct pop covers a pending target (typical for frame values, which are
    // null-heavy). Fall back to arithmetic construction for one register, built
    // so it preserves every already-finalized register. Registers that NEED a
    // scratch are built first, while pending registers are still free to borrow.
    const arith = pickArithmeticBuild(workingIndex, pending, targetValues, badchars, done, keyGreater);
    if (!arith) break;
    steps.push(...arith.recipe.steps);
    pending.delete(arith.register);
    done.add(arith.register);
    ordered.push(arith.register);
  }

  const unresolved = [...pending].map((reg) => ({ register: reg, reason: reasonFor(reg, workingIndex, candidates, done, targetValues, badchars, bc) }));
  return { steps, ordered, unresolved, stackBytes: steps.length * 4, success: unresolved.length === 0 };
}

function pickArithmeticBuild(
  index: CapabilityIndex,
  pending: Set<string>,
  targetValues: Map<string, number>,
  badchars: number[],
  done: Set<string>,
  keyGreater: (a: number[], b: number[] | undefined) => boolean,
): { register: string; recipe: NonNullable<ReturnType<typeof solveValue>> } | undefined {
  const preserve = [...done];
  let best: { register: string; recipe: NonNullable<ReturnType<typeof solveValue>> } | undefined;
  let bestKey: number[] | undefined;
  for (const reg of pending) {
    const recipe = solveValue(index, reg, targetValues.get(reg)!, badchars, preserve);
    if (!recipe) continue;
    // Dependency-driven ordering. If this register's build borrows another
    // pending TARGET as scratch, it must run before that target is finalized
    // (once finalized, preserve would forbid using it) — so build it first.
    // Then prefer scratch-needing builds over scratch-free ones (which never
    // need a borrow and can safely go last); then the smallest recipe.
    const scratchIsPendingTarget = recipe.scratchRegister && pending.has(recipe.scratchRegister) ? 1 : 0;
    const usesScratch = recipe.scratchRegister ? 1 : 0;
    const key = [scratchIsPendingTarget, usesScratch, -recipe.stackBytes];
    if (keyGreater(key, bestKey)) { bestKey = key; best = { register: reg, recipe }; }
  }
  return best;
}

function reasonFor(
  reg: string,
  index: CapabilityIndex,
  candidates: Candidate[],
  done: Set<string>,
  targetValues: Map<string, number>,
  badcharList: number[],
  badchars: Set<number>,
): string {
  // A register only reaches "unresolved" after both direct packing and
  // arithmetic construction failed. Distinguish the two failure modes.
  const buildableSomehow = solveValue(index, reg, targetValues.get(reg)!, badcharList) !== undefined;
  const buildablePreserving = solveValue(index, reg, targetValues.get(reg)!, badcharList, [...done]) !== undefined;
  if (buildableSomehow && !buildablePreserving) {
    return `can only be built using a register already finalized (${[...done].join(", ")}) as scratch; too many registers were set before it — free a scratch register or build ${reg} earlier`;
  }
  if (!buildableSomehow) {
    return `no pop/arithmetic construction found for ${hex32(targetValues.get(reg)!)} under these badchars and gadgets`;
  }
  const setters = candidates.filter((c) => c.shape.cleanPops.has(reg));
  if (setters.length === 0) return `no safe gadget cleanly pops ${reg}`;
  if (!isBadcharFree(targetValues.get(reg)!, badchars)) {
    return `value ${hex32(targetValues.get(reg)!)} contains badchars; build it with rop.construct("${reg}", ...) and set it separately`;
  }
  const blockers = new Set<string>();
  for (const setter of setters) {
    for (const w of setter.shape.writes) {
      if (w !== reg && done.has(w)) blockers.add(w);
    }
  }
  if (blockers.size > 0) {
    return `every gadget that sets ${reg} also writes already-finalized ${[...blockers].join(", ")}; no ordering avoids the clobber`;
  }
  return `no gadget sets ${reg} without a badchar in its address`;
}
