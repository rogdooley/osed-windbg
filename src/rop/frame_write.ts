import { CapabilityIndex } from "./capabilities";
import { ChainStep, firstKnownAddress, fixRetImmPadding, isAddressStable, retImmBytes, retImmPadding, setStableAddressHint, getStableAddressHint } from "./chain";
import { RopGadget } from "./types";
import { solveValue } from "./value_solver";
import { getArchConfig } from "../core/arch";

export interface FrameWord {
  value?: number;
  placeholder?: string;
  // Dereference: write *[derefSlot] (read at runtime). Use for an ASLR'd imported
  // API — pass its non-ASLR IAT slot and the live pointer is loaded from it.
  derefSlot?: number;
  comment: string;
  // Set when the token was a bare hex address with no 0x prefix and was assumed
  // to be hex. Purely advisory (the caller can warn); the engine ignores it.
  assumedHex?: boolean;
}

export interface WriteFramePlan {
  steps: ChainStep[];
  unsatisfied: string[];
  gadgets: { store?: bigint; advance?: bigint; pivot?: bigint; popPtr?: bigint };
  placeholders: string[];
  stackBytes: number;
  success: boolean;
}

function lastIsRet(g: RopGadget): boolean {
  const last = g.instructions[g.instructions.length - 1];
  return last?.mnemonic === "ret";
}

function op(g: RopGadget, i: number, n: number): string {
  return (g.instructions[i]?.operands[n] ?? "").trim().toLowerCase();
}

function isBadcharFree(value: number, badchars: Set<number>): boolean {
  if (badchars.size === 0) return true;
  const arch = getArchConfig();
  const w = value >>> 0;
  for (let i = 0; i < arch.pointerSize; i++) if (badchars.has((w >>> (i * 8)) & 0xff)) return false;
  return true;
}

// Rank a set of candidate gadgets: stable module first, then fewest
// instructions, then lowest ret imm, then score.
function pickBest(cands: RopGadget[]): RopGadget | undefined {
  return [...cands]
    .filter((g) => firstKnownAddress(g) !== undefined && retImmBytes(g) >= 0)
    .sort((a, b) => {
      const sa = isAddressStable(firstKnownAddress(a)!) ? 0 : 1;
      const sb = isAddressStable(firstKnownAddress(b)!) ? 0 : 1;
      if (sa !== sb) return sa - sb;
      if (a.instructions.length !== b.instructions.length) return a.instructions.length - b.instructions.length;
      if (retImmBytes(a) !== retImmBytes(b)) return retImmBytes(a) - retImmBytes(b);
      return b.score - a.score;
    })[0];
}

function getValueRegs(): string[] {
  const arch = getArchConfig();
  if (arch.id === "x64") {
    return ["rcx", "rdx", "rbx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
  }
  return ["ecx", "edx", "ebx", "esi", "edi", "ebp"];
}

function getPtrReg(): string {
  return getArchConfig().id === "x64" ? "rax" : "eax";
}

interface Store { gadget: RopGadget; reg: string; }

function findStores(index: CapabilityIndex): Store[] {
  const ptrReg = getPtrReg();
  const valueRegs = getValueRegs();
  const ptrPattern = new RegExp(`\\[${ptrReg}\\]$`);
  const byReg = new Map<string, RopGadget[]>();
  for (const g of index.gadgets) {
    if (g.instructions.length !== 2 || g.instructions[0].mnemonic !== "mov" || !lastIsRet(g)) continue;
    if (!ptrPattern.test(op(g, 0, 0))) continue;
    const reg = op(g, 0, 1);
    if (!valueRegs.includes(reg)) continue;
    (byReg.get(reg) ?? byReg.set(reg, []).get(reg)!).push(g);
  }
  const stores: Store[] = [];
  for (const [reg, gadgets] of byReg) {
    const best = pickBest(gadgets);
    if (best) stores.push({ gadget: best, reg });
  }
  return stores;
}

function findAdvance(index: CapabilityIndex): { gadget: RopGadget; junkPops: number } | undefined {
  const ptrReg = getPtrReg();
  const arch = getArchConfig();
  const immHex = `0x${arch.stackEntrySize.toString(16)}`;
  const immDec = arch.stackEntrySize.toString();
  const cands = index.gadgets.filter((g) => {
    if (!lastIsRet(g)) return false;
    if (g.instructions[0].mnemonic !== "add") return false;
    if (op(g, 0, 0) !== ptrReg) return false;
    const imm = op(g, 0, 1);
    return imm === immHex || imm === immDec;
  });
  const gadget = pickBest(cands);
  if (!gadget) return undefined;
  let junkPops = 0;
  for (let i = 1; i < gadget.instructions.length - 1; i++) {
    if (gadget.instructions[i].mnemonic === "pop") junkPops++;
  }
  return { gadget, junkPops };
}

function findPivot(index: CapabilityIndex): RopGadget | undefined {
  const ptrReg = getPtrReg();
  const sp = getArchConfig().stackPointer;
  const xchg = index.gadgets.filter((g) =>
    g.instructions.length === 2 && g.instructions[0].mnemonic === "xchg" && lastIsRet(g) &&
    ((op(g, 0, 0) === ptrReg && op(g, 0, 1) === sp) || (op(g, 0, 0) === sp && op(g, 0, 1) === ptrReg)));
  const movSp = index.gadgets.filter((g) =>
    g.instructions[0]?.mnemonic === "mov" && op(g, 0, 0) === sp && op(g, 0, 1) === ptrReg && lastIsRet(g));
  return pickBest(xchg) ?? pickBest(movSp);
}

function findCleanPop(index: CapabilityIndex, reg: string): RopGadget | undefined {
  return pickBest(index.gadgets.filter((g) =>
    g.instructions.length === 2 &&
    g.instructions[0].mnemonic === "pop" &&
    op(g, 0, 0) === reg &&
    lastIsRet(g)));
}

interface MemLoad { gadget: RopGadget; valReg: string; ptrReg: string; }

function findMemLoads(index: CapabilityIndex, valRegs: string[]): MemLoad[] {
  const framePtrReg = getPtrReg();
  const arch = getArchConfig();
  const gpRegs = arch.generalPurposeRegisters.filter((r) => r !== arch.stackPointer);
  const regPattern = new RegExp(`\\[(${gpRegs.join("|")})\\]$`);
  const out: MemLoad[] = [];
  for (const g of index.gadgets) {
    if (g.instructions.length !== 2 || g.instructions[0].mnemonic !== "mov" || !lastIsRet(g)) continue;
    const dst = op(g, 0, 0);
    if (!valRegs.includes(dst) || dst === framePtrReg) continue;
    const m = regPattern.exec(op(g, 0, 1));
    if (!m || m[1] === framePtrReg) continue;
    out.push({ gadget: g, valReg: dst, ptrReg: m[1] });
  }
  return out.sort((a, b) => (isAddressStable(firstKnownAddress(a.gadget)!) ? 0 : 1) - (isAddressStable(firstKnownAddress(b.gadget)!) ? 0 : 1));
}

function gadgetStep(g: RopGadget, comment: string): ChainStep {
  return { kind: "gadget", address: firstKnownAddress(g)!, comment };
}

/**
 * Plan a write-based stdcall frame. `bufAddress` is the writable staging buffer
 * (a value, or a placeholder to fill at exploit time); `words` are the frame
 * words in order (index 0 = the API address that the pivoted ret dispatches
 * into, index 1 = the post-call target, then the stdcall arguments).
 */
export function planWriteFrame(
  index: CapabilityIndex,
  bufAddress: { value?: number; placeholder?: string },
  words: FrameWord[],
  badchars: number[] = [],
  preferStable?: (address: bigint) => boolean,
): WriteFramePlan {
  const prevHint = getStableAddressHint();
  setStableAddressHint(preferStable ?? prevHint);
  try {
    return planWriteFrameInner(index, bufAddress, words, badchars);
  } finally {
    setStableAddressHint(prevHint);
  }
}

interface ResolvedWord {
  word: FrameWord;
  store: Store;
  reg: string;
  recipe?: NonNullable<ReturnType<typeof solveValue>>; // set when the value is synthesised
  pop?: RopGadget; // set when the value is popped directly
  deref?: { // set when the value is read from *[slot] at runtime
    memLoad: RopGadget;
    ptrReg: string;
    ptrPop?: RopGadget;
    ptrRecipe?: NonNullable<ReturnType<typeof solveValue>>;
    slot: number;
  };
}

function planWriteFrameInner(
  index: CapabilityIndex,
  bufAddress: { value?: number; placeholder?: string },
  words: FrameWord[],
  badchars: number[],
): WriteFramePlan {
  const bc = new Set(badchars.map((b) => b & 0xff));
  const unsatisfied: string[] = [];
  const placeholders = new Set<string>();

  const arch = getArchConfig();
  const ptrReg = getPtrReg();
  const sp = arch.stackPointer;
  const entrySize = arch.stackEntrySize;

  const stores = findStores(index);
  const advance = findAdvance(index);
  const pivot = findPivot(index);
  const popPtr = findCleanPop(index, ptrReg);
  const popByReg = new Map<string, RopGadget | undefined>();
  const popFor = (reg: string): RopGadget | undefined => {
    if (!popByReg.has(reg)) popByReg.set(reg, findCleanPop(index, reg));
    return popByReg.get(reg);
  };

  if (stores.length === 0) unsatisfied.push(`no \`mov [${ptrReg}], <reg> ; ret\` store gadget`);
  if (!popPtr) unsatisfied.push(`no clean \`pop ${ptrReg} ; ret\``);
  if (words.length > 1 && !advance) unsatisfied.push(`no \`add ${ptrReg}, ${entrySize} ; ret\` pointer-advance gadget`);
  if (!pivot) unsatisfied.push(`no \`xchg ${ptrReg}, ${sp}\` / \`mov ${sp}, ${ptrReg}\` pivot gadget`);
  if (unsatisfied.length > 0) {
    return { steps: [], unsatisfied, gadgets: {}, placeholders: [], stackBytes: 0, success: false };
  }

  // Resolve every word first (pick a store whose value register can hold it),
  // so we either emit a complete frame or report exactly what's missing.
  const valRegs = stores.map((s) => s.reg);
  const memLoads = findMemLoads(index, valRegs);
  const resolved: ResolvedWord[] = [];
  for (const word of words) {
    if (word.derefSlot !== undefined) {
      // Read *[slot] into a store's value register at runtime (ASLR-proof API).
      let done = false;
      for (const load of memLoads) {
        const store = stores.find((s) => s.reg === load.valReg);
        if (!store) continue;
        const ptrPop = isBadcharFree(word.derefSlot, bc) ? popFor(load.ptrReg) : undefined;
        const ptrRecipe = ptrPop ? undefined : solveValue(index, load.ptrReg, word.derefSlot, badchars, [ptrReg]) ?? undefined;
        if (!ptrPop && !ptrRecipe) continue;
        resolved.push({ word, store, reg: load.valReg, deref: { memLoad: load.gadget, ptrReg: load.ptrReg, ptrPop, ptrRecipe, slot: word.derefSlot } });
        done = true;
        break;
      }
      if (!done) unsatisfied.push(`no \`mov <valreg>, [ptr] ; ret\` + settable pointer to deref ${hex(word.derefSlot)} for ${word.comment}`);
    } else if (word.placeholder || (word.value !== undefined && isBadcharFree(word.value, bc))) {
      const store = stores.find((s) => popFor(s.reg) !== undefined);
      if (!store) { unsatisfied.push(`no store+pop for ${word.comment}`); continue; }
      resolved.push({ word, store, reg: store.reg, pop: popFor(store.reg) });
    } else {
      let done = false;
      for (const store of stores) {
        const recipe = solveValue(index, store.reg, word.value!, badchars, [ptrReg]);
        if (recipe) { resolved.push({ word, store, reg: store.reg, recipe }); done = true; break; }
      }
      if (!done) unsatisfied.push(`cannot build any of [${stores.map((s) => s.reg).join(", ")}] = ${hex(word.value!)} for ${word.comment} while preserving ${ptrReg}`);
    }
  }
  if (unsatisfied.length > 0) {
    return { steps: [], unsatisfied, gadgets: {}, placeholders: [], stackBytes: 0, success: false };
  }

  const steps: ChainStep[] = [];
  const setPtr = (word: { value?: number; placeholder?: string }, comment: string): void => {
    steps.push(gadgetStep(popPtr!, `pop ${ptrReg}`));
    if (word.placeholder) {
      placeholders.add(word.placeholder);
      steps.push({ kind: "value", placeholder: word.placeholder, comment });
    } else {
      steps.push({ kind: "value", value: word.value! >>> 0, comment });
    }
    steps.push(...retImmPadding(retImmBytes(popPtr!)));
  };

  setPtr(bufAddress, `${ptrReg} = BUF ${bufAddress.placeholder ?? hex(bufAddress.value!)}`);

  resolved.forEach((r, i) => {
    if (i > 0) {
      steps.push(gadgetStep(advance!.gadget, `add ${ptrReg}, ${entrySize} -> BUF+0x${(i * entrySize).toString(16)}`));
      for (let k = 0; k < advance!.junkPops; k++) {
        steps.push({ kind: "value", value: 0x41414141, comment: "junk (advance side-effect pop)" });
      }
      steps.push(...retImmPadding(retImmBytes(advance!.gadget)));
    }

    if (r.deref) {
      // ptr = slot (pop or construct, preserving eax), then valReg = [ptr].
      if (r.deref.ptrPop) {
        steps.push(gadgetStep(r.deref.ptrPop, `pop ${r.deref.ptrReg}`));
        steps.push({ kind: "value", value: r.deref.slot >>> 0, comment: `${r.deref.ptrReg} = ${hex(r.deref.slot)} (IAT slot of ${r.word.comment})` });
        steps.push(...retImmPadding(retImmBytes(r.deref.ptrPop)));
      } else {
        steps.push(...r.deref.ptrRecipe!.steps);
      }
      steps.push(gadgetStep(r.deref.memLoad, `mov ${r.reg}, [${r.deref.ptrReg}]  -> ${r.reg} = *${hex(r.deref.slot)} (${r.word.comment})`));
      steps.push(...retImmPadding(retImmBytes(r.deref.memLoad)));
    } else if (r.recipe) {
      steps.push(...r.recipe.steps);
    } else {
      steps.push(gadgetStep(r.pop!, `pop ${r.reg}`));
      if (r.word.placeholder) {
        placeholders.add(r.word.placeholder);
        steps.push({ kind: "value", placeholder: r.word.placeholder, comment: `${r.reg} = ${r.word.placeholder} (${r.word.comment})` });
      } else {
        steps.push({ kind: "value", value: r.word.value! >>> 0, comment: `${r.reg} = ${hex(r.word.value!)} (${r.word.comment})` });
      }
      steps.push(...retImmPadding(retImmBytes(r.pop!)));
    }

    steps.push(gadgetStep(r.store.gadget, `mov [${ptrReg}], ${r.reg}  -> BUF+0x${(i * entrySize).toString(16)} = ${r.word.comment}`));
    steps.push(...retImmPadding(retImmBytes(r.store.gadget)));
  });

  setPtr(bufAddress, `${ptrReg} = BUF ${bufAddress.placeholder ?? hex(bufAddress.value!)} (for pivot)`);
  steps.push(gadgetStep(pivot!, `xchg ${ptrReg}, ${sp}  -> ${sp.toUpperCase()} = BUF; ret dispatches into BUF[0]`));
  steps.push(...retImmPadding(retImmBytes(pivot!)));

  return {
    steps: fixRetImmPadding(steps),
    unsatisfied,
    gadgets: {
      store: firstKnownAddress(resolved[0].store.gadget),
      advance: advance ? firstKnownAddress(advance.gadget) : undefined,
      pivot: firstKnownAddress(pivot!),
      popPtr: firstKnownAddress(popPtr!),
    },
    placeholders: [...placeholders],
    stackBytes: steps.length * entrySize,
    success: true,
  };
}

function hex(value: number): string {
  const arch = getArchConfig();
  return `0x${(value >>> 0).toString(16).toUpperCase().padStart(arch.pointerSize * 2, "0")}`;
}
