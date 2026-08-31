import { CapabilityIndex } from "./capabilities";
import { ChainStep, firstKnownAddress, isAddressStable, retImmBytes, retImmPadding, setStableAddressHint, getStableAddressHint } from "./chain";
import { RopGadget } from "./types";
import { solveValue } from "./value_solver";

// Write-based stdcall frame construction — the no-PUSHAD path. Assembles the
// call frame word-by-word in a writable buffer (BUF) using a canonical
// `mov [eax], ecx ; ret` store (EAX = destination pointer, ECX = value), then
// pivots ESP onto BUF so the trailing `ret` dispatches into the API and BUF+4..
// become its stdcall arguments. Null/badchar-heavy words are synthesised in ECX
// via the value solver rather than placed in the payload.

export interface FrameWord {
  value?: number;
  placeholder?: string;
  comment: string;
}

export interface WriteFramePlan {
  steps: ChainStep[];
  unsatisfied: string[];
  gadgets: { store?: bigint; advance?: bigint; pivot?: bigint; popEax?: bigint; popEcx?: bigint };
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
  const w = value >>> 0;
  for (let i = 0; i < 4; i++) if (badchars.has((w >>> (i * 8)) & 0xff)) return false;
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

// mov [eax], ecx ; ret  (canonical store: EAX = pointer, ECX = value)
function findStore(index: CapabilityIndex): RopGadget | undefined {
  return pickBest(index.gadgets.filter((g) =>
    g.instructions.length === 2 &&
    g.instructions[0].mnemonic === "mov" &&
    /\[eax\]$/.test(op(g, 0, 0)) &&
    op(g, 0, 1) === "ecx" &&
    lastIsRet(g)));
}

// add eax, 4 ; ret  (advance the write pointer one dword). Extra pops after the
// add each consume a junk dword — captured so the caller can pad them.
function findAdvance(index: CapabilityIndex): { gadget: RopGadget; junkPops: number } | undefined {
  const cands = index.gadgets.filter((g) => {
    if (!lastIsRet(g)) return false;
    if (g.instructions[0].mnemonic !== "add") return false;
    if (op(g, 0, 0) !== "eax") return false;
    const imm = op(g, 0, 1);
    return imm === "0x4" || imm === "4";
  });
  const gadget = pickBest(cands);
  if (!gadget) return undefined;
  let junkPops = 0;
  for (let i = 1; i < gadget.instructions.length - 1; i++) {
    if (gadget.instructions[i].mnemonic === "pop") junkPops++;
  }
  return { gadget, junkPops };
}

// xchg eax, esp ; ret  (or mov esp, eax ; ret) — land ESP on the assembled frame.
function findPivot(index: CapabilityIndex): RopGadget | undefined {
  const xchg = index.gadgets.filter((g) =>
    g.instructions.length === 2 && g.instructions[0].mnemonic === "xchg" && lastIsRet(g) &&
    ((op(g, 0, 0) === "eax" && op(g, 0, 1) === "esp") || (op(g, 0, 0) === "esp" && op(g, 0, 1) === "eax")));
  const movEsp = index.gadgets.filter((g) =>
    g.instructions[0]?.mnemonic === "mov" && op(g, 0, 0) === "esp" && op(g, 0, 1) === "eax" && lastIsRet(g));
  return pickBest(xchg) ?? pickBest(movEsp);
}

function findCleanPop(index: CapabilityIndex, reg: string): RopGadget | undefined {
  return pickBest(index.gadgets.filter((g) =>
    g.instructions.length === 2 &&
    g.instructions[0].mnemonic === "pop" &&
    op(g, 0, 0) === reg &&
    lastIsRet(g)));
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

function planWriteFrameInner(
  index: CapabilityIndex,
  bufAddress: { value?: number; placeholder?: string },
  words: FrameWord[],
  badchars: number[],
): WriteFramePlan {
  const bc = new Set(badchars.map((b) => b & 0xff));
  const steps: ChainStep[] = [];
  const unsatisfied: string[] = [];
  const placeholders = new Set<string>();

  const store = findStore(index);
  const advance = findAdvance(index);
  const pivot = findPivot(index);
  const popEax = findCleanPop(index, "eax");
  const popEcx = findCleanPop(index, "ecx");

  if (!store) unsatisfied.push("no `mov [eax], ecx ; ret` store gadget");
  if (!popEax) unsatisfied.push("no clean `pop eax ; ret`");
  if (!popEcx) unsatisfied.push("no clean `pop ecx ; ret`");
  if (words.length > 1 && !advance) unsatisfied.push("no `add eax, 4 ; ret` pointer-advance gadget");
  if (!pivot) unsatisfied.push("no `xchg eax, esp` / `mov esp, eax` pivot gadget");
  if (unsatisfied.length > 0) {
    return { steps, unsatisfied, gadgets: {}, placeholders: [], stackBytes: 0, success: false };
  }

  const setEax = (word: { value?: number; placeholder?: string }, comment: string): void => {
    steps.push(gadgetStep(popEax!, "pop eax"));
    if (word.placeholder) {
      placeholders.add(word.placeholder);
      steps.push({ kind: "value", placeholder: word.placeholder, comment });
    } else {
      steps.push({ kind: "value", value: word.value! >>> 0, comment });
    }
    steps.push(...retImmPadding(retImmBytes(popEax!)));
  };

  // EAX = BUF (the frame's base / first slot).
  setEax(bufAddress, `eax = BUF ${bufAddress.placeholder ?? hex(bufAddress.value!)}`);

  words.forEach((word, i) => {
    if (i > 0) {
      // Advance the write pointer by one dword; pad any side-effect pops.
      steps.push(gadgetStep(advance!.gadget, `add eax, 4 -> BUF+0x${(i * 4).toString(16)}`));
      for (let k = 0; k < advance!.junkPops; k++) {
        steps.push({ kind: "value", value: 0x41414141, comment: "junk (advance side-effect pop)" });
      }
      steps.push(...retImmPadding(retImmBytes(advance!.gadget)));
    }

    // ECX = this frame word. Placeholder or badchar-free -> pop; else synthesise
    // in ECX while preserving EAX (the write pointer).
    if (word.placeholder) {
      steps.push(gadgetStep(popEcx!, "pop ecx"));
      placeholders.add(word.placeholder);
      steps.push({ kind: "value", placeholder: word.placeholder, comment: `ecx = ${word.placeholder} (${word.comment})` });
      steps.push(...retImmPadding(retImmBytes(popEcx!)));
    } else if (isBadcharFree(word.value!, bc)) {
      steps.push(gadgetStep(popEcx!, "pop ecx"));
      steps.push({ kind: "value", value: word.value! >>> 0, comment: `ecx = ${hex(word.value!)} (${word.comment})` });
      steps.push(...retImmPadding(retImmBytes(popEcx!)));
    } else {
      const recipe = solveValue(index, "ecx", word.value!, badchars, ["eax"]);
      if (!recipe) {
        unsatisfied.push(`cannot build ecx = ${hex(word.value!)} for ${word.comment} while preserving eax`);
        return;
      }
      steps.push(...recipe.steps);
    }

    // [eax] = ecx
    steps.push(gadgetStep(store!, `mov [eax], ecx  -> BUF+0x${(i * 4).toString(16)} = ${word.comment}`));
    steps.push(...retImmPadding(retImmBytes(store!)));
  });

  // Re-point EAX at BUF and pivot ESP onto the assembled frame.
  setEax(bufAddress, `eax = BUF ${bufAddress.placeholder ?? hex(bufAddress.value!)} (for pivot)`);
  steps.push(gadgetStep(pivot!, "xchg eax, esp  -> ESP = BUF; ret dispatches into BUF[0]"));
  steps.push(...retImmPadding(retImmBytes(pivot!)));

  return {
    steps,
    unsatisfied,
    gadgets: {
      store: firstKnownAddress(store!),
      advance: advance ? firstKnownAddress(advance.gadget) : undefined,
      pivot: firstKnownAddress(pivot!),
      popEax: firstKnownAddress(popEax!),
      popEcx: firstKnownAddress(popEcx!),
    },
    placeholders: [...placeholders],
    stackBytes: steps.length * 4,
    success: unsatisfied.length === 0,
  };
}

function hex(value: number): string {
  return `0x${(value >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
}
