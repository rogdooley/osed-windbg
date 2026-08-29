import { getPointerSize, readPointer, tryReadMemory } from "../core/memory";
import { findModuleByAddress } from "../commands/modules";
import { generateCyclicPattern, generateMsfPattern, decodeOffsetNeedle } from "../logic/pattern_logic";

export type SlotClass =
  | "PATTERN"
  | "RET"
  | "STALE_PTR"
  | "SAVED_EBP"
  | "NULL"
  | "DATA";

export type StackSlot = {
  offset: number;
  address: bigint;
  value: bigint;
  classification: SlotClass;
  detail: string;
  patternKind?: "msf" | "cyclic";
  patternOffset?: number;
  module?: string;
  moduleOffset?: bigint;
  callSiteVerified?: boolean;
};

export type StackMapResult = {
  sp: bigint;
  spName: string;
  ip?: bigint;
  ipName?: string;
  pointerSize: 4 | 8;
  slots: StackSlot[];
  controlledCount: number;
  liveFrameCount: number;
  firstLiveRetOffset?: number;
  ropRoom: number;
  overwrittenFrames: string[];
};

const CALL_NEAR_REL32 = 0xe8;
const CALL_INDIRECT_FF = 0xff;

function isCallInstruction(bytes: Uint8Array): boolean {
  if (bytes.length === 0) return false;
  if (bytes[0] === CALL_NEAR_REL32 && bytes.length >= 5) return true;
  if (bytes[0] === CALL_INDIRECT_FF && bytes.length >= 2) {
    const modrm = bytes[1];
    const reg = (modrm >> 3) & 7;
    return reg === 2 || reg === 3;
  }
  return false;
}

function verifyCallSite(returnAddress: bigint, pointerSize: 4 | 8): boolean {
  const candidates = pointerSize === 8
    ? [7, 6, 5, 3, 2]
    : [5, 6, 3, 2];

  for (const len of candidates) {
    const callAddr = returnAddress - BigInt(len);
    const bytes = tryReadMemory(callAddr, len);
    if (bytes && isCallInstruction(bytes)) return true;
  }
  return false;
}

function matchPattern(
  value: bigint,
  haystacks: { msf: string; cyclic: string },
): { kind: "msf" | "cyclic"; offset: number } | undefined {
  const low = Number(value & BigInt(0xffffffff));
  const needle = decodeOffsetNeedle(low);

  const msfIdx = haystacks.msf.indexOf(needle);
  if (msfIdx >= 0) return { kind: "msf", offset: msfIdx };

  const cyclicIdx = haystacks.cyclic.indexOf(needle);
  if (cyclicIdx >= 0) return { kind: "cyclic", offset: cyclicIdx };

  return undefined;
}

export function classifySlot(
  offset: number,
  address: bigint,
  value: bigint,
  pointerSize: 4 | 8,
  sp: bigint,
  stackEnd: bigint,
  haystacks: { msf: string; cyclic: string },
): StackSlot {
  const slot: StackSlot = {
    offset,
    address,
    value,
    classification: "DATA",
    detail: "local / arg",
  };

  if (value === BigInt(0)) {
    slot.classification = "NULL";
    slot.detail = "frame boundary";
    return slot;
  }

  const pattern = matchPattern(value, haystacks);
  if (pattern) {
    slot.classification = "PATTERN";
    slot.patternKind = pattern.kind;
    slot.patternOffset = pattern.offset;
    slot.detail = `${pattern.kind} offset ${pattern.offset}`;
    return slot;
  }

  if (value >= sp && value < stackEnd) {
    slot.classification = "SAVED_EBP";
    slot.detail = "points into stack";
    return slot;
  }

  const mod = findModuleByAddress(value);
  if (mod) {
    slot.module = mod.name;
    slot.moduleOffset = value - mod.base;
    const isCall = verifyCallSite(value, pointerSize);
    if (isCall) {
      slot.classification = "RET";
      slot.callSiteVerified = true;
      slot.detail = `${mod.name}+0x${slot.moduleOffset.toString(16).toUpperCase()} ← CALL verified`;
    } else {
      slot.classification = "STALE_PTR";
      slot.callSiteVerified = false;
      slot.detail = `${mod.name}+0x${slot.moduleOffset.toString(16).toUpperCase()} (no CALL site)`;
    }
    return slot;
  }

  return slot;
}

export function mapStack(
  sp: bigint,
  spName: string,
  ip: bigint | undefined,
  ipName: string | undefined,
  depth: number,
  patternLength: number,
): StackMapResult {
  const pointerSize = getPointerSize();
  const slotSize = pointerSize;
  const byteCount = depth * slotSize;

  const haystacks = {
    msf: generateMsfPattern(Math.min(patternLength, 20280)),
    cyclic: generateCyclicPattern(Math.max(patternLength, 20000)),
  };

  const stackEnd = sp + BigInt(byteCount) + BigInt(0x1000);
  const slots: StackSlot[] = [];

  for (let i = 0; i < depth; i++) {
    const slotAddr = sp + BigInt(i * slotSize);
    let value: bigint;
    try {
      value = readPointer(slotAddr, pointerSize);
    } catch {
      break;
    }
    slots.push(classifySlot(i * slotSize, slotAddr, value, pointerSize, sp, stackEnd, haystacks));
  }

  const controlledCount = slots.filter(
    (s) => s.classification === "PATTERN",
  ).length;
  const liveFrames = slots.filter(
    (s) => s.classification === "RET" && s.callSiteVerified,
  );
  const liveFrameCount = liveFrames.length;

  const firstLiveRet = slots.find(
    (s) => s.classification === "RET" && s.callSiteVerified,
  );
  const firstLiveRetOffset = firstLiveRet?.offset;

  const ropRoom = firstLiveRetOffset ?? byteCount;

  const overwrittenFrames: string[] = [];
  let seenPattern = false;
  for (const slot of slots) {
    if (slot.classification === "PATTERN") {
      seenPattern = true;
      continue;
    }
    if (seenPattern && slot.classification === "RET" && slot.callSiteVerified) {
      break;
    }
    if (seenPattern && slot.classification === "STALE_PTR" && slot.module) {
      if (!overwrittenFrames.includes(slot.module)) {
        overwrittenFrames.push(slot.module);
      }
    }
  }

  return {
    sp,
    spName,
    ip,
    ipName,
    pointerSize,
    slots,
    controlledCount,
    liveFrameCount,
    firstLiveRetOffset,
    ropRoom,
    overwrittenFrames,
  };
}
