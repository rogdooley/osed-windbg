// Composable pointer/gadget search filters. Pure logic: it encodes instruction
// searches into byte patterns and filters candidate addresses through a stack of
// predicates. The primary filter is badchars-in-address — the single most common
// manual step when picking a ROP/SEH pointer, since the address itself is written
// into the payload and must survive the target's bad-character set.

export type PointerSize = 4 | 8;
export type JumpKind = "jmp" | "call" | "pushret";

// Low 3 register-encoding bits, shared by the x86 and x64 base register names.
const REGISTER_CODE: Record<string, number> = {
  eax: 0, ecx: 1, edx: 2, ebx: 3, esp: 4, ebp: 5, esi: 6, edi: 7,
  rax: 0, rcx: 1, rdx: 2, rbx: 3, rsp: 4, rbp: 5, rsi: 6, rdi: 7,
};

// Encode a control-transfer-to-register gadget. Covers the eight base registers
// for both x86 and x64 (rsp/esp included); r8-r15 need a REX.B prefix and are not
// supported here.
export function encodeJumpToRegister(kind: JumpKind, register: string): number[] | undefined {
  const code = REGISTER_CODE[register.trim().toLowerCase()];
  if (code === undefined) {
    return undefined;
  }
  switch (kind) {
    case "jmp":
      return [0xff, 0xe0 + code];
    case "call":
      return [0xff, 0xd0 + code];
    case "pushret":
      return [0x50 + code, 0xc3];
    default:
      return undefined;
  }
}

// Parse "jmp esp" / "call eax" / "pushret esp" (or "push+ret esp") into bytes.
export function encodeInstructionSearch(text: string): number[] | undefined {
  const parts = text.trim().toLowerCase().split(/\s+/);
  if (parts.length !== 2) {
    return undefined;
  }
  const [mnemonic, register] = parts;
  if (mnemonic === "jmp" || mnemonic === "call") {
    return encodeJumpToRegister(mnemonic, register);
  }
  if (mnemonic === "pushret" || mnemonic === "push+ret") {
    return encodeJumpToRegister("pushret", register);
  }
  return undefined;
}

// Little-endian address bytes — the form written into a payload.
export function addressToBytes(address: bigint, pointerSize: PointerSize): number[] {
  const bytes: number[] = [];
  let value = address;
  for (let index = 0; index < pointerSize; index += 1) {
    bytes.push(Number(value & BigInt(0xff)));
    value >>= BigInt(8);
  }
  return bytes;
}

export function addressHasBadchar(address: bigint, pointerSize: PointerSize, badchars: number[]): boolean {
  if (badchars.length === 0) {
    return false;
  }
  const bad = new Set(badchars.map((value) => value & 0xff));
  return addressToBytes(address, pointerSize).some((byte) => bad.has(byte));
}

export interface PointerCandidate {
  address: bigint;
}

export interface PointerFilter {
  name: string;
  predicate: (candidate: PointerCandidate) => boolean;
}

export function badcharAddressFilter(badchars: number[], pointerSize: PointerSize): PointerFilter {
  return {
    name: "badchar-free-address",
    predicate: (candidate) => !addressHasBadchar(candidate.address, pointerSize, badchars),
  };
}

export interface FilterOutcome {
  kept: bigint[];
  rejected: Array<{ address: bigint; failed: string }>;
}

// Run every address through the filter stack; the first failing predicate names
// why a candidate was rejected.
export function applyFilters(addresses: bigint[], filters: PointerFilter[]): FilterOutcome {
  const kept: bigint[] = [];
  const rejected: Array<{ address: bigint; failed: string }> = [];
  for (const address of addresses) {
    const failing = filters.find((filter) => !filter.predicate({ address }));
    if (failing) {
      rejected.push({ address, failed: failing.name });
    } else {
      kept.push(address);
    }
  }
  return { kept, rejected };
}
