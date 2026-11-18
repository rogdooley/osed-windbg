import { tryReadMemory, getPointerSize } from "./memory";
import { forEachSection, ScanOptions, ModuleSection } from "./scan_engine";

export interface BackwardScanOptions {
  module?: string;
  maxResults?: number;
  maxInstructionsPerGadget?: number;
  maxBackwardBytes?: number;
}

export interface DecodedGadget {
  address: bigint;
  mnemonic: string;
  retImm: number;
  kind: "RET_CHAIN" | "JMP_DISPATCH" | "CALL_DISPATCH";
}

const REG_NAMES = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];

interface DecodedInsn {
  length: number;
  mnemonic: string;
}

const ALU_REG_OPCODES: Array<{ opcode: number; name: string; form: "rm" | "reg" }> = [
  { opcode: 0x01, name: "add", form: "rm" },
  { opcode: 0x03, name: "add", form: "reg" },
  { opcode: 0x09, name: "or",  form: "rm" },
  { opcode: 0x0b, name: "or",  form: "reg" },
  { opcode: 0x11, name: "adc", form: "rm" },
  { opcode: 0x13, name: "adc", form: "reg" },
  { opcode: 0x19, name: "sbb", form: "rm" },
  { opcode: 0x1b, name: "sbb", form: "reg" },
  { opcode: 0x21, name: "and", form: "rm" },
  { opcode: 0x23, name: "and", form: "reg" },
  { opcode: 0x29, name: "sub", form: "rm" },
  { opcode: 0x2b, name: "sub", form: "reg" },
  { opcode: 0x31, name: "xor", form: "rm" },
  { opcode: 0x33, name: "xor", form: "reg" },
  { opcode: 0x39, name: "cmp", form: "rm" },
  { opcode: 0x3b, name: "cmp", form: "reg" },
  { opcode: 0x85, name: "test", form: "rm" },
  { opcode: 0x87, name: "xchg", form: "rm" },
  { opcode: 0x89, name: "mov", form: "rm" },
  { opcode: 0x8b, name: "mov", form: "reg" },
];

const ALU_EAX_IMM32: Array<{ opcode: number; name: string }> = [
  { opcode: 0x05, name: "add" },
  { opcode: 0x0d, name: "or" },
  { opcode: 0x15, name: "adc" },
  { opcode: 0x1d, name: "sbb" },
  { opcode: 0x25, name: "and" },
  { opcode: 0x2d, name: "sub" },
  { opcode: 0x35, name: "xor" },
];

const GRP1_NAMES = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];

const FPU_D9_MNEMONICS: Record<number, string> = {
  0xe0: "fchs", 0xe1: "fabs", 0xe4: "ftst", 0xe5: "fxam",
  0xe8: "fld1", 0xe9: "fldl2t", 0xea: "fldl2e", 0xeb: "fldpi",
  0xec: "fldlg2", 0xed: "fldln2", 0xee: "fldz",
  0xf0: "f2xm1", 0xf1: "fyl2x", 0xf2: "fptan", 0xf3: "fpatan",
  0xf4: "fxtract", 0xf5: "fprem1", 0xf6: "fdecstp", 0xf7: "fincstp",
  0xf8: "fprem", 0xf9: "fyl2xp1", 0xfa: "fsqrt", 0xfb: "fsincos",
  0xfc: "frndint", 0xfd: "fscale", 0xfe: "fsin", 0xff: "fcos",
};

function formatHex(value: number): string {
  return `0x${(value >>> 0).toString(16)}`;
}

interface DecodedModRM {
  reg: number;
  rm?: number;
  memory?: string;
  length: number;
}

function signedByte(value: number): number {
  return value > 0x7f ? value - 0x100 : value;
}

function signedDword(bytes: Uint8Array, offset: number): number | undefined {
  if (offset + 3 >= bytes.length) return undefined;
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) | 0;
}

function formatDisplacement(value: number): string {
  if (value === 0) return "";
  return value < 0 ? `-0x${(-value).toString(16)}` : `+0x${value.toString(16)}`;
}

// Decode the complete x86 ModRM addressing family once.  Consumers choose
// whether a decoded memory operand has semantics they can model; decoding a
// byte sequence must not depend on a particular gadget pattern.
function decodeModRM(bytes: Uint8Array, offset: number): DecodedModRM | undefined {
  if (offset >= bytes.length) return undefined;
  const modrm = bytes[offset];
  const mod = modrm >> 6;
  const reg = (modrm >> 3) & 7;
  const rm = modrm & 7;
  if (mod === 3) return { reg, rm, length: 1 };

  let cursor = offset + 1;
  let base: string | undefined;
  let index: string | undefined;
  let scale = 1;
  let displacement = 0;
  let hasDisplacement = false;

  if (rm === 4) {
    if (cursor >= bytes.length) return undefined;
    const sib = bytes[cursor++];
    scale = 1 << (sib >> 6);
    const indexId = (sib >> 3) & 7;
    const baseId = sib & 7;
    if (indexId !== 4) index = REG_NAMES[indexId];
    if (!(mod === 0 && baseId === 5)) base = REG_NAMES[baseId];
    if (mod === 0 && baseId === 5) {
      const value = signedDword(bytes, cursor);
      if (value === undefined) return undefined;
      displacement = value;
      hasDisplacement = true;
      cursor += 4;
    }
  } else if (mod === 0 && rm === 5) {
    const value = signedDword(bytes, cursor);
    if (value === undefined) return undefined;
    displacement = value;
    hasDisplacement = true;
    cursor += 4;
  } else {
    base = REG_NAMES[rm];
  }

  if (mod === 1) {
    if (cursor >= bytes.length) return undefined;
    displacement = signedByte(bytes[cursor++]);
    hasDisplacement = true;
  } else if (mod === 2) {
    const value = signedDword(bytes, cursor);
    if (value === undefined) return undefined;
    displacement = value;
    hasDisplacement = true;
    cursor += 4;
  }

  const terms: string[] = [];
  if (base) terms.push(base);
  if (index) terms.push(scale === 1 ? index : `${index}*${scale}`);
  let expression = terms.join("+");
  if (hasDisplacement || !expression) {
    if (!expression) expression = formatHex(displacement);
    else expression += formatDisplacement(displacement);
  }
  return { reg, memory: `dword [${expression}]`, length: cursor - offset };
}

export function tryDecodeInsn(bytes: Uint8Array, offset: number): DecodedInsn | undefined {
  if (offset >= bytes.length) return undefined;
  const b0 = bytes[offset];

  if (b0 >= 0x40 && b0 <= 0x47) return { length: 1, mnemonic: `inc ${REG_NAMES[b0 - 0x40]}` };
  if (b0 >= 0x48 && b0 <= 0x4f) return { length: 1, mnemonic: `dec ${REG_NAMES[b0 - 0x48]}` };
  if (b0 >= 0x50 && b0 <= 0x57) return { length: 1, mnemonic: `push ${REG_NAMES[b0 - 0x50]}` };
  if (b0 >= 0x58 && b0 <= 0x5f) return { length: 1, mnemonic: `pop ${REG_NAMES[b0 - 0x58]}` };
  if (b0 === 0x60) return { length: 1, mnemonic: "pushad" };
  if (b0 === 0x61) return { length: 1, mnemonic: "popad" };
  if (b0 === 0x90) return { length: 1, mnemonic: "nop" };
  if (b0 >= 0x91 && b0 <= 0x97) return { length: 1, mnemonic: `xchg eax, ${REG_NAMES[b0 - 0x90]}` };
  if (b0 === 0xc9) return { length: 1, mnemonic: "leave" };
  if (b0 === 0xf8) return { length: 1, mnemonic: "clc" };
  if (b0 === 0xf9) return { length: 1, mnemonic: "stc" };

  if (b0 === 0x68) {
    const immediate = signedDword(bytes, offset + 1);
    if (immediate === undefined) return undefined;
    return { length: 5, mnemonic: `push ${formatHex(immediate)}` };
  }
  if (b0 === 0x6a) {
    if (offset + 1 >= bytes.length) return undefined;
    return { length: 2, mnemonic: `push ${formatHex(signedByte(bytes[offset + 1]))}` };
  }
  if (b0 >= 0xb8 && b0 <= 0xbf) {
    const immediate = signedDword(bytes, offset + 1);
    if (immediate === undefined) return undefined;
    return { length: 5, mnemonic: `mov ${REG_NAMES[b0 - 0xb8]}, ${formatHex(immediate)}` };
  }

  if (offset + 1 >= bytes.length) return undefined;
  const b1 = bytes[offset + 1];

  for (const entry of ALU_REG_OPCODES) {
    if (b0 === entry.opcode) {
      const decoded = decodeModRM(bytes, offset + 1);
      if (!decoded) return undefined;
      if (decoded.rm !== undefined) {
        const dst = entry.form === "rm" ? REG_NAMES[decoded.rm] : REG_NAMES[decoded.reg];
        const src = entry.form === "rm" ? REG_NAMES[decoded.reg] : REG_NAMES[decoded.rm];
        return { length: 1 + decoded.length, mnemonic: `${entry.name} ${dst}, ${src}` };
      }
      // Memory operands are only decoded for the data-movement instructions
      // whose semantics are modeled below. The remaining ALU forms retain the
      // register-only boundary rather than inventing incomplete addressing.
      if (entry.name !== "xchg" && entry.name !== "mov") return undefined;
      if (!decoded.memory) return undefined;
      const dst = entry.form === "rm" ? decoded.memory : REG_NAMES[decoded.reg];
      const src = entry.form === "rm" ? REG_NAMES[decoded.reg] : decoded.memory;
      return { length: 1 + decoded.length, mnemonic: `${entry.name} ${dst}, ${src}` };
    }
  }

  if (b0 === 0x8d) {
    const decoded = decodeModRM(bytes, offset + 1);
    if (!decoded?.memory) return undefined;
    return { length: 1 + decoded.length, mnemonic: `lea ${REG_NAMES[decoded.reg]}, ${decoded.memory}` };
  }

  if (b0 === 0xf7) {
    const decoded = decodeModRM(bytes, offset + 1);
    if (!decoded || decoded.rm === undefined) return undefined;
    const op = (b1 >> 3) & 7;
    if (op === 2) return { length: 2, mnemonic: `not ${REG_NAMES[decoded.rm]}` };
    if (op === 3) return { length: 2, mnemonic: `neg ${REG_NAMES[decoded.rm]}` };
    return undefined;
  }

  if (b0 === 0xff) {
    const decoded = decodeModRM(bytes, offset + 1);
    if (!decoded) return undefined;
    const op = (b1 >> 3) & 7;
    const operand = decoded.rm !== undefined ? REG_NAMES[decoded.rm] : decoded.memory;
    if (!operand) return undefined;
    if (op === 2) return { length: 1 + decoded.length, mnemonic: `call ${operand}` };
    if (op === 4) return { length: 1 + decoded.length, mnemonic: `jmp ${operand}` };
    return undefined;
  }

  if (b0 === 0xd9) {
    const name = FPU_D9_MNEMONICS[b1];
    if (name) return { length: 2, mnemonic: name };
    return undefined;
  }

  if (b0 === 0x83) {
    if (offset + 2 >= bytes.length) return undefined;
    const decoded = decodeModRM(bytes, offset + 1);
    if (!decoded || decoded.rm === undefined) return undefined;
    const op = (b1 >> 3) & 7;
    const imm8 = bytes[offset + 2];
    const signed = imm8 > 0x7f ? imm8 - 0x100 : imm8;
    const name = GRP1_NAMES[op];
    return { length: 3, mnemonic: `${name} ${REG_NAMES[decoded.rm]}, ${formatHex(signed < 0 ? (signed >>> 0) : imm8)}` };
  }

  if (b0 === 0x81) {
    const decoded = decodeModRM(bytes, offset + 1);
    if (!decoded || decoded.rm === undefined) return undefined;
    const immediateOffset = offset + 1 + decoded.length;
    const imm = signedDword(bytes, immediateOffset);
    if (imm === undefined) return undefined;
    const op = (b1 >> 3) & 7;
    return { length: 1 + decoded.length + 4, mnemonic: `${GRP1_NAMES[op]} ${REG_NAMES[decoded.rm]}, ${formatHex(imm)}` };
  }

  for (const entry of ALU_EAX_IMM32) {
    if (b0 === entry.opcode) {
      if (offset + 4 >= bytes.length) return undefined;
      const imm = bytes[offset + 1] | (bytes[offset + 2] << 8) | (bytes[offset + 3] << 16) | ((bytes[offset + 4] << 24) >>> 0);
      return { length: 5, mnemonic: `${entry.name} eax, ${formatHex(imm >>> 0)}` };
    }
  }

  return undefined;
}

function tryDecodeSequence(
  bytes: Uint8Array,
  startOffset: number,
  targetOffset: number,
  maxInsns: number,
): DecodedInsn[] | undefined {
  const insns: DecodedInsn[] = [];
  let pos = startOffset;
  while (pos < targetOffset && insns.length < maxInsns) {
    const decoded = tryDecodeInsn(bytes, pos);
    if (!decoded) return undefined;
    pos += decoded.length;
    insns.push(decoded);
  }
  return pos === targetOffset ? insns : undefined;
}

const PATTERN_SCANNER_PREFIXES = new Set(["pop ", "push ", "pushad", "popad", "nop", "xchg eax, "]);

function isPatternScannerGadget(mnemonic: string): boolean {
  for (const prefix of PATTERN_SCANNER_PREFIXES) {
    if (mnemonic.startsWith(prefix) || mnemonic === prefix.trimEnd()) return true;
  }
  return false;
}

function hasUsefulEffect(insns: DecodedInsn[]): boolean {
  if (insns.every((insn) => insn.mnemonic === "nop")) return false;
  if (insns.length === 1 && isPatternScannerGadget(insns[0].mnemonic)) return false;
  return true;
}

function dispatchKind(mnemonic: string): DecodedGadget["kind"] | undefined {
  if (mnemonic.startsWith("jmp ")) return "JMP_DISPATCH";
  if (mnemonic.startsWith("call ")) return "CALL_DISPATCH";
  return undefined;
}

// A RET chain is sequential only until its terminal RET. A CALL/JMP before it
// transfers control away, so the listed RET is not reached by fall-through.
export function isSequentialRetChain(mnemonics: readonly string[]): boolean {
  return !mnemonics.some((mnemonic) => dispatchKind(mnemonic) !== undefined);
}

export function scanBackward(options: BackwardScanOptions): {
  gadgets: DecodedGadget[];
  warnings: string[];
  stats: Record<string, number>;
} {
  if (getPointerSize() !== 4) {
    return { gadgets: [], warnings: ["Backward scanning is x86-only."], stats: {} };
  }

  const maxResults = options.maxResults ?? 500;
  const maxInsns = options.maxInstructionsPerGadget ?? 3;
  const maxBack = options.maxBackwardBytes ?? 12;

  const scanOpts: ScanOptions = {
    module: options.module,
    executableOnly: true,
    maxResults: 200,
    chunkSize: 0x4000,
  };

  const scope = forEachSection(scanOpts);
  const warnings = scope.warnings.map((w) => w);
  const seen = new Set<string>();
  const gadgets: DecodedGadget[] = [];
  let terminatorsFound = 0;
  let dispatchFound = 0;
  let nonSequentialRejected = 0;

  for (const section of scope.sections) {
    const readAhead = maxBack + 6;
    for (let offset = 0; offset < section.size; offset += 0x4000) {
      const chunkStart = section.start + BigInt(offset);
      const remaining = section.size - offset;
      const size = Math.min(remaining, 0x4000 + readAhead);
      const bytes = tryReadMemory(chunkStart, size);
      if (!bytes) continue;

      const scanLimit = Math.min(bytes.length, remaining < 0x4000 ? remaining : 0x4000);

      for (let i = 0; i < scanLimit; i++) {
        // Decode dispatch instructions from every byte boundary. This retains
        // overlapping streams while keeping CALL/JMP out of RET-chain paths.
        const standalone = tryDecodeInsn(bytes, i);
        const standaloneKind = standalone ? dispatchKind(standalone.mnemonic) : undefined;
        if (standaloneKind) {
          const addr = chunkStart + BigInt(i);
          const key = addr.toString();
          if (!seen.has(key)) {
            seen.add(key);
            gadgets.push({ address: addr, mnemonic: standalone!.mnemonic, retImm: 0, kind: standaloneKind });
            dispatchFound++;
            if (gadgets.length >= maxResults) {
              return {
                gadgets,
                warnings,
                stats: { terminatorsFound, dispatchFound, nonSequentialRejected, gadgetsDiscovered: gadgets.length, candidateLimit: maxResults, stoppedEarly: 1 },
              };
            }
          }
        }

        let retMnemonic: string;
        let retImm = 0;

        if (bytes[i] === 0xc3) {
          retMnemonic = "ret";
        } else if (bytes[i] === 0xc2 && i + 2 < bytes.length) {
          retImm = bytes[i + 1] | (bytes[i + 2] << 8);
          if (retImm === 0 || retImm > 0x1000) continue;
          retMnemonic = `ret ${formatHex(retImm)}`;
        } else {
          continue;
        }

        terminatorsFound++;
        const termStart = i;
        const lookBack = Math.min(termStart, maxBack);

        for (let back = 1; back <= lookBack; back++) {
          const candidateStart = termStart - back;
          const insns = tryDecodeSequence(bytes, candidateStart, termStart, maxInsns);
          if (!insns || insns.length === 0) continue;
          if (!hasUsefulEffect(insns)) continue;
          if (!isSequentialRetChain(insns.map((insn) => insn.mnemonic))) {
            nonSequentialRejected++;
            continue;
          }

          const addr = chunkStart + BigInt(candidateStart);
          const key = addr.toString();
          if (seen.has(key)) continue;
          seen.add(key);

          const parts = insns.map((insn) => insn.mnemonic);
          parts.push(retMnemonic);
          gadgets.push({ address: addr, mnemonic: parts.join(" ; "), retImm, kind: "RET_CHAIN" });

          if (gadgets.length >= maxResults) {
            return {
              gadgets,
              warnings,
              stats: { terminatorsFound, dispatchFound, nonSequentialRejected, gadgetsDiscovered: gadgets.length, candidateLimit: maxResults, stoppedEarly: 1 },
            };
          }
        }
      }
    }
  }

  return {
    gadgets,
    warnings,
    stats: { terminatorsFound, dispatchFound, nonSequentialRejected, gadgetsDiscovered: gadgets.length, candidateLimit: maxResults, stoppedEarly: 0 },
  };
}
