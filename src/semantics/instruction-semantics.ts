import { canonicalizeInstruction } from "./canonicalize";
import {
  Confidence,
  FlowEffectKind,
  Instruction,
  InstructionSemantic,
  Register,
  RegisterEffectMap,
  RegisterExpr,
  RegisterOffset,
  SEMANTIC_SCHEMA_VERSION,
  SemanticField,
  SemanticSet,
} from "./types";
import { ArchConfig, getArchConfig } from "../core/arch";

type OperandKind = "register" | "immediate" | "memory" | "unknown";

interface ParsedOperand {
  kind: OperandKind;
  text: string;
  register?: Register;
}

interface RuleResult {
  reads?: Register[];
  writes?: Register[];
  stackDelta?: { exact?: number[]; conservative?: number[]; unknown?: boolean };
  flags?: { exact?: string[]; conservative?: string[]; unknown?: boolean };
  memoryReads?: string[];
  memoryWrites?: string[];
  flowEffects?: FlowEffectKind[];
  registerEffects?: RegisterEffectMap;
  evidence?: string[];
}

interface Rule {
  name: string;
  match(instruction: Instruction): boolean;
  evaluate(instruction: Instruction, arch: ArchConfig): RuleResult;
}

const X86_REGISTERS: Register[] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
const X64_REGISTERS: Register[] = [
  "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];
const ALL_REGISTERS: Register[] = [...X86_REGISTERS, ...X64_REGISTERS];

function registersForArch(arch: ArchConfig): Register[] {
  return arch.id === "x64" ? X64_REGISTERS : X86_REGISTERS;
}

function spForArch(arch: ArchConfig): Register {
  return arch.stackPointer as Register;
}

function bpForArch(arch: ArchConfig): Register {
  return arch.basePointer as Register;
}

let REGISTERS: Register[] = X86_REGISTERS;

function makeSet<T>(exact: T[] = [], conservative: T[] = [], unknown = false): SemanticSet<T> {
  return {
    exact: new Set(exact),
    conservative: new Set(conservative),
    unknown,
  };
}

function confidenceForSet<T>(set: SemanticSet<T>): Confidence {
  if (set.unknown) {
    return "UNKNOWN";
  }
  if (set.conservative.size > 0) {
    return "CONSERVATIVE";
  }
  return "EXACT";
}

function makeField<T>(exact: T[] = [], conservative: T[] = [], unknown = false, evidence: string[] = []): SemanticField<T> {
  const values = makeSet(exact, conservative, unknown);
  return {
    values,
    confidence: confidenceForSet(values),
    evidence,
  };
}

function mergeField<T>(left: SemanticField<T>, right: SemanticField<T>): SemanticField<T> {
  const exact = new Set([...left.values.exact, ...right.values.exact]);
  const conservative = new Set([...left.values.conservative, ...right.values.conservative]);
  return {
    values: {
      exact,
      conservative,
      unknown: left.values.unknown || right.values.unknown,
    },
    confidence: confidenceForSet({
      exact,
      conservative,
      unknown: left.values.unknown || right.values.unknown,
    }),
    evidence: [...left.evidence, ...right.evidence],
  };
}

function emptyField<T>(): SemanticField<T> {
  return makeField<T>();
}

function parseOperand(text: string): ParsedOperand {
  const normalized = text.trim().toLowerCase();
  if (!normalized) {
    return { kind: "unknown", text: normalized };
  }

  if (ALL_REGISTERS.includes(normalized as Register)) {
    return { kind: "register", text: normalized, register: normalized as Register };
  }

  if (/^-?(?:0x[0-9a-f]+|\d+)$/.test(normalized)) {
    return { kind: "immediate", text: normalized };
  }

  if (normalized.includes("[") || normalized.includes("]")) {
    return { kind: "memory", text: normalized };
  }

  return { kind: "unknown", text: normalized };
}

function memoryBaseRegister(text: string): Register | undefined {
  const match = text.toLowerCase().match(/\[([a-z][a-z0-9]{1,2})\]/);
  if (!match) {
    return undefined;
  }
  const register = match[1] as Register;
  return ALL_REGISTERS.includes(register) ? register : undefined;
}

function isRegisterOperand(operand: ParsedOperand): operand is ParsedOperand & { register: Register } {
  return operand.kind === "register" && operand.register !== undefined;
}

function sameRegisterOperands(instruction: Instruction): Register | undefined {
  if (instruction.operands.length !== 2) {
    return undefined;
  }
  const left = parseOperand(instruction.operands[0]);
  const right = parseOperand(instruction.operands[1]);
  if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
    return undefined;
  }
  if (left.register !== right.register) {
    return undefined;
  }
  return left.register;
}

function immediateOperand(instruction: Instruction): number | undefined {
  if (instruction.operands.length === 0) {
    return undefined;
  }
  const operand = parseOperand(instruction.operands[instruction.operands.length - 1]);
  if (operand.kind !== "immediate") {
    return undefined;
  }
  const raw = operand.text;
  if (raw.startsWith("0x")) {
    return Number.parseInt(raw.slice(2), 16) >>> 0;
  }
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed >>> 0 : undefined;
}

function parseImmediateValue(text: string): number | undefined {
  const raw = text.trim().toLowerCase();
  if (/^-?0x[0-9a-f]+$/.test(raw)) {
    const negative = raw.startsWith("-");
    const hex = negative ? raw.slice(3) : raw.slice(2);
    const parsed = Number.parseInt(hex, 16);
    if (!Number.isFinite(parsed)) {
      return undefined;
    }
    const value = negative ? -parsed : parsed;
    return value | 0;
  }
  if (/^-?\d+$/.test(raw)) {
    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) ? parsed | 0 : undefined;
  }
  return undefined;
}

function constantOffset(value: number): RegisterOffset {
  return { kind: "constant", value };
}

function selfPlus(value: number): RegisterExpr {
  return { kind: "affine", base: "self", offset: constantOffset(value) };
}

function registerExpr(register: Register, offset = 0): RegisterExpr {
  return { kind: "affine", base: register, offset: constantOffset(offset) };
}

function constantExpr(value: number): RegisterExpr {
  return { kind: "constant", value };
}

function unknownExpr(): RegisterExpr {
  return { kind: "unknown" };
}

function memoryExpr(address: RegisterExpr): RegisterExpr {
  return { kind: "memory", address, confidence: "EXACT" };
}

function memoryAddressExpression(text: string): RegisterExpr | undefined {
  const match = text.toLowerCase().match(/\[\s*([a-z][a-z0-9]{1,2})(?:\s*([+-])\s*(0x[0-9a-f]+|\d+))?\s*\]/);
  if (!match) {
    return undefined;
  }
  const register = match[1] as Register;
  if (!ALL_REGISTERS.includes(register)) {
    return undefined;
  }
  const rawOffset = match[3] === undefined ? 0 : parseImmediateValue(match[3]);
  if (rawOffset === undefined) {
    return undefined;
  }
  const offset = match[2] === "-" ? -rawOffset : rawOffset;
  return registerExpr(register, offset);
}

function isStackPointerReg(register: Register): boolean {
  return register === "esp" || register === "rsp";
}

function isBasePointerReg(register: Register): boolean {
  return register === "ebp" || register === "rbp";
}

function stackDeltaForRegisterImmediate(register: Register, delta: number | undefined): RuleResult["stackDelta"] {
  return isStackPointerReg(register) && delta !== undefined ? { exact: [delta] } : undefined;
}

function stackReadEvidence(text: string): string {
  return `${text} reads stack`;
}

function fieldFromRegisters(values: Register[], evidence: string, conservative = false): SemanticField<Register> {
  return makeField(values, conservative ? values : [], false, [evidence]);
}

function unsupported(instruction: Instruction): InstructionSemantic {
  const text = canonicalizeInstruction(instruction);
  const unknownField = <T>() => makeField<T>([], [], true, [text]);
  return {
    schemaVersion: SEMANTIC_SCHEMA_VERSION,
    instructionIndex: -1,
    instruction,
    reads: unknownField<Register>(),
    writes: unknownField<Register>(),
    stackDelta: unknownField<number>(),
    flags: unknownField<string>(),
    memoryReads: unknownField<string>(),
    memoryWrites: unknownField<string>(),
    flowEffects: unknownField<FlowEffectKind>(),
    registerEffects: {},
    registerEffectsUnknown: true,
    evidence: [`unsupported instruction: ${text}`],
    supported: false,
  };
}

const RULES: Rule[] = [
  {
    name: "pop-reg",
    match: (instruction) => instruction.mnemonic === "pop" && instruction.operands.length === 1,
    evaluate: (instruction, arch) => {
      const operand = parseOperand(instruction.operands[0]);
      if (!isRegisterOperand(operand)) {
        return {};
      }
      const sp = spForArch(arch);
      const entrySize = arch.stackEntrySize;
      const popsSp = isStackPointerReg(operand.register);
      return {
        reads: [sp],
        writes: [operand.register],
        stackDelta: popsSp ? { unknown: true } : { exact: [entrySize] },
        memoryReads: [`[${sp}]`],
        flowEffects: [],
        registerEffects: popsSp
          ? { [sp]: unknownExpr() }
          : {
              [operand.register]: memoryExpr(registerExpr(sp)),
              [sp]: selfPlus(entrySize),
            },
        evidence: [`POP ${operand.register} reads stack and writes ${operand.register}`],
      };
    },
  },
  {
    name: "push-reg",
    match: (instruction) => instruction.mnemonic === "push" && instruction.operands.length === 1,
    evaluate: (instruction, arch) => {
      const operand = parseOperand(instruction.operands[0]);
      if (!isRegisterOperand(operand)) {
        return {};
      }
      const sp = spForArch(arch);
      const entrySize = arch.stackEntrySize;
      return {
        reads: [operand.register, sp],
        writes: [sp],
        stackDelta: { exact: [-entrySize] },
        memoryWrites: [`[${sp}]`],
        registerEffects: { [sp]: selfPlus(-entrySize) },
        evidence: [`PUSH ${operand.register} decrements stack pointer`],
      };
    },
  },
  {
    name: "ret",
    match: (instruction) => instruction.mnemonic === "ret",
    evaluate: (instruction, arch) => {
      const sp = spForArch(arch);
      const entrySize = arch.stackEntrySize;
      const imm = immediateOperand(instruction);
      const delta = imm === undefined ? entrySize : entrySize + imm;
      const evidence = imm === undefined
        ? ["RET pops return address"]
        : [`RET ${imm} adjusts stack by ${delta}`];
      return {
        reads: [sp],
        writes: [sp],
        stackDelta: { exact: [delta] },
        flowEffects: ["RETURN"],
        registerEffects: { [sp]: selfPlus(delta) },
        evidence,
      };
    },
  },
  {
    name: "mov-reg-reg",
    match: (instruction) => instruction.mnemonic === "mov" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
        return {};
      }
      return {
        reads: [right.register],
        writes: [left.register],
        registerEffects: { [left.register]: registerExpr(right.register) },
        evidence: [`MOV ${left.register}, ${right.register}`],
      };
    },
  },
  {
    name: "mov-reg-mem",
    match: (instruction) => instruction.mnemonic === "mov" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || right.kind !== "memory") {
        return {};
      }
      const baseRegister = memoryBaseRegister(right.text);
      const address = memoryAddressExpression(right.text);
      return {
        reads: baseRegister ? [baseRegister] : [],
        writes: [left.register],
        memoryReads: [right.text],
        registerEffects: { [left.register]: address ? memoryExpr(address) : unknownExpr() },
        evidence: [`MOV ${left.register}, ${right.text}`],
      };
    },
  },
  {
    name: "mov-mem-reg",
    match: (instruction) => instruction.mnemonic === "mov" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (left.kind !== "memory" || !isRegisterOperand(right)) {
        return {};
      }
      const base = memoryBaseRegister(left.text);
      return {
        reads: [right.register, ...(base ? [base] : [])],
        writes: base && isStackPointerReg(base) ? [base] : [],
        memoryWrites: [left.text],
        evidence: [`MOV ${left.text}, ${right.register}`],
      };
    },
  },
  {
    name: "xor-reg-reg",
    match: (instruction) => instruction.mnemonic === "xor" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const reg = sameRegisterOperands(instruction);
      if (!reg) {
        return {};
      }
      return {
        reads: [reg],
        writes: [reg],
        registerEffects: { [reg]: constantExpr(0) },
        evidence: [`XOR ${reg}, ${reg} zeros register`],
      };
    },
  },
  {
    name: "add-reg-reg",
    match: (instruction) => instruction.mnemonic === "add" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
        return {};
      }
      return {
        reads: [left.register, right.register],
        writes: [left.register],
        registerEffects: { [left.register]: { kind: "affine", base: "self", offset: { kind: "register", register: right.register } } },
        evidence: [`ADD ${left.register}, ${right.register}`],
      };
    },
  },
  {
    name: "add-reg-imm",
    match: (instruction) => instruction.mnemonic === "add" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || right.kind !== "immediate") {
        return {};
      }
      const imm = parseImmediateValue(right.text);
      return {
        reads: [left.register],
        writes: [left.register],
        stackDelta: stackDeltaForRegisterImmediate(left.register, imm),
        registerEffects: { [left.register]: imm === undefined ? unknownExpr() : selfPlus(imm) },
        evidence: [`ADD ${left.register}, ${right.text}`],
      };
    },
  },
  {
    name: "sub-reg-reg",
    match: (instruction) => instruction.mnemonic === "sub" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
        return {};
      }
      return {
        reads: [left.register, right.register],
        writes: [left.register],
        registerEffects: { [left.register]: unknownExpr() },
        evidence: [`SUB ${left.register}, ${right.register}`],
      };
    },
  },
  {
    name: "sub-reg-imm",
    match: (instruction) => instruction.mnemonic === "sub" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || right.kind !== "immediate") {
        return {};
      }
      const imm = parseImmediateValue(right.text);
      return {
        reads: [left.register],
        writes: [left.register],
        stackDelta: stackDeltaForRegisterImmediate(left.register, imm === undefined ? undefined : -imm),
        registerEffects: { [left.register]: imm === undefined ? unknownExpr() : selfPlus(-imm) },
        evidence: [`SUB ${left.register}, ${right.text}`],
      };
    },
  },
  {
    name: "neg-reg",
    match: (instruction) => instruction.mnemonic === "neg" && instruction.operands.length === 1,
    evaluate: (instruction, _arch) => {
      const operand = parseOperand(instruction.operands[0]);
      if (!isRegisterOperand(operand)) {
        return {};
      }
      return {
        reads: [operand.register],
        writes: [operand.register],
        registerEffects: { [operand.register]: unknownExpr() },
        evidence: [`NEG ${operand.register}`],
      };
    },
  },
  {
    name: "not-reg",
    match: (instruction) => instruction.mnemonic === "not" && instruction.operands.length === 1,
    evaluate: (instruction, _arch) => {
      const operand = parseOperand(instruction.operands[0]);
      if (!isRegisterOperand(operand)) {
        return {};
      }
      return {
        reads: [operand.register],
        writes: [operand.register],
        registerEffects: { [operand.register]: unknownExpr() },
        evidence: [`NOT ${operand.register}`],
      };
    },
  },
  {
    name: "or-reg-reg",
    match: (instruction) => instruction.mnemonic === "or" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
        return {};
      }
      return {
        reads: [left.register, right.register],
        writes: [left.register],
        registerEffects: { [left.register]: unknownExpr() },
        evidence: [`OR ${left.register}, ${right.register}`],
      };
    },
  },
  {
    name: "or-reg-imm",
    match: (instruction) => instruction.mnemonic === "or" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || right.kind !== "immediate") {
        return {};
      }
      return {
        reads: [left.register],
        writes: [left.register],
        registerEffects: { [left.register]: unknownExpr() },
        evidence: [`OR ${left.register}, ${right.text}`],
      };
    },
  },
  {
    name: "and-reg-reg",
    match: (instruction) => instruction.mnemonic === "and" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
        return {};
      }
      return {
        reads: [left.register, right.register],
        writes: [left.register],
        registerEffects: { [left.register]: unknownExpr() },
        evidence: [`AND ${left.register}, ${right.register}`],
      };
    },
  },
  {
    name: "and-reg-imm",
    match: (instruction) => instruction.mnemonic === "and" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || right.kind !== "immediate") {
        return {};
      }
      return {
        reads: [left.register],
        writes: [left.register],
        registerEffects: { [left.register]: unknownExpr() },
        evidence: [`AND ${left.register}, ${right.text}`],
      };
    },
  },
  {
    name: "adc-reg-reg",
    match: (instruction) => instruction.mnemonic === "adc" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
        return {};
      }
      return {
        reads: [left.register, right.register],
        writes: [left.register],
        registerEffects: { [left.register]: unknownExpr() },
        evidence: [`ADC ${left.register}, ${right.register}`],
      };
    },
  },
  {
    name: "adc-reg-imm",
    match: (instruction) => instruction.mnemonic === "adc" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || right.kind !== "immediate") {
        return {};
      }
      return {
        reads: [left.register],
        writes: [left.register],
        registerEffects: { [left.register]: unknownExpr() },
        evidence: [`ADC ${left.register}, ${right.text}`],
      };
    },
  },
  {
    name: "sbb-reg-reg",
    match: (instruction) => instruction.mnemonic === "sbb" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
        return {};
      }
      return {
        reads: [left.register, right.register],
        writes: [left.register],
        registerEffects: { [left.register]: unknownExpr() },
        evidence: [`SBB ${left.register}, ${right.register}`],
      };
    },
  },
  {
    name: "sbb-reg-imm",
    match: (instruction) => instruction.mnemonic === "sbb" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || right.kind !== "immediate") {
        return {};
      }
      return {
        reads: [left.register],
        writes: [left.register],
        registerEffects: { [left.register]: unknownExpr() },
        evidence: [`SBB ${left.register}, ${right.text}`],
      };
    },
  },
  {
    name: "inc-reg",
    match: (instruction) => instruction.mnemonic === "inc" && instruction.operands.length === 1,
    evaluate: (instruction, _arch) => {
      const operand = parseOperand(instruction.operands[0]);
      if (!isRegisterOperand(operand)) {
        return {};
      }
      return {
        reads: [operand.register],
        writes: [operand.register],
        registerEffects: { [operand.register]: selfPlus(1) },
        evidence: [`INC ${operand.register}`],
      };
    },
  },
  {
    name: "dec-reg",
    match: (instruction) => instruction.mnemonic === "dec" && instruction.operands.length === 1,
    evaluate: (instruction, _arch) => {
      const operand = parseOperand(instruction.operands[0]);
      if (!isRegisterOperand(operand)) {
        return {};
      }
      return {
        reads: [operand.register],
        writes: [operand.register],
        registerEffects: { [operand.register]: selfPlus(-1) },
        evidence: [`DEC ${operand.register}`],
      };
    },
  },
  {
    name: "xchg-reg-reg",
    match: (instruction) => instruction.mnemonic === "xchg" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
        return {};
      }
      return {
        reads: [left.register, right.register],
        writes: [left.register, right.register],
        registerEffects: {
          [left.register]: registerExpr(right.register),
          [right.register]: registerExpr(left.register),
        },
        evidence: [`XCHG ${left.register}, ${right.register}`],
      };
    },
  },
  {
    name: "lea-reg-mem",
    match: (instruction) => instruction.mnemonic === "lea" && instruction.operands.length === 2,
    evaluate: (instruction, _arch) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || right.kind !== "memory") {
        return {};
      }
      const address = memoryAddressExpression(right.text);
      if (!address) {
        return {};
      }
      const base = memoryBaseRegister(right.text);
      return {
        reads: base ? [base] : [],
        writes: [left.register],
        registerEffects: { [left.register]: address },
        evidence: [`LEA ${left.register}, ${right.text}`],
      };
    },
  },
  {
    name: "leave",
    match: (instruction) => instruction.mnemonic === "leave",
    evaluate: (_instruction, arch) => {
      const sp = spForArch(arch);
      const bp = bpForArch(arch);
      const entrySize = arch.stackEntrySize;
      return {
        reads: [bp, sp],
        writes: [sp, bp],
        stackDelta: { conservative: [entrySize] },
        memoryReads: [`[${bp}]`],
        registerEffects: {
          [sp]: registerExpr(bp, entrySize),
          [bp]: memoryExpr(registerExpr(bp)),
        },
        evidence: ["LEAVE restores frame and pops saved base pointer"],
      };
    },
  },
  {
    name: "call",
    match: (instruction) => instruction.mnemonic === "call" && instruction.operands.length >= 1,
    evaluate: (instruction, arch) => {
      const sp = spForArch(arch);
      const entrySize = arch.stackEntrySize;
      const defaultReg = (arch.id === "x64" ? "rax" : "eax") as Register;
      return {
        reads: instruction.operands.length > 0 ? [parseOperand(instruction.operands[0]).register ?? defaultReg] : [defaultReg],
        writes: [sp],
        stackDelta: { exact: [-entrySize] },
        flowEffects: ["CALL"] as FlowEffectKind[],
        registerEffects: { [sp]: selfPlus(-entrySize) },
        evidence: [`CALL ${instruction.operands.join(", ")}`],
      };
    },
  },
  {
    name: "jmp",
    match: (instruction) => instruction.mnemonic === "jmp" && instruction.operands.length >= 1,
    evaluate: (instruction, arch) => {
      const defaultReg = (arch.id === "x64" ? "rax" : "eax") as Register;
      return {
        reads: instruction.operands.length > 0 ? [parseOperand(instruction.operands[0]).register ?? defaultReg] : [defaultReg],
        flowEffects: ["JUMP"] as FlowEffectKind[],
        evidence: [`JMP ${instruction.operands.join(", ")}`],
      };
    },
  },
  {
    name: "nop",
    match: (instruction) => instruction.mnemonic === "nop",
    evaluate: (_instruction, _arch) => ({
      evidence: ["NOP has no semantic side effects"],
    }),
  },
];

function buildSemanticField<T>(values?: { exact?: T[]; conservative?: T[]; unknown?: boolean }, evidence: string[] = []): SemanticField<T> {
  return makeField(values?.exact ?? [], values?.conservative ?? [], values?.unknown ?? false, evidence);
}

function mergeOptionalField<T>(current: SemanticField<T>, next?: SemanticField<T>): SemanticField<T> {
  if (!next) {
    return current;
  }
  return mergeField(current, next);
}

function fromRuleResult(instruction: Instruction, index: number, result: RuleResult, supported: boolean): InstructionSemantic {
  return {
    schemaVersion: SEMANTIC_SCHEMA_VERSION,
    instructionIndex: index,
    instruction,
    reads: buildSemanticField<Register>({ exact: result.reads }, result.evidence),
    writes: buildSemanticField<Register>({ exact: result.writes }, result.evidence),
    stackDelta: buildSemanticField<number>(result.stackDelta, result.evidence),
    flags: buildSemanticField<string>(result.flags, result.evidence),
    memoryReads: buildSemanticField<string>({ exact: result.memoryReads }, result.evidence),
    memoryWrites: buildSemanticField<string>({ exact: result.memoryWrites }, result.evidence),
    flowEffects: buildSemanticField<FlowEffectKind>({ exact: result.flowEffects }, result.evidence),
    registerEffects: result.registerEffects ?? {},
    registerEffectsUnknown: false,
    evidence: result.evidence ?? [],
    supported,
  };
}

export function analyzeInstruction(instruction: Instruction, index: number, arch?: ArchConfig): InstructionSemantic {
  const config = arch ?? getArchConfig();
  for (const rule of RULES) {
    if (!rule.match(instruction)) {
      continue;
    }

    const result = rule.evaluate(instruction, config);
    const supported = Object.values(result).some((value) => Array.isArray(value) ? value.length > 0 : value !== undefined);
    if (!supported) {
      continue;
    }
    return fromRuleResult(instruction, index, result, true);
  }

  const fallback = unsupported(instruction);
  return {
    ...fallback,
    instructionIndex: index,
  };
}

export function isExactLoadRegister(instruction: InstructionSemantic): Register | undefined {
  if (instruction.instruction.mnemonic === "pop" && instruction.instruction.operands.length === 1) {
    const operand = parseOperand(instruction.instruction.operands[0]);
    if (isRegisterOperand(operand) && instruction.supported) {
      return operand.register;
    }
  }
  if (instruction.instruction.mnemonic === "mov" && instruction.instruction.operands.length === 2) {
    const left = parseOperand(instruction.instruction.operands[0]);
    const right = parseOperand(instruction.instruction.operands[1]);
    if (isRegisterOperand(left) && isRegisterOperand(right) && instruction.supported) {
      return left.register;
    }
  }
  return undefined;
}

export function countKnownStackDelta(semantic: InstructionSemantic): number | undefined {
  if (semantic.stackDelta.values.exact.size === 1 && semantic.stackDelta.values.conservative.size === 0 && !semantic.stackDelta.values.unknown) {
    return [...semantic.stackDelta.values.exact][0];
  }
  return undefined;
}
