import { canonicalizeInstruction } from "./canonicalize";
import {
  Confidence,
  FlowEffectKind,
  Instruction,
  InstructionSemantic,
  Register,
  SEMANTIC_SCHEMA_VERSION,
  SemanticField,
  SemanticSet,
} from "./types";

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
  evidence?: string[];
}

interface Rule {
  name: string;
  match(instruction: Instruction): boolean;
  evaluate(instruction: Instruction): RuleResult;
}

const REGISTERS: Register[] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];

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

  if (REGISTERS.includes(normalized as Register)) {
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
  const match = text.toLowerCase().match(/\[([a-z]{3})\]/);
  if (!match) {
    return undefined;
  }
  const register = match[1] as Register;
  return REGISTERS.includes(register) ? register : undefined;
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
    evidence: [`unsupported instruction: ${text}`],
    supported: false,
  };
}

const RULES: Rule[] = [
  {
    name: "pop-reg",
    match: (instruction) => instruction.mnemonic === "pop" && instruction.operands.length === 1,
    evaluate: (instruction) => {
      const operand = parseOperand(instruction.operands[0]);
      if (!isRegisterOperand(operand)) {
        return {};
      }
      return {
        reads: ["esp"],
        writes: [operand.register],
        stackDelta: { exact: [4] },
        memoryReads: ["[esp]"],
        flowEffects: [],
        evidence: [`POP ${operand.register} reads stack and writes ${operand.register}`],
      };
    },
  },
  {
    name: "push-reg",
    match: (instruction) => instruction.mnemonic === "push" && instruction.operands.length === 1,
    evaluate: (instruction) => {
      const operand = parseOperand(instruction.operands[0]);
      if (!isRegisterOperand(operand)) {
        return {};
      }
      return {
        reads: [operand.register, "esp"],
        writes: ["esp"],
        stackDelta: { exact: [-4] },
        memoryWrites: ["[esp]"],
        evidence: [`PUSH ${operand.register} decrements stack pointer`],
      };
    },
  },
  {
    name: "ret",
    match: (instruction) => instruction.mnemonic === "ret",
    evaluate: (instruction) => {
      const imm = immediateOperand(instruction);
      const delta = imm === undefined ? 4 : 4 + imm;
      const evidence = imm === undefined
        ? ["RET pops return address"]
        : [`RET ${imm} adjusts stack by ${delta}`];
      return {
        reads: ["esp"],
        writes: ["esp"],
        stackDelta: { exact: [delta] },
        flowEffects: ["RETURN"],
        evidence,
      };
    },
  },
  {
    name: "mov-reg-reg",
    match: (instruction) => instruction.mnemonic === "mov" && instruction.operands.length === 2,
    evaluate: (instruction) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
        return {};
      }
      return {
        reads: [right.register],
        writes: [left.register],
        evidence: [`MOV ${left.register}, ${right.register}`],
      };
    },
  },
  {
    name: "mov-reg-mem",
    match: (instruction) => instruction.mnemonic === "mov" && instruction.operands.length === 2,
    evaluate: (instruction) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || right.kind !== "memory") {
        return {};
      }
      const baseRegister = memoryBaseRegister(right.text);
      return {
        reads: baseRegister ? [baseRegister] : [],
        writes: [left.register],
        memoryReads: [right.text],
        evidence: [`MOV ${left.register}, ${right.text}`],
      };
    },
  },
  {
    name: "mov-mem-reg",
    match: (instruction) => instruction.mnemonic === "mov" && instruction.operands.length === 2,
    evaluate: (instruction) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (left.kind !== "memory" || !isRegisterOperand(right)) {
        return {};
      }
      const base = memoryBaseRegister(left.text);
      return {
        reads: [right.register, ...(base ? [base] : [])],
        writes: base === "esp" ? ["esp"] : [],
        memoryWrites: [left.text],
        evidence: [`MOV ${left.text}, ${right.register}`],
      };
    },
  },
  {
    name: "xor-reg-reg",
    match: (instruction) => instruction.mnemonic === "xor" && instruction.operands.length === 2,
    evaluate: (instruction) => {
      const reg = sameRegisterOperands(instruction);
      if (!reg) {
        return {};
      }
      return {
        reads: [reg],
        writes: [reg],
        evidence: [`XOR ${reg}, ${reg} zeros register`],
      };
    },
  },
  {
    name: "add-reg-reg",
    match: (instruction) => instruction.mnemonic === "add" && instruction.operands.length === 2,
    evaluate: (instruction) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
        return {};
      }
      return {
        reads: [left.register, right.register],
        writes: [left.register],
        evidence: [`ADD ${left.register}, ${right.register}`],
      };
    },
  },
  {
    name: "add-reg-imm",
    match: (instruction) => instruction.mnemonic === "add" && instruction.operands.length === 2,
    evaluate: (instruction) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || right.kind !== "immediate") {
        return {};
      }
      return {
        reads: [left.register],
        writes: [left.register],
        stackDelta: left.register === "esp" ? { conservative: [Number.parseInt(right.text.replace(/^0x/, ""), 16) || 0] } : undefined,
        evidence: [`ADD ${left.register}, ${right.text}`],
      };
    },
  },
  {
    name: "sub-reg-reg",
    match: (instruction) => instruction.mnemonic === "sub" && instruction.operands.length === 2,
    evaluate: (instruction) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
        return {};
      }
      return {
        reads: [left.register, right.register],
        writes: [left.register],
        evidence: [`SUB ${left.register}, ${right.register}`],
      };
    },
  },
  {
    name: "sub-reg-imm",
    match: (instruction) => instruction.mnemonic === "sub" && instruction.operands.length === 2,
    evaluate: (instruction) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || right.kind !== "immediate") {
        return {};
      }
      return {
        reads: [left.register],
        writes: [left.register],
        evidence: [`SUB ${left.register}, ${right.text}`],
      };
    },
  },
  {
    name: "neg-reg",
    match: (instruction) => instruction.mnemonic === "neg" && instruction.operands.length === 1,
    evaluate: (instruction) => {
      const operand = parseOperand(instruction.operands[0]);
      if (!isRegisterOperand(operand)) {
        return {};
      }
      return {
        reads: [operand.register],
        writes: [operand.register],
        evidence: [`NEG ${operand.register}`],
      };
    },
  },
  {
    name: "inc-reg",
    match: (instruction) => instruction.mnemonic === "inc" && instruction.operands.length === 1,
    evaluate: (instruction) => {
      const operand = parseOperand(instruction.operands[0]);
      if (!isRegisterOperand(operand)) {
        return {};
      }
      return {
        reads: [operand.register],
        writes: [operand.register],
        evidence: [`INC ${operand.register}`],
      };
    },
  },
  {
    name: "dec-reg",
    match: (instruction) => instruction.mnemonic === "dec" && instruction.operands.length === 1,
    evaluate: (instruction) => {
      const operand = parseOperand(instruction.operands[0]);
      if (!isRegisterOperand(operand)) {
        return {};
      }
      return {
        reads: [operand.register],
        writes: [operand.register],
        evidence: [`DEC ${operand.register}`],
      };
    },
  },
  {
    name: "xchg-reg-reg",
    match: (instruction) => instruction.mnemonic === "xchg" && instruction.operands.length === 2,
    evaluate: (instruction) => {
      const left = parseOperand(instruction.operands[0]);
      const right = parseOperand(instruction.operands[1]);
      if (!isRegisterOperand(left) || !isRegisterOperand(right)) {
        return {};
      }
      return {
        reads: [left.register, right.register],
        writes: [left.register, right.register],
        evidence: [`XCHG ${left.register}, ${right.register}`],
      };
    },
  },
  {
    name: "leave",
    match: (instruction) => instruction.mnemonic === "leave",
    evaluate: () => ({
      reads: ["ebp", "esp"],
      writes: ["esp", "ebp"],
      stackDelta: { conservative: [4] },
      memoryReads: ["[ebp]"],
      evidence: ["LEAVE restores frame and pops saved base pointer"],
    }),
  },
  {
    name: "call",
    match: (instruction) => instruction.mnemonic === "call" && instruction.operands.length >= 1,
    evaluate: (instruction) => ({
      reads: instruction.operands.length > 0 ? [parseOperand(instruction.operands[0]).register ?? "eax"] : ["eax"],
      writes: ["esp"],
      stackDelta: { exact: [-4] },
      flowEffects: ["CALL"],
      evidence: [`CALL ${instruction.operands.join(", ")}`],
    }),
  },
  {
    name: "jmp",
    match: (instruction) => instruction.mnemonic === "jmp" && instruction.operands.length >= 1,
    evaluate: (instruction) => ({
      reads: instruction.operands.length > 0 ? [parseOperand(instruction.operands[0]).register ?? "eax"] : ["eax"],
      flowEffects: ["JUMP"],
      evidence: [`JMP ${instruction.operands.join(", ")}`],
    }),
  },
  {
    name: "nop",
    match: (instruction) => instruction.mnemonic === "nop",
    evaluate: () => ({
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
    evidence: result.evidence ?? [],
    supported,
  };
}

export function analyzeInstruction(instruction: Instruction, index: number): InstructionSemantic {
  for (const rule of RULES) {
    if (!rule.match(instruction)) {
      continue;
    }

    const result = rule.evaluate(instruction);
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
