import { canonicalizeInstruction, canonicalizeInstructionSequence } from "../semantics/canonicalize";
import { InstructionSemantic, SemanticSequence } from "../semantics/types";
import { AnalysisReason, RopCategory, RopGadget, ROP_SCHEMA_VERSION } from "./types";

function hasExactFlow(semantic: SemanticSequence, kind: "CALL" | "JUMP" | "RETURN"): boolean {
  return semantic.summary.flowEffects.values.exact.has(kind);
}

const ARITHMETIC_MNEMONICS = new Set(["add", "sub", "inc", "dec", "neg"]);

// A register is zeroed when its aggregated net transform is exactly the constant
// 0. More precise than matching `xor reg, reg` text: it also rejects a later
// write that un-zeros the register (e.g. `xor eax, eax ; inc eax` nets to 1).
function zeroedRegisters(semantic: SemanticSequence): string[] {
  const zeroed: string[] = [];
  for (const [register, expr] of Object.entries(semantic.summary.registerTransforms)) {
    if (expr.kind === "constant" && expr.value === 0) {
      zeroed.push(register);
    }
  }
  return zeroed;
}

// ESP ends up based on a register other than ESP: `xchg esp, r` / `mov esp, r` /
// `lea esp, [r+k]` / `leave` (esp := ebp+4). Driven by the net transform, so a
// round trip like `xchg esp, eax ; xchg esp, eax` (net identity) is not a pivot.
function pivotsStack(semantic: SemanticSequence): boolean {
  const esp = semantic.summary.registerTransforms.esp;
  return esp.kind === "affine" && esp.base !== "esp" && esp.base !== "none";
}

function isLoadRegister(step: InstructionSemantic): string | undefined {
  if (!step.supported) {
    return undefined;
  }
  // Writing ESP is a pivot/adjust, not a general register load, so exclude it.
  if (step.instruction.mnemonic === "pop" && step.instruction.operands.length === 1) {
    const register = step.instruction.operands[0].trim().toLowerCase();
    return register === "esp" ? undefined : register;
  }
  if (step.instruction.mnemonic === "mov" && step.instruction.operands.length === 2) {
    const left = step.instruction.operands[0].trim().toLowerCase();
    const right = step.instruction.operands[1].trim().toLowerCase();
    if (/^[a-z]{3}$/.test(left) && /^[a-z]{3}$/.test(right) && left !== right && left !== "esp") {
      return left;
    }
  }
  return undefined;
}

// STACK_ADJUST is a deliberate, fixed-amount ESP move that stays ESP-relative
// (`add/sub esp, imm` or `ret imm`). Kept instruction-keyed because ret mechanics
// also move ESP ESP-relatively, so the net delta alone cannot distinguish it.
// `leave` makes ESP EBP-relative and is classified as a pivot instead.
function adjustsStackExplicitly(step: InstructionSemantic): boolean {
  const ins = step.instruction;
  const destination = ins.operands[0]?.trim().toLowerCase();
  if ((ins.mnemonic === "add" || ins.mnemonic === "sub") && destination === "esp") {
    return true;
  }
  return ins.mnemonic === "ret" && ins.operands.length >= 1;
}

function addCategory(categories: Set<RopCategory>, reasonList: AnalysisReason[], category: RopCategory, rule: string, message: string, evidence: string[]): void {
  categories.add(category);
  reasonList.push({ rule, message, evidence });
}

function buildEvidenceFromSemantic(semantic: SemanticSequence): string[] {
  return semantic.instructionSemantics.flatMap((step) => step.evidence.length > 0 ? step.evidence : [step.instruction.normalizedText]);
}

export function classifySemanticSequence(semantic: SemanticSequence): { categories: RopCategory[]; reasons: AnalysisReason[] } {
  const categories = new Set<RopCategory>();
  const reasons: AnalysisReason[] = [];
  const evidence = buildEvidenceFromSemantic(semantic);

  if (hasExactFlow(semantic, "RETURN")) {
    addCategory(categories, reasons, "RETURN", "return-flow", "gadget returns control to the stack", evidence);
  }
  if (hasExactFlow(semantic, "CALL") || hasExactFlow(semantic, "JUMP")) {
    addCategory(categories, reasons, "FLOW_TRANSFER", "flow-transfer", "gadget transfers control flow", evidence);
  }

  for (const zeroReg of zeroedRegisters(semantic)) {
    addCategory(categories, reasons, "ZERO_REGISTER", "zero-register", `net-zeroes ${zeroReg}`, evidence);
  }

  for (const step of semantic.instructionSemantics) {
    const text = canonicalizeInstruction(step.instruction);
    const loadRegister = isLoadRegister(step);
    if (loadRegister) {
      if (semantic.instructionSemantics.length === 1 || semantic.instructionSemantics.every((item) => item.supported)) {
        addCategory(categories, reasons, "LOAD_REGISTER", "load-register", `loads ${loadRegister}`, [text]);
      }
    }
    if (adjustsStackExplicitly(step)) {
      addCategory(categories, reasons, "STACK_ADJUST", "stack-adjust", "adjusts the stack pointer by a fixed amount", [text]);
    }
    if (ARITHMETIC_MNEMONICS.has(step.instruction.mnemonic)) {
      addCategory(categories, reasons, "ARITHMETIC", "arithmetic", "performs arithmetic transformation", [text]);
    }
    if (step.instruction.mnemonic === "pop" && step.instruction.operands.length > 1) {
      addCategory(categories, reasons, "MULTI_REGISTER_LOAD", "multi-load", "loads multiple registers", [text]);
    }
    if (step.instruction.mnemonic === "call" || step.instruction.mnemonic === "jmp") {
      addCategory(categories, reasons, "FLOW_TRANSFER", "explicit-flow", "explicit control-flow transfer", [text]);
    }
  }

  // Pivot classification is driven by the net ESP transform (see pivotsStack).
  if (pivotsStack(semantic)) {
    addCategory(categories, reasons, "STACK_PIVOT", "stack-pivot", "esp becomes based on another register", evidence);
  }

  if (semantic.instructionSemantics.some((step) => step.instruction.mnemonic === "mov" && step.instruction.operands.length === 2 && step.instruction.operands[0].includes("[") && !step.instruction.operands[1].includes("["))) {
    addCategory(categories, reasons, "MEMORY_WRITE", "memory-write", "contains a memory write", evidence);
  }

  if (semantic.instructionSemantics.some((step) => step.instruction.mnemonic === "mov" && step.instruction.operands.length === 2 && !step.instruction.operands[0].includes("[") && step.instruction.operands[1].includes("["))) {
    addCategory(categories, reasons, "MEMORY_READ", "memory-read", "contains a memory read", evidence);
  }

  return { categories: [...categories], reasons };
}

export function canonicalizeRopGadgetId(semantic: SemanticSequence): string {
  return canonicalizeInstructionSequence(semantic.instructionSequence);
}

export function buildRopGadget(semantic: SemanticSequence): Pick<RopGadget, "schemaVersion" | "canonicalId" | "categories" | "classificationReasons"> {
  const classification = classifySemanticSequence(semantic);
  return {
    schemaVersion: ROP_SCHEMA_VERSION,
    canonicalId: canonicalizeRopGadgetId(semantic),
    categories: classification.categories,
    classificationReasons: classification.reasons,
  };
}

