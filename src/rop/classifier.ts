import { canonicalizeInstruction, canonicalizeInstructionSequence } from "../semantics/canonicalize";
import { InstructionSemantic, SemanticSequence } from "../semantics/types";
import { AnalysisReason, RopCategory, RopGadget, ROP_SCHEMA_VERSION } from "./types";

function hasExactFlow(semantic: SemanticSequence, kind: "CALL" | "JUMP" | "RETURN"): boolean {
  return semantic.summary.flowEffects.values.exact.has(kind);
}

function isExactZeroRegister(semantic: SemanticSequence): string | undefined {
  for (const step of semantic.instructionSemantics) {
    const ins = step.instruction;
    if (ins.mnemonic === "xor" && ins.operands.length === 2 && ins.operands[0].toLowerCase() === ins.operands[1].toLowerCase()) {
      return ins.operands[0].trim().toLowerCase();
    }
  }
  return undefined;
}

function isLoadRegister(step: InstructionSemantic): string | undefined {
  if (!step.supported) {
    return undefined;
  }
  if (step.instruction.mnemonic === "pop" && step.instruction.operands.length === 1) {
    return step.instruction.operands[0].trim().toLowerCase();
  }
  if (step.instruction.mnemonic === "mov" && step.instruction.operands.length === 2) {
    const left = step.instruction.operands[0].trim().toLowerCase();
    const right = step.instruction.operands[1].trim().toLowerCase();
    if (/^[a-z]{3}$/.test(left) && /^[a-z]{3}$/.test(right) && left !== right) {
      return left;
    }
  }
  return undefined;
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

  const zeroReg = isExactZeroRegister(semantic);
  if (zeroReg) {
    addCategory(categories, reasons, "ZERO_REGISTER", "xor-self", `zeroes ${zeroReg} via xor ${zeroReg}, ${zeroReg}`, evidence);
  }

  for (const step of semantic.instructionSemantics) {
    const text = canonicalizeInstruction(step.instruction);
    const lower = text.toLowerCase();
    const loadRegister = isLoadRegister(step);
    if (loadRegister) {
      if (semantic.instructionSemantics.length === 1 || semantic.instructionSemantics.every((item) => item.supported)) {
        addCategory(categories, reasons, "LOAD_REGISTER", "load-register", `loads ${loadRegister}`, [text]);
      }
    }
    if (lower.startsWith("mov ") && lower.includes("[") && lower.includes("]")) {
      if (lower.indexOf("[") < lower.indexOf(",")) {
        addCategory(categories, reasons, "MEMORY_WRITE", "memory-write", "writes to memory", [text]);
      } else {
        addCategory(categories, reasons, "MEMORY_READ", "memory-read", "reads from memory", [text]);
      }
    }
    if (lower.startsWith("xchg ") && lower.includes("esp")) {
      addCategory(categories, reasons, "STACK_PIVOT", "stack-pivot", "writes esp via exchange", [text]);
    }
    if (lower === "leave" || lower.startsWith("ret ")) {
      addCategory(categories, reasons, "STACK_ADJUST", "stack-adjust", "adjusts the stack", [text]);
    }
    if (lower.startsWith("add ") || lower.startsWith("sub ") || lower.startsWith("inc ") || lower.startsWith("dec ") || lower.startsWith("neg ")) {
      addCategory(categories, reasons, "ARITHMETIC", "arithmetic", "performs arithmetic transformation", [text]);
    }
    if (step.instruction.mnemonic === "pop" && step.instruction.operands.length > 1) {
      addCategory(categories, reasons, "MULTI_REGISTER_LOAD", "multi-load", "loads multiple registers", [text]);
    }
    if (step.instruction.mnemonic === "call" || step.instruction.mnemonic === "jmp") {
      addCategory(categories, reasons, "FLOW_TRANSFER", "explicit-flow", "explicit control-flow transfer", [text]);
    }
  }

  if (semantic.instructionSemantics.some((step) => step.instruction.mnemonic === "xchg" && step.instruction.operands.some((operand) => operand.trim().toLowerCase() === "esp"))) {
    addCategory(categories, reasons, "STACK_PIVOT", "stack-pivot", "exchange touches esp", evidence);
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

