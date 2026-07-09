import { SemanticSequence } from "../semantics/types";
import { AnalysisReason, RopCategory } from "./types";

function addReason(reasons: AnalysisReason[], rule: string, message: string, evidence: string[], delta: number): void {
  reasons.push({ rule, message: `${message} (${delta >= 0 ? "+" : ""}${delta})`, evidence });
}

function hasCategory(categories: RopCategory[], category: RopCategory): boolean {
  return categories.includes(category);
}

export function scoreSemanticSequence(
  semantic: SemanticSequence,
  categories: RopCategory[],
): { score: number; scoreReasons: AnalysisReason[] } {
  let score = 100;
  const reasons: AnalysisReason[] = [];
  const evidence = semantic.instructionSemantics.flatMap((step) => (step.evidence.length > 0 ? step.evidence : [step.instruction.normalizedText]));

  const instructionCount = semantic.instructionSemantics.length;
  const unsupportedCount = semantic.instructionSemantics.filter((step) => !step.supported).length;
  const memoryWrites = semantic.summary.memoryWrites.values.exact.size + semantic.summary.memoryWrites.values.conservative.size;
  const memoryReads = semantic.summary.memoryReads.values.exact.size + semantic.summary.memoryReads.values.conservative.size;
  const flowTransfers = semantic.summary.flowEffects.values.exact.size;
  const stackWrites = semantic.summary.writes.values.exact.has("esp") || semantic.summary.writes.values.conservative.has("esp");

  const exactFields = [
    semantic.summary.reads.confidence,
    semantic.summary.writes.confidence,
    semantic.summary.stackDelta.confidence,
    semantic.summary.flags.confidence,
    semantic.summary.memoryReads.confidence,
    semantic.summary.memoryWrites.confidence,
    semantic.summary.flowEffects.confidence,
  ].filter((confidence) => confidence === "EXACT").length;

  score += exactFields * 5;
  if (exactFields > 0) {
    addReason(reasons, "exact-semantics", "exact semantic facts available", evidence, exactFields * 5);
  }

  if (instructionCount <= 2) {
    score += 20;
    addReason(reasons, "short-gadget", "short gadget", evidence, 20);
  } else {
    const penalty = (instructionCount - 2) * 10;
    score -= penalty;
    addReason(reasons, "long-gadget", "longer gadget", evidence, -penalty);
  }

  if (unsupportedCount > 0) {
    const penalty = unsupportedCount * 30;
    score -= penalty;
    addReason(reasons, "unknown-semantics", "unsupported instructions reduce confidence", evidence, -penalty);
  }

  if (memoryWrites > 0) {
    const penalty = memoryWrites * 35;
    score -= penalty;
    addReason(reasons, "memory-write", "memory writes are expensive and risky", evidence, -penalty);
  }

  if (memoryReads > 0) {
    const penalty = memoryReads * 10;
    score -= penalty;
    addReason(reasons, "memory-read", "memory reads add side effects", evidence, -penalty);
  }

  if (flowTransfers > 0 || hasCategory(categories, "FLOW_TRANSFER")) {
    const penalty = 55;
    score -= penalty;
    addReason(reasons, "flow-transfer", "explicit control-flow transfer", evidence, -penalty);
  }

  if (hasCategory(categories, "STACK_PIVOT")) {
    const penalty = 25;
    score -= penalty;
    addReason(reasons, "stack-pivot", "stack pivot candidates are deprioritized by default", evidence, -penalty);
  }

  if (stackWrites && !hasCategory(categories, "STACK_PIVOT")) {
    const penalty = 15;
    score -= penalty;
    addReason(reasons, "stack-write", "writes to ESP without a pivot classification", evidence, -penalty);
  }

  if (semantic.summary.writes.values.exact.size === 1 && semantic.summary.writes.values.exact.has("eax")) {
    score += 5;
    addReason(reasons, "simple-register-load", "simple single-register write", evidence, 5);
  }

  if (categories.includes("LOAD_REGISTER") || categories.includes("ZERO_REGISTER") || categories.includes("MOVE_REGISTER")) {
    score += 10;
    addReason(reasons, "register-primitive", "simple register primitive", evidence, 10);
  }

  if (semantic.summary.memoryWrites.values.unknown || semantic.summary.memoryReads.values.unknown) {
    score -= 10;
    addReason(reasons, "unknown-memory", "unknown memory effects reduce confidence", evidence, -10);
  }

  return {
    score,
    scoreReasons: reasons,
  };
}
