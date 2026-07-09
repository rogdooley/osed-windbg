import { canonicalizeInstructionSequence } from "./canonicalize";
import { analyzeInstruction } from "./instruction-semantics";
import {
  Confidence,
  InstructionSequence,
  SemanticField,
  SemanticSequence,
  SemanticSummary,
  SemanticSet,
  SEMANTIC_SCHEMA_VERSION,
} from "./types";

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
  return { values, confidence: confidenceForSet(values), evidence };
}

function mergeSet<T>(left: SemanticSet<T>, right: SemanticSet<T>): SemanticSet<T> {
  return {
    exact: new Set([...left.exact, ...right.exact]),
    conservative: new Set([...left.conservative, ...right.conservative]),
    unknown: left.unknown || right.unknown,
  };
}

function mergeField<T>(left: SemanticField<T>, right: SemanticField<T>): SemanticField<T> {
  const values = mergeSet(left.values, right.values);
  return {
    values,
    confidence: confidenceForSet(values),
    evidence: [...left.evidence, ...right.evidence],
  };
}

function emptyField<T>(): SemanticField<T> {
  return makeField<T>();
}

function appendField<T>(current: SemanticField<T>, next: SemanticField<T>): SemanticField<T> {
  return mergeField(current, next);
}

function aggregateStackDelta(instructionSemantics: SemanticSequence["instructionSemantics"]): SemanticField<number> {
  let exactTotal = 0;
  let conservativeTotal = 0;
  let sawExact = true;
  let sawConservative = false;
  let sawUnknown = false;
  const evidence: string[] = [];

  for (const step of instructionSemantics) {
    evidence.push(...step.stackDelta.evidence);

    if (step.stackDelta.values.unknown) {
      sawUnknown = true;
      sawExact = false;
      continue;
    }

    if (step.stackDelta.values.conservative.size > 0) {
      sawConservative = true;
      sawExact = false;
      for (const value of step.stackDelta.values.conservative) {
        conservativeTotal += value;
      }
      continue;
    }

    if (step.stackDelta.values.exact.size === 1) {
      exactTotal += [...step.stackDelta.values.exact][0];
      continue;
    }

    if (step.stackDelta.values.exact.size > 1) {
      sawExact = false;
      sawUnknown = true;
    }
  }

  if (sawUnknown) {
    return makeField<number>([], [], true, evidence);
  }
  if (sawConservative) {
    return makeField<number>([], [conservativeTotal], false, evidence);
  }
  if (sawExact) {
    return makeField<number>([exactTotal], [], false, evidence);
  }
  return makeField<number>([], [], true, evidence);
}

function makeSummary(): SemanticSummary {
  return {
    schemaVersion: SEMANTIC_SCHEMA_VERSION,
    reads: emptyField(),
    writes: emptyField(),
    stackDelta: emptyField(),
    flags: emptyField(),
    memoryReads: emptyField(),
    memoryWrites: emptyField(),
    flowEffects: emptyField(),
  };
}

function fieldFromExact<T>(exact: T[], evidence: string[]): SemanticField<T> {
  return makeField(exact, [], false, evidence);
}

export function composeSemanticSequence(sequence: InstructionSequence): SemanticSequence {
  const instructionSemantics = sequence.instructions.map((instruction, index) => analyzeInstruction(instruction, index));
  const summary = makeSummary();

  for (const semantic of instructionSemantics) {
    summary.reads = appendField(summary.reads, semantic.reads);
    summary.writes = appendField(summary.writes, semantic.writes);
    summary.stackDelta = appendField(summary.stackDelta, semantic.stackDelta);
    summary.flags = appendField(summary.flags, semantic.flags);
    summary.memoryReads = appendField(summary.memoryReads, semantic.memoryReads);
    summary.memoryWrites = appendField(summary.memoryWrites, semantic.memoryWrites);
    summary.flowEffects = appendField(summary.flowEffects, semantic.flowEffects);
  }

  summary.stackDelta = aggregateStackDelta(instructionSemantics);

  return {
    schemaVersion: SEMANTIC_SCHEMA_VERSION,
    instructionSequenceId: sequence.id,
    instructionSequence: sequence,
    instructionSemantics,
    summary,
  };
}

export function canonicalizeSequenceForPolicy(sequence: InstructionSequence): string {
  return canonicalizeInstructionSequence(sequence);
}
