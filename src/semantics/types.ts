export const SEMANTIC_SCHEMA_VERSION = "v1" as const;

export type SchemaVersion = typeof SEMANTIC_SCHEMA_VERSION;

export type Confidence = "EXACT" | "CONSERVATIVE" | "UNKNOWN";

export type Register =
  | "eax"
  | "ecx"
  | "edx"
  | "ebx"
  | "esp"
  | "ebp"
  | "esi"
  | "edi";

export type FlowEffectKind = "RETURN" | "CALL" | "JUMP";

export type RegisterOffset =
  | { kind: "constant"; value: number }
  | { kind: "register"; register: Register }
  | { kind: "unknown" };

export type RegisterExpr =
  | { kind: "affine"; base: "self" | Register | "none"; offset: RegisterOffset }
  | { kind: "constant"; value: number }
  | { kind: "memory"; address: RegisterExpr; confidence: Confidence }
  | { kind: "unknown" };

export type RegisterEffectMap = Partial<Record<Register, RegisterExpr>>;
export type RegisterTransformMap = Record<Register, RegisterExpr>;

export interface SemanticSet<T> {
  exact: Set<T>;
  conservative: Set<T>;
  unknown: boolean;
}

export interface SemanticField<T> {
  values: SemanticSet<T>;
  confidence: Confidence;
  evidence: string[];
}

export interface InstructionSequenceSource {
  kind: string;
  name: string;
  format: string;
  version?: string;
}

export interface Provenance {
  module?: string;
  section?: string;
  virtualAddress?: number;
  fileOffset?: number;
  executable: Confidence;
  writable: Confidence;
  aslr: Confidence;
  rebaseable: Confidence;
}

export interface Instruction {
  originalText: string;
  normalizedText: string;
  mnemonic: string;
  operands: string[];
}

export interface InstructionSequence {
  schemaVersion: SchemaVersion;
  id: string;
  source: InstructionSequenceSource;
  originalText: string;
  instructions: Instruction[];
  provenance: Provenance;
}

export interface InstructionSemantic {
  schemaVersion: SchemaVersion;
  instructionIndex: number;
  instruction: Instruction;
  reads: SemanticField<Register>;
  writes: SemanticField<Register>;
  stackDelta: SemanticField<number>;
  flags: SemanticField<string>;
  memoryReads: SemanticField<string>;
  memoryWrites: SemanticField<string>;
  flowEffects: SemanticField<FlowEffectKind>;
  registerEffects: RegisterEffectMap;
  registerEffectsUnknown: boolean;
  evidence: string[];
  supported: boolean;
}

export interface SemanticSummary {
  schemaVersion: SchemaVersion;
  reads: SemanticField<Register>;
  writes: SemanticField<Register>;
  stackDelta: SemanticField<number>;
  flags: SemanticField<string>;
  memoryReads: SemanticField<string>;
  memoryWrites: SemanticField<string>;
  flowEffects: SemanticField<FlowEffectKind>;
  registerTransforms: RegisterTransformMap;
}

export interface SemanticSequence {
  schemaVersion: SchemaVersion;
  instructionSequenceId: string;
  instructionSequence: InstructionSequence;
  instructionSemantics: InstructionSemantic[];
  summary: SemanticSummary;
}
