import { Instruction, SemanticSequence } from "../semantics/types";

export const ROP_SCHEMA_VERSION = "v1" as const;

export type RopCategory =
  | "LOAD_REGISTER"
  | "MOVE_REGISTER"
  | "ZERO_REGISTER"
  | "ARITHMETIC"
  | "MEMORY_READ"
  | "MEMORY_WRITE"
  | "STACK_PIVOT"
  | "STACK_ADJUST"
  | "MULTI_REGISTER_LOAD"
  | "FLOW_TRANSFER"
  | "RETURN";

export type CapabilityKind =
  | "LOAD_REGISTER"
  | "ZERO_REGISTER"
  | "MOVE_REGISTER"
  | "EXCHANGE_REGISTER"
  | "STACK_PIVOT"
  | "MEMORY_READ"
  | "MEMORY_WRITE";

export type TerminatorKind = "RETURN" | "CALL" | "JUMP";

export interface AnalysisReason {
  rule: string;
  message: string;
  evidence: string[];
}

export interface GadgetLocation {
  module?: string;
  section?: string;
  virtualAddress?: number;
  fileOffset?: number;
  executable: string;
  writable: string;
  aslr: string;
  rebaseable: string;
  source?: string;
}

export interface RopCapability {
  kind: CapabilityKind;
  register?: string;
  targetRegister?: string;
  evidence: string[];
}

export interface RopQuery {
  reads?: string[];
  writes?: string[];
  preserves?: string[];
  stackDelta?: number | number[];
  capability?: CapabilityKind | CapabilityKind[];
  terminator?: TerminatorKind | TerminatorKind[];
  memoryReads?: boolean;
  memoryWrites?: boolean;
  memoryRead?: boolean;
  memoryWrite?: boolean;
  executableOnly?: boolean;
}

export interface RopGadget {
  schemaVersion: typeof ROP_SCHEMA_VERSION;
  canonicalId: string;
  instructions: Instruction[];
  locations: GadgetLocation[];
  semanticSummary: SemanticSequence;
  categories: RopCategory[];
  score: number;
  scoreReasons: AnalysisReason[];
  classificationReasons: AnalysisReason[];
  capabilities: RopCapability[];
}

export interface RopIndex {
  gadgets: RopGadget[];
  byCanonicalId: Map<string, RopGadget>;
}
