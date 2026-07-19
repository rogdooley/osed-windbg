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

// Asserts a net register transform at gadget exit. Only the provided fields are
// checked; each is matched against the gadget's aggregated `registerTransforms`
// entry for `register`. An unknown net transform satisfies no positive field.
export interface RegisterTransformQuery {
  register: string;
  // Net value is `base + offset`. Use the register's own name as `base` for a
  // self-relative change (e.g. `{ register: "esi", base: "esi", offset: 4 }`).
  base?: string;
  offset?: number;
  offsetRegister?: string;
  // Net value is a fixed constant (e.g. zeroed / set).
  constant?: number;
  // Net value is loaded from memory (pop-like / dereference).
  fromMemory?: boolean;
}

export interface RopQuery {
  reads?: string[];
  writes?: string[];
  // Net-unchanged at gadget exit: the register's aggregated transform is exactly
  // identity. Admits gadgets that clobber and restore (e.g. xchg/…/xchg).
  preserves?: string[];
  // Strict: the register is never written by any instruction in the gadget.
  preservesThroughout?: string[];
  transforms?: RegisterTransformQuery[];
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
