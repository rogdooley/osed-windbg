import type { ChainStep } from "../chain";
import type { CapabilityIndex } from "../capabilities";

export const PROOF_RECORD_SCHEMA_VERSION = "v1" as const;

export type ProofRecordSchemaVersion = typeof PROOF_RECORD_SCHEMA_VERSION;
export type ProofMode = "guided" | "observe";
export type ProofAssertionStatus = "VERIFIED" | "FAILED" | "UNVERIFIED";
export type ProofOutcomeStatus = ProofAssertionStatus;
export type ProofStopOutcome = ProofAssertionStatus | "UNEXPECTED_STOP" | "STALE_TARGET";

export type ProofSessionState =
  | "IDLE"
  | "ARMED"
  | "CHECKPOINT_REACHED"
  | "FAILED"
  | "UNVERIFIED"
  | "STALE_TARGET"
  | "EXECUTION_COMPLETE"
  | "POSTCONDITION_ARMED"
  | "POSTCONDITION_OBSERVED"
  | "POSTCONDITION_FAILED"
  | "CANCELLED";

export interface AdapterError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export type AdapterResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: AdapterError };

export interface ProofRegisterSnapshot {
  eip: bigint;
  esp: bigint;
  registers: Record<string, bigint>;
  exceptionCode?: bigint;
}

export interface BreakpointSnapshot {
  id: number;
  address: bigint;
  enabled: boolean;
  oneShot: boolean;
  marker: string;
  command: string;
}

export interface OwnedBreakpoint {
  id: number;
  address: bigint;
  enabled: boolean;
  oneShot: boolean;
  marker: string;
}

export type DeleteOwnedResult =
  | { status: "deleted" | "already-fired" | "not-found"; breakpoint: OwnedBreakpoint }
  | { status: "identity-mismatch"; breakpoint: OwnedBreakpoint; observed: BreakpointSnapshot };

export interface LiveDisassembly {
  address: bigint;
  bytes: Uint8Array;
  instructions: string[];
}

export interface MemoryProtectionRegion {
  base: bigint;
  size: bigint;
  protect: number;
  name: string;
  executable: boolean;
  writable: boolean;
}

export interface FingerprintScope {
  targetPath?: string;
  moduleNames: string[];
  gadgetAddresses: bigint[];
  protectionAddresses: bigint[];
}

export interface FingerprintModule {
  name: string;
  path: string;
  base: bigint;
  preferredBase: bigint;
  size: bigint;
  timestamp?: number;
  checksum?: number;
}

export interface FingerprintGadget {
  address: bigint;
  module: string;
  rva: bigint;
  bytes: Uint8Array;
  instructions: string[];
}

export interface FingerprintProtection {
  address: bigint;
  region: MemoryProtectionRegion;
}

export interface TargetFingerprint {
  processId: bigint;
  threadId: bigint;
  architecture: "x86" | "x64" | "unknown";
  pointerSize: 4 | 8;
  targetPath: string;
  targetSha256?: string;
  complete: boolean;
  incompleteReasons: string[];
  modules: FingerprintModule[];
  gadgets: FingerprintGadget[];
  protections: FingerprintProtection[];
}

export interface FingerprintComparison {
  status: "CURRENT" | "INCOMPLETE" | "STALE_TARGET";
  reasons: string[];
}

export type ProofValueExpression =
  | { kind: "constant"; value: bigint }
  | { kind: "register"; register: string; checkpoint: "before" | "after" }
  | { kind: "register-offset"; register: string; checkpoint: "before"; offset: number }
  | { kind: "memory-dword"; address: ProofValueExpression }
  | { kind: "sum"; terms: ProofValueExpression[] }
  | { kind: "deferred"; reason: string }
  | { kind: "unknown"; reason: string };

export interface ProofAssertionTemplate {
  subject: string;
  expected: ProofValueExpression;
  observed?: ProofValueExpression;
  confidence: "EXACT" | "CONSERVATIVE" | "UNKNOWN";
  evidence: string[];
  required: boolean;
}

export interface ProofCheckpoint {
  id: number;
  stepIndex: number;
  label: string;
  target: ProofValueExpression;
  assertions: ProofAssertionTemplate[];
  provenance: Array<{ address?: bigint; module?: string; instructions: string[] }>;
  dynamic: boolean;
}

export interface ProofAssertionObservation {
  subject: string;
  expectedExpression: string;
  expectedValue?: bigint;
  observedValue?: bigint;
  status: ProofAssertionStatus;
  confidence: "EXACT" | "CONSERVATIVE" | "UNKNOWN";
  evidence: string[];
  reason: string;
  differenceBytes?: number;
}

export interface CheckpointObservation {
  checkpointId: number;
  timestamp: string;
  outcome: ProofStopOutcome;
  registers: ProofRegisterSnapshot;
  assertions: ProofAssertionObservation[];
  reason: string;
}

export interface ProofPlan {
  steps: ChainStep[];
  checkpoints: ProofCheckpoint[];
  api?: string;
  incompleteReasons: string[];
}

export interface ProofPlanInput {
  chain: string | ChainStep[];
  corpus?: CapabilityIndex;
  api?: string;
}

export interface ProofEvent {
  sequence: number;
  timestamp: string;
  kind: string;
  detail: Record<string, unknown>;
}

export interface ProofSession {
  id: string;
  mode: ProofMode;
  state: ProofSessionState;
  plan: ProofPlan;
  checkpointIndex: number;
  ownedBreakpoint?: OwnedBreakpoint;
  baselineFingerprint: TargetFingerprint;
  observations: CheckpointObservation[];
  events: ProofEvent[];
  executionStatus: ProofOutcomeStatus;
  objectiveStatus: ProofOutcomeStatus;
  objectiveReason: string;
}

export interface SerializedProofAssertion {
  subject: string;
  expectedExpression: string;
  expectedValue?: string;
  observedValue?: string;
  status: ProofAssertionStatus;
  reason: string;
  differenceBytes?: number;
}

export interface ProofRecordV1 {
  schemaVersion: ProofRecordSchemaVersion;
  sessionId: string;
  mode: ProofMode;
  state: ProofSessionState;
  executionStatus: ProofOutcomeStatus;
  objectiveStatus: ProofOutcomeStatus;
  objectiveReason: string;
  targetPath: string;
  targetSha256?: string;
  observations: Array<{
    checkpointId: number;
    timestamp: string;
    outcome: ProofStopOutcome;
    reason: string;
    assertions: SerializedProofAssertion[];
  }>;
  events: ProofEvent[];
}
