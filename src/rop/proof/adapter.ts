import type {
  AdapterResult,
  BreakpointSnapshot,
  DeleteOwnedResult,
  FingerprintScope,
  LiveDisassembly,
  MemoryProtectionRegion,
  OwnedBreakpoint,
  ProofRegisterSnapshot,
  TargetFingerprint,
} from "./types";

export interface ProofDebuggerAdapter {
  readRegisters(): ProofRegisterSnapshot;
  readMemory(address: bigint, length: number): AdapterResult<Uint8Array>;
  listBreakpoints(): AdapterResult<BreakpointSnapshot[]>;
  setOneShot(address: bigint, marker: string): AdapterResult<OwnedBreakpoint>;
  deleteOwned(breakpoint: OwnedBreakpoint): DeleteOwnedResult;
  disassemble(address: bigint, maxInstructions: number): AdapterResult<LiveDisassembly>;
  getFingerprint(scope: FingerprintScope): AdapterResult<TargetFingerprint>;
  queryProtection(address: bigint): AdapterResult<MemoryProtectionRegion>;
}
