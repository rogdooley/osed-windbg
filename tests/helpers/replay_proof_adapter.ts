import type {
  AdapterResult,
  BreakpointSnapshot,
  DeleteOwnedResult,
  FingerprintScope,
  LiveDisassembly,
  MemoryProtectionRegion,
  OwnedBreakpoint,
  ProofDebuggerAdapter,
  ProofRegisterSnapshot,
  TargetFingerprint,
} from "../../src/rop/proof";

type RawFrame = {
  registers: Record<string, string>;
  memory: Record<string, string>;
  breakpoints: Array<{
    id: number;
    address: string;
    enabled: boolean;
    oneShot: boolean;
    command: string;
  }>;
  disassembly: Record<string, { bytes: string; instructions: string[] }>;
  protections: Record<string, {
    base: string;
    size: string;
    protect: number;
    name: string;
    executable: boolean;
    writable: boolean;
  }>;
  fingerprint: {
    processId: string;
    threadId: string;
    architecture: "x86" | "x64" | "unknown";
    pointerSize: 4 | 8;
    targetPath: string;
    targetSha256?: string;
    complete: boolean;
    modules: unknown[];
    gadgets: unknown[];
    protections: unknown[];
  };
};

export type ReplayFixture = { frames: RawFrame[] };

function ok<T>(value: T): AdapterResult<T> {
  return { ok: true, value };
}

function fail<T>(code: string, message: string): AdapterResult<T> {
  return { ok: false, error: { code, message } };
}

function parseHex(value: string): bigint {
  return BigInt(value);
}

function parseBytes(value: string): Uint8Array {
  if (value.length % 2 !== 0) throw new Error(`Invalid replay byte string: ${value}`);
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export class ReplayProofAdapter implements ProofDebuggerAdapter {
  private frameIndex = 0;
  private managedBreakpoints: BreakpointSnapshot[] = [];
  readonly actions: Array<{ kind: "set" | "delete"; id: number; address: bigint; marker: string }> = [];

  constructor(private readonly fixture: ReplayFixture) {
    if (fixture.frames.length === 0) throw new Error("Replay fixture requires at least one frame.");
  }

  private get frame(): RawFrame {
    return this.fixture.frames[this.frameIndex];
  }

  advanceStop(): void {
    if (this.frameIndex + 1 >= this.fixture.frames.length) {
      throw new Error("Replay has no later stop frame.");
    }
    this.frameIndex += 1;
  }

  replaceManagedBreakpoint(id: number, replacement: BreakpointSnapshot): void {
    const index = this.managedBreakpoints.findIndex((entry) => entry.id === id);
    if (index < 0) throw new Error(`Managed breakpoint ${id} not found.`);
    this.managedBreakpoints[index] = replacement;
  }

  readRegisters(): ProofRegisterSnapshot {
    const parsed: Record<string, bigint> = {};
    for (const [name, value] of Object.entries(this.frame.registers)) parsed[name] = parseHex(value);
    return {
      eip: parsed.eip,
      esp: parsed.esp,
      registers: parsed,
      exceptionCode: parsed.exceptionCode,
    };
  }

  readMemory(address: bigint, length: number): AdapterResult<Uint8Array> {
    for (const [rawBase, encoded] of Object.entries(this.frame.memory)) {
      const base = parseHex(rawBase);
      const bytes = parseBytes(encoded);
      const offset = Number(address - base);
      if (offset >= 0 && offset + length <= bytes.length) {
        return ok(bytes.slice(offset, offset + length));
      }
    }
    return fail("memory-unreadable", `Replay memory unreadable at 0x${address.toString(16)} (${length} bytes).`);
  }

  listBreakpoints(): AdapterResult<BreakpointSnapshot[]> {
    const recorded = this.frame.breakpoints.map((entry) => ({
      ...entry,
      address: parseHex(entry.address),
      marker: entry.command,
    }));
    return ok([...recorded, ...this.managedBreakpoints].map((entry) => ({ ...entry })));
  }

  setOneShot(address: bigint, marker: string): AdapterResult<OwnedBreakpoint> {
    const listed = this.listBreakpoints();
    if (!listed.ok) return listed;
    const id = listed.value.reduce((highest, entry) => Math.max(highest, entry.id), -1) + 1;
    const breakpoint: OwnedBreakpoint = { id, address, enabled: true, oneShot: true, marker };
    this.managedBreakpoints.push({ ...breakpoint, command: marker });
    this.actions.push({ kind: "set", id, address, marker });
    return ok(breakpoint);
  }

  deleteOwned(owned: OwnedBreakpoint): DeleteOwnedResult {
    const index = this.managedBreakpoints.findIndex((entry) => entry.id === owned.id);
    if (index < 0) {
      return this.readRegisters().eip === owned.address
        ? { status: "already-fired", breakpoint: owned }
        : { status: "not-found", breakpoint: owned };
    }
    const current = this.managedBreakpoints[index];
    if (
      current.address !== owned.address ||
      current.marker !== owned.marker ||
      current.enabled !== owned.enabled ||
      current.oneShot !== owned.oneShot
    ) {
      return { status: "identity-mismatch", breakpoint: owned, observed: { ...current } };
    }
    this.managedBreakpoints.splice(index, 1);
    this.actions.push({ kind: "delete", id: owned.id, address: owned.address, marker: owned.marker });
    return { status: "deleted", breakpoint: owned };
  }

  disassemble(address: bigint, _maxInstructions: number): AdapterResult<LiveDisassembly> {
    const raw = this.frame.disassembly[`0x${address.toString(16).padStart(8, "0")}`];
    if (!raw) return fail("disassembly-unavailable", `No replay disassembly at 0x${address.toString(16)}.`);
    return ok({ address, bytes: parseBytes(raw.bytes), instructions: [...raw.instructions] });
  }

  getFingerprint(_scope: FingerprintScope): AdapterResult<TargetFingerprint> {
    const raw = this.frame.fingerprint;
    return ok({
      processId: parseHex(raw.processId),
      threadId: parseHex(raw.threadId),
      architecture: raw.architecture,
      pointerSize: raw.pointerSize,
      targetPath: raw.targetPath,
      targetSha256: raw.targetSha256,
      complete: raw.complete,
      incompleteReasons: raw.complete ? [] : ["fixture fingerprint incomplete"],
      modules: [],
      gadgets: [],
      protections: [],
    });
  }

  queryProtection(address: bigint): AdapterResult<MemoryProtectionRegion> {
    for (const raw of Object.values(this.frame.protections)) {
      const base = parseHex(raw.base);
      const size = parseHex(raw.size);
      if (address >= base && address < base + size) {
        return ok({ ...raw, base, size });
      }
    }
    return fail("protection-unavailable", `No replay protection at 0x${address.toString(16)}.`);
  }
}
