import { memoryRegion } from "../../analysis/memory";
import { decodeProtectValue, executeDebuggerCommand, readMemory } from "../../core/memory";
import type { ProofDebuggerAdapter } from "./adapter";
import { Sha256 } from "./fingerprint";
import type {
  AdapterResult,
  BreakpointSnapshot,
  DeleteOwnedResult,
  FingerprintModule,
  FingerprintScope,
  LiveDisassembly,
  MemoryProtectionRegion,
  OwnedBreakpoint,
  ProofRegisterSnapshot,
  TargetFingerprint,
} from "./types";

declare const host: unknown;

function ok<T>(value: T): AdapterResult<T> { return { ok: true, value }; }
function fail<T>(code: string, message: string): AdapterResult<T> { return { ok: false, error: { code, message } }; }

function bigintValue(value: unknown): bigint | undefined {
  try {
    if (typeof value === "bigint") return value;
    if (typeof value === "number") return BigInt(value);
    if (typeof value === "string") return BigInt(value.replace(/`/g, ""));
    if (value && typeof value === "object") {
      const record = value as Record<string, unknown>;
      return bigintValue(record.value ?? record.Value ?? String(value));
    }
  } catch { /* structured failure at caller */ }
  return undefined;
}

export function isAllowedProofCommand(command: string): boolean {
  const trimmed = command.trim();
  return trimmed === "bl"
    || /^r(?:\s+@[a-z][a-z0-9]*)+$/i.test(trimmed)
    || /^u\s+0x[0-9a-f]+\s+L[1-9][0-9]*$/i.test(trimmed)
    || /^!vprot\s+0x[0-9a-f]+$/i.test(trimmed)
    || /^bp\s+\/1\s+0x[0-9a-f]+\s+"\.echo\s+osed-proof:v1:[A-Za-z0-9-]+:[A-Za-z0-9-]+:\d+"$/i.test(trimmed)
    || /^bc\s+\d+$/i.test(trimmed);
}

function command(commandText: string): string[] {
  if (!isAllowedProofCommand(commandText)) throw new Error(`Proof adapter rejected debugger command: ${commandText}`);
  return executeDebuggerCommand(commandText);
}

function iterable(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  try { return value ? Array.from(value as Iterable<unknown>) : []; } catch { return []; }
}

function parseBreakpoint(line: string): BreakpointSnapshot | undefined {
  const marker = /(osed-proof:v[^\s";]+)/i.exec(line)?.[1];
  const match = /^\s*(\d+)\s+\w+\s+([0-9a-f`]+)/i.exec(line);
  if (!match || !marker) return undefined;
  return {
    id: Number(match[1]),
    address: BigInt(`0x${match[2].replace(/`/g, "")}`),
    enabled: !/^\s*\d+\s+d/i.test(line),
    oneShot: /\/1|one.?shot/i.test(line) || marker.startsWith("osed-proof:"),
    marker,
    command: line,
  };
}

function hashFile(path: string): string | undefined {
  try {
    const hostAny = host as { namespace?: { Debugger?: { Utility?: { FileSystem?: Record<string, unknown> } } } };
    const fs = hostAny.namespace?.Debugger?.Utility?.FileSystem as {
      OpenFile?: (path: string) => unknown;
      CreateFile?: (path: string, disposition: string) => unknown;
    } | undefined;
    const raw = fs?.OpenFile?.(path) ?? fs?.CreateFile?.(path, "OpenExisting");
    if (!raw) return undefined;
    const file = raw as { ReadBytes?: (count: number) => unknown; Close?: () => void };
    if (typeof file.ReadBytes !== "function") return undefined;
    const digest = new Sha256();
    for (;;) {
      const chunk = Uint8Array.from(iterable(file.ReadBytes(64 * 1024)).map(Number));
      if (chunk.length === 0) break;
      digest.update(chunk);
      if (chunk.length < 64 * 1024) break;
    }
    file.Close?.();
    return digest.digestHex();
  } catch {
    return undefined;
  }
}

export class WinDbgProofAdapter implements ProofDebuggerAdapter {
  readRegisters(): ProofRegisterSnapshot {
    const hostAny = host as { currentThread?: Record<string, unknown> };
    const thread = hostAny.currentThread ?? {};
    const registers = ((thread.Registers as Record<string, unknown> | undefined)?.User ?? {}) as Record<string, unknown>;
    const parsed: Record<string, bigint> = {};
    for (const name of ["eip", "esp", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"]) {
      const value = bigintValue(registers[name] ?? registers[name.toUpperCase()]);
      if (value !== undefined) parsed[name] = BigInt.asUintN(32, value);
    }
    if (parsed.eip === undefined || parsed.esp === undefined) throw new Error("Unable to read x86 EIP/ESP from the current thread.");
    return { eip: parsed.eip, esp: parsed.esp, registers: parsed };
  }

  readMemory(address: bigint, length: number): AdapterResult<Uint8Array> {
    try { return ok(readMemory(address, length)); }
    catch (error) { return fail("memory-unreadable", error instanceof Error ? error.message : String(error)); }
  }

  listBreakpoints(): AdapterResult<BreakpointSnapshot[]> {
    try { return ok(command("bl").map(parseBreakpoint).filter((entry): entry is BreakpointSnapshot => entry !== undefined)); }
    catch (error) { return fail("breakpoint-list-failed", error instanceof Error ? error.message : String(error)); }
  }

  setOneShot(address: bigint, marker: string): AdapterResult<OwnedBreakpoint> {
    if (!/^osed-proof:v1:[A-Za-z0-9-]+:[A-Za-z0-9-]+:\d+$/.test(marker)) return fail("invalid-marker", "Invalid proof breakpoint marker.");
    try {
      command(`bp /1 0x${address.toString(16)} ".echo ${marker}"`);
      const listed = this.listBreakpoints();
      if (!listed.ok) return listed;
      const found = listed.value.find((entry) => entry.address === address && entry.marker === marker);
      return found ? ok({ id: found.id, address, enabled: found.enabled, oneShot: found.oneShot, marker })
        : fail("breakpoint-unconfirmed", "WinDbg did not report the newly created proof breakpoint.");
    } catch (error) {
      return fail("breakpoint-set-failed", error instanceof Error ? error.message : String(error));
    }
  }

  deleteOwned(breakpoint: OwnedBreakpoint): DeleteOwnedResult {
    const listed = this.listBreakpoints();
    if (!listed.ok) return { status: "not-found", breakpoint };
    const observed = listed.value.find((entry) => entry.id === breakpoint.id);
    if (!observed) return this.readRegisters().eip === breakpoint.address
      ? { status: "already-fired", breakpoint }
      : { status: "not-found", breakpoint };
    if (observed.address !== breakpoint.address || observed.marker !== breakpoint.marker ||
      observed.enabled !== breakpoint.enabled || observed.oneShot !== breakpoint.oneShot) {
      return { status: "identity-mismatch", breakpoint, observed };
    }
    command(`bc ${breakpoint.id}`);
    return { status: "deleted", breakpoint };
  }

  disassemble(address: bigint, maxInstructions: number): AdapterResult<LiveDisassembly> {
    try {
      const lines = command(`u 0x${address.toString(16)} L${Math.max(1, Math.floor(maxInstructions))}`);
      const instructions = lines.map((line) => /^\s*[0-9a-f`]+\s+[0-9a-f]+\s+(.+)$/i.exec(line)?.[1]?.trim()).filter((line): line is string => Boolean(line));
      const bytes = readMemory(address, Math.max(1, Math.min(16, maxInstructions * 4)));
      return ok({ address, bytes, instructions });
    } catch (error) { return fail("disassembly-unavailable", error instanceof Error ? error.message : String(error)); }
  }

  getFingerprint(scope: FingerprintScope): AdapterResult<TargetFingerprint> {
    try {
      const hostAny = host as { currentProcess?: Record<string, unknown>; currentThread?: Record<string, unknown> };
      const process = hostAny.currentProcess ?? {};
      const thread = hostAny.currentThread ?? {};
      const rawModules = iterable(process.Modules);
      const allModules: FingerprintModule[] = rawModules.map((item) => {
        const module = item as Record<string, unknown>;
        const base = bigintValue(module.BaseAddress) ?? BigInt(0);
        const end = bigintValue(module.EndAddress) ?? base;
        return {
          name: String(module.Name ?? ""), path: String(module.Path ?? module.Name ?? ""), base,
          preferredBase: bigintValue(module.PreferredBaseAddress) ?? base, size: end - base,
          timestamp: module.TimeDateStamp === undefined ? undefined : Number(module.TimeDateStamp),
          checksum: module.CheckSum === undefined ? undefined : Number(module.CheckSum),
        };
      });
      const target = scope.targetPath
        ? allModules.find((module) => module.path.toLowerCase() === scope.targetPath!.toLowerCase())
        : allModules[0];
      const selectedNames = new Set(scope.moduleNames.map((name) => name.toLowerCase()));
      const modules = allModules.filter((module) => module === target || selectedNames.has(module.name.toLowerCase()));
      const incompleteReasons: string[] = [];
      const targetSha256 = target?.path ? hashFile(target.path) : undefined;
      if (!target) incompleteReasons.push("target executable identity is unavailable");
      if (!targetSha256) incompleteReasons.push("target executable could not be read for SHA-256");
      const gadgets = scope.gadgetAddresses.flatMap((address) => {
        const module = allModules.find((entry) => address >= entry.base && address < entry.base + entry.size);
        const read = this.readMemory(address, 16);
        if (!read.ok) { incompleteReasons.push(read.error.message); return []; }
        return [{ address, module: module?.name ?? "", rva: module ? address - module.base : address, bytes: read.value, instructions: [] }];
      });
      const protections = scope.protectionAddresses.flatMap((address) => {
        const result = this.queryProtection(address);
        if (!result.ok) { incompleteReasons.push(result.error.message); return []; }
        return [{ address, region: result.value }];
      });
      const is64 = process.Is64Bit === true || String(process.Machine ?? "").toLowerCase().includes("64");
      return ok({
        processId: bigintValue(process.Id ?? process.ProcessId) ?? BigInt(0),
        threadId: bigintValue(thread.Id ?? thread.ThreadId) ?? BigInt(0),
        architecture: is64 ? "x64" : "x86",
        pointerSize: is64 ? 8 : 4,
        targetPath: target?.path ?? scope.targetPath ?? "",
        targetSha256,
        complete: incompleteReasons.length === 0,
        incompleteReasons,
        modules,
        gadgets,
        protections,
      });
    } catch (error) { return fail("fingerprint-failed", error instanceof Error ? error.message : String(error)); }
  }

  queryProtection(address: bigint): AdapterResult<MemoryProtectionRegion> {
    const evidence = memoryRegion(address);
    if (evidence.baseAddress === undefined || evidence.regionSize === undefined || evidence.raw.protection === undefined) {
      return fail("protection-unavailable", evidence.warnings.join("; ") || "Memory protection is unavailable.");
    }
    const decoded = decodeProtectValue(evidence.raw.protection);
    return ok({ base: evidence.baseAddress, size: evidence.regionSize, protect: evidence.raw.protection, ...decoded });
  }
}
