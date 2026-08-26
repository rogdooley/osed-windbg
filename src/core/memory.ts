import { formatAddress } from "./output";

export function readMemory(address: bigint, length: number): Uint8Array {
  const attempts: (number | bigint)[] = [address];

  if (address >= BigInt(0) && address <= BigInt(Number.MAX_SAFE_INTEGER)) {
    attempts.push(Number(address));
  }

  let lastError: unknown;
  for (const attempt of attempts) {
    try {
      const values = host.memory.readMemoryValues(attempt, length, 1, false);
      return Uint8Array.from(values.map((value) => value & 0xff));
    } catch (error) {
      lastError = error;
    }
  }

  const suffix = lastError instanceof Error && lastError.message ? ` (${lastError.message})` : "";
  throw new Error(`Memory read failed at ${formatAddress(address, getPointerSize())}${suffix}.`);
}

export function tryReadMemory(address: bigint, length: number): Uint8Array | undefined {
  try {
    return readMemory(address, length);
  } catch (_error) {
    return undefined;
  }
}

export function readUint16LE(address: bigint): number {
  const bytes = readMemory(address, 2);
  return bytes[0] | (bytes[1] << 8);
}

export function readUint32LE(address: bigint): number {
  const bytes = readMemory(address, 4);
  return (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0;
}

export function readUint64LE(address: bigint): bigint {
  const bytes = readMemory(address, 8);
  let result = BigInt(0);
  for (let i = 0; i < 8; i += 1) {
    result |= BigInt(bytes[i]) << BigInt(i * 8);
  }
  return result;
}

export function readPointer(address: bigint, pointerSize: 4 | 8): bigint {
  return pointerSize === 8 ? readUint64LE(address) : BigInt(readUint32LE(address));
}

export function executeDebuggerCommand(command: string): string[] {
  const hostAny = host as unknown as {
    namespace?: {
      Debugger?: {
        Utility?: {
          Control?: {
            ExecuteCommand?: (input: string) => unknown;
          };
        };
      };
    };
  };

  const exec = hostAny.namespace?.Debugger?.Utility?.Control?.ExecuteCommand;
  if (typeof exec !== "function") {
    throw new Error("WinDbg command execution is unavailable in this host.");
  }

  const control = hostAny.namespace?.Debugger?.Utility?.Control;
  const result = exec.call(control, command);
  if (Array.isArray(result)) {
    return result.map((line) => String(line));
  }
  if (result && typeof (result as { [Symbol.iterator]?: unknown })[Symbol.iterator] === "function") {
    try {
      return Array.from(result as Iterable<unknown>).map((line) => String(line));
    } catch (_error) {
      return [];
    }
  }
  return [];
}

export function parseProtectFromVprot(lines: string[]): number | undefined {
  for (const line of lines) {
    const match = line.match(/^\s*Protect:\s+([0-9a-f`]+)\s+/i);
    if (match) {
      return Number(BigInt(`0x${match[1].replace(/`/g, "")}`) & BigInt(0xffffffff));
    }
  }
  return undefined;
}

export function decodeProtectValue(value: number): { name: string; executable: boolean; writable: boolean } {
  const protect = value & 0xff;
  switch (protect) {
    case 0x01:
      return { name: "PAGE_NOACCESS", executable: false, writable: false };
    case 0x02:
      return { name: "PAGE_READONLY", executable: false, writable: false };
    case 0x04:
      return { name: "PAGE_READWRITE", executable: false, writable: true };
    case 0x08:
      return { name: "PAGE_WRITECOPY", executable: false, writable: true };
    case 0x10:
      return { name: "PAGE_EXECUTE", executable: true, writable: false };
    case 0x20:
      return { name: "PAGE_EXECUTE_READ", executable: true, writable: false };
    case 0x40:
      return { name: "PAGE_EXECUTE_READWRITE", executable: true, writable: true };
    case 0x80:
      return { name: "PAGE_EXECUTE_WRITECOPY", executable: true, writable: true };
    default:
      return { name: `0x${protect.toString(16).toUpperCase().padStart(2, "0")}`, executable: false, writable: false };
  }
}

export type StackProtection = {
  protect: number;
  name: string;
  executable: boolean;
  writable: boolean;
  depEnforced: boolean;
};

export function queryStackProtection(sp: bigint, pointerSize: 4 | 8): StackProtection | undefined {
  try {
    const output = executeDebuggerCommand(`!vprot ${formatAddress(sp, pointerSize)}`);
    const protect = parseProtectFromVprot(output);
    if (protect === undefined) return undefined;
    const decoded = decodeProtectValue(protect);
    return {
      protect,
      ...decoded,
      depEnforced: !decoded.executable,
    };
  } catch (_error) {
    return undefined;
  }
}

export function getPointerSize(): 4 | 8 {
  const process = host.currentProcess as unknown as { Is64Bit?: boolean; Machine?: string };
  const machine = (process?.Machine ?? "").toLowerCase();
  if (process?.Is64Bit || machine.includes("x64") || machine.includes("amd64")) {
    return 8;
  }
  return 4;
}
