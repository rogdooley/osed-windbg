import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readUint16LE, readUint32LE } from "../core/memory";

type TriState = "enabled" | "disabled" | "unknown";

export type ModuleMitigation = {
  name: string;
  path: string;
  base: bigint;
  size: bigint;
  characteristics: number;
  dllCharacteristics: number;
  aslr: TriState;
  dep: TriState;
  safeseh: TriState;
  system: boolean;
};

const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100;

function parseBigIntString(value: string): bigint {
  const text = value.trim();
  if (/^0x[0-9a-fA-F]+$/.test(text)) {
    return BigInt(text);
  }
  if (/^[0-9a-fA-F]+$/.test(text)) {
    return BigInt(`0x${text}`);
  }
  if (/^[0-9]+$/.test(text)) {
    return BigInt(text);
  }
  return BigInt(0);
}

function toBigInt(value: unknown): bigint {
  if (typeof value === "bigint") {
    return value;
  }

  if (typeof value === "number") {
    return BigInt(Math.max(0, Math.trunc(value)));
  }

  if (typeof value === "string") {
    return parseBigIntString(value);
  }

  if (value && typeof value === "object") {
    const valueOf = (value as { valueOf?: () => unknown }).valueOf;
    if (typeof valueOf === "function") {
      const resolved = valueOf.call(value);
      if (resolved !== value) {
        const parsed = toBigInt(resolved);
        if (parsed !== BigInt(0)) {
          return parsed;
        }
      }
    }

    const asString = (value as { toString?: () => string }).toString;
    if (typeof asString === "function") {
      return parseBigIntString(asString.call(value));
    }
  }

  return BigInt(0);
}

function asArray(value: unknown): unknown[] {
  if (Array.isArray(value)) {
    return value;
  }

  if (value && typeof (value as { [Symbol.iterator]?: unknown })[Symbol.iterator] === "function") {
    try {
      return Array.from(value as Iterable<unknown>);
    } catch (_error) {
      return [];
    }
  }

  return [];
}

function parseSafeSeh(base: bigint, pe: bigint, optionalHeaderMagic: number): TriState {
  if (optionalHeaderMagic !== 0x10b) {
    return "unknown";
  }

  try {
    const optionalHeaderOffset = pe + BigInt(0x18);
    const dataDirectoryOffset = optionalHeaderOffset + BigInt(0x60);
    const loadConfigRva = readUint32LE(dataDirectoryOffset + BigInt(8 * 10));
    const loadConfigSize = readUint32LE(dataDirectoryOffset + BigInt(8 * 10 + 4));

    if (loadConfigRva === 0 || loadConfigSize === 0) {
      return "unknown";
    }

    const loadConfig = base + BigInt(loadConfigRva);
    const sehTable = readUint32LE(loadConfig + BigInt(0x40));
    const sehCount = readUint32LE(loadConfig + BigInt(0x44));

    if (sehTable !== 0 && sehCount > 0) {
      return "enabled";
    }

    return "disabled";
  } catch (_error) {
    return "unknown";
  }
}

export function listModulesWithMitigations(filter?: string): ModuleMitigation[] {
  const process = host.currentProcess as unknown as { Modules?: unknown };
  const modules = asArray(process?.Modules);

  const listed = modules
    .map((entry) => {
      const module = entry as {
        Name?: string;
        Path?: string;
        BaseAddress?: number | bigint;
        Base?: number | bigint | string;
        Address?: number | bigint | string;
        Size?: number | bigint;
        Length?: number | bigint | string;
        EndAddress?: number | bigint | string;
      };

      const name = module.Name ?? "<unknown>";
      const path = module.Path ?? name;
      const base = toBigInt(module.BaseAddress ?? module.Base ?? module.Address);
      let size = toBigInt(module.Size ?? module.Length);
      const end = toBigInt(module.EndAddress);
      if (size === BigInt(0) && end > base) {
        size = end - base;
      }

      let characteristics = 0;
      let dllCharacteristics = 0;
      let aslr: TriState = "unknown";
      let dep: TriState = "unknown";
      let safeseh: TriState = "unknown";

      try {
        const mz = readUint16LE(base);
        if (mz === 0x5a4d) {
          const peOffset = readUint32LE(base + BigInt(0x3c));
          const pe = base + BigInt(peOffset);
          const sig = readUint32LE(pe);
          if (sig === 0x4550) {
            characteristics = readUint16LE(pe + BigInt(0x16));
            const optionalHeaderMagic = readUint16LE(pe + BigInt(0x18));
            dllCharacteristics = readUint16LE(pe + BigInt(0x5e));

            aslr = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) !== 0 ? "enabled" : "disabled";
            dep = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) !== 0 ? "enabled" : "disabled";
            safeseh = parseSafeSeh(base, pe, optionalHeaderMagic);
          }
        }
      } catch (_error) {
        // Keep unknown tri-state when header parsing fails.
      }

      const system = path.toLowerCase().includes("\\windows\\system32");

      return {
        name,
        path,
        base,
        size,
        characteristics,
        dllCharacteristics,
        aslr,
        dep,
        safeseh,
        system,
      };
    })
    .filter((item) => {
      if (!filter) {
        return true;
      }
      const needle = filter.toLowerCase();
      return item.name.toLowerCase().includes(needle) || item.path.toLowerCase().includes(needle);
    })
    .sort((a, b) => (a.base < b.base ? -1 : 1));

  return listed;
}

export function findModuleByAddress(address: bigint): ModuleMitigation | undefined {
  return listModulesWithMitigations().find((module) => {
    const start = module.base;
    const end = module.base + module.size;
    return address >= start && address < end;
  });
}

export function createModulesCommand(): Command {
  return {
    name: "modules",
    description: "Enumerate modules and mitigation states.",
    usage: "dx @$osed.modules({ filter: 'essfunc' })",
    examples: ["dx @$osed.modules({})", "dx @$osed.modules({ filter: 'kernel32' })"],
    schema: {
      filter: { type: "string" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const modules = listModulesWithMitigations(options.filter as string | undefined);
      const pointerSize = getPointerSize();

      out.section("Modules");
      out.table(
        [
          { key: "name", header: "Module", width: 20 },
          { key: "base", header: "Base", width: 18 },
          { key: "size", header: "Size", width: 10 },
          { key: "aslr", header: "ASLR", width: 8 },
          { key: "dep", header: "DEP", width: 8 },
          { key: "safeseh", header: "SafeSEH", width: 8 },
          { key: "system", header: "System", width: 8 },
        ],
        modules.map((module) => ({
          name: module.name,
          base: out.formatAddress(module.base, pointerSize),
          size: `0x${module.size.toString(16).toUpperCase()}`,
          aslr: module.aslr,
          dep: module.dep,
          safeseh: module.safeseh,
          system: module.system ? "yes" : "no",
        })),
      );

      out.whyItMatters("Mitigation triage identifies practical modules for reliable exploitation paths.");

      return {
        command: "modules",
        args: options,
        success: true,
        findings: modules,
        warnings: [],
        errors: [],
      };
    },
  };
}
