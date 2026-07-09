import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readPointer } from "../core/memory";
import { findModuleByAddress } from "./modules";

function safeGet(objectValue: unknown, key: string): unknown {
  if (!objectValue || typeof objectValue !== "object") {
    return undefined;
  }
  try {
    return (objectValue as Record<string, unknown>)[key];
  } catch (_error) {
    return undefined;
  }
}

function safeKeys(objectValue: unknown): string[] {
  if (!objectValue || typeof objectValue !== "object") {
    return [];
  }
  try {
    return Object.keys(objectValue as Record<string, unknown>);
  } catch (_error) {
    return [];
  }
}

function toAddress(value: unknown): bigint {
  if (typeof value === "bigint") {
    return value;
  }

  if (typeof value === "number") {
    return BigInt(Math.max(0, Math.trunc(value)));
  }

  if (typeof value === "string") {
    const text = value.trim();
    const embeddedHex = text.match(/0x[0-9a-fA-F]+/);
    if (embeddedHex) {
      return BigInt(embeddedHex[0]);
    }
    if (/^[0-9a-fA-F]+$/.test(text)) {
      return BigInt(`0x${text}`);
    }
    if (/^[0-9]+$/.test(text)) {
      return BigInt(text);
    }
  }

  if (value && typeof value === "object") {
    const pointerFields = ["targetLocation", "address", "Address", "Value", "value"];
    for (const field of pointerFields) {
      const parsed = toAddress(safeGet(value, field));
      if (parsed !== BigInt(0)) {
        return parsed;
      }
    }

    try {
      const valueOfFn = safeGet(value, "valueOf");
      if (typeof valueOfFn === "function") {
        const resolved = (valueOfFn as () => unknown).call(value);
        if (resolved !== value) {
          const parsed = toAddress(resolved);
          if (parsed !== BigInt(0)) {
            return parsed;
          }
        }
      }
    } catch (_error) {
      // Fall through to toString parsing.
    }

    try {
      const toStringFn = safeGet(value, "toString");
      if (typeof toStringFn === "function") {
        const text = (toStringFn as () => string).call(value);
        const parsed = toAddress(text);
        if (parsed !== BigInt(0)) {
          return parsed;
        }
      }
    } catch (_error) {
      // Ignore and fall through.
    }
  }

  return BigInt(0);
}

function resolveTebAddress(): bigint {
  const thread = host.currentThread as Record<string, unknown>;

  const envTeb = resolveFromEnvironmentBlock(thread);
  if (envTeb !== BigInt(0)) {
    return envTeb;
  }

  const directCandidates: unknown[] = [
    safeGet(thread, "Teb"),
    safeGet(thread, "Teb32"),
    safeGet(thread, "TebAddress"),
    safeGet(thread, "Wow64Teb"),
    safeGet(thread, "Wow64Teb32"),
  ];

  for (const candidate of directCandidates) {
    const parsed = toAddress(candidate);
    if (parsed !== BigInt(0)) {
      return parsed;
    }
  }

  for (const key of safeKeys(thread)) {
    if (!/teb/i.test(key)) {
      continue;
    }
    const parsed = toAddress(safeGet(thread, key));
    if (parsed !== BigInt(0)) {
      return parsed;
    }
  }

  const candidates = collectAddressCandidates(thread, 0, 2);
  for (const candidate of candidates) {
    if (looksLikeTeb32(candidate)) {
      return candidate;
    }
  }

  return BigInt(0);
}

function resolveFromEnvironmentBlock(thread: Record<string, unknown>): bigint {
  const env = safeGet(thread, "Environment");
  const nativeEnv = safeGet(thread, "NativeEnvironment");
  const blocks = [safeGet(env, "EnvironmentBlock"), safeGet(nativeEnv, "EnvironmentBlock")];

  for (const block of blocks) {
    if (!block || typeof block !== "object") {
      continue;
    }

    const directSelf = toAddress(safeGet(block, "Self"));
    if (directSelf !== BigInt(0)) {
      return directSelf;
    }

    const ntTib = safeGet(block, "NtTib");
    const nestedSelf = toAddress(safeGet(ntTib, "Self"));
    if (nestedSelf !== BigInt(0)) {
      return nestedSelf;
    }

    const wowOffset = toSignedInteger(safeGet(block, "WowTebOffset"));
    const nativeSelf = toAddress(safeGet(ntTib, "Self"));
    if (nativeSelf !== BigInt(0) && wowOffset !== 0) {
      const derived = nativeSelf + BigInt(wowOffset);
      if (derived > BigInt(0)) {
        return derived;
      }
    }
  }

  return BigInt(0);
}

function toSignedInteger(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.trunc(value);
  }

  if (typeof value === "bigint") {
    return Number(value);
  }

  if (typeof value === "string") {
    const text = value.trim();
    if (/^-?[0-9]+$/.test(text)) {
      return parseInt(text, 10);
    }
  }

  if (value && typeof value === "object") {
    let valueOfResolved: unknown = undefined;
    try {
      const valueOf = (value as Record<string, unknown>).valueOf;
      if (typeof valueOf === "function") {
        valueOfResolved = valueOf.call(value);
      }
    } catch (_error) {
      valueOfResolved = undefined;
    }

    const parsed = toSignedInteger(valueOfResolved);
    if (parsed !== 0) {
      return parsed;
    }

    let text: unknown = undefined;
    try {
      const toStringFn = (value as Record<string, unknown>).toString;
      if (typeof toStringFn === "function") {
        text = toStringFn.call(value);
      }
    } catch (_error) {
      text = undefined;
    }

    if (typeof text === "string") {
      const match = text.match(/-?[0-9]+/);
      if (match) {
        return parseInt(match[0], 10);
      }
    }
  }

  return 0;
}

function collectAddressCandidates(value: unknown, depth: number, maxDepth: number): bigint[] {
  if (depth > maxDepth || value === null || value === undefined) {
    return [];
  }

  const found = new Set<bigint>();

  const direct = toAddress(value);
  if (direct !== BigInt(0)) {
    found.add(direct);
  }

  if (typeof value !== "object") {
    return [...found];
  }

  for (const key of safeKeys(value)) {
    const nested = collectAddressCandidates(safeGet(value, key), depth + 1, maxDepth);
    for (const entry of nested) {
      found.add(entry);
    }
  }

  return [...found];
}

function looksLikeTeb32(address: bigint): boolean {
  try {
    if (address < BigInt(0x1000)) {
      return false;
    }

    const self = readPointer(address + BigInt(0x18), 4);
    if (self !== address) {
      return false;
    }

    const exceptionList = readPointer(address, 4);
    if (exceptionList === BigInt(0) || exceptionList === BigInt(0xffffffff)) {
      return false;
    }

    return true;
  } catch (_error) {
    return false;
  }
}

export function createSehCommand(): Command {
  return {
    name: "seh",
    description: "Walk current thread SEH chain.",
    usage: "dx @$osed.seh({})",
    examples: ["dx @$osed.seh({})", "dx @$osed.seh({})"],
    schema: {},
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      if (pointerSize !== 4) {
        return {
          command: "seh",
          args: options,
          success: false,
          findings: [],
          warnings: ["SEH chain walking is x86-focused in v1."],
          errors: ["Current pointer size is not x86."],
        };
      }

      const teb = resolveTebAddress();
      if (teb === BigInt(0)) {
        throw new Error("Current thread TEB is unavailable.");
      }

      const rows: Array<Record<string, string>> = [];
      const findings: unknown[] = [];

      let node = readPointer(teb, 4);
      let guard = 0;

      while (node !== BigInt(0xffffffff) && guard < 64) {
        const next = readPointer(node, 4);
        const handler = readPointer(node + BigInt(4), 4);
        const module = findModuleByAddress(handler);

        const safeSehRisk = module && module.safeseh !== "enabled" ? "risk" : "ok";
        const outsideModule = module === undefined;

        rows.push({
          node: out.formatAddress(node, 4),
          handler: out.formatAddress(handler, 4),
          target: module ? `${module.name}+0x${(handler - module.base).toString(16).toUpperCase()}` : "<outside module>",
          safeseh: module ? module.safeseh : "unknown",
          status: outsideModule || safeSehRisk === "risk" ? "flag" : "ok",
        });

        findings.push({
          node,
          next,
          handler,
          module: module?.name,
          outsideModule,
          safeSeh: module?.safeseh ?? "unknown",
        });

        node = next;
        guard += 1;
      }

      out.section("SEH Chain");
      out.table(
        [
          { key: "node", header: "Node", width: 10 },
          { key: "handler", header: "Handler", width: 10 },
          { key: "target", header: "Module+Offset", width: 24 },
          { key: "safeseh", header: "SafeSEH", width: 8 },
          { key: "status", header: "Status", width: 6 },
        ],
        rows,
      );
      out.whyItMatters("SEH handler control is a classic exploit path when stack overwrite is constrained.");

      return {
        command: "seh",
        args: options,
        success: true,
        findings,
        warnings: guard >= 64 ? ["SEH walk stopped at guard limit (64 entries)."] : [],
        errors: [],
      };
    },
  };
}
