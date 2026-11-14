/** Read-only API-address resolution analysis.  This deliberately stops before
 * gadget selection: a byte-safe address relationship is not a ROP chain. */

export type ApiPlanStrategy = "direct-slot" | "derived-address";
export type ApiPlanState = "DISCOVERED" | "ADDRESS_VALIDATED" | "ENCODABLE";

export interface ApiPlanTarget {
  module: string;
  symbol: string;
  address: bigint;
  exportRva: number;
}

export interface ApiPlanImport {
  ownerModule: string;
  ownerBase: bigint;
  ownerImageBase: bigint;
  slot: bigint;
  pointer: bigint;
  actualModule?: string;
  actualModuleBase?: bigint;
  importedSymbol: string;
  nearestSymbol?: string;
  nearestOffset?: bigint;
}

export interface ApiPlanCandidate {
  strategy: ApiPlanStrategy;
  state: ApiPlanState;
  target: ApiPlanTarget;
  anchor?: { symbol: string; pointer: bigint; delta: bigint };
  ownerModule: string;
  ownerBase: bigint;
  ownerImageBase: bigint;
  slot: bigint;
  pointer: bigint;
  slotPayloadSafe: boolean;
  pointerResolved: boolean;
  targetModuleVerified: boolean;
  exportRvaVerified: boolean;
  recommendation: string;
}

export function dwordIsByteSafe(value: bigint, badchars: readonly number[]): boolean {
  const bad = new Set(badchars.map((byte) => byte & 0xff));
  const word = Number(value & BigInt(0xffffffff)) >>> 0;
  for (let shift = 0; shift < 32; shift += 8) {
    if (bad.has((word >>> shift) & 0xff)) return false;
  }
  return true;
}

function sameModule(left: string | undefined, right: string): boolean {
  const normalize = (name: string) => name.toLowerCase().replace(/\.dll$/, "");
  return left !== undefined && normalize(left) === normalize(right);
}

/**
 * Classify observed IAT entries.  The caller is responsible for collecting the
 * observation from one stopped debugger snapshot.
 */
export function planApiResolution(
  target: ApiPlanTarget,
  imports: readonly ApiPlanImport[],
  badchars: readonly number[] = [],
): ApiPlanCandidate[] {
  const candidates: ApiPlanCandidate[] = [];
  for (const entry of imports) {
    const pointerResolved = entry.pointer !== BigInt(0);
    const targetModuleVerified = sameModule(entry.actualModule, target.module)
      && entry.actualModuleBase !== undefined;
    const exactExport = entry.pointer === target.address;
    const slotPayloadSafe = dwordIsByteSafe(entry.slot, badchars);
    const base = {
      target,
      ownerModule: entry.ownerModule,
      ownerBase: entry.ownerBase,
      ownerImageBase: entry.ownerImageBase,
      slot: entry.slot,
      pointer: entry.pointer,
      slotPayloadSafe,
      pointerResolved,
      targetModuleVerified,
    };

    if (entry.importedSymbol.toLowerCase() === target.symbol.toLowerCase()) {
      const exportRvaVerified = targetModuleVerified && exactExport;
      candidates.push({
        ...base,
        strategy: "direct-slot",
        state: exportRvaVerified && slotPayloadSafe ? "ENCODABLE" : exportRvaVerified ? "ADDRESS_VALIDATED" : "DISCOVERED",
        exportRvaVerified,
        recommendation: slotPayloadSafe
          ? "Use rop.slot_call subject to corpus feasibility."
          : "Direct slot is validated but cannot be embedded; requires address construction.",
      });
      continue;
    }

    // An arithmetic anchor must be an exact export entry in the same observed
    // image, never merely a nearby symbol or an import-DLL name match.
    const anchorExact = entry.nearestOffset === BigInt(0) && !!entry.nearestSymbol;
    if (!targetModuleVerified || !anchorExact || !pointerResolved) continue;
    const delta = (target.address - entry.pointer) & BigInt(0xffffffff);
    candidates.push({
      ...base,
      strategy: "derived-address",
      state: slotPayloadSafe ? "ENCODABLE" : "ADDRESS_VALIDATED",
      exportRvaVerified: true,
      anchor: { symbol: entry.nearestSymbol!, pointer: entry.pointer, delta },
      recommendation: slotPayloadSafe
        ? "Candidate for gadget feasibility analysis; no chain has been constructed."
        : "Anchor is validated but its slot requires address construction before gadget feasibility analysis.",
    });
  }

  return candidates.sort((left, right) => {
    const strategy = left.strategy === right.strategy ? 0 : left.strategy === "direct-slot" ? -1 : 1;
    if (strategy !== 0) return strategy;
    if (left.slotPayloadSafe !== right.slotPayloadSafe) return left.slotPayloadSafe ? -1 : 1;
    return Number(left.slot - right.slot);
  });
}
