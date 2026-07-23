import { getPointerSize } from "../core/memory";
import { scanPattern } from "../core/scan_engine";
import { knownPatternsForPointerSize } from "../logic/instruction_validation";
import { applyFilters, badcharAddressFilter } from "../logic/pointer_filter_logic";
import { findModuleByAddress } from "../commands/modules";
import { LiveGadgetHit } from "../semantics/live-provider";

// Host-facing live gadget discovery: scans executable memory for the curated
// known-pattern set, rejects any address containing a bad character, and returns
// decoded gadget hits ready for the semantic pipeline. No target mutation — reads
// only.

export interface LiveDiscoveryOptions {
  module?: string;
  badchars?: number[];
  maxPerPattern?: number;
}

export interface LiveDiscoveryResult {
  hits: LiveGadgetHit[];
  warnings: string[];
  stats: Record<string, number>;
}

export function discoverLiveGadgets(options: LiveDiscoveryOptions = {}): LiveDiscoveryResult {
  const pointerSize = getPointerSize();
  const patterns = knownPatternsForPointerSize(pointerSize);
  const filter = badcharAddressFilter(options.badchars ?? [], pointerSize);
  const maxPerPattern = options.maxPerPattern ?? 5;

  const hits: LiveGadgetHit[] = [];
  const warningSet = new Set<string>();
  let scanned = 0;
  let rejected = 0;

  for (const pattern of patterns) {
    const scan = scanPattern(
      {
        module: options.module,
        executableOnly: true,
        maxResults: Math.min(maxPerPattern * 4, 200),
        chunkSize: 0x4000,
      },
      Uint8Array.from(pattern.bytes),
    );
    scanned += scan.hits.length;
    for (const warning of scan.warnings) {
      warningSet.add(`${warning.region}: ${warning.message}`);
    }

    const outcome = applyFilters(scan.hits, [filter]);
    rejected += outcome.rejected.length;
    for (const address of outcome.kept.slice(0, maxPerPattern)) {
      hits.push({ mnemonic: pattern.mnemonic, address, module: findModuleByAddress(address)?.name });
    }
  }

  return {
    hits,
    warnings: [...warningSet],
    stats: { patterns: patterns.length, scanned, rejected, discovered: hits.length },
  };
}
