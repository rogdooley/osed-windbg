import { getPointerSize } from "../core/memory";
import { scanPattern } from "../core/scan_engine";
import { scanBackward } from "../core/backward_scanner";
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
  const maxPerPattern = options.maxPerPattern ?? 40;
  // Scan far deeper than we keep: most low-address hits are rejected by the
  // badchar filter (their address holds a null/bad byte), and clean gadgets in
  // preferred-base modules often live deep in .text. Scanning only a few
  // candidates left the corpus with just the first survivors — frequently none
  // clean-and-stable — so the solver fell back to dirtier gadgets.
  const scanDepth = Math.min(Math.max(maxPerPattern * 20, 1500), 4000);

  const hits: LiveGadgetHit[] = [];
  const warningSet = new Set<string>();
  let scanned = 0;
  let rejected = 0;

  for (const pattern of patterns) {
    const scan = scanPattern(
      {
        module: options.module,
        executableOnly: true,
        maxResults: scanDepth,
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

  const seenAddresses = new Set(hits.map((h) => h.address.toString()));
  const backward = scanBackward({
    module: options.module,
    maxResults: 10000,
    maxInstructionsPerGadget: 3,
    maxBackwardBytes: 12,
  });
  for (const w of backward.warnings) warningSet.add(w);
  let backwardAdded = 0;
  for (const gadget of backward.gadgets) {
    const key = gadget.address.toString();
    if (seenAddresses.has(key)) continue;
    seenAddresses.add(key);
    const outcome = applyFilters([gadget.address], [filter]);
    if (outcome.kept.length === 0) {
      rejected++;
      continue;
    }
    hits.push({ mnemonic: gadget.mnemonic, address: gadget.address, module: findModuleByAddress(gadget.address)?.name });
    backwardAdded++;
  }

  return {
    hits,
    warnings: [...warningSet],
    stats: {
      patterns: patterns.length,
      scanned,
      rejected,
      discovered: hits.length,
      backwardTerminators: backward.stats.terminatorsFound ?? 0,
      backwardGadgets: backwardAdded,
    },
  };
}
