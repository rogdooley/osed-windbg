import { CapabilityIndex } from "./capabilities";
import { ExploitStrategy, RopStrategyPlan, StrategyPlan } from "./planner";
import { CapabilityKind, RopGadget } from "./types";

export interface EmittedGadget {
  capability: CapabilityKind;
  canonicalId: string;
  address: bigint;
  module: string;
  sequence: string;
  score: number;
  stackDelta?: number;
  sideEffects: number;
}

export interface EmissionResult {
  planId: number;
  strategy: ExploitStrategy;
  strategyId: number;
  shape: StrategyPlan["shape"];
  success: boolean;
  gadgets: EmittedGadget[];
  missing: CapabilityKind[];
  diagnostics: string[];
}

export interface RopEmitter {
  emit(index: CapabilityIndex, plan: RopStrategyPlan, strategyId?: number): EmissionResult;
}

function knownAddress(gadget: RopGadget): { address: bigint; module: string } | undefined {
  const location = gadget.locations.find((candidate) => candidate.virtualAddress !== undefined);
  return location?.virtualAddress === undefined
    ? undefined
    : { address: BigInt(location.virtualAddress), module: location.module ?? "unknown" };
}

function exactStackDelta(gadget: RopGadget): number | undefined {
  const values = [...gadget.semanticSummary.summary.stackDelta.values.exact];
  return values.length === 1 ? values[0] : undefined;
}

function sideEffectCount(gadget: RopGadget): number {
  const summary = gadget.semanticSummary.summary;
  return summary.writes.values.exact.size
    + summary.writes.values.conservative.size
    + summary.memoryReads.values.exact.size
    + summary.memoryReads.values.conservative.size
    + (summary.memoryWrites.values.exact.size + summary.memoryWrites.values.conservative.size) * 2;
}

function rankCandidates(gadgets: RopGadget[]): RopGadget[] {
  return gadgets
    .filter((gadget) => knownAddress(gadget) !== undefined)
    .sort((left, right) => {
      const sideEffectDifference = sideEffectCount(left) - sideEffectCount(right);
      if (sideEffectDifference !== 0) return sideEffectDifference;
      const stackDifference = (exactStackDelta(left) ?? Number.MAX_SAFE_INTEGER)
        - (exactStackDelta(right) ?? Number.MAX_SAFE_INTEGER);
      if (stackDifference !== 0) return stackDifference;
      const lengthDifference = left.instructions.length - right.instructions.length;
      return lengthDifference !== 0 ? lengthDifference : right.score - left.score;
    });
}

export class RankedSemanticEmitter implements RopEmitter {
  public emit(index: CapabilityIndex, plan: RopStrategyPlan, strategyId?: number): EmissionResult {
    const strategy = strategyId === undefined
      ? plan.strategies.find((candidate) => candidate.recommended)
      : plan.strategies.find((candidate) => candidate.id === strategyId);
    if (!strategy) {
      return {
        planId: plan.id,
        strategy: plan.strategy,
        strategyId: strategyId ?? 0,
        shape: "RET_DISPATCH",
        success: false,
        gadgets: [],
        missing: [],
        diagnostics: ["No matching or recommended strategy exists for this plan."],
      };
    }
    if (!strategy.possible) {
      return {
        planId: plan.id,
        strategy: plan.strategy,
        strategyId: strategy.id,
        shape: strategy.shape,
        success: false,
        gadgets: [],
        missing: strategy.missing,
        diagnostics: [strategy.reason],
      };
    }

    const gadgets: EmittedGadget[] = [];
    const missing: CapabilityKind[] = [];
    for (const capability of strategy.required) {
      const selected = rankCandidates(index.query({ capability }))[0];
      const location = selected ? knownAddress(selected) : undefined;
      if (!selected || !location) {
        missing.push(capability);
        continue;
      }
      gadgets.push({
        capability,
        canonicalId: selected.canonicalId,
        address: location.address,
        module: location.module,
        sequence: selected.instructions.map((instruction) => instruction.normalizedText).join(" ; "),
        score: selected.score,
        stackDelta: exactStackDelta(selected),
        sideEffects: sideEffectCount(selected),
      });
    }

    return {
      planId: plan.id,
      strategy: plan.strategy,
      strategyId: strategy.id,
      shape: strategy.shape,
      success: missing.length === 0,
      gadgets,
      missing,
      diagnostics: missing.length === 0
        ? ["Gadget assignment (not an ordered executable chain). Use chain_vp/chain_wpm/chain_va for executable chain output."]
        : [`No address-bearing gadget satisfies: ${missing.join(", ")}.`],
    };
  }
}

export function emissionRows(result: EmissionResult): Array<Record<string, string>> {
  if (result.gadgets.length === 0) {
    return [{
      Plan: result.planId.toString(),
      Strategy: `${result.strategy} / ${result.shape}`,
      Status: result.success ? "ok" : "unavailable",
      Missing: result.missing.join(", "),
      Diagnostic: result.diagnostics.join(" "),
    }];
  }
  return result.gadgets.map((gadget) => ({
    Plan: result.planId.toString(),
    Strategy: `${result.strategy} / ${result.shape}`,
    Capability: gadget.capability,
    Address: `0x${gadget.address.toString(16).toUpperCase()}`,
    Module: gadget.module,
    Sequence: gadget.sequence,
    Score: gadget.score.toString(),
    StackDelta: gadget.stackDelta?.toString() ?? "unknown",
    SideEffects: gadget.sideEffects.toString(),
  }));
}
