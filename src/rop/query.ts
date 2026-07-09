import { SemanticField } from "../semantics/types";
import { CapabilityIndex, RopGadget, RopQuery, TerminatorKind } from "./types";

function normalizeRegisters(registers?: string[]): string[] {
  return (registers ?? [])
    .map((register) => register.trim().toLowerCase())
    .filter((register) => register.length > 0);
}

function normalizeKinds<T extends string>(values?: T | T[]): T[] {
  if (values === undefined) {
    return [];
  }
  return Array.isArray(values) ? values : [values];
}

function fieldSupportsAll<T>(field: SemanticField<T> | undefined, expected: T[]): boolean {
  if (expected.length === 0) {
    return true;
  }
  if (!field || field.values.unknown) {
    return false;
  }
  for (const value of expected) {
    if (!field.values.exact.has(value) && !field.values.conservative.has(value)) {
      return false;
    }
  }
  return true;
}

function fieldExcludesAll<T>(field: SemanticField<T> | undefined, forbidden: T[]): boolean {
  if (forbidden.length === 0) {
    return true;
  }
  if (!field || field.values.unknown) {
    return false;
  }
  for (const value of forbidden) {
    if (field.values.exact.has(value) || field.values.conservative.has(value)) {
      return false;
    }
  }
  return true;
}

function fieldMatchesAny<T>(field: SemanticField<T> | undefined, expected: T[]): boolean {
  if (expected.length === 0) {
    return true;
  }
  if (!field || field.values.unknown) {
    return false;
  }
  for (const value of expected) {
    if (field.values.exact.has(value) || field.values.conservative.has(value)) {
      return true;
    }
  }
  return false;
}

function hasKnownValues<T>(field: SemanticField<T> | undefined): boolean {
  return !!field && !field.values.unknown && (field.values.exact.size > 0 || field.values.conservative.size > 0);
}

// True only when the field is known AND empty — i.e. the gadget definitely has no
// effect of this kind. An unknown field fails this check so that a negative
// constraint (e.g. memoryWrite: false) excludes gadgets whose effect is unproven.
function isDefinitelyEmpty<T>(field: SemanticField<T> | undefined): boolean {
  return !!field && !field.values.unknown && field.values.exact.size === 0 && field.values.conservative.size === 0;
}

function matchesStackDelta(field: SemanticField<number> | undefined, expected: number[]): boolean {
  return fieldMatchesAny(field, expected);
}

function matchesCapability(gadget: RopGadget, expected: string[]): boolean {
  if (expected.length === 0) {
    return true;
  }
  const expectedSet = new Set(expected.map((item) => item.trim().toUpperCase()));
  return gadget.capabilities.some((capability) => expectedSet.has(capability.kind));
}

function matchesTerminator(gadget: RopGadget, expected: TerminatorKind[]): boolean {
  if (expected.length === 0) {
    return true;
  }
  return fieldMatchesAny(gadget.semanticSummary.summary.flowEffects, expected);
}

function matchesExecutableOnly(gadget: RopGadget): boolean {
  return gadget.locations.some((location) => location.executable !== "UNKNOWN");
}

export function queryRopGadgets(gadgets: RopGadget[], query: RopQuery): RopGadget[] {
  const reads = normalizeRegisters(query.reads);
  const writes = normalizeRegisters(query.writes);
  const preserves = normalizeRegisters(query.preserves);
  const stackDelta = normalizeKinds(query.stackDelta);
  const capabilities = normalizeKinds(query.capability);
  const terminators = normalizeKinds(query.terminator);
  const memoryReads = query.memoryReads ?? query.memoryRead;
  const memoryWrites = query.memoryWrites ?? query.memoryWrite;

  return gadgets.filter((gadget) => {
    if (query.executableOnly && !matchesExecutableOnly(gadget)) {
      return false;
    }

    if (!fieldSupportsAll(gadget.semanticSummary.summary.reads, reads)) {
      return false;
    }

    if (!fieldSupportsAll(gadget.semanticSummary.summary.writes, writes)) {
      return false;
    }

    if (!fieldExcludesAll(gadget.semanticSummary.summary.writes, preserves)) {
      return false;
    }

    if (!matchesStackDelta(gadget.semanticSummary.summary.stackDelta, stackDelta)) {
      return false;
    }

    if (!matchesCapability(gadget, capabilities)) {
      return false;
    }

    if (!matchesTerminator(gadget, terminators)) {
      return false;
    }

    if (memoryReads !== undefined) {
      const field = gadget.semanticSummary.summary.memoryReads;
      // memoryReads: true  requires proven reads; memoryReads: false requires proven absence.
      // Unknown fails both, so an unproven gadget never satisfies either constraint.
      if (memoryReads ? !hasKnownValues(field) : !isDefinitelyEmpty(field)) {
        return false;
      }
    }

    if (memoryWrites !== undefined) {
      const field = gadget.semanticSummary.summary.memoryWrites;
      if (memoryWrites ? !hasKnownValues(field) : !isDefinitelyEmpty(field)) {
        return false;
      }
    }

    return true;
  });
}

export function summarizeCapabilities(index: CapabilityIndex): Array<Record<string, string>> {
  const counts = new Map<string, { kind: string; register: string; targetRegister: string; count: number }>();

  for (const gadget of index.gadgets) {
    for (const capability of gadget.capabilities) {
      const key = [capability.kind, capability.register ?? "", capability.targetRegister ?? ""].join(":");
      const existing = counts.get(key) ?? {
        kind: capability.kind,
        register: capability.register ?? "",
        targetRegister: capability.targetRegister ?? "",
        count: 0,
      };
      existing.count += 1;
      counts.set(key, existing);
    }
  }

  return [...counts.values()]
    .sort((left, right) => {
      if (left.kind !== right.kind) {
        return left.kind.localeCompare(right.kind);
      }
      if (left.register !== right.register) {
        return left.register.localeCompare(right.register);
      }
      return left.targetRegister.localeCompare(right.targetRegister);
    })
    .map((entry) => ({
      Kind: entry.kind,
      Register: entry.register || "",
      Target: entry.targetRegister || "",
      Count: entry.count.toString(),
    }));
}
