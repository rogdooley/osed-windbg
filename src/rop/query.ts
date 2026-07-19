import { Register, RegisterExpr, SemanticField } from "../semantics/types";
import type { CapabilityIndex } from "./capabilities";
import { RegisterTransformQuery, RopGadget, RopQuery, TerminatorKind } from "./types";

function normalizeRegisters(registers?: string[]): string[] {
  return (registers ?? [])
    .map((register) => register.trim().toLowerCase())
    .filter((register) => register.length > 0);
}

function normalizeKinds<T>(values?: T | T[]): T[] {
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

// A register is net-preserved iff its aggregated transform is exactly identity
// (base is the register itself, constant offset of zero). Unknown, memory, and
// constant transforms all fail, matching the conservative discipline elsewhere:
// an unproven net effect is never treated as "preserved".
function isIdentityTransform(register: string, expr: RegisterExpr | undefined): boolean {
  return (
    !!expr &&
    expr.kind === "affine" &&
    expr.base === register &&
    expr.offset.kind === "constant" &&
    expr.offset.value === 0
  );
}

function matchesPreserves(gadget: RopGadget, registers: string[]): boolean {
  if (registers.length === 0) {
    return true;
  }
  const transforms = gadget.semanticSummary.summary.registerTransforms;
  return registers.every((register) => isIdentityTransform(register, transforms[register as Register]));
}

function normalizeTransformQuery(query: RegisterTransformQuery): RegisterTransformQuery {
  return {
    register: query.register.trim().toLowerCase(),
    base: query.base?.trim().toLowerCase(),
    offset: query.offset,
    offsetRegister: query.offsetRegister?.trim().toLowerCase(),
    constant: query.constant,
    fromMemory: query.fromMemory,
  };
}

function matchesTransform(expr: RegisterExpr | undefined, query: RegisterTransformQuery): boolean {
  if (!expr) {
    return false;
  }
  if (query.constant !== undefined) {
    if (expr.kind !== "constant" || expr.value !== query.constant) {
      return false;
    }
  }
  if (query.fromMemory !== undefined && (expr.kind === "memory") !== query.fromMemory) {
    return false;
  }
  const wantsAffine = query.base !== undefined || query.offset !== undefined || query.offsetRegister !== undefined;
  if (wantsAffine) {
    if (expr.kind !== "affine") {
      return false;
    }
    if (query.base !== undefined && expr.base !== query.base) {
      return false;
    }
    if (query.offset !== undefined && (expr.offset.kind !== "constant" || expr.offset.value !== query.offset)) {
      return false;
    }
    if (query.offsetRegister !== undefined && (expr.offset.kind !== "register" || expr.offset.register !== query.offsetRegister)) {
      return false;
    }
  }
  return true;
}

function matchesTransforms(gadget: RopGadget, queries: RegisterTransformQuery[]): boolean {
  if (queries.length === 0) {
    return true;
  }
  const transforms = gadget.semanticSummary.summary.registerTransforms;
  return queries.every((query) => matchesTransform(transforms[query.register as Register], query));
}

export function queryRopGadgets(gadgets: RopGadget[], query: RopQuery): RopGadget[] {
  const reads = normalizeRegisters(query.reads);
  const writes = normalizeRegisters(query.writes);
  const preserves = normalizeRegisters(query.preserves);
  const preservesThroughout = normalizeRegisters(query.preservesThroughout);
  const transforms = (query.transforms ?? []).map(normalizeTransformQuery);
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

    // Net-preserve: register is unchanged at gadget exit (transform is identity).
    if (!matchesPreserves(gadget, preserves)) {
      return false;
    }

    // Strict-preserve: register is never written at any step in the gadget.
    if (!fieldExcludesAll(gadget.semanticSummary.summary.writes, preservesThroughout)) {
      return false;
    }

    if (!matchesTransforms(gadget, transforms)) {
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
