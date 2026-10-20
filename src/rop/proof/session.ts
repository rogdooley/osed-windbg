import type { ProofDebuggerAdapter } from "./adapter";
import { compareCheckpoint, resolveProofExpression } from "./comparator";
import { captureProofFingerprint, compareProofFingerprint } from "./fingerprint";
import { ProofSessionStore } from "./store";
import { captureStdcallFrame, evaluatePostcondition } from "./postcondition";
import type {
  BreakpointSnapshot,
  FingerprintScope,
  OrphanCleanupResult,
  OwnedBreakpoint,
  ProofMode,
  ProofPlan,
  ProofRegisterSnapshot,
  ProofSession,
} from "./types";

const MARKER_PREFIX = "osed-proof:";
const MARKER_V1 = /^osed-proof:v1:([A-Za-z0-9-]+):([A-Za-z0-9-]+):(\d+)$/;
const MARKER_ANY_VERSION = /^osed-proof:v([^:]+):/;
let sessionCounter = 0;

export interface StartProofSessionInput {
  mode: ProofMode;
  plan: ProofPlan;
  sessionId?: string;
  nonce?: string;
  postcondition?: boolean;
}

function fingerprintScope(plan: ProofPlan): FingerprintScope {
  const gadgetAddresses = plan.checkpoints.flatMap((checkpoint) =>
    checkpoint.provenance.flatMap((entry) => entry.address === undefined ? [] : [entry.address]));
  const moduleNames = plan.checkpoints.flatMap((checkpoint) =>
    checkpoint.provenance.flatMap((entry) => entry.module === undefined ? [] : [entry.module]));
  return {
    moduleNames: [...new Set(moduleNames)],
    gadgetAddresses: [...new Set(gadgetAddresses)],
    protectionAddresses: [],
  };
}

function ownedFrom(snapshot: BreakpointSnapshot): OwnedBreakpoint {
  return {
    id: snapshot.id,
    address: snapshot.address,
    enabled: snapshot.enabled,
    oneShot: snapshot.oneShot,
    marker: snapshot.marker,
  };
}

export class ProofSessionMachine {
  private readonly priorRegisters = new Map<string, ProofRegisterSnapshot>();
  private readonly resolvedTargets = new Map<string, bigint>();

  constructor(
    private readonly adapter: ProofDebuggerAdapter,
    private readonly store: ProofSessionStore,
  ) {}

  start(input: StartProofSessionInput): ProofSession {
    if (this.store.active()) throw new Error("A ROP proof session is already active.");
    const orphans = this.markerBreakpoints().filter((entry) => MARKER_V1.test(entry.marker));
    if (orphans.length > 0) {
      throw new Error(`Found ${orphans.length} orphaned rop.prove breakpoint(s). Run rop.prove({action:\"cancel\", orphans:true}).`);
    }

    const baselineFingerprint = captureProofFingerprint(fingerprintScope(input.plan), this.adapter);
    if (baselineFingerprint.architecture !== "x86" || baselineFingerprint.pointerSize !== 4) {
      throw new Error("rop.prove v1 requires an x86 target with a four-byte pointer size.");
    }
    if (input.plan.checkpoints.length === 0) throw new Error("The proof plan has no checkpoints.");

    sessionCounter += 1;
    const sessionId = input.sessionId ?? `proof-${Date.now().toString(36)}-${sessionCounter}`;
    const nonce = input.nonce ?? `${Date.now().toString(36)}-${sessionCounter}`;
    const session: ProofSession = {
      id: sessionId,
      mode: input.mode,
      state: "CHECKPOINT_REACHED",
      plan: input.plan,
      checkpointIndex: 0,
      baselineFingerprint,
      observations: [],
      events: [],
      executionStatus: "UNVERIFIED",
      objectiveStatus: "UNVERIFIED",
      objectiveReason: "not requested",
      postconditionRequested: input.postcondition === true,
    };
    this.store.add(session);
    this.store.appendEvent(session, "session-started", { mode: input.mode, nonce });
    const current = this.adapter.readRegisters();
    this.priorRegisters.set(session.id, current);

    const first = input.plan.checkpoints[0];
    const target = resolveProofExpression(first.target, current, current, this.adapter);
    if (target.ok && target.value === current.eip) {
      const observation = compareCheckpoint({ checkpoint: first, previous: current, resolvedTarget: target.value }, this.adapter);
      session.observations.push(observation);
      session.checkpointIndex = 1;
      this.store.appendEvent(session, "checkpoint-observed", { checkpointId: first.id, outcome: observation.outcome });
      if (observation.outcome === "FAILED") {
        session.state = "FAILED";
        session.executionStatus = "FAILED";
        return session;
      }
    }
    return this.armOrComplete(session, nonce);
  }

  observeAndAdvance(): ProofSession {
    const session = this.store.active();
    if (!session) throw new Error("No active proof session. Start one with rop.prove({mode:\"guided\"}).");
    if (session.state === "POSTCONDITION_ARMED") return this.observePostcondition(session);
    if (session.checkpointIndex >= session.plan.checkpoints.length) return this.complete(session);

    const currentFingerprint = captureProofFingerprint(fingerprintScope(session.plan), this.adapter);
    const fingerprint = compareProofFingerprint(session.baselineFingerprint, currentFingerprint, {
      ownedBreakpoint: session.ownedBreakpoint,
    });
    if (fingerprint.status === "STALE_TARGET") {
      session.state = "STALE_TARGET";
      session.executionStatus = "UNVERIFIED";
      this.store.appendEvent(session, "stale-target", { reasons: fingerprint.reasons });
      return session;
    }

    const checkpoint = session.plan.checkpoints[session.checkpointIndex];
    const previous = this.priorRegisters.get(session.id) ?? this.adapter.readRegisters();
    const targetKey = `${session.id}:${checkpoint.id}`;
    const capturedTarget = this.resolvedTargets.get(targetKey);
    const target = capturedTarget === undefined
      ? resolveProofExpression(checkpoint.target, previous, previous, this.adapter)
      : { ok: true as const, value: capturedTarget };
    const observation = compareCheckpoint({
      checkpoint,
      previous,
      resolvedTarget: target.ok ? target.value : undefined,
    }, this.adapter);
    session.observations.push(observation);
    this.store.appendEvent(session, "checkpoint-observed", {
      checkpointId: checkpoint.id,
      outcome: observation.outcome,
      exceptionCode: observation.registers.exceptionCode?.toString(16),
    });

    if (observation.outcome === "UNEXPECTED_STOP") {
      session.state = "ARMED";
      return session;
    }
    if (session.ownedBreakpoint) {
      const deleted = this.adapter.deleteOwned(session.ownedBreakpoint);
      this.store.appendEvent(session, "breakpoint-consumed", { status: deleted.status, id: session.ownedBreakpoint.id });
      if (deleted.status === "identity-mismatch") {
        session.state = "UNVERIFIED";
        session.executionStatus = "UNVERIFIED";
        return session;
      }
      session.ownedBreakpoint = undefined;
    }
    if (observation.outcome === "FAILED") {
      session.state = "FAILED";
      session.executionStatus = "FAILED";
      return session;
    }
    if (observation.outcome === "UNVERIFIED") session.executionStatus = "UNVERIFIED";

    session.state = "CHECKPOINT_REACHED";
    session.checkpointIndex += 1;
    this.priorRegisters.set(session.id, observation.registers);
    const nonce = this.sessionNonce(session);
    return this.armOrComplete(session, nonce);
  }

  status(): ProofSession | undefined {
    return this.store.latest();
  }

  cancel(): ProofSession | undefined {
    const session = this.store.active();
    if (!session) return this.store.latest();
    if (session.ownedBreakpoint) {
      const result = this.adapter.deleteOwned(session.ownedBreakpoint);
      this.store.appendEvent(session, "breakpoint-cancelled", { id: session.ownedBreakpoint.id, status: result.status });
      if (result.status === "identity-mismatch") return session;
      session.ownedBreakpoint = undefined;
    }
    session.state = "CANCELLED";
    this.store.appendEvent(session, "session-cancelled");
    return session;
  }

  cancelOrphans(): OrphanCleanupResult[] {
    const results: OrphanCleanupResult[] = [];
    for (const breakpoint of this.markerBreakpoints()) {
      const version = MARKER_ANY_VERSION.exec(breakpoint.marker);
      if (!version) continue;
      if (!MARKER_V1.test(breakpoint.marker)) {
        results.push({ status: "unsupported-marker-version", breakpoint });
        continue;
      }
      results.push(this.adapter.deleteOwned(ownedFrom(breakpoint)));
    }
    return results;
  }

  private armOrComplete(session: ProofSession, nonce: string): ProofSession {
    if (session.checkpointIndex >= session.plan.checkpoints.length) return this.complete(session);
    const checkpoint = session.plan.checkpoints[session.checkpointIndex];
    const previous = this.priorRegisters.get(session.id) ?? this.adapter.readRegisters();
    const resolved = resolveProofExpression(checkpoint.target, previous, previous, this.adapter);
    if (!resolved.ok) {
      session.state = "UNVERIFIED";
      session.executionStatus = "UNVERIFIED";
      this.store.appendEvent(session, "dynamic-target-unresolved", { checkpointId: checkpoint.id, reason: resolved.reason });
      return session;
    }
    if (checkpoint.dynamic) {
      this.store.appendEvent(session, "dynamic-target-resolved", {
        checkpointId: checkpoint.id,
        target: `0x${resolved.value.toString(16)}`,
      });
    }
    this.resolvedTargets.set(`${session.id}:${checkpoint.id}`, resolved.value);
    if (session.mode === "observe") {
      session.state = "ARMED";
      return session;
    }
    const marker = `${MARKER_PREFIX}v1:${session.id}:${nonce}:${checkpoint.id}`;
    const armed = this.adapter.setOneShot(resolved.value, marker);
    if (!armed.ok) {
      session.state = "UNVERIFIED";
      this.store.appendEvent(session, "breakpoint-arm-failed", { reason: armed.error.message });
      return session;
    }
    session.ownedBreakpoint = armed.value;
    session.state = "ARMED";
    this.store.appendEvent(session, "breakpoint-armed", { id: armed.value.id, address: `0x${armed.value.address.toString(16)}` });
    return session;
  }

  private complete(session: ProofSession): ProofSession {
    const incomplete = !session.baselineFingerprint.complete || session.plan.incompleteReasons.length > 0 ||
      session.observations.some((observation) => observation.outcome === "UNVERIFIED");
    session.executionStatus = incomplete ? "UNVERIFIED" : "VERIFIED";
    this.store.appendEvent(session, "execution-complete", { executionStatus: session.executionStatus });
    if (session.postconditionRequested && session.plan.api) {
      const current = this.adapter.readRegisters();
      const frame = captureStdcallFrame(session.plan.api, current.esp, this.adapter);
      session.runtimeFrame = frame;
      session.objectiveReason = frame.reason;
      if (frame.status !== "VERIFIED" || frame.returnAddress === undefined) {
        session.state = "EXECUTION_COMPLETE";
        return session;
      }
      const marker = `${MARKER_PREFIX}v1:${session.id}:${this.sessionNonce(session)}:${session.plan.checkpoints.length}`;
      if (session.mode === "guided") {
        const armed = this.adapter.setOneShot(frame.returnAddress, marker);
        if (!armed.ok) {
          session.state = "EXECUTION_COMPLETE";
          session.objectiveReason = armed.error.message;
          return session;
        }
        session.ownedBreakpoint = armed.value;
        this.store.appendEvent(session, "postcondition-breakpoint-armed", {
          id: armed.value.id,
          address: `0x${armed.value.address.toString(16)}`,
        });
      }
      session.state = "POSTCONDITION_ARMED";
      return session;
    }
    session.state = "EXECUTION_COMPLETE";
    return session;
  }

  private observePostcondition(session: ProofSession): ProofSession {
    const frame = session.runtimeFrame;
    if (!frame || !session.plan.api) {
      session.state = "POSTCONDITION_FAILED";
      session.objectiveStatus = "UNVERIFIED";
      session.objectiveReason = "captured runtime frame is unavailable";
      return session;
    }
    const registers = this.adapter.readRegisters();
    if (frame.returnAddress !== registers.eip) {
      this.store.appendEvent(session, "postcondition-unexpected-stop", {
        expected: frame.returnAddress === undefined ? undefined : `0x${frame.returnAddress.toString(16)}`,
        observed: `0x${registers.eip.toString(16)}`,
      });
      return session;
    }
    if (session.ownedBreakpoint) {
      const deleted = this.adapter.deleteOwned(session.ownedBreakpoint);
      this.store.appendEvent(session, "postcondition-breakpoint-consumed", { status: deleted.status });
      if (deleted.status === "identity-mismatch") return session;
      session.ownedBreakpoint = undefined;
    }
    const objective = evaluatePostcondition({ api: session.plan.api }, frame, registers, this.adapter);
    session.objectiveObservation = objective;
    session.objectiveStatus = objective.status;
    session.objectiveReason = objective.reason;
    session.state = objective.status === "VERIFIED" ? "POSTCONDITION_OBSERVED" : "POSTCONDITION_FAILED";
    this.store.appendEvent(session, "postcondition-observed", { status: objective.status, reason: objective.reason });
    return session;
  }

  private markerBreakpoints(): BreakpointSnapshot[] {
    const listed = this.adapter.listBreakpoints();
    if (!listed.ok) return [];
    return listed.value.filter((entry) => entry.marker.startsWith(MARKER_PREFIX));
  }

  private sessionNonce(session: ProofSession): string {
    const start = session.events.find((event) => event.kind === "session-started");
    return typeof start?.detail.nonce === "string" ? start.detail.nonce : "session";
  }
}
