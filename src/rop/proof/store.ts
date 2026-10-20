import type { ProofEvent, ProofSession } from "./types";

const ACTIVE_STATES = new Set([
  "ARMED",
  "CHECKPOINT_REACHED",
  "POSTCONDITION_ARMED",
  "POSTCONDITION_OBSERVED",
]);

export class ProofSessionStore {
  private readonly sessions: ProofSession[] = [];
  private eventSequence = 0;

  add(session: ProofSession): ProofSession {
    if (this.active()) throw new Error("A ROP proof session is already active.");
    this.sessions.push(session);
    return session;
  }

  active(): ProofSession | undefined {
    const session = this.sessions[this.sessions.length - 1];
    return session && ACTIVE_STATES.has(session.state) ? session : undefined;
  }

  latest(): ProofSession | undefined {
    return this.sessions[this.sessions.length - 1];
  }

  history(): readonly ProofSession[] {
    return this.sessions;
  }

  appendEvent(session: ProofSession, kind: string, detail: Record<string, unknown> = {}): ProofEvent {
    const event: ProofEvent = {
      sequence: this.eventSequence,
      timestamp: new Date().toISOString(),
      kind,
      detail,
    };
    this.eventSequence += 1;
    session.events.push(event);
    return event;
  }
}
