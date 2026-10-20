import type { CapabilityIndex } from "../capabilities";
import type { ChainStep } from "../chain";
import type { ProofDebuggerAdapter } from "./adapter";
import { buildProofPlan } from "./predictor";
import { ProofSessionMachine } from "./session";
import { ProofSessionStore } from "./store";
import type { OrphanCleanupResult, ProofMode, ProofPlanInput, ProofSession } from "./types";

export interface ProofControllerDependencies {
  adapter: ProofDebuggerAdapter;
  store: ProofSessionStore;
  getDefaultInput(): ProofPlanInput | undefined;
  getCorpus?(): CapabilityIndex | undefined;
}

export interface ProofCommandOptions {
  action?: "status" | "cancel" | "history";
  mode?: ProofMode;
  chain?: string | ChainStep[];
  api?: string;
  postcondition?: boolean;
  orphans?: boolean;
}

export interface ProofCommandOutcome {
  success: boolean;
  session?: ProofSession;
  history?: readonly ProofSession[];
  orphanResults?: OrphanCleanupResult[];
  error?: string;
}

export class ProofController {
  private readonly machine: ProofSessionMachine;

  constructor(private readonly dependencies: ProofControllerDependencies) {
    this.machine = new ProofSessionMachine(dependencies.adapter, dependencies.store);
  }

  execute(options?: ProofCommandOptions): ProofCommandOutcome {
    try {
      if (options === undefined) {
        if (!this.dependencies.store.active()) {
          return { success: false, error: "No active proof session. Start one with rop.prove({mode:\"guided\"})." };
        }
        return this.outcome(this.machine.observeAndAdvance());
      }

      if (options.action === "status") {
        const session = this.machine.status();
        return session ? this.outcome(session) : { success: false, error: "No proof session has been recorded." };
      }
      if (options.action === "history") {
        return { success: true, history: this.dependencies.store.history() };
      }
      if (options.action === "cancel") {
        const session = this.machine.cancel();
        const orphanResults = options.orphans ? this.machine.cancelOrphans() : undefined;
        return { success: false, session, orphanResults };
      }
      if (this.dependencies.store.active()) {
        return { success: false, error: "A ROP proof session is already active; inspect status or cancel it first." };
      }

      const inherited = this.dependencies.getDefaultInput();
      const chain = options.chain ?? inherited?.chain;
      if (chain === undefined) {
        return { success: false, error: "No chain to prove. Run rop.generate first or pass {chain: ...}." };
      }
      const input: ProofPlanInput = {
        chain,
        corpus: this.dependencies.getCorpus?.() ?? inherited?.corpus,
        api: options.api ?? inherited?.api,
      };
      const plan = buildProofPlan(input, this.dependencies.adapter);
      const session = this.machine.start({
        mode: options.mode ?? "guided",
        plan,
        postcondition: options.postcondition === true,
      });
      return this.outcome(session);
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  private outcome(session: ProofSession): ProofCommandOutcome {
    return {
      success: session.executionStatus === "VERIFIED" && session.objectiveStatus === "VERIFIED",
      session,
    };
  }
}
