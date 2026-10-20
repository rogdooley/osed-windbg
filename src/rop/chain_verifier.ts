import type { ChainStep } from "./chain";
import type { CapabilityIndex } from "./capabilities";
import type { RopGadget } from "./types";
import { STDCALL_ARG_COUNT, type ApiExploitStrategy } from "./planner";

// ─── Public types ──────────────────────────────────────────────────────────

export interface VerifyInput {
  steps: ChainStep[];
  badchars: number[];
  api?: string;                        // expected API (validates frame structure)
  corpus?: CapabilityIndex;            // when available, enables runtime trace
  expectedArgCount?: number;           // override frame arg count
}

export interface BadcharHit {
  stepIndex: number;
  byteOffset: number;                  // byte offset from chain start
  byte: number;                        // the offending byte
  bytePosition: number;               // 0-3 within the DWORD (LE)
  dwordHex: string;                    // the full DWORD as hex
  comment: string;
}

export interface UnresolvedEntry {
  stepIndex: number;
  byteOffset: number;
  placeholder: string;
  comment: string;
}

export interface FrameCheck {
  api: string;
  expectedArgCount: number;
  expectedFrameWords: number;            // 1 (retaddr) + argCount
  status: "ok" | "too_few" | "too_many" | "unknown_api" | "not_checked";
  detail: string;
}

export interface StaticReport {
  valid: boolean;
  dwordCount: number;
  totalStackBytes: number;
  alignment: "aligned" | "misaligned";
  badcharHits: BadcharHit[];
  unresolvedPlaceholders: UnresolvedEntry[];
  frameCheck?: FrameCheck;
  assumptions: string[];
}

export interface TraceRegisterState {
  [reg: string]: string;               // hex value or "?" for unknown
}

export interface TraceStep {
  stepIndex: number;
  espOffset: number;                   // bytes from chain start
  dwordHex: string;                    // the DWORD value or "????????" for placeholder
  action: string;                      // what this DWORD does
  kind: "gadget" | "pop-operand" | "frame-value" | "padding" | "placeholder";
  registersAfter: TraceRegisterState;  // cumulative register snapshot
  sideEffects: string[];               // register clobbers, etc.
  notes: string[];
}

export interface RuntimeReport {
  available: boolean;
  reason?: string;                     // why unavailable
  trace: TraceStep[];
  finalRegisters: TraceRegisterState;
  registerClobbers: string[];          // regs written then overwritten before use
  assumptions: string[];
}

export interface VerificationReport {
  static: StaticReport;
  runtime: RuntimeReport;
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function hex32(v: number): string {
  return `0x${(v >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
}

function dwordBytes(value: number): number[] {
  const v = value >>> 0;
  return [(v) & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
}

function resolveStepDword(step: ChainStep): number | undefined {
  if (step.kind === "gadget" && step.address !== undefined) return Number(step.address) >>> 0;
  if (step.value !== undefined) return step.value >>> 0;
  return undefined;
}

function stepDwordHex(step: ChainStep): string {
  const v = resolveStepDword(step);
  return v !== undefined ? hex32(v) : "????????";
}

// ─── Static analysis ───────────────────────────────────────────────────────

function analyzeStatic(input: VerifyInput): StaticReport {
  const { steps, badchars } = input;
  const badSet = new Set(badchars.map(b => b & 0xff));
  const hits: BadcharHit[] = [];
  const unresolved: UnresolvedEntry[] = [];
  const assumptions: string[] = [];

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const byteOffset = i * 4;

    if (step.placeholder) {
      unresolved.push({
        stepIndex: i,
        byteOffset,
        placeholder: step.placeholder,
        comment: step.comment,
      });
      continue;
    }

    const dword = resolveStepDword(step);
    if (dword === undefined) continue;

    if (badSet.size > 0) {
      const bytes = dwordBytes(dword);
      for (let pos = 0; pos < 4; pos++) {
        if (badSet.has(bytes[pos])) {
          hits.push({
            stepIndex: i,
            byteOffset: byteOffset + pos,
            byte: bytes[pos],
            bytePosition: pos,
            dwordHex: hex32(dword),
            comment: step.comment,
          });
        }
      }
    }
  }

  const totalBytes = steps.length * 4;
  const aligned = totalBytes % 4 === 0;

  // Frame validation: if an API is specified, validate the frame word count.
  //
  // A bare frame (all value steps, no gadgets) is a flat stdcall layout where
  // every step IS a frame word — count them directly against retaddr + args.
  //
  // A generated slot_call chain mixes gadget addresses, pop operands, IAT slot
  // values, staging filler, and padding alongside the actual frame words. Counting
  // value steps in that chain tells you nothing about the frame — the machinery
  // outnumbers the payload. Frame validation is not meaningful there; the chain
  // builder already enforces the correct frame word count at construction time.
  let frameCheck: FrameCheck | undefined;
  if (input.api || input.expectedArgCount !== undefined) {
    const apiName = input.api ?? "";
    const knownArgCount = input.expectedArgCount
      ?? (STDCALL_ARG_COUNT[apiName as ApiExploitStrategy] as number | undefined);
    if (knownArgCount === undefined) {
      frameCheck = {
        api: apiName,
        expectedArgCount: 0,
        expectedFrameWords: 0,
        status: "unknown_api",
        detail: `Unknown API "${apiName}" — cannot validate frame structure. Known APIs: ${Object.keys(STDCALL_ARG_COUNT).join(", ")}`,
      };
    } else {
      const expectedWords = 1 + knownArgCount; // retaddr + args
      const hasGadgets = steps.some(s => s.kind === "gadget");

      if (hasGadgets) {
        // Generated chain: frame words are embedded inside ROP machinery
        // (pop operands, IAT slots, staging filler). Value-step counting
        // cannot distinguish frame words from machinery, so we do not
        // assert a count. Report not_checked so callers know this was
        // not validated — only the builder enforces frame structure.
        frameCheck = {
          api: apiName,
          expectedArgCount: knownArgCount,
          expectedFrameWords: expectedWords,
          status: "not_checked",
          detail: `${apiName} expects ${expectedWords} frame words (1 retaddr + ${knownArgCount} args); chain contains gadget machinery — frame word count not verifiable from flat steps, verify against builder output`,
        };
      } else {
        // Bare frame: every step is a frame word, so count directly.
        const actualCount = steps.length;
        let status: FrameCheck["status"];
        let detail: string;
        if (actualCount < expectedWords) {
          status = "too_few";
          detail = `${apiName} requires ${expectedWords} frame words (1 retaddr + ${knownArgCount} args), but chain has ${actualCount}`;
        } else if (actualCount > expectedWords) {
          status = "too_many";
          detail = `${apiName} requires ${expectedWords} frame words (1 retaddr + ${knownArgCount} args), but chain has ${actualCount}`;
        } else {
          status = "ok";
          detail = `Frame matches ${apiName}: ${expectedWords} words (1 retaddr + ${knownArgCount} args)`;
        }
        frameCheck = { api: apiName, expectedArgCount: knownArgCount, expectedFrameWords: expectedWords, status, detail };
      }
    }
  }
  if (badchars.length === 0) {
    assumptions.push("No bad characters specified — byte-level check skipped");
  } else {
    assumptions.push(`Bad characters: ${badchars.map(b => `0x${(b & 0xff).toString(16).padStart(2, "0")}`).join(" ")}`);
  }
  if (unresolved.length > 0) {
    assumptions.push(`${unresolved.length} placeholder(s) must be resolved before deployment`);
  }

  // All gadget addresses are assumed to be at stable (non-ASLR) locations
  const gadgetSteps = steps.filter(s => s.kind === "gadget");
  if (gadgetSteps.length > 0) {
    assumptions.push(`${gadgetSteps.length} gadget address(es) assumed stable (non-ASLR module, preferred base)`);
  }

  const frameOk = !frameCheck || frameCheck.status === "ok" || frameCheck.status === "not_checked";

  return {
    valid: hits.length === 0 && unresolved.length === 0 && aligned && frameOk,
    dwordCount: steps.length,
    totalStackBytes: totalBytes,
    alignment: aligned ? "aligned" : "misaligned",
    badcharHits: hits,
    unresolvedPlaceholders: unresolved,
    frameCheck,
    assumptions,
  };
}

// ─── Runtime simulation ────────────────────────────────────────────────────

interface GadgetInfo {
  instructions: Array<{ mnemonic: string; operands: string[]; normalizedText?: string; originalText: string }>;
}

function lookupGadgetByAddress(corpus: CapabilityIndex, address: bigint): GadgetInfo | undefined {
  for (const g of corpus.gadgets) {
    for (const loc of g.locations) {
      if (loc.virtualAddress !== undefined && BigInt(loc.virtualAddress) === address) {
        return g;
      }
    }
  }
  return undefined;
}

function cloneRegs(regs: TraceRegisterState): TraceRegisterState {
  return { ...regs };
}

const X86_REGS = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];

function simulateGadget(
  gadget: GadgetInfo,
  regs: TraceRegisterState,
  steps: ChainStep[],
  currentIndex: number,
): { consumed: number; sideEffects: string[]; popTargets: Array<{ reg: string; stepIndex: number }> } {
  const sideEffects: string[] = [];
  const popTargets: Array<{ reg: string; stepIndex: number }> = [];
  let consumed = 0;

  for (const instr of gadget.instructions) {
    const m = instr.mnemonic.toLowerCase();
    const ops = instr.operands.map(o => o.trim().toLowerCase());

    if (m === "ret") {
      // ret or ret N: the ret itself consumed the gadget address (already accounted for).
      // ret N skips N additional bytes; padding steps handle those.
      break;
    }

    if (m === "pop") {
      const reg = ops[0];
      if (reg && X86_REGS.includes(reg)) {
        consumed++;
        const targetIdx = currentIndex + consumed;
        if (targetIdx < steps.length) {
          const targetStep = steps[targetIdx];
          const val = resolveStepDword(targetStep);
          regs[reg] = val !== undefined ? hex32(val) : (targetStep.placeholder ?? "?");
          popTargets.push({ reg, stepIndex: targetIdx });
        } else {
          regs[reg] = "? (past end of chain)";
          sideEffects.push(`pop ${reg} reads past chain end`);
        }
      }
    } else if (m === "xchg") {
      const [a, b] = ops;
      if (a && b && X86_REGS.includes(a) && X86_REGS.includes(b)) {
        const tmp = regs[a] ?? "?";
        regs[a] = regs[b] ?? "?";
        regs[b] = tmp;
        sideEffects.push(`xchg ${a}, ${b}`);
      }
    } else if (m === "mov") {
      const dst = ops[0];
      const src = ops[1];
      if (dst && src) {
        // mov reg, reg
        if (X86_REGS.includes(dst) && X86_REGS.includes(src)) {
          regs[dst] = regs[src] ?? "?";
          sideEffects.push(`${dst} ← ${src} (${regs[src] ?? "?"})`);
        }
        // mov reg, [reg] (deref)
        else if (X86_REGS.includes(dst)) {
          const match = /\[(e[a-z]{2})\]/.exec(src);
          if (match) {
            const ptrReg = match[1];
            regs[dst] = `*[${regs[ptrReg] ?? ptrReg}]`;
            sideEffects.push(`${dst} ← *[${ptrReg}] (runtime deref)`);
          } else {
            regs[dst] = "?";
          }
        }
        // mov [reg], reg (store) — no register change
        else {
          const dstMatch = /\[(e[a-z]{2})\]/.exec(dst);
          if (dstMatch && X86_REGS.includes(src)) {
            sideEffects.push(`*[${dstMatch[1]}] ← ${src} (${regs[src] ?? "?"})`);
          }
        }
      }
    } else if (m === "add" || m === "sub") {
      const reg = ops[0];
      if (reg && X86_REGS.includes(reg)) {
        const immMatch = /^(?:0x)?([0-9a-f]+)$/i.exec(ops[1] ?? "");
        if (immMatch && regs[reg] && /^0x[0-9A-F]+$/i.test(regs[reg])) {
          const current = parseInt(regs[reg].replace(/^0x/i, ""), 16) >>> 0;
          const imm = parseInt(immMatch[1], 16) >>> 0;
          const result = m === "add" ? (current + imm) >>> 0 : (current - imm) >>> 0;
          regs[reg] = hex32(result);
        } else {
          regs[reg] = "?";
        }
        sideEffects.push(`${m} ${reg}, ${ops[1]}`);
      }
    } else if (m === "xor") {
      const [a, b] = ops;
      if (a === b && X86_REGS.includes(a)) {
        regs[a] = hex32(0);
        sideEffects.push(`${a} ← 0 (xor self)`);
      } else if (a && X86_REGS.includes(a)) {
        regs[a] = "?";
        sideEffects.push(`xor ${a}, ${b} (clobber)`);
      }
    } else if (m === "neg" || m === "not" || m === "inc" || m === "dec") {
      const reg = ops[0];
      if (reg && X86_REGS.includes(reg)) {
        if (regs[reg] && /^0x[0-9A-F]+$/i.test(regs[reg])) {
          const v = parseInt(regs[reg].replace(/^0x/i, ""), 16) >>> 0;
          let result: number;
          if (m === "neg") result = (-v) >>> 0;
          else if (m === "not") result = (~v) >>> 0;
          else if (m === "inc") result = (v + 1) >>> 0;
          else result = (v - 1) >>> 0;
          regs[reg] = hex32(result);
        } else {
          regs[reg] = "?";
        }
        sideEffects.push(`${m} ${reg}`);
      }
    } else if (m === "jmp") {
      sideEffects.push(`jmp ${ops[0]} (dispatch)`);
      break;
    } else if (m === "push") {
      if (ops[0] && X86_REGS.includes(ops[0])) {
        sideEffects.push(`push ${ops[0]} (${regs[ops[0]] ?? "?"})`);
      }
    } else if (m === "nop" || m === "int3") {
      // no-op
    } else {
      if (ops[0] && X86_REGS.includes(ops[0])) {
        sideEffects.push(`${instr.originalText} (may clobber ${ops[0]})`);
      }
    }
  }

  return { consumed, sideEffects, popTargets };
}

function analyzeRuntime(input: VerifyInput): RuntimeReport {
  const { steps, corpus } = input;

  if (!corpus) {
    return {
      available: false,
      reason: "No ROP corpus loaded — runtime trace requires gadget instruction data. Load a corpus with rop.scan() first.",
      trace: [],
      finalRegisters: {},
      registerClobbers: [],
      assumptions: [],
    };
  }

  const regs: TraceRegisterState = {};
  for (const r of X86_REGS) regs[r] = "?";

  const trace: TraceStep[] = [];
  const assumptions: string[] = [];
  const registerWrites: Map<string, number[]> = new Map();

  let i = 0;
  while (i < steps.length) {
    const step = steps[i];
    const espOffset = i * 4;
    const dword = stepDwordHex(step);

    if (step.placeholder) {
      trace.push({
        stepIndex: i,
        espOffset,
        dwordHex: "????????",
        action: `PLACEHOLDER: ${step.placeholder}`,
        kind: "placeholder",
        registersAfter: cloneRegs(regs),
        sideEffects: [],
        notes: [`Unresolved: ${step.placeholder} — ${step.comment}`],
      });
      i++;
      continue;
    }

    if (step.kind === "gadget" && step.address !== undefined) {
      const gadget = lookupGadgetByAddress(corpus, step.address);
      const instrText = gadget
        ? gadget.instructions.map(ins => ins.normalizedText || ins.originalText).join(" ; ")
        : "? (not in corpus)";

      if (!gadget) {
        trace.push({
          stepIndex: i,
          espOffset,
          dwordHex: dword,
          action: `GADGET: ${dword} — ${step.comment}`,
          kind: "gadget",
          registersAfter: cloneRegs(regs),
          sideEffects: [],
          notes: [`Address ${dword} not found in corpus — cannot trace instructions`],
        });
        assumptions.push(`Gadget at ${dword} not in corpus; register effects unknown from step ${i} onward`);
        i++;
        continue;
      }

      const { consumed, sideEffects, popTargets } = simulateGadget(gadget, regs, steps, i);

      // Track register writes for clobber detection
      for (const { reg, stepIndex } of popTargets) {
        const writes = registerWrites.get(reg) ?? [];
        writes.push(stepIndex);
        registerWrites.set(reg, writes);
      }
      for (const effect of sideEffects) {
        const match = /^(e[a-z]{2}) ←/.exec(effect);
        if (match) {
          const writes = registerWrites.get(match[1]) ?? [];
          writes.push(i);
          registerWrites.set(match[1], writes);
        }
      }

      trace.push({
        stepIndex: i,
        espOffset,
        dwordHex: dword,
        action: `GADGET: ${instrText}`,
        kind: "gadget",
        registersAfter: cloneRegs(regs),
        sideEffects,
        notes: [],
      });

      // Emit trace entries for popped operands
      for (let p = 0; p < consumed; p++) {
        const opIdx = i + 1 + p;
        if (opIdx < steps.length) {
          trace.push({
            stepIndex: opIdx,
            espOffset: opIdx * 4,
            dwordHex: stepDwordHex(steps[opIdx]),
            action: `POP operand for: ${step.comment}`,
            kind: "pop-operand",
            registersAfter: cloneRegs(regs),
            sideEffects: [],
            notes: [steps[opIdx].comment],
          });
        }
      }

      // Check for ret N padding
      const lastInstr = gadget.instructions[gadget.instructions.length - 1];
      if (lastInstr?.mnemonic === "ret" && lastInstr.operands.length > 0) {
        const retN = parseInt(lastInstr.operands[0].replace(/^0x/i, ""), 16);
        if (retN > 0) {
          const padCount = Math.floor(retN / 4);
          for (let p = 0; p < padCount; p++) {
            const padIdx = i + 1 + consumed + p;
            if (padIdx < steps.length) {
              trace.push({
                stepIndex: padIdx,
                espOffset: padIdx * 4,
                dwordHex: stepDwordHex(steps[padIdx]),
                action: `PADDING (ret ${retN} skip)`,
                kind: "padding",
                registersAfter: cloneRegs(regs),
                sideEffects: [],
                notes: [],
              });
            }
          }
          i += 1 + consumed + padCount;
          continue;
        }
      }

      i += 1 + consumed;
      continue;
    }

    // Value step not consumed by a pop — it's a frame value or standalone
    const isPadding = step.comment.startsWith("padding (ret ");
    trace.push({
      stepIndex: i,
      espOffset,
      dwordHex: dword,
      action: isPadding ? `PADDING: ${step.comment}` : `VALUE: ${step.comment}`,
      kind: isPadding ? "padding" : "frame-value",
      registersAfter: cloneRegs(regs),
      sideEffects: [],
      notes: [],
    });
    i++;
  }

  // Detect register clobbers: register written, then overwritten before any
  // meaningful use (heuristic: a later gadget or jmp/call reads it).
  // For the verifier's purposes, flag regs that were set more than once.
  const clobbers: string[] = [];
  for (const [reg, writes] of registerWrites) {
    if (writes.length > 1) {
      clobbers.push(`${reg} set ${writes.length} times (steps ${writes.join(", ")}) — verify intended value survives to use`);
    }
  }

  // Assumptions
  assumptions.push("Trace assumes linear execution: no conditional branches taken");
  assumptions.push("Register state before chain entry is unknown (shown as '?')");
  if (steps.some(s => s.kind === "gadget" && s.address !== undefined &&
    !lookupGadgetByAddress(corpus, s.address))) {
    assumptions.push("Some gadget addresses not found in corpus — trace may be incomplete");
  }

  return {
    available: true,
    trace,
    finalRegisters: cloneRegs(regs),
    registerClobbers: clobbers,
    assumptions,
  };
}

// ─── Public entry point ────────────────────────────────────────────────────

export function verifyChain(input: VerifyInput): VerificationReport {
  return {
    static: analyzeStatic(input),
    runtime: analyzeRuntime(input),
  };
}

// ─── Manual chain parser ───────────────────────────────────────────────────

/**
 * Parse a space-separated hex string into ChainSteps for verification.
 * Each token is a DWORD: "10022D64 1005D060 DEADBEEF"
 * Tokens that don't parse as hex become placeholders.
 */
export function parseManualChain(input: string): ChainStep[] {
  const tokens = input.trim().split(/\s+/).filter(t => t.length > 0);
  return tokens.map((token, i) => {
    const cleaned = token.replace(/^0x/i, "");
    const value = parseInt(cleaned, 16);
    if (/^[0-9a-fA-F]{1,8}$/.test(cleaned) && Number.isFinite(value)) {
      return { kind: "value" as const, value: value >>> 0, comment: `DWORD ${i}` };
    }
    return { kind: "value" as const, placeholder: token, comment: `DWORD ${i} (unresolved)` };
  });
}
