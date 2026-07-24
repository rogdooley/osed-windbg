import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize } from "../core/memory";
import { resolveTeb32Address, walkSehRecords } from "../analysis/seh";
import { findModuleByAddress } from "./modules";
import { memoryRegion } from "../analysis/memory";
import { readRegisters } from "./triage";

function shortModuleName(name: string): string {
  return name.replace(/\//g, "\\").split("\\").pop() ?? name;
}

function formatEspDelta(node: bigint, esp: bigint | undefined): string {
  if (esp === undefined) return "unknown";
  const delta = node - esp;
  const sign = delta < BigInt(0) ? "-" : "+";
  const magnitude = delta < BigInt(0) ? -delta : delta;
  return `${sign}0x${magnitude.toString(16).toUpperCase()}`;
}

function triStateFlag(value: boolean | null): string {
  return value === null ? "unknown" : value ? "yes" : "no";
}

export function createSehCommand(): Command {
  return {
    name: "seh",
    description: "Walk current thread SEH chain.",
    usage: "dx @$osed().seh.visualize()",
    examples: ["dx @$osed().seh.visualize()"],
    schema: {},
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      if (pointerSize !== 4) {
        return {
          command: "seh",
          args: options,
          success: false,
          findings: [],
          warnings: ["SEH chain walking is x86-focused in v1."],
          errors: ["Current pointer size is not x86."],
        };
      }

      const teb = resolveTeb32Address(host.currentThread as Record<string, unknown>);
      if (teb === undefined) {
        throw new Error("Current thread TEB is unavailable.");
      }

      const rows: Array<Record<string, string>> = [];
      const findings: unknown[] = [];

      const walk = walkSehRecords(teb);
      const records = walk.records;
      const esp = readRegisters(4).sp;

      for (const [depth, { node, next, handler }] of records.entries()) {
        const module = findModuleByAddress(handler);
        const executable = memoryRegion(handler).executable;
        const brokenNext = depth === records.length - 1 && walk.warning !== undefined;
        const end = next === BigInt(0xffffffff);
        const integrity = brokenNext
          ? "BROKEN NEXT"
          : !module || executable === false
            ? "BAD HANDLER"
            : end
              ? "END"
              : "OK";
        const candidate = Boolean(
          module
          && executable === true
          && module.safeseh === "disabled"
          && module.aslr === "disabled"
        );
        const assessment = candidate
          ? "CANDIDATE"
          : !module || executable === false
            ? "INVALID"
            : module.safeseh === "enabled"
              ? "PROTECTED"
              : module.aslr === "enabled"
                ? "ASLR"
                : "REVIEW";

        const moduleName = module ? shortModuleName(module.name) : "<unmapped>";
        const target = module
          ? `${moduleName}+0x${(handler - module.base).toString(16).toUpperCase()}`
          : "<unmapped>";

        rows.push({
          depth: `${depth}`,
          node: out.formatAddress(node, 4),
          next: end ? "END" : out.formatAddress(next, 4),
          handler: out.formatAddress(handler, 4),
          target,
          safeseh: module ? module.safeseh : "unknown",
          aslr: module ? module.aslr : "unknown",
          executable: triStateFlag(executable),
          espDelta: formatEspDelta(node, esp),
          integrity,
          assessment,
        });

        findings.push({
          depth,
          node,
          next,
          handler,
          module: moduleName,
          moduleOffset: module ? handler - module.base : undefined,
          espDelta: esp === undefined ? undefined : node - esp,
          executable,
          aslr: module?.aslr ?? "unknown",
          safeSeh: module?.safeseh ?? "unknown",
          end,
          brokenNext,
          integrity,
          candidate,
          assessment,
        });

      }

      out.section("SEH Chain");
      out.table(
        [
          { key: "depth", header: "#", width: 2 },
          { key: "node", header: "Node", width: 10 },
          { key: "next", header: "Next", width: 10 },
          { key: "handler", header: "Handler", width: 10 },
          { key: "target", header: "Module+Offset", width: 24 },
          { key: "safeseh", header: "SafeSEH", width: 8 },
          { key: "aslr", header: "ASLR", width: 8 },
          { key: "executable", header: "Exec", width: 7 },
          { key: "espDelta", header: "ESP Delta", width: 10 },
          { key: "integrity", header: "Integrity", width: 11 },
          { key: "assessment", header: "Assessment", width: 10 },
        ],
        rows,
      );
      if (walk.warning) {
        out.warn(walk.warning);
      }
      if (walk.stoppedAtGuard) {
        out.warn("SEH walk stopped at guard limit (64 entries).");
      }
      out.whyItMatters("The chain identifies overwritten frames, ESP-relative offsets, and handlers protected by SafeSEH or ASLR.");

      return {
        command: "seh",
        args: options,
        success: true,
        findings,
        warnings: [
          ...(walk.warning ? [walk.warning] : []),
          ...(walk.stoppedAtGuard ? ["SEH walk stopped at guard limit (64 entries)."] : []),
        ],
        errors: [],
      };
    },
  };
}
