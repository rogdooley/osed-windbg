import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize } from "../core/memory";
import { readSehRecords, resolveTeb32Address } from "../analysis/seh";
import { findModuleByAddress } from "./modules";

export function createSehCommand(): Command {
  return {
    name: "seh",
    description: "Walk current thread SEH chain.",
    usage: "dx @$osed().seh()",
    examples: ["dx @$osed().seh()"],
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

      const records = readSehRecords(teb);

      for (const { node, next, handler } of records) {
        const module = findModuleByAddress(handler);

        const safeSehRisk = module && module.safeseh !== "enabled" ? "risk" : "ok";
        const outsideModule = module === undefined;

        rows.push({
          node: out.formatAddress(node, 4),
          handler: out.formatAddress(handler, 4),
          target: module ? `${module.name}+0x${(handler - module.base).toString(16).toUpperCase()}` : "<outside module>",
          safeseh: module ? module.safeseh : "unknown",
          status: outsideModule || safeSehRisk === "risk" ? "flag" : "ok",
        });

        findings.push({
          node,
          next,
          handler,
          module: module?.name,
          outsideModule,
          safeSeh: module?.safeseh ?? "unknown",
        });

      }

      out.section("SEH Chain");
      out.table(
        [
          { key: "node", header: "Node", width: 10 },
          { key: "handler", header: "Handler", width: 10 },
          { key: "target", header: "Module+Offset", width: 24 },
          { key: "safeseh", header: "SafeSEH", width: 8 },
          { key: "status", header: "Status", width: 6 },
        ],
        rows,
      );
      out.whyItMatters("SEH handler control is a classic exploit path when stack overwrite is constrained.");

      return {
        command: "seh",
        args: options,
        success: true,
        findings,
        warnings: records.length >= 64 ? ["SEH walk stopped at guard limit (64 entries)."] : [],
        errors: [],
      };
    },
  };
}
