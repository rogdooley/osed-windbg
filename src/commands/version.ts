import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getVersionInfo } from "../core/version";

export function createVersionCommand(): Command {
  return {
    name: "version",
    description: "Show the loaded osed-windbg build identity.",
    usage: "dx @$osed().version()",
    examples: ["dx @$osed().version()", "dx @$osed().help(\"version\")"],
    schema: {},
    execute(options: Record<string, unknown>): CommandResult {
      const info = getVersionInfo();
      const rows = [
        { Field: "Name", Value: info.name },
        { Field: "Version", Value: info.version },
        { Field: "BuildTime", Value: info.buildTime },
        { Field: "GitCommit", Value: info.gitCommit },
        { Field: "GitDirty", Value: info.gitDirty ? "yes" : "no" },
      ];

      out.section("OSED Version");
      out.table(
        [
          { key: "Field", header: "Field" },
          { key: "Value", header: "Value" },
        ],
        rows,
      );

      return {
        command: "version",
        args: options,
        success: true,
        findings: [info],
        warnings: [],
        errors: [],
      };
    },
  };
}

