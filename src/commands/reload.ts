import { Command, CommandRegistry, CommandResult } from "../core/registry";
import * as out from "../core/output";

export function createReloadCommand(registry: CommandRegistry): Command {
  return {
    name: "reload",
    description: "Clear and re-register command registry.",
    usage: "dx @$osed.reload({})",
    examples: ["dx @$osed.reload({})", "dx @$osed.reload({})"],
    schema: {},
    execute(options: Record<string, unknown>): CommandResult {
      const result = registry.reload();
      result.args = options;
      out.section("Reload");
      if (result.success) {
        out.info(`Re-registered ${((result.findings[0] as { commandCount: number })?.commandCount ?? 0)} commands.`);
      } else {
        for (const err of result.errors) {
          out.error(err);
        }
      }
      out.whyItMatters("Fast in-session reload shortens debug-iterate-test cycles.");
      return result;
    },
  };
}
