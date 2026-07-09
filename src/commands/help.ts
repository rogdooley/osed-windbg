import { Command, CommandRegistry, CommandResult } from "../core/registry";
import * as out from "../core/output";

export function createHelpCommand(registry: CommandRegistry): Command {
  return {
    name: "help",
    description: "List commands or show detailed command help.",
    usage: "dx @$osed.help({ command: 'badchars' })",
    examples: ["dx @$osed.help({})", "dx @$osed.help({ command: 'badchars' })"],
    schema: {
      command: { type: "string" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const commandName = options.command as string | undefined;

      if (!commandName) {
        const commands = registry.getAll();
        out.section("OSED Commands");
        out.table(
          [
            { key: "name", header: "Command", width: 16 },
            { key: "description", header: "Description", width: 40 },
          ],
          commands.map((command) => ({ name: command.name, description: command.description })),
        );
        out.whyItMatters("Fast command discovery lowers debugger friction during exploit iteration.");

        return {
          command: "help",
          args: options,
          success: true,
          findings: commands.map((command) => ({
            name: command.name,
            description: command.description,
            usage: command.usage,
            examples: command.examples,
            schema: command.schema,
          })),
          warnings: [],
          errors: [],
          schema: {
            command: { type: "string", optional: true },
          },
        };
      }

      const command = registry.get(commandName);
      if (!command) {
        return {
          command: "help",
          args: options,
          success: false,
          findings: [],
          warnings: [],
          errors: [`Unknown command '${commandName}'.`],
        };
      }

      out.section(`Help: ${command.name}`);
      out.info(command.description);
      out.info(`Usage: ${command.usage}`);
      for (const example of command.examples) {
        out.print(`  ${example}`);
      }
      out.whyItMatters("Inline help prevents context switching and keeps exploit workflow focused.");

      return {
        command: "help",
        args: options,
        success: true,
        findings: [
          {
            name: command.name,
            description: command.description,
            usage: command.usage,
            examples: command.examples,
            schema: command.schema,
          },
        ],
        warnings: [],
        errors: [],
        schema: command.schema as Record<string, unknown>,
      };
    },
  };
}
