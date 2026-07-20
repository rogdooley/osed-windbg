import { Command, CommandRegistry, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { findHelpEntry, helpRows, NAMESPACE_HELP_ENTRIES } from "../core/help_catalog";

export function createHelpCommand(registry: CommandRegistry): Command {
  return {
    name: "help",
    description: "List commands or show detailed command help.",
    usage: "dx @$osed().help(command?)",
    examples: ["dx @$osed().help()", "dx @$osed().help(\"badchars\")", "dx @$osed().help(\"sc.iat\")"],
    schema: {
      command: { type: "string" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const commandName = options.command as string | undefined;

      if (!commandName) {
        const commands = registry.getAll().filter((command) => command.name !== "rop");
        out.section("OSED Commands");
        out.table(
          [
            { key: "name", header: "Command", width: 16 },
            { key: "description", header: "Description", width: 40 },
          ],
          commands.map((command) => ({ name: command.name, description: command.description })),
        );
        const groups = new Map<string, typeof NAMESPACE_HELP_ENTRIES>();
        for (const entry of NAMESPACE_HELP_ENTRIES) {
          const group = entry.name.includes(".") ? entry.name.split(".")[0] : "other";
          groups.set(group, [...(groups.get(group) ?? []), entry]);
        }
        for (const [group, entries] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
          out.section(`${group} Namespace Helpers`);
          out.table(
            [
              { key: "name", header: "Helper", width: 22 },
              { key: "description", header: "Description", width: 56 },
            ],
            entries.map((entry) => ({ name: entry.name, description: entry.description })),
          );
        }
        out.info("Use help(\"name\") for details, e.g. dx @$osed().help(\"sc.iat\").");
        out.info("Most helpers also accept \"help\" as the first argument, e.g. dx @$osed().sc.iat(\"help\").");
        out.whyItMatters("Fast command discovery lowers debugger friction during exploit iteration.");

        return {
          command: "help",
          args: options,
          success: true,
          findings: [
            ...commands.map((command) => ({
              name: command.name,
              description: command.description,
              usage: command.usage,
              examples: command.examples,
              schema: command.schema,
            })),
            ...NAMESPACE_HELP_ENTRIES,
          ],
          warnings: [],
          errors: [],
          schema: {
            command: { type: "string", optional: true },
          },
        };
      }

      const command = registry.get(commandName);
      const helper = findHelpEntry(commandName === "rop" ? "rop.find" : commandName);
      if (!command && !helper) {
        return {
          command: "help",
          args: options,
          success: false,
          findings: [],
          warnings: [],
          errors: [`Unknown command '${commandName}'.`],
        };
      }

      if (helper) {
        out.section(`Help: ${helper.name}`);
        out.info(helper.description);
        out.info(`Usage: ${helper.usage}`);
        for (const example of helper.examples) {
          out.print(`  ${example}`);
        }
        out.whyItMatters("Inline helper documentation keeps namespace workflows discoverable at the debugger prompt.");

        return {
          command: "help",
          args: options,
          success: true,
          findings: helpRows(helper),
          warnings: [],
          errors: [],
        };
      }

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
