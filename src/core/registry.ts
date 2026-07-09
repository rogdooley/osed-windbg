import { error as printError } from "./output";
import { ObjectSchema, validateOptions } from "./validation";

export type ValidationFlags = {
  executable: boolean;
  moduleBacked: boolean;
  decoded: boolean;
  badcharSafe: boolean;
  mnemonicMatch?: boolean;
};

export type CommandResult = {
  command: string;
  args: Record<string, unknown>;
  success: boolean;
  findings: unknown[];
  warnings: string[];
  errors: string[];
  stats?: Record<string, number>;
  schema?: Record<string, unknown>;
};

export type Command = {
  name: string;
  description: string;
  usage: string;
  examples: string[];
  schema: ObjectSchema;
  execute(options: Record<string, unknown>): CommandResult;
};

export class CommandRegistry {
  private readonly commands = new Map<string, Command>();
  private reloader?: () => void;

  register(command: Command): void {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(command.name)) {
      throw new Error(`Invalid command name '${command.name}'.`);
    }

    this.commands.set(command.name, command);
  }

  getAll(): Command[] {
    return [...this.commands.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  get(name: string): Command | undefined {
    return this.commands.get(name);
  }

  clear(): void {
    this.commands.clear();
  }

  setReloader(reloader: () => void): void {
    this.reloader = reloader;
  }

  reload(): CommandResult {
    if (!this.reloader) {
      return this.failure("reload", {}, "Reload hook is not configured.");
    }

    this.clear();
    this.reloader();

    return {
      command: "reload",
      args: {},
      success: true,
      findings: [{ commandCount: this.getAll().length }],
      warnings: [],
      errors: [],
    };
  }

  execute(name: string, options: unknown): CommandResult {
    const command = this.commands.get(name);
    if (!command) {
      return this.failure(name, {}, `Unknown command '${name}'.`);
    }

    const checked = validateOptions(options ?? {}, command.schema);
    if (!checked.success || !checked.value) {
      const errors = checked.errors.map((issue) => `${issue.path}: ${issue.message}`);
      return {
        command: name,
        args: {},
        success: false,
        findings: [],
        warnings: checked.warnings,
        errors,
        schema: command.schema as Record<string, unknown>,
      };
    }

    try {
      const result = command.execute(checked.value);
      result.warnings = [...checked.warnings, ...result.warnings];
      return result;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : String(caught);
      printError(`Command failed: ${message}`);
      return this.failure(name, checked.value, message);
    }
  }

  private failure(name: string, args: Record<string, unknown>, message: string): CommandResult {
    return {
      command: name,
      args,
      success: false,
      findings: [],
      warnings: [],
      errors: [message],
    };
  }
}
