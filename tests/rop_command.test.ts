import { describe, expect, test } from "vitest";
import { createRopCommands } from "../src/commands/rop";

describe("rop_suggest command", () => {
  test("exposes an engine option with legacy and semantic modes", () => {
    const ropSuggest = createRopCommands().find((command) => command.name === "rop_suggest");

    expect(ropSuggest).toBeDefined();
    expect(ropSuggest?.schema.engine).toEqual({
      type: "string",
      enum: ["legacy", "semantic"],
      default: "legacy",
    });
    expect(ropSuggest?.examples).toContain("dx @$osed.rop_suggest({ module: 'essfunc', engine: 'semantic' })");
  });
});
