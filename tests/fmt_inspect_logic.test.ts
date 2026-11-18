import { describe, expect, test } from "vitest";
import { analyzeFormatString } from "../src/commands/fmtstr";

describe("format inspection parser", () => {
  test("identifies disclosure and write conversions without treating %% as a specifier", () => {
    expect(analyzeFormatString("value=%08x ptr=%p str=%2$s count=%n %%")).toEqual([
      { token: "%08x", conversion: "x", disclosure: false, write: false },
      { token: "%p", conversion: "p", disclosure: true, write: false },
      { token: "%2$s", conversion: "s", disclosure: true, write: false },
      { token: "%n", conversion: "n", disclosure: true, write: true },
    ]);
  });
});
