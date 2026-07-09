const esbuild = require("esbuild");

esbuild
  .build({
    entryPoints: ["src/index.ts"],
    outfile: "dist/osed.js",
    bundle: true,
    platform: "neutral",
    target: ["es2017"],
    format: "iife",
    globalName: "osed_bundle",
    footer: {
      js: [
        "var __osed_global = (typeof globalThis !== 'undefined') ? globalThis : (typeof self !== 'undefined' ? self : (typeof this !== 'undefined' ? this : undefined));",
        "if (__osed_global && __osed_global.osed_bundle && __osed_global.osed_bundle.initializeScript) { __osed_global.initializeScript = __osed_global.osed_bundle.initializeScript; }",
      ].join("\n"),
    },
    sourcemap: false,
    external: [],
    logLevel: "info",
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
