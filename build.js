const esbuild = require("esbuild");
const { execSync } = require("child_process");
const pkg = require("./package.json");

function readGitValue(command, fallback) {
  try {
    return execSync(command, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || fallback;
  } catch (_error) {
    return fallback;
  }
}

const gitCommit = readGitValue("git rev-parse --short=12 HEAD", "unknown");
const gitStatus = readGitValue("git status --porcelain", "");

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
    define: {
      __OSED_VERSION__: JSON.stringify(pkg.version),
      __OSED_BUILD_TIME__: JSON.stringify(new Date().toISOString()),
      __OSED_GIT_COMMIT__: JSON.stringify(gitCommit),
      __OSED_GIT_DIRTY__: JSON.stringify(gitStatus.length > 0),
    },
    logLevel: "info",
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
