declare const __OSED_VERSION__: string;
declare const __OSED_BUILD_TIME__: string;
declare const __OSED_GIT_COMMIT__: string;
declare const __OSED_GIT_DIRTY__: boolean;

export type VersionInfo = {
  name: string;
  version: string;
  buildTime: string;
  gitCommit: string;
  gitDirty: boolean;
};

function readBuildString(key: "__OSED_VERSION__" | "__OSED_BUILD_TIME__" | "__OSED_GIT_COMMIT__", fallback: string): string {
  const value = (globalThis as Record<string, unknown>)[key];
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function readBuildBoolean(key: "__OSED_GIT_DIRTY__", fallback: boolean): boolean {
  const value = (globalThis as Record<string, unknown>)[key];
  return typeof value === "boolean" ? value : fallback;
}

export function getVersionInfo(): VersionInfo {
  return {
    name: "osed-windbg",
    version: readBuildString("__OSED_VERSION__", "dev"),
    buildTime: readBuildString("__OSED_BUILD_TIME__", "unknown"),
    gitCommit: readBuildString("__OSED_GIT_COMMIT__", "unknown"),
    gitDirty: readBuildBoolean("__OSED_GIT_DIRTY__", false),
  };
}
