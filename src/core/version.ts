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

export function getVersionInfo(): VersionInfo {
  return {
    name: "osed-windbg",
    version: __OSED_VERSION__,
    buildTime: __OSED_BUILD_TIME__,
    gitCommit: __OSED_GIT_COMMIT__,
    gitDirty: __OSED_GIT_DIRTY__,
  };
}

