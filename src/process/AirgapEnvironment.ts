/**
 * Utilities for enforcing 100% offline, deterministic, airgapped subprocess execution.
 * Prevents tools (gcc, binutils, readelf, gdb, objdump) from querying remote symbol servers
 * (such as debuginfod) or relying on ambient locale/timezone/network configurations.
 */

export const AIRGAP_PROCESS_ENV: Readonly<Record<string, string>> =
  Object.freeze({
    DEBUGINFOD_URLS: "",
    DEBUGINFOD_TIMEOUT: "0",
    DEBUGINFOD_MAX_RETRIES: "0",
    DEBUGINFOD_CACHE_PATH: "/dev/null",
    DEBUGINFOD_PROGRESS: "0",
    DEBUGINFOD_VERBOSE: "0",
    LC_ALL: "C",
    TZ: "UTC",
    SOURCE_DATE_EPOCH: "0",
    http_proxy: "",
    https_proxy: "",
    all_proxy: "",
    no_proxy: "*",
    HTTP_PROXY: "",
    HTTPS_PROXY: "",
    ALL_PROXY: "",
    NO_PROXY: "*",
  });

/**
 * Creates an airgapped environment dictionary suitable for `execFile` options.
 */
export const createAirgapEnv = (
  baseEnv: NodeJS.ProcessEnv = process.env,
  customOverrides?: Record<string, string>,
): Record<string, string> => {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(baseEnv)) {
    if (value !== undefined) {
      result[key] = value;
    }
  }
  Object.assign(result, AIRGAP_PROCESS_ENV);
  if (customOverrides) {
    Object.assign(result, customOverrides);
  }
  return result;
};
