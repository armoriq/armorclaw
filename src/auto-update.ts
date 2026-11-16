import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PACKAGE_NAME = "@armoriq/armorclaw";
export const PLUGIN_ID = "armorclaw";
export const OPT_OUT_ENV = "ARMORCLAW_NO_AUTO_UPDATE";
export const DEFAULT_REGISTRY = "https://registry.npmjs.org";
export const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
export const CHECK_TIMEOUT_MS = 5_000;

export type Logger = {
  info: (message: string) => void;
  warn: (message: string) => void;
};

export type UpdateOutcome =
  | { kind: "skipped"; reason: "opted_out" | "not_gateway" | "interval" | "no_version" | "no_host_entry" }
  | { kind: "current"; installed: string; latest: string }
  | { kind: "prerelease"; installed: string; latest: string }
  | { kind: "updating"; installed: string; latest: string }
  | { kind: "failed"; reason: string };

export type SpawnUpdate = (command: string, args: string[], env: NodeJS.ProcessEnv) => void;

export type UpdateOptions = {
  logger?: Logger;
  env?: NodeJS.ProcessEnv;
  argv?: string[];
  execPath?: string;
  now?: number;
  installedVersion?: string | null;
  hostEntry?: string | null;
  stateFile?: string;
  fetchImpl?: typeof fetch;
  spawnUpdate?: SpawnUpdate;
};

type Parsed = { core: [number, number, number]; prerelease: string };

function parseVersion(value: string): Parsed | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(value.trim());
  if (!m) return null;
  return { core: [Number(m[1]), Number(m[2]), Number(m[3])], prerelease: m[4] ?? "" };
}

// Null means at least one side is not a version, which must not read as "not newer".
export function compareVersions(a: string, b: string): number | null {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return null;
  for (let i = 0; i < 3; i++) {
    const diff = left.core[i]! - right.core[i]!;
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  if (left.prerelease === right.prerelease) return 0;
  const leftRank = channelRank(left.prerelease);
  const rightRank = channelRank(right.prerelease);
  if (leftRank !== rightRank) return leftRank < rightRank ? -1 : 1;
  if (leftRank === 2) return Number(left.prerelease) < Number(right.prerelease) ? -1 : 1;
  return comparePrerelease(left.prerelease.split("."), right.prerelease.split("."));
}

// OpenClaw versions YYYY.M.P-N are stable corrections that sort after YYYY.M.P
// (isOpenClawStableCorrectionVersion in OpenClaw's src/infra/npm-registry-spec.ts), not prereleases.
export function isCorrection(prerelease: string): boolean {
  return /^[1-9]\d*$/.test(prerelease);
}

function channelRank(prerelease: string): number {
  if (prerelease === "") return 1;
  return isCorrection(prerelease) ? 2 : 0;
}

// SemVer precedence: numeric identifiers compare as numbers and sort below alphanumeric ones.
function comparePrerelease(a: string[], b: string[]): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const x = a[i]!;
    const y = b[i]!;
    if (x === y) continue;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) return Number(x) < Number(y) ? -1 : 1;
    if (xn !== yn) return xn ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

function findPackageJson(start: string, name: string): string | null {
  let dir = start;
  for (let i = 0; i < 8; i++) {
    const candidate = path.join(dir, "package.json");
    try {
      const parsed = JSON.parse(fs.readFileSync(candidate, "utf8")) as { name?: unknown };
      if (parsed.name === name) return candidate;
    } catch {}
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

// Read from the installed package, so the comparison follows whatever npm actually put on disk.
export function readInstalledVersion(moduleUrl: string = import.meta.url): string | null {
  try {
    const file = findPackageJson(path.dirname(fileURLToPath(moduleUrl)), PACKAGE_NAME);
    if (!file) return null;
    const version = (JSON.parse(fs.readFileSync(file, "utf8")) as { version?: unknown }).version;
    return typeof version === "string" && version !== "" ? version : null;
  } catch {
    return null;
  }
}

// OpenClaw finds its own package root from argv[1] the same way (src/infra/openclaw-root.ts).
export function resolveHostEntry(argv1: string | undefined): string | null {
  if (!argv1) return null;
  try {
    const file = findPackageJson(path.dirname(fs.realpathSync(argv1)), "openclaw");
    if (!file) return null;
    const pkg = JSON.parse(fs.readFileSync(file, "utf8")) as { bin?: unknown };
    const bin = typeof pkg.bin === "string" ? pkg.bin : (pkg.bin as Record<string, unknown> | undefined)?.openclaw;
    if (typeof bin !== "string") return null;
    const entry = path.resolve(path.dirname(file), bin);
    return fs.existsSync(entry) ? entry : null;
  } catch {
    return null;
  }
}

function expandHome(input: string, home: string): string {
  if (input === "~") return home;
  if (input.startsWith("~/") || input.startsWith("~\\")) return path.join(home, input.slice(2));
  return path.resolve(input);
}

// Mirrors OpenClaw's resolveStateDir: OPENCLAW_HOME before HOME, and ~ expanded in either override.
export function defaultStateFile(env: NodeJS.ProcessEnv): string {
  const osHome = env.HOME?.trim() || os.homedir();
  const openclawHome = env.OPENCLAW_HOME?.trim();
  const home = openclawHome ? expandHome(openclawHome, osHome) : osHome;
  const override = env.OPENCLAW_STATE_DIR?.trim();
  const stateDir = override ? expandHome(override, home) : path.join(home, ".openclaw");
  return path.join(stateDir, "armorclaw", "update-check.json");
}

function readLastCheckedAt(file: string): number | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as { lastCheckedAt?: unknown };
    return typeof parsed.lastCheckedAt === "number" ? parsed.lastCheckedAt : null;
  } catch {
    return null;
  }
}

function writeState(file: string, state: Record<string, unknown>): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

async function latestVersion(env: NodeJS.ProcessEnv, fetchImpl: typeof fetch): Promise<string> {
  const registry = (env.npm_config_registry?.trim() || DEFAULT_REGISTRY).replace(/\/+$/, "");
  const response = await fetchImpl(`${registry}/-/package/${encodeURIComponent(PACKAGE_NAME)}/dist-tags`, {
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(CHECK_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`dist-tags returned ${response.status}`);
  const latest = ((await response.json()) as { latest?: unknown }).latest;
  if (typeof latest !== "string" || latest === "") throw new Error("dist-tags has no latest");
  return latest;
}

// The logger belongs to the host, so a throw there must not escape into it or undo an outcome.
function log(logger: Logger | undefined, level: "info" | "warn", message: string): void {
  try {
    logger?.[level](message);
  } catch {}
}

const defaultSpawn: SpawnUpdate = (command, args, env) => {
  const child = spawn(command, args, { detached: true, stdio: "ignore", env });
  child.on("error", () => {});
  child.unref();
};

/**
 * Asks npm for a newer release and, when there is one, hands the install to OpenClaw's own
 * `plugins update`, which replaces the installed package. The running gateway keeps the code it
 * loaded, so the new version takes effect at the next gateway start.
 */
export async function checkAndUpdate(opts: UpdateOptions = {}): Promise<UpdateOutcome> {
  const env = opts.env ?? process.env;
  try {
    if (env[OPT_OUT_ENV] === "1") return { kind: "skipped", reason: "opted_out" };
    const argv = opts.argv ?? process.argv;
    // The spawned `plugins update` loads plugins too; only the gateway may start an update.
    if (!argv.slice(2).includes("gateway")) return { kind: "skipped", reason: "not_gateway" };

    const now = opts.now ?? Date.now();
    const stateFile = opts.stateFile ?? defaultStateFile(env);
    const last = readLastCheckedAt(stateFile);
    // A timestamp in the future comes from a clock change and would otherwise suppress every check.
    if (last !== null && last <= now && now - last < CHECK_INTERVAL_MS) return { kind: "skipped", reason: "interval" };

    const installed = opts.installedVersion === undefined ? readInstalledVersion() : opts.installedVersion;
    if (!installed) return { kind: "skipped", reason: "no_version" };
    const hostEntry = opts.hostEntry === undefined ? resolveHostEntry(argv[1]) : opts.hostEntry;
    if (!hostEntry) return { kind: "skipped", reason: "no_host_entry" };

    // Recorded before the request, so an offline gateway or a failing update does not retry every start.
    writeState(stateFile, { lastCheckedAt: now });
    const latest = await latestVersion(env, opts.fetchImpl ?? fetch);
    writeState(stateFile, { lastCheckedAt: now, latest });
    const order = compareVersions(latest, installed);
    if (order === null) return { kind: "failed", reason: `unreadable version ${latest} or ${installed}` };
    if (order <= 0) return { kind: "current", installed, latest };
    // `plugins update` refuses a prerelease reached through latest, so asking it would only fail daily.
    const pre = parseVersion(latest)?.prerelease;
    if (pre && !isCorrection(pre)) return { kind: "prerelease", installed, latest };

    (opts.spawnUpdate ?? defaultSpawn)(opts.execPath ?? process.execPath, [hostEntry, "plugins", "update", PLUGIN_ID], env);
    log(opts.logger, "info", `armoriq: ArmorClaw ${latest} is available (running ${installed}); installing it, it loads at the next gateway start`);
    return { kind: "updating", installed, latest };
  } catch (error) {
    log(opts.logger, "warn", `armoriq: update check failed: ${String(error)}`);
    return { kind: "failed", reason: String(error) };
  }
}

let started = false;

// register() runs once per agent scope; the check runs once per process and is never awaited.
export function startAutoUpdate(opts: UpdateOptions = {}): void {
  if (started) return;
  started = true;
  void checkAndUpdate(opts).catch(() => {});
}
