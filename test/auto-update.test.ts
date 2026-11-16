import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CHECK_INTERVAL_MS,
  checkAndUpdate,
  compareVersions,
  defaultStateFile,
  readInstalledVersion,
  resolveHostEntry,
  type UpdateOptions,
} from "../src/auto-update.js";

let dir: string;
let stateFile: string;
const NOW = 1_800_000_000_000;
const GATEWAY_ARGV = ["/usr/bin/node", "/opt/openclaw/openclaw.mjs", "gateway"];

function registry(latest: unknown, status = 200) {
  return vi.fn(async () => new Response(JSON.stringify({ latest }), { status })) as unknown as typeof fetch;
}

function options(overrides: Partial<UpdateOptions> = {}): UpdateOptions {
  return {
    env: {},
    argv: GATEWAY_ARGV,
    execPath: "/usr/bin/node",
    now: NOW,
    installedVersion: "2026.8.5",
    hostEntry: "/opt/openclaw/openclaw.mjs",
    stateFile,
    fetchImpl: registry("2026.8.6"),
    spawnUpdate: vi.fn(),
    logger: { info: vi.fn(), warn: vi.fn() },
    ...overrides,
  };
}

beforeEach(async () => {
  dir = await fs.mkdtemp(join(tmpdir(), "armorclaw-update-"));
  stateFile = join(dir, "state", "update-check.json");
});

afterEach(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

describe("checkAndUpdate", () => {
  it("hands a newer release to `openclaw plugins update armorclaw`", async () => {
    const opts = options();
    const outcome = await checkAndUpdate(opts);
    expect(outcome).toEqual({ kind: "updating", installed: "2026.8.5", latest: "2026.8.6" });
    expect(opts.spawnUpdate).toHaveBeenCalledWith(
      "/usr/bin/node",
      ["/opt/openclaw/openclaw.mjs", "plugins", "update", "armorclaw"],
      {},
    );
    expect(opts.logger!.info).toHaveBeenCalledWith(expect.stringContaining("2026.8.6 is available"));
  });

  it("does nothing when the registry has the running version or an older one", async () => {
    for (const latest of ["2026.8.5", "2026.8.4"]) {
      await fs.rm(stateFile, { force: true });
      const opts = options({ fetchImpl: registry(latest) });
      expect((await checkAndUpdate(opts)).kind).toBe("current");
      expect(opts.spawnUpdate).not.toHaveBeenCalled();
    }
  });

  it("checks at most once a day, including after a failed request", async () => {
    const failing = options({ fetchImpl: registry("x", 503) });
    expect((await checkAndUpdate(failing)).kind).toBe("failed");

    const soon = options({ now: NOW + CHECK_INTERVAL_MS - 1 });
    expect(await checkAndUpdate(soon)).toEqual({ kind: "skipped", reason: "interval" });
    expect(soon.fetchImpl).not.toHaveBeenCalled();

    const later = options({ now: NOW + CHECK_INTERVAL_MS });
    expect((await checkAndUpdate(later)).kind).toBe("updating");
  });

  it("ignores a last-check timestamp from the future", async () => {
    await checkAndUpdate(options({ now: NOW + 10 * CHECK_INTERVAL_MS, fetchImpl: registry("2026.8.5") }));
    expect((await checkAndUpdate(options())).kind).toBe("updating");
  });

  it("respects ARMORCLAW_NO_AUTO_UPDATE=1", async () => {
    const opts = options({ env: { ARMORCLAW_NO_AUTO_UPDATE: "1" } });
    expect(await checkAndUpdate(opts)).toEqual({ kind: "skipped", reason: "opted_out" });
    expect(opts.fetchImpl).not.toHaveBeenCalled();
  });

  it("only starts an update from the gateway, never from the update command it spawns", async () => {
    const opts = options({ argv: ["/usr/bin/node", "/opt/openclaw/openclaw.mjs", "plugins", "update", "armorclaw"] });
    expect(await checkAndUpdate(opts)).toEqual({ kind: "skipped", reason: "not_gateway" });
    expect(opts.fetchImpl).not.toHaveBeenCalled();
  });

  it("asks the registry named by npm_config_registry", async () => {
    const opts = options({ env: { npm_config_registry: "http://127.0.0.1:4873/" } });
    await checkAndUpdate(opts);
    expect(opts.fetchImpl).toHaveBeenCalledWith(
      "http://127.0.0.1:4873/-/package/%40armoriq%2Farmorclaw/dist-tags",
      expect.anything(),
    );
  });

  it("skips without an installed version or a resolvable OpenClaw entry", async () => {
    expect(await checkAndUpdate(options({ installedVersion: null }))).toEqual({ kind: "skipped", reason: "no_version" });
    expect(await checkAndUpdate(options({ hostEntry: null }))).toEqual({ kind: "skipped", reason: "no_host_entry" });
  });

  it("never throws, even when spawning or logging throws", async () => {
    const opts = options({
      spawnUpdate: () => {
        throw new Error("spawn EACCES");
      },
      logger: {
        info: vi.fn(),
        warn: () => {
          throw new Error("logger gone");
        },
      },
    });
    await expect(checkAndUpdate(opts)).resolves.toMatchObject({ kind: "failed" });
  });

  it("leaves a prerelease on latest alone, as OpenClaw refuses to install one from there", async () => {
    const opts = options({ fetchImpl: registry("2026.8.6-beta.1") });
    expect((await checkAndUpdate(opts)).kind).toBe("prerelease");
    expect(opts.spawnUpdate).not.toHaveBeenCalled();
  });

  it("installs a stable correction release such as 2026.8.5-1", async () => {
    const opts = options({ fetchImpl: registry("2026.8.5-1") });
    expect(await checkAndUpdate(opts)).toEqual({ kind: "updating", installed: "2026.8.5", latest: "2026.8.5-1" });
    expect(opts.spawnUpdate).toHaveBeenCalledTimes(1);
  });

  it("treats an unreadable registry version as a failure, not as current", async () => {
    const opts = options({ fetchImpl: registry("latest-ish") });
    expect((await checkAndUpdate(opts)).kind).toBe("failed");
    expect(opts.spawnUpdate).not.toHaveBeenCalled();
  });
});

describe("compareVersions", () => {
  it("orders calendar versions and prereleases", () => {
    expect(compareVersions("2026.10.0", "2026.8.5")).toBe(1);
    expect(compareVersions("2026.8.5", "2026.8.5")).toBe(0);
    expect(compareVersions("2026.8.6-beta.1", "2026.8.6")).toBe(-1);
    expect(compareVersions("not-a-version", "2026.8.5")).toBeNull();
  });

  it("sorts OpenClaw stable corrections after their base and by correction number", () => {
    expect(compareVersions("2026.8.5-1", "2026.8.5")).toBe(1);
    expect(compareVersions("2026.8.5-10", "2026.8.5-2")).toBe(1);
    expect(compareVersions("2026.8.5-1", "2026.8.5-beta.3")).toBe(1);
    expect(compareVersions("2026.8.6", "2026.8.5-3")).toBe(1);
  });

  it("orders prerelease identifiers by SemVer precedence", () => {
    expect(compareVersions("2026.8.6-beta.10", "2026.8.6-beta.2")).toBe(1);
    expect(compareVersions("2026.8.6-alpha.1", "2026.8.6-beta.1")).toBe(-1);
  });
});

describe("defaultStateFile", () => {
  it("expands ~ in OPENCLAW_STATE_DIR against the home", () => {
    expect(defaultStateFile({ HOME: "/home/u", OPENCLAW_STATE_DIR: "~/oc" })).toBe("/home/u/oc/armorclaw/update-check.json");
  });

  it("honors OPENCLAW_HOME before HOME", () => {
    expect(defaultStateFile({ HOME: "/home/u", OPENCLAW_HOME: "/srv/claw" })).toBe(
      "/srv/claw/.openclaw/armorclaw/update-check.json",
    );
    expect(defaultStateFile({ HOME: "/home/u", OPENCLAW_HOME: "~/alt", OPENCLAW_STATE_DIR: "~/state" })).toBe(
      "/home/u/alt/state/armorclaw/update-check.json",
    );
  });

  it("defaults to ~/.openclaw", () => {
    expect(defaultStateFile({ HOME: "/home/u" })).toBe("/home/u/.openclaw/armorclaw/update-check.json");
  });
});

describe("install discovery", () => {
  it("reads the version from the package the module was loaded from", async () => {
    const root = join(dir, "node_modules", "@armoriq", "armorclaw");
    await fs.mkdir(join(root, "dist", "src"), { recursive: true });
    await fs.writeFile(join(root, "package.json"), JSON.stringify({ name: "@armoriq/armorclaw", version: "2026.9.1" }));
    const moduleUrl = pathToFileURL(join(root, "dist", "src", "auto-update.js")).href;
    expect(readInstalledVersion(moduleUrl)).toBe("2026.9.1");
  });

  it("resolves the OpenClaw bin from the gateway's argv[1]", async () => {
    const root = join(dir, "openclaw");
    await fs.mkdir(join(root, "dist"), { recursive: true });
    await fs.writeFile(join(root, "package.json"), JSON.stringify({ name: "openclaw", bin: { openclaw: "openclaw.mjs" } }));
    await fs.writeFile(join(root, "openclaw.mjs"), "");
    await fs.writeFile(join(root, "dist", "entry.js"), "");
    const real = await fs.realpath(root);
    expect(resolveHostEntry(join(root, "dist", "entry.js"))).toBe(join(real, "openclaw.mjs"));
    expect(resolveHostEntry(join(dir, "nowhere.js"))).toBeNull();
  });
});
