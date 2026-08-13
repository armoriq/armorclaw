import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The recorder is faked so these tests assert what ArmorClaw sends, not what
 * the SDK does with it. The product tag and the allow/deny mapping are the two
 * things the dashboard depends on, so both are pinned here.
 */
const calls: Array<{ method: string; args: unknown[] }> = [];
let constructedWith: Record<string, unknown> | null = null;

class FakeRecorder {
  constructor(config: Record<string, unknown>) {
    constructedWith = config;
  }
  startTrace(name: string, attributes?: Record<string, unknown>) {
    calls.push({ method: "startTrace", args: [name, attributes] });
    return { traceId: "t-1", sessionId: null } as never;
  }
  recordEvent(_ctx: unknown, attrs: unknown) {
    calls.push({ method: "recordEvent", args: [attrs] });
    return {} as never;
  }
  recordPolicyCall(_ctx: unknown, attrs: unknown) {
    calls.push({ method: "recordPolicyCall", args: [attrs] });
    return {} as never;
  }
  endTrace(_ctx: unknown, opts?: unknown) {
    calls.push({ method: "endTrace", args: [opts] });
  }
  async flush() {
    calls.push({ method: "flush", args: [] });
    return { accepted: 1, rejected: 0 };
  }
}

vi.mock("@armoriq/sdk", () => ({
  ObservabilityRecorder: FakeRecorder,
  isValidUuid: (v: string) =>
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v),
}));

const { createObservability, OBSERVABILITY_PRODUCT } = await import("../src/observability.js");

const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };

function make(overrides: Record<string, unknown> = {}) {
  return createObservability({
    enabled: true,
    backendEndpoint: "https://api.armoriq.ai",
    apiKey: "ak_live_test",
    userId: "dev@armoriq.io",
    agentId: "openclaw-agent-001",
    logger,
    ...overrides,
  } as never);
}

describe("armorclaw observability", () => {
  beforeEach(() => {
    calls.length = 0;
    constructedWith = null;
    logger.warn.mockReset();
  });

  it("is inert when disabled", async () => {
    const obs = make({ enabled: false });
    expect(obs.active).toBe(false);
    obs.startRun("run-1", "hello");
    obs.recordToolDecision("run-1", "bash", { allowed: false, reason: "drift" });
    await obs.endRun("run-1");
    expect(calls).toHaveLength(0);
  });

  it("is inert without an API key, since nothing could be attributed", () => {
    expect(make({ apiKey: "" }).active).toBe(false);
  });

  it("tags every trace with the armorclaw product", () => {
    make().startRun("run-1", "list /tmp");
    expect(constructedWith?.product).toBe("armorclaw");
    expect(OBSERVABILITY_PRODUCT).toBe("armorclaw");
  });

  it("sends a non-UUID userId as null but keeps the logical agentId", () => {
    make().startRun("run-1", "x");
    // userId is a UUID column on the backend; agentId is free-form text.
    expect(constructedWith?.userId).toBeNull();
    expect(constructedWith?.agentId).toBe("openclaw-agent-001");
  });

  it("passes a real UUID userId through", () => {
    make({ userId: "a837a53e-c872-4d95-8074-349b0f46fc9a" }).startRun("run-1", "x");
    expect(constructedWith?.userId).toBe("a837a53e-c872-4d95-8074-349b0f46fc9a");
  });

  it("records an allowed tool call as an allow decision", () => {
    const obs = make();
    obs.startRun("run-1", "x");
    obs.recordToolDecision("run-1", "bash", { allowed: true, reason: null });
    const call = calls.find((c) => c.method === "recordPolicyCall");
    expect((call?.args[0] as any).decision).toBe("allow");
    expect((call?.args[0] as any).enforcementAction).toBe("allow");
  });

  it("records a blocked tool call as a deny carrying the block reason", () => {
    const obs = make();
    obs.startRun("run-1", "x");
    obs.recordToolDecision("run-1", "send_email", {
      allowed: false,
      reason: "ArmorIQ intent drift: tool not in plan (send_email)",
    });
    const attrs = calls.find((c) => c.method === "recordPolicyCall")?.args[0] as any;
    expect(attrs.decision).toBe("deny");
    expect(attrs.enforcementAction).toBe("block");
    expect(attrs.reason).toContain("intent drift");
    expect(attrs.input).toEqual({ tool: "send_email" });
  });

  it("collapses agent retries of the same refused tool into one span", () => {
    const obs = make();
    obs.startRun("run-1", "x");
    // The agent retried a blocked exec ten times in one turn; that produced ten
    // identical spans on the dashboard before this was deduped.
    for (let i = 0; i < 10; i++) {
      obs.recordToolDecision("run-1", "exec", {
        allowed: false,
        reason: "ArmorIQ intent drift: tool not in plan (exec)",
      });
    }
    expect(calls.filter((c) => c.method === "recordPolicyCall")).toHaveLength(1);
  });

  it("still records a genuinely different decision for the same tool", () => {
    const obs = make();
    obs.startRun("run-1", "x");
    obs.recordToolDecision("run-1", "exec", { allowed: false, reason: "drift" });
    obs.recordToolDecision("run-1", "exec", { allowed: true, reason: null });
    expect(calls.filter((c) => c.method === "recordPolicyCall")).toHaveLength(2);
  });

  it("ignores decisions for a run that was never started", () => {
    make().recordToolDecision("unknown-run", "bash", { allowed: true, reason: null });
    expect(calls.filter((c) => c.method === "recordPolicyCall")).toHaveLength(0);
  });

  it("ends and flushes the trace, marking a failed plan as an error", async () => {
    const obs = make();
    obs.startRun("run-1", "x");
    await obs.endRun("run-1", "error");
    expect((calls.find((c) => c.method === "endTrace")?.args[0] as any).status).toBe("error");
    expect(calls.some((c) => c.method === "flush")).toBe(true);
  });

  it("does not start the same run twice", () => {
    const obs = make();
    obs.startRun("run-1", "x");
    obs.startRun("run-1", "x");
    expect(calls.filter((c) => c.method === "startTrace")).toHaveLength(1);
  });

  it("never throws out of a hook when the recorder misbehaves", async () => {
    const obs = make();
    obs.startRun("run-1", "x");
    vi.spyOn(FakeRecorder.prototype, "recordPolicyCall").mockImplementationOnce(() => {
      throw new Error("boom");
    });
    expect(() =>
      obs.recordToolDecision("run-1", "bash", { allowed: true, reason: null }),
    ).not.toThrow();
    await expect(obs.endRun("run-1")).resolves.toBeUndefined();
  });
});
