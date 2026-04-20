import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import register from "./index.js";

const completeSimpleMock = vi.fn();
const fetchMock = vi.fn();
const ORIGINAL_ENV = { ...process.env };

vi.mock("@mariozechner/pi-ai", () => ({
  completeSimple: (...args: unknown[]) => completeSimpleMock(...args),
}));

vi.mock("@armoriq/sdk", () => ({
  ArmorIQClient: class {
    capturePlan(_llm: string, _prompt: string, plan: Record<string, unknown>) {
      return { plan, llm: _llm, prompt: _prompt, metadata: {} };
    }

    async getIntentToken() {
      return { expiresAt: Date.now() / 1000 + 60 };
    }
  },
}));

type HookName = "before_tool_call" | "agent_end" | "inbound_claim" | "before_prompt_build" | "llm_input";

function createApi(pluginConfig: Record<string, unknown>) {
  const handlers = new Map<string, Array<(event: any, ctx: any) => any>>();
  const tools: Array<(ctx: any) => any> = [];
  const api = {
    id: "armoriq",
    name: "ArmorIQ",
    source: "test",
    pluginConfig,
    logger: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
    runtime: {
      modelAuth: {
        resolveApiKeyForProvider: async () => ({ apiKey: "test-api-key" }),
      },
    },
    on: (name: string, handler: (event: any, ctx: any) => any) => {
      const list = handlers.get(name) ?? [];
      list.push(handler);
      handlers.set(name, list);
    },
    registerTool: (tool: any) => {
      const factory = typeof tool === "function" ? tool : () => tool;
      tools.push(factory);
    },
    resolvePath: (input: string) => input,
  };
  return { api, handlers, tools };
}

function createCtx(runId: string) {
  return {
    runId,
    sessionKey: "session:test",
    agentId: "agent-1",
  };
}

/** Fire inbound_claim to populate sender identity cache */
async function fireInboundClaim(handlers: Map<string, Array<(event: any, ctx: any) => any>>) {
  const handler = handlers.get("inbound_claim")?.[0];
  await handler?.(
    {
      content: "test",
      channel: "whatsapp",
      accountId: "acct-1",
      senderId: "sender-1",
      senderName: "Sender",
      senderUsername: "sender",
      conversationId: "session:test",
      isGroup: false,
    },
    { channelId: "whatsapp" },
  );
}

/** Fire llm_input to trigger plan generation */
async function fireLlmInput(
  handlers: Map<string, Array<(event: any, ctx: any) => any>>,
  runId: string,
  prompt = "Read a file",
  systemPrompt = "Available tools:\n- read: Read files\n- send_email: Send email\n- write_file: Write file",
) {
  const handler = handlers.get("llm_input")?.[0];
  await handler?.(
    {
      runId,
      sessionId: "session:test",
      provider: "test",
      model: "model",
      systemPrompt,
      prompt,
      historyMessages: [],
      imagesCount: 0,
    },
    { agentId: "agent-1", sessionKey: "session:test" },
  );
  // Wait for the planning promise to complete
  await new Promise((r) => setTimeout(r, 10));
}

describe("ArmorIQ plugin", () => {
  beforeEach(() => {
    completeSimpleMock.mockReset();
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    for (const key of Object.keys(process.env)) {
      if (!(key in ORIGINAL_ENV)) {
        delete process.env[key];
      }
    }
    for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
      if (value !== undefined) {
        process.env[key] = value;
      }
    }
    process.env.REQUIRE_CSRG_PROOFS = "false";
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("captures a plan via llm_input and allows matching tool calls", async () => {
    const { api, handlers } = createApi({
      enabled: true,
      apiKey: "ak_live_test",
      userId: "user-1",
      agentId: "agent-1",
    });
    register(api as any);

    completeSimpleMock.mockResolvedValue({
      content: JSON.stringify({
        steps: [{ action: "read", mcp: "openclaw" }],
        metadata: { goal: "read a file" },
      }),
    });

    await fireInboundClaim(handlers);
    await fireLlmInput(handlers, "run-allow", "Read a file", "- read: Read files");

    const ctx = createCtx("run-allow");
    const beforeToolCall = handlers.get("before_tool_call")?.[0];
    const result = await beforeToolCall?.({ toolName: "read", params: { path: "demo.txt" } }, ctx);
    expect(result?.block).not.toBe(true);
  });

  it("blocks when API key is missing", async () => {
    const { api, handlers } = createApi({
      enabled: true,
      userId: "user-1",
      agentId: "agent-1",
    });
    register(api as any);

    const ctx = createCtx("run-missing-key");
    const beforeToolCall = handlers.get("before_tool_call")?.[0];
    const result = await beforeToolCall?.({ toolName: "read", params: {} }, ctx);
    expect(result?.block).toBe(true);
    expect(result?.blockReason).toContain("API key missing");
  });

  it("allows tool calls when plan includes the tool", async () => {
    const { api, handlers } = createApi({
      enabled: true,
      apiKey: "ak_live_test",
      userId: "user-1",
      agentId: "agent-1",
    });
    register(api as any);

    completeSimpleMock.mockResolvedValue({
      content: JSON.stringify({
        steps: [{ action: "web_fetch", mcp: "openclaw" }],
        metadata: { goal: "fetch a URL" },
      }),
    });

    await fireInboundClaim(handlers);
    await fireLlmInput(handlers, "run-intent-header", "Fetch a URL");

    const ctx = createCtx("run-intent-header");
    const beforeToolCall = handlers.get("before_tool_call")?.[0];
    const result = await beforeToolCall?.(
      { toolName: "web_fetch", params: { url: "https://example.com" } },
      ctx,
    );
    expect(result?.block).not.toBe(true);
  });

  it("blocks tool calls when plan excludes the tool", async () => {
    const { api, handlers } = createApi({
      enabled: true,
      apiKey: "ak_live_test",
      userId: "user-1",
      agentId: "agent-1",
    });
    register(api as any);

    completeSimpleMock.mockResolvedValue({
      content: JSON.stringify({
        steps: [{ action: "read", mcp: "openclaw" }],
        metadata: { goal: "read a file" },
      }),
    });

    await fireInboundClaim(handlers);
    await fireLlmInput(handlers, "run-intent-block", "Read a file");

    const ctx = createCtx("run-intent-block");
    const beforeToolCall = handlers.get("before_tool_call")?.[0];
    const result = await beforeToolCall?.({ toolName: "web_fetch", params: {} }, ctx);
    expect(result?.block).toBe(true);
    expect(result?.blockReason).toContain("intent drift");
  });

  it("allows tool call when cached plan matches and token is valid", async () => {
    const { api, handlers } = createApi({
      enabled: true,
      apiKey: "ak_live_test",
      userId: "user-1",
      agentId: "agent-1",
      backendEndpoint: "https://iap.example",
    });
    register(api as any);

    completeSimpleMock.mockResolvedValue({
      content: JSON.stringify({
        steps: [{ action: "web_fetch", mcp: "openclaw" }],
        metadata: { goal: "fetch a URL" },
      }),
    });

    await fireInboundClaim(handlers);
    await fireLlmInput(handlers, "run-csrg-allow", "Fetch a URL");

    const ctx = createCtx("run-csrg-allow");
    const beforeToolCall = handlers.get("before_tool_call")?.[0];
    const result = await beforeToolCall?.(
      { toolName: "web_fetch", params: { url: "https://example.com" } },
      ctx,
    );
    expect(result?.block).not.toBe(true);
  });

  it("blocks policy updates when sender is not allowed", async () => {
    const { api, handlers } = createApi({
      enabled: true,
      apiKey: "ak_live_test",
      userId: "user-1",
      agentId: "agent-1",
      policyUpdateEnabled: true,
      policyUpdateAllowList: ["someone-else"],
    });
    register(api as any);

    await fireInboundClaim(handlers);
    const ctx = createCtx("run-policy-deny");
    const beforeToolCall = handlers.get("before_tool_call")?.[0];
    const result = await beforeToolCall?.({ toolName: "policy_update", params: {} }, ctx);
    expect(result?.block).toBe(true);
    expect(result?.blockReason).toContain("policy update denied");
  });

  it("applies policy updates and blocks PCI send_email", async () => {
    const dir = await fs.mkdtemp(join(tmpdir(), "armoriq-policy-"));
    const policyPath = join(dir, "policy.json");

    const { api, handlers, tools } = createApi({
      enabled: true,
      apiKey: "ak_live_test",
      userId: "user-1",
      agentId: "agent-1",
      policyUpdateEnabled: true,
      policyUpdateAllowList: ["sender-1"],
      policyStorePath: policyPath,
    });
    register(api as any);

    const policyToolFactory = tools.find((factory) => {
      const tool = factory({ agentId: "agent-1", sessionKey: "session:test" });
      return tool?.name === "policy_update";
    });
    expect(policyToolFactory).toBeTruthy();
    const policyTool = policyToolFactory?.({ agentId: "agent-1", sessionKey: "session:test" });
    if (!policyTool) {
      throw new Error("policy_update tool not registered");
    }

    const updateResult = await policyTool.execute("call-1", {
      update: {
        reason: "Block PCI in email",
        mode: "replace",
        rules: [
          {
            id: "deny_pci_email",
            action: "deny",
            tool: "send_email",
            dataClass: "PCI",
          },
        ],
      },
    });
    expect(updateResult?.details?.version).toBeGreaterThan(0);

    completeSimpleMock.mockResolvedValue({
      content: JSON.stringify({
        steps: [{ action: "send_email", mcp: "openclaw" }],
        metadata: { goal: "send email" },
      }),
    });

    await fireInboundClaim(handlers);
    await fireLlmInput(handlers, "run-policy-block", "Send email");

    const ctx = createCtx("run-policy-block");
    const beforeToolCall = handlers.get("before_tool_call")?.[0];
    const result = await beforeToolCall?.(
      { toolName: "send_email", params: { body: "Card 4111 1111 1111 1111" } },
      ctx,
    );
    expect(result?.block).toBe(true);
    expect(result?.blockReason).toContain("policy deny");
  });

  it("before_prompt_build returns prependSystemContext when policy updates enabled", async () => {
    const { api, handlers } = createApi({
      enabled: true,
      apiKey: "ak_live_test",
      userId: "user-1",
      agentId: "agent-1",
      policyUpdateEnabled: true,
      policyUpdateAllowList: ["*"],
    });
    register(api as any);

    const beforePromptBuild = handlers.get("before_prompt_build")?.[0];
    const result = await beforePromptBuild?.({}, {});
    expect(result?.prependSystemContext).toBeTruthy();
    expect(result?.prependSystemContext).toContain("Policy updates");
  });

  it("before_prompt_build returns undefined when policy updates disabled", async () => {
    const { api, handlers } = createApi({
      enabled: true,
      apiKey: "ak_live_test",
      userId: "user-1",
      agentId: "agent-1",
    });
    register(api as any);

    const beforePromptBuild = handlers.get("before_prompt_build")?.[0];
    const result = await beforePromptBuild?.({}, {});
    expect(result).toBeUndefined();
  });

  it("works with config-based identity when inbound_claim never fires (CLI mode)", async () => {
    const { api, handlers } = createApi({
      enabled: true,
      apiKey: "ak_live_test",
      userId: "user-1",
      agentId: "agent-1",
    });
    register(api as any);

    completeSimpleMock.mockResolvedValue({
      content: JSON.stringify({
        steps: [{ action: "read", mcp: "openclaw" }],
        metadata: { goal: "read a file" },
      }),
    });

    // Fire llm_input WITHOUT inbound_claim (CLI mode)
    await fireLlmInput(handlers, "run-cli-mode", "Read a file");

    const ctx = createCtx("run-cli-mode");
    const beforeToolCall = handlers.get("before_tool_call")?.[0];
    const result = await beforeToolCall?.({ toolName: "read", params: { path: "demo.txt" } }, ctx);
    expect(result?.block).not.toBe(true);
  });

  it("ONE TOKEN PER RUN: shares plan across multiple tool calls", async () => {
    let tokenCreationCount = 0;
    completeSimpleMock.mockImplementation(async () => {
      tokenCreationCount++;
      return {
        content: JSON.stringify({
          steps: [
            { action: "send_email", mcp: "openclaw" },
            { action: "read_file", mcp: "openclaw" },
            { action: "write_file", mcp: "openclaw" },
          ],
          metadata: { goal: "Multi-step task" },
        }),
      };
    });

    const { api, handlers } = createApi({
      enabled: true,
      apiKey: "ak_live_test",
      userId: "user-1",
      agentId: "agent-1",
    });
    register(api as any);

    const stableRunId = "stable-run-456";

    await fireInboundClaim(handlers);
    await fireLlmInput(handlers, stableRunId, "Send email, read file, write file");

    expect(tokenCreationCount).toBe(1);

    const ctx = createCtx(stableRunId);
    const beforeToolCall = handlers.get("before_tool_call")?.[0];

    const result1 = await beforeToolCall?.(
      { toolName: "send_email", params: { to: "user@example.com" } },
      ctx,
    );
    expect(result1?.block).not.toBe(true);

    const result2 = await beforeToolCall?.(
      { toolName: "read_file", params: { path: "/tmp/data.txt" } },
      ctx,
    );
    expect(result2?.block).not.toBe(true);

    const result3 = await beforeToolCall?.(
      { toolName: "write_file", params: { path: "/tmp/output.txt" } },
      ctx,
    );
    expect(result3?.block).not.toBe(true);

    expect(tokenCreationCount).toBe(1);

    // Cleanup
    const agentEnd = handlers.get("agent_end")?.[0];
    await agentEnd?.({}, ctx);
  });

  it("inbound_claim caches sender identity for before_tool_call", async () => {
    const { api, handlers } = createApi({
      enabled: true,
      apiKey: "ak_live_test",
      userId: "user-1",
      agentId: "agent-1",
      policyUpdateEnabled: true,
      policyUpdateAllowList: ["sender-1"],
    });
    register(api as any);

    // Fire inbound_claim to cache sender identity
    await fireInboundClaim(handlers);

    // Policy update should be allowed for sender-1
    const ctx = createCtx("run-sender-cache");
    const beforeToolCall = handlers.get("before_tool_call")?.[0];
    const result = await beforeToolCall?.({ toolName: "policy_update", params: {} }, ctx);
    expect(result?.block).not.toBe(true);
  });

  it("blocks when no plan has been generated (no llm_input fired)", async () => {
    const { api, handlers } = createApi({
      enabled: true,
      apiKey: "ak_live_test",
      userId: "user-1",
      agentId: "agent-1",
    });
    register(api as any);

    const ctx = createCtx("run-no-plan");
    const beforeToolCall = handlers.get("before_tool_call")?.[0];
    const result = await beforeToolCall?.(
      { toolName: "send_email", params: {} },
      ctx,
    );

    expect(result?.block).toBe(true);
    expect(result?.blockReason).toContain("intent plan missing");
  });

  describe("planner response extraction", () => {
    const validPlan = {
      steps: [{ action: "read", mcp: "openclaw" }],
      metadata: { goal: "read" },
    };

    const setupAndFire = async (plannerText: string, runId: string) => {
      const { api, handlers } = createApi({
        enabled: true,
        apiKey: "ak_live_test",
        userId: "user-1",
        agentId: "agent-1",
      });
      register(api as any);
      completeSimpleMock.mockResolvedValue({ content: plannerText });
      await fireInboundClaim(handlers);
      await fireLlmInput(handlers, runId, "Read a file", "- read: Read files");
      const beforeToolCall = handlers.get("before_tool_call")?.[0];
      return await beforeToolCall?.({ toolName: "read", params: { path: "x.txt" } }, createCtx(runId));
    };

    it("parses Gemini-style closed ```json fenced response", async () => {
      const result = await setupAndFire("```json\n" + JSON.stringify(validPlan) + "\n```", "run-fenced");
      expect(result?.block).not.toBe(true);
    });

    it("parses truncated/unclosed fenced response", async () => {
      const result = await setupAndFire("```json\n" + JSON.stringify(validPlan), "run-unclosed");
      expect(result?.block).not.toBe(true);
    });

    it("parses JSON surrounded by prose via brace-slice", async () => {
      const text = `Sure, here you go:\n${JSON.stringify(validPlan)}\nHope this helps!`;
      const result = await setupAndFire(text, "run-prose");
      expect(result?.block).not.toBe(true);
    });

    it("parses raw JSON without any wrapping", async () => {
      const result = await setupAndFire(JSON.stringify(validPlan), "run-raw");
      expect(result?.block).not.toBe(true);
    });

    it("type-guard rejects bare string (no plan captured, tool blocked)", async () => {
      const result = await setupAndFire('"just a string"', "run-bare-string");
      expect(result?.block).toBe(true);
    });

    it("type-guard rejects bare array (no plan captured, tool blocked)", async () => {
      const result = await setupAndFire("[1,2,3]", "run-bare-array");
      expect(result?.block).toBe(true);
    });

    it("planner error excludes raw preview by default", async () => {
      delete process.env.ARMORCLAW_DEBUG_PLANNER;
      completeSimpleMock.mockResolvedValue({ content: "not json at all" });
      const { api, handlers } = createApi({
        enabled: true,
        apiKey: "ak_live_test",
        userId: "user-1",
        agentId: "agent-1",
      });
      register(api as any);
      await fireInboundClaim(handlers);
      await fireLlmInput(handlers, "run-no-preview", "Read a file", "- read: Read files");
      const warnCalls = (api.logger.warn as any).mock.calls.map((c: unknown[]) => String(c[0]));
      const plannerWarn = warnCalls.find((m: string) => m.includes("planning failed"));
      expect(plannerWarn).toBeDefined();
      expect(plannerWarn).toContain("Planner returned invalid JSON");
      expect(plannerWarn).not.toContain('preview="');
    });

    it("planner error includes preview when ARMORCLAW_DEBUG_PLANNER=1", async () => {
      process.env.ARMORCLAW_DEBUG_PLANNER = "1";
      completeSimpleMock.mockResolvedValue({ content: "not json at all" });
      const { api, handlers } = createApi({
        enabled: true,
        apiKey: "ak_live_test",
        userId: "user-1",
        agentId: "agent-1",
      });
      register(api as any);
      try {
        await fireInboundClaim(handlers);
        await fireLlmInput(handlers, "run-preview", "Read a file", "- read: Read files");
      } finally {
        delete process.env.ARMORCLAW_DEBUG_PLANNER;
      }
      const warnCalls = (api.logger.warn as any).mock.calls.map((c: unknown[]) => String(c[0]));
      const plannerWarn = warnCalls.find((m: string) => m.includes("planning failed"));
      expect(plannerWarn).toBeDefined();
      expect(plannerWarn).toContain('preview="not json at all"');
    });
  });
});

