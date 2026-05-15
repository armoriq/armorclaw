import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

type PlanStep = {
  action: string;
  mcp: string;
  description?: string;
  metadata?: Record<string, unknown>;
};

type Plan = {
  steps: PlanStep[];
  metadata: { goal: string };
};

type PlanCacheEntry = {
  token: unknown;
  plan: Plan;
  allowedActions: Set<string>;
  createdAt: number;
  expiresAt?: number;
  error?: string;
};

function normalizeToolName(value: string): string {
  return value.trim().toLowerCase();
}

function extractAllowedActions(plan: Plan): Set<string> {
  const actions = new Set<string>();
  if (plan?.steps && Array.isArray(plan.steps)) {
    for (const step of plan.steps) {
      if (step?.action) {
        actions.add(normalizeToolName(step.action));
      }
    }
  }
  return actions;
}

function createMockPlanCache(plan: Plan, expiresInSeconds = 60): PlanCacheEntry {
  return {
    token: { tokenId: "test-token-123", signature: "mock-sig" },
    plan,
    allowedActions: extractAllowedActions(plan),
    createdAt: Date.now(),
    expiresAt: Date.now() / 1000 + expiresInSeconds,
  };
}

function simulateBeforeToolCall(
  cached: PlanCacheEntry | undefined,
  toolName: string
): { blocked: boolean; reason?: string } {
  if (!cached) {
    return {
      blocked: true,
      reason: "ArmorIQ intent plan missing for this run",
    };
  }

  if (cached.error) {
    return {
      blocked: true,
      reason: cached.error,
    };
  }

  if (cached.expiresAt && Date.now() / 1000 > cached.expiresAt) {
    return {
      blocked: true,
      reason: "ArmorIQ intent token expired",
    };
  }

  const normalizedTool = normalizeToolName(toolName);
  if (!cached.allowedActions.has(normalizedTool)) {
    return {
      blocked: true,
      reason: `ArmorIQ intent drift: tool not in plan (${toolName})`,
    };
  }

  return { blocked: false };
}

describe("ArmorIQ Intent Enforcement", () => {
  describe("Tool Allowlist Enforcement", () => {
    it("should ALLOW tool that IS in the plan", () => {
      const plan: Plan = {
        steps: [{ action: "list_dir", mcp: "openclaw", description: "List files" }],
        metadata: { goal: "List directory contents" },
      };

      const cached = createMockPlanCache(plan);
      const result = simulateBeforeToolCall(cached, "list_dir");

      expect(result.blocked).toBe(false);
      expect(result.reason).toBeUndefined();
    });

    it("should BLOCK tool that is NOT in the plan (intent drift)", () => {
      const plan: Plan = {
        steps: [{ action: "list_dir", mcp: "openclaw", description: "List files" }],
        metadata: { goal: "List directory contents" },
      };

      const cached = createMockPlanCache(plan);
      const result = simulateBeforeToolCall(cached, "write_file");

      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("intent drift");
      expect(result.reason).toContain("write_file");
    });

    it("should BLOCK dangerous tool when plan only has safe tool", () => {
      const plan: Plan = {
        steps: [{ action: "read_file", mcp: "openclaw", description: "Read a file" }],
        metadata: { goal: "Read configuration" },
      };

      const cached = createMockPlanCache(plan);

      const dangerousTools = ["bash", "exec", "delete_file", "rm", "sudo"];

      for (const tool of dangerousTools) {
        const result = simulateBeforeToolCall(cached, tool);
        expect(result.blocked).toBe(true);
        expect(result.reason).toContain("intent drift");
      }
    });

    it("should handle case-insensitive tool names", () => {
      const plan: Plan = {
        steps: [{ action: "List_Dir", mcp: "openclaw" }],
        metadata: { goal: "List files" },
      };

      const cached = createMockPlanCache(plan);

      expect(simulateBeforeToolCall(cached, "list_dir").blocked).toBe(false);
      expect(simulateBeforeToolCall(cached, "LIST_DIR").blocked).toBe(false);
      expect(simulateBeforeToolCall(cached, "List_Dir").blocked).toBe(false);
    });
  });

  describe("Token Expiry Enforcement", () => {
    it("should ALLOW tool call before token expires", () => {
      const plan: Plan = {
        steps: [{ action: "test_tool", mcp: "openclaw" }],
        metadata: { goal: "Test" },
      };

      const cached = createMockPlanCache(plan, 60);
      const result = simulateBeforeToolCall(cached, "test_tool");

      expect(result.blocked).toBe(false);
    });

    it("should BLOCK tool call after token expires", () => {
      const plan: Plan = {
        steps: [{ action: "test_tool", mcp: "openclaw" }],
        metadata: { goal: "Test" },
      };

      const cached = createMockPlanCache(plan, -1);
      const result = simulateBeforeToolCall(cached, "test_tool");

      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("expired");
    });
  });

  describe("Missing Plan Enforcement", () => {
    it("should BLOCK when no plan is cached", () => {
      const result = simulateBeforeToolCall(undefined, "any_tool");

      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("intent plan missing");
    });

    it("should BLOCK when plan has error", () => {
      const cached: PlanCacheEntry = {
        token: null,
        plan: { steps: [], metadata: { goal: "" } },
        allowedActions: new Set(),
        createdAt: Date.now(),
        error: "Token issuance failed: API key invalid",
      };

      const result = simulateBeforeToolCall(cached, "any_tool");

      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("API key invalid");
    });
  });

  describe("Multi-Step Plan Enforcement", () => {
    it("should ALLOW all tools in a multi-step plan", () => {
      const plan: Plan = {
        steps: [
          { action: "read_file", mcp: "openclaw" },
          { action: "write_file", mcp: "openclaw" },
          { action: "list_dir", mcp: "openclaw" },
        ],
        metadata: { goal: "File operations" },
      };

      const cached = createMockPlanCache(plan);

      expect(simulateBeforeToolCall(cached, "read_file").blocked).toBe(false);
      expect(simulateBeforeToolCall(cached, "write_file").blocked).toBe(false);
      expect(simulateBeforeToolCall(cached, "list_dir").blocked).toBe(false);
    });

    it("should BLOCK tool not in multi-step plan", () => {
      const plan: Plan = {
        steps: [
          { action: "read_file", mcp: "openclaw" },
          { action: "write_file", mcp: "openclaw" },
        ],
        metadata: { goal: "File operations" },
      };

      const cached = createMockPlanCache(plan);

      expect(simulateBeforeToolCall(cached, "delete_file").blocked).toBe(true);
      expect(simulateBeforeToolCall(cached, "bash").blocked).toBe(true);
    });
  });

  describe("Session ID / Run Key Resolution", () => {
    function resolveRunKey(ctx: { runId?: string; sessionKey?: string }): string | null {
      const runId = ctx.runId?.trim();
      const sessionKey = ctx.sessionKey?.trim();

      if (runId) {
        if (sessionKey && sessionKey !== runId) {
          return `${sessionKey}::${runId}`;
        }
        return runId;
      }
      return sessionKey || null;
    }

    it("should return runId when sessionKey equals runId (THE FIX)", () => {
      const result = resolveRunKey({
        runId: "test-session-123",
        sessionKey: "test-session-123",
      });

      expect(result).toBe("test-session-123");
      expect(result).not.toContain("::");
    });

    it("should combine sessionKey::runId when they differ", () => {
      const result = resolveRunKey({
        runId: "run-456",
        sessionKey: "session-123",
      });

      expect(result).toBe("session-123::run-456");
    });

    it("should return just runId when no sessionKey", () => {
      const result = resolveRunKey({
        runId: "run-only",
        sessionKey: undefined,
      });

      expect(result).toBe("run-only");
    });

    it("should return sessionKey when no runId", () => {
      const result = resolveRunKey({
        runId: undefined,
        sessionKey: "session-only",
      });

      expect(result).toBe("session-only");
    });

    it("should return null when both missing", () => {
      const result = resolveRunKey({});
      expect(result).toBeNull();
    });

    it("should handle whitespace-only values", () => {
      const result = resolveRunKey({
        runId: "  ",
        sessionKey: "  ",
      });
      expect(result).toBeNull();
    });
  });
});

describe("ArmorIQ Intent Drift Attack Scenarios", () => {
  describe("Prompt Injection Attack", () => {
    it("should BLOCK agent trying to escape plan via prompt injection", () => {
      const plan: Plan = {
        steps: [{ action: "list_dir", mcp: "openclaw", description: "List home directory" }],
        metadata: { goal: "Show files in home" },
      };

      const cached = createMockPlanCache(plan);

      const attackTools = ["bash", "exec", "run_command", "shell", "eval", "system"];

      for (const tool of attackTools) {
        const result = simulateBeforeToolCall(cached, tool);
        expect(result.blocked).toBe(true);
        expect(result.reason).toContain("intent drift");
      }
    });
  });

  describe("Privilege Escalation Attack", () => {
    it("should BLOCK read_file when plan only allows list_dir", () => {
      const plan: Plan = {
        steps: [{ action: "list_dir", mcp: "openclaw" }],
        metadata: { goal: "List files only" },
      };

      const cached = createMockPlanCache(plan);
      const result = simulateBeforeToolCall(cached, "read_file");

      expect(result.blocked).toBe(true);
    });

    it("should BLOCK write_file when plan only allows read_file", () => {
      const plan: Plan = {
        steps: [{ action: "read_file", mcp: "openclaw" }],
        metadata: { goal: "Read only" },
      };

      const cached = createMockPlanCache(plan);
      const result = simulateBeforeToolCall(cached, "write_file");

      expect(result.blocked).toBe(true);
    });
  });

  describe("Token Replay Attack", () => {
    it("should BLOCK reusing expired token", () => {
      const plan: Plan = {
        steps: [{ action: "any_tool", mcp: "openclaw" }],
        metadata: { goal: "Test" },
      };

      const expiredCache = createMockPlanCache(plan, -100);
      const result = simulateBeforeToolCall(expiredCache, "any_tool");

      expect(result.blocked).toBe(true);
      expect(result.reason).toContain("expired");
    });
  });
});

describe("CSRG vs IAP URL Distinction", () => {
  it("should document the URL purposes", () => {
    const urls = {
      csrg: "http://localhost:8000",
      iap: "http://localhost:8000",
      backend: "http://localhost:3000",
      proxy: "http://localhost:3001",
    };

    expect(urls.csrg).toBe("http://localhost:8000");
    expect(urls.iap).toBe("http://localhost:8000");

    const csrgEndpoints = [
      "POST /intent - Create CSRG intent with Merkle tree",
      "POST /verify/action - Verify tool call against Merkle proof",
      "GET /intent/{id}/proof - Get Merkle proof for step",
      "POST /delegation/create - Create delegation token",
    ];

    const iapEndpoints = [
      "POST /iap/process - Issue intent token with policy validation",
      "POST /iap/verify-step - Verify step (fallback from CSRG)",
      "POST /iap/audit-log - Record tool execution audit",
    ];

    expect(csrgEndpoints.length).toBeGreaterThan(0);
    expect(iapEndpoints.length).toBeGreaterThan(0);
  });
});
