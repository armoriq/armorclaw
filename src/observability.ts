/**
 * ArmorClaw observability bridge.
 *
 * Mirrors what armorClaude does: one SDK ObservabilityRecorder per run, a trace
 * per agent turn, a policy_call span per tool decision. Without this ArmorClaw
 * is invisible on the dashboard while every other product reports.
 *
 * Two rules hold everywhere in this file:
 *   1. Nothing may throw into a hook. Observability is reporting, not
 *      enforcement, so a broken recorder must never block a tool call.
 *   2. Nothing may block. Emissions are buffered by the SDK and shipped in the
 *      background; only the flush at agent_end is awaited, and even that is
 *      bounded by the SDK's own shipper.
 */
import { ObservabilityRecorder, isValidUuid } from "@armoriq/sdk";

export const OBSERVABILITY_PRODUCT = "armorclaw";

type Logger = {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
};

export type ObservabilityOptions = {
  enabled: boolean;
  backendEndpoint: string;
  apiKey: string;
  userId?: string;
  agentId?: string;
  logger: Logger;
  debug?: boolean;
};

type TraceCtx = ReturnType<ObservabilityRecorder["startTrace"]>;

type RunEntry = {
  recorder: ObservabilityRecorder;
  ctx: TraceCtx;
};

export type ToolDecision = {
  allowed: boolean;
  reason: string | null;
};

/**
 * The no-op shape returned when observability is off or unusable. Callers never
 * branch on whether it is live; they just call and it does nothing.
 */
export interface Observability {
  readonly active: boolean;
  startRun(runKey: string, prompt: string, attributes?: Record<string, unknown>): void;
  recordPlan(runKey: string, attrs: { planId?: string; steps: number; error?: string }): void;
  recordToolDecision(runKey: string, toolName: string, decision: ToolDecision): void;
  endRun(runKey: string, status?: "ok" | "error" | "denied"): Promise<void>;
}

const NOOP: Observability = {
  active: false,
  startRun: () => {},
  recordPlan: () => {},
  recordToolDecision: () => {},
  endRun: async () => {},
};

export function createObservability(opts: ObservabilityOptions): Observability {
  // No key means nothing can be attributed to an account, so there is nothing
  // useful to ship. Same for an explicit opt out.
  if (!opts.enabled || !opts.apiKey || !opts.backendEndpoint) {
    return NOOP;
  }

  // If the installed SDK predates the observability exports, degrade to the
  // no-op rather than failing inside every hook. Said once, not per call.
  if (typeof ObservabilityRecorder !== "function") {
    opts.logger.warn(
      "armoriq: observability unavailable (SDK has no ObservabilityRecorder); continuing without it",
    );
    return NOOP;
  }

  const runs = new Map<string, RunEntry>();
  const { logger } = opts;

  const safe = <T>(fn: () => T): T | undefined => {
    try {
      return fn();
    } catch (err) {
      if (opts.debug) {
        logger.warn(`armoriq: [obs] ${(err as Error)?.message ?? String(err)}`);
      }
      return undefined;
    }
  };

  // sessionId and userId are UUID columns on the backend, and ArmorClaw's ids
  // are logical strings ("openclaw-agent-001", an email), so they are only sent
  // when they genuinely are UUIDs. agentId is a free-form text column, so the
  // logical value goes through as-is. armorClaude learned this the hard way:
  // gating agentId behind the same UUID check blanked the dashboard's AGENT
  // column on every trace.
  const uuidOrNull = (value: string | undefined): string | null =>
    value && isValidUuid(value) ? value : null;

  const newRecorder = (): ObservabilityRecorder =>
    new ObservabilityRecorder({
      enabled: true,
      endpoint: opts.backendEndpoint,
      apiKey: opts.apiKey,
      product: OBSERVABILITY_PRODUCT,
      sessionId: null,
      userId: uuidOrNull(opts.userId),
      agentId: opts.agentId ?? null,
    });

  return {
    active: true,

    startRun(runKey, prompt, attributes) {
      if (!runKey || runs.has(runKey)) return;
      safe(() => {
        const recorder = newRecorder();
        const ctx = recorder.startTrace("armorclaw.turn", {
          "armorclaw.prompt_preview": prompt.slice(0, 200),
          "armorclaw.user_id": opts.userId ?? null,
          "armorclaw.agent_id": opts.agentId ?? null,
          ...(attributes ?? {}),
        });
        runs.set(runKey, { recorder, ctx });
      });
    },

    recordPlan(runKey, attrs) {
      const entry = runs.get(runKey);
      if (!entry) return;
      safe(() => {
        const message = attrs.error
          ? `intent plan failed: ${attrs.error}`
          : `intent plan captured: ${attrs.steps} step(s)${attrs.planId ? ` plan=${attrs.planId}` : ""}`;
        entry.recorder.recordEvent(entry.ctx, {
          message,
          level: attrs.error ? "error" : "info",
        });
      });
    },

    // Every tool call produces one policy_call span, allowed or blocked. Blocks
    // are the interesting half: intent drift, expired tokens, policy denies.
    recordToolDecision(runKey, toolName, decision) {
      const entry = runs.get(runKey);
      if (!entry) return;
      safe(() => {
        entry.recorder.recordPolicyCall(entry.ctx, {
          policyId: null,
          policyName: "armorclaw.intent",
          decision: decision.allowed ? "allow" : "deny",
          reason: decision.reason,
          source: "sdk-local",
          input: { tool: toolName },
          output: { allowed: decision.allowed },
          enforcementAction: decision.allowed ? "allow" : "block",
        });
      });
    },

    async endRun(runKey, status = "ok") {
      const entry = runs.get(runKey);
      if (!entry) return;
      runs.delete(runKey);
      safe(() => entry.recorder.endTrace(entry.ctx, { status }));
      try {
        await entry.recorder.flush();
      } catch (err) {
        if (opts.debug) {
          logger.warn(`armoriq: [obs] flush failed: ${(err as Error)?.message ?? String(err)}`);
        }
      }
    },
  };
}
