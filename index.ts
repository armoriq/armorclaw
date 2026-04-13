import type { Api, Model } from "@mariozechner/pi-ai";
import { getModel, registerBuiltInApiProviders } from "@mariozechner/pi-ai";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { ArmorIQClient } from "@armoriq/sdk";
import { completeSimple } from "@mariozechner/pi-ai";
import { Type } from "@sinclair/typebox";
import { createHash } from "node:crypto";
import { CryptoPolicyService, computePolicyDigest } from "./src/crypto-policy.service.js";
import { IAPVerificationService, type CsrgProofHeaders } from "./src/iap-verfication.service.js";
import {
  PolicyStore,
  PolicyUpdateSchema,
  evaluatePolicy,
  normalizePolicyDefinition,
  type PolicyUpdate,
  type PolicyRule,
  type PolicyDataClass,
} from "./src/policy.js";

type ArmorIqConfig = {
  enabled: boolean;
  apiKey?: string;
  userId?: string;
  agentId?: string;
  contextId?: string;
  userIdSource?:
    | "senderE164"
    | "senderId"
    | "senderUsername"
    | "senderName"
    | "sessionKey"
    | "agentId";
  agentIdSource?: "agentId" | "sessionKey";
  contextIdSource?: "sessionKey" | "agentId" | "channel" | "accountId";
  policy?: Record<string, unknown>;
  policyStorePath?: string;
  policyUpdateEnabled?: boolean;
  policyUpdateAllowList?: string[];
  cryptoPolicyEnabled?: boolean;
  csrgEndpoint?: string;
  validitySeconds: number;
  useProduction?: boolean;
  iapEndpoint?: string;
  proxyEndpoint?: string;
  backendEndpoint?: string;
  proxyEndpoints?: Record<string, string>;
  timeoutMs?: number;
  maxRetries?: number;
  verifySsl?: boolean;
  maxParamChars: number;
  maxParamDepth: number;
  maxParamKeys: number;
  maxParamItems: number;
};

type ToolContext = {
  agentId?: string;
  sessionKey?: string;
  messageChannel?: string;
  accountId?: string;
  senderId?: string;
  senderName?: string;
  senderUsername?: string;
  senderE164?: string;
  runId?: string;
};

type SenderIdentityEntry = {
  senderId?: string;
  senderName?: string;
  senderUsername?: string;
  accountId?: string;
  channel?: string;
  conversationId?: string;
  cachedAt: number;
};

type IdentityBundle = {
  userId: string;
  agentId: string;
  contextId: string;
};

type PlanCacheEntry = {
  token: unknown;
  tokenRaw?: string;
  tokenPlan?: Record<string, unknown>;
  plan: Record<string, unknown>;
  allowedActions: Set<string>;
  executedStepIndices: Set<number>;
  createdAt: number;
  expiresAt?: number;
  error?: string;
  // DB plan UUID returned by POST /iap/sdk/token. Used to attach audit logs
  // (block / success) to the correct plan row so the dashboard can roll up
  // status and decision history per plan.
  planId?: string;
  // Raw JWT we can replay on follow-up audit calls without re-issuing.
  jwtToken?: string;
};

type ContextTokenExecutionEntry = {
  tokenHash: string;
  usedStepIndices: Set<number>;
  updatedAt: number;
};

const DEFAULT_VALIDITY_SECONDS = 60;
const DEFAULT_MAX_PARAM_CHARS = 2000;
const DEFAULT_MAX_PARAM_DEPTH = 4;
const DEFAULT_MAX_PARAM_KEYS = 50;
const DEFAULT_MAX_PARAM_ITEMS = 50;
const POLICY_ACTIONS = ["allow", "deny", "require_approval"] as const;
const POLICY_SCOPES = ["org", "project", "run"] as const;
const POLICY_DATA_CLASSES = ["PCI", "PAYMENT", "PHI", "PII"] as const;
const POLICY_UPDATE_INSTRUCTIONS = `Policy updates:
- When the user asks to update, list, delete, or reset policy (e.g. "Policy update policy2: ...", "Policy list"), call the policy_update tool immediately.
- Pass the user's plain-text request via the tool parameter "text" (do NOT emit JSON to the user).
- Require an explicit policy id for updates (policy1, policy2, etc.). If missing, ask them to run "Policy list" or use "Policy new: ...".
- Use "Policy new: ..." to create a new rule with the next policy id.
- If details are missing, infer reasonable defaults: reason="User policy update", mode="merge", tool="*", action="deny" for "block/disallow" intents.
- For "credit card" or "payment" requests, set dataClass to PCI or PAYMENT.
- Only use policy_update for explicit policy changes.
- If the user asks for help/commands, return the policy command cheat-sheet.
- New rules are prepended (top of list) so they take priority over existing rules.
- Reset clears all rules; default behavior with no rules is allow-all.

Tool access enforcement:
- The ArmorIQ policy engine is the SOLE authority for deciding whether a tool call is allowed or blocked.
- If the policy engine permits a tool call, you MUST execute it. Do NOT independently refuse, second-guess, or add your own safety judgment on top of the policy decision.
- If the policy engine blocks a tool call, it will be blocked automatically. You do not need to enforce it yourself.
- Never override, bypass, or supplement the policy engine with your own allow/deny logic.
- Your role is to execute what the policy permits and inform the user when the policy blocks something.`;

const clientCache = new Map<string, ArmorIQClient>();
const planCache = new Map<string, PlanCacheEntry>();
const sessionKeyIndex = new Map<string, string>();
const contextTokenExecutionCache = new Map<string, ContextTokenExecutionEntry>();
const senderIdentityCache = new Map<string, SenderIdentityEntry>();
const planningPromises = new Map<string, Promise<void>>();

function stringEnum<T extends readonly string[]>(
  values: T,
  options: { description?: string } = {},
) {
  return Type.Unsafe<T[number]>({
    type: "string",
    enum: [...values],
    ...options,
  });
}

const PolicyRuleToolSchema = Type.Object(
  {
    id: Type.String({ description: "Unique rule id" }),
    action: stringEnum(POLICY_ACTIONS, { description: "allow, deny, or require_approval" }),
    tool: Type.String({ description: "Tool name or *" }),
    dataClass: Type.Optional(stringEnum(POLICY_DATA_CLASSES)),
    params: Type.Optional(Type.Object({}, { additionalProperties: true })),
    scope: Type.Optional(stringEnum(POLICY_SCOPES)),
  },
  { additionalProperties: false },
);

const PolicyUpdateToolSchema = Type.Object(
  {
    text: Type.Optional(
      Type.String({
        description: "Plain-language policy command (update/list/delete/reset).",
      }),
    ),
    update: Type.Optional(
      Type.Object(
        {
          reason: Type.String({ description: "Why this policy change is needed" }),
          rules: Type.Array(PolicyRuleToolSchema, { minItems: 1 }),
          mode: Type.Optional(stringEnum(["replace", "merge"] as const)),
          scope: Type.Optional(stringEnum(POLICY_SCOPES)),
          expiresAt: Type.Optional(Type.Number({ description: "Unix timestamp (seconds)" })),
          actor: Type.Optional(Type.String({ description: "Optional actor label" })),
        },
        { additionalProperties: false },
      ),
    ),
  },
  { additionalProperties: false },
);

function readString(value: unknown): string | undefined {
  return typeof value === "string" ? value.trim() || undefined : undefined;
}

function readStringArray(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    const items = value
      .map((entry) => {
        if (typeof entry === "string") {
          return entry.trim();
        }
        if (typeof entry === "number" && Number.isFinite(entry)) {
          return String(entry);
        }
        return "";
      })
      .filter(Boolean);
    return items.length > 0 ? items : undefined;
  }
  if (typeof value === "string") {
    const items = value
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean);
    return items.length > 0 ? items : undefined;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return [String(value)];
  }
  return undefined;
}

function readNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function readBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function readRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

type PolicyState = ReturnType<PolicyStore["getState"]>;
type PolicyCommand =
  | { kind: "list" }
  | { kind: "get"; id: string }
  | { kind: "help" }
  | { kind: "need_id" }
  | { kind: "reorder"; id: string; position: number; reason: string }
  | { kind: "delete"; ids: string[]; reason: string }
  | { kind: "reset"; reason: string }
  | { kind: "update"; update: PolicyUpdate };

function truncateReason(text: string, max = 160): string {
  const trimmed = text.trim();
  if (trimmed.length <= max) {
    return trimmed;
  }
  return `${trimmed.slice(0, max)}...`;
}

function slugifyRuleId(text: string): string {
  return text
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-_]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function formatPolicyRule(rule: PolicyRule): string {
  const parts = [`id=${rule.id}`, `action=${rule.action}`, `tool=${rule.tool}`];
  if (rule.dataClass) {
    parts.push(`dataClass=${rule.dataClass}`);
  }
  if (rule.scope) {
    parts.push(`scope=${rule.scope}`);
  }
  return parts.join(" ");
}

function formatPolicyHelp(): string {
  return [
    "Policy commands (8):",
    "1. Policy list: list all rules",
    "2. Policy get policy1: show one rule by id",
    "3. Policy delete policy1: remove a rule by id",
    "4. Policy reset: clear all rules (reverts to default-allow)",
    "5. Policy update policy1: block send_email for payment data",
    "6. Policy update policy2: allow write_file",
    "7. Policy new: block upload_file for PII (creates new policyN, added at top)",
    "8. Policy prioritize policy2 1: move rule to position 1 (higher priority)",
    "Note: Rules are evaluated top-to-bottom; first match wins. New rules go to the top.",
  ].join("\n");
}

function formatPolicyNeedId(): string {
  return [
    "Policy update needs a policy id.",
    "Use: Policy list (to see ids), then:",
    "- Policy update policy2: <your change>",
    "Or create a new rule with:",
    "- Policy new: <your rule>",
  ].join("\n");
}

function formatPolicyList(state: PolicyState): string {
  if (!state.policy.rules.length) {
    return `Policy version ${state.version}. No explicit rules. Default: allow all tools.`;
  }
  const lines = state.policy.rules.map(
    (rule, idx) => `${idx + 1}. ${formatPolicyRule(rule)} (order=${idx + 1})`,
  );
  return `Policy version ${state.version}:\n${lines.join("\n")}`;
}

function nextPolicyId(state: PolicyState): string {
  const ids = state.policy.rules
    .map((rule) => rule.id)
    .map((id) => {
      const match = id.match(/^policy(\d+)$/i);
      return match ? Number.parseInt(match[1] ?? "", 10) : null;
    })
    .filter((value): value is number => Number.isFinite(value));
  const max = ids.length ? Math.max(...ids) : 0;
  return `policy${max + 1}`;
}

function extractPolicyIdsFromText(text: string, state: PolicyState): string[] {
  const ids = new Set<string>();
  const policyNumeric = [...text.matchAll(/\bpolicy[-_]?(\d+)\b/gi)];
  for (const match of policyNumeric) {
    const num = match[1];
    if (num) {
      ids.add(`policy${num}`);
    }
  }

  const updateNumeric = [...text.matchAll(/\bupdate\s+(\d+)\b/gi)];
  for (const match of updateNumeric) {
    const num = match[1];
    if (num) {
      ids.add(`policy${num}`);
    }
  }

  const ruleMatches = [...text.matchAll(/\brule\s*[:#]?\s*([a-z0-9][\w.-]*)/gi)];
  for (const match of ruleMatches) {
    const raw = match[1];
    if (raw) {
      ids.add(raw);
    }
  }

  const idMatches = [...text.matchAll(/\bid\s*[:#]?\s*([a-z0-9][\w.-]*)/gi)];
  for (const match of idMatches) {
    const raw = match[1];
    if (raw) {
      ids.add(raw);
    }
  }

  for (const rule of state.policy.rules) {
    if (text.includes(rule.id)) {
      ids.add(rule.id);
    }
  }
  return Array.from(ids);
}

function inferPolicyAction(text: string): "allow" | "deny" | "require_approval" {
  const lower = text.toLowerCase();
  if (/(require\s+approval|needs\s+approval|approval\s+required)/i.test(lower)) {
    return "require_approval";
  }
  if (/(allow|permit|enable|whitelist)/i.test(lower)) {
    return "allow";
  }
  if (/(deny|block|disallow|prevent|prohibit|stop)/i.test(lower)) {
    return "deny";
  }
  return "deny";
}

function inferPolicyDataClass(text: string): PolicyDataClass | undefined {
  const lower = text.toLowerCase();
  if (/(credit\s*card|card\s*number|pci)/i.test(lower)) {
    return "PCI";
  }
  if (/(payment|billing|bank|iban|swift|routing)/i.test(lower)) {
    return "PAYMENT";
  }
  if (/(phi|health|patient|medical)/i.test(lower)) {
    return "PHI";
  }
  if (/(pii|ssn|personal\s+data|identity)/i.test(lower)) {
    return "PII";
  }
  return undefined;
}

function inferPolicyTool(text: string): string {
  const lower = text.toLowerCase();
  if (/(all\s+tools|any\s+tool|\*\b)/i.test(lower)) {
    return "*";
  }
  const backtickMatch = text.match(/`([a-z0-9_.:-]+)`/i);
  if (backtickMatch?.[1]) {
    return backtickMatch[1];
  }
  const toolMatch = text.match(/\btool\s*[:=]?\s*([a-z0-9_.:-]+)/i);
  if (toolMatch?.[1]) {
    return toolMatch[1];
  }
  const actionMatch = text.match(/\b(block|deny|allow|disallow|permit|require)\s+([a-z0-9_.:-]+)/i);
  if (actionMatch?.[2]) {
    return actionMatch[2];
  }
  const forMatch = text.match(/\bfor\s+([a-z0-9_.:-]+)\s+tool\b/i);
  if (forMatch?.[1]) {
    return forMatch[1];
  }
  return "*";
}

function buildPolicyUpdateFromText(text: string, state: PolicyState): PolicyUpdate {
  const action = inferPolicyAction(text);
  const dataClass = inferPolicyDataClass(text);
  const tool = inferPolicyTool(text);
  const explicitIds = extractPolicyIdsFromText(text, state);
  const ruleId = explicitIds[0] ?? nextPolicyId(state);
  return {
    reason: truncateReason(`User policy update: ${text}`),
    mode: /replace/i.test(text) ? "replace" : "merge",
    rules: [
      {
        id: ruleId,
        action,
        tool,
        dataClass,
      },
    ],
  };
}

function parsePolicyTextCommand(text: string, state: PolicyState): PolicyCommand {
  const trimmed = text.trim();
  const lower = trimmed.toLowerCase();
  const ids = extractPolicyIdsFromText(trimmed, state);

  const reorderMatch = trimmed.match(
    /\bpolicy\s*(?:priorit(?:y|ize|ise)|reorder|move)\s+(policy\d+|[a-z0-9][\w.-]*)\s+(?:to\s+)?(\d+)\b/i,
  );
  if (reorderMatch?.[1] && reorderMatch?.[2]) {
    const id = reorderMatch[1];
    const position = Number.parseInt(reorderMatch[2], 10);
    if (Number.isFinite(position)) {
      return {
        kind: "reorder",
        id,
        position,
        reason: truncateReason(`Policy reorder: ${trimmed}`),
      };
    }
  }
  if (/\b(new|create|add)\b/.test(lower) && /\bpolicy|policies\b/.test(lower)) {
    return { kind: "update", update: buildPolicyUpdateFromText(trimmed, state) };
  }
  if (
    /\b(help|commands|prompt)\b/.test(lower) &&
    !/\b(new|create|add|update|delete|reset|list)\b/.test(lower) &&
    /\bpolicy|policies\b/.test(lower)
  ) {
    return { kind: "help" };
  }
  if (/\b(list|show|view)\b/.test(lower) && /\bpolicy|policies\b/.test(lower)) {
    return { kind: "list" };
  }
  if (/\b(get|show|view)\b/.test(lower) && ids.length === 1) {
    return { kind: "get", id: ids[0] };
  }
  if (/\b(reset|clear\s+all|wipe)\b/.test(lower)) {
    return { kind: "reset", reason: truncateReason(`Policy reset: ${trimmed}`) };
  }
  if (/\b(delete|remove|undo|revert)\b/.test(lower)) {
    if (ids.length > 0) {
      return {
        kind: "delete",
        ids,
        reason: truncateReason(`Policy delete: ${trimmed}`),
      };
    }
    const dataClass = inferPolicyDataClass(trimmed);
    if (dataClass) {
      const matches = state.policy.rules.filter((rule) => rule.dataClass === dataClass);
      if (matches.length > 0) {
        return {
          kind: "delete",
          ids: matches.map((rule) => rule.id),
          reason: truncateReason(`Policy delete: ${trimmed}`),
        };
      }
    }
  }
  if (/\bupdate\b/.test(lower) && ids.length === 0) {
    return { kind: "need_id" };
  }
  return { kind: "update", update: buildPolicyUpdateFromText(trimmed, state) };
}

function resolveConfig(api: OpenClawPluginApi): ArmorIqConfig {
  const raw = readRecord(api.pluginConfig) ?? {};
  const enabled = readBoolean(raw.enabled) ?? false;
  return {
    enabled,
    apiKey: readString(raw.apiKey) ?? readString(process.env.ARMORIQ_API_KEY),
    userId: readString(raw.userId) ?? readString(process.env.USER_ID),
    agentId: readString(raw.agentId) ?? readString(process.env.AGENT_ID),
    contextId: readString(raw.contextId) ?? readString(process.env.CONTEXT_ID),
    userIdSource: readString(raw.userIdSource) as ArmorIqConfig["userIdSource"],
    agentIdSource: readString(raw.agentIdSource) as ArmorIqConfig["agentIdSource"],
    contextIdSource: readString(raw.contextIdSource) as ArmorIqConfig["contextIdSource"],
    policy: readRecord(raw.policy),
    policyStorePath:
      readString(raw.policyStorePath) ?? readString(process.env.ARMORIQ_POLICY_STORE_PATH),
    policyUpdateEnabled:
      readBoolean(raw.policyUpdateEnabled) ??
      readBoolean(process.env.ARMORIQ_POLICY_UPDATE_ENABLED),
    policyUpdateAllowList:
      readStringArray(raw.policyUpdateAllowList) ??
      readStringArray(process.env.ARMORIQ_POLICY_UPDATE_ALLOWLIST),
    cryptoPolicyEnabled:
      readBoolean(raw.cryptoPolicyEnabled) ??
      readBoolean(process.env.ARMORIQ_CRYPTO_POLICY_ENABLED),
    csrgEndpoint:
      readString(raw.csrgEndpoint) ?? readString(process.env.CSRG_URL) ?? "https://customer-iap.armoriq.ai",
    validitySeconds: readNumber(raw.validitySeconds) ?? DEFAULT_VALIDITY_SECONDS,
    useProduction: readBoolean(raw.useProduction),
    iapEndpoint: readString(raw.iapEndpoint) ?? readString(process.env.IAP_ENDPOINT),
    proxyEndpoint: readString(raw.proxyEndpoint) ?? readString(process.env.PROXY_ENDPOINT),
    backendEndpoint: readString(raw.backendEndpoint) ?? readString(process.env.BACKEND_ENDPOINT),
    proxyEndpoints: readRecord(raw.proxyEndpoints) as Record<string, string> | undefined,
    timeoutMs: readNumber(raw.timeoutMs),
    maxRetries: readNumber(raw.maxRetries),
    verifySsl: readBoolean(raw.verifySsl),
    maxParamChars: readNumber(raw.maxParamChars) ?? DEFAULT_MAX_PARAM_CHARS,
    maxParamDepth: readNumber(raw.maxParamDepth) ?? DEFAULT_MAX_PARAM_DEPTH,
    maxParamKeys: readNumber(raw.maxParamKeys) ?? DEFAULT_MAX_PARAM_KEYS,
    maxParamItems: readNumber(raw.maxParamItems) ?? DEFAULT_MAX_PARAM_ITEMS,
  };
}

function resolvePolicyStorePath(api: OpenClawPluginApi, cfg: ArmorIqConfig): string {
  const rawPath = cfg.policyStorePath?.trim() || "armoriq.policy.json";
  return api.resolvePath ? api.resolvePath(rawPath) : rawPath;
}

function isPolicyUpdateAllowed(
  cfg: ArmorIqConfig,
  ctx: ToolContext,
): {
  allowed: boolean;
  reason?: string;
  candidates?: string[];
} {
  if (!cfg.policyUpdateEnabled) {
    return { allowed: false, reason: "ArmorIQ policy updates disabled" };
  }
  const allowList = cfg.policyUpdateAllowList ?? [];
  if (allowList.includes("*")) {
    return { allowed: true };
  }
  if (allowList.length === 0) {
    return { allowed: false, reason: "ArmorIQ policy updates not allowed" };
  }
  const candidates = [
    ctx.senderE164,
    ctx.senderId,
    ctx.senderUsername,
    ctx.senderName,
    ctx.sessionKey,
    ctx.agentId,
  ]
    .map((value) => {
      if (typeof value === "string") {
        return value.trim();
      }
      if (typeof value === "number" && Number.isFinite(value)) {
        return String(value);
      }
      return "";
    })
    .filter(Boolean) as string[];
  const allowed = candidates.some((candidate) => allowList.includes(candidate));
  return allowed
    ? { allowed: true, candidates }
    : { allowed: false, reason: "ArmorIQ policy update denied", candidates };
}

function buildToolContextFromCaches(
  nativeCtx: { agentId?: string; sessionKey?: string; sessionId?: string; runId?: string },
): ToolContext {
  const key = nativeCtx.sessionKey ?? nativeCtx.agentId ?? "";
  const senderInfo = senderIdentityCache.get(key)
    ?? (nativeCtx.sessionId ? senderIdentityCache.get(nativeCtx.sessionId) : undefined)
    ?? (senderIdentityCache.size > 0 ? [...senderIdentityCache.values()].at(-1) : undefined);
  return {
    agentId: nativeCtx.agentId,
    sessionKey: nativeCtx.sessionKey,
    runId: nativeCtx.runId,
    senderId: senderInfo?.senderId,
    senderName: senderInfo?.senderName,
    senderUsername: senderInfo?.senderUsername,
    messageChannel: senderInfo?.channel,
    accountId: senderInfo?.accountId,
  };
}

function resolveUserId(cfg: ArmorIqConfig, ctx: ToolContext): string | undefined {
  if (cfg.userId) {
    return cfg.userId;
  }
  const source = cfg.userIdSource;
  if (source === "senderE164") {
    // senderE164 is not available in upstream OpenClaw hooks; fall back to senderId
    return ctx.senderE164?.trim() || ctx.senderId?.trim();
  }
  if (source === "senderId") {
    return ctx.senderId?.trim();
  }
  if (source === "senderUsername") {
    return ctx.senderUsername?.trim();
  }
  if (source === "senderName") {
    return ctx.senderName?.trim();
  }
  if (source === "sessionKey") {
    return ctx.sessionKey?.trim();
  }
  if (source === "agentId") {
    return ctx.agentId?.trim();
  }

  return (
    ctx.senderE164?.trim() ||
    ctx.senderId?.trim() ||
    ctx.senderUsername?.trim() ||
    ctx.senderName?.trim() ||
    ctx.sessionKey?.trim() ||
    ctx.agentId?.trim()
  );
}

function resolveAgentId(cfg: ArmorIqConfig, ctx: ToolContext): string | undefined {
  if (cfg.agentId) {
    return cfg.agentId;
  }
  const source = cfg.agentIdSource;
  if (source === "sessionKey") {
    return ctx.sessionKey?.trim();
  }
  return ctx.agentId?.trim();
}

function resolveContextId(cfg: ArmorIqConfig, ctx: ToolContext): string | undefined {
  if (cfg.contextId) {
    return cfg.contextId;
  }
  const source = cfg.contextIdSource;
  if (source === "agentId") {
    return ctx.agentId?.trim();
  }
  if (source === "channel") {
    return ctx.messageChannel?.trim();
  }
  if (source === "accountId") {
    return ctx.accountId?.trim();
  }
  return ctx.sessionKey?.trim();
}

function resolveIdentities(cfg: ArmorIqConfig, ctx: ToolContext): IdentityBundle | null {
  const userId = resolveUserId(cfg, ctx);
  const agentId = resolveAgentId(cfg, ctx);
  const contextId = resolveContextId(cfg, ctx) ?? "default";
  if (!userId || !agentId) {
    return null;
  }
  return { userId, agentId, contextId };
}

function resolveRunKey(ctx: ToolContext): string | null {
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

function normalizeToolName(value: string): string {
  return value.trim().toLowerCase();
}

function parseCsrgProofHeaders(ctx: Record<string, unknown>): {
  proofs?: CsrgProofHeaders;
  error?: string;
} {
  const path = readString(ctx.csrgPath);
  const valueDigest = readString(ctx.csrgValueDigest);
  const proofRaw = readString(ctx.csrgProofRaw);
  if (!path && !valueDigest && !proofRaw) {
    return {};
  }

  let proof: unknown = undefined;
  if (proofRaw) {
    try {
      proof = JSON.parse(proofRaw);
    } catch {
      return { error: "ArmorIQ CSRG proof header invalid JSON" };
    }
    if (!Array.isArray(proof)) {
      return { error: "ArmorIQ CSRG proof header must be a JSON array" };
    }
  }

  return { proofs: { path, valueDigest, proof } };
}

function validateCsrgProofHeaders(
  proofs: CsrgProofHeaders | undefined,
  required: boolean,
): string | null {
  if (!required) {
    return null;
  }
  if (!proofs) {
    return "ArmorIQ CSRG proof headers missing";
  }
  if (!proofs.path) {
    return "ArmorIQ CSRG path header missing";
  }
  if (!proofs.valueDigest) {
    return "ArmorIQ CSRG value digest header missing";
  }
  if (!proofs.proof || !Array.isArray(proofs.proof)) {
    return "ArmorIQ CSRG proof header missing";
  }
  return null;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function parseStepIndex(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return null;
}

function extractStepInputCandidates(step: Record<string, unknown>): Record<string, unknown>[] {
  const candidates: Record<string, unknown>[] = [];

  const metadata = step.metadata;
  if (isPlainObject(metadata)) {
    const inputs = metadata.inputs;
    if (isPlainObject(inputs)) {
      candidates.push(inputs);
    }
  }

  if (isPlainObject(step.params)) {
    candidates.push(step.params);
  }
  if (isPlainObject(step.arguments)) {
    candidates.push(step.arguments);
  }

  return candidates;
}

function isSubsetValue(needle: unknown, haystack: unknown): boolean {
  if (needle === haystack) {
    return true;
  }
  if (typeof needle !== typeof haystack) {
    return false;
  }
  if (needle && typeof needle === "object") {
    if (Array.isArray(needle)) {
      if (!Array.isArray(haystack) || needle.length !== haystack.length) {
        return false;
      }
      for (let idx = 0; idx < needle.length; idx += 1) {
        if (!isSubsetValue(needle[idx], (haystack as unknown[])[idx])) {
          return false;
        }
      }
      return true;
    }
    if (!haystack || typeof haystack !== "object" || Array.isArray(haystack)) {
      return false;
    }
    const haystackRecord = haystack as Record<string, unknown>;
    for (const [key, value] of Object.entries(needle as Record<string, unknown>)) {
      if (!(key in haystackRecord)) {
        return false;
      }
      if (!isSubsetValue(value, haystackRecord[key])) {
        return false;
      }
    }
    return true;
  }
  return false;
}

function findPlanStepIndices(
  plan: Record<string, unknown>,
  toolName: string,
  toolParams?: Record<string, unknown>,
): { matches: number[]; paramMatches: number[] } {
  const steps = Array.isArray(plan.steps) ? plan.steps : [];
  const normalizedTool = normalizeToolName(toolName);
  const matches: number[] = [];
  const paramMatches: number[] = [];
  for (let idx = 0; idx < steps.length; idx += 1) {
    const step = steps[idx];
    if (!step || typeof step !== "object") {
      continue;
    }
    const action =
      typeof (step as { action?: unknown }).action === "string"
        ? String((step as { action?: unknown }).action)
        : typeof (step as { tool?: unknown }).tool === "string"
          ? String((step as { tool?: unknown }).tool)
          : "";
    if (normalizeToolName(action) !== normalizedTool) {
      continue;
    }
    matches.push(idx);
    if (toolParams) {
      const inputCandidates = extractStepInputCandidates(step as Record<string, unknown>);
      if (inputCandidates.some((inputs) => isSubsetValue(inputs, toolParams))) {
        paramMatches.push(idx);
      }
    }
  }
  return { matches, paramMatches };
}

function readStepProofsFromToken(tokenObj: Record<string, unknown>): unknown[] | null {
  if (Array.isArray(tokenObj.stepProofs)) {
    return tokenObj.stepProofs;
  }
  if (Array.isArray((tokenObj as { step_proofs?: unknown }).step_proofs)) {
    return (tokenObj as { step_proofs?: unknown[] }).step_proofs ?? null;
  }
  const rawToken = tokenObj.rawToken;
  if (rawToken && typeof rawToken === "object") {
    if (Array.isArray((rawToken as { stepProofs?: unknown }).stepProofs)) {
      return (rawToken as { stepProofs?: unknown[] }).stepProofs ?? null;
    }
    if (Array.isArray((rawToken as { step_proofs?: unknown }).step_proofs)) {
      return (rawToken as { step_proofs?: unknown[] }).step_proofs ?? null;
    }
  }
  return null;
}

function resolveStepProofEntry(
  stepProofs: unknown[],
  stepIndex: number,
): { proof?: unknown; path?: string; valueDigest?: string; stepIndex: number } | null {
  const entry = stepProofs[stepIndex];
  if (!entry) {
    return null;
  }
  if (Array.isArray(entry)) {
    return { proof: entry, stepIndex };
  }
  if (typeof entry === "object") {
    const record = entry as Record<string, unknown>;
    const proof = Array.isArray(record.proof) ? record.proof : undefined;
    const path =
      readString(record.path) ??
      readString(record.step_path) ??
      readString(record.csrg_path) ??
      undefined;
    const indexFromField = parseStepIndex(record.step_index) ?? parseStepIndex(record.stepIndex);
    const indexFromPath = parseStepIndexFromPath(path);
    const resolvedStepIndex = indexFromField ?? indexFromPath ?? stepIndex;
    const valueDigest =
      readString(record.value_digest) ??
      readString(record.valueDigest) ??
      readString(record.csrg_value_digest) ??
      undefined;
    return { proof, path, valueDigest, stepIndex: resolvedStepIndex };
  }
  return null;
}

function parseStepIndexFromPath(path?: string): number | null {
  if (!path) {
    return null;
  }
  const match = path.match(/\/steps\/\[(\d+)\]/);
  if (!match) {
    return null;
  }
  const index = Number.parseInt(match[1] ?? "", 10);
  return Number.isFinite(index) ? index : null;
}

function getContextTokenUsedStepIndices(
  runKey: string | null,
  tokenRaw: string,
): Set<number> | undefined {
  if (!runKey) {
    return undefined;
  }
  const tokenHash = sha256Hex(tokenRaw);
  const cached = contextTokenExecutionCache.get(runKey);
  if (cached && cached.tokenHash === tokenHash) {
    cached.updatedAt = Date.now();
    return cached.usedStepIndices;
  }
  const entry: ContextTokenExecutionEntry = {
    tokenHash,
    usedStepIndices: new Set<number>(),
    updatedAt: Date.now(),
  };
  contextTokenExecutionCache.set(runKey, entry);
  return entry.usedStepIndices;
}

function scoreProofPath(path?: string): number {
  if (!path) {
    return 0;
  }
  if (/\/(action|tool)$/i.test(path)) {
    return 3;
  }
  if (/\/(arguments|params|metadata)$/i.test(path)) {
    return 1;
  }
  return 2;
}

function chooseProofEntry(
  entries: Array<{ stepIndex: number; proof?: unknown; path?: string; valueDigest?: string }>,
  usedStepIndices?: Set<number>,
): { stepIndex: number; proof?: unknown; path?: string; valueDigest?: string } | null {
  if (!entries.length) {
    return null;
  }
  const stepGroups = new Map<
    number,
    Array<{ stepIndex: number; proof?: unknown; path?: string; valueDigest?: string }>
  >();
  for (const entry of entries) {
    const list = stepGroups.get(entry.stepIndex) ?? [];
    list.push(entry);
    stepGroups.set(entry.stepIndex, list);
  }

  const orderedStepIndices = Array.from(stepGroups.keys()).sort((a, b) => {
    const aUsed = usedStepIndices?.has(a) ? 1 : 0;
    const bUsed = usedStepIndices?.has(b) ? 1 : 0;
    if (aUsed !== bUsed) {
      return aUsed - bUsed;
    }
    return a - b;
  });
  const selectedStepIndex = orderedStepIndices[0];
  if (selectedStepIndex === undefined) {
    return null;
  }
  const candidates = stepGroups.get(selectedStepIndex) ?? [];
  candidates.sort((a, b) => {
    const pathScore = scoreProofPath(b.path) - scoreProofPath(a.path);
    if (pathScore !== 0) {
      return pathScore;
    }
    const digestScore = Number(Boolean(b.valueDigest)) - Number(Boolean(a.valueDigest));
    if (digestScore !== 0) {
      return digestScore;
    }
    return 0;
  });
  return candidates[0] ?? null;
}

function resolveCsrgProofsFromToken(params: {
  intentTokenRaw: string;
  plan: Record<string, unknown>;
  toolName: string;
  toolParams: unknown;
  usedStepIndices?: Set<number>;
}): (CsrgProofHeaders & { stepIndex: number }) | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(params.intentTokenRaw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") {
    return null;
  }
  const tokenObj = parsed as Record<string, unknown>;
  const stepProofs = readStepProofsFromToken(tokenObj);
  if (!stepProofs || stepProofs.length === 0) {
    return null;
  }
  const steps = Array.isArray(params.plan.steps) ? params.plan.steps : [];
  const toolParams = isPlainObject(params.toolParams) ? params.toolParams : undefined;
  const { matches, paramMatches } = findPlanStepIndices(params.plan, params.toolName, toolParams);
  if (matches.length === 0) {
    return null;
  }
  const resolvedEntries: Array<{
    stepIndex: number;
    proof?: unknown;
    path?: string;
    valueDigest?: string;
  }> = [];
  for (let idx = 0; idx < stepProofs.length; idx += 1) {
    const entry = resolveStepProofEntry(stepProofs, idx);
    if (!entry?.proof || !Array.isArray(entry.proof)) {
      continue;
    }
    resolvedEntries.push(entry);
  }

  const entriesMatchingTool = resolvedEntries.filter((resolved) =>
    matches.includes(resolved.stepIndex),
  );
  if (entriesMatchingTool.length === 0) {
    return null;
  }

  const entriesMatchingParams =
    paramMatches.length > 0
      ? entriesMatchingTool.filter((entry) => paramMatches.includes(entry.stepIndex))
      : [];

  const selectedEntry = chooseProofEntry(
    entriesMatchingParams.length > 0 ? entriesMatchingParams : entriesMatchingTool,
    params.usedStepIndices,
  );
  if (
    !selectedEntry ||
    typeof selectedEntry.stepIndex !== "number" ||
    !selectedEntry.proof ||
    !Array.isArray(selectedEntry.proof)
  ) {
    return null;
  }
  const stepIndex = selectedEntry.stepIndex;
  const path = selectedEntry.path ?? `/steps/[${stepIndex}]/action`;
  const stepObj = steps[stepIndex];
  const action =
    typeof (stepObj as { action?: unknown }).action === "string"
      ? String((stepObj as { action?: unknown }).action)
      : typeof (stepObj as { tool?: unknown }).tool === "string"
        ? String((stepObj as { tool?: unknown }).tool)
        : params.toolName;
  const valueDigest = selectedEntry.valueDigest ?? sha256Hex(JSON.stringify(action));
  return { path, proof: selectedEntry.proof, valueDigest, stepIndex };
}

function extractAllowedActions(plan: Record<string, unknown>): Set<string> {
  const allowed = new Set<string>();
  const steps = Array.isArray(plan.steps) ? plan.steps : [];
  for (const step of steps) {
    if (!step || typeof step !== "object") {
      continue;
    }
    const action =
      typeof (step as { action?: unknown }).action === "string"
        ? String((step as { action?: unknown }).action)
        : typeof (step as { tool?: unknown }).tool === "string"
          ? String((step as { tool?: unknown }).tool)
          : "";
    if (action.trim()) {
      allowed.add(normalizeToolName(action));
    }
  }
  return allowed;
}

function extractPlanFromIntentToken(raw: string): {
  plan: Record<string, unknown>;
  expiresAt?: number;
} | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // TODO(armoriq): Support base64-encoded token payloads.
    return null;
  }
  if (!parsed || typeof parsed !== "object") {
    return null;
  }
  const tokenObj = parsed as Record<string, unknown>;
  const rawToken = tokenObj.rawToken as Record<string, unknown> | undefined;
  const planCandidate =
    (rawToken && typeof rawToken.plan === "object"
      ? (rawToken.plan as Record<string, unknown>)
      : undefined) ||
    (typeof tokenObj.plan === "object" ? (tokenObj.plan as Record<string, unknown>) : undefined) ||
    (typeof (tokenObj.token as Record<string, unknown> | undefined)?.plan === "object"
      ? ((tokenObj.token as Record<string, unknown>).plan as Record<string, unknown>)
      : undefined);
  if (!planCandidate) {
    return null;
  }
  const expiresAt =
    typeof tokenObj.expiresAt === "number"
      ? tokenObj.expiresAt
      : typeof (tokenObj.token as Record<string, unknown> | undefined)?.expires_at === "number"
        ? ((tokenObj.token as Record<string, unknown>).expires_at as number)
        : undefined;
  return { plan: planCandidate, expiresAt };
}

function checkIntentTokenPlan(params: {
  intentTokenRaw: string;
  toolName: string;
  toolParams: unknown;
}): {
  matched: boolean;
  blockReason?: string;
  params?: Record<string, unknown>;
  plan?: Record<string, unknown>;
} {
  const parsed = extractPlanFromIntentToken(params.intentTokenRaw);
  if (!parsed) {
    return { matched: false };
  }
  if (parsed.expiresAt && Date.now() / 1000 > parsed.expiresAt) {
    return { matched: true, blockReason: "ArmorIQ intent token expired", plan: parsed.plan };
  }
  const allowedActions = extractAllowedActions(parsed.plan);
  const normalizedTool = normalizeToolName(params.toolName);
  if (!allowedActions.has(normalizedTool)) {
    return {
      matched: true,
      blockReason: `ArmorIQ intent drift: tool not in plan (${params.toolName})`,
      plan: parsed.plan,
    };
  }
  const step = findPlanStep(parsed.plan, params.toolName);
  if (step) {
    const toolParams = isPlainObject(params.toolParams)
      ? (params.toolParams as Record<string, unknown>)
      : undefined;
    if (toolParams && !isParamsAllowedByPlan(step, toolParams)) {
      return {
        matched: true,
        blockReason: `ArmorIQ intent mismatch: parameters not allowed for ${params.toolName}`,
        plan: parsed.plan,
      };
    }
  }
  return {
    matched: true,
    params: isPlainObject(params.toolParams)
      ? (params.toolParams as Record<string, unknown>)
      : undefined,
    plan: parsed.plan,
  };
}

function buildToolList(tools?: Array<{ name: string; description?: string }>): string {
  if (!tools || tools.length === 0) {
    return "- (no tools available)";
  }
  const lines: string[] = [];
  for (const tool of tools) {
    const name = tool.name?.trim();
    if (!name) {
      continue;
    }
    const description = tool.description?.trim();
    lines.push(description ? `- ${name}: ${description}` : `- ${name}`);
  }
  return lines.length > 0 ? lines.join("\n") : "- (no tools available)";
}

function findPlanStep(
  plan: Record<string, unknown>,
  toolName: string,
): Record<string, unknown> | null {
  const steps = Array.isArray(plan.steps) ? plan.steps : [];
  const normalizedTool = normalizeToolName(toolName);
  for (const step of steps) {
    if (!step || typeof step !== "object") {
      continue;
    }
    const action =
      typeof (step as { action?: unknown }).action === "string"
        ? String((step as { action?: unknown }).action)
        : typeof (step as { tool?: unknown }).tool === "string"
          ? String((step as { tool?: unknown }).tool)
          : "";
    if (normalizeToolName(action) === normalizedTool) {
      return step as Record<string, unknown>;
    }
  }
  return null;
}

function isParamsAllowedByPlan(
  _step: Record<string, unknown>,
  _params: Record<string, unknown>,
): boolean {
  // TODO(armoriq): Enforce parameter-level intent by comparing call params against step metadata inputs.
  // This should support placeholders or allowlists of fields to avoid blocking dynamic results.
  return true;
}

function parseToolsFromSystemPrompt(
  systemPrompt?: string,
): Array<{ name: string; description?: string }> {
  if (!systemPrompt) return [];
  const tools: Array<{ name: string; description?: string }> = [];

  // Match tool definition blocks: "tool_name: description" or "- tool_name: description"
  const linePattern = /^[-*]?\s*([a-z0-9_.:/-]+)\s*[:—–-]\s*(.+)/gim;
  for (const match of systemPrompt.matchAll(linePattern)) {
    const name = match[1]?.trim();
    const description = match[2]?.trim();
    if (name && name.length > 1 && name.length < 80) {
      tools.push({ name, description });
    }
  }

  // Match JSON function-calling format: { "name": "tool_name", ... "description": "..." }
  const jsonPattern = /"name"\s*:\s*"([^"]+)"[^}]*?"description"\s*:\s*"([^"]+)"/g;
  const seenNames = new Set(tools.map((t) => normalizeToolName(t.name)));
  for (const match of systemPrompt.matchAll(jsonPattern)) {
    const name = match[1]?.trim();
    const description = match[2]?.trim();
    if (name && !seenNames.has(normalizeToolName(name))) {
      tools.push({ name, description });
      seenNames.add(normalizeToolName(name));
    }
  }

  return tools;
}

async function buildPlanFromPrompt(params: {
  prompt: string;
  tools?: Array<{ name: string; description?: string }>;
  provider: string;
  modelId: string;
  apiKey: string;
  log: (message: string) => void;
}): Promise<Record<string, unknown>> {
  const toolDescriptions = new Map<string, string>();
  for (const tool of params.tools ?? []) {
    const name = tool.name?.trim();
    const description = tool.description?.trim();
    if (name && description) {
      toolDescriptions.set(normalizeToolName(name), description);
    }
  }

  const toolList = buildToolList(params.tools);
  const planningPrompt =
    `You are a planning assistant. Produce a JSON plan for the user's request.\n` +
    `Rules:\n` +
    `- Output ONLY valid JSON.\n` +
    `- Use the tool names exactly as given.\n` +
    `- Create a sequence of tool calls needed to satisfy the request.\n` +
    `- If no tools are needed, return an empty steps array.\n` +
    `- Every step MUST include: { action, mcp }.\n` +
    `- Use mcp="openclaw" for all steps.\n\n` +
    `Available tools:\n${toolList}\n\n` +
    `User request:\n${params.prompt}\n\n` +
    `Return JSON with shape:\n` +
    `{\n  "steps": [ { "action": "tool_name", "mcp": "openclaw", "description": "...", "metadata": { } } ],\n  "metadata": { "goal": "..." }\n}\n`;

  params.log(`armoriq: planning with model ${params.provider}/${params.modelId}`);

  // Ensure pi-ai's built-in API providers (openai-responses, anthropic-messages,
  // google-generative-ai, etc.) are registered. Called every time; the function
  // is idempotent (safe to re-invoke). Without this, resolveApiProvider() returns
  // undefined and completeSimple throws "No API provider registered for api: …".
  try {
    registerBuiltInApiProviders();
  } catch {
    /* ignore — registry may already be populated */
  }

  // Build a full Model descriptor. pi-ai requires api/baseUrl/contextWindow/etc.
  // on top of provider+id — look them up from the built-in catalog.
  let model: Model<Api>;
  try {
    // getModel is strictly typed over the generated MODELS catalog; at runtime
    // we pass dynamic strings so go through `unknown` to keep tsc happy.
    model = (getModel as unknown as (p: string, m: string) => Model<Api>)(
      params.provider,
      params.modelId,
    );
  } catch {
    // Fallback: minimal descriptor that at least has the api field set so
    // resolveApiProvider() can find the provider.
    const apiByProvider: Record<string, Api> = {
      openai: "openai-responses",
      anthropic: "anthropic-messages",
      google: "google-generative-ai",
      "google-vertex": "google-vertex",
      "azure-openai-responses": "azure-openai-responses",
    };
    model = {
      id: params.modelId,
      name: params.modelId,
      api: apiByProvider[params.provider] ?? "openai-responses",
      provider: params.provider,
      baseUrl: "",
      reasoning: false,
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 128000,
      maxTokens: 4096,
    } as Model<Api>;
  }
  const response = await completeSimple(
    model as never,
    {
      messages: [
        {
          role: "user",
          content: planningPrompt,
          timestamp: Date.now(),
        },
      ],
    },
    {
      apiKey: params.apiKey,
      maxTokens: 512,
      temperature: 0.2,
    },
  );

  const content = response.content as string | { type?: string; text?: string }[] | undefined;
  const text =
    typeof content === "string"
      ? content.trim()
      : Array.isArray(content)
        ? content
            .filter((block) => block && block.type === "text")
            .map((block) => block.text ?? "")
            .join(" ")
            .trim()
        : "";

  if (!text) {
    throw new Error("Planner returned empty response");
  }

  // Strip Markdown code-fence wrappers some providers emit around JSON
  // (Gemini emits ```json ... ```; Claude/OpenAI sometimes do too despite
  // "respond with JSON only" instructions). Order of attempts:
  //   1. Fenced block with optional `json` tag
  //   2. First {...} brace-balanced substring in the text
  //   3. Raw text as-is
  const extractJson = (raw: string): string => {
    const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
    if (fenced && fenced[1]) return fenced[1].trim();
    const firstBrace = raw.indexOf("{");
    const lastBrace = raw.lastIndexOf("}");
    if (firstBrace !== -1 && lastBrace > firstBrace) {
      return raw.slice(firstBrace, lastBrace + 1).trim();
    }
    return raw;
  };

  const jsonText = extractJson(text);

  try {
    const parsed = JSON.parse(jsonText) as { steps?: unknown[]; metadata?: Record<string, unknown> };
    if (!parsed.steps || !Array.isArray(parsed.steps)) {
      parsed.steps = [];
    }
    if (!parsed.metadata || typeof parsed.metadata !== "object" || Array.isArray(parsed.metadata)) {
      parsed.metadata = { goal: params.prompt };
    }
    for (const step of parsed.steps as Record<string, unknown>[]) {
      if (!step || typeof step !== "object") {
        continue;
      }
      const stepObj = step as Record<string, unknown>;
      if (!stepObj.action && typeof stepObj.tool === "string") {
        stepObj.action = stepObj.tool;
      }
      if (!stepObj.mcp || typeof stepObj.mcp !== "string") {
        stepObj.mcp = "openclaw";
      }
      if (!stepObj.description && typeof stepObj.action === "string") {
        const description = toolDescriptions.get(normalizeToolName(stepObj.action));
        if (description) {
          stepObj.description = description;
        }
      }
    }
    return parsed;
  } catch (err) {
    throw new Error(`Planner returned invalid JSON: ${err instanceof Error ? err.message : err}`, {
      cause: err,
    });
  }
}

function buildClientKey(cfg: ArmorIqConfig, ids: IdentityBundle): string {
  return [
    cfg.apiKey,
    ids.userId,
    ids.agentId,
    ids.contextId,
    cfg.iapEndpoint,
    cfg.proxyEndpoint,
    cfg.backendEndpoint,
    cfg.useProduction ? "prod" : "dev",
  ]
    .filter(Boolean)
    .join("|");
}

function getClient(cfg: ArmorIqConfig, ids: IdentityBundle): ArmorIQClient {
  const key = buildClientKey(cfg, ids);
  const cached = clientCache.get(key);
  if (cached) {
    return cached;
  }

  const client = new ArmorIQClient({
    apiKey: cfg.apiKey,
    userId: ids.userId,
    agentId: ids.agentId,
    contextId: ids.contextId,
    useProduction: cfg.useProduction,
    iapEndpoint: cfg.iapEndpoint,
    proxyEndpoint: cfg.proxyEndpoint,
    backendEndpoint: cfg.backendEndpoint,
    proxyEndpoints: cfg.proxyEndpoints,
    timeout: cfg.timeoutMs,
    maxRetries: cfg.maxRetries,
    verifySsl: cfg.verifySsl,
  });
  clientCache.set(key, client);
  return client;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sanitizeValue(
  value: unknown,
  opts: {
    maxChars: number;
    maxDepth: number;
    maxKeys: number;
    maxItems: number;
  },
  depth: number,
): unknown {
  if (depth > opts.maxDepth) {
    return "<max-depth>";
  }
  if (value == null) {
    return value;
  }
  if (typeof value === "string") {
    if (value.length <= opts.maxChars) {
      return value;
    }
    return `${value.slice(0, opts.maxChars)}...`;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (typeof value === "symbol") {
    return value.toString();
  }
  if (typeof value === "function") {
    return "<function>";
  }
  if (value instanceof Uint8Array) {
    return `<binary:${value.length}>`;
  }
  if (Array.isArray(value)) {
    return value.slice(0, opts.maxItems).map((entry) => sanitizeValue(entry, opts, depth + 1));
  }
  if (isPlainObject(value)) {
    const entries = Object.entries(value).slice(0, opts.maxKeys);
    const next: Record<string, unknown> = {};
    for (const [key, entry] of entries) {
      next[key] = sanitizeValue(entry, opts, depth + 1);
    }
    return next;
  }
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return "<unserializable>";
  }
}

function sanitizeParams(
  params: Record<string, unknown>,
  cfg: ArmorIqConfig,
): Record<string, unknown> {
  const sanitized = sanitizeValue(
    params,
    {
      maxChars: cfg.maxParamChars,
      maxDepth: cfg.maxParamDepth,
      maxKeys: cfg.maxParamKeys,
      maxItems: cfg.maxParamItems,
    },
    0,
  );
  return isPlainObject(sanitized) ? sanitized : {};
}

export default function register(api: OpenClawPluginApi) {
  const cfg = resolveConfig(api);

  if (!cfg.enabled) {
    api.logger.info("armoriq: plugin disabled (set plugins.entries.armoriq.enabled=true)");
    return;
  }

  const cryptoPolicyService = cfg.cryptoPolicyEnabled
    ? new CryptoPolicyService({
        csrgBaseUrl: cfg.csrgEndpoint,
        timeoutMs: cfg.timeoutMs ?? 30000,
        logger: api.logger,
      })
    : null;

  const handleCryptoPolicyUpdate = async (state: {
    version: number;
    updatedAt: string;
    updatedBy?: string;
    policy: { rules: any[] };
    history: any[];
  }) => {
    if (!cryptoPolicyService) return;
    try {
      const identity = {
        userId: cfg.userId ?? "plugin-user",
        agentId: cfg.agentId ?? "openclaw-agent",
        contextId: cfg.contextId ?? "default",
      };
      const token = await cryptoPolicyService.issuePolicyToken(
        state,
        identity,
        cfg.validitySeconds,
      );
      policyStore.setCryptoTokenDigest(token.policy_digest);
      api.logger.info(
        `armoriq: crypto-bound policy token issued, digest=${token.policy_digest.slice(0, 16)}..., merkle_root=${token.merkle_root?.slice(0, 16)}...`,
      );
    } catch (err) {
      api.logger.warn(`armoriq: crypto policy token issuance failed: ${String(err)}`);
    }
  };

  const policyStore = new PolicyStore({
    filePath: resolvePolicyStorePath(api, cfg),
    basePolicy: normalizePolicyDefinition(cfg.policy),
    logger: api.logger,
    onPolicyChange: cfg.cryptoPolicyEnabled ? handleCryptoPolicyUpdate : undefined,
  });
  const policyReady = policyStore.load().then(async () => {
    if (cfg.cryptoPolicyEnabled && policyStore.getPolicy().rules.length > 0) {
      await handleCryptoPolicyUpdate(policyStore.getState());
    }
  });

  if (cfg.policyUpdateEnabled) {
    api.registerTool(
      (toolCtx) => ({
        name: "policy_update",
        label: "Policy Update",
        description:
          "Manage ArmorIQ policy rules (update/list/delete/reset). Use only for explicit policy changes from authorized users.",
        parameters: PolicyUpdateToolSchema,
        async execute(_toolCallId, params) {
          await policyReady;
          const rawUpdate = (params as { update?: unknown }).update;
          const rawText = readString((params as { text?: unknown }).text);
          const actor = toolCtx.agentId ?? toolCtx.sessionKey ?? "unknown";

          if (rawText) {
            const command = parsePolicyTextCommand(rawText, policyStore.getState());
            if (command.kind === "list") {
              const state = policyStore.getState();
              return {
                content: [{ type: "text", text: formatPolicyList(state) }],
                details: { action: "list", version: state.version },
              };
            }
            if (command.kind === "help") {
              return {
                content: [{ type: "text", text: formatPolicyHelp() }],
                details: { action: "help" },
              };
            }
            if (command.kind === "need_id") {
              return {
                content: [{ type: "text", text: formatPolicyNeedId() }],
                details: { action: "need_id" },
              };
            }
            if (command.kind === "get") {
              const rule = policyStore
                .getState()
                .policy.rules.find((entry) => entry.id === command.id);
              return {
                content: [
                  {
                    type: "text",
                    text: rule
                      ? `Policy rule:\n- ${formatPolicyRule(rule)}`
                      : `Policy rule not found: ${command.id}`,
                  },
                ],
                details: { action: "get", id: command.id, found: Boolean(rule) },
              };
            }
            if (command.kind === "reorder") {
              try {
                const nextState = await policyStore.reorderRule(
                  command.id,
                  command.position,
                  actor,
                  command.reason,
                );
                return {
                  content: [
                    {
                      type: "text",
                      text: `Policy ${command.id} moved to position ${command.position}.`,
                    },
                  ],
                  details: {
                    action: "reorder",
                    id: command.id,
                    position: command.position,
                    version: nextState.version,
                  },
                };
              } catch (err) {
                return {
                  content: [
                    {
                      type: "text",
                      text: `Policy reorder failed: ${
                        err instanceof Error ? err.message : String(err)
                      }`,
                    },
                  ],
                  details: { action: "reorder", error: String(err) },
                };
              }
            }
            if (command.kind === "delete") {
              const beforeCount = policyStore.getState().policy.rules.length;
              const nextState = await policyStore.removeRules(command.ids, actor, command.reason);
              const afterCount = nextState.policy.rules.length;
              const removed = beforeCount - afterCount;
              return {
                content: [
                  {
                    type: "text",
                    text:
                      removed > 0
                        ? `Policy updated: removed ${removed} rule(s): ${command.ids.join(", ")}.`
                        : `No matching rules removed. Known rules:\n${formatPolicyList(
                            policyStore.getState(),
                          )}`,
                  },
                ],
                details: {
                  version: nextState.version,
                  updatedAt: nextState.updatedAt,
                  policyHash: policyStore.getPolicyHash(),
                },
              };
            }
            if (command.kind === "reset") {
              const resetUpdate: PolicyUpdate = {
                reason: command.reason,
                mode: "replace",
                rules: [],
              };
              const parsedReset = PolicyUpdateSchema.safeParse(resetUpdate);
              if (!parsedReset.success) {
                return {
                  content: [
                    {
                      type: "text",
                      text: `Policy reset rejected: ${parsedReset.error.message}`,
                    },
                  ],
                  details: { error: parsedReset.error.flatten() },
                };
              }
              const nextState = await policyStore.applyUpdate(parsedReset.data, actor);
              return {
                content: [
                  {
                    type: "text",
                    text: `Policy reset to version ${nextState.version}.`,
                  },
                ],
                details: {
                  version: nextState.version,
                  updatedAt: nextState.updatedAt,
                  policyHash: policyStore.getPolicyHash(),
                },
              };
            }
            if (command.kind === "update") {
              const parsed = PolicyUpdateSchema.safeParse(command.update);
              if (!parsed.success) {
                return {
                  content: [
                    {
                      type: "text",
                      text: `Policy update rejected: ${parsed.error.message}`,
                    },
                  ],
                  details: { error: parsed.error.flatten() },
                };
              }
              const nextState = await policyStore.applyUpdate(parsed.data, actor);
              return {
                content: [
                  {
                    type: "text",
                    text: `Policy updated to version ${nextState.version}.`,
                  },
                ],
                details: {
                  version: nextState.version,
                  updatedAt: nextState.updatedAt,
                  policyHash: policyStore.getPolicyHash(),
                },
              };
            }
          }

          if (!rawUpdate) {
            return {
              content: [
                {
                  type: "text",
                  text: "Policy update rejected: missing update or text payload.",
                },
              ],
              details: { action: "error", reason: "missing_update" },
            };
          }

          const parsed = PolicyUpdateSchema.safeParse(rawUpdate);
          if (!parsed.success) {
            return {
              content: [
                {
                  type: "text",
                  text: `Policy update rejected: ${parsed.error.message}`,
                },
              ],
              details: { error: parsed.error.flatten() },
            };
          }
          try {
            const nextState = await policyStore.applyUpdate(parsed.data, actor);
            return {
              content: [
                {
                  type: "text",
                  text: `Policy updated to version ${nextState.version}.`,
                },
              ],
              details: {
                version: nextState.version,
                updatedAt: nextState.updatedAt,
                policyHash: policyStore.getPolicyHash(),
              },
            };
          } catch (err) {
            return {
              content: [
                {
                  type: "text",
                  text: `Policy update failed: ${err instanceof Error ? err.message : String(err)}`,
                },
              ],
              details: { error: err instanceof Error ? err.stack : String(err) },
            };
          }
        },
      }),
      { name: "policy_update" },
    );
  }

  const verificationService = new IAPVerificationService({
    iapBaseUrl: cfg.backendEndpoint ?? cfg.iapEndpoint,
    timeoutMs: cfg.timeoutMs,
    logger: api.logger,
  });

  // Cache sender identity from inbound messages
  api.on("inbound_claim" as any, async (event: any) => {
    const key = event.conversationId ?? event.senderId ?? "unknown";
    senderIdentityCache.set(key, {
      senderId: event.senderId,
      senderName: event.senderName,
      senderUsername: event.senderUsername,
      accountId: event.accountId,
      channel: event.channel,
      conversationId: event.conversationId,
      cachedAt: Date.now(),
    });
    api.logger.info(`armoriq: [inbound_claim] cached sender identity for key=${key}`);
  });

  // Inject policy update instructions into the system prompt
  api.on("before_prompt_build" as any, async () => {
    if (!cfg.policyUpdateEnabled) return undefined;
    return { prependSystemContext: POLICY_UPDATE_INSTRUCTIONS };
  });

  // Generate intent plan when LLM input is prepared (fire-and-forget; awaited in before_tool_call)
  api.on("llm_input" as any, async (event: any, _ctx: any) => {
    const llmCtx: ToolContext = {
      runId: event.runId,
      sessionKey: _ctx?.sessionKey ?? event.sessionId,
      agentId: _ctx?.agentId,
    };
    const runKey = resolveRunKey(llmCtx);
    if (!runKey || planCache.has(runKey)) return;

    const planPromise = (async () => {
      const toolCtx = buildToolContextFromCaches(llmCtx);
      const identity = resolveIdentities(cfg, toolCtx);
      if (!identity) {
        planCache.set(runKey, {
          token: null,
          plan: { steps: [], metadata: { goal: "invalid" } },
          allowedActions: new Set(),
          executedStepIndices: new Set(),
          createdAt: Date.now(),
          error: "ArmorIQ identity missing (userId/agentId)",
        });
        return;
      }

      try {
        await policyReady;
        const tools = parseToolsFromSystemPrompt(event.systemPrompt);
        const authResult = await (api as any).runtime.modelAuth.resolveApiKeyForProvider({
          provider: event.provider,
        });
        const apiKey = typeof authResult === "string" ? authResult : authResult?.apiKey ?? authResult?.key;
        if (!apiKey) {
          throw new Error(`No API key available for provider ${event.provider}`);
        }
        const plan = await buildPlanFromPrompt({
          prompt: event.prompt,
          tools,
          provider: event.provider,
          modelId: event.model,
          apiKey,
          log: (message) => api.logger.info(message),
        });
        const planRecord = plan as Record<string, unknown>;
        const metadata = readRecord(planRecord.metadata);
        const normalizedMetadata = metadata ?? {};
        normalizedMetadata.policy_hash = policyStore.getPolicyHash();
        normalizedMetadata.policy_version = policyStore.getState().version;
        planRecord.metadata = normalizedMetadata;

        const client = getClient(cfg, identity);
        const planCapture = client.capturePlan("openclaw", event.prompt, plan, {
          sessionKey: toolCtx.sessionKey,
          messageChannel: toolCtx.messageChannel,
          accountId: toolCtx.accountId,
          senderId: toolCtx.senderId,
          senderName: toolCtx.senderName,
          senderUsername: toolCtx.senderUsername,
          runId: event.runId,
        });
        const token = await client.getIntentToken(planCapture, cfg.policy, cfg.validitySeconds);
        const tokenRaw = JSON.stringify(token);
        const tokenParsed = extractPlanFromIntentToken(tokenRaw);
        const tokenPlan = tokenParsed?.plan ?? plan;
        // The /iap/sdk/token backend response includes plan_id + jwt_token.
        // Newer SDKs may surface them on the returned token under various
        // names; probe a few to stay forward-compatible.
        const tokenAny = token as Record<string, unknown>;
        const planId =
          (typeof tokenAny.plan_id === "string" && tokenAny.plan_id) ||
          (typeof tokenAny.planId === "string" && tokenAny.planId) ||
          (typeof (tokenAny as any).planRecordId === "string" && (tokenAny as any).planRecordId) ||
          undefined;
        const jwtToken =
          (typeof tokenAny.jwt_token === "string" && tokenAny.jwt_token) ||
          (typeof tokenAny.jwtToken === "string" && tokenAny.jwtToken) ||
          undefined;
        planCache.set(runKey, {
          token,
          tokenRaw,
          tokenPlan,
          plan: tokenPlan,
          allowedActions: extractAllowedActions(tokenPlan),
          executedStepIndices: new Set<number>(),
          createdAt: Date.now(),
          expiresAt:
            typeof tokenParsed?.expiresAt === "number"
              ? tokenParsed.expiresAt
              : typeof token.expiresAt === "number"
                ? token.expiresAt
                : undefined,
          planId: planId || undefined,
          jwtToken: jwtToken || undefined,
        });
        const sessionId = event.sessionId?.trim();
        if (sessionId && runKey !== sessionId) {
          sessionKeyIndex.set(sessionId, runKey);
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        // Surface planning failures in the gateway log. Silent failure here
        // means no plan/intent-token is ever created, which breaks the
        // dashboard (no plan row, no audit chain). Log loudly.
        api.logger.warn(
          `armoriq: planning failed (runKey=${runKey}) — ${message}`,
        );
        if (err instanceof Error && err.stack) {
          api.logger.warn(`armoriq: planning stack:\n${err.stack}`);
        }
        planCache.set(runKey, {
          token: null,
          plan: { steps: [], metadata: { goal: "invalid" } },
          allowedActions: new Set(),
          executedStepIndices: new Set(),
          createdAt: Date.now(),
          error: `ArmorIQ planning failed: ${message}`,
        });
      }
    })();

    planningPromises.set(runKey, planPromise);
    api.logger.info(
      `armoriq: [llm_input] planning started runKey=${runKey} provider=${event.provider} model=${event.model}`,
    );
  });

  api.on("agent_end", async (_event, ctx) => {
    const runKey = resolveRunKey(ctx as ToolContext);
    if (!runKey) return;
    const indexed = sessionKeyIndex.get(runKey);
    const cacheKey = indexed ?? runKey;
    const cached = planCache.get(cacheKey);

    // Before evicting the plan from the cache, mark it complete on the backend
    // so the dashboard row transitions from EXECUTING → COMPLETED. A plan can
    // reach agent_end without any non-policy_update tool calls (pure chat, or
    // policy-only turns); in those cases we'd otherwise leave the row active
    // forever. Fire-and-forget; errors are logged and never block eviction.
    if (cached && cached.planId && !cached.error) {
      const token = cached.jwtToken ?? cached.tokenRaw ?? "";
      const backendUrl =
        cfg.backendEndpoint ??
        process.env.BACKEND_ENDPOINT ??
        "http://127.0.0.1:8081";
      if (token) {
        void fetch(`${backendUrl}/iap/plans/${cached.planId}/status`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
            ...(cfg.apiKey ? { "X-API-Key": cfg.apiKey } : {}),
          },
          body: JSON.stringify({ status: "completed" }),
        }).catch((err) => {
          api.logger.warn(
            `armoriq: plan complete-on-end failed (non-fatal): ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        });
      }
    }

    if (indexed) {
      planCache.delete(indexed);
      contextTokenExecutionCache.delete(indexed);
      planningPromises.delete(indexed);
      sessionKeyIndex.delete(runKey);
    } else {
      planCache.delete(runKey);
      contextTokenExecutionCache.delete(runKey);
      planningPromises.delete(runKey);
    }
  });

  // ── audit-on-success ────────────────────────────────────────────────────
  // Fire-and-forget audit log for every tool that actually executed (so the
  // backend's /iap/audit handler can flip the parent plan to "completed" once
  // all steps succeed). policy_update is internal — skip it.
  api.on("after_tool_call", async (event, ctx) => {
    try {
      const normalized = normalizeToolName(event.toolName);
      if (normalized === "policy_update") return;
      const runKey = resolveRunKey(ctx as ToolContext);
      if (!runKey) return;
      const cached =
        planCache.get(runKey) ??
        planCache.get(sessionKeyIndex.get(runKey) ?? "");
      if (!cached) return;
      const token = cached.jwtToken ?? cached.tokenRaw ?? "";
      if (!token) return;
      const isError = typeof event.error === "string" && event.error.length > 0;
      void verificationService
        .createAuditLog({
          token,
          plan_id: cached.planId,
          step_index: 0,
          action: "tool_call",
          tool: event.toolName,
          input: sanitizeParams(
            isPlainObject(event.params)
              ? (event.params as Record<string, unknown>)
              : {},
            cfg,
          ),
          output: isError ? null : (event.result ?? null),
          status: isError ? "failed" : "success",
          error_message: isError ? event.error : undefined,
          duration_ms: event.durationMs ?? 0,
          executed_at: new Date().toISOString(),
        })
        .catch((auditErr) => {
          api.logger.warn(
            `armoriq: audit-on-success failed (non-fatal): ${
              auditErr instanceof Error ? auditErr.message : String(auditErr)
            }`,
          );
        });
    } catch (err) {
      api.logger.warn(
        `armoriq: after_tool_call hook errored: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  });

  api.on("before_tool_call", async (event, ctx) => {
    const normalizedTool = normalizeToolName(event.toolName);
    const toolCtx = buildToolContextFromCaches(ctx);
    const runKey = resolveRunKey(toolCtx);
    api.logger.info(
      `armoriq: [tool_call] tool=${normalizedTool} runKey=${runKey} runId=${toolCtx.runId} sessionKey=${toolCtx.sessionKey} cacheKeys=[${[...planCache.keys()].join(",")}]`,
    );

    // Await pending plan if llm_input planning is still in flight
    const pending = planningPromises.get(runKey ?? "");
    if (pending) {
      try { await pending; } catch { /* errors are captured in planCache */ }
      planningPromises.delete(runKey ?? "");
    }

    const policyCheck = async (): Promise<{ block: true; blockReason: string } | null> => {
      if (normalizedTool === "policy_update") {
        return null;
      }
      await policyReady;
      const policy = policyStore.getPolicy();
      if (!policy.rules.length) {
        return null;
      }

      if (cfg.cryptoPolicyEnabled && cryptoPolicyService) {
        const currentDigest = computePolicyDigest(policy.rules);
        const tokenDigest = policyStore.getCryptoTokenDigest();
        const verifyResult = cryptoPolicyService.verifyPolicyDigest(currentDigest, tokenDigest);
        if (!verifyResult.valid) {
          api.logger.warn(`armoriq: crypto policy verification failed: ${verifyResult.reason}`);
          return {
            block: true,
            blockReason: `ArmorIQ crypto policy mismatch: ${verifyResult.reason}`,
          };
        }
        api.logger.info?.(`armoriq: crypto policy digest verified`);
      }

      const rawParams = isPlainObject(event.params)
        ? (event.params as Record<string, unknown>)
        : {};
      const sanitized = sanitizeParams(rawParams, cfg);
      const decision = evaluatePolicy({
        policy,
        toolName: event.toolName,
        toolParams: sanitized,
      });
      if (!decision.allowed) {
        api.logger.warn(
          `armoriq: policy block tool=${event.toolName} rule=${
            decision.matchedRule?.id ?? "unknown"
          } action=${decision.matchedRule?.action ?? "unknown"} dataClasses=${JSON.stringify(
            decision.dataClasses,
          )} runId=${String(toolCtx.runId ?? "")} sessionKey=${String(
            toolCtx.sessionKey ?? "",
          )} senderId=${String(toolCtx.senderId ?? "")} senderUsername=${String(
            toolCtx.senderUsername ?? "",
          )}`,
        );
        // Fire-and-forget audit so the dashboard records the block. We don't
        // await — the deny path must remain fast and never fail because the
        // audit endpoint blipped.
        const cachedForBlock = planCache.get(runKey ?? "");
        const blockToken =
          cachedForBlock?.jwtToken ?? cachedForBlock?.tokenRaw ?? "";
        if (blockToken) {
          void verificationService
            .createAuditLog({
              token: blockToken,
              plan_id: cachedForBlock?.planId,
              step_index: 0,
              action: "policy_deny",
              tool: event.toolName,
              input: sanitized,
              output: null,
              status: "failed",
              error_message: `policy_deny: ${decision.matchedRule?.id ?? "unknown"}`,
              duration_ms: 0,
              executed_at: new Date().toISOString(),
            })
            .catch((auditErr) => {
              api.logger.warn(
                `armoriq: audit-on-block failed (non-fatal): ${
                  auditErr instanceof Error ? auditErr.message : String(auditErr)
                }`,
              );
            });
        }
        return {
          block: true,
          blockReason: decision.reason ?? "ArmorIQ policy denied",
        };
      }
      return null;
    };

    if (normalizedTool === "policy_update") {
      const allowed = isPolicyUpdateAllowed(cfg, toolCtx);
      if (!allowed.allowed) {
        api.logger.warn(
          `armoriq: policy_update denied (allowList=${JSON.stringify(
            cfg.policyUpdateAllowList ?? [],
          )}, candidates=${JSON.stringify(allowed.candidates ?? [])}, senderId=${String(
            toolCtx.senderId ?? "",
          )}, senderUsername=${String(toolCtx.senderUsername ?? "")}, sessionKey=${String(
            toolCtx.sessionKey ?? "",
          )})`,
        );
        return {
          block: true,
          blockReason: allowed.reason ?? "ArmorIQ policy update denied",
        };
      }
      return event.params ? { params: event.params as Record<string, unknown> } : undefined;
    }
    const verifyWithIap = async (
      tokenRaw: string,
      plan: Record<string, unknown>,
      usedStepIndices?: Set<number>,
    ): Promise<{ block: true; blockReason: string } | { block: false; stepIndex?: number }> => {
      const proofParse = parseCsrgProofHeaders(toolCtx);
      if (proofParse.error) {
        return { block: true, blockReason: proofParse.error };
      }
      let proofs = proofParse.proofs;
      let resolvedStepIndex = parseStepIndexFromPath(proofs?.path) ?? undefined;
      if (!proofs) {
        const resolvedProofs = resolveCsrgProofsFromToken({
          intentTokenRaw: tokenRaw,
          plan,
          toolName: event.toolName,
          toolParams: event.params,
          usedStepIndices,
        });
        if (resolvedProofs) {
          proofs = resolvedProofs;
          resolvedStepIndex = resolvedProofs.stepIndex;
        }
      }
      const proofCount = proofs?.proof && Array.isArray(proofs.proof) ? proofs.proof.length : 0;
      api.logger.info(
        `armoriq: verify-step request tool=${event.toolName} runId=${String(
          toolCtx.runId ?? "",
        )} proofs=${proofs ? "present" : "none"} proofCount=${proofCount} path=${String(
          proofs?.path ?? "",
        )}`,
      );
      const proofsRequired =
        verificationService.csrgProofsRequired() && verificationService.csrgVerifyIsEnabled();
      const proofError = validateCsrgProofHeaders(proofs, proofsRequired);
      if (proofError) {
        return { block: true, blockReason: proofError };
      }

      let verifyToken = tokenRaw;
      try {
        const parsed = JSON.parse(tokenRaw);
        if (parsed?.jwtToken) {
          verifyToken = parsed.jwtToken;
          api.logger.info(
            `armoriq: using jwtToken for verification (length=${verifyToken.length})`,
          );
        } else {
          api.logger.warn(
            `armoriq: no jwtToken in token, using raw (keys=${Object.keys(parsed).join(",")})`,
          );
        }
      } catch {
        api.logger.warn(`armoriq: failed to parse tokenRaw, using as-is`);
      }

      try {
        const verifyResult = await verificationService.verifyStep(
          verifyToken,
          proofs,
          event.toolName,
        );
        api.logger.info(
          `armoriq: verify-step result tool=${event.toolName} allowed=${
            verifyResult.allowed
          } reason=${verifyResult.reason || "n/a"}`,
        );
        if (!verifyResult.allowed) {
          return {
            block: true,
            blockReason: verifyResult.reason || "ArmorIQ intent verification denied",
          };
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          block: true,
          blockReason: `ArmorIQ intent verification failed: ${message}`,
        };
      }
      return { block: false, stepIndex: resolvedStepIndex };
    };

    if (!cfg.apiKey) {
      return { block: true, blockReason: "ArmorIQ API key missing" };
    }

    const identity = resolveIdentities(cfg, toolCtx);
    if (!identity) {
      return {
        block: true,
        blockReason: "ArmorIQ identity missing (userId/agentId)",
      };
    }

    if (!runKey) {
      return {
        block: true,
        blockReason: "ArmorIQ run id missing",
      };
    }

    const cached = planCache.get(runKey) ?? planCache.get(sessionKeyIndex.get(runKey) ?? "");

    if (!cached) {
      return {
        block: true,
        blockReason: "ArmorIQ intent plan missing for this run",
      };
    }

    if (cached.error) {
      return {
        block: true,
        blockReason: cached.error,
      };
    }

    if (cached.tokenRaw) {
      const tokenCheck = checkIntentTokenPlan({
        intentTokenRaw: cached.tokenRaw,
        toolName: event.toolName,
        toolParams: event.params,
      });
      if (tokenCheck.matched) {
        api.logger.info(
          `armoriq: plan check (cached token) tool=${event.toolName} steps=${
            Array.isArray(tokenCheck.plan?.steps) ? tokenCheck.plan?.steps.length : 0
          } status=${tokenCheck.blockReason ? "blocked" : "ok"}`,
        );
        if (tokenCheck.blockReason) {
          return { block: true, blockReason: tokenCheck.blockReason };
        }
        const policyResult = await policyCheck();
        if (policyResult) {
          return policyResult;
        }
        const csrgResult = await verifyWithIap(
          cached.tokenRaw,
          tokenCheck.plan ?? {},
          cached.executedStepIndices,
        );
        if (csrgResult.block) {
          return csrgResult;
        }
        if (typeof csrgResult.stepIndex === "number") {
          cached.executedStepIndices.add(csrgResult.stepIndex);
        }
        return { params: tokenCheck.params ?? event.params };
      }
    }

    if (cached.expiresAt && Date.now() / 1000 > cached.expiresAt) {
      return {
        block: true,
        blockReason: "ArmorIQ intent token expired",
      };
    }

    if (!cached.allowedActions.has(normalizedTool)) {
      return {
        block: true,
        blockReason: `ArmorIQ intent drift: tool not in plan (${event.toolName})`,
      };
    }

    const step = findPlanStep(cached.plan, event.toolName);
    if (step) {
      const params = isPlainObject(event.params) ? event.params : {};
      if (!isParamsAllowedByPlan(step, params)) {
        return {
          block: true,
          blockReason: `ArmorIQ intent mismatch: parameters not allowed for ${event.toolName}`,
        };
      }
    }

    const policyResult = await policyCheck();
    if (policyResult) {
      return policyResult;
    }
    return { params: event.params };
  });
}
