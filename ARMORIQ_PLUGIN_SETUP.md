# ArmorIQ OpenClaw Plugin - Setup & Reference

**Target**: OpenClaw v2026.2.12
**Last verified**: 14 Feb 2026

The ArmorIQ plugin provides intent enforcement, cryptographic policy verification, and audit integration for OpenClaw agents.This doc covers how to install the standalone plugin into OpenClaw Latest Release .

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  OpenClaw Gateway                                   │
│  ┌───────────────────────────────────────────────┐  │
│  │  before_agent_start hook                      │  │
│  │  ┌─────────────────────────────────────────┐  │  │
│  │  │  ArmorIQ Plugin                         │  │  │
│  │  │  - Intent Planning (LLM call)           │  │  │
│  │  │  - Token issuance (IAP backend)         │  │  │
│  │  │  - Step verification (CSRG)             │  │  │
│  │  │  - Policy enforcement                   │  │  │
│  │  └─────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────┘  │
│  before_tool_call hook → verify step against token  │
│  agent_end hook → audit logging                     │
└─────────────────────────────────────────────────────┘
         │                          │
         ▼                          ▼
   IAP Backend               CSRG Verification
   (intent tokens)           (cryptographic proofs)
```

## The Problem: Vanilla OpenClaw Missing Hook Context

The **official OpenClaw** `before_agent_start` hook only passes 4 fields to plugins:

```typescript
// Official OpenClaw (vanilla)
{
  agentId, sessionKey, workspaceDir, messageProvider
}
```

The ArmorIQ plugin needs **13 fields** to function:

```typescript
// What ArmorIQ needs
{
  agentId, sessionKey, workspaceDir, messageProvider,
  messageChannel, accountId, senderId, senderName,
  senderUsername, senderE164, runId, model, modelRegistry
}
```

Without `model`, the plugin can't make LLM calls for intent planning.
Without `senderId`/`senderName`, per-user policy enforcement is impossible.
Without `tools`, the plugin can't inspect what tools are available.

Additionally, the `before_tool_call` hook in vanilla OpenClaw passes **no identity context** (`agentId`, `sessionKey` are missing), which means the plugin can't match the caller against the policy allowList and denies all tool calls.

A secondary issue in v2026.2.12: `toToolDefinitions()` in `pi-tool-definition-adapter.ts` added a **duplicate** `before_tool_call` hook invocation that fires _before_ the one in `handlers.tools.ts`, without any context — causing immediate denial even after the handlers path was fixed.

## Patch to Fix This

Apply `patch-armoriq.sh` to a fresh v2026.2.12 clone. The patch modifies 5 files:

| File | Change |
|------|--------|
| `src/plugins/types.ts` | Extended `PluginHookAgentContext` with 9 new optional fields, extended `PluginHookBeforeAgentStartEvent` with `tools` array |
| `src/agents/pi-embedded-runner/run/attempt.ts` | Passes extended context to `runBeforeAgentStart` hook; passes `agentId`/`sessionKey` to `subscribeEmbeddedPiSession` |
| `src/agents/pi-embedded-subscribe.types.ts` | Added `agentId?`/`sessionKey?` to `SubscribeEmbeddedPiSessionParams` |
| `src/agents/pi-embedded-subscribe.handlers.tools.ts` | Fixed `before_tool_call` hook to pass `agentId`/`sessionKey` from subscribe params |
| `src/agents/pi-tool-definition-adapter.ts` | Removed duplicate `before_tool_call`/`after_tool_call` hooks from `toToolDefinitions()` (hooks are handled by `handlers.tools.ts`) |

All changes are **backward-compatible** (new fields are optional).

---

## Step-by-Step Setup

### Prerequisites

- Node.js v22+
- pnpm v10+
- OpenAI API key (or OpenRouter key for model access)

### 1. Clone OpenClaw v2026.2.12 and Patch

```bash
git clone --branch v2026.2.12 https://github.com/openclaw/openclaw.git
cd openclaw
bash /path/to/patch-armoriq.sh
pnpm install
pnpm build
```

### 3. Install the ArmorIQ Plugin

```bash
# Remove stale installs if any
rm -rf ~/.openclaw/extensions/armoriq

# Install from local path
node openclaw.mjs plugins install /path/to/armoriq-openclaw-plugin
```

### 4. Configure OpenClaw

Edit `~/.openclaw/openclaw.json` and add under `plugins.entries`:

```json
{
  "plugins": {
    "enabled": true,
    "entries": {
      "armoriq": {
        "enabled": true,
        "config": {
          "enabled": true,
          "userId": "test-user-001",
          "agentId": "openclaw-agent-001",
          "contextId": "default",
          "policyUpdateEnabled": true,
          "policyUpdateAllowList": ["5929428080", "akv2011"],
          "policyStorePath": "~/.openclaw/armoriq.policy.json"
        }
      }
    }
  }
}
```

### 5. Set Environment Variables

Create a `.env` file in the openclaw root:

```bash
# ArmorIQ 
ARMORIQ_API_KEY=ak_live_...
IAP_BACKEND_URL=https://customer-api.armoriq.ai
CSRG_URL=https://customer-iap.armoriq.ai
IAP_ENDPOINT=https://customer-iap.armoriq.ai
PROXY_ENDPOINT=https://customer-proxy.armoriq.ai
BACKEND_ENDPOINT=https://customer-api.armoriq.ai

# LLM provider
OPENAI_API_KEY=sk-proj-...
# OR
OPENROUTER_API_KEY=sk-or-...
```

### 6. Run the Gateway

```bash
export $(grep -v '^#' .env | xargs)
pnpm dev gateway
```

---

## Environment Variables Reference

| Variable | Used By | Default | Purpose |
|----------|---------|---------|---------|
| `ARMORIQ_API_KEY` | Plugin config | none | API key for ArmorIQ services |
| `IAP_BACKEND_URL` | `iap-verification.service.ts` | `https://customer-api.armoriq.ai` | IAP backend for intent tokens |
| `CONMAP_AUTO_URL` | `iap-verification.service.ts` | (fallback for IAP) | Alternative IAP URL |
| `CSRG_URL` | `crypto-policy.service.ts`, `iap-verification.service.ts` | `https://customer-iap.armoriq.ai` | CSRG cryptographic verification |
| `IAP_ENDPOINT` | Plugin config (`index.ts`) | none | IAP endpoint (plugin-level) |
| `PROXY_ENDPOINT` | Plugin config (`index.ts`) | none | Proxy endpoint |
| `BACKEND_ENDPOINT` | Plugin config (`index.ts`) | none | Backend endpoint |
| `REQUIRE_CSRG_PROOFS` | `iap-verification.service.ts` | `true` | Require CSRG proof headers |
| `CSRG_VERIFY_ENABLED` | `iap-verification.service.ts` | `true` | Enable CSRG /verify/action |
| `USER_ID` | Plugin config | none | Default user ID |
| `AGENT_ID` | Plugin config | none | Default agent ID |
| `CONTEXT_ID` | Plugin config | none | Default context ID |
| `ARMORIQ_POLICY_STORE_PATH` | Plugin config | none | Policy JSON file path |
| `ARMORIQ_POLICY_UPDATE_ENABLED` | Plugin config | none | Allow policy updates |
| `ARMORIQ_CRYPTO_POLICY_ENABLED` | Plugin config | none | Enable crypto policy |

---

## Problems Encountered & Fixes

### 1. Plugin build failed on types

**Error**: Type mismatch when accessing `ctx.model` in hook handler.

**Fix**: Used type assertions in the plugin `index.ts` since the vanilla SDK types didn't include the extended fields:
```typescript
const model = (ctx as any).model;
```
After the PR is merged upstream, these casts can be removed.

### 2. Plugin install failed - missing dependency

**Error**: `failed to load plugin: Cannot find module '@mariozechner/pi-ai'`

**Fix**: Installed the missing dependency in the plugin:
```bash
cd armoriq-openclaw-plugin
npm install @mariozechner/pi-ai
npm run build
```

### 3. Plugin install failed - directory already exists

**Error**: `plugin already exists: ~/.openclaw/extensions/armoriq`

**Fix**: Remove the old extension directory first:
```bash
rm -rf ~/.openclaw/extensions/armoriq
```

### 4. Config validation failed

**Error**: `plugins.entries.armoriq: plugin not found: armoriq`

**Cause**: Config references the plugin but the extension directory was deleted.

**Fix**: Either remove the `armoriq` entry from config, install the plugin, then re-add it. Or clear `plugins.installs` from the config JSON.

### 5. Intent Planning returned 0 steps (first run)

**Log**: `Plan captured with 0 steps`

**Cause**: First run with no conversation history; the LLM had nothing to plan against.

**Fix**: Normal behavior. Subsequent messages with tool actions produce proper plans (seen: `Plan captured with 2 steps`).

### 6. Telegram sendChatAction network error

**Error**: `TypeError: fetch failed` / `telegram sendChatAction failed`

**Cause**: Network timeout or Telegram API rate limit.

**Fix**: Non-fatal, gateway continues. The error is logged but doesn't block agent execution.

### 7. policy_update denied on v2026.2.12 (before_tool_call missing context)

**Log**:
```
[tool_call] tool=policy_update runKey=null sessionKey=undefined candidates=[]
policy_update denied (allowList=[...], candidates=[], senderId=, senderUsername=, sessionKey=)
```

**Cause**: Two issues in vanilla v2026.2.12:
1. `toToolDefinitions()` in `pi-tool-definition-adapter.ts` added an inline `before_tool_call` hook that fires **without any identity context** (`agentId`, `sessionKey` are undefined). This duplicate hook fires before the one in `handlers.tools.ts`, causing immediate denial.
2. `handlers.tools.ts` only passed `{ toolName }` to `runBeforeToolCall` — no `agentId` or `sessionKey`.

**Fix** (applied in `patch-armoriq.sh`):
- Removed the duplicate `before_tool_call` + `after_tool_call` hooks from `toToolDefinitions()` (hooks are already handled by `handlers.tools.ts`)
- Added `agentId`/`sessionKey` to `SubscribeEmbeddedPiSessionParams`
- Passed `agentId: sessionAgentId` and `sessionKey: params.sessionKey` in the `subscribeEmbeddedPiSession()` call in `attempt.ts`
- Fixed `handlers.tools.ts` to pass `agentId: ctx.params.agentId` and `sessionKey: ctx.params.sessionKey` to the hook

**Verified**: After patch, both hook calls show `runKey=agent:main:main sessionKey=agent:main:main` and policy operations work correctly.

---

## Successful Run Log (Verified Working)

```
[plugins] armoriq: [agent_start] runKey=agent:main:main::... sessionKey=agent:main:main
[plugins] armoriq: planning with model openai/gpt-5.1
Plan captured with 2 steps
Intent token issued: id=..., plan_hash=..., expires=60.0s, stepProofs=8

[plugins] armoriq: [tool_call] tool=read
[plugins] armoriq: plan check (cached token) tool=read steps=2 status=ok
[plugins] armoriq: verify-step result tool=read allowed=true reason=Token valid, proof verified, policy allows

[plugins] armoriq: [tool_call] tool=message
[plugins] armoriq: verify-step result tool=message allowed=true reason=Token valid, proof verified, policy allows
```

Policy operations via Telegram (v2026.2.12 patched):
```
[tool_call] tool=policy_update runKey=agent:main:main sessionKey=agent:main:main
[tool_call] tool=policy_update runKey=agent:main:main sessionKey=agent:main:main
```

This confirms:
- Plugin loads and registers hooks
- Intent planning works (uses `model` from extended context)
- Token issuance works (IAP backend)
- Step verification works (CSRG)
- Policy enforcement works (deny/allow based on rules)
- Policy list/update/reset work via Telegram with proper identity context

---

## Test Results (OpenClaw v2026.2.12 + patch-armoriq.sh)

| Test | Result |
|------|--------|
| Full build (`pnpm build`) | Pass |
| Plugin install | Success |
| Plugin runtime (plugins list) | Status: loaded |
| Gateway dev run with Telegram | Working |
| Intent planning + tool verification | Working |
| Policy list / update / reset (Telegram) | Working |
