# ArmorClaw v2026.3.0 Release Notes

## No More Patching

ArmorClaw no longer requires runtime patches to OpenClaw source files. Starting with this release, the plugin works as a standard drop-in for OpenClaw 2026.3.x:

```bash
openclaw plugins install @armoriq/armorclaw
```

Previous versions required a `patch-armoriq.sh` script that modified 5 OpenClaw source files to expose model, tool, and sender identity data to the plugin. OpenClaw 2026.3.x now provides this data natively through new hooks, making the patch unnecessary.

## What Changed

### New Hook Architecture

The plugin migrated from the deprecated `before_agent_start` hook to three native OpenClaw 2026.3.x hooks:

- **`inbound_claim`** — Captures sender identity (`senderId`, `senderName`, `senderUsername`) from inbound messages for per-user policy enforcement and audit logging.
- **`llm_input`** — Generates the intent plan when the LLM input is prepared. Parses available tools directly from the system prompt and resolves API credentials via `api.runtime.modelAuth`. Planning runs concurrently with the agent's LLM call and completes before the first tool call.
- **`before_prompt_build`** — Injects policy update instructions into the system prompt using `prependSystemContext` for improved prompt caching.

### Version Alignment

ArmorClaw now follows the OpenClaw versioning scheme. This makes it clear which ArmorClaw version is compatible with which OpenClaw version:

| ArmorClaw | OpenClaw | Install |
|---|---|---|
| 2026.3.x | 2026.3.x | `npm install @armoriq/armorclaw` |
| 2026.2.x | 2026.2.x | `npm install @armoriq/armorclaw@openclaw-2026.2` |

## Breaking Changes

- **Requires OpenClaw >= 2026.3.0** — The new hooks (`llm_input`, `before_prompt_build`, `inbound_claim`) and `api.runtime.modelAuth` are not available in older versions. Users on OpenClaw 2026.2.x should install `@armoriq/armorclaw@openclaw-2026.2`.
- **`senderE164` identity source is limited** — The upstream `inbound_claim` hook does not provide `senderE164`. If `userIdSource` is set to `"senderE164"`, the plugin falls back to `senderId`. Deployments that relied on phone number-based identity should switch `userIdSource` to `"senderId"`.
- **Context-token path removed** — The `intentTokenRaw`, `csrgPath`, `csrgProofRaw`, and `csrgValueDigest` fields are no longer read from hook context. All intent verification now flows through the cached plan from `llm_input`. Deployments that injected tokens via custom OpenClaw middleware should use the standard plan cache flow instead.

## Upgrading

1. Update OpenClaw to 2026.3.x
2. Remove any ArmorClaw patches from your OpenClaw installation
3. Install the new version: `openclaw plugins install @armoriq/armorclaw`
4. If using `userIdSource: "senderE164"`, switch to `"senderId"`
5. Restart your gateway: `openclaw gateway restart`

No configuration changes are required for standard deployments.
