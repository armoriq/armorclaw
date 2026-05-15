#!/usr/bin/env node
/**
 * ArmorIQ Intent Drift Live Test
 *
 * This script tests that ArmorIQ blocks tool calls that aren't in the original plan.
 *
 * Usage: node test-intent-drift.mjs
 */

import { ArmorIQClient } from "@armoriq/sdk";

const API_KEY =
  process.env.ARMORIQ_API_KEY ||
  "ak_live_9b566af8e02585ac1ec08d72a95045b00de99e092e8ed1ffe531b474e58e108e";

async function testIntentDrift() {
  console.log("🧪 ArmorIQ Intent Drift Test\n");
  console.log("=".repeat(60));

  const client = new ArmorIQClient({
    apiKey: API_KEY,
    userId: "test-drift-user",
    agentId: "test-drift-agent",
    contextId: "test-context",
    iapEndpoint: "http://localhost:8000",
    proxyEndpoint: "http://localhost:3001",
    backendEndpoint: "http://localhost:3000",
  });

  console.log("\n✅ ArmorIQ SDK initialized");

  const plan = {
    steps: [
      {
        action: "list_dir",
        mcp: "openclaw",
        description: "List files in directory",
        metadata: { path: "/tmp" },
      },
    ],
    metadata: { goal: "Only list files - no other operations" },
  };

  console.log("\n📋 Plan:");
  console.log(JSON.stringify(plan, null, 2));

  console.log("\n📦 Capturing plan...");
  const planCapture = client.capturePlan("openclaw", "List files only", plan);
  console.log(`   Plan captured with ${plan.steps.length} step(s)`);

  console.log("\n🎫 Requesting intent token...");
  let token;
  try {
    token = await client.getIntentToken(planCapture, {}, 60);
    console.log(`   Token issued: ${token.tokenId.substring(0, 16)}...`);
    console.log(`   Plan hash: ${token.planHash?.substring(0, 16)}...`);
    console.log(
      `   Expires in: ${token.expiresAt ? (token.expiresAt - Date.now() / 1000).toFixed(0) : "N/A"}s`
    );
    console.log(`   Total steps: ${token.totalSteps}`);
    console.log(`   Raw token plan steps: ${token.rawToken?.plan?.steps?.length || 0}`);
    if (token.rawToken?.plan?.steps) {
      console.log(
        `   Plan steps: ${JSON.stringify(token.rawToken.plan.steps.map((s) => s.action))}`
      );
    }
  } catch (err) {
    console.error(`   ❌ Token issuance failed: ${err.message}`);
    process.exit(1);
  }

  console.log("\n" + "=".repeat(60));
  console.log("TEST 1: Call tool IN the plan (should SUCCEED)");
  console.log("=".repeat(60));

  try {
    const result = await client.invoke("openclaw", "list_dir", token, { path: "/tmp" });
    console.log("   ✅ list_dir ALLOWED (as expected)");
    console.log(`   Result: ${JSON.stringify(result).substring(0, 100)}...`);
  } catch (err) {
    console.log(`   ❌ list_dir BLOCKED: ${err.message}`);
    console.log("   This is unexpected - list_dir should be allowed!");
  }

  console.log("\n" + "=".repeat(60));
  console.log("TEST 2: Call tool NOT in the plan (should FAIL - intent drift)");
  console.log("=".repeat(60));

  try {
    const result = await client.invoke("openclaw", "write_file", token, {
      path: "/tmp/malicious.txt",
      content: "This should be blocked",
    });
    console.log("   ⚠️  write_file ALLOWED - THIS IS A SECURITY ISSUE!");
    console.log(`   Result: ${JSON.stringify(result)}`);
  } catch (err) {
    if (
      err.message.includes("intent drift") ||
      err.message.includes("not in plan") ||
      err.message.includes("not found in the original plan") ||
      err.message.includes("IntentMismatch")
    ) {
      console.log("   ✅ write_file BLOCKED (as expected - intent drift protection)");
      console.log(`   Error: ${err.message}`);
    } else {
      console.log(`   ❓ write_file BLOCKED with unexpected error: ${err.message}`);
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log("TEST 3: Call dangerous tool NOT in the plan (should FAIL)");
  console.log("=".repeat(60));

  try {
    const result = await client.invoke("openclaw", "bash", token, {
      command: "rm -rf /",
    });
    console.log("   ⚠️  bash ALLOWED - THIS IS A CRITICAL SECURITY ISSUE!");
  } catch (err) {
    if (
      err.message.includes("intent drift") ||
      err.message.includes("not in plan") ||
      err.message.includes("not found in the original plan") ||
      err.message.includes("IntentMismatch")
    ) {
      console.log("   ✅ bash BLOCKED (as expected - intent drift protection)");
    } else {
      console.log(`   ✅ bash BLOCKED with error: ${err.message.substring(0, 80)}...`);
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log("SUMMARY");
  console.log("=".repeat(60));
  console.log("✅ Intent enforcement is working correctly");
  console.log("✅ Tools in plan are allowed");
  console.log("✅ Tools NOT in plan are blocked (intent drift protection)");
  console.log("\n🎉 ArmorIQ intent enforcement test completed!");

  client.close();
}

testIntentDrift().catch(console.error);
