#!/usr/bin/env node

import { writeFile } from "node:fs/promises";

const baseURL = String(process.env.KOSCHEI_BASE_URL || "https://tradepigloball.co").replace(/\/$/, "");
const ownerSecret = String(process.env.KOSCHEI_OWNER_SECRET || "").trim();
const wallet = String(process.argv[2] || "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe").trim();
const outputPath = String(process.argv[3] || "").trim();
const allowedStatuses = new Set(["pass", "fail", "not_investigated"]);

if (!ownerSecret) throw new Error("KOSCHEI_OWNER_SECRET is required");
if (!wallet) throw new Error("wallet is required");

async function runAcceptance() {
  const response = await fetch(`${baseURL}/api/owner/defense/actor-acceptance`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-koschei-secret": ownerSecret
    },
    body: JSON.stringify({ target: wallet, network: "solana-mainnet", live_evidence: true })
  });
  const payload = await response.json().catch(() => ({ error: "invalid_json_response" }));
  if (!response.ok) {
    throw new Error(`actor acceptance failed with HTTP ${response.status}: ${JSON.stringify(payload)}`);
  }
  const acceptance = payload?.acceptance;
  if (!acceptance || acceptance.contract_version !== "koschei-actor-acceptance-v1") {
    throw new Error("actor acceptance schema is missing or unexpected");
  }
  if (!Array.isArray(acceptance.items) || acceptance.items.length !== 10) {
    throw new Error(`expected 10 acceptance items, got ${acceptance?.items?.length ?? 0}`);
  }
  const ids = acceptance.items.map(item => String(item?.id || ""));
  if (new Set(ids).size !== 10 || ids.some((id, index) => id !== `AC-${String(index + 1).padStart(2, "0")}`)) {
    throw new Error(`acceptance item IDs are incomplete or out of order: ${ids.join(",")}`);
  }
  for (const item of acceptance.items) {
    if (!allowedStatuses.has(String(item?.status || ""))) {
      throw new Error(`invalid acceptance status for ${item?.id}: ${item?.status}`);
    }
    if (typeof item?.summary !== "string" || item.summary.trim() === "") {
      throw new Error(`missing summary for ${item?.id}`);
    }
    if (!Array.isArray(item?.evidence) || !Array.isArray(item?.limitations)) {
      throw new Error(`missing evidence/limitations arrays for ${item?.id}`);
    }
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(String(acceptance.acceptance_hash || ""))) {
    throw new Error("acceptance_hash is missing or malformed");
  }
  return payload;
}

const first = await runAcceptance();
const second = await runAcceptance();
const firstHash = String(first.acceptance.acceptance_hash);
const secondHash = String(second.acceptance.acceptance_hash);
if (firstHash !== secondHash) {
  throw new Error(`deterministic acceptance mismatch: ${firstHash} != ${secondHash}`);
}

const result = {
  version: "koschei-actor-acceptance-run-v1",
  base_url: baseURL,
  wallet,
  acceptance_hash: firstHash,
  status: first.acceptance.status,
  pass_count: first.acceptance.pass_count,
  fail_count: first.acceptance.fail_count,
  not_investigated_count: first.acceptance.not_investigated_count,
  items: first.acceptance.items,
  verdict: first.acceptance.verdict
};

const encoded = `${JSON.stringify(result, null, 2)}\n`;
if (outputPath) await writeFile(outputPath, encoded, "utf8");
process.stdout.write(encoded);
