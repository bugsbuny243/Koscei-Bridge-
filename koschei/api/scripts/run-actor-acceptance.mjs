#!/usr/bin/env node

import { writeFile } from "node:fs/promises";

const baseURL = String(process.env.KOSCHEI_BASE_URL || "https://tradepigloball.co").replace(/\/$/, "");
const ownerSecret = String(process.env.KOSCHEI_OWNER_SECRET || "").trim();
const wallet = String(process.argv[2] || "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe").trim();
const outputPath = String(process.argv[3] || "").trim();
const allowedStatuses = new Set(["pass", "fail", "not_investigated"]);

function compactDiffValue(value) {
  if (value === undefined) return "<undefined>";
  if (typeof value === "string") return value.length > 500 ? `${value.slice(0, 500)}…` : value;
  if (value === null || typeof value === "number" || typeof value === "boolean") return value;
  let encoded;
  try {
    encoded = JSON.stringify(value);
  } catch {
    return String(value);
  }
  if (typeof encoded !== "string") return String(value);
  return encoded.length > 1000 ? `${encoded.slice(0, 1000)}…` : value;
}

function collectDiffs(first, second, path = "$", out = []) {
  if (out.length >= 250) return out;
  if (Object.is(first, second)) return out;

  const firstArray = Array.isArray(first);
  const secondArray = Array.isArray(second);
  if (firstArray || secondArray) {
    if (!firstArray || !secondArray) {
      out.push({ path, first: compactDiffValue(first), second: compactDiffValue(second) });
      return out;
    }
    if (first.length !== second.length) {
      out.push({ path: `${path}.length`, first: first.length, second: second.length });
    }
    const length = Math.max(first.length, second.length);
    for (let index = 0; index < length && out.length < 250; index += 1) {
      collectDiffs(first[index], second[index], `${path}[${index}]`, out);
    }
    return out;
  }

  const firstObject = first !== null && typeof first === "object";
  const secondObject = second !== null && typeof second === "object";
  if (firstObject || secondObject) {
    if (!firstObject || !secondObject) {
      out.push({ path, first: compactDiffValue(first), second: compactDiffValue(second) });
      return out;
    }
    const keys = [...new Set([...Object.keys(first), ...Object.keys(second)])].sort();
    for (const key of keys) {
      if (out.length >= 250) break;
      collectDiffs(first[key], second[key], `${path}.${key}`, out);
    }
    return out;
  }

  out.push({ path, first: compactDiffValue(first), second: compactDiffValue(second) });
  return out;
}

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

async function main() {
  if (!ownerSecret) throw new Error("KOSCHEI_OWNER_SECRET is required");
  if (!wallet) throw new Error("wallet is required");

  // Two live passes are intentional: persistent chain evidence must be idempotent,
  // so an unchanged evidence set produces the same acceptance hash.
  const first = await runAcceptance();
  const second = await runAcceptance();
  const firstHash = String(first.acceptance.acceptance_hash);
  const secondHash = String(second.acceptance.acceptance_hash);
  if (firstHash !== secondHash) {
    const diagnostic = {
      version: "koschei-actor-acceptance-diff-v1",
      wallet,
      first_hash: firstHash,
      second_hash: secondHash,
      differences: collectDiffs(first.acceptance, second.acceptance)
    };
    const encodedDiagnostic = `${JSON.stringify(diagnostic, null, 2)}\n`;
    await writeFile("actor-acceptance-diff.json", encodedDiagnostic, "utf8");
    process.stderr.write(`[actor-acceptance-diff]\n${encodedDiagnostic}`);
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
}

main().catch(error => {
  const message = String(error?.message || error || "actor acceptance failed").trim();
  process.stderr.write(`[actor-acceptance-error] ${message}\n`);
  process.exitCode = 1;
});
