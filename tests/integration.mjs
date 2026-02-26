import { spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY = path.join(ROOT, "tiny002.ts");
const TMP = path.join(ROOT, ".tmp-itest");
const BIN = process.execPath;

const ADMIN_TOKEN = "itest-admin";
const PEER_TOKEN = "itest-peer";
const SNAPSHOT_KEY = "itest-snapshot-key";
const MINER = "1".repeat(64);

const BASE_ENV = {
  TINYCHAIN_ADMIN_TOKEN: ADMIN_TOKEN,
  TINYCHAIN_PEER_TOKEN: PEER_TOKEN,
  TINYCHAIN_SNAPSHOT_KEY: SNAPSHOT_KEY,
  TINYCHAIN_UNSAFE_DEV: "I_UNDERSTAND",
  TINYCHAIN_ALLOW_PRIVATE_PEERS: "1",
};

function assert(ok, msg) {
  if (!ok) throw new Error(msg);
}
function origin(port) {
  return `http://127.0.0.1:${port}`;
}
function peerHeaders(token = PEER_TOKEN) {
  return { "x-peer-token": token };
}
function adminHeaders() {
  return { "x-admin-token": ADMIN_TOKEN };
}
function jsonHeaders(extra = {}) {
  return { "content-type": "application/json", ...extra };
}
function extractErr(e) {
  return String(e?.message ?? e);
}
async function fetchJson(url, init = {}) {
  const r = await fetch(url, init);
  const text = await r.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch {}
  return { status: r.status, body, text };
}
async function waitUntil(label, timeoutMs, fn) {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) {
      last = extractErr(e);
    }
    await sleep(200);
  }
  throw new Error(`timeout waiting for ${label}${last ? `: ${last}` : ""}`);
}
function startNode(name, port, extraArgs = [], extraEnv = {}, clean = true) {
  const dataDir = path.join(TMP, name);
  if (clean) fs.rmSync(dataDir, { recursive: true, force: true });
  fs.mkdirSync(dataDir, { recursive: true });
  const args = [ENTRY, `--port=${port}`, ...extraArgs];
  const env = { ...process.env, ...BASE_ENV, ...extraEnv, TINYCHAIN_DATA_DIR: dataDir };
  const proc = spawn(BIN, args, { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
  let logs = "";
  proc.stdout.on("data", (d) => { logs += d.toString("utf8"); });
  proc.stderr.on("data", (d) => { logs += d.toString("utf8"); });
  return { name, port, dataDir, proc, logs: () => logs };
}
async function stopNode(node) {
  if (!node || node.proc.exitCode !== null) return;
  node.proc.kill("SIGTERM");
  await Promise.race([once(node.proc, "exit"), sleep(2_000)]);
  if (node.proc.exitCode === null) {
    node.proc.kill("SIGKILL");
    await Promise.race([once(node.proc, "exit"), sleep(2_000)]);
  }
}

async function main() {
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(TMP, { recursive: true });
  const nodes = [];
  let b = null;
  try {
    let a = startNode("a", 4101, [`--mine=${MINER}`]);
    b = startNode("b", 4102);
    nodes.push(a, b);

    await waitUntil("node A tip", 20_000, async () => {
      const t = await fetchJson(`${origin(a.port)}/tip`, { headers: peerHeaders() });
      return t.status === 200;
    });
    await waitUntil("node B tip", 20_000, async () => {
      const t = await fetchJson(`${origin(b.port)}/tip`, { headers: peerHeaders() });
      return t.status === 200;
    });

    const unauthTip = await fetchJson(`${origin(a.port)}/tip`);
    assert(unauthTip.status === 403, `expected 403 on unauth /tip, got ${unauthTip.status}`);

    await waitUntil("node A mine >=1 block", 120_000, async () => {
      const t = await fetchJson(`${origin(a.port)}/tip`, { headers: peerHeaders() });
      return t.status === 200 && Number(t.body?.height) >= 1;
    });
    const minedTip = await fetchJson(`${origin(a.port)}/tip`, { headers: peerHeaders() });
    assert(minedTip.status === 200, `tip after mining failed: ${minedTip.status}`);
    const targetHeight = Number(minedTip.body?.height);
    await stopNode(a);
    a = startNode("a", 4101, [], {}, false);
    nodes.push(a);
    await waitUntil("node A restart fixed tip", 20_000, async () => {
      const t = await fetchJson(`${origin(a.port)}/tip`, { headers: peerHeaders() });
      return t.status === 200 && Number(t.body?.height) >= targetHeight;
    });

    const addPeer = await fetchJson(`${origin(b.port)}/peers`, {
      method: "POST",
      headers: jsonHeaders(adminHeaders()),
      body: JSON.stringify({ peer: origin(a.port) }),
    });
    assert(addPeer.status === 200, `add-peer failed: ${addPeer.status} ${addPeer.text}`);
    const peersNow = await fetchJson(`${origin(b.port)}/peers`, { headers: peerHeaders() });
    assert(peersNow.status === 200 && Array.isArray(peersNow.body?.peers) && peersNow.body.peers.includes(origin(a.port)), `peer not present after add: ${peersNow.text}`);

    const targetTip = await fetchJson(`${origin(a.port)}/tip`, { headers: peerHeaders() });
    assert(targetTip.status === 200, `tip after mining failed: ${targetTip.status}`);
    assert(Number(targetTip.body?.height) >= targetHeight, `unexpected target tip after restart: ${targetTip.text}`);

    let synced = false;
    for (let i = 0; i < 12; i++) {
      const syncNow = await fetchJson(`${origin(b.port)}/sync`, {
        method: "POST",
        headers: jsonHeaders(adminHeaders()),
        body: "{}",
      });
      assert(syncNow.status === 200 || syncNow.status === 429, `sync-now failed: ${syncNow.status} ${syncNow.text}`);
      try {
        await waitUntil("node B sync height", 5_500, async () => {
          const tb = await fetchJson(`${origin(b.port)}/tip`, { headers: peerHeaders() });
          return tb.status === 200 && Number(tb.body?.height) >= targetHeight;
        });
        synced = true;
        break;
      } catch {}
      await sleep(500);
    }
    assert(synced, "node B did not reach synced target height");

    const c = startNode("c", 4103, [], { TINYCHAIN_PEER_TOKEN: "wrong-peer-token" });
    nodes.push(c);
    await waitUntil("node C tip", 20_000, async () => {
      const t = await fetchJson(`${origin(c.port)}/tip`, { headers: peerHeaders("wrong-peer-token") });
      return t.status === 200;
    });

    const addBad = await fetchJson(`${origin(b.port)}/peers`, {
      method: "POST",
      headers: jsonHeaders(adminHeaders()),
      body: JSON.stringify({ peer: origin(c.port) }),
    });
    assert(addBad.status === 400 && addBad.body?.error === "peer-incompatible", `expected peer-incompatible, got ${addBad.status} ${addBad.text}`);

    await stopNode(b);
    const chainPath = path.join(b.dataDir, "chain.json");
    const snap = JSON.parse(fs.readFileSync(chainPath, "utf8"));
    assert(snap?.meta?.mac, "missing snapshot MAC before tamper test");
    snap.meta.mac = "0".repeat(64);
    fs.writeFileSync(chainPath, JSON.stringify(snap), "utf8");

    const b2 = startNode("b", 4102, [], {}, false);
    nodes.push(b2);
    b = b2;
    await waitUntil("node B restart tip", 20_000, async () => {
      const t = await fetchJson(`${origin(b.port)}/tip`, { headers: peerHeaders() });
      return t.status === 200;
    });
    const tipAfterTamper = await fetchJson(`${origin(b.port)}/tip`, { headers: peerHeaders() });
    assert(b.logs().includes("snapshot-load-failed"), "missing snapshot-load-failed log after tamper");
    assert(Number(tipAfterTamper.body?.height) >= 1, `expected recovery sync after tampered snapshot, got ${tipAfterTamper.text}`);

    console.log(JSON.stringify({ ok: true, tests: ["peer-auth-required", "sync-path", "peer-token-mismatch", "snapshot-mac-tamper-recovery"] }, null, 2));
  } catch (e) {
    for (const n of nodes) {
      console.error(`\n--- logs ${n.name}@${n.port} ---\n${n.logs()}`);
    }
    throw e;
  } finally {
    for (let i = nodes.length - 1; i >= 0; i--) {
      try { await stopNode(nodes[i]); } catch {}
    }
    fs.rmSync(TMP, { recursive: true, force: true });
  }
}

void main().catch((e) => {
  console.error(`integration-test-failed: ${extractErr(e)}`);
  process.exit(1);
});
