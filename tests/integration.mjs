import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import nacl from "tweetnacl";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY = path.join(ROOT, "tiny002.ts");
const TMP = path.join(ROOT, ".tmp-itest");
const BIN = process.execPath;

const ADMIN_TOKEN = "itest-admin";
const PEER_TOKEN = "itest-peer";
const SNAPSHOT_KEY = "itest-snapshot-key";
const CHAIN_ID = "tinychain-main-001";
const PROTOCOL_VERSION = 2;
function bytesToHex(b) {
  return Buffer.from(b).toString("hex");
}
function sha256Hex(data) {
  return createHash("sha256").update(data).digest("hex");
}
function sha256Bytes(data) {
  return createHash("sha256").update(data).digest();
}
function keypair(seedByte) {
  const seed = new Uint8Array(32).fill(seedByte);
  const kp = nacl.sign.keyPair.fromSeed(seed);
  return { pub: bytesToHex(kp.publicKey), secret: bytesToHex(kp.secretKey) };
}
const MINER_KP = keypair(1);
const RECEIVER_KP = keypair(2);
const PEER_SIGNER = keypair(3);
const MINER = MINER_KP.pub;

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
function signTx(secret, to, amount, fee, nonce) {
  const from = Buffer.from(secret, "hex").subarray(32).toString("hex");
  const tx = { from, to, amount, fee, nonce, sig: "" };
  const msg = sha256Bytes(JSON.stringify([CHAIN_ID, tx.from, tx.to, tx.amount, tx.fee, tx.nonce]));
  tx.sig = bytesToHex(nacl.sign.detached(msg, Buffer.from(secret, "hex")));
  return tx;
}
function signedPeerHeaders(pathname, method = "GET", token = PEER_TOKEN) {
  const ts = String(Date.now());
  const nonce = randomBytes(12).toString("hex");
  const sigPayload = JSON.stringify([CHAIN_ID, PROTOCOL_VERSION, method, pathname, ts, nonce, PEER_SIGNER.pub]);
  const sig = bytesToHex(nacl.sign.detached(sha256Bytes(sigPayload), Buffer.from(PEER_SIGNER.secret, "hex")));
  return {
    "x-peer-token": token,
    "x-peer-node": sha256Hex(PEER_SIGNER.pub),
    "x-peer-pub": PEER_SIGNER.pub,
    "x-peer-ts": ts,
    "x-peer-nonce": nonce,
    "x-peer-sig": sig,
  };
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
    const chainUnsigned = await fetchJson(`${origin(a.port)}/chain?from=0&maxBytes=128000`, { headers: peerHeaders() });
    assert(chainUnsigned.status === 403, `expected 403 on unsigned /chain, got ${chainUnsigned.status}`);
    const chainSigned = await fetchJson(`${origin(a.port)}/chain?from=0&maxBytes=128000`, { headers: signedPeerHeaders("/chain", "GET") });
    assert(chainSigned.status === 200, `expected 200 on signed /chain, got ${chainSigned.status}`);
    const replayHeaders = signedPeerHeaders("/chain", "GET");
    const chainReplayA = await fetchJson(`${origin(a.port)}/chain?from=0&maxBytes=128000`, { headers: replayHeaders });
    const chainReplayB = await fetchJson(`${origin(a.port)}/chain?from=0&maxBytes=128000`, { headers: replayHeaders });
    assert(chainReplayA.status === 200 && chainReplayB.status === 403, `expected replay reject for signed /chain, got ${chainReplayA.status}/${chainReplayB.status}`);
    const openTx = await fetchJson(`${origin(a.port)}/tx`, {
      method: "POST",
      headers: jsonHeaders(),
      body: "{}",
    });
    assert(openTx.status !== 403, `expected permissionless /tx path, got ${openTx.status}`);
    const nodeDoc = JSON.parse(fs.readFileSync(path.join(a.dataDir, "node.json"), "utf8"));
    assert(!nodeDoc?.nodeSecret && typeof nodeDoc?.nodeSecretEnc?.ciphertext === "string", "expected encrypted node secret at rest");

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
    const tx1 = signTx(MINER_KP.secret, RECEIVER_KP.pub, "1", "1", "1");
    const tx1Post = await fetchJson(`${origin(a.port)}/tx`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify(tx1),
    });
    assert(tx1Post.status === 200 && tx1Post.body?.replaced === false, `expected first tx accepted, got ${tx1Post.status} ${tx1Post.text}`);
    const txLowBump = signTx(MINER_KP.secret, RECEIVER_KP.pub, "2", "1", "1");
    const txLowPost = await fetchJson(`${origin(a.port)}/tx`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify(txLowBump),
    });
    assert(txLowPost.status === 409 && txLowPost.body?.error === "rbf-fee-too-low", `expected low bump rejection, got ${txLowPost.status} ${txLowPost.text}`);
    const tx2 = signTx(MINER_KP.secret, RECEIVER_KP.pub, "1", "2", "1");
    const tx2Post = await fetchJson(`${origin(a.port)}/tx`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify(tx2),
    });
    assert(tx2Post.status === 200 && tx2Post.body?.replaced === true, `expected RBF replacement, got ${tx2Post.status} ${tx2Post.text}`);
    const mempoolAfterRbf = await fetchJson(`${origin(a.port)}/mempool`, { headers: peerHeaders() });
    assert(mempoolAfterRbf.status === 200 && Array.isArray(mempoolAfterRbf.body?.txs) && mempoolAfterRbf.body.txs.length === 1 && mempoolAfterRbf.body.txs[0]?.fee === "2", `expected mempool replacement outcome, got ${mempoolAfterRbf.text}`);

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
    const d = startNode("d", 4104, [], { TINYCHAIN_UNSAFE_DEV: "", TINYCHAIN_ALLOW_PRIVATE_PEERS: "0" });
    nodes.push(d);
    await waitUntil("node D tip", 20_000, async () => {
      const t = await fetchJson(`${origin(d.port)}/tip`, { headers: peerHeaders() });
      return t.status === 200;
    });
    const addHttpPeer = await fetchJson(`${origin(d.port)}/peers`, {
      method: "POST",
      headers: jsonHeaders(adminHeaders()),
      body: JSON.stringify({ peer: "http://example.com" }),
    });
    assert(addHttpPeer.status === 400 && addHttpPeer.body?.error === "bad-peer", `expected http peer rejection, got ${addHttpPeer.status} ${addHttpPeer.text}`);

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

    console.log(JSON.stringify({ ok: true, tests: ["peer-auth-required", "signed-chain-auth", "signed-chain-replay-reject", "open-relay-route", "node-secret-at-rest-encrypted", "rbf-fee-bump", "tls-only-peer-policy", "sync-path", "peer-token-mismatch", "snapshot-mac-tamper-recovery"] }, null, 2));
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
