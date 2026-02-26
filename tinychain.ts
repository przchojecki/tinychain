// Tinychain: a tiny public PoW blockchain (educational).
// - Single-process full node: validates, mines, gossips blocks/txs over HTTP.
// - Consensus-critical hashing/signing uses JSON.stringify on ARRAYS (fixed order).
// - Goal: stay under ~1000 LOC while being reasonably correct and easy to read.
//
// DISCLAIMER: This is a toy. It is NOT production-ready security.
// Missing: robust peer discovery, eclipse/DoS protections, database, pruning, time-sync, etc.

import http from "node:http";
import { createHash } from "node:crypto";
import { URL } from "node:url";
import nacl from "tweetnacl";

type Hex = string;

type Tx = {
  // For normal tx, `from` is the sender public key (32 bytes, hex).
  // For coinbase, `from` is the literal string "COINBASE" and sig is "".
  from: Hex | "COINBASE";
  to: Hex;          // receiver pubkey (32 bytes, hex)
  amount: number;   // integer
  fee: number;      // integer
  nonce: number;    // sender nonce (monotonic, starts at 0)
  sig: Hex;         // Ed25519 signature (64 bytes, hex) or "" for coinbase
};

type Header = {
  prev: Hex;         // previous block hash (32 bytes, hex)
  height: number;    // 0 = genesis
  timestamp: number; // ms since epoch
  difficulty: number;// leading hex zeros required in block hash
  nonce: number;     // PoW nonce
  txRoot: Hex;       // sha256 of concatenated txids (toy "merkle root")
};

type Block = {
  header: Header;
  miner: Hex;        // miner pubkey (32 bytes, hex)
  txs: Tx[];
  hash: Hex;         // sha256(header+miner) and must satisfy difficulty
};

type State = {
  balances: Map<string, number>; // pubkeyHex -> balance
  nonces: Map<string, number>;   // pubkeyHex -> latest nonce
};

const ZERO32: Hex = "0".repeat(64);

// ---- Chain parameters (keep tiny; make them CLI-overridable if you want) ----
const DEFAULT_PORT = 3001;

let INITIAL_DIFFICULTY = 3;         // 3 leading hex zeros ~= 4096 avg tries
const MIN_DIFFICULTY = 1;
const MAX_DIFFICULTY = 8;

const TARGET_BLOCK_MS = 10_000;     // 10s target block time
const RETARGET_INTERVAL = 20;       // adjust every 20 blocks (very rough)

const MAX_TX_PER_BLOCK = 200;
const MAX_MEMPOOL = 5000;

const MAX_BODY_BYTES = 1_000_000;   // 1MB HTTP body limit
const MAX_FUTURE_MS = 2 * 60_000;   // reject blocks > 2min in future

const BLOCK_REWARD = 50;            // fixed issuance per block (toy integer units)

// ---- Helpers: bytes/hex/hash ----
function isHex(s: string): boolean {
  return /^[0-9a-f]+$/i.test(s);
}
function bytesToHex(b: Uint8Array): Hex {
  return Buffer.from(b).toString("hex");
}
function hexToBytes(h: Hex): Uint8Array {
  if (!isHex(h) || h.length % 2 !== 0) throw new Error("bad hex");
  return Buffer.from(h, "hex");
}
function sha256Hex(data: string | Uint8Array): Hex {
  return createHash("sha256").update(data).digest("hex");
}
function sha256Bytes(data: string | Uint8Array): Uint8Array {
  return createHash("sha256").update(data).digest();
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

// ---- Canonical consensus encodings (arrays only) ----
// IMPORTANT: if you change field order, you hard-fork the chain.
function txUnsignedArray(tx: Tx): any[] {
  return [tx.from, tx.to, tx.amount, tx.fee, tx.nonce];
}
function txSignedArray(tx: Tx): any[] {
  return [tx.from, tx.to, tx.amount, tx.fee, tx.nonce, tx.sig];
}
function txId(tx: Tx): Hex {
  return sha256Hex(JSON.stringify(txSignedArray(tx)));
}
function txMessageHash(tx: Tx): Uint8Array {
  return sha256Bytes(JSON.stringify(txUnsignedArray(tx)));
}
function headerArray(h: Header, miner: Hex): any[] {
  return [h.prev, h.height, h.timestamp, h.difficulty, h.nonce, h.txRoot, miner];
}
function blockHash(h: Header, miner: Hex): Hex {
  return sha256Hex(JSON.stringify(headerArray(h, miner)));
}
function checkPow(hash: Hex, difficulty: number): boolean {
  return hash.startsWith("0".repeat(difficulty));
}

function txRoot(txs: Tx[]): Hex {
  // Toy "merkle root": sha256(txid1 || txid2 || ...)
  const joined = txs.map(txId).join("");
  return sha256Hex(joined);
}

function workForDifficulty(d: number): bigint {
  // difficulty is hex-zeros => 4 bits each.
  // Work is not exact, but monotonic, which is enough for chain choice.
  return 1n << BigInt(4 * clamp(d, 0, 60));
}

// ---- Keys ----
function genKeypair(): { pub: Hex; secret: Hex } {
  const kp = nacl.sign.keyPair();
  return { pub: bytesToHex(kp.publicKey), secret: bytesToHex(kp.secretKey) };
}

// ---- Validation ----
function isPubKeyHex(x: any): x is Hex {
  return typeof x === "string" && isHex(x) && x.length === 64;
}
function isSigHex(x: any): x is Hex {
  return typeof x === "string" && isHex(x) && x.length === 128;
}
function isHashHex(x: any): x is Hex {
  return typeof x === "string" && isHex(x) && x.length === 64;
}

function verifyTxSig(tx: Tx): boolean {
  if (tx.from === "COINBASE") return tx.sig === "";
  if (!isPubKeyHex(tx.from) || !isSigHex(tx.sig)) return false;
  const msg = txMessageHash(tx);
  return nacl.sign.detached.verify(msg, hexToBytes(tx.sig), hexToBytes(tx.from));
}

function cloneState(st: State): State {
  return { balances: new Map(st.balances), nonces: new Map(st.nonces) };
}
function getBal(st: State, pub: Hex): number {
  return st.balances.get(pub) ?? 0;
}
function getNonce(st: State, pub: Hex): number {
  return st.nonces.get(pub) ?? 0;
}

function validateNormalTx(tx: Tx, st: State): string | null {
  if (!tx || typeof tx !== "object") return "tx-not-object";
  if (tx.from === "COINBASE") return "coinbase-not-allowed-here";
  if (!isPubKeyHex(tx.from)) return "bad-from";
  if (!isPubKeyHex(tx.to)) return "bad-to";
  if (!Number.isSafeInteger(tx.amount) || tx.amount <= 0) return "bad-amount";
  if (!Number.isSafeInteger(tx.fee) || tx.fee < 0) return "bad-fee";
  if (!Number.isSafeInteger(tx.nonce) || tx.nonce <= 0) return "bad-nonce";
  if (!isSigHex(tx.sig)) return "bad-sig";
  if (!verifyTxSig(tx)) return "sig-fail";

  const expectedNonce = getNonce(st, tx.from) + 1;
  if (tx.nonce !== expectedNonce) return `nonce-mismatch (expected ${expectedNonce})`;

  const cost = tx.amount + tx.fee;
  if (getBal(st, tx.from) < cost) return "insufficient-funds";
  return null;
}

function applyNormalTx(tx: Tx, st: State): void {
  if (tx.from === "COINBASE") throw new Error("not normal tx");
  const fromBal = getBal(st, tx.from);
  st.balances.set(tx.from, fromBal - tx.amount - tx.fee);
  st.balances.set(tx.to, getBal(st, tx.to) + tx.amount);
  st.nonces.set(tx.from, tx.nonce);
}

function validateCoinbaseTx(cb: Tx, expectedTo: Hex, expectedAmount: number, height: number): string | null {
  if (!cb || typeof cb !== "object") return "coinbase-not-object";
  if (cb.from !== "COINBASE") return "coinbase-from";
  if (cb.sig !== "") return "coinbase-sig";
  if (cb.fee !== 0) return "coinbase-fee";
  if (cb.nonce !== height) return "coinbase-nonce";
  if (!isPubKeyHex(cb.to)) return "coinbase-to";
  if (cb.to !== expectedTo) return "coinbase-to-mismatch";
  if (!Number.isSafeInteger(cb.amount) || cb.amount !== expectedAmount) return "coinbase-amount";
  return null;
}

function applyCoinbaseTx(cb: Tx, st: State): void {
  st.balances.set(cb.to, getBal(st, cb.to) + cb.amount);
}

// ---- Difficulty ----
function expectedDifficultyForNext(chain: Block[]): number {
  const nextHeight = chain.length; // because genesis is at index 0
  if (nextHeight === 1) return INITIAL_DIFFICULTY;

  const prev = chain[chain.length - 1];
  let diff = prev.header.difficulty;

  if (nextHeight % RETARGET_INTERVAL !== 0) return diff;

  const start = chain[chain.length - RETARGET_INTERVAL].header.timestamp;
  const end = prev.header.timestamp;
  const actual = Math.max(1, end - start);
  const expected = TARGET_BLOCK_MS * RETARGET_INTERVAL;

  if (actual < expected / 2) diff++;
  else if (actual > expected * 2) diff--;

  return clamp(diff, MIN_DIFFICULTY, MAX_DIFFICULTY);
}

// ---- Chain state ----
function makeGenesis(): Block {
  const miner = ZERO32;
  const header: Header = {
    prev: ZERO32,
    height: 0,
    timestamp: 1_700_000_000_000, // fixed so everyone shares same genesis
    difficulty: INITIAL_DIFFICULTY,
    nonce: 0,
    txRoot: sha256Hex(""),
  };
  const hash = blockHash(header, miner);
  return { header, miner, txs: [], hash };
}

function sameGenesis(a: Block, b: Block): boolean {
  return (
    a.header?.height === 0 &&
    a.header?.prev === b.header.prev &&
    a.header?.timestamp === b.header.timestamp &&
    a.header?.difficulty === b.header.difficulty &&
    a.header?.nonce === b.header.nonce &&
    a.header?.txRoot === b.header.txRoot &&
    a.miner === b.miner &&
    Array.isArray(a.txs) && a.txs.length === 0 &&
    a.hash === b.hash &&
    blockHash(a.header, a.miner) === a.hash
  );
}

let chain: Block[] = [makeGenesis()];
let totalWork: bigint = 0n;
let state: State = { balances: new Map(), nonces: new Map() };

const mempool = new Map<Hex, Tx>();
const seenBlocks = new Set<Hex>();
const seenTxs = new Set<Hex>();

// ---- P2P (tiny): manual peer list + HTTP gossip ----
const peers = new Set<string>();

function normPeer(p: string): string {
  // accept "http://host:port" (no trailing slash)
  try {
    const u = new URL(p);
    return u.origin;
  } catch {
    return p.replace(/\/+$/, "");
  }
}

async function postJson(peer: string, path: string, body: any): Promise<void> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 1500);
  try {
    await fetch(peer + path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ac.signal,
    });
  } catch {
    // ignore
  } finally {
    clearTimeout(t);
  }
}

async function getJson(peer: string, path: string): Promise<any | null> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 1500);
  try {
    const r = await fetch(peer + path, { signal: ac.signal });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function broadcastTx(tx: Tx): void {
  const id = txId(tx);
  for (const p of peers) void postJson(p, "/tx", tx);
  seenTxs.add(id);
}

function broadcastBlock(b: Block): void {
  for (const p of peers) void postJson(p, "/block", b);
  seenBlocks.add(b.hash);
}

// ---- Mempool selection ----
function selectTxsForBlock(st: State): { txs: Tx[]; fees: number } {
  const temp = cloneState(st);
  const txs = Array.from(mempool.values());
  txs.sort((a, b) => (b.fee - a.fee) || txId(a).localeCompare(txId(b)));

  const picked: Tx[] = [];
  let fees = 0;

  for (const tx of txs) {
    if (picked.length >= MAX_TX_PER_BLOCK) break;
    const err = validateNormalTx(tx, temp);
    if (err) continue;
    applyNormalTx(tx, temp);
    fees += tx.fee;
    picked.push(tx);
  }
  return { txs: picked, fees };
}

// ---- Block append / chain replace ----
function tryAppendBlock(b: Block): { ok: boolean; err?: string } {
  const tip = chain[chain.length - 1];
  const now = Date.now();

  if (!b || typeof b !== "object") return { ok: false, err: "block-not-object" };
  if (!isHashHex(b.hash)) return { ok: false, err: "bad-hash-hex" };
  if (!b.header || typeof b.header !== "object") return { ok: false, err: "bad-header" };

  if (b.header.height !== chain.length) return { ok: false, err: "bad-height" };
  if (b.header.prev !== tip.hash) return { ok: false, err: "bad-prev" };
  if (b.header.timestamp < tip.header.timestamp) return { ok: false, err: "time-backwards" };
  if (b.header.timestamp > now + MAX_FUTURE_MS) return { ok: false, err: "time-in-future" };

  const expectedDiff = expectedDifficultyForNext(chain);
  if (b.header.difficulty !== expectedDiff) return { ok: false, err: "bad-difficulty" };

  if (!isPubKeyHex(b.miner)) return { ok: false, err: "bad-miner" };

  if (!Array.isArray(b.txs)) return { ok: false, err: "txs-not-array" };
  if (b.txs.length < 1) return { ok: false, err: "no-coinbase" };
  if (b.txs.length > MAX_TX_PER_BLOCK + 1) return { ok: false, err: "too-many-txs" };

  const wantRoot = txRoot(b.txs);
  if (b.header.txRoot !== wantRoot) return { ok: false, err: "bad-txroot" };

  const wantHash = blockHash(b.header, b.miner);
  if (b.hash !== wantHash) return { ok: false, err: "bad-hash" };
  if (!checkPow(b.hash, b.header.difficulty)) return { ok: false, err: "pow-fail" };

  // Validate txs and apply state transition
  const cb = b.txs[0];
  const temp = cloneState(state);

  let fees = 0;
  for (let i = 1; i < b.txs.length; i++) {
    const tx = b.txs[i];
    const err = validateNormalTx(tx, temp);
    if (err) return { ok: false, err: `tx${i}:${err}` };
    applyNormalTx(tx, temp);
    fees += tx.fee;
  }

  const expectedCbAmount = BLOCK_REWARD + fees;
  const cbErr = validateCoinbaseTx(cb, b.miner, expectedCbAmount, b.header.height);
  if (cbErr) return { ok: false, err: `coinbase:${cbErr}` };
  applyCoinbaseTx(cb, temp);

  // Commit
  chain.push(b);
  state = temp;
  totalWork += workForDifficulty(b.header.difficulty);
  seenBlocks.add(b.hash);

  // Remove included txs from mempool
  for (let i = 1; i < b.txs.length; i++) mempool.delete(txId(b.txs[i]));

  return { ok: true };
}

function validateWholeChain(candidate: Block[]): { ok: boolean; work: bigint; st: State; err?: string } {
  if (!Array.isArray(candidate) || candidate.length < 1) {
    return { ok: false, work: 0n, st: { balances: new Map(), nonces: new Map() }, err: "empty" };
  }

  const localGenesis = makeGenesis();
  const g = candidate[0];
  if (!sameGenesis(g, localGenesis)) {
    return { ok: false, work: 0n, st: { balances: new Map(), nonces: new Map() }, err: "genesis-mismatch" };
  }

  let work = 0n;
  let st: State = { balances: new Map(), nonces: new Map() };
  let localChain: Block[] = [localGenesis];

  for (let i = 1; i < candidate.length; i++) {
    const b = candidate[i];

    if (!b || typeof b !== "object") return { ok: false, work, st, err: `block@${i}` };
    if (!b.header || typeof b.header !== "object") return { ok: false, work, st, err: `header@${i}` };
    if (!isHashHex(b.hash)) return { ok: false, work, st, err: `hashhex@${i}` };

    const tip = localChain[localChain.length - 1];
    const nextHeight = localChain.length;

    if (b.header.height !== nextHeight) return { ok: false, work, st, err: `h@${i}` };
    if (b.header.prev !== tip.hash) return { ok: false, work, st, err: `prev@${i}` };
    if (b.header.timestamp < tip.header.timestamp) return { ok: false, work, st, err: `time@${i}` };

    const expectedDiff = expectedDifficultyForNext(localChain);
    if (b.header.difficulty !== expectedDiff) return { ok: false, work, st, err: `diff@${i}` };

    if (!isPubKeyHex(b.miner)) return { ok: false, work, st, err: `miner@${i}` };

    if (!Array.isArray(b.txs) || b.txs.length < 1) return { ok: false, work, st, err: `txs@${i}` };
    if (b.txs.length > MAX_TX_PER_BLOCK + 1) return { ok: false, work, st, err: `tooManyTx@${i}` };

    if (b.header.txRoot !== txRoot(b.txs)) return { ok: false, work, st, err: `txroot@${i}` };
    if (b.hash !== blockHash(b.header, b.miner)) return { ok: false, work, st, err: `hash@${i}` };
    if (!checkPow(b.hash, b.header.difficulty)) return { ok: false, work, st, err: `pow@${i}` };

    const cb = b.txs[0];
    const temp = cloneState(st);
    let fees = 0;

    for (let j = 1; j < b.txs.length; j++) {
      const tx = b.txs[j];
      const err = validateNormalTx(tx, temp);
      if (err) return { ok: false, work, st, err: `tx@${i}.${j}:${err}` };
      applyNormalTx(tx, temp);
      fees += tx.fee;
    }

    const expectedCbAmount = BLOCK_REWARD + fees;
    const cbErr = validateCoinbaseTx(cb, b.miner, expectedCbAmount, b.header.height);
    if (cbErr) return { ok: false, work, st, err: `cb@${i}:${cbErr}` };
    applyCoinbaseTx(cb, temp);

    st = temp;
    localChain.push(b);
    work += workForDifficulty(b.header.difficulty);
  }

  return { ok: true, work, st };
}

async function maybeSyncFromPeers(): Promise<void> {
  // Dumb-but-tiny sync: if any peer reports higher work, pull full /chain and validate.
  for (const p of peers) {
    const tip = await getJson(p, "/tip");
    if (!tip || typeof tip.work !== "string") continue;
    let peerWork = 0n;
    try { peerWork = BigInt(tip.work); } catch { continue; }

    if (peerWork <= totalWork) continue;

    const theirChain = await getJson(p, "/chain?from=0");
    if (!theirChain || !Array.isArray(theirChain.blocks)) continue;

    const cand = theirChain.blocks as Block[];
    const res = validateWholeChain(cand);
    if (res.ok && res.work > totalWork) {
      chain = cand;
      state = res.st;
      totalWork = res.work;
      mempool.clear();
      console.log(`synced from ${p}: height=${chain.length - 1} work=${totalWork}`);
    }
  }
}

// ---- HTTP server ----
function sendJson(res: http.ServerResponse, code: number, obj: any): void {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        req.destroy();
        reject(new Error("body-too-large"));
        return;
      }
      data += chunk;
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

async function readJson(req: http.IncomingMessage): Promise<any> {
  const s = await readBody(req);
  if (!s) return null;
  return JSON.parse(s);
}

function routeNotFound(res: http.ServerResponse): void {
  sendJson(res, 404, { error: "not-found" });
}

function startServer(port: number): void {
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      const method = req.method ?? "GET";

      if (method === "GET" && url.pathname === "/tip") {
        const tip = chain[chain.length - 1];
        return sendJson(res, 200, {
          hash: tip.hash,
          height: tip.header.height,
          difficulty: expectedDifficultyForNext(chain),
          work: totalWork.toString(),
          peers: Array.from(peers),
        });
      }

      if (method === "GET" && url.pathname === "/chain") {
        const from = Number(url.searchParams.get("from") ?? "0");
        const start = Number.isFinite(from) ? clamp(Math.floor(from), 0, chain.length - 1) : 0;
        return sendJson(res, 200, { blocks: chain.slice(start) });
      }

      if (method === "GET" && url.pathname === "/state") {
        const acct = url.searchParams.get("acct");
        if (!acct || !isPubKeyHex(acct)) return sendJson(res, 400, { error: "bad-acct" });
        return sendJson(res, 200, { acct, balance: getBal(state, acct), nonce: getNonce(state, acct) });
      }

      if (method === "GET" && url.pathname === "/mempool") {
        return sendJson(res, 200, { txs: Array.from(mempool.values()) });
      }

      if (method === "GET" && url.pathname === "/peers") {
        return sendJson(res, 200, { peers: Array.from(peers) });
      }

      if (method === "POST" && url.pathname === "/peers") {
        const body = await readJson(req);
        const p = typeof body?.peer === "string" ? normPeer(body.peer) : null;
        if (!p) return sendJson(res, 400, { error: "bad-peer" });
        peers.add(p);
        return sendJson(res, 200, { ok: true, peers: Array.from(peers) });
      }

      if (method === "POST" && url.pathname === "/tx") {
        const tx = (await readJson(req)) as Tx;
        if (!tx || typeof tx !== "object") return sendJson(res, 400, { error: "bad-json" });

        const id = txId(tx);
        if (seenTxs.has(id)) return sendJson(res, 200, { ok: true, dup: true });

        if (mempool.size >= MAX_MEMPOOL) return sendJson(res, 429, { error: "mempool-full" });

        const err = validateNormalTx(tx, state);
        if (err) return sendJson(res, 400, { error: err });

        mempool.set(id, tx);
        seenTxs.add(id);
        broadcastTx(tx);

        return sendJson(res, 200, { ok: true, txid: id });
      }

      if (method === "POST" && url.pathname === "/block") {
        const b = (await readJson(req)) as Block;
        if (!b || typeof b !== "object") return sendJson(res, 400, { error: "bad-json" });
        if (isHashHex(b.hash) && seenBlocks.has(b.hash)) return sendJson(res, 200, { ok: true, dup: true });

        const r = tryAppendBlock(b);
        if (r.ok) {
          broadcastBlock(b);
          return sendJson(res, 200, { ok: true });
        }

        // If it doesn't connect, do a tiny sync attempt (maybe we missed blocks).
        void maybeSyncFromPeers();
        return sendJson(res, 400, { ok: false, error: r.err });
      }

      if (method === "POST" && url.pathname === "/sync") {
        void maybeSyncFromPeers();
        return sendJson(res, 200, { ok: true });
      }

      return routeNotFound(res);
    } catch (e: any) {
      return sendJson(res, 500, { error: "server-error", detail: String(e?.message ?? e) });
    }
  });

  server.listen(port, () => {
    console.log(`tinychain listening on http://127.0.0.1:${port}`);
  });
}

// ---- Mining ----
let mining = false;

function startMining(minerPub: Hex): void {
  mining = true;
  const BATCH = 20_000;

  const tick = () => {
    if (!mining) return;

    const tip = chain[chain.length - 1];
    const height = tip.header.height + 1;
    const diff = expectedDifficultyForNext(chain);
    const timestamp = Date.now();

    const { txs, fees } = selectTxsForBlock(state);
    const coinbase: Tx = {
      from: "COINBASE",
      to: minerPub,
      amount: BLOCK_REWARD + fees,
      fee: 0,
      nonce: height,
      sig: "",
    };
    const all = [coinbase, ...txs];

    const header: Header = {
      prev: tip.hash,
      height,
      timestamp,
      difficulty: diff,
      nonce: 0,
      txRoot: txRoot(all),
    };

    for (let i = 0; i < BATCH; i++) {
      header.nonce++;
      const h = blockHash(header, minerPub);
      if (checkPow(h, diff)) {
        const b: Block = { header: { ...header }, miner: minerPub, txs: all, hash: h };
        const r = tryAppendBlock(b);
        if (r.ok) {
          console.log(`mined block h=${b.header.height} hash=${b.hash.slice(0, 16)}... txs=${b.txs.length}`);
          broadcastBlock(b);
        }
        break;
      }
    }

    setImmediate(tick);
  };

  tick();
}

// ---- CLI ----
function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (const a of argv) {
    if (!a.startsWith("--")) continue;
    const raw = a.slice(2);
    const eq = raw.indexOf("=");
    if (eq === -1) out[raw] = true;
    else out[raw.slice(0, eq)] = raw.slice(eq + 1);
  }
  return out;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args["keygen"]) {
    const kp = genKeypair();
    console.log(JSON.stringify(kp, null, 2));
    return;
  }

  const port = args["port"] ? Number(args["port"]) : DEFAULT_PORT;
  if (!Number.isFinite(port)) throw new Error("bad --port");

  if (args["difficulty"]) {
    const d = Number(args["difficulty"]);
    if (!Number.isFinite(d) || d < 0 || d > 20) throw new Error("bad --difficulty");
    INITIAL_DIFFICULTY = d;
    // rebuild genesis with new difficulty
    chain = [makeGenesis()];
    totalWork = 0n;
    state = { balances: new Map(), nonces: new Map() };
  }

  if (args["peers"]) {
    const list = String(args["peers"]).split(",").map(s => s.trim()).filter(Boolean);
    for (const p of list) peers.add(normPeer(p));
  }

  startServer(port);

  // initial sync (best-effort)
  void maybeSyncFromPeers();

  if (args["mine"]) {
    const minerPub = String(args["mine"]);
    if (!isPubKeyHex(minerPub)) throw new Error("bad --mine (expected 32-byte pubkey hex)");
    console.log(`mining to ${minerPub}`);
    startMining(minerPub);
  }
}

void main().catch((e) => {
  console.error(e);
  process.exit(1);
});