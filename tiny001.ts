import http from "node:http";
import { createHash } from "node:crypto";
import net from "node:net";
import { URL } from "node:url";
import fs from "node:fs";
import path from "node:path";
import nacl from "tweetnacl";
type Hex = string;
type Tx = {
  from: Hex | "COINBASE";
  to: Hex;          // receiver pubkey (32 bytes, hex)
  amount: string;   // canonical unsigned decimal integer string
  fee: string;      // canonical unsigned decimal integer string
  nonce: string;    // canonical unsigned decimal integer string
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
  balances: Map<string, bigint>; // pubkeyHex -> balance
  nonces: Map<string, bigint>;   // pubkeyHex -> latest nonce
};
const ZERO32: Hex = "0".repeat(64);
const DEFAULT_PORT = 3001;
const INITIAL_DIFFICULTY = 3;       // frozen mainnet profile
const MIN_DIFFICULTY = 1;
const MAX_DIFFICULTY = 12;
const TARGET_BLOCK_MS = 10_000;
const RETARGET_INTERVAL = 20;
const MTP_WINDOW = 11;
const GENESIS_TIMESTAMP = 1_700_000_000_000;
const MAX_TX_PER_BLOCK = 200;
const MAX_MEMPOOL = 5000;
const MAX_BODY_BYTES = 1_000_000;   // 1MB HTTP body limit
const MAX_FUTURE_MS = 2 * 60_000;   // reject blocks > 2min in future
const MAX_SYNC_RESPONSE_BYTES = 2_000_000; // cap peer response bytes during sync
const CHAIN_CHUNK_BLOCKS = 256;     // /chain page size for sync
const MAX_SYNC_AHEAD = 2048;
const MAX_SYNC_CHUNKS_PER_ATTEMPT = 24;
const SYNC_COOLDOWN_MS = 5000;
const RATE_WINDOW_MS = 10_000;
const RATE_LIMIT: Record<string, number> = { "/tx": 120, "/block": 40, "/peers": 8, "/sync": 4 };
const BLOCK_REWARD = 50n;           // fixed issuance per block (toy integer units)
const MAX_AMOUNT = (1n << 63n) - 1n; // hard cap for amount/fee/nonce/balance values
const CHAIN_ID = "tinychain-main-001";
const SEEN_TX_CAP = 50_000;
const SEEN_BLOCK_CAP = 50_000;
const MAX_PEERS = 128;
const ADMIN_TOKEN = process.env.TINYCHAIN_ADMIN_TOKEN || "";
const DATA_DIR = process.env.TINYCHAIN_DATA_DIR || ".tinychain";
const CHAIN_FILE = path.join(DATA_DIR, "chain.json");
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
function isCanonicalUDec(s: any): s is string {
  return typeof s === "string" && /^(0|[1-9][0-9]*)$/.test(s);
}
function parseUDec(s: any): bigint | null {
  if (!isCanonicalUDec(s)) return null;
  try {
    const n = BigInt(s);
    if (n < 0n || n > MAX_AMOUNT) return null;
    return n;
  } catch {
    return null;
  }
}
function addChecked(a: bigint, b: bigint): bigint | null {
  const c = a + b;
  if (c < 0n || c > MAX_AMOUNT) return null;
  return c;
}
function subChecked(a: bigint, b: bigint): bigint | null {
  if (a < 0n || b < 0n || b > a) return null;
  return a - b;
}
function txUnsignedArray(tx: Tx): any[] {
  return [CHAIN_ID, tx.from, tx.to, tx.amount, tx.fee, tx.nonce];
}
function txSignedArray(tx: Tx): any[] {
  return [CHAIN_ID, tx.from, tx.to, tx.amount, tx.fee, tx.nonce, tx.sig];
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
function headerShapeOk(h: any): boolean {
  return Number.isSafeInteger(h?.height) && h.height >= 0 &&
    Number.isSafeInteger(h?.timestamp) && h.timestamp > 0 &&
    Number.isSafeInteger(h?.difficulty) && h.difficulty >= MIN_DIFFICULTY && h.difficulty <= MAX_DIFFICULTY &&
    Number.isSafeInteger(h?.nonce) && h.nonce >= 0;
}
function txRoot(txs: Tx[]): Hex {
  const joined = txs.map(txId).join("");
  return sha256Hex(joined);
}
function workForDifficulty(d: number): bigint {
  return 1n << BigInt(4 * clamp(d, 0, 60));
}
function rememberSeen(set: Set<Hex>, queue: Hex[], id: Hex, cap: number): void {
  if (set.has(id)) return;
  set.add(id);
  queue.push(id);
  if (queue.length > cap) {
    const evicted = queue.shift();
    if (evicted) set.delete(evicted);
  }
}
function genKeypair(): { pub: Hex; secret: Hex } {
  const kp = nacl.sign.keyPair();
  return { pub: bytesToHex(kp.publicKey), secret: bytesToHex(kp.secretKey) };
}
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
function pubFromSecretHex(secret: Hex): Hex {
  if (typeof secret !== "string" || !isHex(secret) || secret.length !== 128) throw new Error("bad-secret");
  const sk = hexToBytes(secret);
  if (sk.length !== 64) throw new Error("bad-secret");
  return bytesToHex(sk.slice(32));
}
function signTx(secret: Hex, to: Hex, amount: string, fee: string, nonce: string): Tx {
  const from = pubFromSecretHex(secret);
  if (!isPubKeyHex(to)) throw new Error("bad-to");
  const pAmount = parseUDec(amount);
  const pFee = parseUDec(fee);
  const pNonce = parseUDec(nonce);
  if (pAmount === null || pAmount <= 0n || pFee === null || pNonce === null || pNonce <= 0n) throw new Error("bad-tx-fields");
  const tx: Tx = { from, to, amount, fee, nonce, sig: "" };
  tx.sig = bytesToHex(nacl.sign.detached(txMessageHash(tx), hexToBytes(secret)));
  return tx;
}
function cloneState(st: State): State {
  return { balances: new Map(st.balances), nonces: new Map(st.nonces) };
}
function getBal(st: State, pub: Hex): bigint {
  return st.balances.get(pub) ?? 0n;
}
function getNonce(st: State, pub: Hex): bigint {
  return st.nonces.get(pub) ?? 0n;
}
function txParsed(tx: Tx): { amount: bigint; fee: bigint; nonce: bigint } | null {
  const amount = parseUDec(tx.amount);
  const fee = parseUDec(tx.fee);
  const nonce = parseUDec(tx.nonce);
  if (amount === null || fee === null || nonce === null) return null;
  return { amount, fee, nonce };
}
function txCost(tx: Tx): bigint | null {
  const p = txParsed(tx);
  if (!p) return null;
  return addChecked(p.amount, p.fee);
}
function validateNormalTx(tx: Tx, st: State): string | null {
  if (!tx || typeof tx !== "object") return "tx-not-object";
  if (tx.from === "COINBASE") return "coinbase-not-allowed-here";
  if (!isPubKeyHex(tx.from)) return "bad-from";
  if (!isPubKeyHex(tx.to)) return "bad-to";
  const p = txParsed(tx);
  if (!p || p.amount <= 0n || p.fee < 0n || p.nonce <= 0n) return "bad-num";
  if (!isSigHex(tx.sig)) return "bad-sig";
  if (!verifyTxSig(tx)) return "sig-fail";
  const stNonce = getNonce(st, tx.from);
  if (stNonce < 0n || stNonce > MAX_AMOUNT) return "state-nonce-corrupt";
  const expectedNonce = stNonce + 1n;
  if (expectedNonce > MAX_AMOUNT) return "nonce-overflow";
  if (p.nonce !== expectedNonce) return `nonce-mismatch (expected ${expectedNonce.toString()})`;
  const cost = txCost(tx);
  if (cost === null) return "cost-overflow";
  const bal = getBal(st, tx.from);
  if (bal < 0n || bal > MAX_AMOUNT) return "state-balance-corrupt";
  if (bal < cost) return "insufficient-funds";
  return null;
}
function applyNormalTx(tx: Tx, st: State): string | null {
  if (tx.from === "COINBASE") return "coinbase-in-normal";
  const p = txParsed(tx);
  if (!p) return "bad-num";
  const cost = addChecked(p.amount, p.fee);
  if (cost === null) return "cost-overflow";
  const fromBal = getBal(st, tx.from);
  if (fromBal < 0n || fromBal > MAX_AMOUNT) return "state-balance-corrupt";
  const newFromBal = subChecked(fromBal, cost);
  if (newFromBal === null) return "from-underflow";
  const toBal = getBal(st, tx.to);
  if (toBal < 0n || toBal > MAX_AMOUNT) return "state-balance-corrupt";
  const newToBal = addChecked(toBal, p.amount);
  if (newToBal === null) return "to-overflow";
  if (p.nonce < 0n || p.nonce > MAX_AMOUNT) return "bad-nonce";
  st.balances.set(tx.from, newFromBal);
  st.balances.set(tx.to, newToBal);
  st.nonces.set(tx.from, p.nonce);
  return null;
}
function validateCoinbaseTx(cb: Tx, expectedTo: Hex, expectedAmount: bigint, height: number): string | null {
  if (!cb || typeof cb !== "object") return "coinbase-not-object";
  if (cb.from !== "COINBASE") return "coinbase-from";
  if (cb.sig !== "") return "coinbase-sig";
  const p = txParsed(cb);
  if (!p) return "coinbase-num";
  if (p.fee !== 0n) return "coinbase-fee";
  if (p.nonce !== BigInt(height)) return "coinbase-nonce";
  if (!isPubKeyHex(cb.to)) return "coinbase-to";
  if (cb.to !== expectedTo) return "coinbase-to-mismatch";
  if (expectedAmount < 0n || expectedAmount > MAX_AMOUNT) return "expected-amount-overflow";
  if (p.amount !== expectedAmount) return "coinbase-amount";
  return null;
}
function applyCoinbaseTx(cb: Tx, st: State): string | null {
  const p = txParsed(cb);
  if (!p) return "coinbase-num";
  const bal = getBal(st, cb.to);
  if (bal < 0n || bal > MAX_AMOUNT) return "state-balance-corrupt";
  const newBal = addChecked(bal, p.amount);
  if (newBal === null) return "coinbase-overflow";
  st.balances.set(cb.to, newBal);
  return null;
}
function medianTimePast(c: Block[]): number {
  const n = Math.min(MTP_WINDOW, c.length);
  const t = c.slice(c.length - n).map((b) => b.header.timestamp).sort((a, b) => a - b);
  return t[t.length >> 1] ?? 0;
}
function expectedDifficultyForNext(chain: Block[]): number {
  const nextHeight = chain.length;
  if (nextHeight === 1) return clamp(INITIAL_DIFFICULTY, MIN_DIFFICULTY, MAX_DIFFICULTY);
  const prev = chain[chain.length - 1];
  let diff = prev.header.difficulty;
  if (nextHeight % RETARGET_INTERVAL !== 0) return diff;
  const start = chain[chain.length - RETARGET_INTERVAL].header.timestamp;
  const end = prev.header.timestamp;
  const expected = TARGET_BLOCK_MS * RETARGET_INTERVAL;
  const actual = clamp(Math.max(1, end - start), Math.floor(expected / 4), expected * 4);
  if (actual < expected / 2) diff += 2;
  else if (actual < expected) diff += 1;
  else if (actual > expected * 2) diff -= 2;
  else if (actual > expected) diff -= 1;
  return clamp(diff, MIN_DIFFICULTY, MAX_DIFFICULTY);
}
function saveChainSnapshot(): void {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = CHAIN_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify({ chain }), "utf8");
    fs.renameSync(tmp, CHAIN_FILE);
  } catch (e: any) {
    console.error(`snapshot-save-failed: ${String(e?.message ?? e)}`);
  }
}
function makeGenesis(): Block {
  const miner = ZERO32;
  const header: Header = {
    prev: ZERO32,
    height: 0,
    timestamp: GENESIS_TIMESTAMP,
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
const seenBlockQueue: Hex[] = [];
const seenTxQueue: Hex[] = [];
const rateState = new Map<string, { t: number; n: number }>();
let syncInProgress = false;
let nextSyncAfter = 0;
function hasMempoolNonceConflict(tx: Tx): boolean {
  if (tx.from === "COINBASE") return false;
  const n = parseUDec(tx.nonce);
  if (n === null) return false;
  for (const other of mempool.values()) {
    if (other.from !== tx.from) continue;
    const on = parseUDec(other.nonce);
    if (on !== null && on === n) return true;
  }
  return false;
}
function pruneMempoolAgainstState(): void {
  for (const [id, tx] of mempool) {
    if (validateNormalTx(tx, state)) mempool.delete(id);
  }
}
const peers = new Set<string>();
function remoteIp(req: http.IncomingMessage): string {
  const ip = req.socket?.remoteAddress || "";
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}
function isLocalIp(ip: string): boolean {
  return ip === "127.0.0.1" || ip === "::1";
}
function isPrivateOrLocalHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost") return true;
  const ipType = net.isIP(h);
  if (ipType === 4) {
    const [a, b] = h.split(".").map(Number);
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    return false;
  }
  if (ipType === 6) {
    return h === "::1" || h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd");
  }
  return false;
}
function isAdmin(req: http.IncomingMessage): boolean {
  if (isLocalIp(remoteIp(req))) return true;
  const t = req.headers["x-admin-token"];
  return Boolean(ADMIN_TOKEN && typeof t === "string" && t === ADMIN_TOKEN);
}
function rateLimitOk(req: http.IncomingMessage, path: string): boolean {
  const lim = RATE_LIMIT[path];
  if (!lim) return true;
  const key = `${remoteIp(req)}|${path}`;
  const now = Date.now();
  const s = rateState.get(key);
  if (!s || now - s.t >= RATE_WINDOW_MS) {
    rateState.set(key, { t: now, n: 1 });
    return true;
  }
  if (s.n >= lim) return false;
  s.n++;
  return true;
}
function normPeer(p: string): string {
  try {
    const u = new URL(p);
    if (isPrivateOrLocalHost(u.hostname)) return "";
    if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password || u.pathname !== "/" || u.search || u.hash) return "";
    return u.origin;
  } catch {
    return "";
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
  } finally {
    clearTimeout(t);
  }
}
async function readResponseJsonLimited(r: any, maxBytes: number): Promise<any | null> {
  const lenHeader = r.headers?.get?.("content-length");
  if (lenHeader) {
    const len = Number(lenHeader);
    if (Number.isFinite(len) && len > maxBytes) return null;
  }
  const reader = r.body?.getReader?.();
  if (!reader) return null;
  const chunks: Buffer[] = [];
  let size = 0;
  while (true) {
    const part = await reader.read();
    if (part.done) break;
    const value = part.value as Uint8Array;
    if (!value) continue;
    size += value.byteLength;
    if (size > maxBytes) {
      try { await reader.cancel(); } catch {}
      return null;
    }
    chunks.push(Buffer.from(value));
  }
  if (size < 1) return null;
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
async function getJson(peer: string, path: string, maxBytes = MAX_SYNC_RESPONSE_BYTES): Promise<any | null> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 1500);
  try {
    const r = await fetch(peer + path, { signal: ac.signal });
    if (!r.ok) return null;
    return await readResponseJsonLimited(r, maxBytes);
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}
async function postJsonRead(peer: string, path: string, body: any, maxBytes = 256_000): Promise<any | null> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 1500);
  try {
    const r = await fetch(peer + path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ac.signal,
    });
    const parsed = await readResponseJsonLimited(r, maxBytes);
    return { ok: r.ok, status: r.status, body: parsed };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}
function broadcastTx(tx: Tx): void {
  for (const p of peers) void postJson(p, "/tx", tx);
}
function broadcastBlock(b: Block): void {
  for (const p of peers) void postJson(p, "/block", b);
}
function selectTxsForBlock(st: State): { txs: Tx[]; fees: bigint } {
  const temp = cloneState(st);
  const txs = Array.from(mempool.values());
  txs.sort((a, b) => {
    const af = parseUDec(a.fee) ?? 0n;
    const bf = parseUDec(b.fee) ?? 0n;
    if (af === bf) return txId(a).localeCompare(txId(b));
    return af > bf ? -1 : 1;
  });
  const picked: Tx[] = [];
  let fees = 0n;
  for (const tx of txs) {
    if (picked.length >= MAX_TX_PER_BLOCK) break;
    const err = validateNormalTx(tx, temp);
    if (err) continue;
    const apErr = applyNormalTx(tx, temp);
    if (apErr) continue;
    const p = txParsed(tx);
    if (!p) continue;
    const newFees = addChecked(fees, p.fee);
    if (newFees === null) break;
    fees = newFees;
    picked.push(tx);
  }
  return { txs: picked, fees };
}
function tryAppendBlock(b: Block): { ok: boolean; err?: string } {
  const tip = chain[chain.length - 1];
  const now = Date.now();
  if (!b || typeof b !== "object") return { ok: false, err: "block-not-object" };
  if (!isHashHex(b.hash)) return { ok: false, err: "bad-hash-hex" };
  if (!b.header || typeof b.header !== "object") return { ok: false, err: "bad-header" };
  if (!headerShapeOk(b.header)) return { ok: false, err: "bad-header-shape" };
  if (b.header.height !== chain.length) return { ok: false, err: "bad-height" };
  if (b.header.prev !== tip.hash) return { ok: false, err: "bad-prev" };
  if (b.header.timestamp <= medianTimePast(chain)) return { ok: false, err: "time-mtp" };
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
  const cb = b.txs[0];
  const temp = cloneState(state);
  let fees = 0n;
  for (let i = 1; i < b.txs.length; i++) {
    const tx = b.txs[i];
    const err = validateNormalTx(tx, temp);
    if (err) return { ok: false, err: `tx${i}:${err}` };
    const apErr = applyNormalTx(tx, temp);
    if (apErr) return { ok: false, err: `tx${i}:apply:${apErr}` };
    const p = txParsed(tx);
    if (!p) return { ok: false, err: `tx${i}:bad-num` };
    const newFees = addChecked(fees, p.fee);
    if (newFees === null) return { ok: false, err: `tx${i}:fee-overflow` };
    fees = newFees;
  }
  const expectedCbAmount = addChecked(BLOCK_REWARD, fees);
  if (expectedCbAmount === null) return { ok: false, err: "coinbase-overflow" };
  const cbErr = validateCoinbaseTx(cb, b.miner, expectedCbAmount, b.header.height);
  if (cbErr) return { ok: false, err: `coinbase:${cbErr}` };
  const cbApplyErr = applyCoinbaseTx(cb, temp);
  if (cbApplyErr) return { ok: false, err: `coinbase-apply:${cbApplyErr}` };
  chain.push(b);
  state = temp;
  totalWork += workForDifficulty(b.header.difficulty);
  rememberSeen(seenBlocks, seenBlockQueue, b.hash, SEEN_BLOCK_CAP);
  for (let i = 1; i < b.txs.length; i++) mempool.delete(txId(b.txs[i]));
  pruneMempoolAgainstState();
  saveChainSnapshot();
  return { ok: true };
}
function validateWholeChain(candidate: Block[]): { ok: boolean; work: bigint; st: State; err?: string } {
  if (!Array.isArray(candidate) || candidate.length < 1) {
    return { ok: false, work: 0n, st: { balances: new Map(), nonces: new Map() }, err: "empty" };
  }
  const now = Date.now();
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
    if (!headerShapeOk(b.header)) return { ok: false, work, st, err: `headerShape@${i}` };
    if (!isHashHex(b.hash)) return { ok: false, work, st, err: `hashhex@${i}` };
    const tip = localChain[localChain.length - 1];
    const nextHeight = localChain.length;
    if (b.header.height !== nextHeight) return { ok: false, work, st, err: `h@${i}` };
    if (b.header.prev !== tip.hash) return { ok: false, work, st, err: `prev@${i}` };
    if (b.header.timestamp <= medianTimePast(localChain)) return { ok: false, work, st, err: `mtp@${i}` };
    if (b.header.timestamp < tip.header.timestamp) return { ok: false, work, st, err: `time@${i}` };
    if (b.header.timestamp > now + MAX_FUTURE_MS) return { ok: false, work, st, err: `future@${i}` };
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
    let fees = 0n;
    for (let j = 1; j < b.txs.length; j++) {
      const tx = b.txs[j];
      const err = validateNormalTx(tx, temp);
      if (err) return { ok: false, work, st, err: `tx@${i}.${j}:${err}` };
      const apErr = applyNormalTx(tx, temp);
      if (apErr) return { ok: false, work, st, err: `tx@${i}.${j}:apply:${apErr}` };
      const p = txParsed(tx);
      if (!p) return { ok: false, work, st, err: `tx@${i}.${j}:bad-num` };
      const newFees = addChecked(fees, p.fee);
      if (newFees === null) return { ok: false, work, st, err: `fees@${i}` };
      fees = newFees;
    }
    const expectedCbAmount = addChecked(BLOCK_REWARD, fees);
    if (expectedCbAmount === null) return { ok: false, work, st, err: `cbOverflow@${i}` };
    const cbErr = validateCoinbaseTx(cb, b.miner, expectedCbAmount, b.header.height);
    if (cbErr) return { ok: false, work, st, err: `cb@${i}:${cbErr}` };
    const cbApplyErr = applyCoinbaseTx(cb, temp);
    if (cbApplyErr) return { ok: false, work, st, err: `cbApply@${i}:${cbApplyErr}` };
    st = temp;
    localChain.push(b);
    work += workForDifficulty(b.header.difficulty);
  }
  return { ok: true, work, st };
}
function loadChainSnapshot(): void {
  try {
    if (!fs.existsSync(CHAIN_FILE)) return;
    const raw = fs.readFileSync(CHAIN_FILE, "utf8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed?.chain)) throw new Error("bad-snapshot-format");
    const cand = parsed.chain as Block[];
    const res = validateWholeChain(cand);
    if (!res.ok) throw new Error(`bad-snapshot:${res.err}`);
    chain = cand;
    state = res.st;
    totalWork = res.work;
    console.log(`loaded snapshot: height=${chain.length - 1} work=${totalWork}`);
  } catch (e: any) {
    console.error(`snapshot-load-failed: ${String(e?.message ?? e)}`);
  }
}
async function fetchChainRange(peer: string, fromHeight: number, tipHeight: number): Promise<Block[] | null> {
  if (!Number.isSafeInteger(fromHeight) || !Number.isSafeInteger(tipHeight)) return null;
  if (fromHeight < 0 || tipHeight < fromHeight) return null;
  const out: Block[] = [];
  let chunks = 0;
  for (let from = fromHeight; from <= tipHeight; from += CHAIN_CHUNK_BLOCKS) {
    chunks++;
    if (chunks > MAX_SYNC_CHUNKS_PER_ATTEMPT) return null;
    const limit = Math.min(CHAIN_CHUNK_BLOCKS, tipHeight + 1 - from);
    const resp = await getJson(peer, `/chain?from=${from}&limit=${limit}`, MAX_SYNC_RESPONSE_BYTES);
    if (!resp || !Array.isArray(resp.blocks)) return null;
    const blocks = resp.blocks as Block[];
    if (blocks.length < 1 || blocks.length > limit) return null;
    for (let i = 0; i < blocks.length; i++) {
      if (blocks[i]?.header?.height !== from + i) return null;
    }
    out.push(...blocks);
  }
  return out;
}
async function maybeSyncFromPeers(): Promise<void> {
  const now = Date.now();
  if (syncInProgress || now < nextSyncAfter) return;
  syncInProgress = true;
  nextSyncAfter = now + SYNC_COOLDOWN_MS;
  try {
  for (const p of peers) {
    const tip = await getJson(p, "/tip", 64_000);
    if (!tip || typeof tip.work !== "string" || !Number.isSafeInteger(tip.height)) continue;
    const tipHeight = tip.height as number;
    if (tipHeight < 0) continue;
    const localTip = chain.length - 1;
    if (tipHeight > localTip + MAX_SYNC_AHEAD) continue;
    let peerWork = 0n;
    try { peerWork = BigInt(tip.work); } catch { continue; }
    if (peerWork <= totalWork) continue;
    const anchor = Math.max(0, chain.length - 1 - RETARGET_INTERVAL);
    const tail = await fetchChainRange(p, anchor, tipHeight);
    if (!tail) continue;
    let cand = chain.slice(0, anchor).concat(tail);
    let res = validateWholeChain(cand);
    if ((!res.ok || res.work <= totalWork) && anchor > 0) {
      const full = await fetchChainRange(p, 0, tipHeight);
      if (!full) continue;
      cand = full;
      res = validateWholeChain(cand);
    }
    if (res.ok && res.work > totalWork) {
      chain = cand;
      state = res.st;
      totalWork = res.work;
      mempool.clear();
      saveChainSnapshot();
      console.log(`synced from ${p}: height=${chain.length - 1} work=${totalWork}`);
    }
  }
  } finally {
    syncInProgress = false;
  }
}
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
      if (method === "POST" && !rateLimitOk(req, url.pathname)) {
        return sendJson(res, 429, { error: "rate-limit" });
      }
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
        const start = Number.isFinite(from) ? Math.floor(from) : 0;
        if (start < 0 || start >= chain.length) return sendJson(res, 200, { blocks: [] });
        const lim = Number(url.searchParams.get("limit") ?? String(CHAIN_CHUNK_BLOCKS));
        const limit = Number.isFinite(lim) ? clamp(Math.floor(lim), 1, CHAIN_CHUNK_BLOCKS) : CHAIN_CHUNK_BLOCKS;
        return sendJson(res, 200, { blocks: chain.slice(start, start + limit) });
      }
      if (method === "GET" && url.pathname === "/state") {
        const acct = url.searchParams.get("acct");
        if (!acct || !isPubKeyHex(acct)) return sendJson(res, 400, { error: "bad-acct" });
        return sendJson(res, 200, {
          acct,
          balance: getBal(state, acct).toString(),
          nonce: getNonce(state, acct).toString(),
        });
      }
      if (method === "GET" && url.pathname === "/mempool") {
        return sendJson(res, 200, { txs: Array.from(mempool.values()) });
      }
      if (method === "GET" && url.pathname === "/peers") {
        return sendJson(res, 200, { peers: Array.from(peers) });
      }
      if (method === "POST" && url.pathname === "/peers") {
        if (!isAdmin(req)) return sendJson(res, 403, { error: "forbidden" });
        const body = await readJson(req);
        const p = typeof body?.peer === "string" ? normPeer(body.peer) : null;
        if (!p) return sendJson(res, 400, { error: "bad-peer" });
        if ((p === `http://127.0.0.1:${port}` || p === `http://localhost:${port}`) || p === `https://127.0.0.1:${port}` || p === `https://localhost:${port}`) {
          return sendJson(res, 400, { error: "self-peer" });
        }
        if (!peers.has(p) && peers.size >= MAX_PEERS) return sendJson(res, 429, { error: "too-many-peers" });
        peers.add(p);
        return sendJson(res, 200, { ok: true, peers: Array.from(peers) });
      }
      if (method === "POST" && url.pathname === "/tx") {
        const tx = (await readJson(req)) as Tx;
        if (!tx || typeof tx !== "object") return sendJson(res, 400, { error: "bad-json" });
        const id = txId(tx);
        if (seenTxs.has(id)) return sendJson(res, 200, { ok: true, dup: true });
        if (mempool.size >= MAX_MEMPOOL) return sendJson(res, 429, { error: "mempool-full" });
        if (hasMempoolNonceConflict(tx)) return sendJson(res, 409, { error: "mempool-nonce-conflict" });
        const err = validateNormalTx(tx, state);
        if (err) return sendJson(res, 400, { error: err });
        mempool.set(id, tx);
        rememberSeen(seenTxs, seenTxQueue, id, SEEN_TX_CAP);
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
        void maybeSyncFromPeers();
        return sendJson(res, 400, { ok: false, error: r.err });
      }
      if (method === "POST" && url.pathname === "/sync") {
        if (!isAdmin(req)) return sendJson(res, 403, { error: "forbidden" });
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
    const cbAmount = addChecked(BLOCK_REWARD, fees);
    if (cbAmount === null) {
      setImmediate(tick);
      return;
    }
    const coinbase: Tx = {
      from: "COINBASE",
      to: minerPub,
      amount: cbAmount.toString(),
      fee: "0",
      nonce: BigInt(height).toString(),
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
function mineOne(chainSoFar: Block[], miner: Hex, txs: Tx[], timestamp: number): Block {
  const tip = chainSoFar[chainSoFar.length - 1];
  const header: Header = {
    prev: tip.hash,
    height: chainSoFar.length,
    timestamp,
    difficulty: expectedDifficultyForNext(chainSoFar),
    nonce: 0,
    txRoot: txRoot(txs),
  };
  for (;;) {
    const hash = blockHash(header, miner);
    if (checkPow(hash, header.difficulty)) return { header: { ...header }, miner, txs, hash };
    header.nonce++;
    if (header.nonce > 20_000_000) throw new Error("selftest-mine-timeout");
  }
}
function runSelfTest(): void {
  const seedA = new Uint8Array(32).fill(1);
  const seedB = new Uint8Array(32).fill(2);
  const ka = nacl.sign.keyPair.fromSeed(seedA);
  const kb = nacl.sign.keyPair.fromSeed(seedB);
  const secA = bytesToHex(ka.secretKey);
  const pubA = bytesToHex(ka.publicKey);
  const pubB = bytesToHex(kb.publicKey);
  const g = makeGenesis();
  const cb1: Tx = { from: "COINBASE", to: pubA, amount: BLOCK_REWARD.toString(), fee: "0", nonce: "1", sig: "" };
  const t1 = g.header.timestamp + TARGET_BLOCK_MS;
  const b1 = mineOne([g], pubA, [cb1], t1);
  const pay = signTx(secA, pubB, "20", "3", "1");
  if (!verifyTxSig(pay)) throw new Error("selftest-signature");
  const cb2: Tx = { from: "COINBASE", to: pubA, amount: (BLOCK_REWARD + 3n).toString(), fee: "0", nonce: "2", sig: "" };
  const t2 = Math.max(b1.header.timestamp + 1, medianTimePast([g, b1]) + 1);
  const b2 = mineOne([g, b1], pubA, [cb2, pay], t2);
  const good = validateWholeChain([g, b1, b2]);
  if (!good.ok) throw new Error(`selftest-good:${good.err}`);
  const bad = JSON.parse(JSON.stringify([g, b1, b2])) as Block[];
  bad[2].header.timestamp = medianTimePast([g, b1]);
  bad[2].hash = blockHash(bad[2].header, bad[2].miner);
  const badRes = validateWholeChain(bad);
  if (badRes.ok || !String(badRes.err).startsWith("mtp@")) throw new Error("selftest-mtp");
  console.log(JSON.stringify({ ok: true, vectors: { txid: txId(pay), block1: b1.hash, block2: b2.hash } }, null, 2));
}
async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args["selftest"]) {
    runSelfTest();
    return;
  }
  if (args["keygen"]) {
    const kp = genKeypair();
    console.log(JSON.stringify(kp, null, 2));
    return;
  }
  if (args["sign-tx"]) {
    if (!args["secret"]) throw new Error("missing --secret for --sign-tx");
    const req = JSON.parse(String(args["sign-tx"]));
    const tx = signTx(
      String(args["secret"]),
      String(req?.to ?? ""),
      String(req?.amount ?? ""),
      String(req?.fee ?? "0"),
      String(req?.nonce ?? ""),
    );
    const out: any = { txid: txId(tx), tx };
    if (args["send-tx"]) {
      const node = args["node"] ? String(args["node"]) : `http://127.0.0.1:${DEFAULT_PORT}`;
      out.send = await postJsonRead(node, "/tx", tx);
      if (!out.send) throw new Error("send-failed");
    }
    console.log(JSON.stringify(out, null, 2));
    return;
  }
  if (args["send-tx"]) {
    const txRaw = args["tx"] ? String(args["tx"]) : "";
    if (!txRaw) throw new Error("missing --tx for --send-tx");
    const node = args["node"] ? String(args["node"]) : `http://127.0.0.1:${DEFAULT_PORT}`;
    const sent = await postJsonRead(node, "/tx", JSON.parse(txRaw));
    if (!sent) throw new Error("send-failed");
    console.log(JSON.stringify(sent, null, 2));
    return;
  }
  if (args["difficulty"]) throw new Error("--difficulty is disabled on frozen mainnet profile");
  const port = args["port"] ? Number(args["port"]) : DEFAULT_PORT;
  if (!Number.isFinite(port)) throw new Error("bad --port");
  loadChainSnapshot();
  if (args["peers"]) {
    const list = String(args["peers"]).split(",").map(s => s.trim()).filter(Boolean);
    for (const p of list) {
      const n = normPeer(p);
      if (n) peers.add(n);
      if (peers.size >= MAX_PEERS) break;
    }
  }
  startServer(port);
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
