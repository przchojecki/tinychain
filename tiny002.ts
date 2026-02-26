import http from "node:http";
import https from "node:https";
import { createHash, createHmac, timingSafeEqual, randomBytes, scryptSync, createCipheriv, createDecipheriv } from "node:crypto";
import net from "node:net";
import dns from "node:dns/promises";
import readline from "node:readline/promises";
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
  difficulty: number;// PoW difficulty bits (higher = harder)
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
const INITIAL_DIFFICULTY = 18;      // expected ~2^18 hashes per block
const MIN_DIFFICULTY = 8;
const MAX_DIFFICULTY = 40;
const TARGET_BLOCK_MS = 10_000;
const RETARGET_INTERVAL = 20;
const DAA_WINDOW = 60;
const DAA_MAX_STEP = 2;
const MTP_WINDOW = 11;
const GENESIS_TIMESTAMP = 1_700_000_000_000;
const MAX_TX_PER_BLOCK = 200;
const MAX_MEMPOOL = 5000;
const MAX_MEMPOOL_PER_SENDER = 64;
const MIN_RELAY_FEE = 1n;
const MAX_BODY_BYTES = 1_000_000;   // 1MB HTTP body limit
const MAX_FUTURE_MS = 2 * 60_000;   // reject blocks > 2min in future
const MAX_SYNC_RESPONSE_BYTES = 2_000_000; // cap peer response bytes during sync
const CHAIN_CHUNK_BLOCKS = 256;     // /chain page size for sync
const CHAIN_PAGE_TARGET_BYTES = 512_000;
const MAX_SYNC_AHEAD = 2048;
const MAX_SYNC_CHUNKS_PER_ATTEMPT = 24;
const SYNC_COOLDOWN_MS = 5000;
const SYNC_INTERVAL_MS = 15_000;
const RATE_WINDOW_MS = 10_000;
const RATE_SWEEP_MS = 30_000;
const RATE_STATE_CAP = 50_000;
const RATE_LIMIT: Record<string, number> = {
  "GET:/hello": 120,
  "GET:/tip": 220,
  "GET:/chain": 40,
  "GET:/state": 220,
  "GET:/mempool": 40,
  "GET:/peers": 120,
  "POST:/tx": 120,
  "POST:/block": 40,
  "POST:/peers": 8,
  "POST:/sync": 4,
};
const BLOCK_REWARD = 50n;           // fixed issuance per block (toy integer units)
const MAX_AMOUNT = (1n << 63n) - 1n; // hard cap for amount/fee/nonce/balance values
const CHAIN_ID = "tinychain-main-001";
const PROTOCOL_VERSION = 2;
const APP_VERSION = "tiny002";
const SNAPSHOT_VERSION = 2;
const SEEN_TX_CAP = 50_000;
const SEEN_BLOCK_CAP = 50_000;
const MAX_PEERS = 128;
const MAX_PEER_FAILURES = 8;
const MAX_DISCOVERED_PEERS_PER_TIP = 16;
const KDF_N = 16384;
const KDF_R = 8;
const KDF_P = 1;
const KEYSIZE = 32;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const ADMIN_TOKEN = process.env.TINYCHAIN_ADMIN_TOKEN || "";
const PEER_TOKEN = process.env.TINYCHAIN_PEER_TOKEN || "";
const UNSAFE_DEV_MODE = process.env.TINYCHAIN_UNSAFE_DEV === "I_UNDERSTAND";
const STRICT_ADMIN = process.env.TINYCHAIN_STRICT_ADMIN !== "0";
const ALLOW_LOOPBACK_ADMIN = process.env.TINYCHAIN_ALLOW_LOOPBACK_ADMIN === "1";
const ALLOW_PRIVATE_PEERS = process.env.TINYCHAIN_ALLOW_PRIVATE_PEERS === "1";
const ALLOW_LOOPBACK_PEER_AUTH = process.env.TINYCHAIN_ALLOW_LOOPBACK_PEER_AUTH === "1";
const TLS_CERT_ENV = process.env.TINYCHAIN_TLS_CERT || "";
const TLS_KEY_ENV = process.env.TINYCHAIN_TLS_KEY || "";
const WALLET_PASS_ENV = process.env.TINYCHAIN_WALLET_PASSPHRASE || "";
const SNAPSHOT_KEY = process.env.TINYCHAIN_SNAPSHOT_KEY || "";
const BOOTSTRAP_SEEDS_ENV = process.env.TINYCHAIN_BOOTSTRAP_SEEDS || "";
const SEED_FILE_ENV = process.env.TINYCHAIN_SEED_FILE || "";
const OPEN_RELAY = process.env.TINYCHAIN_OPEN_RELAY !== "0";
const PEER_SIG_MAX_SKEW_MS = 60_000;
const DATA_DIR = process.env.TINYCHAIN_DATA_DIR || ".tinychain";
const CHAIN_FILE = path.join(DATA_DIR, "chain.json");
const PEERS_FILE = path.join(DATA_DIR, "peers.json");
const NODE_FILE = path.join(DATA_DIR, "node.json");
function isHex(s: string): boolean {
  return /^[0-9a-f]+$/.test(s);
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
  if (!isHashHex(hash)) return false;
  const d = clamp(difficulty, MIN_DIFFICULTY, MAX_DIFFICULTY);
  const target = (1n << BigInt(256 - d)) - 1n;
  return BigInt(`0x${hash}`) <= target;
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
  return 1n << BigInt(clamp(d, 0, 250));
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
function isNodeIdHex(x: any): x is Hex {
  return isHashHex(x);
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
  const spanBlocks = Math.max(1, Math.min(DAA_WINDOW, nextHeight - 1));
  const start = chain[chain.length - 1 - spanBlocks].header.timestamp;
  const end = prev.header.timestamp;
  const expected = TARGET_BLOCK_MS * spanBlocks;
  const actual = clamp(Math.max(1, end - start), Math.floor(expected / 8), expected * 8);
  if (actual <= expected / 4) diff += DAA_MAX_STEP;
  else if (actual < Math.floor(expected * 3 / 4)) diff += 1;
  else if (actual >= expected * 4) diff -= DAA_MAX_STEP;
  else if (actual > Math.floor(expected * 3 / 2)) diff -= 1;
  return clamp(diff, MIN_DIFFICULTY, MAX_DIFFICULTY);
}
function saveChainSnapshot(): void {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const count = chain.length;
    const chainHash = chainSnapshotHash(chain);
    const meta = {
      version: SNAPSHOT_VERSION,
      nodeId,
      count,
      chainHash,
      mac: snapshotMac("chain", chainHash, count, SNAPSHOT_VERSION),
      createdAt: Date.now(),
    };
    const tmp = CHAIN_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify({ chain, meta }), "utf8");
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
const peerFailures = new Map<string, number>();
let syncInProgress = false;
let nextSyncAfter = 0;
let lastRateSweep = 0;
let nodeId = "";
let nodePub = "";
let nodeSecret = "";
let listenScheme = "http";
let listenHost = "127.0.0.1";
let listenPort = DEFAULT_PORT;
let advertisedOrigin = "";
const selfOrigins = new Set<string>();
const peerNodeIds = new Map<string, string>();
function txFee(tx: Tx): bigint | null {
  return parseUDec(tx?.fee);
}
function mempoolSenderCount(from: string): number {
  let c = 0;
  for (const tx of mempool.values()) if (tx.from === from) c++;
  return c;
}
function evictLowestFeeFor(candidate: Tx): boolean {
  const candidateFee = txFee(candidate);
  if (candidateFee === null) return false;
  let lowId = "";
  let lowFee: bigint | null = null;
  for (const [id, tx] of mempool) {
    const fee = txFee(tx);
    if (fee === null) continue;
    if (lowFee === null || fee < lowFee || (fee === lowFee && id < lowId)) {
      lowFee = fee;
      lowId = id;
    }
  }
  if (lowFee === null || candidateFee <= lowFee || !lowId) return false;
  mempool.delete(lowId);
  return true;
}
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
function safeEq(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
function canonicalOrigin(s: string): string {
  try {
    return new URL(s).origin;
  } catch {
    return "";
  }
}
function chainSnapshotHash(c: Block[]): Hex {
  return sha256Hex(JSON.stringify(c));
}
function peersSnapshotHash(p: string[]): Hex {
  return sha256Hex(JSON.stringify(p));
}
function snapshotMac(kind: "chain" | "peers", hash: Hex, count: number, version: number): string {
  if (!SNAPSHOT_KEY) return "";
  return createHmac("sha256", SNAPSHOT_KEY)
    .update(`${CHAIN_ID}|${kind}|${version}|${count}|${hash}`)
    .digest("hex");
}
function verifySnapshotMac(kind: "chain" | "peers", hash: Hex, count: number, version: number, mac: any): boolean {
  if (typeof mac !== "string" || !isHashHex(mac)) return false;
  if (!SNAPSHOT_KEY) return false;
  const want = snapshotMac(kind, hash, count, version);
  return safeEq(want, mac);
}
function hostForOrigin(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}
function refreshSelfOrigins(advertiseRaw = ""): void {
  selfOrigins.clear();
  advertisedOrigin = "";
  const p = listenPort;
  const s = listenScheme;
  selfOrigins.add(`${s}://${hostForOrigin(listenHost)}:${p}`);
  selfOrigins.add(`${s}://127.0.0.1:${p}`);
  selfOrigins.add(`${s}://localhost:${p}`);
  selfOrigins.add(`${s}://[::1]:${p}`);
  if (!advertiseRaw) return;
  for (const a of advertiseRaw.split(",").map((x) => x.trim()).filter(Boolean)) {
    const o = canonicalOrigin(a);
    if (!o) continue;
    selfOrigins.add(o);
    if (!advertisedOrigin) advertisedOrigin = o;
  }
}
function isSelfPeerOrigin(origin: string): boolean {
  return selfOrigins.has(origin);
}
function nodeOrigin(): string {
  return advertisedOrigin || `${listenScheme}://${hostForOrigin(listenHost)}:${listenPort}`;
}
function registerPeerNodeId(origin: string, id: string): boolean {
  if (!isNodeIdHex(id) || id === nodeId) return false;
  for (const [p, otherId] of peerNodeIds) {
    if (p !== origin && otherId === id) return false;
  }
  peerNodeIds.set(origin, id);
  return true;
}
function loadOrCreateNodeId(): void {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(NODE_FILE)) {
      const raw = fs.readFileSync(NODE_FILE, "utf8");
      const parsed = JSON.parse(raw);
      if (isPubKeyHex(parsed?.nodePub) && typeof parsed?.nodeSecret === "string" && isHex(parsed.nodeSecret) && parsed.nodeSecret.length === 128) {
        if (pubFromSecretHex(parsed.nodeSecret) === parsed.nodePub) {
          nodePub = parsed.nodePub;
          nodeSecret = parsed.nodeSecret;
          nodeId = sha256Hex(nodePub);
          return;
        }
      }
    }
  } catch {}
  const kp = genKeypair();
  nodePub = kp.pub;
  nodeSecret = kp.secret;
  nodeId = sha256Hex(nodePub);
  try {
    const tmp = NODE_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify({ nodeId, nodePub, nodeSecret, createdAt: Date.now() }), "utf8");
    fs.renameSync(tmp, NODE_FILE);
  } catch (e: any) {
    console.error(`nodeid-save-failed: ${String(e?.message ?? e)}`);
  }
}
function savePeersSnapshot(): void {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const sorted = Array.from(peers).sort();
    const count = sorted.length;
    const peersHash = peersSnapshotHash(sorted);
    const meta = {
      version: SNAPSHOT_VERSION,
      nodeId,
      count,
      peersHash,
      mac: snapshotMac("peers", peersHash, count, SNAPSHOT_VERSION),
      createdAt: Date.now(),
    };
    const tmp = PEERS_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify({ peers: sorted, meta }), "utf8");
    fs.renameSync(tmp, PEERS_FILE);
  } catch (e: any) {
    console.error(`peers-save-failed: ${String(e?.message ?? e)}`);
  }
}
function remoteIp(req: http.IncomingMessage): string {
  const ip = req.socket?.remoteAddress || "";
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}
function isLocalIp(ip: string): boolean {
  return ip === "127.0.0.1" || ip === "::1";
}
function isPrivateOrLocalIp(ip: string): boolean {
  const h = ip.toLowerCase();
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
function isPrivateOrLocalHostLiteral(hostname: string): boolean {
  if (UNSAFE_DEV_MODE && ALLOW_PRIVATE_PEERS) return false;
  const h = hostname.toLowerCase();
  if (h === "localhost") return true;
  return net.isIP(h) > 0 && isPrivateOrLocalIp(h);
}
async function hostIsBlocked(hostname: string): Promise<boolean> {
  const h = hostname.toLowerCase();
  const ipType = net.isIP(h);
  if (ipType > 0) {
    if (UNSAFE_DEV_MODE && ALLOW_PRIVATE_PEERS) return false;
    return isPrivateOrLocalIp(h);
  }
  if (h === "localhost") return true;
  if (UNSAFE_DEV_MODE && ALLOW_PRIVATE_PEERS) return false;
  try {
    const resolved = await dns.lookup(h, { all: true, verbatim: true });
    if (!Array.isArray(resolved) || resolved.length < 1 || resolved.length > 32) return true;
    for (const rec of resolved) {
      const ip = typeof rec?.address === "string" ? rec.address : "";
      if (net.isIP(ip) < 1 || isPrivateOrLocalIp(ip)) return true;
    }
    return false;
  } catch {
    return true;
  }
}
function parseListenHost(args: Record<string, string | boolean>): string {
  if (args["host"]) return String(args["host"]).trim();
  if (args["public"]) return "0.0.0.0";
  return "127.0.0.1";
}
function assertListenHost(host: string): void {
  const h = host.trim().toLowerCase();
  if (!h) throw new Error("bad --host");
  if (h === "localhost" || h === "0.0.0.0" || h === "127.0.0.1" || h === "::" || h === "::1") return;
  if (net.isIP(h) > 0) return;
  throw new Error("bad --host (use literal IP/localhost)");
}
function isLoopbackBindHost(host: string): boolean {
  const h = host.trim().toLowerCase();
  return h === "127.0.0.1" || h === "::1" || h === "localhost";
}
function isAdmin(req: http.IncomingMessage): boolean {
  const t = req.headers["x-admin-token"];
  const tokenOk = Boolean(ADMIN_TOKEN && typeof t === "string" && safeEq(ADMIN_TOKEN, t));
  if (tokenOk) return true;
  if (UNSAFE_DEV_MODE && !STRICT_ADMIN && ALLOW_LOOPBACK_ADMIN && isLocalIp(remoteIp(req))) return true;
  return false;
}
function headerOne(req: http.IncomingMessage, name: string): string {
  const v = req.headers[name];
  if (typeof v === "string") return v;
  if (Array.isArray(v) && typeof v[0] === "string") return v[0];
  return "";
}
function peerSigPayload(method: string, path: string, ts: string, pub: string): Uint8Array {
  return sha256Bytes(JSON.stringify([CHAIN_ID, PROTOCOL_VERSION, method, path, ts, pub]));
}
function peerSign(method: string, path: string, ts: string, pub: string, secret: string): string {
  return bytesToHex(nacl.sign.detached(peerSigPayload(method, path, ts, pub), hexToBytes(secret)));
}
function peerAuthHeaders(path = "", method = "GET", token = PEER_TOKEN): Record<string, string> {
  const h: Record<string, string> = {};
  if (token) h["x-peer-token"] = token;
  if (path && nodePub && nodeSecret) {
    const ts = String(Date.now());
    h["x-peer-node"] = nodeId;
    h["x-peer-pub"] = nodePub;
    h["x-peer-ts"] = ts;
    h["x-peer-sig"] = peerSign(method, path, ts, nodePub, nodeSecret);
  }
  return h;
}
function peerSignedOk(req: http.IncomingMessage, method: string, path: string): boolean {
  const peerNode = headerOne(req, "x-peer-node");
  const pub = headerOne(req, "x-peer-pub");
  const ts = headerOne(req, "x-peer-ts");
  const sig = headerOne(req, "x-peer-sig");
  if (!isNodeIdHex(peerNode) || !isPubKeyHex(pub) || !isSigHex(sig)) return false;
  if (peerNode !== sha256Hex(pub)) return false;
  if (peerNode === nodeId) return false;
  if (!/^[0-9]{10,16}$/.test(ts)) return false;
  const tsNum = Number(ts);
  if (!Number.isSafeInteger(tsNum) || Math.abs(Date.now() - tsNum) > PEER_SIG_MAX_SKEW_MS) return false;
  return nacl.sign.detached.verify(peerSigPayload(method, path, ts, pub), hexToBytes(sig), hexToBytes(pub));
}
function peerAuthOk(req: http.IncomingMessage, method: string, path: string): boolean {
  if (UNSAFE_DEV_MODE && ALLOW_LOOPBACK_PEER_AUTH && isLocalIp(remoteIp(req))) return true;
  const t = headerOne(req, "x-peer-token");
  if (PEER_TOKEN && !(t && safeEq(PEER_TOKEN, t))) return false;
  if (path !== "/chain") return true;
  return peerSignedOk(req, method, path);
}
function sweepRateState(now: number): void {
  if (now - lastRateSweep < RATE_SWEEP_MS && rateState.size <= RATE_STATE_CAP) return;
  for (const [k, s] of rateState) {
    if (now - s.t >= RATE_WINDOW_MS * 2) rateState.delete(k);
  }
  while (rateState.size > RATE_STATE_CAP) {
    const oldest = rateState.keys().next().value;
    if (!oldest) break;
    rateState.delete(oldest);
  }
  lastRateSweep = now;
}
function rateLimitOk(req: http.IncomingMessage, method: string, path: string): boolean {
  const lim = RATE_LIMIT[`${method}:${path}`];
  if (!lim) return true;
  const key = `${remoteIp(req)}|${method}|${path}`;
  const now = Date.now();
  sweepRateState(now);
  const s = rateState.get(key);
  if (!s || now - s.t >= RATE_WINDOW_MS) {
    rateState.set(key, { t: now, n: 1 });
    return true;
  }
  if (s.n >= lim) return false;
  s.n++;
  rateState.delete(key);
  rateState.set(key, s);
  return true;
}
function normPeerSyntax(p: string): string {
  try {
    const u = new URL(p);
    if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password || u.pathname !== "/" || u.search || u.hash) return "";
    if (!u.hostname) return "";
    if (isPrivateOrLocalHostLiteral(u.hostname)) return "";
    return u.origin;
  } catch {
    return "";
  }
}
async function normPeer(p: string): Promise<string> {
  const n = normPeerSyntax(p);
  if (!n) return "";
  try {
    const u = new URL(n);
    if (await hostIsBlocked(u.hostname)) return "";
    return n;
  } catch {
    return "";
  }
}
function parseOriginList(raw: string): string[] {
  return raw
    .split(/\r?\n/)
    .flatMap((line) => line.split(","))
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith("#"));
}
function readSeedFile(seedFile: string): string[] {
  const raw = fs.readFileSync(seedFile, "utf8");
  return parseOriginList(raw);
}
async function addPeerCandidates(list: string[]): Promise<boolean> {
  let changed = false;
  for (const p of list) {
    const n = await normPeer(p);
    if (!n || peers.has(n) || isSelfPeerOrigin(n)) continue;
    if (peers.size >= MAX_PEERS) break;
    peers.add(n);
    changed = true;
  }
  return changed;
}
async function loadPeersSnapshot(): Promise<void> {
  try {
    if (!fs.existsSync(PEERS_FILE)) return;
    const raw = fs.readFileSync(PEERS_FILE, "utf8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed?.peers)) return;
    if (parsed?.meta && typeof parsed.meta === "object") {
      const version = Number(parsed.meta.version);
      const count = Number(parsed.meta.count);
      const hash = peersSnapshotHash(parsed.peers.slice().sort());
      const versionOk = Number.isSafeInteger(version) && version <= SNAPSHOT_VERSION;
      const countOk = Number.isSafeInteger(count) && count === parsed.peers.length;
      const hashOk = typeof parsed.meta.peersHash === "string" && parsed.meta.peersHash === hash;
      const hasMac = typeof parsed.meta.mac === "string";
      const macOk = hasMac ? verifySnapshotMac("peers", hash, count, version, parsed.meta.mac) : !SNAPSHOT_KEY;
      if (!versionOk || !countOk || !hashOk) throw new Error("bad-peers-meta");
      if (!macOk) throw new Error(hasMac ? "bad-peers-mac" : "missing-peers-mac");
    } else if (SNAPSHOT_KEY) {
      throw new Error("missing-peers-meta");
    }
    for (const p of parsed.peers) {
      if (typeof p !== "string") continue;
      const n = await normPeer(p);
      if (!n || isSelfPeerOrigin(n)) continue;
      peers.add(n);
      if (peers.size >= MAX_PEERS) break;
    }
  } catch (e: any) {
    console.error(`peers-load-failed: ${String(e?.message ?? e)}`);
  }
}
function markPeerSuccess(p: string): void {
  peerFailures.delete(p);
}
function markPeerFailure(p: string): void {
  const n = (peerFailures.get(p) ?? 0) + 1;
  if (n >= MAX_PEER_FAILURES) {
    peerFailures.delete(p);
    peerNodeIds.delete(p);
    if (peers.delete(p)) savePeersSnapshot();
    return;
  }
  peerFailures.set(p, n);
}
async function postJson(peer: string, path: string, body: any, headers: Record<string, string> = {}): Promise<void> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 1500);
  try {
    await fetch(peer + path, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
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
async function getJson(peer: string, path: string, maxBytes = MAX_SYNC_RESPONSE_BYTES, headers: Record<string, string> = {}): Promise<any | null> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 1500);
  try {
    const r = await fetch(peer + path, { signal: ac.signal, headers });
    if (!r.ok) return null;
    return await readResponseJsonLimited(r, maxBytes);
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}
async function postJsonRead(peer: string, path: string, body: any, maxBytes = 256_000, headers: Record<string, string> = {}): Promise<any | null> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 1500);
  try {
    const r = await fetch(peer + path, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
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
  for (const p of peers) void postJson(p, "/tx", tx, peerAuthHeaders("/tx", "POST"));
}
function broadcastBlock(b: Block): void {
  for (const p of peers) void postJson(p, "/block", b, peerAuthHeaders("/block", "POST"));
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
    if (parsed?.meta && typeof parsed.meta === "object") {
      const version = Number(parsed.meta.version);
      const count = Number(parsed.meta.count);
      const hash = chainSnapshotHash(parsed.chain);
      const versionOk = Number.isSafeInteger(version) && version <= SNAPSHOT_VERSION;
      const countOk = Number.isSafeInteger(count) && count === parsed.chain.length;
      const hashOk = typeof parsed.meta.chainHash === "string" && parsed.meta.chainHash === hash;
      const hasMac = typeof parsed.meta.mac === "string";
      const macOk = hasMac ? verifySnapshotMac("chain", hash, count, version, parsed.meta.mac) : !SNAPSHOT_KEY;
      if (!versionOk || !countOk || !hashOk) throw new Error("bad-snapshot-meta");
      if (!macOk) throw new Error(hasMac ? "bad-snapshot-mac" : "missing-snapshot-mac");
    } else if (SNAPSHOT_KEY) {
      throw new Error("missing-snapshot-meta");
    }
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
  let from = fromHeight;
  let chunks = 0;
  while (from <= tipHeight) {
    chunks++;
    if (chunks > MAX_SYNC_CHUNKS_PER_ATTEMPT) return null;
    const resp = await getJson(peer, `/chain?from=${from}&maxBytes=${CHAIN_PAGE_TARGET_BYTES}`, MAX_SYNC_RESPONSE_BYTES, peerAuthHeaders("/chain", "GET"));
    if (!resp || !Array.isArray(resp.blocks)) return null;
    const blocks = resp.blocks as Block[];
    if (blocks.length < 1 || blocks.length > CHAIN_CHUNK_BLOCKS) return null;
    for (let i = 0; i < blocks.length; i++) {
      const h = blocks[i]?.header?.height;
      if (h !== from + i || h > tipHeight) return null;
    }
    out.push(...blocks);
    let nextFrom = from + blocks.length;
    if (Number.isSafeInteger(resp.nextFrom) && resp.nextFrom >= nextFrom) nextFrom = resp.nextFrom;
    if (nextFrom <= from) return null;
    from = nextFrom;
  }
  return out;
}
async function maybeSyncFromPeers(): Promise<void> {
  const now = Date.now();
  if (syncInProgress || now < nextSyncAfter) return;
  syncInProgress = true;
  nextSyncAfter = now + SYNC_COOLDOWN_MS;
  try {
    let peersChanged = false;
    const dropPeer = (p: string): void => {
      peerFailures.delete(p);
      peerNodeIds.delete(p);
      if (peers.delete(p)) peersChanged = true;
    };
    for (const p of Array.from(peers)) {
      if (isSelfPeerOrigin(p)) {
        dropPeer(p);
        continue;
      }
      const tip = await getJson(p, "/tip", 64_000, peerAuthHeaders("/tip", "GET"));
      if (!tip || tip.chainId !== CHAIN_ID || tip.protocol !== PROTOCOL_VERSION || typeof tip.work !== "string" || !Number.isSafeInteger(tip.height) || !isNodeIdHex(tip.nodeId) || !isPubKeyHex(tip.nodePub) || sha256Hex(tip.nodePub) !== tip.nodeId) {
        markPeerFailure(p);
        continue;
      }
      if (tip.nodeId === nodeId || !registerPeerNodeId(p, tip.nodeId)) {
        dropPeer(p);
        continue;
      }
      if (typeof tip.origin === "string") {
        const o = canonicalOrigin(tip.origin);
        if (o && isSelfPeerOrigin(o)) {
          dropPeer(p);
          continue;
        }
      }
      if (Array.isArray(tip.peers)) {
        let seen = 0;
        for (const rp of tip.peers) {
          if (seen >= MAX_DISCOVERED_PEERS_PER_TIP) break;
          seen++;
          if (typeof rp !== "string") continue;
          const n = await normPeer(rp);
          if (!n || n === p || peers.has(n) || isSelfPeerOrigin(n)) continue;
          if (peers.size >= MAX_PEERS) break;
          peers.add(n);
          peersChanged = true;
        }
      }
      const tipHeight = tip.height as number;
      if (tipHeight < 0) {
        markPeerFailure(p);
        continue;
      }
      const localTip = chain.length - 1;
      const syncTip = Math.min(tipHeight, localTip + MAX_SYNC_AHEAD);
      let peerWork = 0n;
      try { peerWork = BigInt(tip.work); } catch { markPeerFailure(p); continue; }
      if (peerWork <= totalWork) {
        markPeerSuccess(p);
        continue;
      }
      const anchor = Math.max(0, chain.length - 1 - DAA_WINDOW);
      const tail = await fetchChainRange(p, anchor, syncTip);
      if (!tail) {
        markPeerFailure(p);
        continue;
      }
      let cand = chain.slice(0, anchor).concat(tail);
      let res = validateWholeChain(cand);
      if ((!res.ok || res.work <= totalWork) && anchor > 0) {
        const full = await fetchChainRange(p, 0, syncTip);
        if (!full) {
          markPeerFailure(p);
          continue;
        }
        cand = full;
        res = validateWholeChain(cand);
      }
      if (!res.ok || res.work <= totalWork) {
        markPeerFailure(p);
        continue;
      }
      chain = cand;
      state = res.st;
      totalWork = res.work;
      mempool.clear();
      saveChainSnapshot();
      console.log(`synced from ${p}: height=${chain.length - 1} work=${totalWork}`);
      markPeerSuccess(p);
    }
    if (peersChanged) savePeersSnapshot();
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
  try {
    return JSON.parse(s);
  } catch {
    throw new Error("bad-json");
  }
}
function routeNotFound(res: http.ServerResponse): void {
  sendJson(res, 404, { error: "not-found" });
}
function startServer(port: number, host: string, tls: { key: Buffer; cert: Buffer } | null): void {
  const handler = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    try {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      const method = req.method ?? "GET";
      if (!rateLimitOk(req, method, url.pathname)) {
        return sendJson(res, 429, { error: "rate-limit" });
      }
      const peerRoute = method === "GET" && (url.pathname === "/hello" || url.pathname === "/tip" || url.pathname === "/chain");
      if (peerRoute && !peerAuthOk(req, method, url.pathname)) return sendJson(res, 403, { error: "peer-auth" });
      if (method === "GET" && url.pathname === "/hello") {
        return sendJson(res, 200, {
          chainId: CHAIN_ID,
          protocol: PROTOCOL_VERSION,
          app: APP_VERSION,
          nodeId,
          nodePub,
          origin: nodeOrigin(),
          now: Date.now(),
        });
      }
      if (method === "GET" && url.pathname === "/tip") {
        const tip = chain[chain.length - 1];
        return sendJson(res, 200, {
          chainId: CHAIN_ID,
          protocol: PROTOCOL_VERSION,
          app: APP_VERSION,
          hash: tip.hash,
          height: tip.header.height,
          difficulty: expectedDifficultyForNext(chain),
          work: totalWork.toString(),
          nodeId,
          nodePub,
          origin: nodeOrigin(),
          peers: Array.from(peers),
        });
      }
      if (method === "GET" && url.pathname === "/chain") {
        const from = Number(url.searchParams.get("from") ?? "0");
        const start = Number.isFinite(from) ? Math.floor(from) : 0;
        const tipHeight = chain.length - 1;
        if (start < 0 || start >= chain.length) return sendJson(res, 200, { blocks: [], nextFrom: start, tipHeight });
        const mb = Number(url.searchParams.get("maxBytes") ?? String(CHAIN_PAGE_TARGET_BYTES));
        const maxBytes = Number.isFinite(mb) ? clamp(Math.floor(mb), 64_000, MAX_SYNC_RESPONSE_BYTES) : CHAIN_PAGE_TARGET_BYTES;
        const blocks: Block[] = [];
        let bytes = 2;
        for (let i = start; i < chain.length && blocks.length < CHAIN_CHUNK_BLOCKS; i++) {
          const b = chain[i];
          const bsz = Buffer.byteLength(JSON.stringify(b)) + (blocks.length > 0 ? 1 : 0);
          if (blocks.length > 0 && bytes + bsz > maxBytes) break;
          bytes += bsz;
          blocks.push(b);
        }
        return sendJson(res, 200, { blocks, nextFrom: start + blocks.length, tipHeight });
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
        const p = typeof body?.peer === "string" ? await normPeer(body.peer) : "";
        if (!p) return sendJson(res, 400, { error: "bad-peer" });
        if (isSelfPeerOrigin(p)) return sendJson(res, 400, { error: "self-peer" });
        const hello = await getJson(p, "/hello", 64_000, peerAuthHeaders("/hello", "GET"));
        if (!hello || hello.chainId !== CHAIN_ID || hello.protocol !== PROTOCOL_VERSION || !isNodeIdHex(hello.nodeId) || !isPubKeyHex(hello.nodePub) || sha256Hex(hello.nodePub) !== hello.nodeId) {
          return sendJson(res, 400, { error: "peer-incompatible" });
        }
        if (hello.nodeId === nodeId || !registerPeerNodeId(p, hello.nodeId)) return sendJson(res, 400, { error: "self-peer" });
        if (typeof hello.origin === "string") {
          const o = canonicalOrigin(hello.origin);
          if (o && isSelfPeerOrigin(o)) return sendJson(res, 400, { error: "self-peer" });
        }
        if (!peers.has(p) && peers.size >= MAX_PEERS) return sendJson(res, 429, { error: "too-many-peers" });
        if (!peers.has(p)) {
          peers.add(p);
          savePeersSnapshot();
        }
        return sendJson(res, 200, { ok: true, peers: Array.from(peers) });
      }
      if (method === "POST" && url.pathname === "/tx") {
        if (!OPEN_RELAY && !peerAuthOk(req, method, url.pathname)) return sendJson(res, 403, { error: "peer-auth" });
        const tx = (await readJson(req)) as Tx;
        if (!tx || typeof tx !== "object") return sendJson(res, 400, { error: "bad-json" });
        const id = txId(tx);
        if (seenTxs.has(id)) return sendJson(res, 200, { ok: true, dup: true });
        const err = validateNormalTx(tx, state);
        if (err) return sendJson(res, 400, { error: err });
        const fee = txFee(tx);
        if (fee === null) return sendJson(res, 400, { error: "bad-fee" });
        if (fee < MIN_RELAY_FEE) return sendJson(res, 400, { error: "relay-fee-too-low" });
        if (tx.from !== "COINBASE" && mempoolSenderCount(tx.from) >= MAX_MEMPOOL_PER_SENDER) {
          return sendJson(res, 429, { error: "mempool-sender-limit" });
        }
        if (hasMempoolNonceConflict(tx)) return sendJson(res, 409, { error: "mempool-nonce-conflict" });
        if (mempool.size >= MAX_MEMPOOL && !evictLowestFeeFor(tx)) return sendJson(res, 429, { error: "mempool-full" });
        mempool.set(id, tx);
        rememberSeen(seenTxs, seenTxQueue, id, SEEN_TX_CAP);
        broadcastTx(tx);
        return sendJson(res, 200, { ok: true, txid: id });
      }
      if (method === "POST" && url.pathname === "/block") {
        if (!OPEN_RELAY && !peerAuthOk(req, method, url.pathname)) return sendJson(res, 403, { error: "peer-auth" });
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
      const m = String(e?.message ?? e);
      if (m === "body-too-large") return sendJson(res, 413, { error: "body-too-large" });
      if (m === "bad-json") return sendJson(res, 400, { error: "bad-json" });
      return sendJson(res, 500, { error: "server-error", detail: String(e?.message ?? e) });
    }
  };
  const server = tls ? https.createServer({ key: tls.key, cert: tls.cert }, handler) : http.createServer(handler);
  server.listen(port, host, () => {
    console.log(`tinychain listening on ${listenScheme}://${host}:${port}`);
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
function usage(): void {
  console.log([
    "tinychain tiny002",
    "node mode:",
    "  --port=3001 --host=127.0.0.1|0.0.0.0 --public --mine=<pubhex> --peers=<origin,...>",
    "  --seeds=<origin,...> --seed-file=<path> (also env: TINYCHAIN_BOOTSTRAP_SEEDS / TINYCHAIN_SEED_FILE)",
    "  --tls-cert=<pem> --tls-key=<pem>  (or env: TINYCHAIN_TLS_CERT/TINYCHAIN_TLS_KEY)",
    "  --advertise=<origin,origin,...> (optional announced origins)",
    "  public bind requires: --advertise + TLS + TINYCHAIN_ADMIN_TOKEN + TINYCHAIN_SNAPSHOT_KEY",
    "  --difficulty is disabled (frozen network profile)",
    "security/env:",
    "  STRICT admin is ON by default; set TINYCHAIN_ADMIN_TOKEN for admin routes",
    "  peer auth (optional): set TINYCHAIN_PEER_TOKEN; peers send x-peer-token",
    "  relay policy: TINYCHAIN_OPEN_RELAY=1 (default) keeps /tx and /block permissionless",
    "  unsafe dev toggles require: TINYCHAIN_UNSAFE_DEV=I_UNDERSTAND",
    "  then optionally: TINYCHAIN_STRICT_ADMIN=0 TINYCHAIN_ALLOW_LOOPBACK_ADMIN=1 TINYCHAIN_ALLOW_PRIVATE_PEERS=1",
    "  loopback peer-auth bypass (dev only): TINYCHAIN_ALLOW_LOOPBACK_PEER_AUTH=1",
    "wallet/tx:",
    "  --keygen",
    "  --wallet-new=<file> [--wallet-pass=<pass>] (writes encrypted wallet v2)",
    "  --wallet-pub=<file>",
    "  --sign-tx='{\"to\":\"...\",\"amount\":\"10\",\"fee\":\"1\",\"nonce\":\"1\"}' [--secret=<hex>|--wallet=<file>] [--wallet-pass=<pass>]",
    "  --send-tx --tx='<signed-tx-json>' [--node=http://127.0.0.1:3001] [--peer-token=<token>]",
    "  --sign-tx=... --send-tx [--node=...]",
    "rpc cli:",
    "  --tip | --state=<pubhex> | --mempool | --list-peers [--peer-token=<token>]",
    "  --add-peer=<origin> [--admin-token=<token>] [--node=...]",
    "  --sync-now [--admin-token=<token>] [--node=...]",
    "  --menu [--node=...]",
    "test:",
    "  --selftest",
  ].join("\n"));
}
function deriveWalletKey(passphrase: string, salt: Buffer, n = KDF_N, r = KDF_R, p = KDF_P): Buffer {
  if (!passphrase) throw new Error("empty-wallet-passphrase");
  return scryptSync(passphrase, salt, KEYSIZE, { N: n, r, p, maxmem: 64 * 1024 * 1024 });
}
function parseWalletFile(filePath: string): any {
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw);
}
function encryptWallet(wallet: { pub: Hex; secret: Hex }, passphrase: string): any {
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = deriveWalletKey(passphrase, salt);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(wallet.secret, "utf8"), c.final()]);
  const tag = c.getAuthTag();
  return {
    version: 2,
    pub: wallet.pub,
    kdf: { alg: "scrypt", n: KDF_N, r: KDF_R, p: KDF_P, salt: salt.toString("hex") },
    enc: { alg: "aes-256-gcm", iv: iv.toString("hex"), ciphertext: ct.toString("hex"), tag: tag.toString("hex") },
  };
}
function decryptWalletSecret(parsed: any, passphrase: string): Hex {
  if (!isPubKeyHex(parsed?.pub) || parsed?.version !== 2) throw new Error("bad-wallet-file");
  if (parsed?.kdf?.alg !== "scrypt" || parsed?.enc?.alg !== "aes-256-gcm") throw new Error("bad-wallet-kdf");
  const saltHex = String(parsed?.kdf?.salt ?? "");
  const ivHex = String(parsed?.enc?.iv ?? "");
  const ctHex = String(parsed?.enc?.ciphertext ?? "");
  const tagHex = String(parsed?.enc?.tag ?? "");
  if (!isHex(saltHex) || !isHex(ivHex) || !isHex(ctHex) || !isHex(tagHex)) throw new Error("bad-wallet-enc");
  const n = Number(parsed?.kdf?.n);
  const r = Number(parsed?.kdf?.r);
  const p = Number(parsed?.kdf?.p);
  if (!Number.isSafeInteger(n) || !Number.isSafeInteger(r) || !Number.isSafeInteger(p)) throw new Error("bad-wallet-kdf");
  const key = deriveWalletKey(passphrase, Buffer.from(saltHex, "hex"), n, r, p);
  const d = createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"));
  d.setAuthTag(Buffer.from(tagHex, "hex"));
  let secret = "";
  try {
    secret = Buffer.concat([d.update(Buffer.from(ctHex, "hex")), d.final()]).toString("utf8");
  } catch {
    throw new Error("wallet-decrypt-failed");
  }
  if (!isHex(secret) || secret.length !== 128) throw new Error("wallet-secret-invalid");
  if (pubFromSecretHex(secret) !== parsed.pub) throw new Error("wallet-pub-mismatch");
  return secret;
}
async function promptHidden(prompt: string): Promise<string> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error("tty-required-for-hidden-prompt");
  return await new Promise((resolve, reject) => {
    let out = "";
    const stdin = process.stdin;
    const wasRaw = Boolean((stdin as any).isRaw);
    const cleanup = () => {
      stdin.off("data", onData);
      try { stdin.setRawMode?.(wasRaw); } catch {}
      stdin.pause();
    };
    const onData = (chunk: string | Buffer) => {
      const s = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : chunk;
      for (const ch of s) {
        if (ch === "\r" || ch === "\n") {
          cleanup();
          process.stdout.write("\n");
          resolve(out);
          return;
        }
        if (ch === "\u0003") {
          cleanup();
          reject(new Error("cancelled"));
          return;
        }
        if (ch === "\u0008" || ch === "\u007f") {
          out = out.slice(0, -1);
          continue;
        }
        if (ch >= " " && ch <= "~") out += ch;
      }
    };
    process.stdout.write(prompt);
    stdin.setEncoding("utf8");
    try { stdin.setRawMode?.(true); } catch {}
    stdin.resume();
    stdin.on("data", onData);
  });
}
async function walletPassphraseFromArgs(args: Record<string, string | boolean>, confirm = false): Promise<string> {
  if (args["wallet-pass"]) return String(args["wallet-pass"]);
  if (WALLET_PASS_ENV) return WALLET_PASS_ENV;
  const p1 = await promptHidden("wallet passphrase> ");
  if (!p1) throw new Error("empty-wallet-passphrase");
  if (!confirm) return p1;
  const p2 = await promptHidden("confirm passphrase> ");
  if (p1 !== p2) throw new Error("wallet-passphrase-mismatch");
  return p1;
}
function readWalletPub(filePath: string): { pub: Hex } {
  const parsed = parseWalletFile(filePath);
  if (!isPubKeyHex(parsed?.pub)) throw new Error("bad-wallet-file");
  if (parsed?.version === 2) return { pub: parsed.pub };
  if (typeof parsed?.secret === "string" && isHex(parsed.secret) && parsed.secret.length === 128) {
    if (pubFromSecretHex(parsed.secret) !== parsed.pub) throw new Error("wallet-pub-mismatch");
    return { pub: parsed.pub };
  }
  throw new Error("bad-wallet-file");
}
async function readWalletSecret(filePath: string, args: Record<string, string | boolean>): Promise<Hex> {
  const parsed = parseWalletFile(filePath);
  if (parsed?.version === 2) return decryptWalletSecret(parsed, await walletPassphraseFromArgs(args, false));
  if (!isPubKeyHex(parsed?.pub) || typeof parsed?.secret !== "string" || !isHex(parsed.secret) || parsed.secret.length !== 128) {
    throw new Error("bad-wallet-file");
  }
  if (pubFromSecretHex(parsed.secret) !== parsed.pub) throw new Error("wallet-pub-mismatch");
  return parsed.secret;
}
async function writeWallet(filePath: string, wallet: { pub: Hex; secret: Hex }, args: Record<string, string | boolean>): Promise<void> {
  const passphrase = await walletPassphraseFromArgs(args, true);
  const enc = encryptWallet(wallet, passphrase);
  fs.writeFileSync(filePath, JSON.stringify(enc, null, 2), "utf8");
  try { fs.chmodSync(filePath, 0o600); } catch {}
}
async function secretFromArgs(args: Record<string, string | boolean>): Promise<string> {
  if (args["secret"]) return String(args["secret"]);
  if (args["wallet"]) return readWalletSecret(String(args["wallet"]), args);
  throw new Error("missing signing key (use --secret or --wallet)");
}
function adminHeadersFromArgs(args: Record<string, string | boolean>): Record<string, string> {
  const h: Record<string, string> = {};
  if (args["admin-token"]) h["x-admin-token"] = String(args["admin-token"]);
  return h;
}
function peerHeadersFromArgs(args: Record<string, string | boolean>, path = "", method = "GET"): Record<string, string> {
  if (args["peer-token"]) return peerAuthHeaders(path, method, String(args["peer-token"]));
  return peerAuthHeaders(path, method);
}
async function cliGet(node: string, path: string, args: Record<string, string | boolean>, maxBytes = 512_000): Promise<any> {
  const out = await getJson(node, path, maxBytes, peerHeadersFromArgs(args, new URL(path, "http://x").pathname, "GET"));
  if (!out) throw new Error(`request-failed ${path}`);
  return out;
}
async function cliPost(node: string, path: string, body: any, args: Record<string, string | boolean>, maxBytes = 512_000): Promise<any> {
  const out = await postJsonRead(node, path, body, maxBytes, { ...peerHeadersFromArgs(args, path, "POST"), ...adminHeadersFromArgs(args) });
  if (!out) throw new Error(`request-failed ${path}`);
  if (!out.ok) throw new Error(`request-rejected ${path} status=${out.status} body=${JSON.stringify(out.body)}`);
  return out;
}
async function runMenu(nodeDefault: string, args: Record<string, string | boolean>): Promise<void> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  let node = nodeDefault;
  try {
    while (true) {
      console.log("\n[1] tip [2] state [3] peers [4] mempool [5] add-peer [6] sync [7] sign [8] sign+send [9] set-node [0] quit");
      const c = (await rl.question("choice> ")).trim();
      if (c === "0" || c.toLowerCase() === "q" || c.toLowerCase() === "quit") break;
      try {
        if (c === "1") {
          console.log(JSON.stringify(await cliGet(node, "/tip", args), null, 2));
          continue;
        }
        if (c === "2") {
          const acct = (await rl.question("acct pubhex> ")).trim();
          console.log(JSON.stringify(await cliGet(node, `/state?acct=${acct}`, args), null, 2));
          continue;
        }
        if (c === "3") {
          console.log(JSON.stringify(await cliGet(node, "/peers", args), null, 2));
          continue;
        }
        if (c === "4") {
          console.log(JSON.stringify(await cliGet(node, "/mempool", args), null, 2));
          continue;
        }
        if (c === "5") {
          const peer = (await rl.question("peer origin> ")).trim();
          console.log(JSON.stringify(await cliPost(node, "/peers", { peer }, args), null, 2));
          continue;
        }
        if (c === "6") {
          console.log(JSON.stringify(await cliPost(node, "/sync", {}, args), null, 2));
          continue;
        }
        if (c === "7" || c === "8") {
          rl.pause();
          let secret = "";
          try {
            secret = await promptHidden("secret hex> ");
          } finally {
            rl.resume();
          }
          const to = (await rl.question("to pubhex> ")).trim();
          const amount = (await rl.question("amount> ")).trim();
          const fee = (await rl.question("fee [0]> ")).trim() || "0";
          const nonce = (await rl.question("nonce> ")).trim();
          const tx = signTx(secret, to, amount, fee, nonce);
          const out: any = { txid: txId(tx), tx };
          if (c === "8") out.send = await cliPost(node, "/tx", tx, args);
          console.log(JSON.stringify(out, null, 2));
          continue;
        }
        if (c === "9") {
          const n = (await rl.question("node origin> ")).trim();
          if (n) node = n;
          continue;
        }
        console.log("unknown choice");
      } catch (e: any) {
        console.error(`menu-error: ${String(e?.message ?? e)}`);
      }
    }
  } finally {
    rl.close();
  }
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
function makeRetargetVector(diff: number, spanMs: number): Block[] {
  const out: Block[] = [makeGenesis()];
  out[0].header.difficulty = clamp(diff, MIN_DIFFICULTY, MAX_DIFFICULTY);
  out[0].header.timestamp = GENESIS_TIMESTAMP;
  const n = Math.max(2, DAA_WINDOW);
  for (let i = 1; i < n; i++) {
    const ts = GENESIS_TIMESTAMP + Math.floor((spanMs * i) / (n - 1));
    out.push({
      header: {
        prev: ZERO32,
        height: i,
        timestamp: ts,
        difficulty: clamp(diff, MIN_DIFFICULTY, MAX_DIFFICULTY),
        nonce: 0,
        txRoot: ZERO32,
      },
      miner: ZERO32,
      txs: [],
      hash: ZERO32,
    });
  }
  return out;
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
  const expectedSpan = TARGET_BLOCK_MS * (Math.max(2, DAA_WINDOW) - 1);
  const base = 20;
  const fast = expectedDifficultyForNext(makeRetargetVector(base, Math.floor(expectedSpan / 32)));
  if (fast !== clamp(base + DAA_MAX_STEP, MIN_DIFFICULTY, MAX_DIFFICULTY)) throw new Error("selftest-retarget-fast");
  const slow = expectedDifficultyForNext(makeRetargetVector(base, expectedSpan * 32));
  if (slow !== clamp(base - DAA_MAX_STEP, MIN_DIFFICULTY, MAX_DIFFICULTY)) throw new Error("selftest-retarget-slow");
  const flat = expectedDifficultyForNext(makeRetargetVector(base, expectedSpan));
  if (flat !== base) throw new Error("selftest-retarget-flat");
  const floor = expectedDifficultyForNext(makeRetargetVector(MIN_DIFFICULTY, expectedSpan * 32));
  if (floor !== MIN_DIFFICULTY) throw new Error("selftest-retarget-floor");
  const ceil = expectedDifficultyForNext(makeRetargetVector(MAX_DIFFICULTY, Math.floor(expectedSpan / 32)));
  if (ceil !== MAX_DIFFICULTY) throw new Error("selftest-retarget-ceil");
  console.log(JSON.stringify({ ok: true, vectors: { txid: txId(pay), block1: b1.hash, block2: b2.hash } }, null, 2));
}
async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const node = args["node"] ? String(args["node"]) : `http://127.0.0.1:${DEFAULT_PORT}`;
  if (args["help"] || args["h"] || args["?"]) {
    usage();
    return;
  }
  if (args["selftest"]) {
    runSelfTest();
    return;
  }
  if (args["wallet-new"]) {
    const kp = genKeypair();
    const filePath = String(args["wallet-new"]);
    await writeWallet(filePath, kp, args);
    console.log(JSON.stringify({ ok: true, file: filePath, pub: kp.pub }, null, 2));
    return;
  }
  if (args["wallet-pub"]) {
    const w = readWalletPub(String(args["wallet-pub"]));
    console.log(JSON.stringify({ pub: w.pub }, null, 2));
    return;
  }
  if (args["keygen"]) {
    const kp = genKeypair();
    console.log(JSON.stringify(kp, null, 2));
    return;
  }
  if (args["tip"]) {
    console.log(JSON.stringify(await cliGet(node, "/tip", args), null, 2));
    return;
  }
  if (args["state"]) {
    const acct = String(args["state"]);
    console.log(JSON.stringify(await cliGet(node, `/state?acct=${acct}`, args), null, 2));
    return;
  }
  if (args["mempool"]) {
    console.log(JSON.stringify(await cliGet(node, "/mempool", args), null, 2));
    return;
  }
  if (args["list-peers"]) {
    console.log(JSON.stringify(await cliGet(node, "/peers", args), null, 2));
    return;
  }
  if (args["add-peer"]) {
    const peer = String(args["add-peer"]);
    console.log(JSON.stringify(await cliPost(node, "/peers", { peer }, args), null, 2));
    return;
  }
  if (args["sync-now"]) {
    console.log(JSON.stringify(await cliPost(node, "/sync", {}, args), null, 2));
    return;
  }
  if (args["sign-tx"]) {
    const secret = await secretFromArgs(args);
    const req = JSON.parse(String(args["sign-tx"]));
    const tx = signTx(
      secret,
      String(req?.to ?? ""),
      String(req?.amount ?? ""),
      String(req?.fee ?? "0"),
      String(req?.nonce ?? ""),
    );
    const out: any = { txid: txId(tx), tx };
    if (args["send-tx"]) {
      out.send = await cliPost(node, "/tx", tx, args);
      if (!out.send) throw new Error("send-failed");
    }
    console.log(JSON.stringify(out, null, 2));
    return;
  }
  if (args["send-tx"]) {
    const txRaw = args["tx"] ? String(args["tx"]) : "";
    if (!txRaw) throw new Error("missing --tx for --send-tx");
    const sent = await cliPost(node, "/tx", JSON.parse(txRaw), args);
    if (!sent) throw new Error("send-failed");
    console.log(JSON.stringify(sent, null, 2));
    return;
  }
  if (args["menu"]) {
    await runMenu(node, args);
    return;
  }
  if (args["difficulty"]) throw new Error("--difficulty is disabled on frozen mainnet profile");
  if ((!STRICT_ADMIN || ALLOW_LOOPBACK_ADMIN || ALLOW_PRIVATE_PEERS || ALLOW_LOOPBACK_PEER_AUTH || !OPEN_RELAY) && !UNSAFE_DEV_MODE) {
    throw new Error("unsafe toggles require TINYCHAIN_UNSAFE_DEV=I_UNDERSTAND");
  }
  if (STRICT_ADMIN && !ADMIN_TOKEN) throw new Error("strict admin mode requires TINYCHAIN_ADMIN_TOKEN");
  const port = args["port"] ? Number(args["port"]) : DEFAULT_PORT;
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("bad --port");
  const host = parseListenHost(args);
  assertListenHost(host);
  const tlsCertPath = args["tls-cert"] ? String(args["tls-cert"]) : TLS_CERT_ENV;
  const tlsKeyPath = args["tls-key"] ? String(args["tls-key"]) : TLS_KEY_ENV;
  const tlsEnabled = Boolean(tlsCertPath || tlsKeyPath);
  if (tlsEnabled && (!tlsCertPath || !tlsKeyPath)) throw new Error("both TLS cert and key are required");
  const publicBind = !isLoopbackBindHost(host);
  if (publicBind) {
    if (UNSAFE_DEV_MODE) throw new Error("public bind forbids TINYCHAIN_UNSAFE_DEV");
    if (!args["advertise"]) throw new Error("public bind requires --advertise");
    if (!tlsEnabled) throw new Error("public bind requires TLS cert/key");
    if (!STRICT_ADMIN || !ADMIN_TOKEN) throw new Error("public bind requires strict admin token");
    if (!SNAPSHOT_KEY) throw new Error("public bind requires TINYCHAIN_SNAPSHOT_KEY");
  }
  let tls: { key: Buffer; cert: Buffer } | null = null;
  if (tlsEnabled) {
    tls = { cert: fs.readFileSync(tlsCertPath), key: fs.readFileSync(tlsKeyPath) };
  }
  listenScheme = tlsEnabled ? "https" : "http";
  listenHost = host;
  listenPort = port;
  loadOrCreateNodeId();
  refreshSelfOrigins(args["advertise"] ? String(args["advertise"]) : "");
  loadChainSnapshot();
  await loadPeersSnapshot();
  const seedFile = args["seed-file"] ? String(args["seed-file"]) : SEED_FILE_ENV;
  const candidates: string[] = [];
  if (BOOTSTRAP_SEEDS_ENV) candidates.push(...parseOriginList(BOOTSTRAP_SEEDS_ENV));
  if (args["seeds"]) candidates.push(...parseOriginList(String(args["seeds"])));
  if (seedFile) candidates.push(...readSeedFile(seedFile));
  if (args["peers"]) candidates.push(...parseOriginList(String(args["peers"])));
  if (candidates.length > 0) {
    const changed = await addPeerCandidates(candidates);
    if (changed) savePeersSnapshot();
  }
  startServer(port, host, tls);
  void maybeSyncFromPeers();
  const syncTimer = setInterval(() => { void maybeSyncFromPeers(); }, SYNC_INTERVAL_MS);
  syncTimer.unref?.();
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
