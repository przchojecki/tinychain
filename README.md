# tinychain

`tinychain` is a minimal blockchain node designed to keep consensus-critical code tiny.

Current implementation:

- Core file: `tiny001.ts`
- Core LOC: `996`
- Language/runtime: TypeScript syntax running on modern Node.js
- Scope: single-file node + HTTP API + miner + minimal wallet CLI

This repository is intentionally optimized for clarity and small size, not feature breadth.

## Status

As of **February 26, 2026**, the chain is a strong minimal prototype and can run as a small public test network.
It is **not yet ready for an adversarial “serious mainnet” launch** without additional hardening.

## Goals

- Keep consensus logic understandable and auditable.
- Keep implementation below ~1000 LOC for the core node.
- Support CPU mining and simple peer-to-peer syncing.
- Provide CLI operations for humans and agents.

## Repository Layout

- `tiny001.ts`: current minimal chain implementation (active).
- `tiny001.pretrim.ts`: earlier expanded/pre-trim variant.
- `tinychain.ts`: earlier implementation variant.
- `README.md`: this document.

## Quick Start

## 1) Prerequisites

- Node.js `>= 24` (for direct `.ts` execution in this setup)
- npm

## 2) Install dependency

```bash
npm install
```

## 3) Run deterministic self-test

```bash
npm run selftest
```

Expected: JSON output with `"ok": true` and deterministic vector hashes.

## 4) Generate a keypair

```bash
npm run keygen
```

Returns:

- `pub`: 32-byte public key hex
- `secret`: 64-byte secret key hex (Ed25519 secretKey, 128 hex chars)

## 5) Start a node

```bash
npm run node -- --port=3001
```

Start mining on the node:

```bash
npm run node -- --port=3001 --mine=<MINER_PUB_HEX>
```

## 6) Join peers at startup

```bash
npm run node -- --port=3002 --peers=http://127.0.0.1:3001
```

## CLI Commands

Supported CLI flags in `tiny001.ts`:

- `--keygen`
- `--selftest`
- `--port=<n>`
- `--mine=<pubhex>`
- `--peers=<origin1,origin2,...>`
- `--sign-tx='<json>' --secret=<secretHex>`
- `--sign-tx='<json>' --secret=<secretHex> --send-tx --node=<origin>`
- `--send-tx --tx='<signedTxJson>' --node=<origin>`

Notes:

- `--difficulty` is intentionally disabled (consensus profile is frozen).
- `--node` defaults to `http://127.0.0.1:3001` for send operations.

### Transaction Signing Example

```bash
npm run node -- \
  --secret=<SENDER_SECRET_HEX> \
  --sign-tx='{"to":"<RECIPIENT_PUB_HEX>","amount":"10","fee":"1","nonce":"1"}'
```

Sign and broadcast in one step:

```bash
npm run node -- \
  --secret=<SENDER_SECRET_HEX> \
  --sign-tx='{"to":"<RECIPIENT_PUB_HEX>","amount":"10","fee":"1","nonce":"1"}' \
  --send-tx \
  --node=http://127.0.0.1:3001
```

## HTTP API

Base URL: `http://<host>:<port>`

Read endpoints:

- `GET /tip`
- `GET /chain?from=<height>&limit=<n>`
- `GET /state?acct=<pubhex>`
- `GET /mempool`
- `GET /peers`

Write endpoints:

- `POST /tx` (broadcast signed transaction)
- `POST /block` (broadcast mined block)
- `POST /peers` (admin-only)
- `POST /sync` (admin-only)

Current POST rate limits (per IP, 10s window):

- `/tx`: 120
- `/block`: 40
- `/peers`: 8
- `/sync`: 4

## Consensus Rules (Current)

Network identity:

- `CHAIN_ID = tinychain-main-001`

Genesis:

- `height = 0`
- `prev = 00..00 (32 bytes)`
- `timestamp = 1700000000000`
- `difficulty = 3`
- `txs = []`

PoW:

- Hash function: SHA-256 over canonical JSON array fields
- Rule: block hash must start with `difficulty` leading hex `0`
- Difficulty bounds: `[1..12]`

Difficulty adjustment:

- Target block time: `10s`
- Retarget interval: `20` blocks
- Adjusts using bounded interval timing; clamped to min/max difficulty

Time validity:

- Block timestamp must be `> medianTimePast(last 11 blocks)`
- Block timestamp must be monotonic vs parent
- Block timestamp must be `<= now + 2 minutes`

Transaction rules:

- Ed25519 signatures
- Canonical unsigned decimal string amounts/fees/nonces
- Strict nonce progression per account (`expected nonce = state nonce + 1`)
- Balance + overflow/underflow protections via bounded bigint arithmetic

Block rules:

- `txs[0]` must be coinbase
- Coinbase reward must equal `BLOCK_REWARD + totalFees`
- Max non-coinbase txs per block: `200`
- Header shape/range checks enforced

Chain selection:

- Choose candidate with greater accumulated work
- Full candidate chain is re-validated before adoption

## Networking + Sync Behavior

- Peer list in-memory, max peers: `128`
- Sync lock and cooldown prevent overlap/thrashing
- Sync range bounded by:
  - max forward height window (`MAX_SYNC_AHEAD`)
  - max chunk count per attempt (`MAX_SYNC_CHUNKS_PER_ATTEMPT`)
- Snapshot persistence to `.tinychain/chain.json`

## Security Hardening Included

Implemented in current core:

- Canonical header shape/range checks in append + full-chain validation
- Body size limit (`1MB`) for request parsing
- Sync response byte limit (`2MB`) and streamed response reading
- Peer URL normalization and peer count cap
- Admin-gated `/peers` and `/sync`
- POST endpoint rate limiting
- Seen caches for txs/blocks with capped size
- Deterministic `--selftest` path for consensus regression checks

## Known Gaps Before “Serious Public Mainnet”

These are the main blockers found in the latest audit:

1. PoW security remains toy-level (leading-zero SHA-256; low max difficulty).
2. Admin model can be unsafe behind reverse proxies if loopback trust is not isolated.
3. Peer host filtering is literal-host based and does not resolve DNS targets.
4. GET endpoints are currently not rate-limited.
5. Rate-limit state map has no eviction/cleanup policy.
6. Peer protocol is intentionally minimal (no handshake/version negotiation/ban scoring/discovery persistence).

Conclusion: good minimal public testnet candidate; not hardened enough for adversarial-value mainnet yet.

## Suggested Next Hardening Steps

Priority order:

1. Replace toy PoW with stronger economic security model, or significantly strengthen work target model.
2. Enforce strict token-only admin mode for non-local deployments.
3. Add GET endpoint limits + periodic eviction for rate-limit state.
4. Add DNS resolution checks for peer admission (block private/link-local targets after resolution).
5. Add peer scoring/ban heuristics and durable peer store.
6. Add CI with deterministic consensus vectors and negative test corpus.

## Two-Node Smoke Run

Terminal A:

```bash
npm run node -- --port=3001 --mine=<PUB_A>
```

Terminal B:

```bash
npm run node -- --port=3002 --peers=http://127.0.0.1:3001
```

Add peer from A to B (optional):

```bash
curl -sS -X POST http://127.0.0.1:3001/peers \
  -H 'content-type: application/json' \
  -d '{"peer":"http://127.0.0.1:3002"}'
```

Query tip:

```bash
curl -sS http://127.0.0.1:3001/tip
```

## Release/Publish to GitHub (`przchojecki/tinychain`)

Repository prep (run once):

```bash
git init
git branch -M main
git remote add origin git@github.com:przchojecki/tinychain.git
```

Commit:

```bash
git add README.md tiny001.ts tiny001.pretrim.ts tinychain.ts package.json .gitignore
git commit -m "docs: finalize tinychain spec and launch notes"
```

Push:

```bash
git push -u origin main
```

If HTTPS is preferred:

```bash
git remote set-url origin https://github.com/przchojecki/tinychain.git
```

## License

No license file is present yet. Add one before public release.
