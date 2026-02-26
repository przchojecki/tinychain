# tinychain

`tinychain` is a compact blockchain engineering project focused on single-file, auditable node implementations. The core idea is to keep consensus-critical behavior small enough that one engineer can read and reason about the entire system quickly, without hiding risk in large framework layers.

The roadmap is intentionally line-budgeted. `tiny001.ts` is the strict sub-1000 LOC baseline, and `tiny002.ts` is the hardened sub-2000 LOC evolution designed to be serious public-testnet ready while remaining compact and understandable.

## Current Track

- Active core: `tiny002.ts`
- Core LOC: `1996`
- Runtime: Node.js `>=24`
- Consensus style: single-file PoW chain with strict validation, account model, HTTP gossip/sync, signed peer auth for chain sync
- Baseline core: `tiny001.ts`
- Core LOC: `996`
- Runtime: Node.js `>=24`
- Consensus style: minimal single-file PoW chain profile

## Blockchain Architecture

`tiny002` uses Nakamoto-style Proof-of-Work consensus on a linear chain. Each block commits `prev`, `height`, `timestamp`, `difficulty`, `nonce`, `txRoot`, and `miner`, and validity requires SHA-256 PoW under bounded difficulty (`14..40`). Target cadence is 10 seconds with a bounded DAA (window `60`, max step `2`) plus timestamp safety (`MTP=11`, future skew cap), and chain selection is strictly greatest cumulative work (sum of per-block work weight). Issuance is deterministic via subsidy halvings every `210000` blocks, with miner payout equal to `subsidy(height) + fees`.

Execution is an account/nonce model with canonical integer amounts and Ed25519 transaction signatures. A block must start with a coinbase transaction constrained to exact reward semantics, while normal transactions are validated/applied sequentially against state (`balances`, `nonces`) with strict overflow and replay controls; mempool policy includes sender caps, minimum relay fee, and nonce-based RBF with mandatory fee bump. Networking is intentionally minimal HTTP gossip/sync: `/tx` and `/block` relay by default, peer routes are token-gated, `/chain` is additionally signed with timestamp+nonce and replay protection, and snapshot files support keyed integrity MACs for safer persistence.

## Status (February 26, 2026)

`tiny002` has completed hardening items 1-6 and is launch-ready from an implementation perspective (with item 7 intentionally deferred).

Recent hardening added:

1. TLS-first peer origin policy (default `https` peers only)
2. Stronger economics profile (raised PoW floor + subsidy halving schedule)
3. Node peer-signing secret encryption at rest (`node.json`)
4. Replay protection for signed peer auth (`x-peer-nonce` + bounded replay cache)
5. Safer outbound networking defaults (`TINYCHAIN_HTTP_TIMEOUT_MS`, default 5000ms)
6. Proper nonce-based RBF in mempool with minimum fee bump policy

## Repository Layout

- `tiny002.ts`: active implementation (<2000 LOC target)
- `tiny001.ts`: constrained baseline (<1000 LOC target)
- `tests/integration.mjs`: multi-node integration/adversarial checks
- `README.md`: this document

## Quick Start

Install:

```bash
npm ci
```

Verify:

```bash
npm run check
npm run selftest
npm run itest
```

Version run map:

- `tiny002.ts` (default/current):

```bash
npm run node -- --port=3001
npm run check
npm run selftest
npm run keygen
```

- `tiny001.ts` (legacy baseline):

```bash
npm run node:legacy -- --port=3001
node --check tiny001.ts
node tiny001.ts --selftest
node tiny001.ts --keygen
```

Generate a keypair (tiny002 default):

```bash
npm run keygen
```

## Local Two-Node Dev Smoke Run

Private/local peers are blocked by default. For localhost dev only, use explicit unsafe-dev toggles.

Terminal A:

```bash
TINYCHAIN_UNSAFE_DEV=I_UNDERSTAND \
TINYCHAIN_ALLOW_PRIVATE_PEERS=1 \
TINYCHAIN_ADMIN_TOKEN=dev-admin \
TINYCHAIN_PEER_TOKEN=dev-peer \
TINYCHAIN_SNAPSHOT_KEY=dev-snapshot \
npm run node -- --port=3001 --mine=<PUB_A>
```

Terminal B:

```bash
TINYCHAIN_UNSAFE_DEV=I_UNDERSTAND \
TINYCHAIN_ALLOW_PRIVATE_PEERS=1 \
TINYCHAIN_ADMIN_TOKEN=dev-admin \
TINYCHAIN_PEER_TOKEN=dev-peer \
TINYCHAIN_SNAPSHOT_KEY=dev-snapshot \
npm run node -- --port=3002 --peers=http://127.0.0.1:3001
```

Check tip:

```bash
curl -sS http://127.0.0.1:3001/tip -H 'x-peer-token: dev-peer'
```

## Public Bind Guardrails (Enforced)

If binding non-loopback (`--public` or non-local `--host`), startup requires:

- `--advertise=<origin,...>`
- TLS cert + key (`--tls-cert`, `--tls-key`, or env)
- `TINYCHAIN_ADMIN_TOKEN` (strict admin)
- `TINYCHAIN_PEER_TOKEN`
- `TINYCHAIN_SNAPSHOT_KEY`
- no `TINYCHAIN_UNSAFE_DEV`

Example:

```bash
TINYCHAIN_ADMIN_TOKEN='<strong-admin-token>' \
TINYCHAIN_PEER_TOKEN='<strong-peer-token>' \
TINYCHAIN_SNAPSHOT_KEY='<strong-snapshot-key>' \
TINYCHAIN_TLS_CERT=/etc/tinychain/tls.crt \
TINYCHAIN_TLS_KEY=/etc/tinychain/tls.key \
npm run node -- \
  --public \
  --port=3001 \
  --advertise=https://203.0.113.10:3001 \
  --seeds=https://198.51.100.11:3001,https://198.51.100.12:3001
```

## CLI Highlights (`tiny002.ts`)

- Node/startup: `--port`, `--host`, `--public`, `--mine`, `--advertise`
- Peer bootstrap: `--peers`, `--seeds`, `--seed-file`
- RPC client ops: `--tip`, `--state`, `--mempool`, `--list-peers`, `--add-peer`, `--sync-now`
- Wallet: `--wallet-new`, `--wallet-pub`, `--wallet`, `--wallet-pass`
- TX: `--sign-tx`, `--send-tx`, `--tx`, `--secret`
- UX/tools: `--menu`, `--selftest`, `--keygen`

Auth flags:

- `--admin-token=<token>` for admin routes
- `--peer-token=<token>` for peer-authenticated routes

## HTTP API

Read:

- `GET /hello`
- `GET /tip`
- `GET /chain?from=<height>&maxBytes=<n>`
- `GET /state?acct=<pubhex>`
- `GET /mempool`
- `GET /peers`

Write:

- `POST /tx`
- `POST /block`
- `POST /peers` (admin)
- `POST /sync` (admin)

Auth model:

- `GET /hello`, `GET /tip`, `GET /chain` are peer routes.
- Peer routes require `x-peer-token` whenever `TINYCHAIN_PEER_TOKEN` is configured (and public bind enforces it).
- `GET /chain` additionally requires signed headers: `x-peer-node`, `x-peer-pub`, `x-peer-ts`, `x-peer-nonce`, `x-peer-sig`.
- Admin routes require `x-admin-token`.
- `/tx` and `/block` are permissionless by default (`TINYCHAIN_OPEN_RELAY=1`).

## Consensus Snapshot (tiny002)

- Chain ID: `tinychain-main-001`
- Block target: `10s`
- DAA window: `60`, max adjustment step: `2`
- Difficulty bounds: `[14..40]`, initial `18`
- MTP window: `11`
- Max future skew: `2 minutes`
- Block subsidy: `50`, halving interval `210000` blocks
- Max non-coinbase tx per block: `200`
- Chain sync pagination: `CHAIN_CHUNK_BLOCKS=256`, byte-capped pages
- Chain selection: greatest accumulated work

Mempool policy:

- Max mempool: `5000`
- Max sender entries: `64`
- Min relay fee: `1`
- RBF: same-sender same-nonce replacement requires fee bump `>= max(+10%, +1)`

## Security Model Summary

Implemented:

- Canonical tx/header validation and bounded integer economics
- Bounded DAA with strict full-chain revalidation on sync
- Peer admission hardening and private/link-local peer blocking by default
- TLS-first peer origin policy
- Peer token auth + signed `/chain` requests + replay protection
- Snapshot integrity metadata + optional keyed MAC verification
- Node identity persistence with encrypted secret-at-rest support
- Wallet encryption (AES-256-GCM + scrypt) and hidden passphrase prompt
- Rate limits, peer failure eviction, and bounded in-memory state structures

Intentional minimalism:

- HTTP-based gossip (not a custom encrypted P2P transport)
- No finality gadget beyond PoW work selection
- Compact codebase prioritized over feature breadth

## Key Environment Variables

- `TINYCHAIN_ADMIN_TOKEN`: admin auth token (required in strict mode)
- `TINYCHAIN_PEER_TOKEN`: peer auth token (required for public bind)
- `TINYCHAIN_SNAPSHOT_KEY`: snapshot MAC key (required for public bind)
- `TINYCHAIN_NODE_SECRET_KEY`: node secret-at-rest encryption key (falls back to snapshot key)
- `TINYCHAIN_REQUIRE_PEER_TLS`: TLS-first peer origins (`1` default)
- `TINYCHAIN_HTTP_TIMEOUT_MS`: outbound RPC timeout (`5000` default)
- `TINYCHAIN_OPEN_RELAY`: permissionless `/tx` + `/block` when `1` (default)
- `TINYCHAIN_UNSAFE_DEV=I_UNDERSTAND`: unlock unsafe dev toggles

## License

No license file is present yet. Add one before public release.
