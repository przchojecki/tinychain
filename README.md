# tinychain

`tinychain` is a small-chain engineering project: we build intentionally tiny, auditable blockchains where consensus-critical logic stays compact enough for one person to read in a sitting. The project favors pragmatic minimalism over feature sprawl so that node behavior, economics, and networking can be reasoned about directly from source.

The roadmap is line-budgeted by design. `tiny001.ts` is the strict sub-1000 LOC baseline (minimal but hardened enough to run), while `tiny002.ts` expands the same architecture under a sub-2000 LOC ceiling to add stronger public-network safety: better peer admission, authenticated peer traffic, optional TLS, encrypted wallets, and richer operator CLI/menu flows.

## Current Track

- Active core: `tiny002.ts`
- Core LOC: `1764`
- Runtime: Node.js `>=24`
- Consensus style: single-file PoW chain with strict validation, simple account model, and HTTP-based gossip/sync

## Status (February 26, 2026)

`tiny002` is now a strong release candidate for a serious public **testnet** launch.

Already implemented:

- Strict peer auth boundary (no implicit loopback bypass unless explicit unsafe-dev flag)
- Snapshot integrity metadata + keyed snapshot MAC verification (`TINYCHAIN_SNAPSHOT_KEY`)
- Public-bind safety guardrails (TLS + advertise + auth secrets required)
- Encrypted wallet keystore (AES-256-GCM + scrypt) with hidden passphrase prompt
- Peer/node identity hardening (`nodeId`, self-peer and duplicate-node rejection)
- CI matrix + deterministic selftest + adversarial multi-node integration test

## Repository Layout

- `tiny002.ts`: active implementation (<2000 LOC target)
- `tiny001.ts`: previous constrained implementation (<1000 LOC target)
- `tests/integration.mjs`: multi-node integration/adversarial checks
- `.github/workflows/ci.yml`: CI (`check`, `selftest`, `itest`)
- `README.md`: this document

## Quick Start

### 1) Install deps

```bash
npm ci
```

### 2) Verify build + tests

```bash
npm run check
npm run selftest
npm run itest
```

### 3) Generate keys

```bash
npm run keygen
```

## Local Two-Node Dev Smoke Run

Local private peers are blocked by default. For localhost testing only, run with explicit unsafe-dev toggles.

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

Query with peer token:

```bash
curl -sS http://127.0.0.1:3001/tip -H 'x-peer-token: dev-peer'
```

## Public Launch Guardrails (Enforced)

If binding non-loopback (`--public` or `--host` not localhost/127.0.0.1/::1), startup now requires:

- `--advertise=<origin,...>`
- TLS cert + key (`--tls-cert`, `--tls-key` or env variants)
- `TINYCHAIN_ADMIN_TOKEN`
- `TINYCHAIN_PEER_TOKEN`
- `TINYCHAIN_SNAPSHOT_KEY`
- No `TINYCHAIN_UNSAFE_DEV`

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

## Bootstrap / Seed Strategy

Startup peer candidates are merged from:

1. persisted peer snapshot (`.tinychain/peers.json`)
2. `TINYCHAIN_BOOTSTRAP_SEEDS`
3. `--seeds=<origin,...>`
4. `TINYCHAIN_SEED_FILE`
5. `--seed-file=<path>`
6. `--peers=<origin,...>`

Operational recommendation:

- Publish 3-5 stable public seed nodes.
- Version and publish a canonical seed file.
- Rotate seeds via rolling updates, not all at once.

## CLI Highlights (`tiny002.ts`)

- Node/startup: `--port`, `--host`, `--public`, `--mine`, `--advertise`
- Peer bootstrap: `--peers`, `--seeds`, `--seed-file`
- RPC client ops: `--tip`, `--state`, `--mempool`, `--list-peers`, `--add-peer`, `--sync-now`
- Wallet: `--wallet-new`, `--wallet-pub`, `--wallet`, `--wallet-pass`
- TX: `--sign-tx`, `--send-tx`, `--tx`, `--secret`
- UX: `--menu`, `--selftest`, `--keygen`

Useful CLI auth flags:

- `--admin-token=<token>` for admin routes
- `--peer-token=<token>` for peer-authenticated reads/writes

## HTTP API

Read:

- `GET /hello`
- `GET /tip`
- `GET /chain?from=<height>&limit=<n>`
- `GET /state?acct=<pubhex>`
- `GET /mempool`
- `GET /peers`

Write:

- `POST /tx`
- `POST /block`
- `POST /peers` (admin)
- `POST /sync` (admin)

Auth model:

- Peer routes require `x-peer-token` when `TINYCHAIN_PEER_TOKEN` is set.
- Admin routes require `x-admin-token`.

## Consensus Snapshot

- Chain ID: `tinychain-main-001`
- Block target: `10s`
- Retarget interval: `20`
- Difficulty bounds: `[8..40]`, initial `18`
- MTP window: `11`
- Max future skew: `2 minutes`
- Max non-coinbase tx per block: `200`
- Chain selection: greatest accumulated work

## Security Model Summary

Implemented:

- Canonical tx/header validation and bounded numeric economics
- PoW difficulty schedule with bounded retarget adjustments
- Rate limits + bounded rate state
- Peer admission hardening + peer cap + peer failure eviction
- Peer auth token and admin token controls
- Snapshot atomic writes + metadata + optional keyed MAC verification
- Encrypted wallet storage (v2) and hidden passphrase prompt

Still intentionally minimal:

- HTTP-based gossip instead of full encrypted p2p protocol stack
- No economic finality gadgets beyond work-based longest-chain rule
- Toy-scale PoW economics (appropriate for testnet / experimental network)

## Release Checklist (tiny002)

- [x] `npm run check`
- [x] `npm run selftest`
- [x] `npm run itest`
- [x] CI matrix on Node 24/25 with lockfile (`npm ci`)
- [ ] Add LICENSE before broad public distribution

## License

No license file is present yet. Add one before public release.
