# Sapphire — repository catalog

All references live under `references/`. Sizes are shallow clones (`--depth=1`); deepen as needed when studying history.

## Architecture references (study first)

### `near-mpc/` — NEAR's chain-signatures node ★ primary reference
**Repo:** https://github.com/near/mpc
**Why:** Closest existing system to what Sapphire wants to be. Public MPC signing network, contract-driven request/response, off-chain p2p signing.
**Highlights:**
- `crates/contract/` — the on-chain `sign(payload, path, key_version)` contract. Read first.
- `crates/near-mpc-sdk/` — caller SDK; how user contracts invoke signing.
- `crates/near-mpc-signature-verifier/` — verifying responses.
- `crates/tee-context/` — TEE attestation; signers run inside enclaves. Relevant to Phase 3 prover trust.
- `crates/foreign-chain-inspector/` — how NEAR validates that a sign request matches a real foreign-chain tx (anti-abuse).
- `crates/contract-history/` — version migration patterns.
- `docs/`, `deployment/`, `localnet/` — operational reference.
- `report_NIB-262.pdf` — security audit (NIB-262).

### `cait-sith/` — threshold ECDSA library
**Repo:** https://github.com/cronokirby/cait-sith
**Why:** Used by NEAR for transparent-chain signing. Low-latency presignature-based threshold ECDSA. Also supports Schnorr.
**Use:** Direct reference for Phase 1 (transparent ZEC signing). Possibly drop-in.

### `frost/` — Zcash Foundation FROST library ★ primary signing primitive
**Repo:** https://github.com/ZcashFoundation/frost
**Why:** Production FROST implementation. Supports RedPallas (Orchard), RedJubjub (Sapling), Ed25519, secp256k1, P-256, Ristretto255. Audited (NCC Group).
**Highlights:**
- `frost-redpallas/` — Orchard spend-auth threshold signing. **The center of Sapphire.**
- `frost-rerandomized/` — randomizable variants needed for Zcash spend-auth.
- `frost-core/` — protocol logic shared across ciphersuites.
- `book/` — protocol documentation (FROST book).

### `frost-zcash-demo/` — end-to-end RedPallas signing demo
**Repo:** https://github.com/ZcashFoundation/frost-zcash-demo
**Why:** Working CLI demo of RedPallas threshold signing producing valid Zcash spend-auths. Shows what tx assembly + signing flow looks like in practice.
**Use:** Start here for a hands-on prototype. Strip down to a library for Sapphire's signing service.

## Zcash core (signing target + tx assembly)

### `librustzcash/` (symlinked from parent dir)
**Repo:** https://github.com/zcash/librustzcash
**Why:** Workspace of Zcash Rust crates — `zcash_client_backend`, `zcash_primitives`, `zcash_proofs`, `zcash_keys`, etc. Tx assembly happens here.
**Use:** Used by the prover service to build the spend & generate Halo 2 proofs.

### `orchard/` (symlinked from parent dir)
**Repo:** https://github.com/zcash/orchard
**Why:** Orchard pool implementation — circuits, note structure, keys, value commitments. The thing Sapphire is signing for.
**Use:** Read `src/builder.rs`, `src/bundle.rs`, `src/keys.rs`. Spend authorization (`ask`/`isk`) is what FROST-RedPallas threshold-signs.

### `qedit-orchard/`
**Repo:** https://github.com/QED-it/orchard
**Why:** Qedit's fork with ZSA work. Useful to track issuer-key MPC patterns and diff against upstream `zcash/orchard`.

### `sapling-crypto/`
**Repo:** https://github.com/zcash/sapling-crypto
**Why:** Sapling pool primitives. Relevant if Sapphire supports Sapling spends (FROST-RedJubjub path).

### `halo2/`
**Repo:** https://github.com/zcash/halo2
**Why:** The proving system used by Orchard. Phase 3 (collaborative SNARK proving) targets this.
**Use:** Read `halo2_proofs/` to understand the IPA-based PCS that makes MPC proving non-trivial.

### `zcash/` — zcashd
**Repo:** https://github.com/zcash/zcash
**Why:** Reference C++ Zcash full node. Useful for tx broadcast, RPC reference, edge cases.

### `zebra/` — Rust Zcash node
**Repo:** https://github.com/ZcashFoundation/zebra
**Why:** Pure-Rust Zcash node. Likely Sapphire's preferred runtime dependency for syncing/broadcasting.

## Coordination layer candidates

### `cometbft/`
**Repo:** https://github.com/cometbft/cometbft
**Why:** BFT consensus engine. Mature, validators-are-signers maps naturally to MPC-node-is-validator.
**Use:** Substrate for Sapphire's coordination chain.

### `cosmos-sdk/`
**Repo:** https://github.com/cosmos/cosmos-sdk
**Why:** Application framework on top of CometBFT. Provides staking, slashing, governance modules out of the box.
**Use:** Skeleton for the Sapphire app — define custom modules for `signing-requests`, `mpc-committee`, etc.

## Adjacent MPC networks (design comparison)

### `lit-node/`
**Repo:** https://github.com/LIT-Protocol/node
**Why:** Lit Protocol is another decentralized MPC signing network. Different ciphersuites (BLS-based), different threat model, but architecturally similar.
**Use:** Compare API surface, key derivation, request/response patterns. Cross-check design choices.

## Research / Phase 3

### `collaborative-snark/`
**Repo:** https://github.com/alex-ozdemir/multiprover-snark
**Why:** Reference PoC for collaborative zkSNARKs (Groth16/Marlin/Plonk).
**Use:** Starting point for Phase 3 collaborative Halo 2 proving. **PoC only — not secure, not production.** Adapting to Halo 2's IPA-PCS is the research problem.

## Parent-directory cross-reference

Other Zcash work already cloned in `/Users/jules/ZcashMe/` — mostly unrelated to Sapphire but worth knowing:

| Path | Relevance to Sapphire |
|------|----------------------|
| `librustzcash/`, `orchard/` | **Core — symlinked into references/** |
| `zingolib/`, `zingo_cli/` | Reference wallet impl; useful for end-user UX patterns later |
| `cake_wallet/`, `edge-wallet/`, `unstoppable-wallet/`, `vizor-wallet/` | Third-party wallets; potential integration targets |
| `zcash-ts-wallet-sdk/` | TypeScript wallet SDK; client-side request signing |
| `cipherscan/` | Privacy tooling; unclear direct fit |
| `seer-sync/` | Sync infrastructure; unrelated |
| `taps/` | Unclear — investigate |
| `ZNS/`, `zns-*/`, `zcashname/` | Zcash naming service work; unrelated to Sapphire |
| `directory/`, `runbook/`, `ultrazound-money/` | Project-side docs/tools; unrelated |
| `ZVS/` | Unclear — investigate |

## Repos to consider adding later

- **`zips/`** (https://github.com/zcash/zips) — Zcash improvement proposals. Useful when designing custom address types or extensions.
- **`zcash-test-vectors/`** — for verifying signing correctness.
- **Penumbra** (https://github.com/penumbra-zone/penumbra) — fully-shielded Cosmos chain. Useful reference for shielded-app design on CometBFT.
- **Anoma** — shielded multi-asset chain; intent-centric, MPC-relevant patterns.
- **Threshold Network / tBTC** (https://github.com/keep-network) — production threshold-BTC signing; battle-tested ops patterns.
- **DKLS19 / DKLS23 implementations** — alternative to FROST for threshold ECDSA.
- **Powers of Tau ceremony coordinator code** — for any ceremony Sapphire eventually runs.
