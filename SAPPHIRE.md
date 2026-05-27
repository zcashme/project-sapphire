# Sapphire

A decentralized MPC signing network for Zcash — a "Chain Signatures"-style service for native ZEC (transparent and shielded), inspired by NEAR's chain-signatures architecture and built on FROST-RedPallas / FROST-RedJubjub threshold Schnorr signing.

## One-line pitch

Multiple independent parties cooperatively produce a Zcash spend-authorization signature; no single party holds the full key, and the on-chain footprint is indistinguishable from a normal single-signer Zcash transaction.

## Why this is interesting

- **No equivalent exists publicly.** FROST-RedPallas is production-grade as a *library* (`zfnd/frost`), and a few institutional custody firms (Qedit, etc.) run private threshold-signing setups. There is no open, programmable, network-as-a-service equivalent of NEAR Chain Signatures for Zcash.
- **Zcash structural gaps make this non-trivial.** No on-chain smart contracts, two distinct shielded signature schemes (RedJubjub/Sapling, RedPallas/Orchard), and the hard problem of MPC-aware shielded proof generation.
- **Real demand surface.** Institutional custody, shielded treasury management, ZSA issuer key management, multi-party shielded payroll.

## High-level architecture

```
                ┌───────────────────────────────────────────────────┐
                │   Sapphire Coordination Chain (CometBFT-based)    │
                │                                                   │
   user ────────┼──► tx: sign(payload, derivation_path, auth_zkp)   │
                │              │                                    │
                │              ▼                                    │
                │       BFT consensus orders requests               │
                │              │                                    │
                │              ▼                                    │
                │  Validators = MPC signers (same node set)         │
                │     ├─ FROST-RedPallas off-chain p2p              │
                │     └─ Halo 2 proving (Phase 2: trusted prover)   │
                │              │                                    │
                │              ▼                                    │
                │  tx: respond(signature, proof) → state            │
                └──────────────────────┬────────────────────────────┘
                                       ▼
                          User pulls signed tx
                          Broadcasts to Zcash L1
```

### Layer responsibilities

| Layer | Mechanism | What it solves |
|-------|-----------|----------------|
| Request transport + sequencing + audit | CometBFT-based coordination chain; validators = MPC signers | NEAR-equivalent on-chain `sign(...)` surface, replaces missing Zcash smart contracts |
| Request authentication / privacy | ZKP attached to request — proves authorization without revealing user/path | Private-by-default signing; better than NEAR (which uses host-chain accounts) |
| Threshold signing | FROST-RedPallas (Orchard) or FROST-RedJubjub (Sapling) off-chain p2p between validators | Single Schnorr signature, on-chain footprint identical to normal tx |
| Shielded proof generation | Phase 2: trusted prover with viewing key. Phase 3: collaborative Halo 2 | The Halo 2 spend/output proof |
| Final settlement | Resulting tx broadcast to Zcash L1 | Verified by Zcash consensus like any other tx |

## Current status (V0 → V1)

**Shipped in this revision** (`/Users/jules/ZcashMe/sapphire/crates/`):
- Cargo workspace, **9 crates** (added `sapphire-chain`, `sapphire-validator`)
- FROST signing pipeline: trusted-dealer + DKG keygen, round-1 commit, round-2 sign-share, aggregate, verify
- **Ciphersuite-generic core** — Ed25519 (default) and **RedPallas** (Zcash Orchard) both pass full round trips
- **Two V0 transports** — `LocalTransport` (in-process) and `HttpTransport` (axum + reqwest)
- **V1 BFT coordination chain** — deterministic state machine, validators-are-signers, in-process simulator
- **ABCI adapter** — typed skeleton showing the CometBFT integration shape (no `tower-abci` dep yet)
- CLI: `keygen`, `demo-sign`, `serve`, `http-sign`, `v1-demo`
- **13 passing tests** across both ciphersuites, both keygen modes, both transports, and the V1 chain lifecycle

**What's not yet there (and the path to it):**

| Gap | Path |
|-----|------|
| Rerandomized RedPallas signatures (real Orchard spend-auth) | V1.1: integrate `frost-rerandomized` with the Orchard bundle's per-spend randomizer |
| Zcash transaction assembly | V1.1: use `zcash_client_backend` + `librustzcash` to build the spend tx around the threshold signature |
| Persistent key shares + rotation | V1.2: file-backed share storage with zeroize; key resharing via FROST refresh |
| Authentication of sign requests | V1.3: ZKP-of-authorization circuit, request envelope verification on-chain |
| **Real CometBFT deployment** | V1.4: replace `ChainSim` with a `tower-abci` adapter wrapping the same `apply_tx` |
| Cross-chain & non-Zcash signing | V2: leverage NEAR Chain Signatures-style derivation for foreign-chain control |
| MPC proof generation | V2: collaborative Halo 2 (research) |

## Phased build plan

### Phase 1 — Transparent ZEC MPC (weeks)

Treat transparent Zcash as Bitcoin from the MPC perspective.

- ECDSA-secp256k1 threshold signing via `cait-sith` (NEAR's library) or `multi-party-ecdsa`
- BIP32 derivation over the threshold pubkey → t-addrs
- Coordination layer: minimal viable BFT chain or even a centralized coordinator for V0
- **Useful but loses the shielded story** — the whole point of Zcash. Treat as a stepping-stone to validate the architecture.

### Phase 2 — Shielded with threshold spend-auth + trusted prover

The realistic production target. Roughly what Qedit-style institutional custody does today, but as a public network.

- **Threshold spend-auth:** FROST-RedPallas (`zfnd/frost`), DKG mode (not trusted dealer)
- **Trusted prover service:** holds the full viewing key (`fvk`) for the account, generates the Halo 2 proof
- **Coordination chain:** CometBFT-based; validators run both FROST signing and the prover service
- **Tx assembly:** `zcash_client_backend` / `librustzcash`
- **Address scheme:** Choose — single root viewing key with diversified addresses per user (simpler key tree, prover sees all spends) OR per-user FROST keypair (more setup, better privacy isolation)
- **Trust model (honest):** Spending requires threshold. Privacy ≈ trust in prover. Acceptable for institutional custody.

### Phase 3 — Shielded with MPC proof generation (research)

The holy grail: no single party sees the spend witness in cleartext.

Candidate approaches (all research-stage):
- **Collaborative SNARKs** (Ozdemir/Boneh line of work) over Halo 2. Halo 2 is harder than Groth16 here due to IPA-based PCS.
- **TEE-based proving** (SGX, Nitro) — not real MPC, but practical. Shifts trust to silicon vendor.
- **Split-witness proving** — partition the witness so each prover sees only part.
- **Threshold viewing keys** + MPC over circuit-friendly hashes (Poseidon) — partial mitigation.

This is publishable research, not an engineering sprint. Likely needs academic collaboration (Stanford, MIT, ZF research).

## Key design decisions to resolve

1. **Host coordination layer:** Custom CometBFT chain (more control, more ops) vs. piggyback on existing L1 (NEAR, Cosmos chain) for the request/response surface (less control, faster to ship)?
2. **Address scheme:** root-key-with-derivation (NEAR style) vs. per-user FROST keypair (more isolation, more DKG ceremonies)?
3. **Authentication ZKP:** what circuit? Pallas-friendly so it composes with downstream Halo 2 work?
4. **Gas / payment model:** Zcash has no smart-contract gas. Payment must happen on the coordination layer, in its native token, or via signed off-chain receipts.
5. **Committee governance:** Static initial committee with stake-weighted resharing? PoS validator-style with slashing for non-response or equivocation?
6. **Privacy posture of the coordination chain itself:** even if signing requests carry ZKPs, the request rate and timing leak metadata. Shielded coordination layer is an option (Penumbra-style)?

## Open research questions

- **Collaborative Halo 2 proving** — performance characterization, witness partitioning strategies.
- **MPC-friendly viewing-key delegation** — can we limit what the prover learns to the minimum required for a *specific* spend?
- **DKG ceremony for RedPallas at scale** — operational tooling is thin; NEAR's resharing experience is on ECDSA.
- **ZKP-of-authorization circuit** — design a Pallas-friendly circuit that lets users prove "I own account X under spending policy P" without revealing X or P.

## Non-goals (initially)

- Cross-chain abstraction (controlling non-Zcash addresses from Sapphire). NEAR does this; we're focused on native Zcash first.
- Replacing Zcash wallets. Sapphire is custody/signing infrastructure, not an end-user wallet.
- ZSA support in V1 (worth tracking, possibly natural extension in V2).

## Reference architecture sources

- `references/near-mpc/` — NEAR's chain-signatures node + contract (primary architectural reference)
- `references/cait-sith/` — threshold ECDSA library (low-latency, presignature-based)
- `references/frost/` — ZF's FROST library (RedPallas + RedJubjub ciphersuites)
- `references/frost-zcash-demo/` — end-to-end RedPallas threshold spending demo
- `references/halo2/` — Zcash's Halo 2 proving system (target for collaborative SNARK work)
- `references/zebra/` — Rust Zcash node (likely runtime dependency)
- `references/sapling-crypto/` — Sapling primitives
- `references/cometbft/` — candidate BFT substrate for coordination chain
- `references/cosmos-sdk/` — application framework for the coordination chain
- `references/lit-node/` — adjacent MPC signing network for design comparison

See `docs/repos.md` for a fuller catalog and `notes/` for study notes per repo.
