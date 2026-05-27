# Sapphire

A decentralized MPC signing network for Zcash — threshold Schnorr signing over
FROST, modeled on NEAR's chain-signatures architecture, adapted for Zcash's
Orchard (RedPallas) and Sapling (RedJubjub) shielded signature schemes.

See [`SAPPHIRE.md`](./SAPPHIRE.md) for design, [`docs/repos.md`](./docs/repos.md)
for the study corpus.

## What's built

**V0 → V1 (this revision):**
- ✅ Generic-over-ciphersuite library with full FROST round trip
- ✅ Trusted-dealer **and** DKG keygen
- ✅ In-process and HTTP signer transports
- ✅ Ed25519 (default) and **RedPallas** (Zcash Orchard) ciphersuites
- ✅ **V1 coordination chain**: deterministic state machine (validators-are-signers)
- ✅ **ABCI adapter**: skeleton mapping the state machine onto CometBFT ABCI++
- ✅ CLI: `keygen`, `demo-sign`, `serve`, `http-sign`, `v1-demo`
- ✅ 13 passing tests across both ciphersuites, both keygen modes, both transports, and the full V1 chain lifecycle

**Still ahead** (per [SAPPHIRE.md](./SAPPHIRE.md)):
- Rerandomized RedPallas + Zcash tx assembly via `librustzcash` (real Orchard spend-auth)
- Persistent key-share storage + key resharing
- Authentication ZKP layer for sign requests
- Production CometBFT deployment (drop-in: replace `ChainSim` with `tower-abci` adapter)
- Collaborative Halo 2 proving (research)

## Workspace layout

| Crate | Purpose |
|-------|---------|
| `sapphire-core` | Protocol types, FROST re-exports, ciphersuite abstraction, errors |
| `sapphire-keygen` | Trusted-dealer + DKG keygen ceremonies |
| `sapphire-signer` | Signer node: holds a key share, runs FROST rounds, exposes HTTP |
| `sapphire-coordinator` | V0 coordinator: orchestrates rounds, assembles final signature |
| `sapphire-client` | Caller transports: `LocalTransport` (in-process) + `HttpTransport` |
| `sapphire-chain` | **V1**: BFT state machine, tx types, in-process simulator, ABCI adapter |
| `sapphire-validator` | **V1**: validator-signer — watches chain state, submits FROST round txs |
| `sapphire-cli` | Demo CLI: `keygen`, `demo-sign`, `serve`, `http-sign`, `v1-demo` |
| `sapphire-tests` | End-to-end integration tests |

## Quick start

```bash
# Build & test everything
cargo build --workspace
cargo test --workspace      # 13 tests, all green

# V0: trusted-dealer keygen → in-process signing demo
cargo run -p sapphire-cli -- keygen --threshold 2 --total 3 --out ./keys
cargo run -p sapphire-cli -- demo-sign --message "hello" --keys ./keys

# V1: run the full BFT chain pipeline as an in-process demo
cargo run -p sapphire-cli -- v1-demo --threshold 2 --total 3 --message "hello v1"
```

### V0.1 HTTP demo: 3 signer servers + HTTP coordinator

```bash
cargo run -p sapphire-cli -- keygen --threshold 2 --total 3 --out ./keys
cargo run -p sapphire-cli -- serve --share ./keys/share-1.json --addr 127.0.0.1:8801 &
cargo run -p sapphire-cli -- serve --share ./keys/share-2.json --addr 127.0.0.1:8802 &
cargo run -p sapphire-cli -- serve --share ./keys/share-3.json --addr 127.0.0.1:8803 &
cargo run -p sapphire-cli -- http-sign \
    --message "hello over http" \
    --group-pubkey ./keys/group-pubkey.json \
    --signers http://127.0.0.1:8801,http://127.0.0.1:8802,http://127.0.0.1:8803 \
    --threshold 2
```

## V1 architecture

Validators *are* the FROST signers. Every step of a signing session — the
request, each round-1 commitment, each round-2 share — is a transaction on
the coordination chain. The chain's deterministic state machine aggregates
the final signature once enough shares are committed.

```
   client ──Tx::SubmitRequest──▶ Sapphire chain (CometBFT/ABCI++)
                                       │
                                 block N committed
                                       │
                          each Validator observes new request,
                          generates round-1 commitment,
                          submits Tx::SubmitCommitment
                                       │
                                 block N+1 committed
                                       │
                          State machine sees threshold commitments →
                          deterministically builds SigningPackage,
                          transitions to RequestStatus::Signing
                                       │
                          Selected validators see Signing phase,
                          generate round-2 share,
                          submit Tx::SubmitShare
                                       │
                                 block N+2 committed
                                       │
                          State machine sees threshold shares →
                          calls frost_core::aggregate() →
                          RequestStatus::Completed { signature }
                                       │
   client  ─── query: GetRequestStatus ─▶
                            (signature, broadcast to Zcash L1)
```

**Why this works without smart contracts on Zcash L1:** Sapphire's
coordination chain is a *separate* chain. Its sole purpose is to sequence
sign requests and FROST round messages between validator-signers. Zcash L1
sees only the resulting transaction, which is indistinguishable from a normal
single-signer Zcash tx.

## ABCI mapping

The V1 state machine plugs into CometBFT via `tower-abci` with no
re-architecture. The mapping is documented in
[`crates/sapphire-chain/src/abci.rs`](crates/sapphire-chain/src/abci.rs):

| ABCI++ method     | Maps to                                             |
|-------------------|-----------------------------------------------------|
| `Info`            | App hash from `AbciApp::commit`                     |
| `InitChain`       | `State::default()`; group seeded via first `InitGroup` tx |
| `CheckTx`         | `apply_tx(&state, &tx)` dry-run                     |
| `FinalizeBlock`   | For each tx: `state = apply_tx(&state, &tx)?`        |
| `Commit`          | Persist state, return app hash                       |
| `Query`           | `state.requests.get(request_id)`                    |

## Test matrix

```
13 passing tests:

unit                                              # 2
  trusted_dealer_produces_consistent_packages
  dkg_produces_signable_group

V0 / V0.1 / V0.2                                  # 8
  two_of_three_round_trip                         # Ed25519, in-process
  three_of_five_round_trip
  below_threshold_fails
  duplicate_participant_fails
  unknown_participant_fails
  http_two_of_three_round_trip                    # 3 axum servers + http client
  redpallas_two_of_three_round_trip               # Zcash Orchard ciphersuite
  dkg_three_of_five_then_sign                     # DKG keygen → sign pipeline

V1 — BFT coordination chain                       # 3
  v1_two_of_three_full_round_trip                 # full lifecycle: InitGroup → SubmitRequest
                                                  #   → 3 commitments (threshold cut)
                                                  #   → 2 shares → aggregate → Completed
                                                  #   → verify
  v1_init_group_rejects_mismatched_validators
  v1_unknown_request_rejected
```

## Design

See [`SAPPHIRE.md`](./SAPPHIRE.md) for the phased plan, structural decisions,
and remaining open research (collaborative Halo 2 proving, rerandomized
RedPallas + tx assembly, etc.).
