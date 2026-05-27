# Sapphire

A decentralized MPC signing network for Zcash — threshold Schnorr signing over
FROST, modeled on NEAR's chain-signatures architecture, adapted for Zcash's
Orchard (RedPallas) and Sapling (RedJubjub) shielded signature schemes.

See [`SAPPHIRE.md`](./SAPPHIRE.md) for design, [`docs/repos.md`](./docs/repos.md)
for the study corpus.

## What's built

**V0 → V1.1b:**
- ✅ Generic-over-ciphersuite library with full FROST round trip
- ✅ Trusted-dealer **and** DKG keygen
- ✅ In-process and HTTP signer transports
- ✅ Ed25519 (default) and **RedPallas** (Zcash Orchard) ciphersuites
- ✅ **V1 coordination chain**: deterministic state machine (validators-are-signers)
- ✅ **V1.1 rerandomized RedPallas on-chain**: `Tx::SubmitRequest` carries a per-request `Randomizer<C>` (Orchard's α); state machine aggregates via `frost_rerandomized::aggregate`; final signature verifies against `rk = ak + α·G` — the spend-auth key Orchard actually checks
- ✅ **V1.1b Sapphire ↔ Orchard interop** (`sapphire-zcash` crate): `drive_signing_session` runs the full chain lifecycle for a `(sighash, α)` pair; optional `pczt` feature exposes `sign_pczt_orchard_bundle` which walks an `orchard::pczt::Bundle`, signs each action, and injects via `Action::apply_signature`. Compatibility proven by `orchard_compat` test — a Sapphire signature passes Orchard's *actual* `redpallas::VerificationKey<SpendAuth>::randomize(α).verify(sighash, sig)` check.
- ✅ **ABCI adapter**: skeleton mapping the state machine onto CometBFT ABCI++
- ✅ CLI: `keygen`, `demo-sign`, `serve`, `http-sign`, `v1-demo` (V1 demo runs on RedPallas + rerandomization)
- ✅ 14 passing tests across both ciphersuites, both keygen modes, both transports, the full V1.1 chain lifecycle, and Orchard rk-verify compatibility

**Still ahead** (per [SAPPHIRE.md](./SAPPHIRE.md)):
- V1.1c: real end-to-end Orchard PCZT test (construct a bundle with notes + proof, sign via Sapphire, extract a broadcastable tx)
- V1.2: persistent key-share storage + key resharing
- V1.3: authentication ZKP layer for sign requests
- V1.4: production CometBFT deployment (drop-in: replace `ChainSim` with `tower-abci` adapter)
- V2: collaborative Halo 2 proving (research)

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
| `sapphire-zcash` | **V1.1b**: Zcash interop — drives the chain to sign Orchard sighashes, optional PCZT helper (`pczt` feature) for `orchard::pczt::Bundle` injection |
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

# V1.1: run the full BFT chain pipeline (rerandomized RedPallas) as an
# in-process demo. Prints the per-request α and the final signature, which
# verifies against the rerandomized verifying key rk = ak + α·G.
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

## V1.1 architecture

Validators *are* the FROST signers. Every step of a signing session — the
request (which includes the per-spend randomizer α), each round-1 commitment,
each round-2 share — is a transaction on the coordination chain. The chain's
deterministic state machine aggregates the final rerandomized signature once
enough shares are committed.

```
   client ──Tx::SubmitRequest { msg, α } ──▶ Sapphire chain (CometBFT/ABCI++)
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
                          read α from chain state, sign rerandomized
                          round-2 share, submit Tx::SubmitShare
                                       │
                                 block N+2 committed
                                       │
                          State machine sees threshold shares →
                          calls frost_rerandomized::aggregate(
                              .., &RandomizedParams::from_randomizer(vk, α)
                          ) → RequestStatus::Completed { signature }
                                       │
   client  ─── query: GetRequestStatus ─▶
                            signature verifies against rk = ak + α·G
                            (= the rk in an Orchard spend description)
```

**Why this works without smart contracts on Zcash L1:** Sapphire's
coordination chain is a *separate* chain. Its sole purpose is to sequence
sign requests and FROST round messages between validator-signers. Zcash L1
sees only the resulting transaction, which is indistinguishable from a normal
single-signer Zcash tx.

**Why rerandomization matters:** Orchard verifies the spend-auth signature
against `rk` (the rerandomized spend-auth key) *in each spend description*,
not against the account's underlying `ak`. The randomizer α is part of the
spend; producing a signature valid under `rk` is what makes the Sapphire
output usable as Orchard spend-auth.

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
14 passing tests:

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

V1.1 — BFT coordination chain (rerandomized RedPallas)  # 3
  v1_two_of_three_full_round_trip                 # full lifecycle: InitGroup → SubmitRequest{α}
                                                  #   → 3 commitments (threshold cut)
                                                  #   → 2 rerandomized shares
                                                  #   → frost_rerandomized::aggregate → Completed
                                                  #   → verify against rk = ak + α·G
  v1_init_group_rejects_mismatched_validators
  v1_unknown_request_rejected

V1.1b — Orchard interop                            # 1
  sapphire_signature_passes_orchard_rk_verify    # the loop-closer: Sapphire output
                                                  #   verifies via reddsa::VerificationKey<
                                                  #   orchard::SpendAuth>::randomize(α).verify
                                                  #   — the exact check Orchard runs in
                                                  #   pczt::Action::apply_signature
```

## Design

See [`SAPPHIRE.md`](./SAPPHIRE.md) for the phased plan, structural decisions,
and remaining open research (collaborative Halo 2 proving, rerandomized
RedPallas + tx assembly, etc.).
