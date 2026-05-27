# Sapphire

A decentralized MPC signing network for Zcash. Threshold Schnorr signing
via FROST over RedPallas (Orchard spend-auth) and RedJubjub (Sapling),
with both **DKG and signing** running as transactions on a BFT
coordination chain.

No HTTP coordinator. No single party holds the spending key. Every step —
key generation, request submission, FROST round-1 commitments, round-2
rerandomized shares — flows through a deterministic state machine driven
by an authenticated Noise-encrypted mesh between the validators.

## What it does

```
                       ┌──────────────────────────────────┐
   client                       Sapphire chain
   ────── DkgBegin ──────►   (CometBFT / in-mem sim)
                              │
                              │  validators react:
                              │    Tx::DkgRound1  (public r1 commitments)
                              │    Tx::DkgRound2  (sealed-to-recipient r2)
                              │    Tx::DkgFinalize (each posts derived PKP)
                              │
                              ▼  state machine cross-checks PKPs match,
                                 promotes ceremony → GroupConfig
                              │
   client ─ SubmitRequest{msg, α} ─►
                              │  validators react:
                              │    Tx::SubmitCommitment (round 1)
                              │    Tx::SubmitShare      (round 2, rerandomized)
                              │
                              ▼  frost_rerandomized::aggregate →
                                 64-byte RedPallas signature valid under
                                 rk = ak + α·G
                              │
   client ─ query ─►  Completed { signature }
                       (broadcast to Zcash L1 as spend-auth)
```

The chain only ever sees ciphertexts and protocol messages — never the
spending key. Zcash L1 only ever sees a vanilla shielded transaction; it
has no idea Sapphire produced the signature.

## Workspace

| Crate | Purpose |
|-------|---------|
| `sapphire-core` | Protocol types, FROST re-exports, ciphersuite abstraction, errors |
| `sapphire-keygen` | Trusted-dealer + in-process DKG keygen (for offline / test setups) |
| `sapphire-chain` | Deterministic state machine, tx types, in-memory simulator (`ChainSim`), DKG sealed-envelope layer |
| `sapphire-node` | A Sapphire node: holds a FROST key share, runs DKG + signing rounds, reacts to chain state by submitting txs |
| `sapphire-net` | Noise-XX-encrypted authenticated mesh between nodes; carries Tx<C> as opaque frames |
| `sapphire-zcash` | Zcash interop: drives signing for Orchard sighashes; optional `pczt` feature for `orchard::pczt::Bundle` injection |
| `sapphire-cli` | Demo CLI: `keygen`, `v1-demo` |
| `sapphire-tests` | End-to-end integration tests |

## Quick start

```bash
cargo build --workspace
cargo test  --workspace     # 10 tests, all green

# Full pipeline (5-of-8) end-to-end in-process: chain-driven DKG, then
# rerandomized RedPallas signing. Prints the block-by-block transcript and
# the final 64-byte signature, verified under rk = ak + α·G.
cargo run -p sapphire-cli -- v1-demo --threshold 5 --total 8 \
    --message "shielded zec escrow signing test"

# Offline keygen (trusted dealer or in-process DKG) → writes share-*.json
# for setups where you bootstrap key material outside the chain.
cargo run -p sapphire-cli -- keygen --threshold 2 --total 3 --out ./keys --dkg
```

## DKG over the chain

The hard part of "no single party holds the key" isn't signing — FROST gives
you that. It's the *setup*: round-2 of FROST DKG sends each participant a
secret share contribution that must reach exactly one recipient and nobody
else. If you broadcast those in plaintext, anyone listening reconstructs the
secret.

Sapphire's solution: ship round-2 packages through the chain (so every
validator sees the same auditable transcript), but **seal each one to the
recipient's X25519 public key** (XChaCha20-Poly1305 over `ChaChaBox`). The
chain stores ciphertexts and never decrypts them. Sender identity is
asserted by chain inclusion.

```
DkgBegin { params, validators: { id → X25519 pubkey } }     // bootstrap
DkgRound1   { from, package }                                // public
DkgRound2   { from, to, sealed }                             // recipient-only
DkgFinalize { from, pkp }                                    // cross-check
   └── state machine: all `total` PKPs match → promote to GroupConfig
```

After promotion, the existing rerandomized-FROST signing flow takes over.
Same key material, same code, no separate "trusted dealer" path needed.

## Rerandomized RedPallas

Orchard verifies the spend-auth signature against `rk` — the *rerandomized*
spend-auth key — in each spend description, not against the account's
underlying `ak`. `Tx::SubmitRequest` carries the per-spend `Randomizer<C>`
(Orchard's α); the chain's aggregation step calls
`frost_rerandomized::aggregate` with `RandomizedParams::from_randomizer(vk, α)`,
producing a signature that verifies under `rk = ak + α·G` — which is what
`orchard::pczt::Action::apply_signature` actually checks. The
`orchard_compat` integration test closes the loop against `reddsa`'s real
`VerificationKey<orchard::SpendAuth>::randomize(α).verify`.

## Tests

```
10 passing tests:

dkg_envelope               # sealed envelope round-trip + wrong-recipient rejection (2)
keygen                     # trusted-dealer + in-process DKG produce signable groups (2)
v1_chain                   # 2-of-3 full chain lifecycle + reject-bad-init/unknown-request (3)
orchard_compat             # Sapphire sig passes Orchard's actual rk-verify (1)
dkg_over_chain             # 5-of-8 chain-driven DKG → rerandomized signing (1)
mesh_converges             # 4 Noise-XX-meshed nodes converge on shared state (1)
```

## Why no consensus engine?

The state machine is **monotonic and commutative**: each tx only adds info,
order doesn't change correctness. So Sapphire doesn't need a BFT consensus
algorithm — just authenticated reliable delivery between known validators.
That's exactly what zebra-style P2P provides, and exactly what
`sapphire-net` implements: Noise XX over TCP, 32-byte X25519 static keys
on both sides, length-prefixed frames carrying serialized `Tx<C>`.

Accountability and slashing belong on a *separate* public chain (NEAR is
the planned anchor) where audit digests and operator bonds live. The
inter-validator coordination doesn't.

## What's still ahead

- Per-escrow demux via Zcash encrypted memo fields (validators read memos to bucket incoming notes by escrow ID)
- Authorization / policy layer: the witness that tells validators *whether* to sign for a given request
- Persistent key-share storage + key resharing
- NEAR accountability contract: validator registration, slash bond, periodic audit anchors
- Collaborative Halo 2 proving (research-grade)
