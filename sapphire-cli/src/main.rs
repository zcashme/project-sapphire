//! Sapphire demo CLI.
//!
//! Subcommands:
//!  * `keygen` — DKG keygen, writes shares to disk.
//!  * `escrow-demo` — end-to-end in-process: chain-driven DKG, then the
//!    validators validate a proposed escrow release and threshold-sign it,
//!    plus the reject path where a tampered release gets no signature.
//!  * `oracle` — interactive single-party settlement builder + predicate check.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use frost_ed25519::Ed25519Sha512;
use rand::rngs::OsRng;

use sapphire_chain::{sim::ChainSim, state::RequestStatus, tx::Tx as ChainTx};
use sapphire_core::{protocol::uuid_lite::Uuid, protocol::KeyShareBundle, MpcParams};
use sapphire_keygen::generate_with_dkg;
use sapphire_node::{DkgParticipant, Node};

type Cs = Ed25519Sha512;

#[derive(Parser)]
#[command(name = "sapphire", about = "Sapphire MPC signing demo CLI")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a `threshold`-of-`total` group via DKG (no single party ever
    /// sees the full key).
    Keygen {
        #[arg(long)]
        threshold: u16,
        #[arg(long)]
        total: u16,
        #[arg(long)]
        out: PathBuf,
    },

    /// Escrow demo: the full validating-signer story in-process.
    ///
    /// DKG-generates a `threshold`-of-`total` group, then has the validators
    /// run the escrow predicate over a proposed release and threshold-sign it
    /// — and shows a tampered release being refused, with no signature.
    EscrowDemo {
        #[arg(long, default_value_t = 2)]
        threshold: u16,
        #[arg(long, default_value_t = 3)]
        total: u16,
    },

    /// Interactive oracle: assemble an escrow release/refund, run the
    /// validation predicate over it, and emit the settlement intent that a
    /// relayer would wrap in a two-action PCZT and submit to the 5-of-8.
    Oracle,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Cmd::Keygen {
            threshold,
            total,
            out,
        } => cmd_keygen(threshold, total, &out),
        Cmd::EscrowDemo { threshold, total } => cmd_escrow_demo(threshold, total),
        Cmd::Oracle => cmd_oracle(),
    }
}

fn cmd_escrow_demo(threshold: u16, total: u16) -> Result<()> {
    use frost_core::{Field, Group};
    use frost_rerandomized::{RandomizedParams, Randomizer};
    use reddsa::frost::redpallas::PallasBlake2b512 as DemoCs;
    use sapphire_escrow::{
        verifiers::HashPreimage, Address, EscrowTerms, PaymentLeg, ReleaseProposal,
        SettlementIntent, Zatoshis,
    };
    use sapphire_node::EscrowPolicy;
    use std::collections::BTreeMap;

    let mut rng = OsRng;
    let params = MpcParams::new(threshold, total)?;
    println!("== Sapphire escrow demo: validate → threshold-sign a release ==");
    println!("   ciphersuite: RedPallas (Zcash Orchard spend-auth), rerandomized\n");

    // ---- DKG over the chain: no party ever holds the full key ----
    println!("[setup] chain-driven DKG ({}-of-{}): validators run FROST DKG", threshold, total);
    println!("        rounds 1→2→3 as chain txs; the chain promotes the agreed");
    println!("        PKP into a GroupConfig.\n");

    let mut participants: Vec<DkgParticipant<DemoCs>> = (1..=total)
        .map(|i| {
            let id: frost_core::Identifier<DemoCs> =
                i.try_into().expect("identifier in range");
            DkgParticipant::<DemoCs>::new(id, &mut rng)
        })
        .collect();

    let mut chain: ChainSim<DemoCs> = ChainSim::new();
    let dkg_validators: BTreeMap<_, _> = participants
        .iter()
        .map(|p| (p.identifier, p.enc_public))
        .collect();
    chain.submit(ChainTx::DkgBegin {
        params,
        validators: dkg_validators,
    });
    let results = chain.commit_block();
    print_block(&chain, &results, "DkgBegin");

    let mut step = 0;
    while chain.state.group.is_none() {
        step += 1;
        if step > 20 {
            return Err(anyhow!("DKG failed to converge in 20 blocks"));
        }
        for p in participants.iter_mut() {
            for tx in p.react(&chain.state, &mut rng)
                .map_err(|e| anyhow!("dkg react: {e}"))?
            {
                chain.submit(tx);
            }
        }
        let results = chain.commit_block();
        let label = if chain.state.group.is_some() {
            "DkgRound* → promoted to GroupConfig"
        } else {
            "DkgRound*"
        };
        print_block(&chain, &results, label);
    }
    let pkp = chain.state.group.as_ref().unwrap().pkp.clone();

    // ---- the escrow ----
    let secret = b"parcel #4417 delivered".to_vec();
    let terms = EscrowTerms {
        escrow_id: [0x5a; 32],
        amount: Zatoshis(800_000_000),
        payee: Address("u_alice".into()),
        refund_to: Address("u_bob".into()),
        timeout_height: 1_000,
        condition: HashPreimage::digest(&secret).to_vec(),
    };

    // Each validator becomes a *validating* signer: its react() runs the escrow
    // predicate against terms it holds itself, and refuses to commit unless a
    // proposed release matches. The gate lives INSIDE the node, not in the demo.
    let mut nodes: Vec<Node<DemoCs>> = participants
        .into_iter()
        .map(|p| {
            p.into_node()
                .expect("DKG complete")
                .with_policy(EscrowPolicy::new(HashPreimage).with_escrow(terms.clone()))
        })
        .collect();

    println!("\n[escrow] Bob funded an 8 ZEC escrow, locked by a hash-preimage");
    println!("         condition. Every validator holds the terms; release pays");
    println!("         u_alice, timeout refunds u_bob.\n");

    let randomizer = {
        let scalar = <<<DemoCs as frost_core::Ciphersuite>::Group as Group>::Field as Field>::random(&mut rng);
        Randomizer::<DemoCs>::from_scalar(scalar)
    };

    // ---- happy path: a correct release the validators will sign ----
    println!("[release] oracle proposes paying u_alice, revealing the preimage.");
    let good_msg = serde_json::to_vec(&ReleaseProposal {
        escrow_id: terms.escrow_id,
        intent: SettlementIntent {
            payment: PaymentLeg {
                amount: Zatoshis(800_000_000),
                to: Address("u_alice".into()),
            },
            witness: secret.clone(),
        },
    })?;
    let good_id = Uuid::new(&mut rng);
    chain.submit(ChainTx::SubmitRequest {
        request_id: good_id,
        message: good_msg.clone(),
        randomizer,
    });
    chain.commit_block();
    for label in ["round-1 commitments", "round-2 rerandomized shares"] {
        println!("[validators] validate internally → react → {label}");
        for v in nodes.iter_mut() {
            for tx in v.react(&chain.state, &mut rng)? {
                chain.submit(tx);
            }
        }
        chain.commit_block();
    }
    match &chain.state.requests.get(&good_id).unwrap().status {
        RequestStatus::Completed {
            signature,
            participants,
        } => {
            RandomizedParams::<DemoCs>::from_randomizer(pkp.verifying_key(), randomizer)
                .randomized_verifying_key()
                .verify(&good_msg, signature)
                .map_err(|e| anyhow!("verification failed: {e}"))?;
            let sig_bytes = signature.serialize().map_err(|e| anyhow!("serializing: {e}"))?;
            println!("\n== RELEASE AUTHORIZED ==");
            println!("signers    : {} of {}", participants.len(), total);
            println!("authorizes : release 8 ZEC → u_alice (leg A)");
            println!("signature  : {}", hex::encode(&sig_bytes));
            println!("verified vs: rerandomized vk (rk = ak + α·G)");
        }
        other => return Err(anyhow!("expected Completed, got {:?}", other)),
    }

    // ---- reject path: the gate refuses internally, so no signature forms ----
    println!("\n[reject] oracle tampers — same money, same preimage, paid to u_attacker.");
    let bad_msg = serde_json::to_vec(&ReleaseProposal {
        escrow_id: terms.escrow_id,
        intent: SettlementIntent {
            payment: PaymentLeg {
                amount: Zatoshis(800_000_000),
                to: Address("u_attacker".into()),
            },
            witness: secret,
        },
    })?;
    let bad_id = Uuid::new(&mut rng);
    chain.submit(ChainTx::SubmitRequest {
        request_id: bad_id,
        message: bad_msg,
        randomizer,
    });
    chain.commit_block();
    for v in nodes.iter_mut() {
        for tx in v.react(&chain.state, &mut rng)? {
            chain.submit(tx);
        }
    }
    chain.commit_block();
    match &chain.state.requests.get(&bad_id).unwrap().status {
        RequestStatus::AwaitingCommitments { commitments } if commitments.is_empty() => {
            println!("  → 0 commitments. Every validator refused inside react.");
            println!("  → no threshold, no aggregation, no signature. The gate held.");
        }
        other => return Err(anyhow!("tampered release must not progress, got {:?}", other)),
    }
    Ok(())
}

fn print_block<C: frost_core::Ciphersuite>(
    chain: &ChainSim<C>,
    results: &[(ChainTx<C>, Result<(), sapphire_chain::state::ApplyError>)],
    label: &str,
) {
    println!("\n[block {}] {}", chain.block_height, label);
    for (i, (_, r)) in results.iter().enumerate() {
        let status = match r {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("REJECTED: {e}"),
        };
        println!("  tx#{}: {}", i, status);
    }
}

/// Read a line from stdin, showing `default` in brackets; empty input keeps it.
fn prompt(label: &str, default: &str) -> Result<String> {
    use std::io::{self, Write};
    if default.is_empty() {
        print!("  {label}: ");
    } else {
        print!("  {label} [{default}]: ");
    }
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let s = line.trim().to_string();
    Ok(if s.is_empty() {
        default.to_string()
    } else {
        s
    })
}

fn prompt_u64(label: &str, default: u64) -> Result<u64> {
    let s = prompt(label, &default.to_string())?;
    s.parse::<u64>().with_context(|| format!("'{s}' is not a number"))
}

/// Interactive oracle: assemble an escrow release/refund and run Sapphire's
/// validation predicate over it. This is the *oracle/relayer* role — the party
/// that proposes a settlement. The structured intent it emits here is exactly
/// what gets encoded into the two-action PCZT and handed to the 5-of-8 (who
/// re-validate it independently before signing).
fn cmd_oracle() -> Result<()> {
    use sapphire_escrow::{
        validate_refund, validate_settlement, verifiers::HashPreimage, Address, EscrowTerms,
        PaymentLeg, RefundIntent, SettlementIntent, Zatoshis,
    };

    println!("== Sapphire oracle: escrow settlement builder ==");
    println!("   Proposes a release/refund; Sapphire validators re-check it before signing.\n");

    println!("-- escrow terms (the binding reference funds were locked under) --");
    let amount = prompt_u64("escrowed amount (zatoshis)", 800_000_000)?;
    let payee = prompt("payee (release recipient)", "u_alice")?;
    let refund_to = prompt("refund recipient", "u_bob")?;
    let timeout_height = prompt_u64("timeout height", 1000)?;

    // Lock the escrow with a hash-preimage (HTLC-style) condition: the
    // `condition` is the SHA-256 digest of a secret. Revealing the secret
    // unlocks the release. This is application-agnostic — no ZNS involved.
    println!("\n-- release condition: hash-preimage (HTLC) --");
    let secret = prompt("lock secret (preimage the escrow commits to)", "open sesame")?;
    let digest = HashPreimage::digest(secret.as_bytes());
    println!("  → condition (sha256 digest): {}", hex::encode(digest));

    let terms = EscrowTerms {
        escrow_id: [7u8; 32],
        amount: Zatoshis(amount),
        payee: Address(payee.clone()),
        refund_to: Address(refund_to.clone()),
        timeout_height,
        condition: digest.to_vec(),
    };

    println!("\n-- which settlement is the oracle proposing? --");
    let action = prompt("action (release / refund)", "release")?;

    match action.as_str() {
        "release" => {
            println!("\n-- assemble release --");
            let to = prompt("pay to", &payee)?;
            let pay_amount = prompt_u64("pay amount (zatoshis)", amount)?;
            let revealed = prompt("revealed preimage (witness)", &secret)?;

            let intent = SettlementIntent {
                payment: PaymentLeg {
                    amount: Zatoshis(pay_amount),
                    to: Address(to),
                },
                witness: revealed.into_bytes(),
            };

            let result = validate_settlement(&terms, &intent, &HashPreimage);
            print_verdict(&terms, "release", &result)?;
            let payment_json = serde_json::to_value(&intent.payment)?;
            println!("\n  settlement intent (→ leg A of the PCZT):");
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "payment": payment_json,
                    "witness_hex": hex::encode(&intent.witness),
                }))?
            );
            if result.is_err() {
                std::process::exit(1);
            }
        }
        "refund" => {
            println!("\n-- assemble refund --");
            let to = prompt("refund to", &refund_to)?;
            let pay_amount = prompt_u64("refund amount (zatoshis)", amount)?;
            let current_height = prompt_u64("current block height", timeout_height)?;

            let intent = RefundIntent {
                payment: PaymentLeg {
                    amount: Zatoshis(pay_amount),
                    to: Address(to),
                },
            };

            let result = validate_refund(&terms, &intent, current_height);
            print_verdict(&terms, "refund", &result)?;
            println!("\n  refund intent:");
            println!("{}", serde_json::to_string_pretty(&intent.payment)?);
            if result.is_err() {
                std::process::exit(1);
            }
        }
        other => return Err(anyhow!("unknown action '{other}' (expected release/refund)")),
    }

    Ok(())
}

fn print_verdict(
    terms: &sapphire_escrow::EscrowTerms,
    kind: &str,
    result: &std::result::Result<(), sapphire_escrow::EscrowError>,
) -> Result<()> {
    println!("\n-- escrow terms --");
    println!("{}", serde_json::to_string_pretty(terms)?);
    match result {
        Ok(()) => println!(
            "\n  VERDICT: ✔ ACCEPT — a validator would sign this {kind}."
        ),
        Err(e) => println!(
            "\n  VERDICT: ✘ REJECT — no signature. reason: {e}"
        ),
    }
    Ok(())
}

fn cmd_keygen(threshold: u16, total: u16, out: &Path) -> Result<()> {
    let params = MpcParams::new(threshold, total)?;
    let mut rng = OsRng;
    println!("running DKG ({}-of-{})...", threshold, total);
    let (key_packages, pkp) = generate_with_dkg::<Cs, _>(params, &mut rng)?;

    std::fs::create_dir_all(out)
        .with_context(|| format!("creating {}", out.display()))?;

    // Write each participant's KeyShareBundle to share-{i}.json.
    for (i, (_id, kp)) in key_packages.iter().enumerate() {
        let bundle = KeyShareBundle {
            key_package: kp.clone(),
            public_key_package: pkp.clone(),
        };
        let path = out.join(format!("share-{}.json", i + 1));
        let f = std::fs::File::create(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        serde_json::to_writer_pretty(f, &bundle)?;
        println!("wrote {}", path.display());
    }

    // Also dump just the public-key package for callers/verifiers.
    let pkp_path = out.join("group-pubkey.json");
    let f = std::fs::File::create(&pkp_path)?;
    serde_json::to_writer_pretty(f, &pkp)?;
    println!("wrote {}", pkp_path.display());

    println!("\nkeygen ok: {}-of-{} group", threshold, total);
    Ok(())
}
