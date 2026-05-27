//! Sapphire demo CLI.
//!
//! Subcommands:
//!  * `keygen` — trusted-dealer keygen, writes shares to disk.
//!  * `demo-sign` — runs a full in-process FROST round trip from saved shares.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use frost_ed25519::Ed25519Sha512;
use rand::rngs::OsRng;

use sapphire_client::{HttpTransport, LocalTransport};
use sapphire_coordinator::{verify, Coordinator};
use sapphire_core::{protocol::KeyShareBundle, MpcParams};
use sapphire_chain::{sim::ChainSim, state::RequestStatus, tx::Tx as ChainTx};
use sapphire_core::protocol::uuid_lite::Uuid;
use sapphire_keygen::{generate_with_dkg, generate_with_trusted_dealer};
use sapphire_validator::Validator;
use sapphire_signer::{server as signer_server, Signer};

type Cs = Ed25519Sha512;

#[derive(Parser)]
#[command(name = "sapphire", about = "Sapphire MPC signing demo CLI")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a `threshold`-of-`total` group.
    Keygen {
        #[arg(long)]
        threshold: u16,
        #[arg(long)]
        total: u16,
        #[arg(long)]
        out: PathBuf,
        /// Use distributed key generation (no single party sees the full key).
        /// Defaults to trusted-dealer for backwards-compatible quick demos.
        #[arg(long, default_value_t = false)]
        dkg: bool,
    },

    /// Demo: load shares from disk, run an in-process FROST signing round.
    DemoSign {
        #[arg(long)]
        message: String,
        #[arg(long)]
        keys: PathBuf,
    },

    /// Run a Sapphire signer node, serving one key share over HTTP.
    Serve {
        /// Path to the signer's `share-N.json` file.
        #[arg(long)]
        share: PathBuf,
        /// Bind address.
        #[arg(long, default_value = "127.0.0.1:8801")]
        addr: SocketAddr,
    },

    /// V1 demo: run the full BFT-coordination-chain pipeline in-process.
    ///
    /// DKG-generates a `threshold`-of-`total` group, spins up that many
    /// validator-signers, drives the chain through InitGroup → SubmitRequest
    /// → commits → shares → completed, then prints the signature and the
    /// chain's block-by-block transcript.
    V1Demo {
        #[arg(long, default_value_t = 2)]
        threshold: u16,
        #[arg(long, default_value_t = 3)]
        total: u16,
        #[arg(long, default_value = "hello sapphire v1 chain")]
        message: String,
    },

    /// Coordinate a signing round against remote signer nodes over HTTP.
    HttpSign {
        /// Message to sign (UTF-8).
        #[arg(long)]
        message: String,
        /// Group public-key package JSON.
        #[arg(long)]
        group_pubkey: PathBuf,
        /// Comma-separated list of signer URLs (one per participant).
        ///
        /// Participant identifiers are inferred by querying each signer's `/info` endpoint.
        #[arg(long, value_delimiter = ',')]
        signers: Vec<String>,
        /// Threshold (`t` in `t-of-n`). Used only to construct the coordinator;
        /// must match the group's actual threshold.
        #[arg(long)]
        threshold: u16,
    },
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
            dkg,
        } => cmd_keygen(threshold, total, &out, dkg),
        Cmd::DemoSign { message, keys } => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(cmd_demo_sign(&message, &keys))
        }
        Cmd::Serve { share, addr } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(cmd_serve(&share, addr))
        }
        Cmd::HttpSign {
            message,
            group_pubkey,
            signers,
            threshold,
        } => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(cmd_http_sign(&message, &group_pubkey, &signers, threshold))
        }
        Cmd::V1Demo {
            threshold,
            total,
            message,
        } => cmd_v1_demo(threshold, total, &message),
    }
}

fn cmd_v1_demo(threshold: u16, total: u16, message: &str) -> Result<()> {
    use frost_core::{Field, Group};
    use frost_rerandomized::{RandomizedParams, Randomizer};
    use reddsa::frost::redpallas::PallasBlake2b512 as V1Cs;

    let mut rng = OsRng;
    let params = MpcParams::new(threshold, total)?;
    println!("== V1: BFT coordination chain (in-process simulator) ==");
    println!("    ciphersuite: RedPallas (Zcash Orchard spend-auth), rerandomized\n");
    println!("[setup] running DKG ({}-of-{})...", threshold, total);
    let (key_packages, pkp) = generate_with_dkg::<V1Cs, _>(params, &mut rng)?;
    let mut validators: Vec<Validator<V1Cs>> = key_packages
        .into_iter()
        .map(|(_, kp)| {
            Validator::new(KeyShareBundle {
                key_package: kp,
                public_key_package: pkp.clone(),
            })
        })
        .collect();
    let validator_ids: Vec<_> = validators.iter().map(|v| v.identifier).collect();
    let mut chain: ChainSim<V1Cs> = ChainSim::new();

    // Block 1: InitGroup
    chain.submit(ChainTx::InitGroup {
        params,
        pkp: pkp.clone(),
        validators: validator_ids,
    });
    let results = chain.commit_block();
    print_block(&chain, &results, "InitGroup");

    // Block 2: client picks a randomizer (stand-in for the Orchard `α`)
    // and submits the signing request.
    let request_id = Uuid::new(&mut rng);
    let randomizer = {
        let scalar = <<<V1Cs as frost_core::Ciphersuite>::Group as Group>::Field as Field>::random(&mut rng);
        Randomizer::<V1Cs>::from_scalar(scalar)
    };
    println!(
        "\n[client] submitting signing request {} for message: {:?}",
        request_id, message
    );
    println!(
        "[client] randomizer (α): {}",
        hex::encode(randomizer.serialize())
    );
    chain.submit(ChainTx::SubmitRequest {
        request_id,
        message: message.as_bytes().to_vec(),
        randomizer,
    });
    let results = chain.commit_block();
    print_block(&chain, &results, "SubmitRequest");

    // Block 3: validators react with commitments.
    println!("\n[validators] reacting → producing round-1 commitments");
    for v in validators.iter_mut() {
        for tx in v.react(&chain.state, &mut rng)? {
            chain.submit(tx);
        }
    }
    let results = chain.commit_block();
    print_block(&chain, &results, "SubmitCommitments");

    // Block 4: validators react with rerandomized shares.
    println!("\n[validators] reacting → producing round-2 rerandomized shares");
    for v in validators.iter_mut() {
        for tx in v.react(&chain.state, &mut rng)? {
            chain.submit(tx);
        }
    }
    let results = chain.commit_block();
    print_block(&chain, &results, "SubmitShares");

    let entry = chain
        .state
        .requests
        .get(&request_id)
        .ok_or_else(|| anyhow!("request missing from final state"))?;
    match &entry.status {
        RequestStatus::Completed {
            signature,
            participants,
        } => {
            // Verify against the rerandomized verifying key (Orchard `rk`).
            let randomized_params =
                RandomizedParams::<V1Cs>::from_randomizer(pkp.verifying_key(), randomizer);
            randomized_params
                .randomized_verifying_key()
                .verify(message.as_bytes(), signature)
                .map_err(|e| anyhow!("verification failed: {e}"))?;
            let sig_bytes = signature
                .serialize()
                .map_err(|e| anyhow!("serializing: {e}"))?;
            println!("\n== COMPLETED ==");
            println!("participants : {} of {}", participants.len(), total);
            println!("signature    : {}", hex::encode(&sig_bytes));
            println!("verified vs  : rerandomized vk (rk = ak + α·G)");
        }
        other => {
            return Err(anyhow!(
                "expected Completed at final state, got {:?}",
                other
            ));
        }
    }
    println!(
        "\n[chain] final state: {} request(s) across {} block(s)",
        chain.state.requests.len(),
        chain.block_height
    );
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

fn cmd_keygen(threshold: u16, total: u16, out: &Path, dkg: bool) -> Result<()> {
    let params = MpcParams::new(threshold, total)?;
    let mut rng = OsRng;
    let (key_packages, pkp) = if dkg {
        println!("running DKG ({}-of-{})...", threshold, total);
        generate_with_dkg::<Cs, _>(params, &mut rng)?
    } else {
        println!("running trusted dealer keygen ({}-of-{})...", threshold, total);
        generate_with_trusted_dealer::<Cs, _>(params, &mut rng)?
    };

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

async fn cmd_demo_sign(message: &str, keys_dir: &Path) -> Result<()> {
    let mut bundles: Vec<KeyShareBundle<Cs>> = Vec::new();
    for entry in std::fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("share-") || !name.ends_with(".json") {
            continue;
        }
        let f = std::fs::File::open(&path)?;
        let b: KeyShareBundle<Cs> = serde_json::from_reader(f)?;
        bundles.push(b);
    }
    if bundles.is_empty() {
        return Err(anyhow!("no share-*.json files in {}", keys_dir.display()));
    }

    let pkp = bundles[0].public_key_package.clone();
    let total = bundles.len() as u16;
    // Heuristic: assume threshold = min_signers from the FROST PKP. The crate
    // doesn't expose it directly, so we read it from one of the key packages.
    let threshold = *bundles[0].key_package.min_signers();
    let params = MpcParams::new(threshold, total)?;

    println!(
        "loaded {} shares, group threshold = {}-of-{}",
        bundles.len(),
        threshold,
        total
    );

    // Build signers map.
    let mut signers_map: BTreeMap<_, Arc<Signer<Cs>>> = BTreeMap::new();
    for bundle in bundles {
        let id = *bundle.key_package.identifier();
        signers_map.insert(id, Arc::new(Signer::new(bundle)));
    }

    // Pick the first `threshold` signers as participants.
    let participants: Vec<_> = signers_map.keys().copied().take(threshold as usize).collect();
    println!("participants: {} of {}", participants.len(), total);

    let transport = LocalTransport::new(signers_map);
    let coord = Coordinator::new(params, pkp.clone());
    let mut rng = OsRng;
    let signature = coord
        .sign(&transport, message.as_bytes(), &participants, &mut rng)
        .await?;

    verify(&pkp, message.as_bytes(), &signature)?;

    let sig_bytes = signature
        .serialize()
        .map_err(|e| anyhow!("serializing signature: {e}"))?;
    println!("\nsignature: {}", hex::encode(&sig_bytes));
    println!("verified  ok");
    Ok(())
}

async fn cmd_serve(share_path: &Path, addr: SocketAddr) -> Result<()> {
    let f = std::fs::File::open(share_path)
        .with_context(|| format!("opening {}", share_path.display()))?;
    let bundle: KeyShareBundle<Cs> = serde_json::from_reader(f)?;
    let signer = Arc::new(Signer::new(bundle));
    println!(
        "sapphire-signer: identifier={} listening on http://{}",
        serde_json::to_string(&signer.identifier())?,
        addr,
    );
    signer_server::serve(signer, addr)
        .await
        .map_err(|e| anyhow!(e.to_string()))?;
    Ok(())
}

async fn cmd_http_sign(
    message: &str,
    group_pubkey_path: &Path,
    signer_urls: &[String],
    threshold: u16,
) -> Result<()> {
    let f = std::fs::File::open(group_pubkey_path)?;
    let pkp: frost_core::keys::PublicKeyPackage<Cs> = serde_json::from_reader(f)?;
    let total = signer_urls.len() as u16;
    let params = MpcParams::new(threshold, total)?;

    // Query each signer's /info endpoint to learn its Identifier.
    let http = reqwest::Client::new();
    let mut base_urls: BTreeMap<frost_core::Identifier<Cs>, String> = BTreeMap::new();
    for url in signer_urls {
        let trimmed = url.trim_end_matches('/');
        let info: serde_json::Value = http
            .get(format!("{}/info", trimmed))
            .send()
            .await
            .with_context(|| format!("GET {}/info", trimmed))?
            .json()
            .await?;
        let id: frost_core::Identifier<Cs> =
            serde_json::from_value(info.get("identifier").cloned().ok_or_else(|| {
                anyhow!("/info from {} missing 'identifier' field", trimmed)
            })?)?;
        println!("discovered {} → {}", id_label(&id)?, trimmed);
        base_urls.insert(id, trimmed.to_string());
    }

    let participants: Vec<_> = base_urls.keys().copied().take(threshold as usize).collect();
    println!(
        "signing with {}-of-{} participants...",
        participants.len(),
        total
    );

    let transport = HttpTransport::<Cs>::new(base_urls);
    let coord = Coordinator::new(params, pkp.clone());
    let mut rng = OsRng;
    let sig = coord
        .sign(&transport, message.as_bytes(), &participants, &mut rng)
        .await?;
    verify(&pkp, message.as_bytes(), &sig)?;
    let sig_bytes = sig
        .serialize()
        .map_err(|e| anyhow!("serializing signature: {e}"))?;
    println!("\nsignature: {}", hex::encode(&sig_bytes));
    println!("verified  ok");
    Ok(())
}

fn id_label(id: &frost_core::Identifier<Cs>) -> Result<String> {
    Ok(serde_json::to_string(id)?)
}
