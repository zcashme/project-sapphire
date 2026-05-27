//! Orchard compatibility: prove that a signature produced by the Sapphire
//! coordination chain is byte-compatible with Orchard's spend-auth check.
//!
//! The test is the loop-closer for V1.1: it shows that what Sapphire emits
//! is what Orchard actually accepts. The verification call here —
//! `redpallas::VerificationKey::<SpendAuth>::randomize(&α).verify(&sighash, &sig)`
//! — is the *same* operation that `orchard::pczt::Action::apply_signature`
//! runs internally to decide whether to attach an externally-computed
//! signature to a spend description.
//!
//! What's NOT here: actually building an Orchard PCZT with notes, anchor,
//! and Halo 2 proof. That's the trusted-prover question (SAPPHIRE.md
//! Phase 2). The signing path itself is what we're validating.

use std::convert::TryFrom;

use frost_core::{Ciphersuite, Field, Group};
use frost_rerandomized::Randomizer;
use rand::rngs::OsRng;
use reddsa::frost::redpallas::PallasBlake2b512;
use reddsa::orchard::SpendAuth;
use reddsa::VerificationKey;

use sapphire_chain::{sim::ChainSim, tx::Tx};
use sapphire_core::{protocol::KeyShareBundle, MpcParams};
use sapphire_keygen::generate_with_dkg;
use sapphire_node::Node;
use sapphire_zcash::drive_signing_session;

type Cs = PallasBlake2b512;

#[test]
fn sapphire_signature_passes_orchard_rk_verify() {
    let mut rng = OsRng;
    let params = MpcParams::new(2, 3).unwrap();

    // 1. Sapphire DKG: generate the group whose verifying key plays the role
    //    of Orchard's `ak` (the underlying spend-auth key). In a real
    //    deployment, the receiver derives addresses from this `ak`; spending
    //    requires Sapphire-coordinated signing.
    let (key_packages, pkp) = generate_with_dkg::<Cs, _>(params, &mut rng).unwrap();
    let mut validators: Vec<Node<Cs>> = key_packages
        .into_iter()
        .map(|(_, kp)| {
            Node::new(KeyShareBundle {
                key_package: kp,
                public_key_package: pkp.clone(),
            })
        })
        .collect();

    // 2. Init the chain with the group.
    let mut chain = ChainSim::<Cs>::new();
    chain.submit(Tx::InitGroup {
        params,
        pkp: pkp.clone(),
        validators: validators.iter().map(|v| v.identifier).collect(),
    });
    chain.commit_block();

    // 3. Caller picks the per-spend randomizer α (in real Orchard, this is
    //    chosen by the Constructor when assembling the action) and computes
    //    the sighash from the surrounding transaction. We synthesize both.
    let alpha_scalar = <<<Cs as Ciphersuite>::Group as Group>::Field as Field>::random(&mut rng);
    let alpha = Randomizer::<Cs>::from_scalar(alpha_scalar);
    let sighash: [u8; 32] = *b"sapphire x orchard sighash 32 by";

    // 4. Drive Sapphire — this runs the full BFT chain lifecycle and returns
    //    the aggregated rerandomized signature.
    let signature = drive_signing_session(
        &mut chain,
        &mut validators,
        sighash,
        alpha,
        &mut rng,
    )
    .expect("sapphire signing should complete");

    // 5. Cross-verify via the *Orchard side* of the world. Take the bytes of
    //    Sapphire's group verifying key and reconstruct it as an
    //    `reddsa::VerificationKey<SpendAuth>` — this is the same type Orchard
    //    uses for `rk` in a spend description (see
    //    `orchard::primitives::redpallas::VerificationKey<SpendAuth>`).
    let ak_bytes: [u8; 32] = pkp
        .verifying_key()
        .serialize()
        .expect("vk serialize")
        .as_slice()
        .try_into()
        .expect("redpallas vk is 32 bytes");
    let ak: VerificationKey<SpendAuth> =
        VerificationKey::try_from(ak_bytes).expect("vk roundtrip");

    // Apply the same randomization Orchard applies: rk = ak + α·G.
    let rk: VerificationKey<SpendAuth> = ak.randomize(&alpha.to_scalar_via_bytes());

    // Convert Sapphire's frost signature bytes into reddsa's signature type
    // (the *exact* type Orchard's apply_signature accepts).
    let sig_bytes: [u8; 64] = signature
        .serialize()
        .expect("sig serialize")
        .as_slice()
        .try_into()
        .expect("redpallas signature is 64 bytes");
    let orchard_sig: reddsa::Signature<SpendAuth> = reddsa::Signature::from(sig_bytes);

    // This is the exact verification Orchard runs in
    // `pczt::Action::apply_signature` before attaching the signature.
    rk.verify(&sighash, &orchard_sig)
        .expect("Orchard rk.verify must accept the Sapphire-produced signature");
}

/// Tiny extension so the test reads cleanly. Pallas scalars from frost-rerandomized
/// and from pasta_curves share the canonical 32-byte little-endian encoding;
/// we go through bytes to stay decoupled from any private newtype lineage.
trait RandomizerScalarBytes {
    fn to_scalar_via_bytes(&self) -> pasta_curves::pallas::Scalar;
}

impl RandomizerScalarBytes for Randomizer<Cs> {
    fn to_scalar_via_bytes(&self) -> pasta_curves::pallas::Scalar {
        use ff::PrimeField;
        let bytes: [u8; 32] = self.serialize().as_slice().try_into().unwrap();
        pasta_curves::pallas::Scalar::from_repr(bytes).unwrap()
    }
}
