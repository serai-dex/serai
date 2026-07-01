use rand_core::{RngCore, CryptoRng};

use serai_primitives::test_helpers::{random_block_hash, random_schnorrkel_keypair};

use crate::{CosignIntent, Cosign, SignedCosign};

/// Generate a random global cosigning session ID.
pub fn random_global_cosigning_session_id<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
  let mut res = [0u8; 32];
  rng.fill_bytes(&mut res);
  res
}

/// Sign a [`Cosign`] with a schnorrkel keypair, producing a [`SignedCosign`].
pub fn sign_cosign(cosign: Cosign, keypair: &schnorrkel::Keypair) -> SignedCosign {
  SignedCosign {
    signature: keypair.sign_simple(crate::COSIGN_CONTEXT, &cosign.signature_message()).to_bytes(),
    cosign,
  }
}

/// Sign a [`Cosign`] with a schnorrkel keypair, producing a [`SignedCosign`].
pub fn random_signed_cosign<R: RngCore + CryptoRng>(rng: &mut R) -> SignedCosign {
  let cosign = random_cosign(rng);
  let (keypair, _) = random_schnorrkel_keypair(rng);
  sign_cosign(cosign, &keypair)
}

/// Generate a random [`Cosign`] for testing.
pub fn random_cosign<R: RngCore + CryptoRng>(rng: &mut R) -> Cosign {
  Cosign {
    global_cosigning_session: random_global_cosigning_session_id(rng),
    block_number: rng.next_u64(),
    block_hash: random_block_hash(rng),
    cosigner: serai_primitives::test_helpers::random_external_network_id(rng),
  }
}

/// Generate a random [`CosignIntent`] for testing.
pub fn random_cosign_intent<R: RngCore + CryptoRng>(rng: &mut R) -> CosignIntent {
  CosignIntent {
    global_cosigning_session: random_global_cosigning_session_id(rng),
    block_number: rng.next_u64(),
    block_hash: random_block_hash(rng),
    notable: rng.next_u32() % 2 == 0,
  }
}
