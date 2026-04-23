use rand_core::{RngCore, CryptoRng};

use serai_primitives::{network_id::ExternalNetworkId, test_helpers::random_block_hash};

use crate::{COSIGN_CONTEXT, CosignIntent, Cosign, SignedCosign};

/// Sign a [`Cosign`] with a schnorrkel keypair, producing a [`SignedCosign`].
pub fn sign_cosign(cosign: Cosign, keypair: &schnorrkel::Keypair) -> SignedCosign {
  SignedCosign {
    signature: keypair.sign_simple(COSIGN_CONTEXT, &cosign.signature_message()).to_bytes(),
    cosign,
  }
}

/// Generate a random [`ExternalNetworkId`] for testing.
pub fn random_external_network_id(rng: &mut (impl RngCore + CryptoRng)) -> ExternalNetworkId {
  let all: Vec<_> = ExternalNetworkId::all().collect();
  #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
  all[(rng.next_u64() as usize) % all.len()]
}

/// Generate a random global session ID (`[u8; 32]`).
pub fn random_global_session<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
  serai_primitives::test_helpers::random_bytes(rng)
}

/// Generate a random [`Cosign`] for testing.
pub fn random_cosign(rng: &mut (impl RngCore + CryptoRng)) -> Cosign {
  Cosign {
    global_session: random_global_session(rng),
    block_number: rng.next_u64(),
    block_hash: random_block_hash(rng),
    cosigner: random_external_network_id(rng),
  }
}

/// Generate a random [`CosignIntent`] for testing.
pub fn random_cosign_intent(rng: &mut (impl RngCore + CryptoRng)) -> CosignIntent {
  CosignIntent {
    global_session: random_global_session(rng),
    block_number: rng.next_u64(),
    block_hash: random_block_hash(rng),
    notable: rng.next_u32() % 2 == 0,
  }
}

#[test]
fn cosign_intent_into_cosign() {
  use rand_core::OsRng;

  let intent = random_cosign_intent(&mut OsRng);
  let network = random_external_network_id(&mut OsRng);
  let Cosign { global_session, block_number, block_hash, cosigner } = intent.into_cosign(network);

  assert_eq!(intent.global_session, global_session);
  assert_eq!(intent.block_number, block_number);
  assert_eq!(intent.block_hash, block_hash);
  assert_eq!(cosigner, network);
}

#[test]
fn deterministic_and_comprehensive_signature_message() {
  use rand_core::OsRng;

  let cosign = random_cosign(&mut OsRng);
  let msg = cosign.signature_message();

  // Deterministic
  assert_eq!(msg, cosign.signature_message(), "signature_message should be deterministic");

  // Comprehensive
  {
    let Cosign { global_session, block_number, block_hash, cosigner } = cosign;
    let mut expected = Vec::new();
    expected.extend(borsh::to_vec(&(global_session, block_number, block_hash, cosigner)).unwrap());
    assert_eq!(msg, expected, "signature_message should include all fields in Borsh order");
  }

  // Changing any single field must produce a different message
  let Cosign { global_session, block_number, block_hash, cosigner } = cosign;
  {
    let mut other_session = global_session;
    other_session[0] ^= 1;
    let other = Cosign { global_session: other_session, ..cosign };
    assert_ne!(msg, other.signature_message(), "different global_session must change message");
  }
  {
    let other = Cosign { block_number: block_number.wrapping_add(1), ..cosign };
    assert_ne!(msg, other.signature_message(), "different block_number must change message");
  }
  {
    let mut other_hash = block_hash;
    other_hash.0[0] ^= 1;
    let other = Cosign { block_hash: other_hash, ..cosign };
    assert_ne!(msg, other.signature_message(), "different block_hash must change message");
  }
  {
    let other_cosigner = ExternalNetworkId::all().find(|n| *n != cosigner).unwrap();
    let other = Cosign { cosigner: other_cosigner, ..cosign };
    assert_ne!(msg, other.signature_message(), "different cosigner must change message");
  }
}

#[test]
fn signed_cosign_verify_signature() {
  use rand_core::OsRng;
  use serai_primitives::test_helpers::random_keypair;

  {
    let (keypair, public) = random_keypair(&mut OsRng);
    let cosign = random_cosign(&mut OsRng);
    let signed = sign_cosign(cosign, &keypair);
    assert!(signed.verify_signature(public), "valid signature should verify");
  }

  {
    let (keypair1, _) = random_keypair(&mut OsRng);
    let (_, public2) = random_keypair(&mut OsRng);
    let cosign = random_cosign(&mut OsRng);
    let signed = sign_cosign(cosign, &keypair1);
    assert!(!signed.verify_signature(public2), "invalid signature should not verify");
  }

  {
    let (keypair, _) = random_keypair(&mut OsRng);
    let cosign = random_cosign(&mut OsRng);
    let signed = sign_cosign(cosign, &keypair);
    let invalid_bytes = [255u8; 32];
    assert!(
      schnorrkel::PublicKey::from_bytes(&invalid_bytes).is_err(),
      "test precondition: bytes should be invalid for schnorrkel"
    );

    let invalid_pubkey = serai_primitives::crypto::Public(invalid_bytes);
    assert!(
      !signed.verify_signature(invalid_pubkey),
      "invalid public key bytes should return false"
    );
  }

  {
    let cosign = random_cosign(&mut OsRng);

    let invalid_sig_bytes = [255u8; 64];
    assert!(
      schnorrkel::Signature::from_bytes(&invalid_sig_bytes).is_err(),
      "test precondition: signature bytes should be invalid for schnorrkel"
    );

    let signed = SignedCosign { cosign, signature: invalid_sig_bytes };

    let (_, valid_public) = random_keypair(&mut OsRng);
    assert!(!signed.verify_signature(valid_public), "invalid signature bytes should return false");
  }
}
