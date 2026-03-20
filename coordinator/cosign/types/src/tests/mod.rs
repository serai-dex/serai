use crate::{COSIGN_CONTEXT, Cosign, SignedCosign};

/// Sign a [`Cosign`] with a schnorrkel keypair, producing a [`SignedCosign`].
pub fn sign_cosign(cosign: Cosign, keypair: &schnorrkel::Keypair) -> SignedCosign {
  SignedCosign {
    cosign: cosign.clone(),
    signature: keypair.sign_simple(COSIGN_CONTEXT, &cosign.signature_message()).to_bytes(),
  }
}

#[cfg(test)]
use rand_core::{OsRng, RngCore};
#[cfg(test)]
use serai_primitives::test_helpers::{random_block_hash, random_keypair};
#[cfg(test)]
use crate::{CosignIntent, ExternalNetworkId, Public};

/// Generate a random global session ID for testing.
#[cfg(any(test, feature = "test-helpers"))]
pub fn random_global_session(
  rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> [u8; 32] {
  let mut id = [0u8; 32];
  rng.fill_bytes(&mut id);
  id
}

#[cfg(test)]
fn random_external_network_id(
  rng: &mut (impl RngCore + rand_core::CryptoRng),
) -> ExternalNetworkId {
  let all: Vec<_> = ExternalNetworkId::all().collect();
  all[(rng.next_u32() as usize) % all.len()]
}

#[test]
fn cosign_intent_into_cosign() {
  let global_session = random_global_session(&mut OsRng);
  let block_number = OsRng.next_u64();
  let block_hash = random_block_hash(&mut OsRng);
  let notable = OsRng.next_u32() % 2 == 0;
  let network = random_external_network_id(&mut OsRng);

  let intent = CosignIntent { global_session, block_number, block_hash, notable };
  let Cosign {
    global_session: cosign_global_session,
    block_number: cosign_block_number,
    block_hash: cosign_block_hash,
    cosigner: cosign_cosigner,
  } = intent.into_cosign(network);

  assert_eq!(cosign_global_session, global_session);
  assert_eq!(cosign_block_number, block_number);
  assert_eq!(cosign_block_hash, block_hash);
  assert_eq!(cosign_cosigner, network);
}

#[test]
fn deterministic_signature_message() {
  let cosign = Cosign {
    global_session: random_global_session(&mut OsRng),
    block_number: OsRng.next_u64(),
    block_hash: random_block_hash(&mut OsRng),
    cosigner: ExternalNetworkId::Bitcoin,
  };

  let msg1 = cosign.signature_message();
  let msg2 = cosign.signature_message();

  assert_eq!(msg1, msg2, "signature_message should be deterministic");
}

#[test]
fn signed_cosign_verify_signature_valid() {
  let (keypair, public) = random_keypair(&mut OsRng);
  let cosign = Cosign {
    global_session: random_global_session(&mut OsRng),
    block_number: OsRng.next_u64(),
    block_hash: random_block_hash(&mut OsRng),
    cosigner: random_external_network_id(&mut OsRng),
  };

  let signed = sign_cosign(cosign, &keypair);

  assert!(signed.verify_signature(public), "valid signature should verify");
}

#[test]
fn signed_cosign_verify_signature_invalid() {
  let (keypair1, _) = random_keypair(&mut OsRng);
  let (_, wrong_public) = random_keypair(&mut OsRng);

  let cosign = Cosign {
    global_session: random_global_session(&mut OsRng),
    block_number: OsRng.next_u64(),
    block_hash: random_block_hash(&mut OsRng),
    cosigner: random_external_network_id(&mut OsRng),
  };

  let signed = sign_cosign(cosign, &keypair1);

  assert!(!signed.verify_signature(wrong_public), "invalid signature should not verify");
}

#[test]
fn signed_cosign_verify_signature_invalid_public_key_bytes() {
  let (keypair, _) = random_keypair(&mut OsRng);
  let cosign = Cosign {
    global_session: random_global_session(&mut OsRng),
    block_number: OsRng.next_u64(),
    block_hash: random_block_hash(&mut OsRng),
    cosigner: random_external_network_id(&mut OsRng),
  };

  let signed = sign_cosign(cosign, &keypair);

  let invalid_bytes = [255u8; 32];
  assert!(
    schnorrkel::PublicKey::from_bytes(&invalid_bytes).is_err(),
    "test precondition: bytes should be invalid for schnorrkel"
  );

  let invalid_pubkey = Public(invalid_bytes);
  assert!(!signed.verify_signature(invalid_pubkey), "invalid public key bytes should return false");
}

#[test]
fn signed_cosign_verify_signature_invalid_signature_bytes() {
  let cosign = Cosign {
    global_session: random_global_session(&mut OsRng),
    block_number: OsRng.next_u64(),
    block_hash: random_block_hash(&mut OsRng),
    cosigner: random_external_network_id(&mut OsRng),
  };

  let invalid_sig_bytes = [255u8; 64];
  assert!(
    schnorrkel::Signature::from_bytes(&invalid_sig_bytes).is_err(),
    "test precondition: signature bytes should be invalid for schnorrkel"
  );

  let signed = SignedCosign { cosign, signature: invalid_sig_bytes };

  let (_, valid_public) = random_keypair(&mut OsRng);

  assert!(!signed.verify_signature(valid_public), "invalid signature bytes should return false");
}
