use crate::{COSIGN_CONTEXT, Cosign, SignedCosign};

#[cfg(test)]
use crate::{BlockHash, CosignIntent, ExternalNetworkId, Public};

fn sr25519_fixture() -> schnorrkel::Keypair {
  schnorrkel::MiniSecretKey::from_bytes(&[0xff; 32])
    .expect("fixed seed should be valid")
    .expand_to_keypair(schnorrkel::ExpansionMode::Ed25519)
}

fn sr25519_fixture_from_seed(seed: [u8; 32]) -> schnorrkel::Keypair {
  schnorrkel::MiniSecretKey::from_bytes(&seed)
    .expect("seed should be valid")
    .expand_to_keypair(schnorrkel::ExpansionMode::Ed25519)
}

fn sign_cosign(cosign: Cosign, keypair: &schnorrkel::Keypair) -> SignedCosign {
  SignedCosign {
    cosign: cosign.clone(),
    signature: keypair.sign_simple(COSIGN_CONTEXT, &cosign.signature_message()).to_bytes(),
  }
}

pub fn fixture_public_key() -> [u8; 32] {
  sr25519_fixture().public.to_bytes()
}

pub fn public_key_from_seed(seed: [u8; 32]) -> [u8; 32] {
  sr25519_fixture_from_seed(seed).public.to_bytes()
}

pub fn sign_cosign_with_fixture(cosign: Cosign) -> SignedCosign {
  sign_cosign(cosign, &sr25519_fixture())
}

pub fn sign_cosign_with_seed(cosign: Cosign, seed: [u8; 32]) -> SignedCosign {
  sign_cosign(cosign, &sr25519_fixture_from_seed(seed))
}

#[test]
fn cosign_intent_to_cosign() {
  let intent = CosignIntent {
    global_session: [1u8; 32],
    block_number: 5,
    block_hash: BlockHash([5u8; 32]),
    notable: true,
  };

  let cosign = intent.into_cosign(ExternalNetworkId::Bitcoin);

  assert_eq!(cosign.global_session, [1u8; 32]);
  assert_eq!(cosign.block_number, 5);
  assert_eq!(cosign.block_hash, BlockHash([5u8; 32]));
  assert_eq!(cosign.cosigner, ExternalNetworkId::Bitcoin);
}

#[test]
fn cosign_signature_message() {
  let cosign = Cosign {
    global_session: [1u8; 32],
    block_number: 5,
    block_hash: BlockHash([5u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };

  let msg1 = cosign.signature_message();
  let msg2 = cosign.signature_message();

  assert_eq!(msg1, msg2, "signature_message should be deterministic");
}

#[test]
fn signed_cosign_verify_signature_valid() {
  let keypair = sr25519_fixture();
  let cosign = Cosign {
    global_session: [1u8; 32],
    block_number: 5,
    block_hash: BlockHash([5u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };

  let signed = sign_cosign(cosign, &keypair);
  let pubkey = Public(keypair.public.to_bytes());

  assert!(signed.verify_signature(pubkey), "valid signature should verify");
}

#[test]
fn signed_cosign_verify_signature_invalid() {
  let keypair1 = sr25519_fixture();
  let keypair2 = schnorrkel::MiniSecretKey::from_bytes(&[0x01; 32])
    .unwrap()
    .expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);

  let cosign = Cosign {
    global_session: [1u8; 32],
    block_number: 5,
    block_hash: BlockHash([5u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };

  let signed = sign_cosign(cosign, &keypair1);
  let wrong_pubkey = Public(keypair2.public.to_bytes());

  assert!(!signed.verify_signature(wrong_pubkey), "invalid signature should not verify");
}

#[test]
fn signed_cosign_verify_signature_invalid_public_key_bytes() {
  let keypair = sr25519_fixture();
  let cosign = Cosign {
    global_session: [1u8; 32],
    block_number: 5,
    block_hash: BlockHash([5u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
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
    global_session: [1u8; 32],
    block_number: 5,
    block_hash: BlockHash([5u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };

  let invalid_sig_bytes = [255u8; 64];
  assert!(
    schnorrkel::Signature::from_bytes(&invalid_sig_bytes).is_err(),
    "test precondition: signature bytes should be invalid for schnorrkel"
  );

  let signed = SignedCosign { cosign, signature: invalid_sig_bytes };

  let keypair = sr25519_fixture();
  let valid_pubkey = Public(keypair.public.to_bytes());

  assert!(!signed.verify_signature(valid_pubkey), "invalid signature bytes should return false");
}
