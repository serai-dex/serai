use crate::{COSIGN_CONTEXT, Cosign, SignedCosign};

/// Sign a [`Cosign`] with a schnorrkel keypair, producing a [`SignedCosign`].
pub fn sign_cosign(cosign: Cosign, keypair: &schnorrkel::Keypair) -> SignedCosign {
  SignedCosign {
    cosign: cosign.clone(),
    signature: keypair.sign_simple(COSIGN_CONTEXT, &cosign.signature_message()).to_bytes(),
  }
}

#[cfg(test)]
use rand_core::OsRng;
#[cfg(test)]
use serai_primitives::test_helpers::random_keypair;
#[cfg(test)]
use crate::{BlockHash, CosignIntent, ExternalNetworkId, Public};

#[test]
fn cosign_intent_into_cosign() {
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
fn deterministic_signature_message() {
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
  let (keypair, public) = random_keypair(&mut OsRng);
  let cosign = Cosign {
    global_session: [1u8; 32],
    block_number: 5,
    block_hash: BlockHash([5u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };

  let signed = sign_cosign(cosign, &keypair);

  assert!(signed.verify_signature(public), "valid signature should verify");
}

#[test]
fn signed_cosign_verify_signature_invalid() {
  let (keypair1, _) = random_keypair(&mut OsRng);
  let (_, wrong_public) = random_keypair(&mut OsRng);

  let cosign = Cosign {
    global_session: [1u8; 32],
    block_number: 5,
    block_hash: BlockHash([5u8; 32]),
    cosigner: ExternalNetworkId::Bitcoin,
  };

  let signed = sign_cosign(cosign, &keypair1);

  assert!(!signed.verify_signature(wrong_public), "invalid signature should not verify");
}

#[test]
fn signed_cosign_verify_signature_invalid_public_key_bytes() {
  let (keypair, _) = random_keypair(&mut OsRng);
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

  let (_, valid_public) = random_keypair(&mut OsRng);

  assert!(!signed.verify_signature(valid_public), "invalid signature bytes should return false");
}
