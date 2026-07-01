use rand_core::OsRng;

use serai_primitives::test_helpers::random_schnorrkel_keypair;

use crate::{
  Cosign, ExternalNetworkId, SignedCosign,
  test_helpers::{random_cosign, random_cosign_intent, sign_cosign, random_signed_cosign},
};

#[test]
fn cosign_intent_into_cosign() {
  let intent = random_cosign_intent(&mut OsRng);
  let network = serai_primitives::test_helpers::random_external_network_id(&mut OsRng);
  let Cosign { global_cosigning_session: global_session, block_number, block_hash, cosigner } =
    intent.into_cosign(network);

  assert_eq!(intent.global_cosigning_session, global_session);
  assert_eq!(intent.block_number, block_number);
  assert_eq!(intent.block_hash, block_hash);
  assert_eq!(cosigner, network);
}

#[test]
fn deterministic_and_comprehensive_signature_message() {
  let cosign = random_cosign(&mut OsRng);
  let msg = cosign.signature_message();

  // Deterministic
  assert_eq!(msg, cosign.signature_message(), "signature_message should be deterministic");

  // Comprehensive
  {
    let Cosign { global_cosigning_session: global_session, block_number, block_hash, cosigner } =
      cosign;
    let mut expected = Vec::new();
    expected.extend(borsh::to_vec(&(global_session, block_number, block_hash, cosigner)).unwrap());
    assert_eq!(msg, expected, "signature_message should include all fields in Borsh order");
  }

  // Changing any single field must produce a different message
  let Cosign { global_cosigning_session: global_session, block_number, block_hash, cosigner } =
    cosign;
  {
    let mut other_session = global_session;
    other_session[0] ^= 1;
    let other = Cosign { global_cosigning_session: other_session, ..cosign };
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
  {
    let (keypair, public) = random_schnorrkel_keypair(&mut OsRng);
    let cosign = random_cosign(&mut OsRng);
    let signed = sign_cosign(cosign, &keypair);
    assert!(signed.verify_signature(public), "valid signature should verify");
  }

  {
    let (keypair1, _) = random_schnorrkel_keypair(&mut OsRng);
    let (_, public2) = random_schnorrkel_keypair(&mut OsRng);
    let cosign = random_cosign(&mut OsRng);
    let signed = sign_cosign(cosign, &keypair1);
    assert!(!signed.verify_signature(public2), "invalid signature should not verify");
  }

  {
    let signed = random_signed_cosign(&mut OsRng);
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

    let (_, valid_public) = random_schnorrkel_keypair(&mut OsRng);
    assert!(!signed.verify_signature(valid_public), "invalid signature bytes should return false");
  }
}
