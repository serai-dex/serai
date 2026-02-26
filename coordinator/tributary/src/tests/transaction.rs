use rand::{CryptoRng, RngCore};
use schnorr::SchnorrSignature;

use ciphersuite::{group::Group as _, *};
use dalek_ff_group::Ristretto;

use crate::transaction::{SigningProtocolRound, Signed};

fn random_signed<R: RngCore + CryptoRng>(rng: &mut R) -> Signed {
  let signed = tributary_sdk::tests::random_signed(&mut *rng);
  Signed { signer: signed.signer, signature: signed.signature }
}

#[test]
fn signing_protocol_round_nonce() {
  assert_eq!(SigningProtocolRound::Preprocess.nonce(), 0);
  assert_eq!(SigningProtocolRound::Share.nonce(), 1);
}

#[test]
fn default_signer_has_identity() {
  let default_signed = Signed::default();
  let identity = <Ristretto as WrappedGroup>::G::identity();
  assert_eq!(default_signed.signer(), identity);
  assert_eq!(
    default_signed.signature,
    SchnorrSignature { R: identity, s: <Ristretto as WrappedGroup>::F::ZERO }
  );
}

#[test]
fn serialize_signed() {
  let default_signed = Signed::default();
  let encoded = borsh::to_vec(&default_signed).unwrap();
  let decoded: Signed = borsh::from_slice(&encoded).unwrap();
  assert_eq!(decoded, default_signed);

  let signed = random_signed(&mut rand::rngs::OsRng);
  let encoded = borsh::to_vec(&signed).unwrap();
  let decoded: Signed = borsh::from_slice(&encoded).unwrap();
  assert_eq!(decoded, signed);
}
