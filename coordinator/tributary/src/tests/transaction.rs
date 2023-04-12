use rand_core::RngCore;

use ciphersuite::{
  group::{ff::Field, Group},
  Ciphersuite, Ristretto,
};
use schnorr::SchnorrSignature;

use crate::Signed;

pub fn random_signed<R: RngCore>(rng: &mut R) -> Signed {
  Signed {
    signer: <Ristretto as Ciphersuite>::G::random(&mut *rng),
    nonce: u32::try_from(rng.next_u64() >> 32).unwrap(),
    signature: SchnorrSignature::<Ristretto> {
      R: <Ristretto as Ciphersuite>::G::random(&mut *rng),
      s: <Ristretto as Ciphersuite>::F::random(rng),
    },
  }
}

#[test]
fn serialize_signed() {
  use crate::ReadWrite;
  let signed = random_signed(&mut rand_core::OsRng);
  assert_eq!(Signed::read::<&[u8]>(&mut signed.serialize().as_ref()).unwrap(), signed);
}
