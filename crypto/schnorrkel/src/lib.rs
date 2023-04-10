use std::io::{self, Read};

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroizing;

use group::{ff::PrimeField, GroupEncoding};
use ciphersuite::{Ciphersuite, Ristretto};
use schnorr::SchnorrSignature;
use frost::{
  ThresholdKeys, ThresholdView, FrostError,
  algorithm::{IetfTranscript, Hram, Algorithm, Schnorr},
};

use schnorrkel::{PublicKey, Signature, context::SigningTranscript, signing_context};

type RistrettoPoint = <Ristretto as Ciphersuite>::G;
type Scalar = <Ristretto as Ciphersuite>::F;

#[cfg(test)]
mod tests;

#[derive(Clone)]
struct SchnorrkelHram;
impl Hram<Ristretto> for SchnorrkelHram {
  #[allow(non_snake_case)]
  fn hram(R: &RistrettoPoint, A: &RistrettoPoint, m: &[u8]) -> Scalar {
    let ctx_len =
      usize::try_from(u32::from_le_bytes(m[0 .. 4].try_into().expect("malformed message")))
        .unwrap();

    let mut t = signing_context(&m[4 .. (4 + ctx_len)]).bytes(&m[(4 + ctx_len) ..]);
    t.proto_name(b"Schnorr-sig");
    let convert =
      |point: &RistrettoPoint| PublicKey::from_bytes(&point.to_bytes()).unwrap().into_compressed();
    t.commit_point(b"sign:pk", &convert(A));
    t.commit_point(b"sign:R", &convert(R));
    Scalar::from_repr(t.challenge_scalar(b"sign:c").to_bytes()).unwrap()
  }
}

#[derive(Clone)]
pub struct Schnorrkel {
  context: &'static [u8],
  schnorr: Schnorr<Ristretto, SchnorrkelHram>,
  msg: Option<Vec<u8>>,
}

impl Schnorrkel {
  pub fn new(context: &'static [u8]) -> Schnorrkel {
    Schnorrkel { context, schnorr: Schnorr::new(), msg: None }
  }
}

impl Algorithm<Ristretto> for Schnorrkel {
  type Transcript = IetfTranscript;
  type Addendum = ();
  type Signature = Signature;

  fn transcript(&mut self) -> &mut Self::Transcript {
    self.schnorr.transcript()
  }

  fn nonces(&self) -> Vec<Vec<<Ristretto as Ciphersuite>::G>> {
    self.schnorr.nonces()
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    _: &mut R,
    _: &ThresholdKeys<Ristretto>,
  ) {
  }

  fn read_addendum<R: Read>(&self, _: &mut R) -> io::Result<Self::Addendum> {
    Ok(())
  }

  fn process_addendum(
    &mut self,
    _: &ThresholdView<Ristretto>,
    _: u16,
    _: (),
  ) -> Result<(), FrostError> {
    Ok(())
  }

  fn sign_share(
    &mut self,
    params: &ThresholdView<Ristretto>,
    nonce_sums: &[Vec<RistrettoPoint>],
    nonces: Vec<Zeroizing<Scalar>>,
    msg: &[u8],
  ) -> Scalar {
    self.msg = Some(msg.to_vec());
    self.schnorr.sign_share(
      params,
      nonce_sums,
      nonces,
      &[
        &u32::try_from(self.context.len()).expect("context exceeded 2^32 bytes").to_le_bytes(),
        self.context,
        msg,
      ]
      .concat(),
    )
  }

  #[must_use]
  fn verify(
    &self,
    group_key: RistrettoPoint,
    nonces: &[Vec<RistrettoPoint>],
    sum: Scalar,
  ) -> Option<Self::Signature> {
    let mut sig = (SchnorrSignature::<Ristretto> { R: nonces[0][0], s: sum }).serialize();
    sig[63] |= 1 << 7;
    Some(Signature::from_bytes(&sig).unwrap()).filter(|sig| {
      PublicKey::from_bytes(&group_key.to_bytes())
        .unwrap()
        .verify(&mut signing_context(self.context).bytes(self.msg.as_ref().unwrap()), sig)
        .is_ok()
    })
  }

  fn verify_share(
    &self,
    verification_share: RistrettoPoint,
    nonces: &[Vec<RistrettoPoint>],
    share: Scalar,
  ) -> Result<Vec<(Scalar, RistrettoPoint)>, ()> {
    self.schnorr.verify_share(verification_share, nonces, share)
  }
}
