use std_shims::{prelude::*, io};

use zeroize::Zeroize;

use transcript::{Transcript as _, DigestTranscript};

use ciphersuite::{
  group::{
    ff::{Field as _, PrimeField as _},
    Group as _, GroupEncoding as _,
  },
  FromUniformBytes as _, GroupIo, WithPreferredHash,
};
use multiexp::multiexp_vartime;

use crate::SchnorrSignature;

// Returns a unbiased scalar weight to use on a signature in order to prevent malleability
fn weight<C: WithPreferredHash>(digest: &mut DigestTranscript<C::H>) -> C::F {
  let bytes = digest.challenge(b"aggregation_weight");
  C::F::from_uniform_bytes(&bytes.into())
}

/// Aggregate Schnorr signature as defined in <https://eprint.iacr.org/2021/350>.
#[expect(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct SchnorrAggregate<C: GroupIo + WithPreferredHash> {
  Rs: Vec<C::G>,
  s: C::F,
}

impl<C: GroupIo + WithPreferredHash> SchnorrAggregate<C> {
  /// Read a SchnorrAggregate from something implementing Read.
  pub fn read(mut reader: impl io::Read) -> io::Result<Self> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;

    #[expect(non_snake_case)]
    let mut Rs = vec![];
    for _ in 0 .. u32::from_le_bytes(len) {
      Rs.push(C::read_G(&mut reader)?);
    }

    Ok(SchnorrAggregate { Rs, s: C::read_F(&mut reader)? })
  }

  /// Write a SchnorrAggregate to something implementing Write.
  ///
  /// This will panic if more than 4 billion signatures were aggregated.
  pub fn write(&self, mut writer: impl io::Write) -> io::Result<()> {
    writer.write_all(
      &u32::try_from(self.Rs.len())
        .expect("more than 4 billion signatures in aggregate")
        .to_le_bytes(),
    )?;
    #[expect(non_snake_case)]
    for R in &self.Rs {
      writer.write_all(R.to_bytes().as_ref())?;
    }
    writer.write_all(self.s.to_repr().as_ref())
  }

  /// Serialize a SchnorrAggregate, returning a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }

  /// The list of nonce commitments within this aggregate signature.
  #[expect(non_snake_case)]
  pub fn Rs(&self) -> &[C::G] {
    self.Rs.as_slice()
  }

  /// Perform signature verification.
  ///
  /// Challenges must be properly crafted, which means being binding to the public key, nonce, and
  /// any message. Failure to do so will let a malicious adversary to forge signatures for
  /// different keys/messages.
  ///
  /// The DST used here must prevent a collision with whatever hash function produced the
  /// challenges.
  #[must_use]
  pub fn verify(&self, dst: &'static [u8], keys_and_challenges: &[(C::G, C::F)]) -> bool {
    if self.Rs.len() != keys_and_challenges.len() {
      return false;
    }

    let mut digest = DigestTranscript::<C::H>::new(dst);
    digest.domain_separate(b"signatures");
    for (_, challenge) in keys_and_challenges {
      digest.append_message(b"challenge", challenge.to_repr());
    }

    let mut pairs = Vec::with_capacity((2 * keys_and_challenges.len()) + 1);
    for (i, (key, challenge)) in keys_and_challenges.iter().enumerate() {
      let z = weight::<C>(&mut digest);
      pairs.push((z, self.Rs[i]));
      pairs.push((z * challenge, *key));
    }
    pairs.push((-self.s, C::generator()));
    multiexp_vartime(&pairs).is_identity().into()
  }
}

/// A signature aggregator capable of consuming signatures in order to produce an aggregate.
#[derive(Clone, Debug)]
pub struct SchnorrAggregator<C: GroupIo + WithPreferredHash> {
  digest: DigestTranscript<C::H>,
  sigs: Vec<SchnorrSignature<C>>,
}

impl<C: GroupIo + WithPreferredHash> SchnorrAggregator<C> {
  /// Create a new aggregator.
  ///
  /// The DST used here must prevent a collision with whatever hash function produced the
  /// challenges.
  pub fn new(dst: &'static [u8]) -> Self {
    let mut res = Self { digest: DigestTranscript::<C::H>::new(dst), sigs: vec![] };
    res.digest.domain_separate(b"signatures");
    res
  }

  /// Aggregate a signature.
  ///
  /// The challenge must be properly crafted, which means being binding to the public key, nonce,
  /// and any message. Failure to do so will let a malicious adversary to forge signatures for
  /// different keys/messages.
  pub fn aggregate(&mut self, challenge: C::F, sig: SchnorrSignature<C>) {
    self.digest.append_message(b"challenge", challenge.to_repr());
    self.sigs.push(sig);
  }

  /// Complete aggregation, returning None if none were aggregated.
  pub fn complete(mut self) -> Option<SchnorrAggregate<C>> {
    if self.sigs.is_empty() {
      return None;
    }

    let mut aggregate = SchnorrAggregate { Rs: Vec::with_capacity(self.sigs.len()), s: C::F::ZERO };
    for i in 0 .. self.sigs.len() {
      aggregate.Rs.push(self.sigs[i].R);
      aggregate.s += self.sigs[i].s * weight::<C>(&mut self.digest);
    }
    Some(aggregate)
  }
}
