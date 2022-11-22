use std::io::{self, Read, Write};

use zeroize::Zeroize;

use digest::Digest;

use group::{
  ff::{Field, PrimeField},
  Group, GroupEncoding,
  prime::PrimeGroup,
};

use multiexp::multiexp_vartime;

use ciphersuite::Ciphersuite;

use crate::SchnorrSignature;

fn digest<D: Digest>() -> D {
  D::new_with_prefix(b"Schnorr Aggregate")
}

// A secure challenge will include the nonce and whatever message
// Depending on the environment, a secure challenge *may* not include the public key, even if
// the modern consensus is it should
// Accordingly, transcript both here, even if ideally only the latter would need to be
fn digest_accumulate<D: Digest, G: PrimeGroup>(digest: &mut D, key: G, challenge: G::Scalar) {
  digest.update(key.to_bytes().as_ref());
  digest.update(challenge.to_repr().as_ref());
}

// Performs a big-endian modular reduction of the hash value
// This is used by the below aggregator to prevent mutability
// Only an 128-bit scalar is needed to offer 128-bits of security against malleability per
// https://cr.yp.to/badbatch/badbatch-20120919.pdf
// Accordingly, while a 256-bit hash used here with a 256-bit ECC will have bias, it shouldn't be
// an issue
fn scalar_from_digest<D: Digest, F: PrimeField>(digest: D) -> F {
  let bytes = digest.finalize();
  debug_assert_eq!(bytes.len() % 8, 0);

  let mut res = F::zero();
  let mut i = 0;
  while i < bytes.len() {
    if i != 0 {
      for _ in 0 .. 8 {
        res += res;
      }
    }
    res += F::from(u64::from_be_bytes(bytes[i .. (i + 8)].try_into().unwrap()));
    i += 8;
  }
  res
}

fn digest_yield<D: Digest, F: PrimeField>(digest: D, i: usize) -> F {
  scalar_from_digest(digest.chain_update(
    u32::try_from(i).expect("more than 4 billion signatures in aggregate").to_le_bytes(),
  ))
}

/// Aggregate Schnorr signature as defined in https://eprint.iacr.org/2021/350.pdf.
#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct SchnorrAggregate<C: Ciphersuite> {
  pub Rs: Vec<C::G>,
  pub s: C::F,
}

impl<C: Ciphersuite> SchnorrAggregate<C> {
  /// Read a SchnorrAggregate from something implementing Read.
  pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;

    #[allow(non_snake_case)]
    let mut Rs = vec![];
    for _ in 0 .. u32::from_le_bytes(len) {
      Rs.push(C::read_G(reader)?);
    }

    Ok(SchnorrAggregate { Rs, s: C::read_F(reader)? })
  }

  /// Write a SchnorrAggregate to something implementing Read.
  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(
      &u32::try_from(self.Rs.len())
        .expect("more than 4 billion signatures in aggregate")
        .to_le_bytes(),
    )?;
    #[allow(non_snake_case)]
    for R in &self.Rs {
      writer.write_all(R.to_bytes().as_ref())?;
    }
    writer.write_all(self.s.to_repr().as_ref())
  }

  /// Serialize a SchnorrAggregate, returning a Vec<u8>.
  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }

  /// Perform signature verification.
  #[must_use]
  pub fn verify<D: Clone + Digest>(&self, keys_and_challenges: &[(C::G, C::F)]) -> bool {
    if self.Rs.len() != keys_and_challenges.len() {
      return false;
    }

    let mut digest = digest::<D>();
    for (key, challenge) in keys_and_challenges {
      digest_accumulate(&mut digest, *key, *challenge);
    }

    let mut pairs = Vec::with_capacity((2 * keys_and_challenges.len()) + 1);
    for (i, (key, challenge)) in keys_and_challenges.iter().enumerate() {
      let z = digest_yield(digest.clone(), i);
      pairs.push((z, self.Rs[i]));
      pairs.push((z * challenge, *key));
    }
    pairs.push((-self.s, C::generator()));
    multiexp_vartime(&pairs).is_identity().into()
  }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Zeroize)]
pub struct SchnorrAggregator<D: Clone + Digest, C: Ciphersuite> {
  digest: D,
  sigs: Vec<SchnorrSignature<C>>,
}

impl<D: Clone + Digest, C: Ciphersuite> Default for SchnorrAggregator<D, C> {
  fn default() -> Self {
    Self { digest: digest(), sigs: vec![] }
  }
}

impl<D: Clone + Digest, C: Ciphersuite> SchnorrAggregator<D, C> {
  /// Create a new aggregator.
  pub fn new() -> Self {
    Self::default()
  }

  /// Aggregate a signature.
  pub fn aggregate(&mut self, public_key: C::G, challenge: C::F, sig: SchnorrSignature<C>) {
    digest_accumulate(&mut self.digest, public_key, challenge);
    self.sigs.push(sig);
  }

  /// Complete aggregation, returning None if none were aggregated.
  pub fn complete(self) -> Option<SchnorrAggregate<C>> {
    if self.sigs.is_empty() {
      return None;
    }

    let mut aggregate =
      SchnorrAggregate { Rs: Vec::with_capacity(self.sigs.len()), s: C::F::zero() };
    for i in 0 .. self.sigs.len() {
      aggregate.Rs.push(self.sigs[i].R);
      aggregate.s += self.sigs[i].s * digest_yield::<_, C::F>(self.digest.clone(), i);
    }
    Some(aggregate)
  }
}
