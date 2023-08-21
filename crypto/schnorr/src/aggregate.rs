use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use zeroize::Zeroize;

use transcript::{Transcript, SecureDigest, DigestTranscript};

use ciphersuite::{
  group::{
    ff::{Field, PrimeField},
    Group, GroupEncoding,
  },
  Ciphersuite,
};
use multiexp::multiexp_vartime;

use crate::SchnorrSignature;

// Returns a unbiased scalar weight to use on a signature in order to prevent malleability
fn weight<D: Send + Clone + SecureDigest, F: PrimeField>(digest: &mut DigestTranscript<D>) -> F {
  let mut bytes = digest.challenge(b"aggregation_weight");
  debug_assert_eq!(bytes.len() % 8, 0);
  // This should be guaranteed thanks to SecureDigest
  debug_assert!(bytes.len() >= 32);

  let mut res = F::ZERO;
  let mut i = 0;

  // Derive a scalar from enough bits of entropy that bias is < 2^128
  // This can't be const due to its usage of a generic
  // Also due to the usize::try_from, yet that could be replaced with an `as`
  // The + 7 forces it to round up
  #[allow(non_snake_case)]
  let BYTES: usize = usize::try_from(((F::NUM_BITS + 128) + 7) / 8).unwrap();

  let mut remaining = BYTES;

  // We load bits in as u64s
  const WORD_LEN_IN_BITS: usize = 64;
  const WORD_LEN_IN_BYTES: usize = WORD_LEN_IN_BITS / 8;

  let mut first = true;
  while i < remaining {
    // Shift over the already loaded bits
    if !first {
      for _ in 0 .. WORD_LEN_IN_BITS {
        res += res;
      }
    }
    first = false;

    // Add the next 64 bits
    res += F::from(u64::from_be_bytes(bytes[i .. (i + WORD_LEN_IN_BYTES)].try_into().unwrap()));
    i += WORD_LEN_IN_BYTES;

    // If we've exhausted this challenge, get another
    if i == bytes.len() {
      bytes = digest.challenge(b"aggregation_weight_continued");
      remaining -= i;
      i = 0;
    }
  }
  res
}

/// Aggregate Schnorr signature as defined in <https://eprint.iacr.org/2021/350>.
#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct SchnorrAggregate<C: Ciphersuite> {
  Rs: Vec<C::G>,
  s: C::F,
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

  /// Write a SchnorrAggregate to something implementing Write.
  ///
  /// This will panic if more than 4 billion signatures were aggregated.
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

  /// Serialize a SchnorrAggregate, returning a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }

  #[allow(non_snake_case)]
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
      let z = weight(&mut digest);
      pairs.push((z, self.Rs[i]));
      pairs.push((z * challenge, *key));
    }
    pairs.push((-self.s, C::generator()));
    multiexp_vartime(&pairs).is_identity().into()
  }
}

/// A signature aggregator capable of consuming signatures in order to produce an aggregate.
#[allow(non_snake_case)]
#[derive(Clone, Debug, Zeroize)]
pub struct SchnorrAggregator<C: Ciphersuite> {
  digest: DigestTranscript<C::H>,
  sigs: Vec<SchnorrSignature<C>>,
}

impl<C: Ciphersuite> SchnorrAggregator<C> {
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
      aggregate.s += self.sigs[i].s * weight::<_, C::F>(&mut self.digest);
    }
    Some(aggregate)
  }
}
