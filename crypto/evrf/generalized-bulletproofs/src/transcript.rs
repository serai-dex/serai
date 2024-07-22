use std::io;

use blake2::{Digest, Blake2b512};

use ciphersuite::{
  group::{ff::PrimeField, GroupEncoding},
  Ciphersuite,
};

use crate::PointVector;

const SCALAR: u8 = 0;
const POINT: u8 = 1;
const CHALLENGE: u8 = 2;

fn challenge<F: PrimeField>(digest: &mut Blake2b512) -> F {
  // Panic if this is such a wide field, we won't successfully perform a reduction into an unbiased
  // scalar
  debug_assert!((F::NUM_BITS + 128) < 512);

  digest.update([CHALLENGE]);
  let chl = digest.clone().finalize();

  let mut res = F::ZERO;
  for (i, mut byte) in chl.iter().cloned().enumerate() {
    for j in 0 .. 8 {
      let lsb = byte & 1;
      let mut bit = F::from(u64::from(lsb));
      for _ in 0 .. ((i * 8) + j) {
        bit = bit.double();
      }
      res += bit;

      byte >>= 1;
    }
  }

  // Negligible probability
  if bool::from(res.is_zero()) {
    panic!("zero challenge");
  }

  res
}

/// Commitments written to/read from a transcript.
// We use a dedicated type for this to coerce the caller into transcripting the commitments as
// expected.
#[cfg_attr(test, derive(Clone, PartialEq, Debug))]
pub struct Commitments<C: Ciphersuite> {
  pub(crate) C: PointVector<C>,
  pub(crate) V: PointVector<C>,
}

impl<C: Ciphersuite> Commitments<C> {
  /// The vector commitments.
  pub fn C(&self) -> &[C::G] {
    &self.C.0
  }
  /// The non-vector commitments.
  pub fn V(&self) -> &[C::G] {
    &self.V.0
  }
}

/// A transcript for proving proofs.
pub struct Transcript {
  digest: Blake2b512,
  transcript: Vec<u8>,
}

/*
  We define our proofs as Vec<u8> and derive our transcripts from the values we deserialize from
  them. This format assumes the order of the values read, their size, and their quantity are
  constant to the context.
*/
impl Transcript {
  /// Create a new transcript off some context.
  pub fn new(context: [u8; 32]) -> Self {
    let mut digest = Blake2b512::new();
    digest.update(context);
    Self { digest, transcript: Vec::with_capacity(1024) }
  }

  /// Push a scalar onto the transcript.
  pub fn push_scalar(&mut self, scalar: impl PrimeField) {
    self.digest.update([SCALAR]);
    let bytes = scalar.to_repr();
    self.digest.update(bytes);
    self.transcript.extend(bytes.as_ref());
  }

  /// Push a point onto the transcript.
  pub fn push_point(&mut self, point: impl GroupEncoding) {
    self.digest.update([POINT]);
    let bytes = point.to_bytes();
    self.digest.update(bytes);
    self.transcript.extend(bytes.as_ref());
  }

  /// Write the Pedersen (vector) commitments to this transcript.
  pub fn write_commitments<C: Ciphersuite>(
    &mut self,
    C: Vec<C::G>,
    V: Vec<C::G>,
  ) -> Commitments<C> {
    for C in &C {
      self.push_point(*C);
    }
    for V in &V {
      self.push_point(*V);
    }
    Commitments { C: PointVector(C), V: PointVector(V) }
  }

  /// Sample a challenge.
  pub fn challenge<F: PrimeField>(&mut self) -> F {
    challenge(&mut self.digest)
  }

  /// Complete a transcript, yielding the fully serialized proof.
  pub fn complete(self) -> Vec<u8> {
    self.transcript
  }
}

/// A transcript for verifying proofs.
pub struct VerifierTranscript<'a> {
  digest: Blake2b512,
  transcript: &'a [u8],
}

impl<'a> VerifierTranscript<'a> {
  /// Create a new transcript to verify a proof with.
  pub fn new(context: [u8; 32], proof: &'a [u8]) -> Self {
    let mut digest = Blake2b512::new();
    digest.update(context);
    Self { digest, transcript: proof }
  }

  /// Read a scalar from the transcript.
  pub fn read_scalar<C: Ciphersuite>(&mut self) -> io::Result<C::F> {
    let scalar = C::read_F(&mut self.transcript)?;
    self.digest.update([SCALAR]);
    let bytes = scalar.to_repr();
    self.digest.update(bytes);
    Ok(scalar)
  }

  /// Read a point from the transcript.
  pub fn read_point<C: Ciphersuite>(&mut self) -> io::Result<C::G> {
    let point = C::read_G(&mut self.transcript)?;
    self.digest.update([POINT]);
    let bytes = point.to_bytes();
    self.digest.update(bytes);
    Ok(point)
  }

  /// Read the Pedersen (Vector) Commitments from the transcript.
  ///
  /// The lengths of the vectors are not transcripted.
  #[allow(clippy::type_complexity)]
  pub fn read_commitments<C: Ciphersuite>(
    &mut self,
    C: usize,
    V: usize,
  ) -> io::Result<Commitments<C>> {
    let mut C_vec = Vec::with_capacity(C);
    for _ in 0 .. C {
      C_vec.push(self.read_point::<C>()?);
    }
    let mut V_vec = Vec::with_capacity(V);
    for _ in 0 .. V {
      V_vec.push(self.read_point::<C>()?);
    }
    Ok(Commitments { C: PointVector(C_vec), V: PointVector(V_vec) })
  }

  /// Sample a challenge.
  pub fn challenge<F: PrimeField>(&mut self) -> F {
    challenge(&mut self.digest)
  }

  /// Complete the transcript, returning the advanced slice.
  pub fn complete(self) -> &'a [u8] {
    self.transcript
  }
}
