use std_shims::{vec::Vec, io};

use blake2::{Digest, Blake2b512};

use ciphersuite::{
  group::{
    ff::{Field, PrimeField},
    GroupEncoding,
  },
  Ciphersuite,
};

use crate::PointVector;

const SCALAR: u8 = 0;
const POINT: u8 = 1;
const CHALLENGE: u8 = 2;

fn challenge<C: Ciphersuite>(digest: &mut Blake2b512) -> C::F {
  digest.update([CHALLENGE]);
  let chl = digest.clone().finalize().into();

  let res = C::reduce_512(chl);

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
  ///
  /// The order and layout of this must be constant to the context.
  pub fn push_scalar(&mut self, scalar: impl PrimeField) {
    self.digest.update([SCALAR]);
    let bytes = scalar.to_repr();
    self.digest.update(bytes);
    self.transcript.extend(bytes.as_ref());
  }

  /// Push a point onto the transcript.
  ///
  /// The order and layout of this must be constant to the context.
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
    self.digest.update(u32::try_from(C.len()).unwrap().to_le_bytes());
    for C in &C {
      self.push_point(*C);
    }
    self.digest.update(u32::try_from(V.len()).unwrap().to_le_bytes());
    for V in &V {
      self.push_point(*V);
    }
    Commitments { C: PointVector(C), V: PointVector(V) }
  }

  /// Sample a challenge.
  pub fn challenge<C: Ciphersuite>(&mut self) -> C::F {
    challenge::<C>(&mut self.digest)
  }

  /// Sample a challenge as a byte array.
  pub fn challenge_bytes(&mut self) -> [u8; 64] {
    self.digest.update([CHALLENGE]);
    self.digest.clone().finalize().into()
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
  ///
  /// The order and layout of this must be constant to the context.
  pub fn read_scalar<C: Ciphersuite>(&mut self) -> io::Result<C::F> {
    // Read the scalar onto the transcript using the serialization present in the transcript
    self.digest.update([SCALAR]);
    let scalar_len = <C::F as PrimeField>::Repr::default().as_ref().len();
    if self.transcript.len() < scalar_len {
      Err(io::Error::new(io::ErrorKind::Other, "not enough bytes to read_scalar"))?;
    }
    self.digest.update(&self.transcript[.. scalar_len]);

    // Read the actual scalar, where `read_F` ensures its canonically serialized
    let scalar = C::read_F(&mut self.transcript)?;
    Ok(scalar)
  }

  /// Read a point from the transcript.
  ///
  /// The order and layout of this must be constant to the context.
  pub fn read_point<C: Ciphersuite>(&mut self) -> io::Result<C::G> {
    // Read the point onto the transcript using the serialization present in the transcript
    self.digest.update([POINT]);
    let point_len = <C::G as GroupEncoding>::Repr::default().as_ref().len();
    if self.transcript.len() < point_len {
      Err(io::Error::new(io::ErrorKind::Other, "not enough bytes to read_point"))?;
    }
    self.digest.update(&self.transcript[.. point_len]);

    // Read the actual point, where `read_G` ensures its canonically serialized
    let point = C::read_G(&mut self.transcript)?;
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
    self.digest.update(u32::try_from(C).unwrap().to_le_bytes());
    let mut C_vec = Vec::with_capacity(C);
    for _ in 0 .. C {
      C_vec.push(self.read_point::<C>()?);
    }
    self.digest.update(u32::try_from(V).unwrap().to_le_bytes());
    let mut V_vec = Vec::with_capacity(V);
    for _ in 0 .. V {
      V_vec.push(self.read_point::<C>()?);
    }
    Ok(Commitments { C: PointVector(C_vec), V: PointVector(V_vec) })
  }

  /// Sample a challenge.
  pub fn challenge<C: Ciphersuite>(&mut self) -> C::F {
    challenge::<C>(&mut self.digest)
  }

  /// Sample a challenge as a byte array.
  pub fn challenge_bytes(&mut self) -> [u8; 64] {
    self.digest.update([CHALLENGE]);
    self.digest.clone().finalize().into()
  }

  /// Complete the transcript transcript, yielding what remains.
  pub fn complete(self) -> &'a [u8] {
    self.transcript
  }
}
