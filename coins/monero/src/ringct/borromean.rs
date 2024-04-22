use core::fmt::Debug;
use std_shims::io::{self, Read, Write};

use curve25519_dalek::{traits::Identity, Scalar, EdwardsPoint};

use monero_generators::H_pow_2;

use crate::{hash_to_scalar, unreduced_scalar::UnreducedScalar, serialize::*};

/// 64 Borromean ring signatures, as needed for a 64-bit range proof.
///
/// s0 and s1 are stored as `UnreducedScalar`s due to Monero not requiring they were reduced.
/// `UnreducedScalar` preserves their original byte encoding and implements a custom reduction
/// algorithm which was in use.
#[derive(Clone, PartialEq, Eq, Debug)]
struct BorromeanSignatures {
  s0: [UnreducedScalar; 64],
  s1: [UnreducedScalar; 64],
  ee: Scalar,
}

impl BorromeanSignatures {
  /// Read a set of BorromeanSignatures from a reader.
  fn read<R: Read>(r: &mut R) -> io::Result<BorromeanSignatures> {
    Ok(BorromeanSignatures {
      s0: read_array(UnreducedScalar::read, r)?,
      s1: read_array(UnreducedScalar::read, r)?,
      ee: read_scalar(r)?,
    })
  }

  /// Write the set of BorromeanSignatures to a writer.
  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for s0 in &self.s0 {
      s0.write(w)?;
    }
    for s1 in &self.s1 {
      s1.write(w)?;
    }
    write_scalar(&self.ee, w)
  }

  fn verify(&self, keys_a: &[EdwardsPoint], keys_b: &[EdwardsPoint]) -> bool {
    let mut transcript = [0; 2048];

    for i in 0 .. 64 {
      #[allow(non_snake_case)]
      let LL = EdwardsPoint::vartime_double_scalar_mul_basepoint(
        &self.ee,
        &keys_a[i],
        &self.s0[i].recover_monero_slide_scalar(),
      );
      #[allow(non_snake_case)]
      let LV = EdwardsPoint::vartime_double_scalar_mul_basepoint(
        &hash_to_scalar(LL.compress().as_bytes()),
        &keys_b[i],
        &self.s1[i].recover_monero_slide_scalar(),
      );
      transcript[(i * 32) .. ((i + 1) * 32)].copy_from_slice(LV.compress().as_bytes());
    }

    hash_to_scalar(&transcript) == self.ee
  }
}

/// A range proof premised on Borromean ring signatures.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BorromeanRange {
  sigs: BorromeanSignatures,
  bit_commitments: [EdwardsPoint; 64],
}

impl BorromeanRange {
  /// Read a BorromeanRange proof from a reader.
  pub fn read<R: Read>(r: &mut R) -> io::Result<BorromeanRange> {
    Ok(BorromeanRange {
      sigs: BorromeanSignatures::read(r)?,
      bit_commitments: read_array(read_point, r)?,
    })
  }

  /// Write the BorromeanRange proof to a reader.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.sigs.write(w)?;
    write_raw_vec(write_point, &self.bit_commitments, w)
  }

  /// Verify the commitment contains a 64-bit value.
  pub fn verify(&self, commitment: &EdwardsPoint) -> bool {
    if &self.bit_commitments.iter().sum::<EdwardsPoint>() != commitment {
      return false;
    }

    #[allow(non_snake_case)]
    let H_pow_2 = H_pow_2();
    let mut commitments_sub_one = [EdwardsPoint::identity(); 64];
    for i in 0 .. 64 {
      commitments_sub_one[i] = self.bit_commitments[i] - H_pow_2[i];
    }

    self.sigs.verify(&self.bit_commitments, &commitments_sub_one)
  }
}
