use core::fmt::Debug;
use std_shims::io::{self, Read, Write};

use curve25519_dalek::edwards::EdwardsPoint;
#[cfg(feature = "experimental")]
use curve25519_dalek::{traits::Identity, scalar::Scalar};

#[cfg(feature = "experimental")]
use monero_generators::H_pow_2;
#[cfg(feature = "experimental")]
use crate::hash_to_scalar;
use crate::serialize::*;

/// 64 Borromean ring signatures.
///
/// This type keeps the data as raw bytes as Monero has some transactions with unreduced scalars in
/// this field. While we could use `from_bytes_mod_order`, we'd then not be able  to encode this
/// back into it's original form.
///
/// Those scalars also have a custom reduction algorithm...
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BorromeanSignatures {
  pub s0: [[u8; 32]; 64],
  pub s1: [[u8; 32]; 64],
  pub ee: [u8; 32],
}

impl BorromeanSignatures {
  pub fn read<R: Read>(r: &mut R) -> io::Result<BorromeanSignatures> {
    Ok(BorromeanSignatures {
      s0: read_array(read_bytes, r)?,
      s1: read_array(read_bytes, r)?,
      ee: read_bytes(r)?,
    })
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for s0 in self.s0.iter() {
      w.write_all(s0)?;
    }
    for s1 in self.s1.iter() {
      w.write_all(s1)?;
    }
    w.write_all(&self.ee)
  }

  #[cfg(feature = "experimental")]
  fn verify(&self, keys_a: &[EdwardsPoint], keys_b: &[EdwardsPoint]) -> bool {
    let mut transcript = [0; 2048];
    for i in 0 .. 64 {
      // TODO: These aren't the correct reduction
      // TODO: Can either of these be tightened?
      #[allow(non_snake_case)]
      let LL = EdwardsPoint::vartime_double_scalar_mul_basepoint(
        &Scalar::from_bytes_mod_order(self.ee),
        &keys_a[i],
        &Scalar::from_bytes_mod_order(self.s0[i]),
      );
      #[allow(non_snake_case)]
      let LV = EdwardsPoint::vartime_double_scalar_mul_basepoint(
        &hash_to_scalar(LL.compress().as_bytes()),
        &keys_b[i],
        &Scalar::from_bytes_mod_order(self.s1[i]),
      );
      transcript[i .. ((i + 1) * 32)].copy_from_slice(LV.compress().as_bytes());
    }

    // TODO: This isn't the correct reduction
    // TODO: Can this be tightened to from_canonical_bytes?
    hash_to_scalar(&transcript) == Scalar::from_bytes_mod_order(self.ee)
  }
}

/// A range proof premised on Borromean ring signatures.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BorromeanRange {
  pub sigs: BorromeanSignatures,
  pub bit_commitments: [EdwardsPoint; 64],
}

impl BorromeanRange {
  pub fn read<R: Read>(r: &mut R) -> io::Result<BorromeanRange> {
    Ok(BorromeanRange {
      sigs: BorromeanSignatures::read(r)?,
      bit_commitments: read_array(read_point, r)?,
    })
  }
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.sigs.write(w)?;
    write_raw_vec(write_point, &self.bit_commitments, w)
  }

  #[cfg(feature = "experimental")]
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
