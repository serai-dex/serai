#![allow(non_snake_case)]

use std::fmt::Debug;
use std::io::{self, Read, Write};

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use monero_generators::H2;

use crate::hash_to_scalar;
use crate::serialize::*;

/// A Borromean signature.
///
/// Note: This type keeps the data as raw bytes as Monero has
/// some transactions with unreduced scalars in this field, we
/// could use `from_bytes_mod_order` but then we would not be able
/// to encode this back into it's original form.
///
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BorroSig {
  pub s0: [[u8; 32]; 64],
  pub s1: [[u8; 32]; 64],
  pub ee: [u8; 32],
}

impl BorroSig {
  pub fn read<R: Read>(r: &mut R) -> io::Result<BorroSig> {
    Ok(BorroSig {
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
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RangeSig {
  pub asig: BorroSig,
  pub Ci: [EdwardsPoint; 64],
}

impl RangeSig {
  pub fn read<R: Read>(r: &mut R) -> io::Result<RangeSig> {
    Ok(RangeSig { asig: BorroSig::read(r)?, Ci: read_array(read_point, r)? })
  }
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.asig.write(w)?;
    write_raw_vec(write_point, &self.Ci, w)
  }

  pub fn verify(&self, commitment: &EdwardsPoint) -> bool {
    let mut P1 = Vec::with_capacity(64);
    let mut P2 = Vec::with_capacity(64);
    let mut bbs0 = Vec::with_capacity(64);
    let mut bbs1 = Vec::with_capacity(64);

    let bbee = Scalar::from_bytes_mod_order(self.asig.ee);

    let mut C_temp = EdwardsPoint::identity();

    for i in 0 .. 64 {
      bbs0.push(Scalar::from_bytes_mod_order(self.asig.s0[i]));
      bbs1.push(Scalar::from_bytes_mod_order(self.asig.s1[i]));

      P1.push(self.Ci[i]);
      P2.push(P1[i] - H2[i]);

      C_temp += P1[i];
    }

    if &C_temp != commitment {
      false
    } else {
      verify_borromean(P1, P2, bbee, bbs0, bbs1)
    }
  }
}

fn verify_borromean(
  P1: Vec<EdwardsPoint>,
  P2: Vec<EdwardsPoint>,
  bbee: Scalar,
  bbs0: Vec<Scalar>,
  bbs1: Vec<Scalar>,
) -> bool {
  let mut LV: Vec<u8> = Vec::with_capacity(2048);
  for i in 0 .. 64 {
    let LL = EdwardsPoint::vartime_double_scalar_mul_basepoint(&bbee, &P1[i], &bbs0[i]);
    let chash = hash_to_scalar(LL.compress().as_bytes());
    let LV_temp = EdwardsPoint::vartime_double_scalar_mul_basepoint(&chash, &P2[i], &bbs1[i]);
    LV.extend(LV_temp.compress().as_bytes());
  }
  let eecomp = hash_to_scalar(&LV);

  eecomp == bbee
}
