#![allow(non_snake_case)]

use std::fmt::Debug;
use std::io::{self, Read, Write};

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use crate::serialize::*;

fn read_64_array<R: Read, T: Debug, F: Fn(&mut R) -> io::Result<T>>(
  f: F,
  r: &mut R,
) -> io::Result<[T; 64]> {
  (0 .. 64).map(|_| f(r)).collect::<io::Result<Vec<T>>>().map(|vec| vec.try_into().unwrap())
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BorroSig {
  pub s0: [[u8; 32]; 64],
  pub s1: [[u8; 32]; 64],
  pub ee: [u8; 32],
}

impl BorroSig {
  pub fn read<R: Read>(r: &mut R) -> io::Result<BorroSig> {
    Ok(BorroSig {
      s0: read_64_array(read_bytes, r)?,
      s1: read_64_array(read_bytes, r)?,
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
    Ok(RangeSig { asig: BorroSig::read(r)?, Ci: read_64_array(read_point, r)? })
  }
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.asig.write(w)?;
    write_raw_vec(write_point, &self.Ci, w)
  }
}
