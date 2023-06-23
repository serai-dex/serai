#![allow(non_snake_case)]

use std::io;
use std::io::{Read, Write};

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::EdwardsPoint;

use crate::{hash_to_scalar, serialize::*};
use crate::ringct::hash_to_point;

/// MgSig part of MLSAG, as used in Monero.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MgSig {
  pub ss: Vec<[Scalar; 2]>,
  pub cc: Scalar,
}

impl MgSig {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for ss in self.ss.iter() {
      write_raw_vec(write_scalar, ss, w)?;
    }
    write_scalar(&self.cc, w)
  }

  pub fn read<R: Read>(mixins: usize, r: &mut R) -> io::Result<MgSig> {
    Ok(MgSig {
      ss: (0 .. mixins).map(|_| read_array(read_scalar, r)).collect::<Result<_, _>>()?,
      cc: read_scalar(r)?,
    })
  }

  pub fn verify(&self, msg: &[u8; 32], ring: &[[EdwardsPoint; 2]], I: &EdwardsPoint) -> bool {
    let mut buf = Vec::with_capacity(32 * 6);

    let mut ci = self.cc;

    for (i, ring_member) in ring.iter().enumerate() {
      buf.extend_from_slice(msg);
      buf.extend_from_slice(ring_member[0].compress().as_bytes());

      let L1 =
        EdwardsPoint::vartime_double_scalar_mul_basepoint(&ci, &ring_member[0], &self.ss[i][0]);
      buf.extend_from_slice(L1.compress().as_bytes());

      let temp = hash_to_point(ring_member[0]);

      let R = self.ss[i][0] * temp + ci * I;
      buf.extend_from_slice(R.compress().as_bytes());

      buf.extend_from_slice(ring_member[1].compress().as_bytes());

      let L2 =
        EdwardsPoint::vartime_double_scalar_mul_basepoint(&ci, &ring_member[1], &self.ss[i][1]);
      buf.extend_from_slice(L2.compress().as_bytes());

      ci = hash_to_scalar(&buf);
      buf.clear();
    }

    ci == self.cc
  }
}
