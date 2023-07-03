use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "experimental")]
use curve25519_dalek::edwards::EdwardsPoint;

use crate::serialize::*;
#[cfg(feature = "experimental")]
use crate::{hash_to_scalar, ringct::hash_to_point};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mlsag {
  pub ss: Vec<[Scalar; 2]>,
  pub cc: Scalar,
}

impl Mlsag {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for ss in self.ss.iter() {
      write_raw_vec(write_scalar, ss, w)?;
    }
    write_scalar(&self.cc, w)
  }

  pub fn read<R: Read>(mixins: usize, r: &mut R) -> io::Result<Mlsag> {
    Ok(Mlsag {
      ss: (0 .. mixins).map(|_| read_array(read_scalar, r)).collect::<Result<_, _>>()?,
      cc: read_scalar(r)?,
    })
  }

  #[cfg(feature = "experimental")]
  pub fn verify(
    &self,
    msg: &[u8; 32],
    ring: &[[EdwardsPoint; 2]],
    key_image: &EdwardsPoint,
  ) -> bool {
    if ring.is_empty() {
      return false;
    }

    let mut buf = Vec::with_capacity(6 * 32);
    let mut ci = self.cc;
    for (i, ring_member) in ring.iter().enumerate() {
      buf.extend_from_slice(msg);

      #[allow(non_snake_case)]
      let L =
        |r| EdwardsPoint::vartime_double_scalar_mul_basepoint(&ci, &ring_member[r], &self.ss[i][r]);

      buf.extend_from_slice(ring_member[0].compress().as_bytes());
      buf.extend_from_slice(L(0).compress().as_bytes());

      #[allow(non_snake_case)]
      let R = (self.ss[i][0] * hash_to_point(ring_member[0])) + (ci * key_image);
      buf.extend_from_slice(R.compress().as_bytes());

      buf.extend_from_slice(ring_member[1].compress().as_bytes());
      buf.extend_from_slice(L(1).compress().as_bytes());

      ci = hash_to_scalar(&buf);
      buf.clear();
    }

    ci == self.cc
  }
}
