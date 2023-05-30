use std::io;
use std::io::{Read, Write};

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use crate::{
  Commitment, random_scalar, hash_to_scalar, wallet::decoys::Decoys, ringct::hash_to_point,
  serialize::*,
};

/// MLSAG signature, as used in Monero.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mlsag {
  pub ss: Vec<Vec<Scalar>>,
  pub cc: EdwardsPoint,
}

impl Mlsag {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for ss in self.ss.iter() {
      write_raw_vec(write_scalar, ss, w)?;
    }
    write_point(&self.cc, w)
  }

  pub fn read<R: Read>(decoys: usize, elements: usize, r: &mut R) -> io::Result<Mlsag> {
    Ok(Mlsag {
      ss: (0 .. decoys)
        .map(|_| read_raw_vec(read_scalar, elements, r))
        .collect::<Result<_, _>>()?,
      cc: read_point(r)?,
    })
  }
}
