use std::io;
use std::io::{Read, Write};


use curve25519_dalek::scalar::Scalar;

use crate::{
  serialize::*,
};

/// MLSAG signature, as used in Monero.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mlsag {
  pub ss: Vec<Vec<Scalar>>,
  pub cc: Scalar,
}

impl Mlsag {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for ss in self.ss.iter() {
      write_raw_vec(write_scalar, ss, w)?;
    }
    write_scalar(&self.cc, w)
  }

  pub fn read<R: Read>(mixins: usize, ss2_elements: usize, r: &mut R) -> io::Result<Mlsag> {
    Ok(Mlsag {
      ss: (0 .. mixins)
        .map(|_| read_raw_vec(read_scalar, ss2_elements, r))
        .collect::<Result<_, _>>()?,
      cc: read_scalar(r)?,
    })
  }
}
