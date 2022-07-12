use ff::PrimeFieldBits;
use group::Group;

use crate::{prep_bits, prep_tables};

pub(crate) fn straus<G: Group>(
  pairs: &[(G::Scalar, G)],
  window: u8
) -> G where G::Scalar: PrimeFieldBits {
  let groupings = prep_bits(pairs, window);
  let tables = prep_tables(pairs, window);

  let mut res = G::identity();
  for b in (0 .. groupings[0].len()).rev() {
    for _ in 0 .. window {
      res = res.double();
    }

    for s in 0 .. tables.len() {
      res += tables[s][usize::from(groupings[s][b])];
    }
  }
  res
}

pub(crate) fn straus_vartime<G: Group>(
  pairs: &[(G::Scalar, G)],
  window: u8
) -> G where G::Scalar: PrimeFieldBits {
  let groupings = prep_bits(pairs, window);
  let tables = prep_tables(pairs, window);

  let mut res = G::identity();
  for b in (0 .. groupings[0].len()).rev() {
    if b != (groupings[0].len() - 1) {
      for _ in 0 .. window {
        res = res.double();
      }
    }

    for s in 0 .. tables.len() {
      if groupings[s][b] != 0 {
        res += tables[s][usize::from(groupings[s][b])];
      }
    }
  }

  res
}
