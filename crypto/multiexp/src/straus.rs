use zeroize::Zeroize;

use ff::PrimeFieldBits;
use group::Group;

use crate::prep_bits;

// Create tables for every included point of size 2^window
fn prep_tables<G: Group>(pairs: &[(G::Scalar, G)], window: u8) -> Vec<Vec<G>> {
  let mut tables = Vec::with_capacity(pairs.len());
  for pair in pairs {
    let p = tables.len();
    tables.push(vec![G::identity(); 2_usize.pow(window.into())]);
    let mut accum = G::identity();
    for i in 1 .. tables[p].len() {
      accum += pair.1;
      tables[p][i] = accum;
    }
  }
  tables
}

// Straus's algorithm for multiexponentation, as published in The American Mathematical Monthly
// DOI: 10.2307/2310929
pub(crate) fn straus<G: Group>(pairs: &[(G::Scalar, G)], window: u8) -> G
where
  G::Scalar: PrimeFieldBits + Zeroize,
{
  let mut groupings = prep_bits(pairs, window);
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

  groupings.zeroize();
  res
}

pub(crate) fn straus_vartime<G: Group>(pairs: &[(G::Scalar, G)], window: u8) -> G
where
  G::Scalar: PrimeFieldBits,
{
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
