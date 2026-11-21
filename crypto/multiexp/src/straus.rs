use alloc::{vec, vec::Vec};

use zeroize::Zeroize;
use subtle::{ConstantTimeEq as _, ConditionallySelectable};

use ff::PrimeFieldBits;
use group::Group;

use crate::{prep_bits, split_digit};

// Create tables for every included point of size 2^(window - 1) + 1
fn prep_tables<G: Group>(pairs: &[(G::Scalar, G)], window: u8) -> Vec<Vec<G>> {
  let mut tables = Vec::with_capacity(pairs.len());
  for pair in pairs {
    let p = tables.len();
    tables.push(vec![G::identity(); 2_usize.pow((window - 1).into()) + 1]);
    tables[p][1] = pair.1;
    for i in 2 .. tables[p].len() {
      tables[p][i] =
        if (i % 2) == 0 { tables[p][i / 2].double() } else { tables[p][i - 1] + pair.1 };
    }
  }
  tables
}

// Straus's algorithm for multiexponentiation, as published in The American Mathematical Monthly
// DOI: 10.2307/2310929
pub(crate) fn straus<G: Zeroize + ConditionallySelectable + Group<Scalar: PrimeFieldBits>>(
  pairs: &[(G::Scalar, G)],
  window: u8,
) -> G {
  let mut groupings = prep_bits(pairs, window);
  let mut tables = prep_tables(pairs, window);

  let mut res = G::identity();
  for b in (0 .. groupings[0].len()).rev() {
    if b != (groupings[0].len() - 1) {
      for _ in 0 .. window {
        res = res.double();
      }
    }

    for s in 0 .. tables.len() {
      let (magnitude, negative) = split_digit(groupings[s][b]);
      let mut elem_to_add = G::identity();
      for (i, elem) in tables[s].iter().enumerate().skip(1) {
        elem_to_add.conditional_assign(elem, i.ct_eq(&magnitude));
      }
      elem_to_add.conditional_assign(&-elem_to_add, negative.ct_eq(&1));
      res += elem_to_add;
    }
  }

  groupings.zeroize();
  tables.zeroize();
  res
}

pub(crate) fn straus_vartime<G: Group<Scalar: PrimeFieldBits>>(
  pairs: &[(G::Scalar, G)],
  window: u8,
) -> G {
  let groupings = prep_bits(pairs, window);
  let tables = prep_tables(pairs, window);

  let mut res: Option<G> = None;
  for b in (0 .. groupings[0].len()).rev() {
    if b != (groupings[0].len() - 1) {
      for _ in 0 .. window {
        res = res.map(|res| res.double());
      }
    }

    for s in 0 .. tables.len() {
      let (magnitude, negative) = split_digit(groupings[s][b]);
      if magnitude != 0 {
        let elem = if negative == 1 { -tables[s][magnitude] } else { tables[s][magnitude] };
        if let Some(res) = res.as_mut() {
          *res += elem;
        } else {
          res = Some(elem);
        }
      }
    }
  }

  res.unwrap_or_else(G::identity)
}
