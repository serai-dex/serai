use group::{ff::PrimeField, Group};

fn prep<G: Group>(pairs: &[(G::Scalar, G)], little: bool) -> (Vec<Vec<u8>>, Vec<[G; 16]>) {
  let mut nibbles = vec![];
  let mut tables = vec![];
  for pair in pairs {
    let p = nibbles.len();
    nibbles.push(vec![]);
    {
      let mut repr = pair.0.to_repr();
      let bytes = repr.as_mut();
      if !little {
        bytes.reverse();
      }

      nibbles[p].resize(bytes.len() * 2, 0);
      for i in 0 .. bytes.len() {
        nibbles[p][i * 2] = bytes[i] & 0b1111;
        nibbles[p][(i * 2) + 1] = (bytes[i] >> 4) & 0b1111;
      }
    }

    tables.push([G::identity(); 16]);
    let mut accum = G::identity();
    for i in 1 .. 16 {
      accum += pair.1;
      tables[p][i] = accum;
    }
  }

  (nibbles, tables)
}

pub(crate) fn straus<G: Group>(pairs: &[(G::Scalar, G)], little: bool) -> G {
  let (nibbles, tables) = prep(pairs, little);

  let mut res = G::identity();
  for b in (0 .. nibbles[0].len()).rev() {
    for _ in 0 .. 4 {
      res = res.double();
    }

    for s in 0 .. tables.len() {
      res += tables[s][usize::from(nibbles[s][b])];
    }
  }
  res
}

pub(crate) fn straus_vartime<G: Group>(pairs: &[(G::Scalar, G)], little: bool) -> G {
  let (nibbles, tables) = prep(pairs, little);

  let mut res = G::identity();
  for b in (0 .. nibbles[0].len()).rev() {
    if b != (nibbles[0].len() - 1) {
      for _ in 0 .. 4 {
        res = res.double();
      }
    }

    for s in 0 .. tables.len() {
      if nibbles[s][b] != 0 {
        res += tables[s][usize::from(nibbles[s][b])];
      }
    }
  }

  res
}
