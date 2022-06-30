use group::{ff::PrimeField, Group};

fn prep<G: Group>(pairs: &[(G::Scalar, G)], little: bool) -> (Vec<Vec<u8>>, Vec<G>) {
  let mut res = vec![];
  let mut points = vec![];
  for pair in pairs {
    let p = res.len();
    res.push(vec![]);
    {
      let mut repr = pair.0.to_repr();
      let bytes = repr.as_mut();
      if !little {
        bytes.reverse();
      }

      res[p].resize(bytes.len(), 0);
      for i in 0 .. bytes.len() {
        res[p][i] = bytes[i];
      }
    }

    points.push(pair.1);
  }

  (res, points)
}

pub(crate) fn pippenger<G: Group>(pairs: &[(G::Scalar, G)], little: bool) -> G {
  let (bytes, points) = prep(pairs, little);

  let mut res = G::identity();
  for n in (0 .. bytes[0].len()).rev() {
    for _ in 0 .. 8 {
      res = res.double();
    }

    let mut buckets = [G::identity(); 256];
    for p in 0 .. bytes.len() {
      buckets[usize::from(bytes[p][n])] += points[p];
    }

    let mut intermediate_sum = G::identity();
    for b in (1 .. buckets.len()).rev() {
      intermediate_sum += buckets[b];
      res += intermediate_sum;
    }
  }

  res
}

pub(crate) fn pippenger_vartime<G: Group>(pairs: &[(G::Scalar, G)], little: bool) -> G {
  let (bytes, points) = prep(pairs, little);

  let mut res = G::identity();
  for n in (0 .. bytes[0].len()).rev() {
    if n != (bytes[0].len() - 1) {
      for _ in 0 .. 8 {
        res = res.double();
      }
    }

    let mut buckets = [G::identity(); 256];
    for p in 0 .. bytes.len() {
      let nibble = usize::from(bytes[p][n]);
      if nibble != 0 {
        buckets[nibble] += points[p];
      }
    }

    let mut intermediate_sum = G::identity();
    for b in (1 .. buckets.len()).rev() {
      intermediate_sum += buckets[b];
      res += intermediate_sum;
    }
  }

  res
}
