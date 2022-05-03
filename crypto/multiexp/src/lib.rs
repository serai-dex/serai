use ff::PrimeField;
use group::{Group, GroupEncoding, ScalarMul};

// An implementation of Straus, with a extremely minimal API that lets us add other algorithms in
// the future. Takes in a list of scalars and points with a boolean for if the scalars are little
// endian encoded or not
pub fn multiexp_vartime<F: PrimeField, G: Group + GroupEncoding + ScalarMul<F>>(
  scalars: &[F],
  points: &[G],
  little: bool
) -> G {
  let mut tables = vec![];
  // dalek uses 8 in their impl, along with a carry scheme where values are [-8, 8)
  // Moving to a similar system here did save a marginal amount, yet not one significant enough for
  // its pain (as some fields do have scalars which can have their top bit set, a scenario dalek
  // assumes is never true)
  tables.resize(points.len(), [G::identity(); 16]);
  for p in 0 .. points.len() {
    let mut accum = G::identity();
    for i in 1 .. 16 {
      accum += points[p];
      tables[p][i] = accum;
    }
  }

  let mut nibbles = vec![];
  nibbles.resize(scalars.len(), vec![]);
  for s in 0 .. scalars.len() {
    let mut repr = scalars[s].to_repr();
    let bytes = repr.as_mut();
    if !little {
      bytes.reverse();
    }

    nibbles[s].resize(bytes.len() * 2, 0);
    for i in 0 .. bytes.len() {
      nibbles[s][i * 2] = bytes[i] & 0b1111;
      nibbles[s][(i * 2) + 1] = (bytes[i] >> 4) & 0b1111;
    }
  }

  let mut res = G::identity();
  for b in (0 .. nibbles[0].len()).rev() {
    for _ in 0 .. 4 {
      res = res.double();
    }

    for s in 0 .. scalars.len() {
      if nibbles[s][b] != 0 {
        res += tables[s][nibbles[s][b] as usize];
      }
    }
  }
  res
}
