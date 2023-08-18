use std_shims::io::{self, *};
use std_shims::sync::OnceLock;

use curve25519_dalek::scalar::Scalar;

use crate::serialize::*;

static PRECOMPUTED_SCALARS_CELL: OnceLock<[Scalar; 8]> = OnceLock::new();
/// Precomputed scalars used to recover an incorrectly reduced scalar
#[allow(non_snake_case)]
pub fn PRECOMPUTED_SCALARS() -> [Scalar; 8] {
  *PRECOMPUTED_SCALARS_CELL.get_or_init(|| {
    let mut precomputed_scalars = [Scalar::one(); 8];
    for i in 1 .. 8 {
      precomputed_scalars[i] = Scalar::from((i * 2 + 1) as u8);
    }
    precomputed_scalars
  })
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnreducedScalar([u8; 32]);

impl UnreducedScalar {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.0)
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<UnreducedScalar> {
    Ok(UnreducedScalar(read_bytes(r)?))
  }

  pub fn as_bytes(&self) -> &[u8; 32] {
    &self.0
  }

  pub fn reduce_mod_order(&self) -> Scalar {
    Scalar::from_bytes_mod_order(self.0)
  }

  fn as_bits(&self) -> [i8; 256] {
    let mut bits = [0; 256];
    for i in 0 .. 256 {
      bits[i] = 1 & (self.0[i >> 3] >> (i & 7)) as i8
    }

    bits
  }

  fn non_adjacent_form(&self) -> [i8; 256] {
    let mut bits = self.as_bits();

    for i in 0 .. 256 {
      if bits[i] != 0 {
        for b in 1 .. 6 {
          if i + b >= 256 {
            break;
          }
          if bits[i + b] != 0 {
            if bits[i] + (bits[i + b] << b) <= 15 {
              bits[i] += bits[i + b] << b;
              bits[i + b] = 0;
            } else if bits[i] - (bits[i + b] << b) >= -15 {
              bits[i] -= bits[i + b] << b;
              for k in i + b .. 256 {
                if bits[k] == 0 {
                  bits[k] = 1;
                  break;
                }
                bits[k] = 0;
              }
            } else {
              break;
            }
          }
        }
      }
    }

    bits
  }

  /// Recover the scalar that an array of bytes was incorrectly interpreted as.
  ///
  /// In Borromean range proofs Monero was not checking that the scalars used were
  /// reduced. This lead to the scalar stored being interpreted as a different scalar,
  /// this function recovers that scalar.
  ///
  /// See: https://github.com/monero-project/monero/issues/8438
  pub fn recover_monero_slide_scalar(&self) -> Scalar {
    if self.0[31] & 128 == 0 {
      // Computing the w-NAF of a number can only give an output with 1 more bit than
      // the number so even if the number isn't reduced the `slide` function will be
      // correct when the last bit isn't set.
      return self.reduce_mod_order();
    }

    let naf = self.non_adjacent_form();

    let precomputed_scalars = PRECOMPUTED_SCALARS();

    let mut recovered = Scalar::zero();

    for &numb in naf.iter().rev() {
      recovered += recovered;

      if numb > 0 {
        recovered += precomputed_scalars[numb as usize / 2];
      } else if numb < 0 {
        recovered -= precomputed_scalars[(-numb) as usize / 2];
      }
    }

    recovered
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn recover_scalars() {
    let test_recover = |stored: &str, recovered: &str| {
      let stored = UnreducedScalar(hex::decode(stored).unwrap().try_into().unwrap());
      let recovered =
        Scalar::from_canonical_bytes(hex::decode(recovered).unwrap().try_into().unwrap()).unwrap();
      assert_eq!(stored.recover_monero_slide_scalar(), recovered);
    };

    // https://www.moneroinflation.com/static/data_py/report_scalars_df.pdf
    // Table 4.
    test_recover(
      "cb2be144948166d0a9edb831ea586da0c376efa217871505ad77f6ff80f203f8",
      "b8ffd6a1aee47828808ab0d4c8524cb5c376efa217871505ad77f6ff80f20308",
    );
    test_recover(
      "343d3df8a1051c15a400649c423dc4ed58bef49c50caef6ca4a618b80dee22f4",
      "21113355bc682e6d7a9d5b3f2137a30259bef49c50caef6ca4a618b80dee2204",
    );
    test_recover(
      "c14f75d612800ca2c1dcfa387a42c9cc086c005bc94b18d204dd61342418eba7",
      "4f473804b1d27ab2c789c80ab21d034a096c005bc94b18d204dd61342418eb07",
    );
    test_recover(
      "000102030405060708090a0b0c0d0e0f826c4f6e2329a31bc5bc320af0b2bcbb",
      "a124cfd387f461bf3719e03965ee6877826c4f6e2329a31bc5bc320af0b2bc0b",
    );
  }

  #[test]
  fn non_adjacent_form() {
    let mut bytes: [u8; 32] = rand::random();
    bytes[31] &= 127;

    let reduced_scalar = Scalar::from_bytes_mod_order(bytes.clone());
    let scalar = UnreducedScalar(bytes);

    let naf = scalar.non_adjacent_form();
    let precomputed_scalars = PRECOMPUTED_SCALARS();

    let mut recovered = Scalar::zero();

    for &numb in naf.iter().rev() {
      recovered += recovered;

      if numb > 0 {
        recovered += precomputed_scalars[numb as usize / 2];
      } else if numb < 0 {
        recovered -= precomputed_scalars[(-numb) as usize / 2];
      }
    }

    assert_eq!(recovered, reduced_scalar)
  }
}
