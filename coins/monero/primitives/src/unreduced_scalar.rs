use core::cmp::Ordering;
use std_shims::{
  sync::OnceLock,
  io::{self, *},
};

use zeroize::Zeroize;

use curve25519_dalek::scalar::Scalar;

use monero_io::*;

static PRECOMPUTED_SCALARS_CELL: OnceLock<[Scalar; 8]> = OnceLock::new();
// Precomputed scalars used to recover an incorrectly reduced scalar.
#[allow(non_snake_case)]
fn PRECOMPUTED_SCALARS() -> [Scalar; 8] {
  *PRECOMPUTED_SCALARS_CELL.get_or_init(|| {
    let mut precomputed_scalars = [Scalar::ONE; 8];
    for (i, scalar) in precomputed_scalars.iter_mut().enumerate().skip(1) {
      *scalar = Scalar::from(u8::try_from((i * 2) + 1).unwrap());
    }
    precomputed_scalars
  })
}

/// An unreduced scalar.
///
/// While most of modern Monero enforces scalars be reduced, certain legacy parts of the code did
/// not. These section can generally simply be read as a scalar/reduced into a scalar when the time
/// comes, yet a couple have non-standard reductions performed.
///
/// This struct delays scalar conversions and offers the non-standard reduction.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct UnreducedScalar(pub [u8; 32]);

impl UnreducedScalar {
  /// Write an UnreducedScalar.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.0)
  }

  /// Read an UnreducedScalar.
  pub fn read<R: Read>(r: &mut R) -> io::Result<UnreducedScalar> {
    Ok(UnreducedScalar(read_bytes(r)?))
  }

  fn as_bits(&self) -> [u8; 256] {
    let mut bits = [0; 256];
    for (i, bit) in bits.iter_mut().enumerate() {
      *bit = core::hint::black_box(1 & (self.0[i / 8] >> (i % 8)))
    }

    bits
  }

  // Computes the non-adjacent form of this scalar with width 5.
  //
  // This matches Monero's `slide` function and intentionally gives incorrect outputs under
  // certain conditions in order to match Monero.
  //
  // This function does not execute in constant time.
  fn non_adjacent_form(&self) -> [i8; 256] {
    let bits = self.as_bits();
    let mut naf = [0i8; 256];
    for (b, bit) in bits.into_iter().enumerate() {
      naf[b] = i8::try_from(bit).unwrap();
    }

    for i in 0 .. 256 {
      if naf[i] != 0 {
        // if the bit is a one, work our way up through the window
        // combining the bits with this bit.
        for b in 1 .. 6 {
          if (i + b) >= 256 {
            // if we are at the length of the array then break out
            // the loop.
            break;
          }
          // potential_carry - the value of the bit at i+b compared to the bit at i
          let potential_carry = naf[i + b] << b;

          if potential_carry != 0 {
            if (naf[i] + potential_carry) <= 15 {
              // if our current "bit" plus the potential carry is less than 16
              // add it to our current "bit" and set the potential carry bit to 0.
              naf[i] += potential_carry;
              naf[i + b] = 0;
            } else if (naf[i] - potential_carry) >= -15 {
              // else if our current "bit" minus the potential carry is more than -16
              // take it away from our current "bit".
              // we then work our way up through the bits setting ones to zero, when
              // we hit the first zero we change it to one then stop, this is to factor
              // in the minus.
              naf[i] -= potential_carry;
              #[allow(clippy::needless_range_loop)]
              for k in (i + b) .. 256 {
                if naf[k] == 0 {
                  naf[k] = 1;
                  break;
                }
                naf[k] = 0;
              }
            } else {
              break;
            }
          }
        }
      }
    }

    naf
  }

  /// Recover the scalar that an array of bytes was incorrectly interpreted as by Monero's `slide`
  /// function.
  ///
  /// In Borromean range proofs, Monero was not checking that the scalars used were
  /// reduced. This lead to the scalar stored being interpreted as a different scalar.
  /// This function recovers that scalar.
  ///
  /// See https://github.com/monero-project/monero/issues/8438 for more info.
  pub fn recover_monero_slide_scalar(&self) -> Scalar {
    if self.0[31] & 128 == 0 {
      // Computing the w-NAF of a number can only give an output with 1 more bit than
      // the number, so even if the number isn't reduced, the `slide` function will be
      // correct when the last bit isn't set.
      return Scalar::from_bytes_mod_order(self.0);
    }

    let precomputed_scalars = PRECOMPUTED_SCALARS();

    let mut recovered = Scalar::ZERO;
    for &numb in self.non_adjacent_form().iter().rev() {
      recovered += recovered;
      match numb.cmp(&0) {
        Ordering::Greater => recovered += precomputed_scalars[usize::try_from(numb).unwrap() / 2],
        Ordering::Less => recovered -= precomputed_scalars[usize::try_from(-numb).unwrap() / 2],
        Ordering::Equal => (),
      }
    }
    recovered
  }
}
