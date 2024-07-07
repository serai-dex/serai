use std_shims::{
  io::{self, *},
  vec::Vec,
};

use zeroize::Zeroize;

use curve25519_dalek::{EdwardsPoint, Scalar};

use crate::{io::*, generators::hash_to_point, primitives::keccak256_to_scalar};

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
struct Signature {
  c: Scalar,
  s: Scalar,
}

impl Signature {
  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_scalar(&self.c, w)?;
    write_scalar(&self.s, w)?;
    Ok(())
  }

  fn read<R: Read>(r: &mut R) -> io::Result<Signature> {
    Ok(Signature { c: read_scalar(r)?, s: read_scalar(r)? })
  }
}

/// A ring signature.
///
/// This was used by the original Cryptonote transaction protocol and was deprecated with RingCT.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct RingSignature {
  sigs: Vec<Signature>,
}

impl RingSignature {
  /// Write the RingSignature.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for sig in &self.sigs {
      sig.write(w)?;
    }
    Ok(())
  }

  /// Read a RingSignature.
  pub fn read<R: Read>(members: usize, r: &mut R) -> io::Result<RingSignature> {
    Ok(RingSignature { sigs: read_raw_vec(Signature::read, members, r)? })
  }

  /// Verify the ring signature.
  pub fn verify(&self, msg: &[u8; 32], ring: &[EdwardsPoint], key_image: &EdwardsPoint) -> bool {
    if ring.len() != self.sigs.len() {
      return false;
    }

    let mut buf = Vec::with_capacity(32 + (2 * 32 * ring.len()));
    buf.extend_from_slice(msg);

    let mut sum = Scalar::ZERO;
    for (ring_member, sig) in ring.iter().zip(&self.sigs) {
      /*
        The traditional Schnorr signature is:
          r = sample()
          c = H(r G || m)
          s = r - c x
        Verified as:
          s G + c A == R

        Each ring member here performs a dual-Schnorr signature for:
          s G + c A
          s HtP(A) + c K
        Where the transcript is pushed both these values, r G, r HtP(A) for the real spend.
        This also serves as a DLEq proof between the key and the key image.

        Checking sum(c) == H(transcript) acts a disjunction, where any one of the `c`s can be
        modified to cause the intended sum, if and only if a corresponding `s` value is known.
      */

      #[allow(non_snake_case)]
      let Li = EdwardsPoint::vartime_double_scalar_mul_basepoint(&sig.c, ring_member, &sig.s);
      buf.extend_from_slice(Li.compress().as_bytes());
      #[allow(non_snake_case)]
      let Ri = (sig.s * hash_to_point(ring_member.compress().to_bytes())) + (sig.c * key_image);
      buf.extend_from_slice(Ri.compress().as_bytes());

      sum += sig.c;
    }
    sum == keccak256_to_scalar(buf)
  }
}
