use std_shims::io::{self, *};

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use dalek_ff_group::ED25519_BASEPOINT_TABLE;

use monero_generators::hash_to_point;

use crate::{serialize::*, hash_to_scalar};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature {
  c: Scalar,
  r: Scalar,
}

impl Signature {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_scalar(&self.c, w)?;
    write_scalar(&self.r, w)?;
    Ok(())
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<Signature> {
    Ok(Signature { c: read_scalar(r)?, r: read_scalar(r)? })
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingSignature {
  sigs: Vec<Signature>,
}

impl RingSignature {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for sig in &self.sigs {
      sig.write(w)?;
    }
    Ok(())
  }

  pub fn read<R: Read>(members: usize, r: &mut R) -> io::Result<RingSignature> {
    Ok(RingSignature { sigs: read_raw_vec(Signature::read, members, r)? })
  }

  pub fn verify_ring_signature(
    &self,
    msg: &[u8; 32],
    ring: &[EdwardsPoint],
    key_image: &EdwardsPoint,
  ) -> bool {
    let mut buf = Vec::with_capacity(32 + 32 * 2 * ring.len());
    buf.extend_from_slice(msg);

    let mut sum = Scalar::ZERO;

    for (ring_member, sig) in ring.iter().zip(&self.sigs) {
      #[allow(non_snake_case)]
      let Li = &sig.r * ED25519_BASEPOINT_TABLE + sig.c * ring_member;
      buf.extend_from_slice(Li.compress().as_bytes());
      #[allow(non_snake_case)]
      let Ri = sig.r * hash_to_point(ring_member.compress().to_bytes()) + sig.c * key_image;
      buf.extend_from_slice(Ri.compress().as_bytes());

      sum += sig.c;
    }

    sum == hash_to_scalar(&buf)
  }
}
