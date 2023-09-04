use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::traits::Identity;

use monero_generators::H;

use crate::serialize::*;
use crate::{hash_to_scalar, ringct::hash_to_point};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mlsag {
  pub ss: Vec<Vec<Scalar>>,
  pub cc: Scalar,
}

impl Mlsag {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for ss in &self.ss {
      write_raw_vec(write_scalar, ss, w)?;
    }
    write_scalar(&self.cc, w)
  }

  pub fn read<R: Read>(mixins: usize, ss_2_elements: usize, r: &mut R) -> io::Result<Mlsag> {
    Ok(Mlsag {
      ss: (0 .. mixins)
        .map(|_| read_raw_vec(read_scalar, ss_2_elements, r))
        .collect::<Result<_, _>>()?,
      cc: read_scalar(r)?,
    })
  }

  /// Verifies an aggregate MLSAG signature, an aggregate signature is over multiple inputs.
  pub fn verify_aggregate(
    &self,
    msg: &[u8; 32],
    rings: &[impl AsRef<[[EdwardsPoint; 2]]>],
    out_pks: &[EdwardsPoint],
    fee: u64,
    key_images: &[&EdwardsPoint],
  ) -> bool {
    // The idea behind the aggregate signature is to add all the inputs commitments and check that
    // when we take the inputs from the outputs we get a commitment to 0. We can't simply sum the
    // decoys as it's only one decoys commitment that is actually being used, so what we do is sum
    // the decoys commitments at the same index, so for a 2 input transaction we sum the first decoy
    // of the first input with the first decoy of the second input continuing for each decoy. We
    // then take away the fee and the sum of outputs from each of those sums.
    //
    // This means that the real spend will be at the same index for each input, hurting privacy.

    let decoys = rings[0].as_ref().len();
    let inputs = rings.len();

    let sum_out_pk = out_pks.iter().sum::<EdwardsPoint>();
    #[allow(non_snake_case)]
    let H_fee = H() * Scalar::from(fee);

    // We start with separate matrix's for keys and commitments.
    let mut key_matrix = vec![vec![EdwardsPoint::identity(); inputs + 1]; decoys];

    for (i, ring) in rings.iter().enumerate() {
      for (j, member) in ring.as_ref().iter().enumerate() {
        key_matrix[j][i] = member[0];
        key_matrix[j][inputs] += member[1];
      }
    }

    for i in 0 .. decoys {
      key_matrix[i][inputs] += -sum_out_pk - H_fee;
    }

    self.verify(msg, &key_matrix, key_images)
  }

  /// Verifies a simple MLSAG signature, a simple signature is over a single input only.
  pub fn verify_simple(
    &self,
    msg: &[u8; 32],
    ring: &[[EdwardsPoint; 2]],
    key_image: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
  ) -> bool {
    let mut ring_matrix = Vec::with_capacity(ring.len());
    for member in ring.iter() {
      ring_matrix.push([member[0], member[1] - pseudo_out].to_vec())
    }

    self.verify(msg, &ring_matrix, &[key_image])
  }

  fn verify(
    &self,
    msg: &[u8; 32],
    ring: &[Vec<EdwardsPoint>],
    key_images: &[&EdwardsPoint],
  ) -> bool {
    if ring.is_empty() {
      return false;
    }

    let mut buf = Vec::with_capacity(6 * 32);
    buf.extend_from_slice(msg);

    let mut ci = self.cc;

    let key_images_iter =
      key_images.iter().map(|ki| Some(*ki)).chain(Some(None).into_iter().cycle());

    for (col, ss) in ring.iter().zip(&self.ss) {
      for ((ring_member, s), ki) in col.iter().zip(ss).zip(key_images_iter.clone()) {
        #[allow(non_snake_case)]
        let L = EdwardsPoint::vartime_double_scalar_mul_basepoint(&ci, &ring_member, &s);

        buf.extend_from_slice(ring_member.compress().as_bytes());
        buf.extend_from_slice(L.compress().as_bytes());

        // Not all dimensions need to be linkable, e.g. commitments, and only linkable layers need
        // to have key images.
        if let Some(ki) = ki {
          #[allow(non_snake_case)]
          let R = (s * hash_to_point(ring_member)) + (ci * ki);
          buf.extend_from_slice(R.compress().as_bytes());
        }
      }

      ci = hash_to_scalar(&buf);
      buf.clear();
      buf.extend_from_slice(msg);

      if ci == Scalar::zero() {
        return false;
      }
    }

    ci == self.cc
  }
}
