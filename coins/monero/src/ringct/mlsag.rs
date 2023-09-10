use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::EdwardsPoint;

use monero_generators::H;

use crate::serialize::*;
use crate::{hash_to_scalar, ringct::hash_to_point};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum MlsagError {
  #[cfg_attr(feature = "std", error("invalid ring"))]
  InvalidRing,
  #[cfg_attr(feature = "std", error("invalid amount of key images"))]
  InvalidAmountOfKeyImages,
  #[cfg_attr(feature = "std", error("invalid ci"))]
  InvalidCi,
}

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

  pub fn verify(
    &self,
    msg: &[u8; 32],
    ring: &RingMatrix,
    key_images: &[&EdwardsPoint],
  ) -> Result<(), MlsagError> {
    // Mlsag allows for layers to not need link-ability hence they don't need key images
    // Monero requires that there is always only 1 non-linkable layer - the amount commitments.
    if ring.member_len() != key_images.len() + 1 {
      return Err(MlsagError::InvalidAmountOfKeyImages);
    }

    let mut buf = Vec::with_capacity(6 * 32);
    buf.extend_from_slice(msg);

    let mut ci = self.cc;

    // This is an iterator over the key images as options with an added entry of `None` at the
    // end for the non-linkable layer
    let key_images_iter = key_images.iter().map(|ki| Some(*ki)).chain(Some(None));

    for (ring_member, ss) in ring.iter().zip(&self.ss) {
      for ((ring_member_layer, s), ki) in ring_member.iter().zip(ss).zip(key_images_iter.clone()) {
        #[allow(non_snake_case)]
        let L = EdwardsPoint::vartime_double_scalar_mul_basepoint(&ci, ring_member_layer, s);

        buf.extend_from_slice(ring_member_layer.compress().as_bytes());
        buf.extend_from_slice(L.compress().as_bytes());

        // Not all dimensions need to be linkable, e.g. commitments, and only linkable layers need
        // to have key images.
        if let Some(ki) = ki {
          #[allow(non_snake_case)]
          let R = (s * hash_to_point(ring_member_layer)) + (ci * ki);
          buf.extend_from_slice(R.compress().as_bytes());
        }
      }

      ci = hash_to_scalar(&buf);
      // keep the msg in the buffer.
      buf.drain(msg.len() ..);

      if ci == Scalar::zero() {
        return Err(MlsagError::InvalidCi);
      }
    }

    if ci == self.cc {
      Ok(())
    } else {
      Err(MlsagError::InvalidCi)
    }
  }
}

pub struct RingMatrix {
  matrix: Vec<Vec<EdwardsPoint>>,
}

impl RingMatrix {
  /// Construct a simple ring matrix.
  pub fn simple(ring: &[[EdwardsPoint; 2]], pseudo_out: EdwardsPoint) -> Result<Self, MlsagError> {
    if ring.is_empty() {
      return Err(MlsagError::InvalidRing);
    }

    let mut matrix = Vec::with_capacity(ring.len());

    for ring_member in ring {
      matrix.push(vec![ring_member[0], ring_member[1] - pseudo_out])
    }

    Ok(RingMatrix { matrix })
  }

  /// Returns a builder that can be used to construct an aggregate ring matrix
  pub fn aggregate_builder(commitments: &[EdwardsPoint], fee: u64) -> AggregateRingMatrix {
    AggregateRingMatrix::new(commitments, fee)
  }

  pub fn iter(&self) -> impl Iterator<Item = &[EdwardsPoint]> {
    self.matrix.iter().map(|ring_member| ring_member.as_slice())
  }

  /// Returns the length of one ring member, a ring member is a set of keys
  /// that are linked, one of which are the real spends.
  pub fn member_len(&self) -> usize {
    // this is safe to do as the constructors don't allow empty rings
    self.matrix[0].len()
  }
}

/// An aggregate ring matrix builder, used to set up the ring matrix to prove/
/// verify an aggregate signature.
pub struct AggregateRingMatrix {
  key_ring: Vec<Vec<EdwardsPoint>>,
  amounts_ring: Vec<EdwardsPoint>,
  sum_out_commitments: EdwardsPoint,
  fee: EdwardsPoint,
}

impl AggregateRingMatrix {
  pub fn new(commitments: &[EdwardsPoint], fee: u64) -> Self {
    AggregateRingMatrix {
      key_ring: vec![],
      amounts_ring: vec![],
      sum_out_commitments: commitments.iter().sum::<EdwardsPoint>(),
      fee: H() * Scalar::from(fee),
    }
  }

  /// push a ring, aka input, to this aggregate ring matrix.
  pub fn push_ring(&mut self, ring: &[[EdwardsPoint; 2]]) -> Result<(), MlsagError> {
    if self.amounts_ring.is_empty() {
      // This is our fist ring, now we know the length of the decoys fill the
      // `amounts_ring` table, so we don't have to loop back over and take
      // these values off at the end.
      self.amounts_ring = vec![-self.sum_out_commitments - self.fee; ring.len()];
    }

    if self.amounts_ring.len() != ring.len() || ring.is_empty() {
      // All the rings in an aggregate matrix must be the same length.
      return Err(MlsagError::InvalidRing);
    }

    for (i, ring_member) in ring.iter().enumerate() {
      if let Some(entry) = self.key_ring.get_mut(i) {
        entry.push(ring_member[0]);
      } else {
        self.key_ring.push(vec![ring_member[0]])
      }

      self.amounts_ring[i] += ring_member[1]
    }

    Ok(())
  }

  /// Finalize and return the [`RingMatrix`]
  ///
  /// This will panic if no rings have been added.
  pub fn finish(mut self) -> RingMatrix {
    assert!(!self.key_ring.is_empty(), "No ring members entered, can't build empty ring");

    for (i, amount_commitment) in self.amounts_ring.drain(..).enumerate() {
      self.key_ring[i].push(amount_commitment)
    }

    RingMatrix { matrix: self.key_ring }
  }
}
