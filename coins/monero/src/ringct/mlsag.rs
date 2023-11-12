use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use zeroize::Zeroize;

use curve25519_dalek::{traits::IsIdentity, Scalar, EdwardsPoint};

use monero_generators::H;

use crate::{hash_to_scalar, ringct::hash_to_point, serialize::*};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum MlsagError {
  #[cfg_attr(feature = "std", error("invalid ring"))]
  InvalidRing,
  #[cfg_attr(feature = "std", error("invalid amount of key images"))]
  InvalidAmountOfKeyImages,
  #[cfg_attr(feature = "std", error("invalid ss"))]
  InvalidSs,
  #[cfg_attr(feature = "std", error("key image was identity"))]
  IdentityKeyImage,
  #[cfg_attr(feature = "std", error("invalid ci"))]
  InvalidCi,
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct RingMatrix {
  matrix: Vec<Vec<EdwardsPoint>>,
}

impl RingMatrix {
  pub fn new(matrix: Vec<Vec<EdwardsPoint>>) -> Result<Self, MlsagError> {
    if matrix.is_empty() {
      Err(MlsagError::InvalidRing)?;
    }
    for member in &matrix {
      if member.is_empty() || (member.len() != matrix[0].len()) {
        Err(MlsagError::InvalidRing)?;
      }
    }

    Ok(RingMatrix { matrix })
  }

  /// Construct a ring matrix for an individual output.
  pub fn individual(
    ring: &[[EdwardsPoint; 2]],
    pseudo_out: EdwardsPoint,
  ) -> Result<Self, MlsagError> {
    let mut matrix = Vec::with_capacity(ring.len());
    for ring_member in ring {
      matrix.push(vec![ring_member[0], ring_member[1] - pseudo_out]);
    }
    RingMatrix::new(matrix)
  }

  pub fn iter(&self) -> impl Iterator<Item = &[EdwardsPoint]> {
    self.matrix.iter().map(AsRef::as_ref)
  }

  /// Return the amount of members in the ring.
  pub fn members(&self) -> usize {
    self.matrix.len()
  }

  /// Returns the length of a ring member.
  ///
  /// A ring member is a vector of points for which the signer knows all of the discrete logarithms
  /// of.
  pub fn member_len(&self) -> usize {
    // this is safe to do as the constructors don't allow empty rings
    self.matrix[0].len()
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
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
    key_images: &[EdwardsPoint],
  ) -> Result<(), MlsagError> {
    // Mlsag allows for layers to not need linkability, hence they don't need key images
    // Monero requires that there is always only 1 non-linkable layer - the amount commitments.
    if ring.member_len() != (key_images.len() + 1) {
      Err(MlsagError::InvalidAmountOfKeyImages)?;
    }

    let mut buf = Vec::with_capacity(6 * 32);
    buf.extend_from_slice(msg);

    let mut ci = self.cc;

    // This is an iterator over the key images as options with an added entry of `None` at the
    // end for the non-linkable layer
    let key_images_iter = key_images.iter().map(|ki| Some(*ki)).chain(core::iter::once(None));

    if ring.matrix.len() != self.ss.len() {
      Err(MlsagError::InvalidSs)?;
    }

    for (ring_member, ss) in ring.iter().zip(&self.ss) {
      if ring_member.len() != ss.len() {
        Err(MlsagError::InvalidSs)?;
      }

      for ((ring_member_entry, s), ki) in ring_member.iter().zip(ss).zip(key_images_iter.clone()) {
        #[allow(non_snake_case)]
        let L = EdwardsPoint::vartime_double_scalar_mul_basepoint(&ci, ring_member_entry, s);

        buf.extend_from_slice(ring_member_entry.compress().as_bytes());
        buf.extend_from_slice(L.compress().as_bytes());

        // Not all dimensions need to be linkable, e.g. commitments, and only linkable layers need
        // to have key images.
        if let Some(ki) = ki {
          if ki.is_identity() {
            Err(MlsagError::IdentityKeyImage)?;
          }

          #[allow(non_snake_case)]
          let R = (s * hash_to_point(ring_member_entry)) + (ci * ki);
          buf.extend_from_slice(R.compress().as_bytes());
        }
      }

      ci = hash_to_scalar(&buf);
      // keep the msg in the buffer.
      buf.drain(msg.len() ..);
    }

    if ci != self.cc {
      Err(MlsagError::InvalidCi)?
    }
    Ok(())
  }
}

/// An aggregate ring matrix builder, usable to set up the ring matrix to prove/verify an aggregate
/// MLSAG signature.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct AggregateRingMatrixBuilder {
  key_ring: Vec<Vec<EdwardsPoint>>,
  amounts_ring: Vec<EdwardsPoint>,
  sum_out: EdwardsPoint,
}

impl AggregateRingMatrixBuilder {
  /// Create a new AggregateRingMatrixBuilder.
  ///
  /// Takes in the transaction's outputs; commitments and fee.
  pub fn new(commitments: &[EdwardsPoint], fee: u64) -> Self {
    AggregateRingMatrixBuilder {
      key_ring: vec![],
      amounts_ring: vec![],
      sum_out: commitments.iter().sum::<EdwardsPoint>() + (H() * Scalar::from(fee)),
    }
  }

  /// Push a ring of [output key, commitment] to the matrix.
  pub fn push_ring(&mut self, ring: &[[EdwardsPoint; 2]]) -> Result<(), MlsagError> {
    if self.key_ring.is_empty() {
      self.key_ring = vec![vec![]; ring.len()];
      // Now that we know the length of the ring, fill the `amounts_ring`.
      self.amounts_ring = vec![-self.sum_out; ring.len()];
    }

    if (self.amounts_ring.len() != ring.len()) || ring.is_empty() {
      // All the rings in an aggregate matrix must be the same length.
      return Err(MlsagError::InvalidRing);
    }

    for (i, ring_member) in ring.iter().enumerate() {
      self.key_ring[i].push(ring_member[0]);
      self.amounts_ring[i] += ring_member[1]
    }

    Ok(())
  }

  /// Build and return the [`RingMatrix`]
  pub fn build(mut self) -> Result<RingMatrix, MlsagError> {
    for (i, amount_commitment) in self.amounts_ring.drain(..).enumerate() {
      self.key_ring[i].push(amount_commitment);
    }
    RingMatrix::new(self.key_ring)
  }
}
