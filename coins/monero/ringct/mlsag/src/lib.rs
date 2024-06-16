#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use zeroize::Zeroize;

use curve25519_dalek::{traits::IsIdentity, Scalar, EdwardsPoint};

use monero_io::*;
use monero_generators::{H, hash_to_point};
use monero_primitives::keccak256_to_scalar;

/// Errors when working with MLSAGs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum MlsagError {
  /// Invalid ring (such as too small or too large).
  #[cfg_attr(feature = "std", error("invalid ring"))]
  InvalidRing,
  /// Invalid amount of key images.
  #[cfg_attr(feature = "std", error("invalid amount of key images"))]
  InvalidAmountOfKeyImages,
  /// Invalid ss matrix.
  #[cfg_attr(feature = "std", error("invalid ss"))]
  InvalidSs,
  /// Invalid key image.
  #[cfg_attr(feature = "std", error("invalid key image"))]
  InvalidKeyImage,
  /// Invalid ci vector.
  #[cfg_attr(feature = "std", error("invalid ci"))]
  InvalidCi,
}

/// A vector of rings, forming a matrix, to verify the MLSAG with.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct RingMatrix {
  matrix: Vec<Vec<EdwardsPoint>>,
}

impl RingMatrix {
  /// Construct a ring matrix from an already formatted series of points.
  fn new(matrix: Vec<Vec<EdwardsPoint>>) -> Result<Self, MlsagError> {
    // Monero requires that there is more than one ring member for MLSAG signatures:
    // https://github.com/monero-project/monero/blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/
    // src/ringct/rctSigs.cpp#L462
    if matrix.len() < 2 {
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

  /// Iterate over the members of the matrix.
  fn iter(&self) -> impl Iterator<Item = &[EdwardsPoint]> {
    self.matrix.iter().map(AsRef::as_ref)
  }

  /// Get the amount of members in the ring.
  pub fn members(&self) -> usize {
    self.matrix.len()
  }

  /// Get the length of a ring member.
  ///
  /// A ring member is a vector of points for which the signer knows all of the discrete logarithms
  /// of.
  pub fn member_len(&self) -> usize {
    // this is safe to do as the constructors don't allow empty rings
    self.matrix[0].len()
  }
}

/// The MLSAG linkable ring signature, as used in Monero.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Mlsag {
  ss: Vec<Vec<Scalar>>,
  cc: Scalar,
}

impl Mlsag {
  /// Write a MLSAG.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for ss in &self.ss {
      write_raw_vec(write_scalar, ss, w)?;
    }
    write_scalar(&self.cc, w)
  }

  /// Read a MLSAG.
  pub fn read<R: Read>(mixins: usize, ss_2_elements: usize, r: &mut R) -> io::Result<Mlsag> {
    Ok(Mlsag {
      ss: (0 .. mixins)
        .map(|_| read_raw_vec(read_scalar, ss_2_elements, r))
        .collect::<Result<_, _>>()?,
      cc: read_scalar(r)?,
    })
  }

  /// Verify a MLSAG.
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

        let compressed_ring_member_entry = ring_member_entry.compress();
        buf.extend_from_slice(compressed_ring_member_entry.as_bytes());
        buf.extend_from_slice(L.compress().as_bytes());

        // Not all dimensions need to be linkable, e.g. commitments, and only linkable layers need
        // to have key images.
        if let Some(ki) = ki {
          if ki.is_identity() || (!ki.is_torsion_free()) {
            Err(MlsagError::InvalidKeyImage)?;
          }

          #[allow(non_snake_case)]
          let R = (s * hash_to_point(compressed_ring_member_entry.to_bytes())) + (ci * ki);
          buf.extend_from_slice(R.compress().as_bytes());
        }
      }

      ci = keccak256_to_scalar(&buf);
      // keep the msg in the buffer.
      buf.drain(msg.len() ..);
    }

    if ci != self.cc {
      Err(MlsagError::InvalidCi)?
    }
    Ok(())
  }
}

/// Builder for a RingMatrix when using an aggregate signature.
///
/// This handles the formatting as necessary.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct AggregateRingMatrixBuilder {
  key_ring: Vec<Vec<EdwardsPoint>>,
  amounts_ring: Vec<EdwardsPoint>,
  sum_out: EdwardsPoint,
}

impl AggregateRingMatrixBuilder {
  /// Create a new AggregateRingMatrixBuilder.
  ///
  /// This takes in the transaction's outputs' commitments and fee used.
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

  /// Build and return the [`RingMatrix`].
  pub fn build(mut self) -> Result<RingMatrix, MlsagError> {
    for (i, amount_commitment) in self.amounts_ring.drain(..).enumerate() {
      self.key_ring[i].push(amount_commitment);
    }
    RingMatrix::new(self.key_ring)
  }
}
