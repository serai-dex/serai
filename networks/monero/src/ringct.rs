use std_shims::{
  vec,
  vec::Vec,
  io::{self, Read, Write},
};

use zeroize::Zeroize;

use curve25519_dalek::edwards::EdwardsPoint;

pub use monero_mlsag as mlsag;
pub use monero_clsag as clsag;
pub use monero_borromean as borromean;
pub use monero_bulletproofs as bulletproofs;

use crate::{
  io::*,
  ringct::{mlsag::Mlsag, clsag::Clsag, borromean::BorromeanRange, bulletproofs::Bulletproof},
};

/// An encrypted amount.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EncryptedAmount {
  /// The original format for encrypted amounts.
  Original {
    /// A mask used with a mask derived from the shared secret to encrypt the amount.
    mask: [u8; 32],
    /// The amount, as a scalar, encrypted.
    amount: [u8; 32],
  },
  /// The "compact" format for encrypted amounts.
  Compact {
    /// The amount, as a u64, encrypted.
    amount: [u8; 8],
  },
}

impl EncryptedAmount {
  /// Read an EncryptedAmount from a reader.
  pub fn read<R: Read>(compact: bool, r: &mut R) -> io::Result<EncryptedAmount> {
    Ok(if !compact {
      EncryptedAmount::Original { mask: read_bytes(r)?, amount: read_bytes(r)? }
    } else {
      EncryptedAmount::Compact { amount: read_bytes(r)? }
    })
  }

  /// Write the EncryptedAmount to a writer.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      EncryptedAmount::Original { mask, amount } => {
        w.write_all(mask)?;
        w.write_all(amount)
      }
      EncryptedAmount::Compact { amount } => w.write_all(amount),
    }
  }
}

/// The type of the RingCT data.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum RctType {
  /// One MLSAG for multiple inputs and Borromean range proofs.
  ///
  /// This aligns with RCTTypeFull.
  AggregateMlsagBorromean,
  // One MLSAG for each input and a Borromean range proof.
  ///
  /// This aligns with RCTTypeSimple.
  MlsagBorromean,
  // One MLSAG for each input and a Bulletproof.
  ///
  /// This aligns with RCTTypeBulletproof.
  MlsagBulletproofs,
  /// One MLSAG for each input and a Bulletproof, yet using EncryptedAmount::Compact.
  ///
  /// This aligns with RCTTypeBulletproof2.
  MlsagBulletproofsCompactAmount,
  /// One CLSAG for each input and a Bulletproof.
  ///
  /// This aligns with RCTTypeCLSAG.
  ClsagBulletproof,
  /// One CLSAG for each input and a Bulletproof+.
  ///
  /// This aligns with RCTTypeBulletproofPlus.
  ClsagBulletproofPlus,
}

impl From<RctType> for u8 {
  fn from(rct_type: RctType) -> u8 {
    match rct_type {
      RctType::AggregateMlsagBorromean => 1,
      RctType::MlsagBorromean => 2,
      RctType::MlsagBulletproofs => 3,
      RctType::MlsagBulletproofsCompactAmount => 4,
      RctType::ClsagBulletproof => 5,
      RctType::ClsagBulletproofPlus => 6,
    }
  }
}

impl TryFrom<u8> for RctType {
  type Error = ();
  fn try_from(byte: u8) -> Result<Self, ()> {
    Ok(match byte {
      1 => RctType::AggregateMlsagBorromean,
      2 => RctType::MlsagBorromean,
      3 => RctType::MlsagBulletproofs,
      4 => RctType::MlsagBulletproofsCompactAmount,
      5 => RctType::ClsagBulletproof,
      6 => RctType::ClsagBulletproofPlus,
      _ => Err(())?,
    })
  }
}

impl RctType {
  /// True if this RctType uses compact encrypted amounts, false otherwise.
  pub fn compact_encrypted_amounts(&self) -> bool {
    match self {
      RctType::AggregateMlsagBorromean | RctType::MlsagBorromean | RctType::MlsagBulletproofs => {
        false
      }
      RctType::MlsagBulletproofsCompactAmount |
      RctType::ClsagBulletproof |
      RctType::ClsagBulletproofPlus => true,
    }
  }

  /// True if this RctType uses a Bulletproof, false otherwise.
  pub(crate) fn bulletproof(&self) -> bool {
    match self {
      RctType::MlsagBulletproofs |
      RctType::MlsagBulletproofsCompactAmount |
      RctType::ClsagBulletproof => true,
      RctType::AggregateMlsagBorromean |
      RctType::MlsagBorromean |
      RctType::ClsagBulletproofPlus => false,
    }
  }

  /// True if this RctType uses a Bulletproof+, false otherwise.
  pub(crate) fn bulletproof_plus(&self) -> bool {
    match self {
      RctType::ClsagBulletproofPlus => true,
      RctType::AggregateMlsagBorromean |
      RctType::MlsagBorromean |
      RctType::MlsagBulletproofs |
      RctType::MlsagBulletproofsCompactAmount |
      RctType::ClsagBulletproof => false,
    }
  }
}

/// The base of the RingCT data.
///
/// This excludes all proofs (which once initially verified do not need to be kept around) and
/// solely keeps data which either impacts the effects of the transactions or is needed to scan it.
///
/// The one exception for this is `pseudo_outs`, which was originally present here yet moved to
/// RctPrunable in a later hard fork (causing it to be present in both).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RctBase {
  /// The fee used by this transaction.
  pub fee: u64,
  /// The re-randomized amount commitments used within inputs.
  ///
  /// This field was deprecated and is empty for modern RctTypes.
  pub pseudo_outs: Vec<EdwardsPoint>,
  /// The encrypted amounts for the recipients to decrypt.
  pub encrypted_amounts: Vec<EncryptedAmount>,
  /// The output commitments.
  pub commitments: Vec<EdwardsPoint>,
}

impl RctBase {
  /// Write the RctBase.
  pub fn write<W: Write>(&self, w: &mut W, rct_type: RctType) -> io::Result<()> {
    w.write_all(&[u8::from(rct_type)])?;

    write_varint(&self.fee, w)?;
    if rct_type == RctType::MlsagBorromean {
      write_raw_vec(write_point, &self.pseudo_outs, w)?;
    }
    for encrypted_amount in &self.encrypted_amounts {
      encrypted_amount.write(w)?;
    }
    write_raw_vec(write_point, &self.commitments, w)
  }

  /// Read a RctBase.
  pub fn read<R: Read>(
    inputs: usize,
    outputs: usize,
    r: &mut R,
  ) -> io::Result<Option<(RctType, RctBase)>> {
    let rct_type = read_byte(r)?;
    if rct_type == 0 {
      return Ok(None);
    }
    let rct_type =
      RctType::try_from(rct_type).map_err(|()| io::Error::other("invalid RCT type"))?;

    match rct_type {
      RctType::AggregateMlsagBorromean | RctType::MlsagBorromean => {}
      RctType::MlsagBulletproofs |
      RctType::MlsagBulletproofsCompactAmount |
      RctType::ClsagBulletproof |
      RctType::ClsagBulletproofPlus => {
        if outputs == 0 {
          // Because the Bulletproofs(+) layout must be canonical, there must be 1 Bulletproof if
          // Bulletproofs are in use
          // If there are Bulletproofs, there must be a matching amount of outputs, implicitly
          // banning 0 outputs
          // Since HF 12 (CLSAG being 13), a 2-output minimum has also been enforced
          Err(io::Error::other("RCT with Bulletproofs(+) had 0 outputs"))?;
        }
      }
    }

    Ok(Some((
      rct_type,
      RctBase {
        fee: read_varint(r)?,
        // Only read pseudo_outs if they have yet to be moved to RctPrunable
        // This would apply to AggregateMlsagBorromean and MlsagBorromean, except
        // AggregateMlsagBorromean doesn't use pseudo_outs due to using the sum of the output
        // commitments directly as the effective singular pseudo-out
        pseudo_outs: if rct_type == RctType::MlsagBorromean {
          read_raw_vec(read_point, inputs, r)?
        } else {
          vec![]
        },
        encrypted_amounts: (0 .. outputs)
          .map(|_| EncryptedAmount::read(rct_type.compact_encrypted_amounts(), r))
          .collect::<Result<_, _>>()?,
        commitments: read_raw_vec(read_point, outputs, r)?,
      },
    )))
  }
}

/// The prunable part of the RingCT data.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RctPrunable {
  /// An aggregate MLSAG with Borromean range proofs.
  AggregateMlsagBorromean {
    /// The aggregate MLSAG ring signature.
    mlsag: Mlsag,
    /// The Borromean range proofs for each output.
    borromean: Vec<BorromeanRange>,
  },
  /// MLSAGs with Borromean range proofs.
  MlsagBorromean {
    /// The MLSAG ring signatures for each input.
    mlsags: Vec<Mlsag>,
    /// The Borromean range proofs for each output.
    borromean: Vec<BorromeanRange>,
  },
  /// MLSAGs with Bulletproofs.
  MlsagBulletproofs {
    /// The MLSAG ring signatures for each input.
    mlsags: Vec<Mlsag>,
    /// The re-blinded commitments for the outputs being spent.
    pseudo_outs: Vec<EdwardsPoint>,
    /// The aggregate Bulletproof, proving the outputs are within range.
    bulletproof: Bulletproof,
  },
  /// MLSAGs with Bulletproofs and compact encrypted amounts.
  ///
  /// This has an identical layout to MlsagBulletproofs and is interpreted the exact same way. It's
  /// only differentiated to ensure discovery of the correct RctType.
  MlsagBulletproofsCompactAmount {
    /// The MLSAG ring signatures for each input.
    mlsags: Vec<Mlsag>,
    /// The re-blinded commitments for the outputs being spent.
    pseudo_outs: Vec<EdwardsPoint>,
    /// The aggregate Bulletproof, proving the outputs are within range.
    bulletproof: Bulletproof,
  },
  /// CLSAGs with Bulletproofs(+).
  Clsag {
    /// The CLSAGs for each input.
    clsags: Vec<Clsag>,
    /// The re-blinded commitments for the outputs being spent.
    pseudo_outs: Vec<EdwardsPoint>,
    /// The aggregate Bulletproof(+), proving the outputs are within range.
    bulletproof: Bulletproof,
  },
}

impl RctPrunable {
  /// Write the RctPrunable.
  pub fn write<W: Write>(&self, w: &mut W, rct_type: RctType) -> io::Result<()> {
    match self {
      RctPrunable::AggregateMlsagBorromean { borromean, mlsag } => {
        write_raw_vec(BorromeanRange::write, borromean, w)?;
        mlsag.write(w)
      }
      RctPrunable::MlsagBorromean { borromean, mlsags } => {
        write_raw_vec(BorromeanRange::write, borromean, w)?;
        write_raw_vec(Mlsag::write, mlsags, w)
      }
      RctPrunable::MlsagBulletproofs { bulletproof, mlsags, pseudo_outs } |
      RctPrunable::MlsagBulletproofsCompactAmount { bulletproof, mlsags, pseudo_outs } => {
        if rct_type == RctType::MlsagBulletproofs {
          w.write_all(&1u32.to_le_bytes())?;
        } else {
          w.write_all(&[1])?;
        }
        bulletproof.write(w)?;

        write_raw_vec(Mlsag::write, mlsags, w)?;
        write_raw_vec(write_point, pseudo_outs, w)
      }
      RctPrunable::Clsag { bulletproof, clsags, pseudo_outs } => {
        w.write_all(&[1])?;
        bulletproof.write(w)?;

        write_raw_vec(Clsag::write, clsags, w)?;
        write_raw_vec(write_point, pseudo_outs, w)
      }
    }
  }

  /// Serialize the RctPrunable to a `Vec<u8>`.
  pub fn serialize(&self, rct_type: RctType) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized, rct_type).unwrap();
    serialized
  }

  /// Read a RctPrunable.
  pub fn read<R: Read>(
    rct_type: RctType,
    ring_length: usize,
    inputs: usize,
    outputs: usize,
    r: &mut R,
  ) -> io::Result<RctPrunable> {
    Ok(match rct_type {
      RctType::AggregateMlsagBorromean => RctPrunable::AggregateMlsagBorromean {
        borromean: read_raw_vec(BorromeanRange::read, outputs, r)?,
        mlsag: Mlsag::read(ring_length, inputs + 1, r)?,
      },
      RctType::MlsagBorromean => RctPrunable::MlsagBorromean {
        borromean: read_raw_vec(BorromeanRange::read, outputs, r)?,
        mlsags: (0 .. inputs).map(|_| Mlsag::read(ring_length, 2, r)).collect::<Result<_, _>>()?,
      },
      RctType::MlsagBulletproofs | RctType::MlsagBulletproofsCompactAmount => {
        let bulletproof = {
          if (if rct_type == RctType::MlsagBulletproofs {
            u64::from(read_u32(r)?)
          } else {
            read_varint(r)?
          }) != 1
          {
            Err(io::Error::other("n bulletproofs instead of one"))?;
          }
          Bulletproof::read(r)?
        };
        let mlsags =
          (0 .. inputs).map(|_| Mlsag::read(ring_length, 2, r)).collect::<Result<_, _>>()?;
        let pseudo_outs = read_raw_vec(read_point, inputs, r)?;
        if rct_type == RctType::MlsagBulletproofs {
          RctPrunable::MlsagBulletproofs { bulletproof, mlsags, pseudo_outs }
        } else {
          debug_assert_eq!(rct_type, RctType::MlsagBulletproofsCompactAmount);
          RctPrunable::MlsagBulletproofsCompactAmount { bulletproof, mlsags, pseudo_outs }
        }
      }
      RctType::ClsagBulletproof | RctType::ClsagBulletproofPlus => RctPrunable::Clsag {
        bulletproof: {
          if read_varint::<_, u64>(r)? != 1 {
            Err(io::Error::other("n bulletproofs instead of one"))?;
          }
          (if rct_type == RctType::ClsagBulletproof {
            Bulletproof::read
          } else {
            Bulletproof::read_plus
          })(r)?
        },
        clsags: (0 .. inputs).map(|_| Clsag::read(ring_length, r)).collect::<Result<_, _>>()?,
        pseudo_outs: read_raw_vec(read_point, inputs, r)?,
      },
    })
  }

  /// Write the RctPrunable as necessary for signing the signature.
  pub(crate) fn signature_write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      RctPrunable::AggregateMlsagBorromean { borromean, .. } |
      RctPrunable::MlsagBorromean { borromean, .. } => {
        borromean.iter().try_for_each(|rs| rs.write(w))
      }
      RctPrunable::MlsagBulletproofs { bulletproof, .. } |
      RctPrunable::MlsagBulletproofsCompactAmount { bulletproof, .. } |
      RctPrunable::Clsag { bulletproof, .. } => bulletproof.signature_write(w),
    }
  }
}

/// The RingCT proofs.
///
/// This contains both the RctBase and RctPrunable structs.
///
/// The C++ codebase refers to this as rct_signatures.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RctProofs {
  /// The data necessary for handling this transaction.
  pub base: RctBase,
  /// The data necessary for verifying this transaction.
  pub prunable: RctPrunable,
}

impl RctProofs {
  /// RctType for a given RctProofs struct.
  pub fn rct_type(&self) -> RctType {
    match &self.prunable {
      RctPrunable::AggregateMlsagBorromean { .. } => RctType::AggregateMlsagBorromean,
      RctPrunable::MlsagBorromean { .. } => RctType::MlsagBorromean,
      RctPrunable::MlsagBulletproofs { .. } => RctType::MlsagBulletproofs,
      RctPrunable::MlsagBulletproofsCompactAmount { .. } => RctType::MlsagBulletproofsCompactAmount,
      RctPrunable::Clsag { bulletproof, .. } => {
        if matches!(bulletproof, Bulletproof::Original { .. }) {
          RctType::ClsagBulletproof
        } else {
          RctType::ClsagBulletproofPlus
        }
      }
    }
  }

  /// Write the RctProofs.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    let rct_type = self.rct_type();
    self.base.write(w, rct_type)?;
    self.prunable.write(w, rct_type)
  }

  /// Serialize the RctProofs to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).unwrap();
    serialized
  }

  /// Read a RctProofs.
  pub fn read<R: Read>(
    ring_length: usize,
    inputs: usize,
    outputs: usize,
    r: &mut R,
  ) -> io::Result<Option<RctProofs>> {
    let Some((rct_type, base)) = RctBase::read(inputs, outputs, r)? else { return Ok(None) };
    Ok(Some(RctProofs {
      base,
      prunable: RctPrunable::read(rct_type, ring_length, inputs, outputs, r)?,
    }))
  }
}

/// A pruned set of RingCT proofs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrunedRctProofs {
  /// The type of RctProofs this used to be.
  pub rct_type: RctType,
  /// The data necessary for handling this transaction.
  pub base: RctBase,
}
