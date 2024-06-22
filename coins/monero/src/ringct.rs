use core::ops::Deref;
use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use zeroize::{Zeroize, Zeroizing};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar, edwards::EdwardsPoint};

pub use monero_mlsag as mlsag;
pub use monero_clsag as clsag;
pub use monero_borromean as borromean;
pub use monero_bulletproofs as bulletproofs;

use crate::{
  io::*,
  generators::hash_to_point,
  ringct::{mlsag::Mlsag, clsag::Clsag, borromean::BorromeanRange, bulletproofs::Bulletproof},
};

/// An encrypted amount.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EncryptedAmount {
  Original { mask: [u8; 32], amount: [u8; 32] },
  Compact { amount: [u8; 8] },
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
  /// No RCT proofs.
  Null,
  /// One MLSAG for multiple inputs and Borromean range proofs.
  ///
  /// This lines up with RCTTypeFull.
  MlsagAggregate,
  // One MLSAG for each input and a Borromean range proof.
  ///
  /// This lines up with RCTTypeSimple.
  MlsagIndividual,
  // One MLSAG for each input and a Bulletproof.
  ///
  /// This lines up with RCTTypeBulletproof.
  Bulletproofs,
  /// One MLSAG for each input and a Bulletproof, yet using EncryptedAmount::Compact.
  ///
  /// This lines up with RCTTypeBulletproof2.
  BulletproofsCompactAmount,
  /// One CLSAG for each input and a Bulletproof.
  ///
  /// This lines up with RCTTypeCLSAG.
  Clsag,
  /// One CLSAG for each input and a Bulletproof+.
  ///
  /// This lines up with RCTTypeBulletproofPlus.
  BulletproofsPlus,
}

impl From<RctType> for u8 {
  fn from(kind: RctType) -> u8 {
    match kind {
      RctType::Null => 0,
      RctType::MlsagAggregate => 1,
      RctType::MlsagIndividual => 2,
      RctType::Bulletproofs => 3,
      RctType::BulletproofsCompactAmount => 4,
      RctType::Clsag => 5,
      RctType::BulletproofsPlus => 6,
    }
  }
}

impl TryFrom<u8> for RctType {
  type Error = ();
  fn try_from(byte: u8) -> Result<Self, ()> {
    Ok(match byte {
      0 => RctType::Null,
      1 => RctType::MlsagAggregate,
      2 => RctType::MlsagIndividual,
      3 => RctType::Bulletproofs,
      4 => RctType::BulletproofsCompactAmount,
      5 => RctType::Clsag,
      6 => RctType::BulletproofsPlus,
      _ => Err(())?,
    })
  }
}

impl RctType {
  /// Returns true if this RctType uses compact encrypted amounts, false otherwise.
  pub fn compact_encrypted_amounts(&self) -> bool {
    match self {
      RctType::Null |
      RctType::MlsagAggregate |
      RctType::MlsagIndividual |
      RctType::Bulletproofs => false,
      RctType::BulletproofsCompactAmount | RctType::Clsag | RctType::BulletproofsPlus => true,
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
  /// The encrypted amounts for the recipient to decrypt.
  pub encrypted_amounts: Vec<EncryptedAmount>,
  /// The output commitments.
  pub commitments: Vec<EdwardsPoint>,
}

impl RctBase {
  /// The weight of this RctBase as relevant for fees.
  pub fn fee_weight(outputs: usize, fee: u64) -> usize {
    // 1 byte for the RCT signature type
    1 + (outputs * (8 + 32)) + varint_len(fee)
  }

  /// Write the RctBase.
  pub fn write<W: Write>(&self, w: &mut W, rct_type: RctType) -> io::Result<()> {
    w.write_all(&[u8::from(rct_type)])?;
    match rct_type {
      RctType::Null => Ok(()),
      _ => {
        write_varint(&self.fee, w)?;
        if rct_type == RctType::MlsagIndividual {
          write_raw_vec(write_point, &self.pseudo_outs, w)?;
        }
        for encrypted_amount in &self.encrypted_amounts {
          encrypted_amount.write(w)?;
        }
        write_raw_vec(write_point, &self.commitments, w)
      }
    }
  }

  /// Read a RctBase.
  pub fn read<R: Read>(inputs: usize, outputs: usize, r: &mut R) -> io::Result<(RctBase, RctType)> {
    let rct_type =
      RctType::try_from(read_byte(r)?).map_err(|_| io::Error::other("invalid RCT type"))?;

    match rct_type {
      RctType::Null | RctType::MlsagAggregate | RctType::MlsagIndividual => {}
      RctType::Bulletproofs |
      RctType::BulletproofsCompactAmount |
      RctType::Clsag |
      RctType::BulletproofsPlus => {
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

    Ok((
      if rct_type == RctType::Null {
        RctBase { fee: 0, pseudo_outs: vec![], encrypted_amounts: vec![], commitments: vec![] }
      } else {
        RctBase {
          fee: read_varint(r)?,
          // Only read pseudo_outs if they have yet to be moved to RctPrunable
          // TODO: Shouldn't this be any Mlsag*?
          pseudo_outs: if rct_type == RctType::MlsagIndividual {
            read_raw_vec(read_point, inputs, r)?
          } else {
            vec![]
          },
          encrypted_amounts: (0 .. outputs)
            .map(|_| EncryptedAmount::read(rct_type.compact_encrypted_amounts(), r))
            .collect::<Result<_, _>>()?,
          commitments: read_raw_vec(read_point, outputs, r)?,
        }
      },
      rct_type,
    ))
  }
}

/// The prunable part of the RingCT data.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RctPrunable {
  /// Null.
  Null,
  /// An aggregate MLSAG with Borromean range proofs.
  AggregateMlsagBorromean { borromean: Vec<BorromeanRange>, mlsag: Mlsag },
  /// MLSAGs with Borromean range proofs.
  MlsagBorromean { borromean: Vec<BorromeanRange>, mlsags: Vec<Mlsag> },
  /// MLSAGs with Bulletproofs.
  MlsagBulletproofs {
    bulletproofs: Bulletproof,
    mlsags: Vec<Mlsag>,
    pseudo_outs: Vec<EdwardsPoint>,
  },
  /// CLSAGs with Bulletproofs(+).
  Clsag { bulletproofs: Bulletproof, clsags: Vec<Clsag>, pseudo_outs: Vec<EdwardsPoint> },
}

impl RctPrunable {
  /// The weight of this RctPrunable as relevant for fees.
  #[rustfmt::skip]
  pub fn fee_weight(bp_plus: bool, ring_len: usize, inputs: usize, outputs: usize) -> usize {
    // 1 byte for number of BPs (technically a VarInt, yet there's always just zero or one)
    1 +
      Bulletproof::fee_weight(bp_plus, outputs) +
      // There's both the CLSAG and the pseudo-out
      (inputs * (Clsag::fee_weight(ring_len) + 32))
  }

  /// Write the RctPrunable.
  pub fn write<W: Write>(&self, w: &mut W, rct_type: RctType) -> io::Result<()> {
    match self {
      RctPrunable::Null => Ok(()),
      RctPrunable::AggregateMlsagBorromean { borromean, mlsag } => {
        write_raw_vec(BorromeanRange::write, borromean, w)?;
        mlsag.write(w)
      }
      RctPrunable::MlsagBorromean { borromean, mlsags } => {
        write_raw_vec(BorromeanRange::write, borromean, w)?;
        write_raw_vec(Mlsag::write, mlsags, w)
      }
      RctPrunable::MlsagBulletproofs { bulletproofs, mlsags, pseudo_outs } => {
        if rct_type == RctType::Bulletproofs {
          w.write_all(&1u32.to_le_bytes())?;
        } else {
          w.write_all(&[1])?;
        }
        bulletproofs.write(w)?;

        write_raw_vec(Mlsag::write, mlsags, w)?;
        write_raw_vec(write_point, pseudo_outs, w)
      }
      RctPrunable::Clsag { bulletproofs, clsags, pseudo_outs } => {
        w.write_all(&[1])?;
        bulletproofs.write(w)?;

        write_raw_vec(Clsag::write, clsags, w)?;
        write_raw_vec(write_point, pseudo_outs, w)
      }
    }
  }

  /// Serialize the RctPrunable to a Vec<u8>.
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
      RctType::Null => RctPrunable::Null,
      RctType::MlsagAggregate => RctPrunable::AggregateMlsagBorromean {
        borromean: read_raw_vec(BorromeanRange::read, outputs, r)?,
        mlsag: Mlsag::read(ring_length, inputs + 1, r)?,
      },
      RctType::MlsagIndividual => RctPrunable::MlsagBorromean {
        borromean: read_raw_vec(BorromeanRange::read, outputs, r)?,
        mlsags: (0 .. inputs).map(|_| Mlsag::read(ring_length, 2, r)).collect::<Result<_, _>>()?,
      },
      RctType::Bulletproofs | RctType::BulletproofsCompactAmount => {
        RctPrunable::MlsagBulletproofs {
          bulletproofs: {
            if (if rct_type == RctType::Bulletproofs {
              u64::from(read_u32(r)?)
            } else {
              read_varint(r)?
            }) != 1
            {
              Err(io::Error::other("n bulletproofs instead of one"))?;
            }
            Bulletproof::read(r)?
          },
          mlsags: (0 .. inputs)
            .map(|_| Mlsag::read(ring_length, 2, r))
            .collect::<Result<_, _>>()?,
          pseudo_outs: read_raw_vec(read_point, inputs, r)?,
        }
      }
      RctType::Clsag | RctType::BulletproofsPlus => RctPrunable::Clsag {
        bulletproofs: {
          if read_varint::<_, u64>(r)? != 1 {
            Err(io::Error::other("n bulletproofs instead of one"))?;
          }
          (if rct_type == RctType::Clsag { Bulletproof::read } else { Bulletproof::read_plus })(r)?
        },
        clsags: (0 .. inputs).map(|_| Clsag::read(ring_length, r)).collect::<Result<_, _>>()?,
        pseudo_outs: read_raw_vec(read_point, inputs, r)?,
      },
    })
  }

  /// Write the RctPrunable as necessary for signing the signature.
  ///
  /// This function will return None if the object is `RctPrunable::Null` (and has no
  /// representation here).
  #[must_use]
  pub(crate) fn signature_write<W: Write>(&self, w: &mut W) -> Option<io::Result<()>> {
    Some(match self {
      RctPrunable::Null => None?,
      RctPrunable::AggregateMlsagBorromean { borromean, .. } |
      RctPrunable::MlsagBorromean { borromean, .. } => {
        borromean.iter().try_for_each(|rs| rs.write(w))
      }
      RctPrunable::MlsagBulletproofs { bulletproofs, .. } |
      RctPrunable::Clsag { bulletproofs, .. } => bulletproofs.signature_write(w),
    })
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RctSignatures {
  pub base: RctBase,
  pub prunable: RctPrunable,
}

impl RctSignatures {
  /// RctType for a given RctSignatures struct.
  ///
  /// This is only guaranteed to return the type for a well-formed RctSignatures. For a malformed
  /// RctSignatures, this will return either the presumed RctType (with no guarantee of compliance
  /// with that type) or None.
  #[must_use]
  pub fn rct_type(&self) -> Option<RctType> {
    Some(match &self.prunable {
      RctPrunable::Null => RctType::Null,
      RctPrunable::AggregateMlsagBorromean { .. } => RctType::MlsagAggregate,
      RctPrunable::MlsagBorromean { .. } => RctType::MlsagIndividual,
      RctPrunable::MlsagBulletproofs { .. } => {
        if matches!(self.base.encrypted_amounts.first()?, EncryptedAmount::Original { .. }) {
          RctType::Bulletproofs
        } else {
          RctType::BulletproofsCompactAmount
        }
      }
      RctPrunable::Clsag { bulletproofs, .. } => {
        if matches!(bulletproofs, Bulletproof::Original { .. }) {
          RctType::Clsag
        } else {
          RctType::BulletproofsPlus
        }
      }
    })
  }

  /// The weight of this RctSignatures as relevant for fees.
  pub fn fee_weight(
    bp_plus: bool,
    ring_len: usize,
    inputs: usize,
    outputs: usize,
    fee: u64,
  ) -> usize {
    RctBase::fee_weight(outputs, fee) + RctPrunable::fee_weight(bp_plus, ring_len, inputs, outputs)
  }

  #[must_use]
  pub fn write<W: Write>(&self, w: &mut W) -> Option<io::Result<()>> {
    let rct_type = self.rct_type()?;
    if let Err(e) = self.base.write(w, rct_type) {
      return Some(Err(e));
    };
    Some(self.prunable.write(w, rct_type))
  }

  #[must_use]
  pub fn serialize(&self) -> Option<Vec<u8>> {
    let mut serialized = vec![];
    self.write(&mut serialized)?.unwrap();
    Some(serialized)
  }

  pub fn read<R: Read>(
    ring_length: usize,
    inputs: usize,
    outputs: usize,
    r: &mut R,
  ) -> io::Result<RctSignatures> {
    let base = RctBase::read(inputs, outputs, r)?;
    Ok(RctSignatures {
      base: base.0,
      prunable: RctPrunable::read(base.1, ring_length, inputs, outputs, r)?,
    })
  }
}
