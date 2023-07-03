use core::ops::Deref;
use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use zeroize::Zeroizing;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar, edwards::EdwardsPoint};

pub(crate) mod hash_to_point;
pub use hash_to_point::{raw_hash_to_point, hash_to_point};

/// CLSAG struct, along with signing and verifying functionality.
pub mod clsag;
/// MLSAG struct, along with verifying functionality.
pub mod mlsag;
/// BorromeanRange struct, along with verifying functionality.
pub mod borromean;
/// Bulletproofs(+) structs, along with proving and verifying functionality.
pub mod bulletproofs;

use crate::{
  Protocol,
  serialize::*,
  ringct::{clsag::Clsag, mlsag::Mlsag, bulletproofs::Bulletproofs, borromean::BorromeanRange},
};

/// Generate a key image for a given key. Defined as `x * hash_to_point(xG)`.
pub fn generate_key_image(secret: &Zeroizing<Scalar>) -> EdwardsPoint {
  hash_to_point(&ED25519_BASEPOINT_TABLE * secret.deref()) * secret.deref()
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EncryptedAmount {
  Original { mask: [u8; 32], amount: [u8; 32] },
  Compact { amount: [u8; 8] },
}

impl EncryptedAmount {
  pub fn read<R: Read>(compact: bool, r: &mut R) -> io::Result<EncryptedAmount> {
    Ok(if !compact {
      EncryptedAmount::Original { mask: read_bytes(r)?, amount: read_bytes(r)? }
    } else {
      EncryptedAmount::Compact { amount: read_bytes(r)? }
    })
  }

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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RctBase {
  pub fee: u64,
  pub encrypted_amounts: Vec<EncryptedAmount>,
  pub pseudo_outs: Vec<EdwardsPoint>,
  pub commitments: Vec<EdwardsPoint>,
}

impl RctBase {
  pub(crate) fn fee_weight(outputs: usize) -> usize {
    1 + 8 + (outputs * (8 + 32))
  }

  pub fn write<W: Write>(&self, w: &mut W, rct_type: u8) -> io::Result<()> {
    w.write_all(&[rct_type])?;
    match rct_type {
      0 => Ok(()),
      _ => {
        write_varint(&self.fee, w)?;
        if rct_type == 2 {
          write_raw_vec(write_point, &self.pseudo_outs, w)?;
        }
        for encrypted_amount in &self.encrypted_amounts {
          encrypted_amount.write(w)?;
        }
        write_raw_vec(write_point, &self.commitments, w)
      }
    }
  }

  pub fn read<R: Read>(inputs: usize, outputs: usize, r: &mut R) -> io::Result<(RctBase, u8)> {
    let rct_type = read_byte(r)?;
    Ok((
      if rct_type == 0 {
        RctBase { fee: 0, encrypted_amounts: vec![], pseudo_outs: vec![], commitments: vec![] }
      } else {
        RctBase {
          fee: read_varint(r)?,
          pseudo_outs: if rct_type == 2 { read_raw_vec(read_point, inputs, r)? } else { vec![] },
          encrypted_amounts: (0 .. outputs)
            .map(|_| EncryptedAmount::read(rct_type >= 4, r))
            .collect::<Result<_, _>>()?,
          commitments: read_raw_vec(read_point, outputs, r)?,
        }
      },
      rct_type,
    ))
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RctPrunable {
  Null,
  Borromean {
    range_sigs: Vec<BorromeanRange>,
    mlsags: Vec<Mlsag>,
    simple: bool,
  },
  Bulletproofs {
    bulletproofs: Vec<Bulletproofs>,
    mlsags: Vec<Mlsag>,
    pseudo_outs: Vec<EdwardsPoint>,
    v2: bool,
  },
  Clsag {
    bulletproofs: Vec<Bulletproofs>,
    clsags: Vec<Clsag>,
    pseudo_outs: Vec<EdwardsPoint>,
  },
}

impl RctPrunable {
  /// RCT Type byte for a given RctPrunable struct.
  pub fn rct_type(&self) -> u8 {
    match self {
      RctPrunable::Null => 0,
      RctPrunable::Borromean { simple, .. } => {
        if !simple {
          1
        } else {
          2
        }
      }
      RctPrunable::Bulletproofs { v2, .. } => {
        if !v2 {
          3
        } else {
          4
        }
      }
      RctPrunable::Clsag { bulletproofs, .. } => {
        if matches!(bulletproofs[0], Bulletproofs::Original { .. }) {
          5
        } else {
          6
        }
      }
    }
  }

  pub(crate) fn fee_weight(protocol: Protocol, inputs: usize, outputs: usize) -> usize {
    1 + Bulletproofs::fee_weight(protocol.bp_plus(), outputs) +
      (inputs * (Clsag::fee_weight(protocol.ring_len()) + 32))
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      RctPrunable::Null => Ok(()),
      RctPrunable::Borromean { range_sigs, mlsags, simple: _ } => {
        write_raw_vec(BorromeanRange::write, range_sigs, w)?;
        write_raw_vec(Mlsag::write, mlsags, w)
      }
      RctPrunable::Bulletproofs { bulletproofs, mlsags, pseudo_outs, v2 } => {
        if !v2 {
          w.write_all(&u32::try_from(bulletproofs.len()).unwrap().to_le_bytes())?;
        } else {
          write_varint(&bulletproofs.len().try_into().unwrap(), w)?;
        }
        write_raw_vec(Bulletproofs::write, bulletproofs, w)?;
        write_raw_vec(Mlsag::write, mlsags, w)?;
        write_raw_vec(write_point, pseudo_outs, w)
      }
      RctPrunable::Clsag { bulletproofs, clsags, pseudo_outs } => {
        write_vec(Bulletproofs::write, bulletproofs, w)?;
        write_raw_vec(Clsag::write, clsags, w)?;
        write_raw_vec(write_point, pseudo_outs, w)
      }
    }
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).unwrap();
    serialized
  }

  pub fn read<R: Read>(
    rct_type: u8,
    decoys: &[usize],
    outputs: usize,
    r: &mut R,
  ) -> io::Result<RctPrunable> {
    Ok(match rct_type {
      0 => RctPrunable::Null,
      1 | 2 => RctPrunable::Borromean {
        range_sigs: read_raw_vec(BorromeanRange::read, outputs, r)?,
        mlsags: decoys.iter().map(|d| Mlsag::read(*d, r)).collect::<Result<_, _>>()?,
        simple: rct_type == 2,
      },
      3 | 4 => RctPrunable::Bulletproofs {
        bulletproofs: read_raw_vec(
          Bulletproofs::read,
          if rct_type == 3 {
            read_u32(r)?.try_into().unwrap()
          } else {
            read_varint(r)?.try_into().unwrap()
          },
          r,
        )?,
        mlsags: decoys.iter().map(|d| Mlsag::read(*d, r)).collect::<Result<_, _>>()?,
        pseudo_outs: read_raw_vec(read_point, decoys.len(), r)?,
        v2: rct_type == 4,
      },
      5 | 6 => RctPrunable::Clsag {
        bulletproofs: read_vec(
          if rct_type == 5 { Bulletproofs::read } else { Bulletproofs::read_plus },
          r,
        )?,
        clsags: (0 .. decoys.len()).map(|o| Clsag::read(decoys[o], r)).collect::<Result<_, _>>()?,
        pseudo_outs: read_raw_vec(read_point, decoys.len(), r)?,
      },
      _ => Err(io::Error::new(io::ErrorKind::Other, "Tried to deserialize unknown RCT type"))?,
    })
  }

  pub(crate) fn signature_write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      RctPrunable::Null => panic!("Serializing RctPrunable::Null for a signature"),
      RctPrunable::Clsag { bulletproofs, .. } => {
        bulletproofs.iter().try_for_each(|bp| bp.signature_write(w))
      }
      RctPrunable::Bulletproofs { bulletproofs, .. } => {
        bulletproofs.iter().try_for_each(|bp| bp.signature_write(w))
      }
      RctPrunable::Borromean { range_sigs, .. } => range_sigs.iter().try_for_each(|rs| rs.write(w)),
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RctSignatures {
  pub base: RctBase,
  pub prunable: RctPrunable,
}

impl RctSignatures {
  pub(crate) fn fee_weight(protocol: Protocol, inputs: usize, outputs: usize) -> usize {
    RctBase::fee_weight(outputs) + RctPrunable::fee_weight(protocol, inputs, outputs)
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.base.write(w, self.prunable.rct_type())?;
    self.prunable.write(w)
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).unwrap();
    serialized
  }

  pub fn read<R: Read>(decoys: Vec<usize>, outputs: usize, r: &mut R) -> io::Result<RctSignatures> {
    let base = RctBase::read(decoys.len(), outputs, r)?;
    Ok(RctSignatures { base: base.0, prunable: RctPrunable::read(base.1, &decoys, outputs, r)? })
  }
}
