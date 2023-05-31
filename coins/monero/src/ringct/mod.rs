use core::ops::Deref;
use std::io::{self, Read, Write};

use zeroize::Zeroizing;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar, edwards::EdwardsPoint};

pub(crate) mod hash_to_point;
pub use hash_to_point::{raw_hash_to_point, hash_to_point};

/// CLSAG struct, along with signing and verifying functionality.
pub mod clsag;
/// MLSAG struct.
pub mod mlsag;
/// RangeSig struct.
pub mod borromean;
/// Bulletproofs(+) structs, along with proving and verifying functionality.
pub mod bulletproofs;

use crate::{
  Protocol,
  serialize::*,
  ringct::{clsag::Clsag, mlsag::Mlsag, bulletproofs::Bulletproofs, borromean::RangeSig},
};

/// Generate a key image for a given key. Defined as `x * hash_to_point(xG)`.
pub fn generate_key_image(secret: &Zeroizing<Scalar>) -> EdwardsPoint {
  hash_to_point(&ED25519_BASEPOINT_TABLE * secret.deref()) * secret.deref()
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EcdhInfo {
  Standard { mask: Scalar, amount: Scalar },
  Bulletproof { amount: [u8; 8] },
}

impl EcdhInfo {
  pub fn read<R: Read>(rct_type: u8, r: &mut R) -> io::Result<(EcdhInfo)> {
    Ok(match rct_type {
      0 ..= 3 => EcdhInfo::Standard { mask: read_scalar(r)?, amount: read_scalar(r)? },
      _ => EcdhInfo::Bulletproof { amount: read_bytes(r)? },
    })
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      EcdhInfo::Standard { mask, amount } => {
        write_scalar(mask, w)?;
        write_scalar(amount, w)
      }
      EcdhInfo::Bulletproof { amount } => w.write_all(amount),
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RctBase {
  pub fee: u64,
  pub ecdh_info: Vec<EcdhInfo>,
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
        for ecdh in &self.ecdh_info {
          ecdh.write(w)?;
        }
        write_raw_vec(write_point, &self.commitments, w)
      }
      _ => panic!("Serializing unknown RctType's Base"),
    }
  }

  pub fn read<R: Read>(inputs: usize, outputs: usize, r: &mut R) -> io::Result<(RctBase, u8)> {
    let rct_type = read_byte(r)?;
    Ok((
      if rct_type == 0 {
        RctBase { fee: 0, ecdh_info: vec![], pseudo_outs: vec![], commitments: vec![] }
      } else {
        RctBase {
          fee: read_varint(r)?,
          pseudo_outs: if rct_type == 2 { read_raw_vec(read_point, inputs, r)? } else { vec![] },
          ecdh_info: (0 .. outputs)
            .map(|_| EcdhInfo::read(rct_type, r))
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
    range_sigs: Vec<RangeSig>,
    mlsags: Vec<Mlsag>,
    simple: bool,
  },
  BulletProof {
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
      RctPrunable::BulletProof { v2, .. } => {
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
        write_raw_vec(RangeSig::write, range_sigs, w)?;
        write_raw_vec(Mlsag::write, mlsags, w)
      }
      RctPrunable::BulletProof { bulletproofs, mlsags, pseudo_outs, v2 } => {
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
      1 => RctPrunable::Borromean {
        range_sigs: read_raw_vec(RangeSig::read, outputs, r)?,
        mlsags: vec![Mlsag::read(decoys[0], 1 + decoys.len(), r)?],
        simple: false,
      },
      2 => RctPrunable::Borromean {
        range_sigs: read_raw_vec(RangeSig::read, outputs, r)?,
        mlsags: (0 .. decoys.len())
          .map(|o| Mlsag::read(decoys[o], 2, r))
          .collect::<Result<_, _>>()?,
        simple: true,
      },
      3 | 4 => RctPrunable::BulletProof {
        bulletproofs: read_raw_vec(
          Bulletproofs::read,
          if rct_type == 3 {
            read_u32(r)?.try_into().unwrap()
          } else {
            read_varint(r)?.try_into().unwrap()
          },
          r,
        )?,
        mlsags: decoys.iter().map(|d| Mlsag::read(*d, 2, r)).collect::<Result<_, _>>()?,
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
      _ => todo!(),
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
