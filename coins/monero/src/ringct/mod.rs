use curve25519_dalek::edwards::EdwardsPoint;

pub mod bulletproofs;
pub mod clsag;

use crate::{
  serialize::*,
  ringct::{clsag::Clsag, bulletproofs::Bulletproofs}
};

#[derive(Clone, PartialEq, Debug)]
pub struct RctBase {
  pub fee: u64,
  pub ecdh_info: Vec<[u8; 8]>,
  pub commitments: Vec<EdwardsPoint>
}

impl RctBase {
  pub(crate) fn fee_weight(outputs: usize) -> usize {
    1 + 8 + (outputs * (8 + 32))
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W, rct_type: u8) -> std::io::Result<()> {
    w.write_all(&[rct_type])?;
    match rct_type {
      0 => Ok(()),
      5 => {
        write_varint(&self.fee, w)?;
        for ecdh in &self.ecdh_info {
          w.write_all(ecdh)?;
        }
        write_raw_vec(write_point, &self.commitments, w)
      },
      _ => panic!("Serializing unknown RctType's Base")
    }
  }

  pub fn deserialize<R: std::io::Read>(outputs: usize, r: &mut R) -> std::io::Result<(RctBase, u8)> {
    let mut rct_type = [0];
    r.read_exact(&mut rct_type)?;
    Ok((
      if rct_type[0] == 0 {
        RctBase { fee: 0, ecdh_info: vec![], commitments: vec![] }
      } else {
        RctBase {
          fee: read_varint(r)?,
          ecdh_info: (0 .. outputs).map(
            |_| { let mut ecdh = [0; 8]; r.read_exact(&mut ecdh).map(|_| ecdh) }
          ).collect::<Result<_, _>>()?,
          commitments: read_raw_vec(read_point, outputs, r)?
        }
      },
      rct_type[0]
    ))
  }
}

#[derive(Clone, PartialEq, Debug)]
pub enum RctPrunable {
  Null,
  Clsag {
    bulletproofs: Vec<Bulletproofs>,
    clsags: Vec<Clsag>,
    pseudo_outs: Vec<EdwardsPoint>
  }
}

impl RctPrunable {
  pub fn rct_type(&self) -> u8 {
    match self {
      RctPrunable::Null => 0,
      RctPrunable::Clsag { .. } => 5
    }
  }

  pub(crate) fn fee_weight(inputs: usize, outputs: usize) -> usize {
    1 + Bulletproofs::fee_weight(outputs) + (inputs * (Clsag::fee_weight() + 32))
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    match self {
      RctPrunable::Null => Ok(()),
      RctPrunable::Clsag { bulletproofs, clsags, pseudo_outs } => {
        write_vec(Bulletproofs::serialize, &bulletproofs, w)?;
        write_raw_vec(Clsag::serialize, &clsags, w)?;
        write_raw_vec(write_point, &pseudo_outs, w)
      }
    }
  }

  pub fn deserialize<R: std::io::Read>(
    rct_type: u8,
    decoys: &[usize],
    r: &mut R
  ) -> std::io::Result<RctPrunable> {
    Ok(
      match rct_type {
        0 => RctPrunable::Null,
        5 => RctPrunable::Clsag {
          // TODO: Can the amount of outputs be calculated from the BPs for any validly formed TX?
          bulletproofs: read_vec(Bulletproofs::deserialize, r)?,
          clsags: (0 .. decoys.len()).map(|o| Clsag::deserialize(decoys[o], r)).collect::<Result<_, _>>()?,
          pseudo_outs: read_raw_vec(read_point, decoys.len(), r)?
        },
        _ => Err(std::io::Error::new(std::io::ErrorKind::Other, "Tried to deserialize unknown RCT type"))?
      }
    )
  }

  pub fn signature_serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    match self {
      RctPrunable::Null => panic!("Serializing RctPrunable::Null for a signature"),
      RctPrunable::Clsag { bulletproofs, .. } => bulletproofs.iter().map(|bp| bp.signature_serialize(w)).collect(),
    }
  }
}

#[derive(Clone, PartialEq, Debug)]
pub struct RctSignatures {
  pub base: RctBase,
  pub prunable: RctPrunable
}

impl RctSignatures {
  pub(crate) fn fee_weight(inputs: usize, outputs: usize) -> usize {
    RctBase::fee_weight(outputs) + RctPrunable::fee_weight(inputs, outputs)
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.base.serialize(w, self.prunable.rct_type())?;
    self.prunable.serialize(w)
  }

  pub fn deserialize<R: std::io::Read>(decoys: Vec<usize>, outputs: usize, r: &mut R) -> std::io::Result<RctSignatures> {
    let base = RctBase::deserialize(outputs, r)?;
    Ok(RctSignatures { base: base.0, prunable: RctPrunable::deserialize(base.1, &decoys, r)? })
  }
}
