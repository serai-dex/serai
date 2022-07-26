use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar, edwards::EdwardsPoint};

pub(crate) mod hash_to_point;
pub use hash_to_point::hash_to_point;

pub mod clsag;
pub mod bulletproofs;

use crate::{
  serialize::*,
  ringct::{clsag::Clsag, bulletproofs::Bulletproofs},
};

pub fn generate_key_image(secret: Scalar) -> EdwardsPoint {
  secret * hash_to_point(&secret * &ED25519_BASEPOINT_TABLE)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RctBase {
  pub fee: u64,
  pub ecdh_info: Vec<[u8; 8]>,
  pub commitments: Vec<EdwardsPoint>,
}

impl RctBase {
  pub(crate) fn fee_weight(outputs: usize) -> usize {
    1 + 8 + (outputs * (8 + 32))
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W, rct_type: u8) -> std::io::Result<()> {
    w.write_all(&[rct_type])?;
    match rct_type {
      0 => Ok(()),
      5 | 6 => {
        write_varint(&self.fee, w)?;
        for ecdh in &self.ecdh_info {
          w.write_all(ecdh)?;
        }
        write_raw_vec(write_point, &self.commitments, w)
      }
      _ => panic!("Serializing unknown RctType's Base"),
    }
  }

  pub fn deserialize<R: std::io::Read>(
    outputs: usize,
    r: &mut R,
  ) -> std::io::Result<(RctBase, u8)> {
    let mut rct_type = [0];
    r.read_exact(&mut rct_type)?;
    Ok((
      if rct_type[0] == 0 {
        RctBase { fee: 0, ecdh_info: vec![], commitments: vec![] }
      } else {
        RctBase {
          fee: read_varint(r)?,
          ecdh_info: (0 .. outputs)
            .map(|_| {
              let mut ecdh = [0; 8];
              r.read_exact(&mut ecdh).map(|_| ecdh)
            })
            .collect::<Result<_, _>>()?,
          commitments: read_raw_vec(read_point, outputs, r)?,
        }
      },
      rct_type[0],
    ))
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RctPrunable {
  Null,
  Clsag {
    plus: bool,
    bulletproofs: Vec<Bulletproofs>,
    clsags: Vec<Clsag>,
    pseudo_outs: Vec<EdwardsPoint>,
  },
}

impl RctPrunable {
  pub fn rct_type(&self) -> u8 {
    match self {
      RctPrunable::Null => 0,
      RctPrunable::Clsag { plus, .. } => {
        if !plus {
          5
        } else {
          6
        }
      }
    }
  }

  pub(crate) fn fee_weight(inputs: usize, outputs: usize) -> usize {
    1 + Bulletproofs::fee_weight(outputs) + (inputs * (Clsag::fee_weight() + 32))
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    match self {
      RctPrunable::Null => Ok(()),
      RctPrunable::Clsag { bulletproofs, clsags, pseudo_outs, .. } => {
        write_vec(Bulletproofs::serialize, bulletproofs, w)?;
        write_raw_vec(Clsag::serialize, clsags, w)?;
        write_raw_vec(write_point, pseudo_outs, w)
      }
    }
  }

  pub fn deserialize<R: std::io::Read>(
    rct_type: u8,
    decoys: &[usize],
    r: &mut R,
  ) -> std::io::Result<RctPrunable> {
    let mut read_clsag = |plus| -> std::io::Result<RctPrunable> {
      Ok(RctPrunable::Clsag {
        plus,
        bulletproofs: read_vec(
          if !plus { Bulletproofs::deserialize } else { Bulletproofs::deserialize_plus },
          r,
        )?,
        clsags: (0 .. decoys.len())
          .map(|o| Clsag::deserialize(decoys[o], r))
          .collect::<Result<_, _>>()?,
        pseudo_outs: read_raw_vec(read_point, decoys.len(), r)?,
      })
    };

    Ok(match rct_type {
      0 => RctPrunable::Null,
      5 => read_clsag(false)?,
      6 => read_clsag(true)?,
      _ => Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Tried to deserialize unknown RCT type",
      ))?,
    })
  }

  pub fn signature_serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    match self {
      RctPrunable::Null => panic!("Serializing RctPrunable::Null for a signature"),
      RctPrunable::Clsag { bulletproofs, .. } => {
        bulletproofs.iter().try_for_each(|bp| bp.signature_serialize(w))
      }
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RctSignatures {
  pub base: RctBase,
  pub prunable: RctPrunable,
}

impl RctSignatures {
  pub(crate) fn fee_weight(inputs: usize, outputs: usize) -> usize {
    RctBase::fee_weight(outputs) + RctPrunable::fee_weight(inputs, outputs)
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.base.serialize(w, self.prunable.rct_type())?;
    self.prunable.serialize(w)
  }

  pub fn deserialize<R: std::io::Read>(
    decoys: Vec<usize>,
    outputs: usize,
    r: &mut R,
  ) -> std::io::Result<RctSignatures> {
    let base = RctBase::deserialize(outputs, r)?;
    Ok(RctSignatures { base: base.0, prunable: RctPrunable::deserialize(base.1, &decoys, r)? })
  }
}
