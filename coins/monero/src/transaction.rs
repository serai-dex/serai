use curve25519_dalek::edwards::EdwardsPoint;

use crate::{
  hash,
  serialize::*,
  bulletproofs::Bulletproofs, clsag::Clsag,
};

pub enum Input {
  Gen(u64),

  ToKey {
    amount: u64,
    key_offsets: Vec<u64>,
    key_image: EdwardsPoint
  }
}

impl Input {
  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    match self {
      Input::Gen(height) => {
        w.write_all(&[0])?;
        write_varint(height, w)
      },

      Input::ToKey { amount, key_offsets, key_image } => {
        w.write_all(&[2])?;
        write_varint(amount, w)?;
        write_vec(write_varint, key_offsets, w)?;
        write_point(key_image, w)
      }
    }
  }
}

// Doesn't bother moving to an enum for the unused Script classes
pub struct Output {
  pub amount: u64,
  pub key: EdwardsPoint,
  pub tag: Option<u8>
}

impl Output {
  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    write_varint(&self.amount, w)?;
    w.write_all(&[2 + (if self.tag.is_some() { 1 } else { 0 })])?;
    write_point(&self.key, w)?;
    if let Some(tag) = self.tag {
      w.write_all(&[tag])?;
    }
    Ok(())
  }
}

pub struct TransactionPrefix {
  pub version: u64,
  pub unlock_time: u64,
  pub inputs: Vec<Input>,
  pub outputs: Vec<Output>,
  pub extra: Vec<u8>
}

impl TransactionPrefix {
  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    write_varint(&self.version, w)?;
    write_varint(&self.unlock_time, w)?;
    write_vec(Input::serialize, &self.inputs, w)?;
    write_vec(Output::serialize, &self.outputs, w)?;
    write_varint(&self.extra.len().try_into().unwrap(), w)?;
    w.write_all(&self.extra)
  }
}

pub struct RctBase {
  pub fee: u64,
  pub ecdh_info: Vec<[u8; 8]>,
  pub commitments: Vec<EdwardsPoint>
}

impl RctBase {
  pub fn serialize<W: std::io::Write>(&self, w: &mut W, rct_type: u8) -> std::io::Result<()> {
    w.write_all(&[rct_type])?;
    write_varint(&self.fee, w)?;
    for ecdh in &self.ecdh_info {
      w.write_all(ecdh)?;
    }
    write_raw_vec(write_point, &self.commitments, w)
  }
}

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

  pub fn signature_serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    match self {
      RctPrunable::Null => panic!("Serializing RctPrunable::Null for a signature"),
      RctPrunable::Clsag { bulletproofs, .. } => bulletproofs.iter().map(|bp| bp.signature_serialize(w)).collect(),
    }
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
}

pub struct RctSignatures {
  pub base: RctBase,
  pub prunable: RctPrunable
}

impl RctSignatures {
  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.base.serialize(w, self.prunable.rct_type())?;
    self.prunable.serialize(w)
  }
}

pub struct Transaction {
  pub prefix: TransactionPrefix,
  pub rct_signatures: RctSignatures
}

impl Transaction {
  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.prefix.serialize(w)?;
    self.rct_signatures.serialize(w)
  }

  pub fn hash(&self) -> [u8; 32] {
    let mut serialized = Vec::with_capacity(2048);
    if self.prefix.version == 1 {
      self.serialize(&mut serialized).unwrap();
      hash(&serialized)
    } else {
      let mut sig_hash = Vec::with_capacity(96);

      self.prefix.serialize(&mut serialized).unwrap();
      sig_hash.extend(hash(&serialized));
      serialized.clear();

      self.rct_signatures.base.serialize(
        &mut serialized,
        self.rct_signatures.prunable.rct_type()
      ).unwrap();
      sig_hash.extend(hash(&serialized));
      serialized.clear();

      self.rct_signatures.prunable.serialize(&mut serialized).unwrap();
      sig_hash.extend(hash(&serialized));

      hash(&sig_hash)
    }
  }

  pub fn signature_hash(&self) -> [u8; 32] {
    let mut serialized = Vec::with_capacity(2048);
    let mut sig_hash = Vec::with_capacity(96);

    self.prefix.serialize(&mut serialized).unwrap();
    sig_hash.extend(hash(&serialized));
    serialized.clear();

    self.rct_signatures.base.serialize(&mut serialized, self.rct_signatures.prunable.rct_type()).unwrap();
    sig_hash.extend(hash(&serialized));
    serialized.clear();

    self.rct_signatures.prunable.signature_serialize(&mut serialized).unwrap();
    sig_hash.extend(&hash(&serialized));

    hash(&sig_hash)
  }
}
