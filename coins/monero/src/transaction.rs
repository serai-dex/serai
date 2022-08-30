use core::cmp::Ordering;

use zeroize::Zeroize;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use crate::{
  Protocol, hash,
  serialize::*,
  ringct::{RctPrunable, RctSignatures},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
  Gen(u64),
  ToKey { amount: u64, key_offsets: Vec<u64>, key_image: EdwardsPoint },
}

impl Input {
  // Worst-case predictive len
  pub(crate) fn fee_weight(ring_len: usize) -> usize {
    // Uses 1 byte for the VarInt amount due to amount being 0
    // Uses 1 byte for the VarInt encoding of the length of the ring as well
    1 + 1 + 1 + (8 * ring_len) + 32
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    match self {
      Input::Gen(height) => {
        w.write_all(&[255])?;
        write_varint(height, w)
      }

      Input::ToKey { amount, key_offsets, key_image } => {
        w.write_all(&[2])?;
        write_varint(amount, w)?;
        write_vec(write_varint, key_offsets, w)?;
        write_point(key_image, w)
      }
    }
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<Input> {
    Ok(match read_byte(r)? {
      255 => Input::Gen(read_varint(r)?),
      2 => Input::ToKey {
        amount: read_varint(r)?,
        key_offsets: read_vec(read_varint, r)?,
        key_image: read_torsion_free_point(r)?,
      },
      _ => Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Tried to deserialize unknown/unused input type",
      ))?,
    })
  }
}

// Doesn't bother moving to an enum for the unused Script classes
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output {
  pub amount: u64,
  pub key: CompressedEdwardsY,
  pub view_tag: Option<u8>,
}

impl Output {
  pub(crate) fn fee_weight() -> usize {
    1 + 1 + 32 + 1
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    write_varint(&self.amount, w)?;
    w.write_all(&[2 + (if self.view_tag.is_some() { 1 } else { 0 })])?;
    w.write_all(&self.key.to_bytes())?;
    if let Some(view_tag) = self.view_tag {
      w.write_all(&[view_tag])?;
    }
    Ok(())
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<Output> {
    let amount = read_varint(r)?;
    let view_tag = match read_byte(r)? {
      2 => false,
      3 => true,
      _ => Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Tried to deserialize unknown/unused output type",
      ))?,
    };

    Ok(Output {
      amount,
      key: CompressedEdwardsY(read_bytes(r)?),
      view_tag: if view_tag { Some(read_byte(r)?) } else { None },
    })
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum Timelock {
  None,
  Block(usize),
  Time(u64),
}

impl Timelock {
  fn from_raw(raw: u64) -> Timelock {
    if raw == 0 {
      Timelock::None
    } else if raw < 500_000_000 {
      Timelock::Block(usize::try_from(raw).unwrap())
    } else {
      Timelock::Time(raw)
    }
  }

  pub(crate) fn fee_weight() -> usize {
    8
  }

  fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    write_varint(
      &match self {
        Timelock::None => 0,
        Timelock::Block(block) => (*block).try_into().unwrap(),
        Timelock::Time(time) => *time,
      },
      w,
    )
  }
}

impl PartialOrd for Timelock {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    match (self, other) {
      (Timelock::None, _) => Some(Ordering::Less),
      (Timelock::Block(a), Timelock::Block(b)) => a.partial_cmp(b),
      (Timelock::Time(a), Timelock::Time(b)) => a.partial_cmp(b),
      _ => None,
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransactionPrefix {
  pub version: u64,
  pub timelock: Timelock,
  pub inputs: Vec<Input>,
  pub outputs: Vec<Output>,
  pub extra: Vec<u8>,
}

impl TransactionPrefix {
  pub(crate) fn fee_weight(ring_len: usize, inputs: usize, outputs: usize, extra: usize) -> usize {
    // Assumes Timelock::None since this library won't let you create a TX with a timelock
    1 + 1 +
      varint_len(inputs) +
      (inputs * Input::fee_weight(ring_len)) +
      1 +
      (outputs * Output::fee_weight()) +
      varint_len(extra) +
      extra
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    write_varint(&self.version, w)?;
    self.timelock.serialize(w)?;
    write_vec(Input::serialize, &self.inputs, w)?;
    write_vec(Output::serialize, &self.outputs, w)?;
    write_varint(&self.extra.len().try_into().unwrap(), w)?;
    w.write_all(&self.extra)
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<TransactionPrefix> {
    let mut prefix = TransactionPrefix {
      version: read_varint(r)?,
      timelock: Timelock::from_raw(read_varint(r)?),
      inputs: read_vec(Input::deserialize, r)?,
      outputs: read_vec(Output::deserialize, r)?,
      extra: vec![],
    };
    prefix.extra = read_vec(read_byte, r)?;
    Ok(prefix)
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
  pub prefix: TransactionPrefix,
  pub rct_signatures: RctSignatures,
}

impl Transaction {
  pub(crate) fn fee_weight(
    protocol: Protocol,
    inputs: usize,
    outputs: usize,
    extra: usize,
  ) -> usize {
    TransactionPrefix::fee_weight(protocol.ring_len(), inputs, outputs, extra) +
      RctSignatures::fee_weight(protocol, inputs, outputs)
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.prefix.serialize(w)?;
    self.rct_signatures.serialize(w)
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<Transaction> {
    let prefix = TransactionPrefix::deserialize(r)?;
    Ok(Transaction {
      rct_signatures: RctSignatures::deserialize(
        prefix
          .inputs
          .iter()
          .map(|input| match input {
            Input::Gen(_) => 0,
            Input::ToKey { key_offsets, .. } => key_offsets.len(),
          })
          .collect(),
        prefix.outputs.len(),
        r,
      )?,
      prefix,
    })
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

      self
        .rct_signatures
        .base
        .serialize(&mut serialized, self.rct_signatures.prunable.rct_type())
        .unwrap();
      sig_hash.extend(hash(&serialized));
      serialized.clear();

      match self.rct_signatures.prunable {
        RctPrunable::Null => serialized.resize(32, 0),
        _ => {
          self.rct_signatures.prunable.serialize(&mut serialized).unwrap();
          serialized = hash(&serialized).to_vec();
        }
      }
      sig_hash.extend(&serialized);

      hash(&sig_hash)
    }
  }

  pub fn signature_hash(&self) -> [u8; 32] {
    let mut serialized = Vec::with_capacity(2048);
    let mut sig_hash = Vec::with_capacity(96);

    self.prefix.serialize(&mut serialized).unwrap();
    sig_hash.extend(hash(&serialized));
    serialized.clear();

    self
      .rct_signatures
      .base
      .serialize(&mut serialized, self.rct_signatures.prunable.rct_type())
      .unwrap();
    sig_hash.extend(hash(&serialized));
    serialized.clear();

    self.rct_signatures.prunable.signature_serialize(&mut serialized).unwrap();
    sig_hash.extend(&hash(&serialized));

    hash(&sig_hash)
  }
}
