use core::cmp::Ordering;
use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use zeroize::Zeroize;

use curve25519_dalek::{
  scalar::Scalar,
  edwards::{EdwardsPoint, CompressedEdwardsY},
};

use crate::{
  Protocol, hash,
  serialize::*,
  ringct::{RctBase, RctPrunable, RctSignatures},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
  Gen(u64),
  ToKey { amount: Option<u64>, key_offsets: Vec<u64>, key_image: EdwardsPoint },
}

impl Input {
  // Worst-case predictive len
  pub(crate) fn fee_weight(ring_len: usize) -> usize {
    // Uses 1 byte for the VarInt amount due to amount being 0
    // Uses 1 byte for the VarInt encoding of the length of the ring as well
    1 + 1 + 1 + (8 * ring_len) + 32
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      Input::Gen(height) => {
        w.write_all(&[255])?;
        write_varint(height, w)
      }

      Input::ToKey { amount, key_offsets, key_image } => {
        w.write_all(&[2])?;
        write_varint(&amount.unwrap_or(0), w)?;
        write_vec(write_varint, key_offsets, w)?;
        write_point(key_image, w)
      }
    }
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut res = vec![];
    self.write(&mut res).unwrap();
    res
  }

  pub fn read<R: Read>(interpret_as_rct: bool, r: &mut R) -> io::Result<Input> {
    Ok(match read_byte(r)? {
      255 => Input::Gen(read_varint(r)?),
      2 => {
        let amount = read_varint(r)?;
        let amount = if (amount == 0) && interpret_as_rct { None } else { Some(amount) };
        Input::ToKey {
          amount,
          key_offsets: read_vec(read_varint, r)?,
          key_image: read_torsion_free_point(r)?,
        }
      }
      _ => {
        Err(io::Error::new(io::ErrorKind::Other, "Tried to deserialize unknown/unused input type"))?
      }
    })
  }
}

// Doesn't bother moving to an enum for the unused Script classes
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output {
  pub amount: Option<u64>,
  pub key: CompressedEdwardsY,
  pub view_tag: Option<u8>,
}

impl Output {
  pub(crate) fn fee_weight() -> usize {
    1 + 1 + 32 + 1
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_varint(&self.amount.unwrap_or(0), w)?;
    w.write_all(&[2 + u8::from(self.view_tag.is_some())])?;
    w.write_all(&self.key.to_bytes())?;
    if let Some(view_tag) = self.view_tag {
      w.write_all(&[view_tag])?;
    }
    Ok(())
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(8 + 1 + 32);
    self.write(&mut res).unwrap();
    res
  }

  pub fn read<R: Read>(interpret_as_rct: bool, r: &mut R) -> io::Result<Output> {
    let amount = read_varint(r)?;
    let amount = if interpret_as_rct {
      if amount != 0 {
        Err(io::Error::new(io::ErrorKind::Other, "RCT TX output wasn't 0"))?;
      }
      None
    } else {
      Some(amount)
    };

    let view_tag = match read_byte(r)? {
      2 => false,
      3 => true,
      _ => Err(io::Error::new(
        io::ErrorKind::Other,
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

  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
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

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_varint(&self.version, w)?;
    self.timelock.write(w)?;
    write_vec(Input::write, &self.inputs, w)?;
    write_vec(Output::write, &self.outputs, w)?;
    write_varint(&self.extra.len().try_into().unwrap(), w)?;
    w.write_all(&self.extra)
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut res = vec![];
    self.write(&mut res).unwrap();
    res
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<TransactionPrefix> {
    let version = read_varint(r)?;
    // TODO: Create an enum out of version
    if (version == 0) || (version > 2) {
      Err(io::Error::new(io::ErrorKind::Other, "unrecognized transaction version"))?;
    }

    let timelock = Timelock::from_raw(read_varint(r)?);

    let inputs = read_vec(|r| Input::read(version == 2, r), r)?;
    if inputs.is_empty() {
      Err(io::Error::new(io::ErrorKind::Other, "transaction had no inputs"))?;
    }
    let is_miner_tx = matches!(inputs[0], Input::Gen { .. });

    let mut prefix = TransactionPrefix {
      version,
      timelock,
      inputs,
      outputs: read_vec(|r| Output::read((!is_miner_tx) && (version == 2), r), r)?,
      extra: vec![],
    };
    prefix.extra = read_vec(read_byte, r)?;
    Ok(prefix)
  }

  pub fn hash(&self) -> [u8; 32] {
    hash(&self.serialize())
  }
}

/// Monero transaction. For version 1, rct_signatures still contains an accurate fee value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
  pub prefix: TransactionPrefix,
  pub signatures: Vec<Vec<(Scalar, Scalar)>>,
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

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.prefix.write(w)?;
    if self.prefix.version == 1 {
      for sigs in &self.signatures {
        for sig in sigs {
          write_scalar(&sig.0, w)?;
          write_scalar(&sig.1, w)?;
        }
      }
      Ok(())
    } else if self.prefix.version == 2 {
      self.rct_signatures.write(w)
    } else {
      panic!("Serializing a transaction with an unknown version");
    }
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(2048);
    self.write(&mut res).unwrap();
    res
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<Transaction> {
    let prefix = TransactionPrefix::read(r)?;
    let mut signatures = vec![];
    let mut rct_signatures = RctSignatures {
      base: RctBase { fee: 0, encrypted_amounts: vec![], pseudo_outs: vec![], commitments: vec![] },
      prunable: RctPrunable::Null,
    };

    if prefix.version == 1 {
      signatures = prefix
        .inputs
        .iter()
        .filter_map(|input| match input {
          Input::ToKey { key_offsets, .. } => Some(
            key_offsets
              .iter()
              .map(|_| Ok((read_scalar(r)?, read_scalar(r)?)))
              .collect::<Result<_, io::Error>>(),
          ),
          _ => None,
        })
        .collect::<Result<_, _>>()?;

      rct_signatures.base.fee = prefix
        .inputs
        .iter()
        .map(|input| match input {
          Input::Gen(..) => 0,
          Input::ToKey { amount, .. } => amount.unwrap(),
        })
        .sum::<u64>()
        .saturating_sub(prefix.outputs.iter().map(|output| output.amount.unwrap()).sum());
    } else if prefix.version == 2 {
      rct_signatures = RctSignatures::read(
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
      )?;
    } else {
      Err(io::Error::new(io::ErrorKind::Other, "Tried to deserialize unknown version"))?;
    }

    Ok(Transaction { prefix, signatures, rct_signatures })
  }

  pub fn hash(&self) -> [u8; 32] {
    let mut buf = Vec::with_capacity(2048);
    if self.prefix.version == 1 {
      self.write(&mut buf).unwrap();
      hash(&buf)
    } else {
      let mut hashes = Vec::with_capacity(96);

      hashes.extend(self.prefix.hash());

      self.rct_signatures.base.write(&mut buf, self.rct_signatures.rct_type()).unwrap();
      hashes.extend(hash(&buf));
      buf.clear();

      match self.rct_signatures.prunable {
        RctPrunable::Null => buf.resize(32, 0),
        _ => {
          self.rct_signatures.prunable.write(&mut buf, self.rct_signatures.rct_type()).unwrap();
          buf = hash(&buf).to_vec();
        }
      }
      hashes.extend(&buf);

      hash(&hashes)
    }
  }

  /// Calculate the hash of this transaction as needed for signing it.
  pub fn signature_hash(&self) -> [u8; 32] {
    let mut buf = Vec::with_capacity(2048);
    let mut sig_hash = Vec::with_capacity(96);

    sig_hash.extend(self.prefix.hash());

    self.rct_signatures.base.write(&mut buf, self.rct_signatures.rct_type()).unwrap();
    sig_hash.extend(hash(&buf));
    buf.clear();

    self.rct_signatures.prunable.signature_write(&mut buf).unwrap();
    sig_hash.extend(hash(&buf));

    hash(&sig_hash)
  }
}
