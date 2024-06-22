use core::cmp::Ordering;
use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use zeroize::Zeroize;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use crate::{
  io::*,
  primitives::keccak256,
  ring_signatures::RingSignature,
  ringct::{bulletproofs::Bulletproof, RctType, RctBase, RctPrunable, RctSignatures},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
  Gen(u64),
  ToKey { amount: Option<u64>, key_offsets: Vec<u64>, key_image: EdwardsPoint },
}

impl Input {
  pub fn fee_weight(offsets_weight: usize) -> usize {
    // Uses 1 byte for the input type
    // Uses 1 byte for the VarInt amount due to amount being 0
    1 + 1 + offsets_weight + 32
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

  pub fn read<R: Read>(r: &mut R) -> io::Result<Input> {
    Ok(match read_byte(r)? {
      255 => Input::Gen(read_varint(r)?),
      2 => {
        let amount = read_varint(r)?;
        // https://github.com/monero-project/monero/
        //   blob/00fd416a99686f0956361d1cd0337fe56e58d4a7/
        //   src/cryptonote_basic/cryptonote_format_utils.cpp#L860-L863
        // A non-RCT 0-amount input can't exist because only RCT TXs can have a 0-amount output
        // That's why collapsing to None if the amount is 0 is safe, even without knowing if RCT
        let amount = if amount == 0 { None } else { Some(amount) };
        Input::ToKey {
          amount,
          key_offsets: read_vec(read_varint, r)?,
          key_image: read_torsion_free_point(r)?,
        }
      }
      _ => Err(io::Error::other("Tried to deserialize unknown/unused input type"))?,
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
  pub fn fee_weight(view_tags: bool) -> usize {
    // Uses 1 byte for the output type
    // Uses 1 byte for the VarInt amount due to amount being 0
    1 + 1 + 32 + if view_tags { 1 } else { 0 }
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

  pub fn read<R: Read>(rct: bool, r: &mut R) -> io::Result<Output> {
    let amount = read_varint(r)?;
    let amount = if rct {
      if amount != 0 {
        Err(io::Error::other("RCT TX output wasn't 0"))?;
      }
      None
    } else {
      Some(amount)
    };

    let view_tag = match read_byte(r)? {
      2 => false,
      3 => true,
      _ => Err(io::Error::other("Tried to deserialize unknown/unused output type"))?,
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
      // TODO: This is trivial to have panic
      Timelock::Block(usize::try_from(raw).unwrap())
    } else {
      Timelock::Time(raw)
    }
  }

  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_varint(
      &match self {
        Timelock::None => 0,
        // TODO: Check this unwrap
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
      (Timelock::None, Timelock::None) => Some(Ordering::Equal),
      (Timelock::None, _) => Some(Ordering::Less),
      (_, Timelock::None) => Some(Ordering::Greater),
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
  pub fn fee_weight(
    decoy_weights: &[usize],
    outputs: usize,
    view_tags: bool,
    extra: usize,
  ) -> usize {
    // Assumes Timelock::None since this library won't let you create a TX with a timelock
    // 1 input for every decoy weight
    1 + 1 +
      varint_len(decoy_weights.len()) +
      decoy_weights.iter().map(|&offsets_weight| Input::fee_weight(offsets_weight)).sum::<usize>() +
      varint_len(outputs) +
      (outputs * Output::fee_weight(view_tags)) +
      varint_len(extra) +
      extra
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_varint(&self.version, w)?;
    self.timelock.write(w)?;
    write_vec(Input::write, &self.inputs, w)?;
    write_vec(Output::write, &self.outputs, w)?;
    write_varint(&self.extra.len(), w)?;
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
      Err(io::Error::other("unrecognized transaction version"))?;
    }

    let timelock = Timelock::from_raw(read_varint(r)?);

    let inputs = read_vec(|r| Input::read(r), r)?;
    if inputs.is_empty() {
      Err(io::Error::other("transaction had no inputs"))?;
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
    keccak256(self.serialize())
  }
}

/// Monero transaction. For version 1, rct_signatures still contains an accurate fee value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
  pub prefix: TransactionPrefix,
  pub signatures: Vec<RingSignature>,
  pub rct_signatures: RctSignatures,
}

impl Transaction {
  // TODO: Replace ring_len, decoy_weights for &[&[usize]], where the inner buf is the decoy
  // offsets
  pub fn fee_weight(
    view_tags: bool,
    bp_plus: bool,
    ring_len: usize,
    decoy_weights: &[usize],
    outputs: usize,
    extra: usize,
    fee: u64,
  ) -> usize {
    TransactionPrefix::fee_weight(decoy_weights, outputs, view_tags, extra) +
      RctSignatures::fee_weight(bp_plus, ring_len, decoy_weights.len(), outputs, fee)
  }

  #[must_use]
  pub fn write<W: Write>(&self, w: &mut W) -> Option<io::Result<()>> {
    if let Err(e) = self.prefix.write(w) {
      return Some(Err(e));
    };
    if self.prefix.version == 1 {
      for ring_sig in &self.signatures {
        if let Err(e) = ring_sig.write(w) {
          return Some(Err(e));
        };
      }
      Some(Ok(()))
    } else if self.prefix.version == 2 {
      if let Err(e) = self.rct_signatures.write(w)? {
        return Some(Err(e));
      }
      Some(Ok(()))
    } else {
      Some(Err(io::Error::other("transaction had an unknown version")))
    }
  }

  #[must_use]
  pub fn serialize(&self) -> Option<Vec<u8>> {
    let mut res = Vec::with_capacity(2048);
    self.write(&mut res)?.unwrap();
    Some(res)
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
          Input::ToKey { key_offsets, .. } => Some(RingSignature::read(key_offsets.len(), r)),
          _ => None,
        })
        .collect::<Result<_, _>>()?;

      if !matches!(prefix.inputs[0], Input::Gen(..)) {
        let in_amount = prefix
          .inputs
          .iter()
          .map(|input| match input {
            Input::Gen(..) => Err(io::Error::other("Input::Gen present in non-coinbase v1 TX"))?,
            // v1 TXs can burn v2 outputs
            // dcff3fe4f914d6b6bd4a5b800cc4cca8f2fdd1bd73352f0700d463d36812f328 is one such TX
            // It includes a pre-RCT signature for a RCT output, yet if you interpret the RCT
            // output as being worth 0, it passes a sum check (guaranteed since no outputs are RCT)
            Input::ToKey { amount, .. } => Ok(amount.unwrap_or(0)),
          })
          .collect::<io::Result<Vec<_>>>()?
          .into_iter()
          .sum::<u64>();

        let mut out = 0;
        for output in &prefix.outputs {
          if output.amount.is_none() {
            Err(io::Error::other("v1 transaction had a 0-amount output"))?;
          }
          out += output.amount.unwrap();
        }

        if in_amount < out {
          Err(io::Error::other("transaction spent more than it had as inputs"))?;
        }
        rct_signatures.base.fee = in_amount - out;
      }
    } else if prefix.version == 2 {
      rct_signatures = RctSignatures::read(
        prefix.inputs.first().map_or(0, |input| match input {
          Input::Gen(_) => 0,
          Input::ToKey { key_offsets, .. } => key_offsets.len(),
        }),
        prefix.inputs.len(),
        prefix.outputs.len(),
        r,
      )?;
    } else {
      Err(io::Error::other("Tried to deserialize unknown version"))?;
    }

    Ok(Transaction { prefix, signatures, rct_signatures })
  }

  #[must_use]
  pub fn hash(&self) -> Option<[u8; 32]> {
    let mut buf = Vec::with_capacity(2048);
    if self.prefix.version == 1 {
      self.write(&mut buf)?.unwrap();
      Some(keccak256(buf))
    } else {
      let mut hashes = Vec::with_capacity(96);

      hashes.extend(self.prefix.hash());

      let rct_type = self.rct_signatures.rct_type()?;
      self.rct_signatures.base.write(&mut buf, rct_type).unwrap();
      hashes.extend(keccak256(&buf));
      buf.clear();

      hashes.extend(&match self.rct_signatures.prunable {
        RctPrunable::Null => [0; 32],
        _ => {
          self.rct_signatures.prunable.write(&mut buf, rct_type).unwrap();
          keccak256(buf)
        }
      });

      Some(keccak256(hashes))
    }
  }

  /// Calculate the hash of this transaction as needed for signing it.
  #[must_use]
  pub fn signature_hash(&self) -> Option<[u8; 32]> {
    if self.prefix.version == 1 {
      return Some(self.prefix.hash());
    }

    let mut buf = Vec::with_capacity(2048);
    let mut sig_hash = Vec::with_capacity(96);

    sig_hash.extend(self.prefix.hash());

    self.rct_signatures.base.write(&mut buf, self.rct_signatures.rct_type()?).unwrap();
    sig_hash.extend(keccak256(&buf));
    buf.clear();

    self.rct_signatures.prunable.signature_write(&mut buf)?.unwrap();
    sig_hash.extend(keccak256(buf));

    Some(keccak256(sig_hash))
  }

  fn is_rct_bulletproof(&self) -> bool {
    let Some(rct_type) = self.rct_signatures.rct_type() else { return false };
    match rct_type {
      RctType::Bulletproofs | RctType::BulletproofsCompactAmount | RctType::Clsag => true,
      RctType::Null |
      RctType::MlsagAggregate |
      RctType::MlsagIndividual |
      RctType::BulletproofsPlus => false,
    }
  }

  fn is_rct_bulletproof_plus(&self) -> bool {
    let Some(rct_type) = self.rct_signatures.rct_type() else { return false };
    match rct_type {
      RctType::BulletproofsPlus => true,
      RctType::Null |
      RctType::MlsagAggregate |
      RctType::MlsagIndividual |
      RctType::Bulletproofs |
      RctType::BulletproofsCompactAmount |
      RctType::Clsag => false,
    }
  }

  /// Calculate the transaction's weight.
  pub fn weight(&self) -> Option<usize> {
    let blob_size = self.serialize()?.len();

    let bp = self.is_rct_bulletproof();
    let bp_plus = self.is_rct_bulletproof_plus();
    Some(if !(bp || bp_plus) {
      blob_size
    } else {
      blob_size + Bulletproof::calculate_bp_clawback(bp_plus, self.prefix.outputs.len()).0
    })
  }
}
