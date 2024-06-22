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
  ringct::{bulletproofs::Bulletproof, RctProofs},
};

/// An input in the Monero protocol.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
  /// An input for a miner transaction, which is generating new coins.
  Gen(u64),
  /// An input spending an output on-chain.
  ToKey {
    /// The pool this input spends an output of.
    amount: Option<u64>,
    /// The decoys used by this input's ring, specified as their offset distance from each other.
    key_offsets: Vec<u64>,
    /// The key image (linking tag, nullifer) for the spent output.
    key_image: EdwardsPoint,
  },
}

impl Input {
  /// The weight of this Input, as relevant for fees.
  pub fn fee_weight(offsets_weight: usize) -> usize {
    // Uses 1 byte for the input type
    // Uses 1 byte for the VarInt amount due to amount being 0
    1 + 1 + offsets_weight + 32
  }

  /// Write the Input.
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

  /// Serialize the Input to a Vec<u8>.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = vec![];
    self.write(&mut res).unwrap();
    res
  }

  /// Read an Input.
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

/// An output in the Monero protocol.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output {
  /// The pool this output should be sorted into.
  pub amount: Option<u64>,
  /// The key which can spend this output.
  pub key: CompressedEdwardsY,
  /// The view tag for this output, as used to accelerate scanning.
  pub view_tag: Option<u8>,
}

impl Output {
  /// The weight of this Output, as relevant for fees.
  pub fn fee_weight(view_tags: bool) -> usize {
    // Uses 1 byte for the output type
    // Uses 1 byte for the VarInt amount due to amount being 0
    1 + 1 + 32 + if view_tags { 1 } else { 0 }
  }

  /// Write the Output.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_varint(&self.amount.unwrap_or(0), w)?;
    w.write_all(&[2 + u8::from(self.view_tag.is_some())])?;
    w.write_all(&self.key.to_bytes())?;
    if let Some(view_tag) = self.view_tag {
      w.write_all(&[view_tag])?;
    }
    Ok(())
  }

  /// Write the Output to a Vec<u8>.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(8 + 1 + 32);
    self.write(&mut res).unwrap();
    res
  }

  /// Read an Output.
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

/// An additional timelock for a Monero transaction.
///
/// Monero outputs are locked by a default timelock. If a timelock is explicitly specified, the
/// longer of the two will be the timelock used.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum Timelock {
  /// No timelock.
  None,
  /// Locked until this block.
  Block(usize),
  /// Locked until this many seconds since the epoch.
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

/// The transaction prefix.
///
/// This is common to all transaction versions and contains most parts of the transaction needed to
/// handle it. It excludes any proofs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransactionPrefix {
  /// The timelock this transaction uses.
  pub timelock: Timelock,
  /// The inputs for this transaction.
  pub inputs: Vec<Input>,
  /// The outputs for this transaction.
  pub outputs: Vec<Output>,
  /// The additional data included within the transaction.
  ///
  /// This is an arbitrary data field, yet is used by wallets for containing the data necessary to
  /// scan the transaction.
  pub extra: Vec<u8>,
}

impl TransactionPrefix {
  /// The weight of this TransactionPrefix, as relevant for fees.
  pub fn fee_weight(
    decoy_weights: &[usize],
    outputs: usize,
    view_tags: bool,
    extra: usize,
  ) -> usize {
    // Assumes Timelock::None since this library won't let you create a TX with a timelock
    // 1 input for every decoy weight
    1 + varint_len(decoy_weights.len()) +
      decoy_weights.iter().map(|&offsets_weight| Input::fee_weight(offsets_weight)).sum::<usize>() +
      varint_len(outputs) +
      (outputs * Output::fee_weight(view_tags)) +
      varint_len(extra) +
      extra
  }

  /// Write a TransactionPrefix.
  ///
  /// This is distinct from Monero in that it won't write any version.
  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.timelock.write(w)?;
    write_vec(Input::write, &self.inputs, w)?;
    write_vec(Output::write, &self.outputs, w)?;
    write_varint(&self.extra.len(), w)?;
    w.write_all(&self.extra)
  }

  /// Read a TransactionPrefix.
  ///
  /// This is distinct from Monero in that it won't read the version. The version must be passed
  /// in.
  pub fn read<R: Read>(r: &mut R, version: u64) -> io::Result<TransactionPrefix> {
    let timelock = Timelock::from_raw(read_varint(r)?);

    let inputs = read_vec(|r| Input::read(r), r)?;
    if inputs.is_empty() {
      Err(io::Error::other("transaction had no inputs"))?;
    }
    let is_miner_tx = matches!(inputs[0], Input::Gen { .. });

    let mut prefix = TransactionPrefix {
      timelock,
      inputs,
      outputs: read_vec(|r| Output::read((!is_miner_tx) && (version == 2), r), r)?,
      extra: vec![],
    };
    prefix.extra = read_vec(read_byte, r)?;
    Ok(prefix)
  }

  fn hash(&self, version: u64) -> [u8; 32] {
    let mut buf = vec![];
    write_varint(&version, &mut buf).unwrap();
    self.write(&mut buf).unwrap();
    keccak256(buf)
  }
}

/// A Monero transaction.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Transaction {
  /// A version 1 transaction, used by the original Cryptonote codebase.
  V1 {
    /// The transaction's prefix.
    prefix: TransactionPrefix,
    /// The transaction's ring signatures.
    signatures: Vec<RingSignature>,
  },
  /// A version 2 transaction, used by the RingCT protocol.
  V2 {
    /// The transaction's prefix.
    prefix: TransactionPrefix,
    /// The transaction's proofs.
    proofs: Option<RctProofs>,
  },
}

impl Transaction {
  /// The weight of this Transaction, as relevant for fees.
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
    1 + TransactionPrefix::fee_weight(decoy_weights, outputs, view_tags, extra) +
      RctProofs::fee_weight(bp_plus, ring_len, decoy_weights.len(), outputs, fee)
  }

  /// Write the Transaction.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      Transaction::V1 { prefix, signatures } => {
        write_varint(&1u8, w)?;
        prefix.write(w)?;
        for ring_sig in signatures {
          ring_sig.write(w)?;
        }
      }
      Transaction::V2 { prefix, proofs } => {
        write_varint(&2u8, w)?;
        prefix.write(w)?;
        match proofs {
          None => w.write_all(&[0])?,
          Some(proofs) => proofs.write(w)?,
        }
      }
    }
    Ok(())
  }

  /// Write the Transaction to a Vec<u8>.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(2048);
    self.write(&mut res).unwrap();
    res
  }

  /// Read a Transaction.
  pub fn read<R: Read>(r: &mut R) -> io::Result<Transaction> {
    let version = read_varint(r)?;
    let prefix = TransactionPrefix::read(r, version)?;

    if version == 1 {
      let signatures = prefix
        .inputs
        .iter()
        .filter_map(|input| match input {
          // TODO: This allows mixing Gen and ToKey, which is likely undefined behavior?
          Input::ToKey { key_offsets, .. } => Some(RingSignature::read(key_offsets.len(), r)),
          _ => None,
        })
        .collect::<Result<_, _>>()?;

      Ok(Transaction::V1 { prefix, signatures })
    } else if version == 2 {
      let proofs = Some(RctProofs::read(
        prefix.inputs.first().map_or(0, |input| match input {
          Input::Gen(_) => 0,
          Input::ToKey { key_offsets, .. } => key_offsets.len(),
        }),
        prefix.inputs.len(),
        prefix.outputs.len(),
        r,
      )?);

      Ok(Transaction::V2 { prefix, proofs })
    } else {
      Err(io::Error::other("tried to deserialize unknown version"))
    }
  }

  /// The hash of the transaction.
  pub fn hash(&self) -> [u8; 32] {
    let mut buf = Vec::with_capacity(2048);
    match self {
      Transaction::V1 { .. } => {
        self.write(&mut buf).unwrap();
        keccak256(buf)
      }
      Transaction::V2 { prefix, proofs } => {
        let mut hashes = Vec::with_capacity(96);

        hashes.extend(prefix.hash(2));

        if let Some(proofs) = proofs {
          let rct_type = proofs.rct_type();
          proofs.base.write(&mut buf, rct_type).unwrap();
          hashes.extend(keccak256(&buf));
          buf.clear();

          proofs.prunable.write(&mut buf, rct_type).unwrap();
          hashes.extend(keccak256(buf));
        } else {
          // Serialization of RctBase::Null
          hashes.extend(keccak256([0]));
          hashes.extend([0; 32]);
        }

        keccak256(hashes)
      }
    }
  }

  /// Calculate the hash of this transaction as needed for signing it.
  ///
  /// This returns None if the transaction is without signatures.
  pub fn signature_hash(&self) -> Option<[u8; 32]> {
    match self {
      Transaction::V1 { prefix, .. } => Some(prefix.hash(1)),
      Transaction::V2 { prefix, proofs } => {
        let mut buf = Vec::with_capacity(2048);
        let mut sig_hash = Vec::with_capacity(96);

        sig_hash.extend(prefix.hash(2));

        let proofs = proofs.as_ref()?;
        proofs.base.write(&mut buf, proofs.rct_type()).unwrap();
        sig_hash.extend(keccak256(&buf));
        buf.clear();

        proofs.prunable.signature_write(&mut buf).unwrap();
        sig_hash.extend(keccak256(buf));

        Some(keccak256(sig_hash))
      }
    }
  }

  fn is_rct_bulletproof(&self) -> bool {
    match self {
      Transaction::V1 { .. } => false,
      Transaction::V2 { proofs, .. } => {
        let Some(proofs) = proofs else { return false };
        proofs.rct_type().bulletproof()
      }
    }
  }

  fn is_rct_bulletproof_plus(&self) -> bool {
    match self {
      Transaction::V1 { .. } => false,
      Transaction::V2 { proofs, .. } => {
        let Some(proofs) = proofs else { return false };
        proofs.rct_type().bulletproof_plus()
      }
    }
  }

  /// Calculate the transaction's weight.
  pub fn weight(&self) -> usize {
    let blob_size = self.serialize().len();

    let bp = self.is_rct_bulletproof();
    let bp_plus = self.is_rct_bulletproof_plus();
    if !(bp || bp_plus) {
      blob_size
    } else {
      blob_size +
        Bulletproof::calculate_bp_clawback(
          bp_plus,
          match self {
            Transaction::V1 { .. } => panic!("v1 transaction was BP(+)"),
            Transaction::V2 { prefix, .. } => prefix.outputs.len(),
          },
        )
        .0
    }
  }
}
