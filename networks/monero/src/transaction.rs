use core::cmp::Ordering;
use std_shims::{
  vec,
  vec::Vec,
  io::{self, Read, Write},
};

use zeroize::Zeroize;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use crate::{
  io::*,
  primitives::keccak256,
  ring_signatures::RingSignature,
  ringct::{bulletproofs::Bulletproof, PrunedRctProofs},
};

/// An input in the Monero protocol.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
  /// An input for a miner transaction, which is generating new coins.
  Gen(usize),
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

  /// Serialize the Input to a `Vec<u8>`.
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

  /// Write the Output to a `Vec<u8>`.
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
  /// No additional timelock.
  None,
  /// Additionally locked until this block.
  Block(usize),
  /// Additionally locked until this many seconds since the epoch.
  Time(u64),
}

impl Timelock {
  /// Write the Timelock.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      Timelock::None => write_varint(&0u8, w),
      Timelock::Block(block) => write_varint(block, w),
      Timelock::Time(time) => write_varint(time, w),
    }
  }

  /// Serialize the Timelock to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(1);
    self.write(&mut res).unwrap();
    res
  }

  /// Read a Timelock.
  pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
    const TIMELOCK_BLOCK_THRESHOLD: usize = 500_000_000;

    let raw = read_varint::<_, u64>(r)?;
    Ok(if raw == 0 {
      Timelock::None
    } else if raw <
      u64::try_from(TIMELOCK_BLOCK_THRESHOLD)
        .expect("TIMELOCK_BLOCK_THRESHOLD didn't fit in a u64")
    {
      Timelock::Block(usize::try_from(raw).expect(
        "timelock overflowed usize despite being less than a const representable with a usize",
      ))
    } else {
      Timelock::Time(raw)
    })
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
  /// The timelock this transaction is additionally constrained by.
  ///
  /// All transactions on the blockchain are subject to a 10-block lock. This adds a further
  /// constraint.
  pub additional_timelock: Timelock,
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
  /// Write a TransactionPrefix.
  ///
  /// This is distinct from Monero in that it won't write any version.
  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.additional_timelock.write(w)?;
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
    let additional_timelock = Timelock::read(r)?;

    let inputs = read_vec(|r| Input::read(r), r)?;
    if inputs.is_empty() {
      Err(io::Error::other("transaction had no inputs"))?;
    }
    let is_miner_tx = matches!(inputs[0], Input::Gen { .. });

    let mut prefix = TransactionPrefix {
      additional_timelock,
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

mod sealed {
  use core::fmt::Debug;
  use crate::ringct::*;
  use super::*;

  pub(crate) trait RingSignatures: Clone + PartialEq + Eq + Default + Debug {
    fn signatures_to_write(&self) -> &[RingSignature];
    fn read_signatures(inputs: &[Input], r: &mut impl Read) -> io::Result<Self>;
  }

  impl RingSignatures for Vec<RingSignature> {
    fn signatures_to_write(&self) -> &[RingSignature] {
      self
    }
    fn read_signatures(inputs: &[Input], r: &mut impl Read) -> io::Result<Self> {
      let mut signatures = Vec::with_capacity(inputs.len());
      for input in inputs {
        match input {
          Input::ToKey { key_offsets, .. } => {
            signatures.push(RingSignature::read(key_offsets.len(), r)?)
          }
          _ => Err(io::Error::other("reading signatures for a transaction with non-ToKey inputs"))?,
        }
      }
      Ok(signatures)
    }
  }

  impl RingSignatures for () {
    fn signatures_to_write(&self) -> &[RingSignature] {
      &[]
    }
    fn read_signatures(_: &[Input], _: &mut impl Read) -> io::Result<Self> {
      Ok(())
    }
  }

  pub(crate) trait RctProofsTrait: Clone + PartialEq + Eq + Debug {
    fn write(&self, w: &mut impl Write) -> io::Result<()>;
    fn read(
      ring_length: usize,
      inputs: usize,
      outputs: usize,
      r: &mut impl Read,
    ) -> io::Result<Option<Self>>;
    fn rct_type(&self) -> RctType;
    fn base(&self) -> &RctBase;
  }

  impl RctProofsTrait for RctProofs {
    fn write(&self, w: &mut impl Write) -> io::Result<()> {
      self.write(w)
    }
    fn read(
      ring_length: usize,
      inputs: usize,
      outputs: usize,
      r: &mut impl Read,
    ) -> io::Result<Option<Self>> {
      RctProofs::read(ring_length, inputs, outputs, r)
    }
    fn rct_type(&self) -> RctType {
      self.rct_type()
    }
    fn base(&self) -> &RctBase {
      &self.base
    }
  }

  impl RctProofsTrait for PrunedRctProofs {
    fn write(&self, w: &mut impl Write) -> io::Result<()> {
      self.base.write(w, self.rct_type)
    }
    fn read(
      _ring_length: usize,
      inputs: usize,
      outputs: usize,
      r: &mut impl Read,
    ) -> io::Result<Option<Self>> {
      Ok(RctBase::read(inputs, outputs, r)?.map(|(rct_type, base)| Self { rct_type, base }))
    }
    fn rct_type(&self) -> RctType {
      self.rct_type
    }
    fn base(&self) -> &RctBase {
      &self.base
    }
  }

  pub(crate) trait PotentiallyPruned {
    type RingSignatures: RingSignatures;
    type RctProofs: RctProofsTrait;
  }
  /// A transaction which isn't pruned.
  #[derive(Clone, PartialEq, Eq, Debug)]
  pub struct NotPruned;
  impl PotentiallyPruned for NotPruned {
    type RingSignatures = Vec<RingSignature>;
    type RctProofs = RctProofs;
  }
  /// A transaction which is pruned.
  #[derive(Clone, PartialEq, Eq, Debug)]
  pub struct Pruned;
  impl PotentiallyPruned for Pruned {
    type RingSignatures = ();
    type RctProofs = PrunedRctProofs;
  }
}
pub use sealed::*;

/// A Monero transaction.
#[allow(private_bounds, private_interfaces, clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Transaction<P: PotentiallyPruned = NotPruned> {
  /// A version 1 transaction, used by the original Cryptonote codebase.
  V1 {
    /// The transaction's prefix.
    prefix: TransactionPrefix,
    /// The transaction's ring signatures.
    signatures: P::RingSignatures,
  },
  /// A version 2 transaction, used by the RingCT protocol.
  V2 {
    /// The transaction's prefix.
    prefix: TransactionPrefix,
    /// The transaction's proofs.
    proofs: Option<P::RctProofs>,
  },
}

enum PrunableHash<'a> {
  V1(&'a [RingSignature]),
  V2([u8; 32]),
}

#[allow(private_bounds)]
impl<P: PotentiallyPruned> Transaction<P> {
  /// Get the version of this transaction.
  pub fn version(&self) -> u8 {
    match self {
      Transaction::V1 { .. } => 1,
      Transaction::V2 { .. } => 2,
    }
  }

  /// Get the TransactionPrefix of this transaction.
  pub fn prefix(&self) -> &TransactionPrefix {
    match self {
      Transaction::V1 { prefix, .. } | Transaction::V2 { prefix, .. } => prefix,
    }
  }

  /// Get a mutable reference to the TransactionPrefix of this transaction.
  pub fn prefix_mut(&mut self) -> &mut TransactionPrefix {
    match self {
      Transaction::V1 { prefix, .. } | Transaction::V2 { prefix, .. } => prefix,
    }
  }

  /// Write the Transaction.
  ///
  /// Some writable transactions may not be readable if they're malformed, per Monero's consensus
  /// rules.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_varint(&self.version(), w)?;
    match self {
      Transaction::V1 { prefix, signatures } => {
        prefix.write(w)?;
        for ring_sig in signatures.signatures_to_write() {
          ring_sig.write(w)?;
        }
      }
      Transaction::V2 { prefix, proofs } => {
        prefix.write(w)?;
        match proofs {
          None => w.write_all(&[0])?,
          Some(proofs) => proofs.write(w)?,
        }
      }
    }
    Ok(())
  }

  /// Write the Transaction to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(2048);
    self.write(&mut res).unwrap();
    res
  }

  /// Read a Transaction.
  pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
    let version = read_varint(r)?;
    let prefix = TransactionPrefix::read(r, version)?;

    if version == 1 {
      let signatures = if (prefix.inputs.len() == 1) && matches!(prefix.inputs[0], Input::Gen(_)) {
        Default::default()
      } else {
        P::RingSignatures::read_signatures(&prefix.inputs, r)?
      };

      Ok(Transaction::V1 { prefix, signatures })
    } else if version == 2 {
      let proofs = P::RctProofs::read(
        prefix.inputs.first().map_or(0, |input| match input {
          Input::Gen(_) => 0,
          Input::ToKey { key_offsets, .. } => key_offsets.len(),
        }),
        prefix.inputs.len(),
        prefix.outputs.len(),
        r,
      )?;

      Ok(Transaction::V2 { prefix, proofs })
    } else {
      Err(io::Error::other("tried to deserialize unknown version"))
    }
  }

  // The hash of the transaction.
  #[allow(clippy::needless_pass_by_value)]
  fn hash_with_prunable_hash(&self, prunable: PrunableHash<'_>) -> [u8; 32] {
    match self {
      Transaction::V1 { prefix, .. } => {
        let mut buf = Vec::with_capacity(512);

        // We don't use `self.write` as that may write the signatures (if this isn't pruned)
        write_varint(&self.version(), &mut buf).unwrap();
        prefix.write(&mut buf).unwrap();

        // We explicitly write the signatures ourselves here
        let PrunableHash::V1(signatures) = prunable else {
          panic!("hashing v1 TX with non-v1 prunable data")
        };
        for signature in signatures {
          signature.write(&mut buf).unwrap();
        }

        keccak256(buf)
      }
      Transaction::V2 { prefix, proofs } => {
        let mut hashes = Vec::with_capacity(96);

        hashes.extend(prefix.hash(2));

        if let Some(proofs) = proofs {
          let mut buf = Vec::with_capacity(512);
          proofs.base().write(&mut buf, proofs.rct_type()).unwrap();
          hashes.extend(keccak256(&buf));
        } else {
          // Serialization of RctBase::Null
          hashes.extend(keccak256([0]));
        }
        let PrunableHash::V2(prunable_hash) = prunable else {
          panic!("hashing v2 TX with non-v2 prunable data")
        };
        hashes.extend(prunable_hash);

        keccak256(hashes)
      }
    }
  }
}

impl Transaction<NotPruned> {
  /// The hash of the transaction.
  pub fn hash(&self) -> [u8; 32] {
    match self {
      Transaction::V1 { signatures, .. } => {
        self.hash_with_prunable_hash(PrunableHash::V1(signatures))
      }
      Transaction::V2 { proofs, .. } => {
        self.hash_with_prunable_hash(PrunableHash::V2(if let Some(proofs) = proofs {
          let mut buf = Vec::with_capacity(1024);
          proofs.prunable.write(&mut buf, proofs.rct_type()).unwrap();
          keccak256(buf)
        } else {
          [0; 32]
        }))
      }
    }
  }

  /// Calculate the hash of this transaction as needed for signing it.
  ///
  /// This returns None if the transaction is without signatures.
  pub fn signature_hash(&self) -> Option<[u8; 32]> {
    Some(match self {
      Transaction::V1 { prefix, signatures } => {
        if (prefix.inputs.len() == 1) && matches!(prefix.inputs[0], Input::Gen(_)) {
          None?;
        }
        self.hash_with_prunable_hash(PrunableHash::V1(&[]))
      }
      Transaction::V2 { proofs, .. } => self.hash_with_prunable_hash({
        let Some(proofs) = proofs else { None? };
        let mut buf = Vec::with_capacity(1024);
        proofs.prunable.signature_write(&mut buf).unwrap();
        PrunableHash::V2(keccak256(buf))
      }),
    })
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

impl From<Transaction<NotPruned>> for Transaction<Pruned> {
  fn from(tx: Transaction<NotPruned>) -> Transaction<Pruned> {
    match tx {
      Transaction::V1 { prefix, .. } => Transaction::V1 { prefix, signatures: () },
      Transaction::V2 { prefix, proofs } => Transaction::V2 {
        prefix,
        proofs: proofs
          .map(|proofs| PrunedRctProofs { rct_type: proofs.rct_type(), base: proofs.base }),
      },
    }
  }
}
