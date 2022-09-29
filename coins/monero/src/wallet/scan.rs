use std::io::Cursor;

use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar, edwards::EdwardsPoint};

use crate::{
  Commitment,
  serialize::{read_byte, read_u32, read_u64, read_bytes, read_scalar, read_point, read_raw_vec},
  transaction::{Timelock, Transaction},
  block::Block,
  rpc::{Rpc, RpcError},
  wallet::{PaymentId, Extra, Scanner, uniqueness, shared_key, amount_decryption, commitment_mask},
};

/// An absolute output ID, defined as its transaction hash and output index.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct AbsoluteId {
  pub tx: [u8; 32],
  pub o: u8,
}

impl AbsoluteId {
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(32 + 1);
    res.extend(self.tx);
    res.push(self.o);
    res
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<AbsoluteId> {
    Ok(AbsoluteId { tx: read_bytes(r)?, o: read_byte(r)? })
  }
}

/// The data contained with an output.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct OutputData {
  pub key: EdwardsPoint,
  /// Absolute difference between the spend key and the key in this output
  pub key_offset: Scalar,
  pub commitment: Commitment,
}

impl OutputData {
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(32 + 32 + 40);
    res.extend(self.key.compress().to_bytes());
    res.extend(self.key_offset.to_bytes());
    res.extend(self.commitment.mask.to_bytes());
    res.extend(self.commitment.amount.to_le_bytes());
    res
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<OutputData> {
    Ok(OutputData {
      key: read_point(r)?,
      key_offset: read_scalar(r)?,
      commitment: Commitment::new(read_scalar(r)?, read_u64(r)?),
    })
  }
}

/// The metadata for an output.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Metadata {
  // Does not have to be an Option since the 0 subaddress is the main address
  /// The subaddress this output was sent to.
  pub subaddress: (u32, u32),
  /// The payment ID included with this output.
  /// This will be gibberish if the payment ID wasn't intended for the recipient or wasn't included.
  // Could be an Option, as extra doesn't necessarily have a payment ID, yet all Monero TXs should
  // have this making it simplest for it to be as-is.
  pub payment_id: [u8; 8],
  /// Arbitrary data encoded in TX extra.
  pub arbitrary_data: Option<Vec<u8>>,
}

impl Metadata {
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(4 + 4 + 8 + 1);
    res.extend(self.subaddress.0.to_le_bytes());
    res.extend(self.subaddress.1.to_le_bytes());
    res.extend(self.payment_id);
    if let Some(data) = self.arbitrary_data.as_ref() {
      res.extend([1, u8::try_from(data.len()).unwrap()]);
      res.extend(data);
    } else {
      res.extend([0]);
    }
    res
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<Metadata> {
    Ok(Metadata {
      subaddress: (read_u32(r)?, read_u32(r)?),
      payment_id: read_bytes(r)?,
      arbitrary_data: {
        if read_byte(r)? == 1 {
          let len = read_byte(r)?;
          Some(read_raw_vec(read_byte, usize::from(len), r)?)
        } else {
          None
        }
      },
    })
  }
}

/// A received output, defined as its absolute ID, data, and metadara.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ReceivedOutput {
  pub absolute: AbsoluteId,
  pub data: OutputData,
  pub metadata: Metadata,
}

impl ReceivedOutput {
  pub fn key(&self) -> EdwardsPoint {
    self.data.key
  }

  pub fn key_offset(&self) -> Scalar {
    self.data.key_offset
  }

  pub fn commitment(&self) -> Commitment {
    self.data.commitment.clone()
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = self.absolute.serialize();
    serialized.extend(&self.data.serialize());
    serialized.extend(&self.metadata.serialize());
    serialized
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<ReceivedOutput> {
    Ok(ReceivedOutput {
      absolute: AbsoluteId::deserialize(r)?,
      data: OutputData::deserialize(r)?,
      metadata: Metadata::deserialize(r)?,
    })
  }
}

/// A spendable output, defined as a received output and its index on the Monero blockchain.
/// This index is dependent on the Monero blockchain and will only be known once the output is
/// included within a block. This may change if there's a reorganization.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SpendableOutput {
  pub output: ReceivedOutput,
  pub global_index: u64,
}

impl SpendableOutput {
  /// Update the spendable output's global index. This is intended to be called if a
  /// re-organization occurred.
  pub async fn refresh_global_index(&mut self, rpc: &Rpc) -> Result<(), RpcError> {
    self.global_index =
      rpc.get_o_indexes(self.output.absolute.tx).await?[usize::from(self.output.absolute.o)];
    Ok(())
  }

  pub async fn from(rpc: &Rpc, output: ReceivedOutput) -> Result<SpendableOutput, RpcError> {
    let mut output = SpendableOutput { output, global_index: 0 };
    output.refresh_global_index(rpc).await?;
    Ok(output)
  }

  pub fn key(&self) -> EdwardsPoint {
    self.output.key()
  }

  pub fn key_offset(&self) -> Scalar {
    self.output.key_offset()
  }

  pub fn commitment(&self) -> Commitment {
    self.output.commitment()
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = self.output.serialize();
    serialized.extend(self.global_index.to_le_bytes());
    serialized
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<SpendableOutput> {
    Ok(SpendableOutput { output: ReceivedOutput::deserialize(r)?, global_index: read_u64(r)? })
  }
}

/// A collection of timelocked outputs, either received or spendable.
#[derive(Zeroize)]
pub struct Timelocked<O: Clone + Zeroize>(Timelock, Vec<O>);
impl<O: Clone + Zeroize> Drop for Timelocked<O> {
  fn drop(&mut self) {
    self.zeroize();
  }
}
impl<O: Clone + Zeroize> ZeroizeOnDrop for Timelocked<O> {}

impl<O: Clone + Zeroize> Timelocked<O> {
  pub fn timelock(&self) -> Timelock {
    self.0
  }

  /// Return the outputs if they're not timelocked, or an empty vector if they are.
  pub fn not_locked(&self) -> Vec<O> {
    if self.0 == Timelock::None {
      return self.1.clone();
    }
    vec![]
  }

  /// Returns None if the Timelocks aren't comparable. Returns Some(vec![]) if none are unlocked.
  pub fn unlocked(&self, timelock: Timelock) -> Option<Vec<O>> {
    // If the Timelocks are comparable, return the outputs if they're now unlocked
    self.0.partial_cmp(&timelock).filter(|_| self.0 <= timelock).map(|_| self.1.clone())
  }

  pub fn ignore_timelock(&self) -> Vec<O> {
    self.1.clone()
  }
}

impl Scanner {
  /// Scan a transaction to discover the received outputs.
  pub fn scan_transaction(&mut self, tx: &Transaction) -> Timelocked<ReceivedOutput> {
    let extra = Extra::deserialize(&mut Cursor::new(&tx.prefix.extra));
    let keys;
    let extra = if let Ok(extra) = extra {
      keys = extra.keys();
      extra
    } else {
      return Timelocked(tx.prefix.timelock, vec![]);
    };
    let payment_id = extra.payment_id();

    let mut res = vec![];
    for (o, output) in tx.prefix.outputs.iter().enumerate() {
      // https://github.com/serai-dex/serai/issues/106
      if let Some(burning_bug) = self.burning_bug.as_ref() {
        if burning_bug.contains(&output.key) {
          continue;
        }
      }

      let output_key = output.key.decompress();
      if output_key.is_none() {
        continue;
      }
      let output_key = output_key.unwrap();

      for key in &keys {
        let (view_tag, shared_key, payment_id_xor) = shared_key(
          if self.burning_bug.is_none() { Some(uniqueness(&tx.prefix.inputs)) } else { None },
          &self.pair.view,
          key,
          o,
        );

        let payment_id =
          if let Some(PaymentId::Encrypted(id)) = payment_id.map(|id| id ^ payment_id_xor) {
            id
          } else {
            payment_id_xor
          };

        if let Some(actual_view_tag) = output.view_tag {
          if actual_view_tag != view_tag {
            continue;
          }
        }

        // P - shared == spend
        let subaddress = self
          .subaddresses
          .get(&(output_key - (&shared_key * &ED25519_BASEPOINT_TABLE)).compress());
        if subaddress.is_none() {
          continue;
        }
        let subaddress = *subaddress.unwrap();

        // If it has torsion, it'll substract the non-torsioned shared key to a torsioned key
        // We will not have a torsioned key in our HashMap of keys, so we wouldn't identify it as
        // ours
        // If we did though, it'd enable bypassing the included burning bug protection
        debug_assert!(output_key.is_torsion_free());

        let key_offset = shared_key + self.pair.subaddress(subaddress);
        // Since we've found an output to us, get its amount
        let mut commitment = Commitment::zero();

        // Miner transaction
        if output.amount != 0 {
          commitment.amount = output.amount;
        // Regular transaction
        } else {
          let amount = match tx.rct_signatures.base.ecdh_info.get(o) {
            Some(amount) => amount_decryption(*amount, shared_key),
            // This should never happen, yet it may be possible with miner transactions?
            // Using get just decreases the possibility of a panic and lets us move on in that case
            None => break,
          };

          // Rebuild the commitment to verify it
          commitment = Commitment::new(commitment_mask(shared_key), amount);
          // If this is a malicious commitment, move to the next output
          // Any other R value will calculate to a different spend key and are therefore ignorable
          if Some(&commitment.calculate()) != tx.rct_signatures.base.commitments.get(o) {
            break;
          }
        }

        if commitment.amount != 0 {
          res.push(ReceivedOutput {
            absolute: AbsoluteId { tx: tx.hash(), o: o.try_into().unwrap() },

            data: OutputData { key: output_key, key_offset, commitment },

            metadata: Metadata { subaddress, payment_id, arbitrary_data: extra.data() },
          });

          if let Some(burning_bug) = self.burning_bug.as_mut() {
            burning_bug.insert(output.key);
          }
        }
        // Break to prevent public keys from being included multiple times, triggering multiple
        // inclusions of the same output
        break;
      }
    }

    Timelocked(tx.prefix.timelock, res)
  }

  /// Scan a block to obtain its spendable outputs. Its the presence in a block giving these
  /// transactions their global index, and this must be batched as asking for the index of specific
  /// transactions is a dead giveaway for which transactions you successfully scanned. This
  /// function obtains the output indexes for the miner transaction, incrementing from there
  /// instead.
  pub async fn scan(
    &mut self,
    rpc: &Rpc,
    block: &Block,
  ) -> Result<Vec<Timelocked<SpendableOutput>>, RpcError> {
    let mut index = rpc.get_o_indexes(block.miner_tx.hash()).await?[0];
    let mut txs = vec![block.miner_tx.clone()];
    txs.extend(rpc.get_transactions(&block.txs).await?);

    let map = |mut timelock: Timelocked<ReceivedOutput>, index| {
      if timelock.1.is_empty() {
        None
      } else {
        Some(Timelocked(
          timelock.0,
          timelock
            .1
            .drain(..)
            .map(|output| SpendableOutput {
              global_index: index + u64::from(output.absolute.o),
              output,
            })
            .collect(),
        ))
      }
    };

    let mut res = vec![];
    for tx in txs {
      if let Some(timelock) = map(self.scan_transaction(&tx), index) {
        res.push(timelock);
      }
      index += u64::try_from(tx.prefix.outputs.len()).unwrap();
    }
    Ok(res)
  }
}
