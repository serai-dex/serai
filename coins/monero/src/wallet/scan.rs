use core::ops::Deref;
use std_shims::io::{self, Read, Write};

use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar, edwards::EdwardsPoint};

use crate::{
  Commitment,
  serialize::{read_byte, read_u32, read_u64, read_bytes, read_scalar, read_point, read_raw_vec},
  transaction::{Input, Timelock, Transaction},
  block::Block,
  rpc::{RpcError, RpcConnection, Rpc},
  wallet::{
    PaymentId, Extra, address::SubaddressIndex, Scanner, uniqueness, shared_key, amount_decryption,
    commitment_mask,
  },
};

/// An absolute output ID, defined as its transaction hash and output index.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct AbsoluteId {
  pub tx: [u8; 32],
  pub o: u8,
}

impl AbsoluteId {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.tx)?;
    w.write_all(&[self.o])
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = Vec::with_capacity(32 + 1);
    self.write(&mut serialized).unwrap();
    serialized
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<AbsoluteId> {
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
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.key.compress().to_bytes())?;
    w.write_all(&self.key_offset.to_bytes())?;
    w.write_all(&self.commitment.mask.to_bytes())?;
    w.write_all(&self.commitment.amount.to_le_bytes())
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = Vec::with_capacity(32 + 32 + 32 + 8);
    self.write(&mut serialized).unwrap();
    serialized
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<OutputData> {
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
  /// The subaddress this output was sent to.
  pub subaddress: Option<SubaddressIndex>,
  /// The payment ID included with this output.
  /// This will be gibberish if the payment ID wasn't intended for the recipient or wasn't included.
  // Could be an Option, as extra doesn't necessarily have a payment ID, yet all Monero TXs should
  // have this making it simplest for it to be as-is.
  pub payment_id: [u8; 8],
  /// Arbitrary data encoded in TX extra.
  pub arbitrary_data: Vec<Vec<u8>>,
}

impl Metadata {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    if let Some(subaddress) = self.subaddress {
      w.write_all(&[1])?;
      w.write_all(&subaddress.account().to_le_bytes())?;
      w.write_all(&subaddress.address().to_le_bytes())?;
    } else {
      w.write_all(&[0])?;
    }
    w.write_all(&self.payment_id)?;

    w.write_all(&u32::try_from(self.arbitrary_data.len()).unwrap().to_le_bytes())?;
    for part in &self.arbitrary_data {
      w.write_all(&[u8::try_from(part.len()).unwrap()])?;
      w.write_all(part)?;
    }
    Ok(())
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = Vec::with_capacity(1 + 8 + 1);
    self.write(&mut serialized).unwrap();
    serialized
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<Metadata> {
    let subaddress = if read_byte(r)? == 1 {
      Some(
        SubaddressIndex::new(read_u32(r)?, read_u32(r)?)
          .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid subaddress in metadata"))?,
      )
    } else {
      None
    };

    Ok(Metadata {
      subaddress,
      payment_id: read_bytes(r)?,
      arbitrary_data: {
        let mut data = vec![];
        for _ in 0 .. read_u32(r)? {
          let len = read_byte(r)?;
          data.push(read_raw_vec(read_byte, usize::from(len), r)?);
        }
        data
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

  pub fn arbitrary_data(&self) -> &[Vec<u8>] {
    &self.metadata.arbitrary_data
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.absolute.write(w)?;
    self.data.write(w)?;
    self.metadata.write(w)
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).unwrap();
    serialized
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<ReceivedOutput> {
    Ok(ReceivedOutput {
      absolute: AbsoluteId::read(r)?,
      data: OutputData::read(r)?,
      metadata: Metadata::read(r)?,
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
  pub async fn refresh_global_index<RPC: RpcConnection>(
    &mut self,
    rpc: &Rpc<RPC>,
  ) -> Result<(), RpcError> {
    self.global_index =
      rpc.get_o_indexes(self.output.absolute.tx).await?[usize::from(self.output.absolute.o)];
    Ok(())
  }

  pub async fn from<RPC: RpcConnection>(
    rpc: &Rpc<RPC>,
    output: ReceivedOutput,
  ) -> Result<SpendableOutput, RpcError> {
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

  pub fn arbitrary_data(&self) -> &[Vec<u8>] {
    self.output.arbitrary_data()
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.output.write(w)?;
    w.write_all(&self.global_index.to_le_bytes())
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).unwrap();
    serialized
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<SpendableOutput> {
    Ok(SpendableOutput { output: ReceivedOutput::read(r)?, global_index: read_u64(r)? })
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
    // Only scan RCT TXs since we can only spend RCT outputs
    if tx.prefix.version != 2 {
      return Timelocked(tx.prefix.timelock, vec![]);
    }

    let extra = Extra::read::<&[u8]>(&mut tx.prefix.extra.as_ref());
    let extra = if let Ok(extra) = extra {
      extra
    } else {
      return Timelocked(tx.prefix.timelock, vec![]);
    };

    let (tx_key, additional) = if let Some((tx_key, additional)) = extra.keys() {
      (tx_key, additional)
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

      for key in [Some(Some(&tx_key)), additional.as_ref().map(|additional| additional.get(o))] {
        let key = if let Some(Some(key)) = key {
          key
        } else if let Some(None) = key {
          // This is non-standard. There were additional keys, yet not one for this output
          // https://github.com/monero-project/monero/
          //   blob/04a1e2875d6e35e27bb21497988a6c822d319c28/
          //   src/cryptonote_basic/cryptonote_format_utils.cpp#L1062
          // TODO: Should this return? Where does Monero set the trap handler for this exception?
          continue;
        } else {
          break;
        };
        let (view_tag, shared_key, payment_id_xor) = shared_key(
          if self.burning_bug.is_none() { Some(uniqueness(&tx.prefix.inputs)) } else { None },
          self.pair.view.deref() * key,
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
        assert!(output_key.is_torsion_free());

        let mut key_offset = shared_key;
        if let Some(subaddress) = subaddress {
          key_offset += self.pair.subaddress_derivation(subaddress);
        }
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
  pub async fn scan<RPC: RpcConnection>(
    &mut self,
    rpc: &Rpc<RPC>,
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
    for tx in txs.drain(..) {
      if let Some(timelock) = map(self.scan_transaction(&tx), index) {
        res.push(timelock);
      }
      index += u64::try_from(
        tx.prefix
          .outputs
          .iter()
          // Filter to miner TX outputs/0-amount outputs since we're tacking the 0-amount index
          // This will fail to scan blocks containing pre-RingCT miner TXs
          .filter(|output| {
            matches!(tx.prefix.inputs.get(0), Some(Input::Gen(..))) || (output.amount == 0)
          })
          .count(),
      )
      .unwrap()
    }
    Ok(res)
  }
}
