use std_shims::{
  vec,
  vec::Vec,
  io::{self, Read, Write},
};

use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::{Scalar, edwards::EdwardsPoint};

use crate::{
  io::*, primitives::Commitment, transaction::Timelock, address::SubaddressIndex, extra::PaymentId,
};

/// An absolute output ID, defined as its transaction hash and output index.
///
/// This is not the output's key as multiple outputs may share an output key.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub(crate) struct AbsoluteId {
  pub(crate) transaction: [u8; 32],
  pub(crate) index_in_transaction: u32,
}

impl core::fmt::Debug for AbsoluteId {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt
      .debug_struct("AbsoluteId")
      .field("transaction", &hex::encode(self.transaction))
      .field("index_in_transaction", &self.index_in_transaction)
      .finish()
  }
}

impl AbsoluteId {
  /// Write the AbsoluteId.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.transaction)?;
    w.write_all(&self.index_in_transaction.to_le_bytes())
  }

  /// Read an AbsoluteId.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  fn read<R: Read>(r: &mut R) -> io::Result<AbsoluteId> {
    Ok(AbsoluteId { transaction: read_bytes(r)?, index_in_transaction: read_u32(r)? })
  }
}

/// An output's relative ID.
///
/// This is defined as the output's index on the blockchain.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub(crate) struct RelativeId {
  pub(crate) index_on_blockchain: u64,
}

impl core::fmt::Debug for RelativeId {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt.debug_struct("RelativeId").field("index_on_blockchain", &self.index_on_blockchain).finish()
  }
}

impl RelativeId {
  /// Write the RelativeId.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.index_on_blockchain.to_le_bytes())
  }

  /// Read an RelativeId.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  fn read<R: Read>(r: &mut R) -> io::Result<Self> {
    Ok(RelativeId { index_on_blockchain: read_u64(r)? })
  }
}

/// The data within an output, as necessary to spend the output.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub(crate) struct OutputData {
  pub(crate) key: EdwardsPoint,
  pub(crate) key_offset: Scalar,
  pub(crate) commitment: Commitment,
}

impl core::fmt::Debug for OutputData {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt
      .debug_struct("OutputData")
      .field("key", &hex::encode(self.key.compress().0))
      .field("key_offset", &hex::encode(self.key_offset.to_bytes()))
      .field("commitment", &self.commitment)
      .finish()
  }
}

impl OutputData {
  /// The key this output may be spent by.
  pub(crate) fn key(&self) -> EdwardsPoint {
    self.key
  }

  /// The scalar to add to the private spend key for it to be the discrete logarithm of this
  /// output's key.
  pub(crate) fn key_offset(&self) -> Scalar {
    self.key_offset
  }

  /// The commitment this output created.
  pub(crate) fn commitment(&self) -> &Commitment {
    &self.commitment
  }

  /// Write the OutputData.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub(crate) fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.key.compress().to_bytes())?;
    w.write_all(&self.key_offset.to_bytes())?;
    self.commitment.write(w)
  }

  /*
  /// Serialize the OutputData to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(32 + 32 + 40);
    self.write(&mut res).unwrap();
    res
  }
  */

  /// Read an OutputData.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub(crate) fn read<R: Read>(r: &mut R) -> io::Result<OutputData> {
    Ok(OutputData {
      key: read_point(r)?,
      key_offset: read_scalar(r)?,
      commitment: Commitment::read(r)?,
    })
  }
}

/// The metadata for an output.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Metadata {
  pub(crate) additional_timelock: Timelock,
  pub(crate) subaddress: Option<SubaddressIndex>,
  pub(crate) payment_id: Option<PaymentId>,
  pub(crate) arbitrary_data: Vec<Vec<u8>>,
}

impl core::fmt::Debug for Metadata {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt
      .debug_struct("Metadata")
      .field("additional_timelock", &self.additional_timelock)
      .field("subaddress", &self.subaddress)
      .field("payment_id", &self.payment_id)
      .field("arbitrary_data", &self.arbitrary_data.iter().map(hex::encode).collect::<Vec<_>>())
      .finish()
  }
}

impl Metadata {
  /// Write the Metadata.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.additional_timelock.write(w)?;

    if let Some(subaddress) = self.subaddress {
      w.write_all(&[1])?;
      w.write_all(&subaddress.account().to_le_bytes())?;
      w.write_all(&subaddress.address().to_le_bytes())?;
    } else {
      w.write_all(&[0])?;
    }

    if let Some(payment_id) = self.payment_id {
      w.write_all(&[1])?;
      payment_id.write(w)?;
    } else {
      w.write_all(&[0])?;
    }

    w.write_all(&u32::try_from(self.arbitrary_data.len()).unwrap().to_le_bytes())?;
    for part in &self.arbitrary_data {
      w.write_all(&[u8::try_from(part.len()).unwrap()])?;
      w.write_all(part)?;
    }
    Ok(())
  }

  /// Read a Metadata.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  fn read<R: Read>(r: &mut R) -> io::Result<Metadata> {
    let additional_timelock = Timelock::read(r)?;

    let subaddress = match read_byte(r)? {
      0 => None,
      1 => Some(
        SubaddressIndex::new(read_u32(r)?, read_u32(r)?)
          .ok_or_else(|| io::Error::other("invalid subaddress in metadata"))?,
      ),
      _ => Err(io::Error::other("invalid subaddress is_some boolean in metadata"))?,
    };

    Ok(Metadata {
      additional_timelock,
      subaddress,
      payment_id: if read_byte(r)? == 1 { PaymentId::read(r).ok() } else { None },
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

/// A scanned output and all associated data.
///
/// This struct contains all data necessary to spend this output, or handle it as a payment.
///
/// This struct is bound to a specific instance of the blockchain. If the blockchain reorganizes
/// the block this struct is bound to, it MUST be discarded. If any outputs are mutual to both
/// blockchains, scanning the new blockchain will yield those outputs again.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct WalletOutput {
  /// The absolute ID for this transaction.
  pub(crate) absolute_id: AbsoluteId,
  /// The ID for this transaction, relative to the blockchain.
  pub(crate) relative_id: RelativeId,
  /// The output's data.
  pub(crate) data: OutputData,
  /// Associated metadata relevant for handling it as a payment.
  pub(crate) metadata: Metadata,
}

impl WalletOutput {
  /// The hash of the transaction which created this output.
  pub fn transaction(&self) -> [u8; 32] {
    self.absolute_id.transaction
  }

  /// The index of the output within the transaction.
  pub fn index_in_transaction(&self) -> u32 {
    self.absolute_id.index_in_transaction
  }

  /// The index of the output on the blockchain.
  pub fn index_on_blockchain(&self) -> u64 {
    self.relative_id.index_on_blockchain
  }

  /// The key this output may be spent by.
  pub fn key(&self) -> EdwardsPoint {
    self.data.key()
  }

  /// The scalar to add to the private spend key for it to be the discrete logarithm of this
  /// output's key.
  pub fn key_offset(&self) -> Scalar {
    self.data.key_offset()
  }

  /// The commitment this output created.
  pub fn commitment(&self) -> &Commitment {
    self.data.commitment()
  }

  /// The additional timelock this output is subject to.
  ///
  /// All outputs are subject to the '10-block lock', a 10-block window after their inclusion
  /// on-chain during which they cannot be spent. Outputs may be additionally timelocked. This
  /// function only returns the additional timelock.
  pub fn additional_timelock(&self) -> Timelock {
    self.metadata.additional_timelock
  }

  /// The index of the subaddress this output was identified as sent to.
  pub fn subaddress(&self) -> Option<SubaddressIndex> {
    self.metadata.subaddress
  }

  /// The payment ID included with this output.
  ///
  /// This field may be `Some` even if wallet would not return a payment ID. This will happen if
  /// the scanned output belongs to the subaddress which spent Monero within the transaction which
  /// created the output. If multiple subaddresses spent Monero within this transactions, the key
  /// image with the highest index is determined to be the subaddress considered as the one
  /// spending.
  // TODO: Clarify and cite for point A ("highest index spent key image"??)
  pub fn payment_id(&self) -> Option<PaymentId> {
    self.metadata.payment_id
  }

  /// The arbitrary data from the `extra` field of the transaction which created this output.
  pub fn arbitrary_data(&self) -> &[Vec<u8>] {
    &self.metadata.arbitrary_data
  }

  /// Write the WalletOutput.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.absolute_id.write(w)?;
    self.relative_id.write(w)?;
    self.data.write(w)?;
    self.metadata.write(w)
  }

  /// Serialize the WalletOutput to a `Vec<u8>`.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = Vec::with_capacity(128);
    self.write(&mut serialized).unwrap();
    serialized
  }

  /// Read a WalletOutput.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn read<R: Read>(r: &mut R) -> io::Result<WalletOutput> {
    Ok(WalletOutput {
      absolute_id: AbsoluteId::read(r)?,
      relative_id: RelativeId::read(r)?,
      data: OutputData::read(r)?,
      metadata: Metadata::read(r)?,
    })
  }
}
