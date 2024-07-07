use core::ops::BitXor;
use std_shims::{
  vec,
  vec::Vec,
  io::{self, Read, BufRead, Write},
};

use zeroize::Zeroize;

use curve25519_dalek::edwards::EdwardsPoint;

use monero_serai::io::*;

pub(crate) const MAX_TX_EXTRA_PADDING_COUNT: usize = 255;
const MAX_TX_EXTRA_NONCE_SIZE: usize = 255;

const PAYMENT_ID_MARKER: u8 = 0;
const ENCRYPTED_PAYMENT_ID_MARKER: u8 = 1;
// Used as it's the highest value not interpretable as a continued VarInt
pub(crate) const ARBITRARY_DATA_MARKER: u8 = 127;

/// The max amount of data which will fit within a blob of arbitrary data.
// 1 byte is used for the marker
pub const MAX_ARBITRARY_DATA_SIZE: usize = MAX_TX_EXTRA_NONCE_SIZE - 1;

/// A Payment ID.
///
/// This is a legacy method of identifying why Monero was sent to the receiver.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum PaymentId {
  /// A deprecated form of payment ID which is no longer supported.
  Unencrypted([u8; 32]),
  /// An encrypted payment ID.
  Encrypted([u8; 8]),
}

impl BitXor<[u8; 8]> for PaymentId {
  type Output = PaymentId;

  fn bitxor(self, bytes: [u8; 8]) -> PaymentId {
    match self {
      // Don't perform the xor since this isn't intended to be encrypted with xor
      PaymentId::Unencrypted(_) => self,
      PaymentId::Encrypted(id) => {
        PaymentId::Encrypted((u64::from_le_bytes(id) ^ u64::from_le_bytes(bytes)).to_le_bytes())
      }
    }
  }
}

impl PaymentId {
  /// Write the PaymentId.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      PaymentId::Unencrypted(id) => {
        w.write_all(&[PAYMENT_ID_MARKER])?;
        w.write_all(id)?;
      }
      PaymentId::Encrypted(id) => {
        w.write_all(&[ENCRYPTED_PAYMENT_ID_MARKER])?;
        w.write_all(id)?;
      }
    }
    Ok(())
  }

  /// Serialize the PaymentId to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(1 + 8);
    self.write(&mut res).unwrap();
    res
  }

  /// Read a PaymentId.
  pub fn read<R: Read>(r: &mut R) -> io::Result<PaymentId> {
    Ok(match read_byte(r)? {
      0 => PaymentId::Unencrypted(read_bytes(r)?),
      1 => PaymentId::Encrypted(read_bytes(r)?),
      _ => Err(io::Error::other("unknown payment ID type"))?,
    })
  }
}

/// A field within the TX extra.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub enum ExtraField {
  /// Padding.
  ///
  /// This is a block of zeroes within the TX extra.
  Padding(usize),
  /// The transaction key.
  ///
  /// This is a commitment to the randomness used for deriving outputs.
  PublicKey(EdwardsPoint),
  /// The nonce field.
  ///
  /// This is used for data, such as payment IDs.
  Nonce(Vec<u8>),
  /// The field for merge-mining.
  ///
  /// This is used within miner transactions who are merge-mining Monero to specify the foreign
  /// block they mined.
  MergeMining(usize, [u8; 32]),
  /// The additional transaction keys.
  ///
  /// These are the per-output commitments to the randomness used for deriving outputs.
  PublicKeys(Vec<EdwardsPoint>),
  /// The 'mysterious' Minergate tag.
  ///
  /// This was used by a closed source entity without documentation. Support for parsing it was
  /// added to reduce extra which couldn't be decoded.
  MysteriousMinergate(Vec<u8>),
}

impl ExtraField {
  /// Write the ExtraField.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      ExtraField::Padding(size) => {
        w.write_all(&[0])?;
        for _ in 1 .. *size {
          write_byte(&0u8, w)?;
        }
      }
      ExtraField::PublicKey(key) => {
        w.write_all(&[1])?;
        w.write_all(&key.compress().to_bytes())?;
      }
      ExtraField::Nonce(data) => {
        w.write_all(&[2])?;
        write_vec(write_byte, data, w)?;
      }
      ExtraField::MergeMining(height, merkle) => {
        w.write_all(&[3])?;
        write_varint(&u64::try_from(*height).unwrap(), w)?;
        w.write_all(merkle)?;
      }
      ExtraField::PublicKeys(keys) => {
        w.write_all(&[4])?;
        write_vec(write_point, keys, w)?;
      }
      ExtraField::MysteriousMinergate(data) => {
        w.write_all(&[0xDE])?;
        write_vec(write_byte, data, w)?;
      }
    }
    Ok(())
  }

  /// Serialize the ExtraField to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(1 + 8);
    self.write(&mut res).unwrap();
    res
  }

  /// Read an ExtraField.
  pub fn read<R: BufRead>(r: &mut R) -> io::Result<ExtraField> {
    Ok(match read_byte(r)? {
      0 => ExtraField::Padding({
        // Read until either non-zero, max padding count, or end of buffer
        let mut size: usize = 1;
        loop {
          let buf = r.fill_buf()?;
          let mut n_consume = 0;
          for v in buf {
            if *v != 0u8 {
              Err(io::Error::other("non-zero value after padding"))?
            }
            n_consume += 1;
            size += 1;
            if size > MAX_TX_EXTRA_PADDING_COUNT {
              Err(io::Error::other("padding exceeded max count"))?
            }
          }
          if n_consume == 0 {
            break;
          }
          r.consume(n_consume);
        }
        size
      }),
      1 => ExtraField::PublicKey(read_point(r)?),
      2 => ExtraField::Nonce({
        let nonce = read_vec(read_byte, r)?;
        if nonce.len() > MAX_TX_EXTRA_NONCE_SIZE {
          Err(io::Error::other("too long nonce"))?;
        }
        nonce
      }),
      3 => ExtraField::MergeMining(read_varint(r)?, read_bytes(r)?),
      4 => ExtraField::PublicKeys(read_vec(read_point, r)?),
      0xDE => ExtraField::MysteriousMinergate(read_vec(read_byte, r)?),
      _ => Err(io::Error::other("unknown extra field"))?,
    })
  }
}

/// The result of decoding a transaction's extra field.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Extra(pub(crate) Vec<ExtraField>);
impl Extra {
  /// The keys within this extra.
  ///
  /// This returns all keys specified with `PublicKey` and the first set of keys specified with
  /// `PublicKeys`, so long as they're well-formed.
  // TODO: Cite this
  pub fn keys(&self) -> Option<(Vec<EdwardsPoint>, Option<Vec<EdwardsPoint>>)> {
    let mut keys = vec![];
    let mut additional = None;
    for field in &self.0 {
      match field.clone() {
        ExtraField::PublicKey(this_key) => keys.push(this_key),
        ExtraField::PublicKeys(these_additional) => {
          additional = additional.or(Some(these_additional))
        }
        _ => (),
      }
    }
    // Don't return any keys if this was non-standard and didn't include the primary key
    if keys.is_empty() {
      None
    } else {
      Some((keys, additional))
    }
  }

  /// The payment ID embedded within this extra.
  // TODO: Monero distinguishes encrypted/unencrypted payment ID retrieval
  pub fn payment_id(&self) -> Option<PaymentId> {
    for field in &self.0 {
      if let ExtraField::Nonce(data) = field {
        return PaymentId::read::<&[u8]>(&mut data.as_ref()).ok();
      }
    }
    None
  }

  /// The arbitrary data within this extra.
  ///
  /// This uses a marker custom to monero-wallet.
  pub fn data(&self) -> Vec<Vec<u8>> {
    let mut res = vec![];
    for field in &self.0 {
      if let ExtraField::Nonce(data) = field {
        if data[0] == ARBITRARY_DATA_MARKER {
          res.push(data[1 ..].to_vec());
        }
      }
    }
    res
  }

  pub(crate) fn new(key: EdwardsPoint, additional: Vec<EdwardsPoint>) -> Extra {
    let mut res = Extra(Vec::with_capacity(3));
    res.push(ExtraField::PublicKey(key));
    if !additional.is_empty() {
      res.push(ExtraField::PublicKeys(additional));
    }
    res
  }

  pub(crate) fn push(&mut self, field: ExtraField) {
    self.0.push(field);
  }

  /// Write the Extra.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for field in &self.0 {
      field.write(w)?;
    }
    Ok(())
  }

  /// Serialize the Extra to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }

  // TODO: Is this supposed to silently drop trailing gibberish?
  /// Read an `Extra`.
  #[allow(clippy::unnecessary_wraps)]
  pub fn read<R: BufRead>(r: &mut R) -> io::Result<Extra> {
    let mut res = Extra(vec![]);
    let mut field;
    while {
      field = ExtraField::read(r);
      field.is_ok()
    } {
      res.0.push(field.unwrap());
    }
    Ok(res)
  }
}
