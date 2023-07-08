use core::ops::BitXor;
use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use zeroize::Zeroize;

use curve25519_dalek::edwards::EdwardsPoint;

use crate::serialize::{
  varint_len, read_byte, read_bytes, read_varint, read_point, read_vec, write_byte, write_varint,
  write_point, write_vec,
};

pub const MAX_TX_EXTRA_NONCE_SIZE: usize = 255;

pub const PAYMENT_ID_MARKER: u8 = 0;
pub const ENCRYPTED_PAYMENT_ID_MARKER: u8 = 1;
// Used as it's the highest value not interpretable as a continued VarInt
pub const ARBITRARY_DATA_MARKER: u8 = 127;

// 1 byte is used for the marker
pub const MAX_ARBITRARY_DATA_SIZE: usize = MAX_TX_EXTRA_NONCE_SIZE - 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum PaymentId {
  Unencrypted([u8; 32]),
  Encrypted([u8; 8]),
}

impl BitXor<[u8; 8]> for PaymentId {
  type Output = Self;

  fn bitxor(self, bytes: [u8; 8]) -> Self {
    match self {
      // Don't perform the xor since this isn't intended to be encrypted with xor
      Self::Unencrypted(_) => self,
      Self::Encrypted(id) => {
        Self::Encrypted((u64::from_le_bytes(id) ^ u64::from_le_bytes(bytes)).to_le_bytes())
      }
    }
  }
}

impl PaymentId {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      Self::Unencrypted(id) => {
        w.write_all(&[PAYMENT_ID_MARKER])?;
        w.write_all(id)?;
      }
      Self::Encrypted(id) => {
        w.write_all(&[ENCRYPTED_PAYMENT_ID_MARKER])?;
        w.write_all(id)?;
      }
    }
    Ok(())
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
    Ok(match read_byte(r)? {
      0 => Self::Unencrypted(read_bytes(r)?),
      1 => Self::Encrypted(read_bytes(r)?),
      _ => Err(io::Error::new(io::ErrorKind::Other, "unknown payment ID type"))?,
    })
  }
}

// Doesn't bother with padding nor MinerGate
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub enum ExtraField {
  PublicKey(EdwardsPoint),
  Nonce(Vec<u8>),
  MergeMining(usize, [u8; 32]),
  PublicKeys(Vec<EdwardsPoint>),
}

impl ExtraField {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      Self::PublicKey(key) => {
        w.write_all(&[1])?;
        w.write_all(&key.compress().to_bytes())?;
      }
      Self::Nonce(data) => {
        w.write_all(&[2])?;
        write_vec(write_byte, data, w)?;
      }
      Self::MergeMining(height, merkle) => {
        w.write_all(&[3])?;
        write_varint(&u64::try_from(*height).unwrap(), w)?;
        w.write_all(merkle)?;
      }
      Self::PublicKeys(keys) => {
        w.write_all(&[4])?;
        write_vec(write_point, keys, w)?;
      }
    }
    Ok(())
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
    Ok(match read_byte(r)? {
      1 => Self::PublicKey(read_point(r)?),
      2 => Self::Nonce({
        let nonce = read_vec(read_byte, r)?;
        if nonce.len() > MAX_TX_EXTRA_NONCE_SIZE {
          Err(io::Error::new(io::ErrorKind::Other, "too long nonce"))?;
        }
        nonce
      }),
      3 => Self::MergeMining(
        usize::try_from(read_varint(r)?)
          .map_err(|_| io::Error::new(io::ErrorKind::Other, "varint for height exceeds usize"))?,
        read_bytes(r)?,
      ),
      4 => Self::PublicKeys(read_vec(read_point, r)?),
      _ => Err(io::Error::new(io::ErrorKind::Other, "unknown extra field"))?,
    })
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Extra(Vec<ExtraField>);
impl Extra {
  #[must_use]
  pub fn keys(&self) -> Option<(EdwardsPoint, Option<Vec<EdwardsPoint>>)> {
    let mut key = None;
    let mut additional = None;
    for field in &self.0 {
      match field.clone() {
        ExtraField::PublicKey(this_key) => key = key.or(Some(this_key)),
        ExtraField::PublicKeys(these_additional) => {
          additional = additional.or(Some(these_additional));
        }
        _ => (),
      }
    }
    // Don't return any keys if this was non-standard and didn't include the primary key
    key.map(|key| (key, additional))
  }

  #[must_use]
  pub fn payment_id(&self) -> Option<PaymentId> {
    for field in &self.0 {
      if let ExtraField::Nonce(data) = field {
        return PaymentId::read::<&[u8]>(&mut data.as_ref()).ok();
      }
    }
    None
  }

  #[must_use]
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

  pub(crate) fn new(key: EdwardsPoint, additional: Vec<EdwardsPoint>) -> Self {
    let mut res = Self(Vec::with_capacity(3));
    res.push(ExtraField::PublicKey(key));
    if !additional.is_empty() {
      res.push(ExtraField::PublicKeys(additional));
    }
    res
  }

  pub(crate) fn push(&mut self, field: ExtraField) {
    self.0.push(field);
  }

  #[rustfmt::skip]
  pub(crate) fn fee_weight(
    outputs: usize,
    additional: bool,
    payment_id: bool,
    data: &[Vec<u8>]
  ) -> usize {
    // PublicKey, key
    (1 + 32) +
    // PublicKeys, length, additional keys
    (if additional { 1 + 1 + (outputs * 32) } else { 0 }) +
    // PaymentId (Nonce), length, encrypted, ID
    (if payment_id { 1 + 1 + 1 + 8 } else { 0 }) +
    // Nonce, length, ARBITRARY_DATA_MARKER, data
    data.iter().map(|v| 1 + varint_len(1 + v.len()) + 1 + v.len()).sum::<usize>()
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for field in &self.0 {
      field.write(w)?;
    }
    Ok(())
  }

  #[must_use]
  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
    let mut res = Self(vec![]);
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
