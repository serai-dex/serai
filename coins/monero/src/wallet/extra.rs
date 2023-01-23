use core::ops::BitXor;
use std::io::{self, Read, Write};

use zeroize::Zeroize;

use curve25519_dalek::edwards::EdwardsPoint;

use crate::serialize::{
  varint_len, read_byte, read_bytes, read_varint, read_point, read_vec, write_byte, write_varint,
  write_point, write_vec,
};

pub const MAX_TX_EXTRA_NONCE_SIZE: usize = 255;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub(crate) enum PaymentId {
  Unencrypted([u8; 32]),
  Encrypted([u8; 8]),
}

impl BitXor<[u8; 8]> for PaymentId {
  type Output = PaymentId;

  fn bitxor(self, bytes: [u8; 8]) -> PaymentId {
    match self {
      PaymentId::Unencrypted(_) => self,
      PaymentId::Encrypted(id) => {
        PaymentId::Encrypted((u64::from_le_bytes(id) ^ u64::from_le_bytes(bytes)).to_le_bytes())
      }
    }
  }
}

impl PaymentId {
  pub(crate) fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      PaymentId::Unencrypted(id) => {
        w.write_all(&[0])?;
        w.write_all(id)?;
      }
      PaymentId::Encrypted(id) => {
        w.write_all(&[1])?;
        w.write_all(id)?;
      }
    }
    Ok(())
  }

  fn read<R: Read>(r: &mut R) -> io::Result<PaymentId> {
    Ok(match read_byte(r)? {
      0 => PaymentId::Unencrypted(read_bytes(r)?),
      1 => PaymentId::Encrypted(read_bytes(r)?),
      _ => Err(io::Error::new(io::ErrorKind::Other, "unknown payment ID type"))?,
    })
  }
}

// Doesn't bother with padding nor MinerGate
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub(crate) enum ExtraField {
  PublicKey(EdwardsPoint),
  Nonce(Vec<u8>),
  MergeMining(usize, [u8; 32]),
  PublicKeys(Vec<EdwardsPoint>),
}

impl ExtraField {
  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
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
    }
    Ok(())
  }

  fn read<R: Read>(r: &mut R) -> io::Result<ExtraField> {
    Ok(match read_byte(r)? {
      1 => ExtraField::PublicKey(read_point(r)?),
      2 => ExtraField::Nonce({
        let nonce = read_vec(read_byte, r)?;
        if nonce.len() > MAX_TX_EXTRA_NONCE_SIZE {
          Err(io::Error::new(io::ErrorKind::Other, "too long nonce"))?;
        }
        nonce
      }),
      3 => ExtraField::MergeMining(
        usize::try_from(read_varint(r)?)
          .map_err(|_| io::Error::new(io::ErrorKind::Other, "varint for height exceeds usize"))?,
        read_bytes(r)?,
      ),
      4 => ExtraField::PublicKeys(read_vec(read_point, r)?),
      _ => Err(io::Error::new(io::ErrorKind::Other, "unknown extra field"))?,
    })
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub(crate) struct Extra(Vec<ExtraField>);
impl Extra {
  pub(crate) fn keys(&self) -> Vec<EdwardsPoint> {
    let mut keys = Vec::with_capacity(2);
    for field in &self.0 {
      match field.clone() {
        ExtraField::PublicKey(key) => keys.push(key),
        ExtraField::PublicKeys(additional) => keys.extend(additional),
        _ => (),
      }
    }
    keys
  }

  pub(crate) fn payment_id(&self) -> Option<PaymentId> {
    for field in &self.0 {
      if let ExtraField::Nonce(data) = field {
        return PaymentId::read::<&[u8]>(&mut data.as_ref()).ok();
      }
    }
    None
  }

  pub(crate) fn data(&self) -> Vec<Vec<u8>> {
    let mut first = true;
    let mut res = vec![];
    for field in &self.0 {
      if let ExtraField::Nonce(data) = field {
        // Skip the first Nonce, which should be the payment ID
        if first {
          first = false;
          continue;
        }
        res.push(data.clone());
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

  #[rustfmt::skip]
  pub(crate) fn fee_weight(outputs: usize, data: &[Vec<u8>]) -> usize {
    // PublicKey, key
    (1 + 32) +
    // PublicKeys, length, additional keys
    (1 + 1 + (outputs.saturating_sub(1) * 32)) +
    // PaymentId (Nonce), length, encrypted, ID
    (1 + 1 + 1 + 8) +
    // Nonce, length, data (if existent)
    data.iter().map(|v| 1 + varint_len(v.len()) + v.len()).sum::<usize>()
  }

  pub(crate) fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    for field in &self.0 {
      field.write(w)?;
    }
    Ok(())
  }

  pub(crate) fn read<R: Read>(r: &mut R) -> io::Result<Extra> {
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
