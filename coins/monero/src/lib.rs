#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

use std::io;

use lazy_static::lazy_static;
use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop};

use sha3::{Digest, Keccak256};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  scalar::Scalar,
  edwards::{EdwardsPoint, EdwardsBasepointTable},
};

pub use monero_generators::H;

mod serialize;
use serialize::{read_byte, read_u16};

/// RingCT structs and functionality.
pub mod ringct;

/// Transaction structs.
pub mod transaction;
/// Block structs.
pub mod block;

/// Monero daemon RPC interface.
pub mod rpc;
/// Wallet functionality, enabling scanning and sending transactions.
pub mod wallet;

#[cfg(test)]
mod tests;

/// Monero protocol version. v15 is omitted as v15 was simply v14 and v16 being active at the same
/// time, with regards to the transactions supported. Accordingly, v16 should be used during v15.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
#[allow(non_camel_case_types)]
pub enum Protocol {
  v14,
  v16,
  Custom { ring_len: usize, bp_plus: bool },
}

impl Protocol {
  /// Amount of ring members under this protocol version.
  pub fn ring_len(&self) -> usize {
    match self {
      Protocol::v14 => 11,
      Protocol::v16 => 16,
      Protocol::Custom { ring_len, .. } => *ring_len,
    }
  }

  /// Whether or not the specified version uses Bulletproofs or Bulletproofs+.
  /// This method will likely be reworked when versions not using Bulletproofs at all are added.
  pub fn bp_plus(&self) -> bool {
    match self {
      Protocol::v14 => false,
      Protocol::v16 => true,
      Protocol::Custom { bp_plus, .. } => *bp_plus,
    }
  }

  pub(crate) fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      Protocol::v14 => w.write_all(&[0, 14]),
      Protocol::v16 => w.write_all(&[0, 16]),
      Protocol::Custom { ring_len, bp_plus } => {
        // Custom, version 0
        w.write_all(&[1, 0])?;
        w.write_all(&u16::try_from(*ring_len).unwrap().to_le_bytes())?;
        w.write_all(&[u8::from(*bp_plus)])
      }
    }
  }

  pub(crate) fn read<R: io::Read>(r: &mut R) -> io::Result<Protocol> {
    Ok(match read_byte(r)? {
      // Monero protocol
      0 => match read_byte(r)? {
        14 => Protocol::v14,
        16 => Protocol::v16,
        _ => Err(io::Error::new(io::ErrorKind::Other, "unrecognized monero protocol"))?,
      },
      // Custom
      1 => match read_byte(r)? {
        0 => Protocol::Custom {
          ring_len: read_u16(r)?.into(),
          bp_plus: match read_byte(r)? {
            0 => false,
            1 => true,
            _ => Err(io::Error::new(io::ErrorKind::Other, "invalid bool serialization"))?,
          },
        },
        _ => {
          Err(io::Error::new(io::ErrorKind::Other, "unrecognized custom protocol serialization"))?
        }
      },
      _ => Err(io::Error::new(io::ErrorKind::Other, "unrecognized protocol serialization"))?,
    })
  }
}

lazy_static! {
  static ref H_TABLE: EdwardsBasepointTable = EdwardsBasepointTable::create(&H);
}

/// Transparent structure representing a Pedersen commitment's contents.
#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Commitment {
  pub mask: Scalar,
  pub amount: u64,
}

impl Commitment {
  /// The zero commitment, defined as a mask of 1 (as to not be the identity) and a 0 amount.
  pub fn zero() -> Commitment {
    Commitment { mask: Scalar::one(), amount: 0 }
  }

  pub fn new(mask: Scalar, amount: u64) -> Commitment {
    Commitment { mask, amount }
  }

  /// Calculate a Pedersen commitment, as a point, from the transparent structure.
  pub fn calculate(&self) -> EdwardsPoint {
    (&self.mask * &ED25519_BASEPOINT_TABLE) + (&Scalar::from(self.amount) * &*H_TABLE)
  }
}

/// Support generating a random scalar using a modern rand, as dalek's is notoriously dated.
pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
  let mut r = [0; 64];
  rng.fill_bytes(&mut r);
  Scalar::from_bytes_mod_order_wide(&r)
}

pub(crate) fn hash(data: &[u8]) -> [u8; 32] {
  Keccak256::digest(data).into()
}

/// Hash the provided data to a scalar via keccak256(data) % l.
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
  let scalar = Scalar::from_bytes_mod_order(hash(data));
  // Monero will explicitly error in this case
  // This library acknowledges its practical impossibility of it occurring, and doesn't bother to
  // code in logic to handle it. That said, if it ever occurs, something must happen in order to
  // not generate/verify a proof we believe to be valid when it isn't
  assert!(scalar != Scalar::zero(), "ZERO HASH: {data:?}");
  scalar
}
