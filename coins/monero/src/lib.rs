#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

use std_shims::{sync::OnceLock, io};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop};

use sha3::{Digest, Keccak256};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar, edwards::EdwardsPoint};

pub use monero_generators::H;

mod merkle;

mod serialize;
use serialize::{read_byte, read_u16};

/// UnreducedScalar struct with functionality for recovering incorrectly reduced scalars.
mod unreduced_scalar;

/// Ring Signature structs and functionality.
pub mod ring_signatures;

/// RingCT structs and functionality.
pub mod ringct;
use ringct::RctType;

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

static INV_EIGHT_CELL: OnceLock<Scalar> = OnceLock::new();
#[allow(non_snake_case)]
pub(crate) fn INV_EIGHT() -> Scalar {
  *INV_EIGHT_CELL.get_or_init(|| Scalar::from(8u8).invert())
}

/// Monero protocol version.
///
/// v15 is omitted as v15 was simply v14 and v16 being active at the same time, with regards to the
/// transactions supported. Accordingly, v16 should be used during v15.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
#[allow(non_camel_case_types)]
pub enum Protocol {
  v14,
  v16,
  Custom {
    ring_len: usize,
    bp_plus: bool,
    optimal_rct_type: RctType,
    view_tags: bool,
    v16_fee: bool,
  },
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
  ///
  /// This method will likely be reworked when versions not using Bulletproofs at all are added.
  pub fn bp_plus(&self) -> bool {
    match self {
      Protocol::v14 => false,
      Protocol::v16 => true,
      Protocol::Custom { bp_plus, .. } => *bp_plus,
    }
  }

  // TODO: Make this an Option when we support pre-RCT protocols
  pub fn optimal_rct_type(&self) -> RctType {
    match self {
      Protocol::v14 => RctType::Clsag,
      Protocol::v16 => RctType::BulletproofsPlus,
      Protocol::Custom { optimal_rct_type, .. } => *optimal_rct_type,
    }
  }

  /// Whether or not the specified version uses view tags.
  pub fn view_tags(&self) -> bool {
    match self {
      Protocol::v14 => false,
      Protocol::v16 => true,
      Protocol::Custom { view_tags, .. } => *view_tags,
    }
  }

  /// Whether or not the specified version uses the fee algorithm from Monero
  /// hard fork version 16 (released in v18 binaries).
  pub fn v16_fee(&self) -> bool {
    match self {
      Protocol::v14 => false,
      Protocol::v16 => true,
      Protocol::Custom { v16_fee, .. } => *v16_fee,
    }
  }

  pub(crate) fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      Protocol::v14 => w.write_all(&[0, 14]),
      Protocol::v16 => w.write_all(&[0, 16]),
      Protocol::Custom { ring_len, bp_plus, optimal_rct_type, view_tags, v16_fee } => {
        // Custom, version 0
        w.write_all(&[1, 0])?;
        w.write_all(&u16::try_from(*ring_len).unwrap().to_le_bytes())?;
        w.write_all(&[u8::from(*bp_plus)])?;
        w.write_all(&[optimal_rct_type.to_byte()])?;
        w.write_all(&[u8::from(*view_tags)])?;
        w.write_all(&[u8::from(*v16_fee)])
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
          optimal_rct_type: RctType::from_byte(read_byte(r)?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid RctType serialization"))?,
          view_tags: match read_byte(r)? {
            0 => false,
            1 => true,
            _ => Err(io::Error::new(io::ErrorKind::Other, "invalid bool serialization"))?,
          },
          v16_fee: match read_byte(r)? {
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

/// Transparent structure representing a Pedersen commitment's contents.
#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Commitment {
  pub mask: Scalar,
  pub amount: u64,
}

impl core::fmt::Debug for Commitment {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt.debug_struct("Commitment").field("amount", &self.amount).finish_non_exhaustive()
  }
}

impl Commitment {
  /// A commitment to zero, defined with a mask of 1 (as to not be the identity).
  pub fn zero() -> Commitment {
    Commitment { mask: Scalar::ONE, amount: 0 }
  }

  pub fn new(mask: Scalar, amount: u64) -> Commitment {
    Commitment { mask, amount }
  }

  /// Calculate a Pedersen commitment, as a point, from the transparent structure.
  pub fn calculate(&self) -> EdwardsPoint {
    (&self.mask * ED25519_BASEPOINT_TABLE) + (Scalar::from(self.amount) * H())
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
  assert!(scalar != Scalar::ZERO, "ZERO HASH: {data:?}");
  scalar
}
