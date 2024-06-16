#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use std_shims::io as stdio;

use zeroize::Zeroize;

pub use monero_io as io;
pub use monero_generators as generators;
pub use monero_primitives as primitives;

mod merkle;

use monero_io as serialize;
use serialize::{read_byte, read_u16};

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

pub const DEFAULT_LOCK_WINDOW: usize = 10;
pub const COINBASE_LOCK_WINDOW: usize = 60;
pub const BLOCK_TIME: usize = 120;

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

  pub(crate) fn write<W: stdio::Write>(&self, w: &mut W) -> stdio::Result<()> {
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

  pub(crate) fn read<R: stdio::Read>(r: &mut R) -> stdio::Result<Protocol> {
    Ok(match read_byte(r)? {
      // Monero protocol
      0 => match read_byte(r)? {
        14 => Protocol::v14,
        16 => Protocol::v16,
        _ => Err(stdio::Error::other("unrecognized monero protocol"))?,
      },
      // Custom
      1 => match read_byte(r)? {
        0 => Protocol::Custom {
          ring_len: read_u16(r)?.into(),
          bp_plus: match read_byte(r)? {
            0 => false,
            1 => true,
            _ => Err(stdio::Error::other("invalid bool serialization"))?,
          },
          optimal_rct_type: RctType::from_byte(read_byte(r)?)
            .ok_or_else(|| stdio::Error::other("invalid RctType serialization"))?,
          view_tags: match read_byte(r)? {
            0 => false,
            1 => true,
            _ => Err(stdio::Error::other("invalid bool serialization"))?,
          },
          v16_fee: match read_byte(r)? {
            0 => false,
            1 => true,
            _ => Err(stdio::Error::other("invalid bool serialization"))?,
          },
        },
        _ => Err(stdio::Error::other("unrecognized custom protocol serialization"))?,
      },
      _ => Err(stdio::Error::other("unrecognized protocol serialization"))?,
    })
  }
}
