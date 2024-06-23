#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
// #![deny(missing_docs)] // TODO
#![cfg_attr(not(feature = "std"), no_std)]

use core::ops::Deref;
use std_shims::{
  io as stdio,
  collections::{HashSet, HashMap},
};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  scalar::Scalar,
  edwards::{EdwardsPoint, CompressedEdwardsY},
};

use monero_serai::{
  io::{read_byte, read_u16, write_varint},
  primitives::{Commitment, keccak256, keccak256_to_scalar},
  ringct::{RctType, EncryptedAmount},
  transaction::Input,
};

pub use monero_serai::*;

pub use monero_rpc as rpc;

pub mod extra;
pub(crate) use extra::{PaymentId, ExtraField, Extra};

pub use monero_address as address;
use address::{Network, AddressType, SubaddressIndex, AddressSpec, AddressMeta, MoneroAddress};

mod scan;
pub use scan::{ReceivedOutput, SpendableOutput, Timelocked};

#[cfg(feature = "std")]
pub mod decoys;
#[cfg(not(feature = "std"))]
pub mod decoys {
  pub use monero_serai::primitives::Decoys;
  pub trait DecoySelection {}
}
pub use decoys::{DecoySelection, Decoys};

mod send;
pub use send::{FeePriority, FeeRate, TransactionError, Change, SignableTransaction, Eventuality};
#[cfg(feature = "std")]
pub use send::SignableTransactionBuilder;
#[cfg(feature = "multisig")]
pub(crate) use send::InternalPayment;
#[cfg(feature = "multisig")]
pub use send::TransactionMachine;

#[cfg(test)]
mod tests;

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

impl TryFrom<u8> for Protocol {
  type Error = ();
  fn try_from(version: u8) -> Result<Self, ()> {
    Ok(match version {
      14 => Protocol::v14, // TODO: 13 | 14?
      15 | 16 => Protocol::v16,
      _ => Err(())?,
    })
  }
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
      Protocol::v14 => RctType::ClsagBulletproof,
      Protocol::v16 => RctType::ClsagBulletproofPlus,
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

  pub fn write<W: stdio::Write>(&self, w: &mut W) -> stdio::Result<()> {
    match self {
      Protocol::v14 => w.write_all(&[0, 14]),
      Protocol::v16 => w.write_all(&[0, 16]),
      Protocol::Custom { ring_len, bp_plus, optimal_rct_type, view_tags, v16_fee } => {
        // Custom, version 0
        w.write_all(&[1, 0])?;
        w.write_all(&u16::try_from(*ring_len).unwrap().to_le_bytes())?;
        w.write_all(&[u8::from(*bp_plus)])?;
        w.write_all(&[u8::from(*optimal_rct_type)])?;
        w.write_all(&[u8::from(*view_tags)])?;
        w.write_all(&[u8::from(*v16_fee)])
      }
    }
  }

  pub fn read<R: stdio::Read>(r: &mut R) -> stdio::Result<Protocol> {
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
          optimal_rct_type: RctType::try_from(read_byte(r)?)
            .map_err(|()| stdio::Error::other("invalid RctType serialization"))?,
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

fn key_image_sort(x: &EdwardsPoint, y: &EdwardsPoint) -> core::cmp::Ordering {
  x.compress().to_bytes().cmp(&y.compress().to_bytes()).reverse()
}

// https://gist.github.com/kayabaNerve/8066c13f1fe1573286ba7a2fd79f6100
pub(crate) fn uniqueness(inputs: &[Input]) -> [u8; 32] {
  let mut u = b"uniqueness".to_vec();
  for input in inputs {
    match input {
      // If Gen, this should be the only input, making this loop somewhat pointless
      // This works and even if there were somehow multiple inputs, it'd be a false negative
      Input::Gen(height) => {
        write_varint(height, &mut u).unwrap();
      }
      Input::ToKey { key_image, .. } => u.extend(key_image.compress().to_bytes()),
    }
  }
  keccak256(u)
}

// Hs("view_tag" || 8Ra || o), Hs(8Ra || o), and H(8Ra || 0x8d) with uniqueness inclusion in the
// Scalar as an option
#[allow(non_snake_case)]
pub(crate) fn shared_key(
  uniqueness: Option<[u8; 32]>,
  ecdh: EdwardsPoint,
  o: usize,
) -> (u8, Scalar, [u8; 8]) {
  // 8Ra
  let mut output_derivation = ecdh.mul_by_cofactor().compress().to_bytes().to_vec();

  let mut payment_id_xor = [0; 8];
  payment_id_xor
    .copy_from_slice(&keccak256([output_derivation.as_ref(), [0x8d].as_ref()].concat())[.. 8]);

  // || o
  write_varint(&o, &mut output_derivation).unwrap();

  let view_tag = keccak256([b"view_tag".as_ref(), &output_derivation].concat())[0];

  // uniqueness ||
  let shared_key = if let Some(uniqueness) = uniqueness {
    [uniqueness.as_ref(), &output_derivation].concat()
  } else {
    output_derivation
  };

  (view_tag, keccak256_to_scalar(shared_key), payment_id_xor)
}

pub(crate) fn commitment_mask(shared_key: Scalar) -> Scalar {
  let mut mask = b"commitment_mask".to_vec();
  mask.extend(shared_key.to_bytes());
  keccak256_to_scalar(mask)
}

pub(crate) fn compact_amount_encryption(amount: u64, key: Scalar) -> [u8; 8] {
  let mut amount_mask = b"amount".to_vec();
  amount_mask.extend(key.to_bytes());
  (amount ^ u64::from_le_bytes(keccak256(amount_mask)[.. 8].try_into().unwrap())).to_le_bytes()
}

pub trait EncryptedAmountExt {
  /// Decrypt an EncryptedAmount into the Commitment it encrypts.
  ///
  /// The caller must verify the decrypted Commitment matches with the actual Commitment used
  /// within in the Monero protocol.
  fn decrypt(&self, key: Scalar) -> Commitment;
}
impl EncryptedAmountExt for EncryptedAmount {
  /// Decrypt an EncryptedAmount into the Commitment it encrypts.
  ///
  /// The caller must verify the decrypted Commitment matches with the actual Commitment used
  /// within in the Monero protocol.
  fn decrypt(&self, key: Scalar) -> Commitment {
    match self {
      // TODO: Add a test vector for this
      EncryptedAmount::Original { mask, amount } => {
        let mask_shared_sec = keccak256(key.as_bytes());
        let mask =
          Scalar::from_bytes_mod_order(*mask) - Scalar::from_bytes_mod_order(mask_shared_sec);

        let amount_shared_sec = keccak256(mask_shared_sec);
        let amount_scalar =
          Scalar::from_bytes_mod_order(*amount) - Scalar::from_bytes_mod_order(amount_shared_sec);
        // d2b from rctTypes.cpp
        let amount = u64::from_le_bytes(amount_scalar.to_bytes()[0 .. 8].try_into().unwrap());

        Commitment::new(mask, amount)
      }
      EncryptedAmount::Compact { amount } => Commitment::new(
        commitment_mask(key),
        u64::from_le_bytes(compact_amount_encryption(u64::from_le_bytes(*amount), key)),
      ),
    }
  }
}

/// The private view key and public spend key, enabling scanning transactions.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ViewPair {
  spend: EdwardsPoint,
  view: Zeroizing<Scalar>,
}

impl ViewPair {
  pub fn new(spend: EdwardsPoint, view: Zeroizing<Scalar>) -> ViewPair {
    ViewPair { spend, view }
  }

  pub fn spend(&self) -> EdwardsPoint {
    self.spend
  }

  pub fn view(&self) -> EdwardsPoint {
    self.view.deref() * ED25519_BASEPOINT_TABLE
  }

  fn subaddress_derivation(&self, index: SubaddressIndex) -> Scalar {
    keccak256_to_scalar(Zeroizing::new(
      [
        b"SubAddr\0".as_ref(),
        Zeroizing::new(self.view.to_bytes()).as_ref(),
        &index.account().to_le_bytes(),
        &index.address().to_le_bytes(),
      ]
      .concat(),
    ))
  }

  fn subaddress_keys(&self, index: SubaddressIndex) -> (EdwardsPoint, EdwardsPoint) {
    let scalar = self.subaddress_derivation(index);
    let spend = self.spend + (&scalar * ED25519_BASEPOINT_TABLE);
    let view = self.view.deref() * spend;
    (spend, view)
  }

  /// Returns an address with the provided specification.
  pub fn address(&self, network: Network, spec: AddressSpec) -> MoneroAddress {
    let mut spend = self.spend;
    let mut view: EdwardsPoint = self.view.deref() * ED25519_BASEPOINT_TABLE;

    // construct the address meta
    let meta = match spec {
      AddressSpec::Standard => AddressMeta::new(network, AddressType::Standard),
      AddressSpec::Integrated(payment_id) => {
        AddressMeta::new(network, AddressType::Integrated(payment_id))
      }
      AddressSpec::Subaddress(index) => {
        (spend, view) = self.subaddress_keys(index);
        AddressMeta::new(network, AddressType::Subaddress)
      }
      AddressSpec::Featured { subaddress, payment_id, guaranteed } => {
        if let Some(index) = subaddress {
          (spend, view) = self.subaddress_keys(index);
        }
        AddressMeta::new(
          network,
          AddressType::Featured { subaddress: subaddress.is_some(), payment_id, guaranteed },
        )
      }
    };

    MoneroAddress::new(meta, spend, view)
  }
}

/// Transaction scanner.
/// This scanner is capable of generating subaddresses, additionally scanning for them once they've
/// been explicitly generated. If the burning bug is attempted, any secondary outputs will be
/// ignored.
#[derive(Clone)]
pub struct Scanner {
  pair: ViewPair,
  // Also contains the spend key as None
  pub(crate) subaddresses: HashMap<CompressedEdwardsY, Option<SubaddressIndex>>,
  pub(crate) burning_bug: Option<HashSet<CompressedEdwardsY>>,
}

impl Zeroize for Scanner {
  fn zeroize(&mut self) {
    self.pair.zeroize();

    // These may not be effective, unfortunately
    for (mut key, mut value) in self.subaddresses.drain() {
      key.zeroize();
      value.zeroize();
    }
    if let Some(ref mut burning_bug) = self.burning_bug.take() {
      for mut output in burning_bug.drain() {
        output.zeroize();
      }
    }
  }
}

impl Drop for Scanner {
  fn drop(&mut self) {
    self.zeroize();
  }
}

impl ZeroizeOnDrop for Scanner {}

impl Scanner {
  /// Create a Scanner from a ViewPair.
  ///
  /// burning_bug is a HashSet of used keys, intended to prevent key reuse which would burn funds.
  ///
  /// When an output is successfully scanned, the output key MUST be saved to disk.
  ///
  /// When a new scanner is created, ALL saved output keys must be passed in to be secure.
  ///
  /// If None is passed, a modified shared key derivation is used which is immune to the burning
  /// bug (specifically the Guaranteed feature from Featured Addresses).
  pub fn from_view(pair: ViewPair, burning_bug: Option<HashSet<CompressedEdwardsY>>) -> Scanner {
    let mut subaddresses = HashMap::new();
    subaddresses.insert(pair.spend.compress(), None);
    Scanner { pair, subaddresses, burning_bug }
  }

  /// Register a subaddress.
  // There used to be an address function here, yet it wasn't safe. It could generate addresses
  // incompatible with the Scanner. While we could return None for that, then we have the issue
  // of runtime failures to generate an address.
  // Removing that API was the simplest option.
  pub fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
    let (spend, _) = self.pair.subaddress_keys(subaddress);
    self.subaddresses.insert(spend.compress(), Some(subaddress));
  }
}
