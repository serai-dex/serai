use core::ops::Deref;
use std::collections::{HashSet, HashMap};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  scalar::Scalar,
  edwards::{EdwardsPoint, CompressedEdwardsY},
};

use crate::{hash, hash_to_scalar, serialize::write_varint, transaction::Input};

mod extra;
pub(crate) use extra::{PaymentId, ExtraField, Extra};

/// Address encoding and decoding functionality.
pub mod address;
use address::{Network, AddressType, AddressMeta, MoneroAddress, AddressSpec};

mod scan;
pub use scan::{ReceivedOutput, SpendableOutput};

pub(crate) mod decoys;
pub(crate) use decoys::Decoys;

mod send;
pub use send::{Fee, TransactionError, SignableTransaction, SignableTransactionBuilder};
#[cfg(feature = "multisig")]
pub use send::TransactionMachine;

fn key_image_sort(x: &EdwardsPoint, y: &EdwardsPoint) -> std::cmp::Ordering {
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
  hash(&u)
}

// Hs("view_tag" || 8Ra || o), Hs(8Ra || o), and H(8Ra || 0x8d) with uniqueness inclusion in the
// Scalar as an option
#[allow(non_snake_case)]
pub(crate) fn shared_key(
  uniqueness: Option<[u8; 32]>,
  s: &Scalar,
  P: &EdwardsPoint,
  o: usize,
) -> (u8, Scalar, [u8; 8]) {
  // 8Ra
  let mut output_derivation = (s * P).mul_by_cofactor().compress().to_bytes().to_vec();
  // || o
  write_varint(&o.try_into().unwrap(), &mut output_derivation).unwrap();

  let view_tag = hash(&[b"view_tag".as_ref(), &output_derivation].concat())[0];
  let mut payment_id_xor = [0; 8];
  payment_id_xor
    .copy_from_slice(&hash(&[output_derivation.as_ref(), [0x8d].as_ref()].concat())[.. 8]);

  // uniqueness ||
  let shared_key = if let Some(uniqueness) = uniqueness {
    [uniqueness.as_ref(), &output_derivation].concat().to_vec()
  } else {
    output_derivation
  };

  (view_tag, hash_to_scalar(&shared_key), payment_id_xor)
}

pub(crate) fn amount_encryption(amount: u64, key: Scalar) -> [u8; 8] {
  let mut amount_mask = b"amount".to_vec();
  amount_mask.extend(key.to_bytes());
  (amount ^ u64::from_le_bytes(hash(&amount_mask)[.. 8].try_into().unwrap())).to_le_bytes()
}

fn amount_decryption(amount: [u8; 8], key: Scalar) -> u64 {
  u64::from_le_bytes(amount_encryption(u64::from_le_bytes(amount), key))
}

pub(crate) fn commitment_mask(shared_key: Scalar) -> Scalar {
  let mut mask = b"commitment_mask".to_vec();
  mask.extend(shared_key.to_bytes());
  hash_to_scalar(&mask)
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

  fn subaddress_keys(&self, index: (u32, u32)) -> Scalar {
    if index == (0, 0) {
      return Scalar::zero();
    }

    hash_to_scalar(&Zeroizing::new(
      [
        b"SubAddr\0".as_ref(),
        Zeroizing::new(self.view.to_bytes()).as_ref(),
        &index.0.to_le_bytes(),
        &index.1.to_le_bytes(),
      ]
      .concat(),
    ))
  }

  fn subaddress_derivation(&self, index: (u32, u32)) -> (EdwardsPoint, EdwardsPoint) {
    let scalar = self.subaddress_keys(index);
    let spend = self.spend + (&scalar * &ED25519_BASEPOINT_TABLE);
    let view = self.view.deref() * spend;
    (spend, view)
  }

  /// Returns an address with the provided specification.
  pub fn address(&self, network: Network, spec: AddressSpec) -> MoneroAddress {
    let mut spend = self.spend;
    let mut view: EdwardsPoint = self.view.deref() * &ED25519_BASEPOINT_TABLE;

    // construct the address meta
    let meta = match spec {
      AddressSpec::Standard => AddressMeta::new(network, AddressType::Standard),
      AddressSpec::Integrated(payment_id) => {
        AddressMeta::new(network, AddressType::Integrated(payment_id))
      }
      AddressSpec::Subaddress(i1, i2) => {
        if i1 == 0 && i2 == 0 {
          AddressMeta::new(network, AddressType::Standard)
        } else {
          (spend, view) = self.subaddress_derivation((i1, i2));
          AddressMeta::new(network, AddressType::Subaddress)
        }
      }
      AddressSpec::Featured(subaddress, payment_id, guaranteed) => {
        let mut is_subaddress = false;
        if let Some(index) = subaddress {
          if index != (0, 0) {
            (spend, view) = self.subaddress_derivation(index);
            is_subaddress = true;
          }
        }
        AddressMeta::new(network, AddressType::Featured(is_subaddress, payment_id, guaranteed))
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
  network: Network,
  pub(crate) subaddresses: HashMap<CompressedEdwardsY, (u32, u32)>,
  pub(crate) burning_bug: Option<HashSet<CompressedEdwardsY>>,
}

impl Zeroize for Scanner {
  fn zeroize(&mut self) {
    self.pair.zeroize();
    self.network.zeroize();

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
  /// The network is used for generating subaddresses.
  /// burning_bug is a HashSet of used keys, intended to prevent key reuse which would burn funds.
  /// When an output is successfully scanned, the output key MUST be saved to disk.
  /// When a new scanner is created, ALL saved output keys must be passed in to be secure.
  /// If None is passed, a modified shared key derivation is used which is immune to the burning
  /// bug (specifically the Guaranteed feature from Featured Addresses).
  // TODO: Should this take in a DB access handle to ensure output keys are saved?
  pub fn from_view(
    pair: ViewPair,
    network: Network,
    burning_bug: Option<HashSet<CompressedEdwardsY>>,
  ) -> Scanner {
    let mut subaddresses = HashMap::new();
    subaddresses.insert(pair.spend.compress(), (0, 0));
    Scanner { pair, network, subaddresses, burning_bug }
  }

  /// Returns the specified address.
  ///
  /// A `Scanner` will fail to scan this address unless it is appropriate to the `Scanner`.
  /// If the `Scanner` was defined as not handling the burning bug, by passing `None` for
  /// `burning_bug` upon construction, this must be a guaranteed address
  /// in order to be scanned by it.
  pub fn address(&mut self, spec: AddressSpec) -> MoneroAddress {
    let addr = self.pair.address(self.network, spec);

    let mut index = (0, 0);
    if let AddressSpec::Subaddress(i1, i2) = spec {
      index = (i1, i2);
    } else if let AddressSpec::Featured(Some(index_inner), _, _) = spec {
      index = index_inner;
    }
    self.subaddresses.insert(addr.spend.compress(), index);
    addr
  }
}
