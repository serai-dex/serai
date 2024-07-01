#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
// #![deny(missing_docs)] // TODO
#![cfg_attr(not(feature = "std"), no_std)]

use core::ops::Deref;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar, EdwardsPoint};

use monero_serai::{
  io::write_varint,
  primitives::{Commitment, keccak256, keccak256_to_scalar},
  ringct::EncryptedAmount,
  transaction::Input,
};

pub use monero_serai::*;

pub use monero_rpc as rpc;

pub mod extra;
pub(crate) use extra::{PaymentId, Extra};

pub use monero_address as address;
use address::{Network, AddressType, SubaddressIndex, AddressSpec, MoneroAddress};

pub mod scan;

#[cfg(feature = "std")]
pub mod decoys;
#[cfg(not(feature = "std"))]
pub mod decoys {
  pub use monero_serai::primitives::Decoys;
  pub trait DecoySelection {}
}
pub use decoys::{DecoySelection, Decoys};

pub mod send;

/* TODO
#[cfg(test)]
mod tests;
*/

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

    // construct the address type
    let kind = match spec {
      AddressSpec::Legacy => AddressType::Legacy,
      AddressSpec::LegacyIntegrated(payment_id) => AddressType::LegacyIntegrated(payment_id),
      AddressSpec::Subaddress(index) => {
        (spend, view) = self.subaddress_keys(index);
        AddressType::Subaddress
      }
      AddressSpec::Featured { subaddress, payment_id, guaranteed } => {
        if let Some(index) = subaddress {
          (spend, view) = self.subaddress_keys(index);
        }
        AddressType::Featured { subaddress: subaddress.is_some(), payment_id, guaranteed }
      }
    };

    MoneroAddress::new(network, kind, spend, view)
  }
}

pub(crate) fn compact_amount_encryption(amount: u64, key: Scalar) -> [u8; 8] {
  let mut amount_mask = b"amount".to_vec();
  amount_mask.extend(key.to_bytes());
  (amount ^ u64::from_le_bytes(keccak256(amount_mask)[.. 8].try_into().unwrap())).to_le_bytes()
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
struct SharedKeyDerivations {
  // Hs("view_tag" || 8Ra || o)
  view_tag: u8,
  // Hs(uniqueness || 8Ra || o) where uniqueness may be empty
  shared_key: Scalar,
}

impl SharedKeyDerivations {
  // https://gist.github.com/kayabaNerve/8066c13f1fe1573286ba7a2fd79f6100
  fn uniqueness(inputs: &[Input]) -> [u8; 32] {
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

  #[allow(clippy::needless_pass_by_value)]
  fn output_derivations(
    uniqueness: Option<[u8; 32]>,
    ecdh: Zeroizing<EdwardsPoint>,
    o: usize,
  ) -> Zeroizing<SharedKeyDerivations> {
    // 8Ra
    let mut output_derivation = Zeroizing::new(
      Zeroizing::new(Zeroizing::new(ecdh.mul_by_cofactor()).compress().to_bytes()).to_vec(),
    );

    // || o
    {
      let output_derivation: &mut Vec<u8> = output_derivation.as_mut();
      write_varint(&o, output_derivation).unwrap();
    }

    let view_tag = keccak256([b"view_tag".as_ref(), &output_derivation].concat())[0];

    // uniqueness ||
    let output_derivation = if let Some(uniqueness) = uniqueness {
      Zeroizing::new([uniqueness.as_ref(), &output_derivation].concat())
    } else {
      output_derivation
    };

    Zeroizing::new(SharedKeyDerivations {
      view_tag,
      shared_key: keccak256_to_scalar(&output_derivation),
    })
  }

  // H(8Ra || 0x8d)
  // TODO: Make this itself a PaymentId
  #[allow(clippy::needless_pass_by_value)]
  fn payment_id_xor(ecdh: Zeroizing<EdwardsPoint>) -> [u8; 8] {
    // 8Ra
    let output_derivation = Zeroizing::new(
      Zeroizing::new(Zeroizing::new(ecdh.mul_by_cofactor()).compress().to_bytes()).to_vec(),
    );

    let mut payment_id_xor = [0; 8];
    payment_id_xor
      .copy_from_slice(&keccak256([output_derivation.as_ref(), [0x8d].as_ref()].concat())[.. 8]);
    payment_id_xor
  }

  fn commitment_mask(&self) -> Scalar {
    let mut mask = b"commitment_mask".to_vec();
    mask.extend(self.shared_key.as_bytes());
    let res = keccak256_to_scalar(&mask);
    mask.zeroize();
    res
  }

  fn decrypt(&self, enc_amount: &EncryptedAmount) -> Commitment {
    match enc_amount {
      // TODO: Add a test vector for this
      EncryptedAmount::Original { mask, amount } => {
        let mask_shared_sec = keccak256(self.shared_key.as_bytes());
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
        self.commitment_mask(),
        u64::from_le_bytes(compact_amount_encryption(u64::from_le_bytes(*amount), self.shared_key)),
      ),
    }
  }
}
