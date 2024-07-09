use core::ops::Deref;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar, EdwardsPoint};

use crate::{
  primitives::keccak256_to_scalar,
  address::{Network, AddressType, SubaddressIndex, MoneroAddress},
};

/// An error while working with a ViewPair.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum ViewPairError {
  /// The spend key was torsioned.
  ///
  /// Torsioned spend keys are of questionable spendability. This library avoids that question by
  /// rejecting such ViewPairs.
  // CLSAG seems to support it if the challenge does a torsion clear, FCMP++ should ship with a
  // torsion clear, yet it's not worth it to modify CLSAG sign to generate challenges until the
  // torsion clears and ensure spendability (nor can we reasonably guarantee that in the future)
  #[cfg_attr(feature = "std", error("torsioned spend key"))]
  TorsionedSpendKey,
}

/// The pair of keys necessary to scan transactions.
///
/// This is composed of the public spend key and the private view key.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ViewPair {
  spend: EdwardsPoint,
  pub(crate) view: Zeroizing<Scalar>,
}

impl ViewPair {
  /// Create a new ViewPair.
  pub fn new(spend: EdwardsPoint, view: Zeroizing<Scalar>) -> Result<Self, ViewPairError> {
    if !spend.is_torsion_free() {
      Err(ViewPairError::TorsionedSpendKey)?;
    }
    Ok(ViewPair { spend, view })
  }

  /// The public spend key for this ViewPair.
  pub fn spend(&self) -> EdwardsPoint {
    self.spend
  }

  /// The public view key for this ViewPair.
  pub fn view(&self) -> EdwardsPoint {
    self.view.deref() * ED25519_BASEPOINT_TABLE
  }

  pub(crate) fn subaddress_derivation(&self, index: SubaddressIndex) -> Scalar {
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

  pub(crate) fn subaddress_keys(&self, index: SubaddressIndex) -> (EdwardsPoint, EdwardsPoint) {
    let scalar = self.subaddress_derivation(index);
    let spend = self.spend + (&scalar * ED25519_BASEPOINT_TABLE);
    let view = self.view.deref() * spend;
    (spend, view)
  }

  /// Derive a legacy address from this ViewPair.
  ///
  /// Subaddresses SHOULD be used instead.
  pub fn legacy_address(&self, network: Network) -> MoneroAddress {
    MoneroAddress::new(network, AddressType::Legacy, self.spend, self.view())
  }

  /// Derive a legacy integrated address from this ViewPair.
  ///
  /// Subaddresses SHOULD be used instead.
  pub fn legacy_integrated_address(&self, network: Network, payment_id: [u8; 8]) -> MoneroAddress {
    MoneroAddress::new(network, AddressType::LegacyIntegrated(payment_id), self.spend, self.view())
  }

  /// Derive a subaddress from this ViewPair.
  pub fn subaddress(&self, network: Network, subaddress: SubaddressIndex) -> MoneroAddress {
    let (spend, view) = self.subaddress_keys(subaddress);
    MoneroAddress::new(network, AddressType::Subaddress, spend, view)
  }
}

/// The pair of keys necessary to scan outputs immune to the burning bug.
///
/// This is composed of the public spend key and a non-zero private view key.
///
/// 'Guaranteed' outputs, or transactions outputs to the burning bug, are not officially specified
/// by the Monero project. They should only be used if necessary. No support outside of
/// monero-wallet is promised.
#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct GuaranteedViewPair(pub(crate) ViewPair);

impl GuaranteedViewPair {
  /// Create a new GuaranteedViewPair.
  pub fn new(spend: EdwardsPoint, view: Zeroizing<Scalar>) -> Result<Self, ViewPairError> {
    ViewPair::new(spend, view).map(GuaranteedViewPair)
  }

  /// The public spend key for this GuaranteedViewPair.
  pub fn spend(&self) -> EdwardsPoint {
    self.0.spend()
  }

  /// The public view key for this GuaranteedViewPair.
  pub fn view(&self) -> EdwardsPoint {
    self.0.view()
  }

  /// Returns an address with the provided specification.
  ///
  /// The returned address will be a featured address with the guaranteed flag set. These should
  /// not be presumed to be interoperable with any other software.
  pub fn address(
    &self,
    network: Network,
    subaddress: Option<SubaddressIndex>,
    payment_id: Option<[u8; 8]>,
  ) -> MoneroAddress {
    let (spend, view) = if let Some(index) = subaddress {
      self.0.subaddress_keys(index)
    } else {
      (self.spend(), self.view())
    };

    MoneroAddress::new(
      network,
      AddressType::Featured { subaddress: subaddress.is_some(), payment_id, guaranteed: true },
      spend,
      view,
    )
  }
}
