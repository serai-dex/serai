use core::ops::Deref;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar, EdwardsPoint};

use crate::{
  primitives::keccak256_to_scalar,
  address::{Network, AddressType, SubaddressIndex, AddressCreationError, MoneroAddress},
};

/// The pair of keys necessary to scan transactions.
///
/// This is composed of the public spend key and the private view key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ViewPair {
  spend: EdwardsPoint,
  pub(crate) view: Zeroizing<Scalar>,
}

impl ViewPair {
  /// Create a new ViewPair.
  pub fn new(spend: EdwardsPoint, view: Zeroizing<Scalar>) -> Self {
    ViewPair { spend, view }
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
    match MoneroAddress::new(network, AddressType::Legacy, self.spend, self.view()) {
      Ok(addr) => addr,
      Err(AddressCreationError::SmallOrderView) => {
        panic!("small-order view key error despite not making a guaranteed address")
      }
    }
  }

  /// Derive a legacy integrated address from this ViewPair.
  ///
  /// Subaddresses SHOULD be used instead.
  pub fn legacy_integrated_address(&self, network: Network, payment_id: [u8; 8]) -> MoneroAddress {
    match MoneroAddress::new(
      network,
      AddressType::LegacyIntegrated(payment_id),
      self.spend,
      self.view(),
    ) {
      Ok(addr) => addr,
      Err(AddressCreationError::SmallOrderView) => {
        panic!("small-order view key error despite not making a guaranteed address")
      }
    }
  }

  /// Derive a subaddress from this ViewPair.
  pub fn subaddress(&self, network: Network, subaddress: SubaddressIndex) -> MoneroAddress {
    let (spend, view) = self.subaddress_keys(subaddress);
    match MoneroAddress::new(network, AddressType::Subaddress, spend, view) {
      Ok(addr) => addr,
      Err(AddressCreationError::SmallOrderView) => {
        panic!("small-order view key error despite not making a guaranteed address")
      }
    }
  }
}

/// The pair of keys necessary to scan outputs immune to the burning bug.
///
/// This is composed of the public spend key and a non-zero private view key.
///
/// 'Guaranteed' outputs, or transactions outputs to the burning bug, are not officially specified
/// by the Monero project. They should only be used if necessary. No support outside of
/// monero-wallet is promised.
#[derive(Clone, Zeroize)]
pub struct GuaranteedViewPair(pub(crate) ViewPair);

impl GuaranteedViewPair {
  /// Create a new GuaranteedViewPair.
  ///
  /// This will return None if the view key is of small order (if it's zero).
  // Internal doc comment: These scalars are of prime order so 0 is the only small order Scalar
  pub fn new(spend: EdwardsPoint, view: Zeroizing<Scalar>) -> Option<Self> {
    if view.deref() == &Scalar::ZERO {
      None?;
    }
    Some(GuaranteedViewPair(ViewPair::new(spend, view)))
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

    match MoneroAddress::new(
      network,
      AddressType::Featured { subaddress: subaddress.is_some(), payment_id, guaranteed: true },
      spend,
      view,
    ) {
      Ok(addr) => addr,
      Err(AddressCreationError::SmallOrderView) => {
        panic!("created a ViewPair with identity as the view key")
      }
    }
  }
}
