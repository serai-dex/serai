use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ed25519};

use monero_wallet::{address::SubaddressIndex, ViewPairError, GuaranteedViewPair};

use view_keys::view_key;

pub(crate) mod output;
pub(crate) mod transaction;
pub(crate) mod block;

pub(crate) const EXTERNAL_SUBADDRESS: SubaddressIndex = match SubaddressIndex::new(1, 0) {
  Some(index) => index,
  None => panic!("SubaddressIndex for EXTERNAL_SUBADDRESS was None"),
};
pub(crate) const BRANCH_SUBADDRESS: SubaddressIndex = match SubaddressIndex::new(2, 0) {
  Some(index) => index,
  None => panic!("SubaddressIndex for BRANCH_SUBADDRESS was None"),
};
pub(crate) const CHANGE_SUBADDRESS: SubaddressIndex = match SubaddressIndex::new(2, 1) {
  Some(index) => index,
  None => panic!("SubaddressIndex for CHANGE_SUBADDRESS was None"),
};
pub(crate) const FORWARDED_SUBADDRESS: SubaddressIndex = match SubaddressIndex::new(2, 2) {
  Some(index) => index,
  None => panic!("SubaddressIndex for FORWARDED_SUBADDRESS was None"),
};

pub(crate) fn view_pair(key: <Ed25519 as Ciphersuite>::G) -> GuaranteedViewPair {
  match GuaranteedViewPair::new(key.0, Zeroizing::new(*view_key::<Ed25519>(0))) {
    Ok(view_pair) => view_pair,
    Err(ViewPairError::TorsionedSpendKey) => {
      unreachable!("dalek_ff_group::EdwardsPoint had torsion")
    }
  }
}
