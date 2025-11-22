use zeroize::Zeroizing;

use ciphersuite::{group::ff::PrimeField, WrappedGroup, GroupIo};
use dalek_ff_group::Ed25519;

use monero_wallet::{
  ed25519::{Scalar, CompressedPoint},
  address::SubaddressIndex,
  ViewPairError, GuaranteedViewPair,
};

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

pub(crate) fn view_pair(key: <Ed25519 as WrappedGroup>::G) -> GuaranteedViewPair {
  match GuaranteedViewPair::new(
    CompressedPoint::from(key.0.compress().to_bytes()).decompress().unwrap(),
    Zeroizing::new(Scalar::read(&mut view_key::<Ed25519>(0).to_repr().as_slice()).unwrap()),
  ) {
    Ok(view_pair) => view_pair,
    Err(ViewPairError::TorsionedSpendKey) => {
      unreachable!("dalek_ff_group::EdwardsPoint had torsion")
    }
  }
}
