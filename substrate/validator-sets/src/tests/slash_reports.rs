/*
  TODO: These tests are minimal and only test basic functioning. These tests _MUST_ be expanded to
  also include:
  - Testing the calculation of virtual stake
  - Slashing when there's a non-zero amount of slash points
  - Fatal slashing
  - Slashing a Serai validator
  at some point in the future. These establish sanity but are not sufficient.
*/

use serai_abi::{
  primitives::{prelude::*, crypto::*},
  TransactionContext as _,
};

use crate::{keys::Keys, allocations::Allocations as _, sessions::SlashReports};

use super::*;

#[test]
fn pruned_slash_report() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    let network = ExternalNetworkId::Bitcoin;
    let session = Session(0);

    let set = ExternalValidatorSet { network, session };

    let oraclization_key = Public([1; 32]);
    let external_key = ExternalKey(vec![2; 64].try_into().unwrap());
    <crate::Abstractions<Test> as Keys>::set_keys(set, KeyPair(oraclization_key, external_key));

    assert!(<crate::Abstractions::<Test> as SlashReports>::should_still_publish_slash_report(set)
      .is_none());
    <crate::Abstractions<Test> as SlashReports>::retire_set_regarding_slash_report(
      set,
      Amount(1_000),
    );
    assert_eq!(
      <crate::Abstractions::<Test> as SlashReports>::should_still_publish_slash_report(set),
      Some(oraclization_key.into())
    );

    <crate::Abstractions<Test> as SlashReports>::prune_historical_set_regarding_slash_report(set);
    assert!(<crate::Abstractions::<Test> as SlashReports>::should_still_publish_slash_report(set)
      .is_none());

    // Because this set was pruned before reporting their slashes, no rewards should've been issued
    assert_eq!(super::Coins::supply(Coin::Serai), Amount(0));
    assert_eq!(
      crate::Abstractions::<Test>::allocation(
        network.into(),
        crate::pallet::GenesisValidators::<Test>::get().unwrap()[0],
      ),
      None
    );
  });
}

#[test]
fn published_slash_report() {
  let mut ext = new_test_ext();
  let state_version = ext.state_version;
  ext.execute_with(|| {
    Core::start_transaction(0);

    let network = ExternalNetworkId::Bitcoin;
    let session = Session(0);

    let set = ExternalValidatorSet { network, session };

    let oraclization_key = Public([1; 32]);
    let external_key = ExternalKey(vec![2; 64].try_into().unwrap());
    <crate::Abstractions<Test> as Keys>::set_keys(set, KeyPair(oraclization_key, external_key));

    assert!(<crate::Abstractions::<Test> as SlashReports>::should_still_publish_slash_report(set)
      .is_none());
    <crate::Abstractions<Test> as SlashReports>::retire_set_regarding_slash_report(
      set,
      Amount(1_000),
    );
    assert_eq!(
      <crate::Abstractions::<Test> as SlashReports>::should_still_publish_slash_report(set),
      Some(oraclization_key.into())
    );

    // Handle the slash report
    <crate::Abstractions<Test> as SlashReports>::handle_slash_report(
      set,
      SlashReport(vec![Slash::Points(0)].try_into().unwrap()),
    );
    // The rewards should have been minted and allocated to the validator's stake
    assert_eq!(super::Coins::supply(Coin::Serai), Amount(1_000));
    assert_eq!(
      super::Coins::balance(serai_abi::validator_sets::address(), Coin::Serai),
      Amount(1_000)
    );
    assert_eq!(
      crate::Abstractions::<Test>::allocation(
        network.into(),
        crate::pallet::GenesisValidators::<Test>::get().unwrap()[0],
      ),
      Some(Amount(1_000))
    );

    // Pruning a set which already published should be a NOP
    let root_before_prune = sp_io::storage::root(state_version);
    <crate::Abstractions<Test> as SlashReports>::prune_historical_set_regarding_slash_report(set);
    assert!(<crate::Abstractions::<Test> as SlashReports>::should_still_publish_slash_report(set)
      .is_none());
    assert_eq!(root_before_prune, sp_io::storage::root(state_version));
  });
}
